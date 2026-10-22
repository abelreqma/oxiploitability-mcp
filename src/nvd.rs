use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{Client, Response};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cache::TtlCache;
use crate::cve::CveId;
use crate::http::{HttpError, read_json};
use crate::ratelimit::RollingWindow;

pub const DEFAULT_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const DEFAULT_CPE_URL: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
const SERVICE: &str = "NVD";
const WINDOW: Duration = Duration::from_secs(30);
const PUBLIC_LIMIT: usize = 5;
const KEYED_LIMIT: usize = 50;
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const CACHE_ENTRIES: usize = 5_000;
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_REFERENCES: usize = 20;
const MAX_AFFECTED: usize = 50;
const SEARCH_MAX_BODY: usize = 16 * 1024 * 1024;
const SEARCH_PAGE: usize = 50;
const KEV_PAGE: usize = 100;
const CPE_PAGE: usize = 100;
/// NVD answers 403 or 429 when its firewall rate limit trips and 502 to 504 when overloaded.
const RETRY_STATUSES: [u16; 5] = [403, 429, 502, 503, 504];
const MAX_RETRIES: u32 = 2;
const RETRY_BACKOFF: Duration = Duration::from_secs(2);

type Gate = Arc<tokio::sync::Mutex<()>>;

pub struct NvdClient {
    http: Client,
    base_url: String,
    cpe_url: String,
    api_key: Option<String>,
    limiter: RollingWindow,
    retry_backoff: Duration,
    cache: TtlCache<Option<NvdSummary>>,
    /// One gate per CVE being fetched, so concurrent lookups of the same id share one request.
    inflight: Mutex<HashMap<String, Gate>>,
}

impl NvdClient {
    pub fn new(http: Client, api_key: Option<String>) -> Self {
        let api_key = api_key.filter(|k| !k.trim().is_empty());
        let cap = if api_key.is_some() {
            KEYED_LIMIT
        } else {
            PUBLIC_LIMIT
        };
        Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
            cpe_url: DEFAULT_CPE_URL.to_string(),
            api_key,
            limiter: RollingWindow::new(cap, WINDOW),
            retry_backoff: RETRY_BACKOFF,
            cache: TtlCache::new(CACHE_TTL, CACHE_ENTRIES),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_cpe_url(mut self, cpe_url: impl Into<String>) -> Self {
        self.cpe_url = cpe_url.into();
        self
    }

    /// Sets the wait before the first retry; each later retry waits twice as long.
    pub fn with_retry_backoff(mut self, backoff: Duration) -> Self {
        self.retry_backoff = backoff;
        self
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    pub fn requests_per_window(&self) -> usize {
        self.limiter.capacity()
    }

    /// Returns `None` when NVD has no record for the id.
    pub async fn lookup(&self, id: &CveId) -> Result<Option<NvdSummary>, HttpError> {
        if let Some(hit) = self.cache.get(id.as_str()) {
            return Ok(hit);
        }
        let entry = InflightEntry::join(&self.inflight, id.as_str());
        let _turn = entry.gate.lock().await;
        if let Some(hit) = self.cache.get(id.as_str()) {
            return Ok(hit);
        }
        self.fetch(id).await
    }

    async fn fetch(&self, id: &CveId) -> Result<Option<NvdSummary>, HttpError> {
        let resp = self.send(&self.base_url, &[("cveId", id.as_str())]).await?;
        let body: NvdResponse = read_json(SERVICE, resp, MAX_BODY).await?;
        let summary = body
            .vulnerabilities
            .into_iter()
            .next()
            .map(|v| NvdSummary::from(v.cve));
        self.cache.insert(id.as_str().to_string(), summary.clone());
        Ok(summary)
    }

    /// Sends one rate-limited GET, retrying rate-limit and overload responses.
    async fn send(&self, url: &str, query: &[(&str, &str)]) -> Result<Response, HttpError> {
        let mut attempt = 0;
        loop {
            self.limiter.acquire().await;
            let mut req = self.http.get(url).query(query);
            if let Some(key) = &self.api_key {
                req = req.header("apiKey", key);
            }
            let err = match req.send().await {
                Ok(resp) if resp.status().is_success() => return Ok(resp),
                Ok(resp) => HttpError::Status {
                    service: SERVICE,
                    status: resp.status().as_u16(),
                },
                Err(e) => HttpError::from(e),
            };
            let retryable = match &err {
                HttpError::Status { status, .. } => RETRY_STATUSES.contains(status),
                HttpError::Transport(e) => e.is_connect(),
                _ => false,
            };
            if !retryable || attempt == MAX_RETRIES {
                return Err(err);
            }
            let wait = self.retry_backoff * 2u32.pow(attempt);
            attempt += 1;
            tracing::warn!(error = %err, attempt, ?wait, "retrying NVD request");
            tokio::time::sleep(wait).await;
        }
    }

    /// The newest CVEs whose CPE criteria match `match_string`, limited to `version` when given:
    /// 50 of all matches, or 100 of those in CISA KEV when `kev` is set. `total` is NVD's full
    /// count.
    pub async fn search_cves(
        &self,
        match_string: &str,
        version: Option<&str>,
        kev: bool,
    ) -> Result<CveSearch, HttpError> {
        let mut query = vec![("virtualMatchString", match_string), ("noRejected", "")];
        if kev {
            query.push(("hasKev", ""));
        }
        if let Some(v) = version {
            query.extend([
                ("versionStart", v),
                ("versionStartType", "including"),
                ("versionEnd", v),
                ("versionEndType", "including"),
            ]);
        }
        let page = if kev { KEV_PAGE } else { SEARCH_PAGE };
        self.newest(&query, page).await
    }

    /// The newest 50 CVEs whose description contains `phrase` and that NVD has not yet mapped
    /// to any product.
    pub async fn search_description(&self, phrase: &str) -> Result<Vec<NvdSummary>, HttpError> {
        let query = [
            ("keywordSearch", phrase),
            ("keywordExactMatch", ""),
            ("noRejected", ""),
        ];
        let search = self.newest(&query, SEARCH_PAGE).await?;
        Ok(search
            .records
            .into_iter()
            .filter(|s| s.affected_count == 0)
            .collect())
    }

    /// Counts the matches, then fetches only the last page, which NVD orders newest. Large pages
    /// of CPE-heavy records take NVD tens of seconds, so one small page keeps a call under a minute.
    async fn newest(&self, query: &[(&str, &str)], page: usize) -> Result<CveSearch, HttpError> {
        let total = self.count(query).await?;
        if total == 0 {
            return Ok(CveSearch {
                total,
                records: Vec::new(),
            });
        }
        let start = total.saturating_sub(page).to_string();
        let per_page = page.to_string();
        let page = [
            ("resultsPerPage", per_page.as_str()),
            ("startIndex", start.as_str()),
        ];
        let resp = self.send(&self.base_url, &[query, &page].concat()).await?;
        let body: NvdResponse = read_json(SERVICE, resp, SEARCH_MAX_BODY).await?;
        let records = body
            .vulnerabilities
            .into_iter()
            .map(|v| NvdSummary::from(v.cve))
            .collect();
        Ok(CveSearch { total, records })
    }

    /// Number of CVEs NVD has in CISA KEV whose CPE criteria match `match_string`, limited to
    /// `version` when given. One small request, unlike fetching the records.
    pub async fn count_kev(
        &self,
        match_string: &str,
        version: Option<&str>,
    ) -> Result<usize, HttpError> {
        let mut query = vec![
            ("virtualMatchString", match_string),
            ("noRejected", ""),
            ("hasKev", ""),
        ];
        if let Some(v) = version {
            query.extend([
                ("versionStart", v),
                ("versionStartType", "including"),
                ("versionEnd", v),
                ("versionEndType", "including"),
            ]);
        }
        self.count(&query).await
    }

    async fn count(&self, query: &[(&str, &str)]) -> Result<usize, HttpError> {
        let resp = self
            .send(
                &self.base_url,
                &[query, &[("resultsPerPage", "1")]].concat(),
            )
            .await?;
        Ok(read_json::<NvdResponse>(SERVICE, resp, SEARCH_MAX_BODY)
            .await?
            .total_results)
    }

    /// CPE dictionary entries matching `keyword`, grouped by part and product, largest first.
    pub async fn cpe_products(&self, keyword: &str) -> Result<Vec<CpeProduct>, HttpError> {
        let per_page = CPE_PAGE.to_string();
        let resp = self
            .send(
                &self.cpe_url,
                &[
                    ("keywordSearch", keyword),
                    ("resultsPerPage", per_page.as_str()),
                ],
            )
            .await?;
        let body: CpeResponse = read_json(SERVICE, resp, SEARCH_MAX_BODY).await?;
        let mut groups: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
        for p in body.products {
            let fields = cpe_fields(&p.cpe.cpe_name);
            if let (Some(part), Some(vendor), Some(product)) =
                (fields.get(2), fields.get(3), fields.get(4))
            {
                *groups
                    .entry((part.to_string(), product.to_string()))
                    .or_default()
                    .entry(vendor.to_string())
                    .or_default() += 1;
            }
        }
        let mut out: Vec<CpeProduct> = groups
            .into_iter()
            .map(|((part, product), vendors)| {
                let mut vendors: Vec<(String, usize)> = vendors.into_iter().collect();
                vendors.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                CpeProduct {
                    entries: vendors.iter().map(|v| v.1).sum(),
                    part,
                    product,
                    vendors: vendors.into_iter().map(|v| v.0).collect(),
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.entries
                .cmp(&a.entries)
                .then_with(|| a.product.cmp(&b.product))
        });
        Ok(out)
    }
}

pub struct CveSearch {
    pub total: usize,
    pub records: Vec<NvdSummary>,
}

/// One product in the CPE dictionary, with every vendor it appears under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeProduct {
    pub part: String,
    pub product: String,
    pub vendors: Vec<String>,
    pub entries: usize,
}

/// A claim on the gate for one CVE. Dropping the last claim removes the gate from the map,
/// including when the lookup future is cancelled.
struct InflightEntry<'a> {
    map: &'a Mutex<HashMap<String, Gate>>,
    key: &'a str,
    gate: Gate,
}

impl<'a> InflightEntry<'a> {
    fn join(map: &'a Mutex<HashMap<String, Gate>>, key: &'a str) -> Self {
        let gate = map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string())
            .or_default()
            .clone();
        Self { map, key, gate }
    }
}

impl Drop for InflightEntry<'_> {
    fn drop(&mut self) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        // The map holds one reference and this entry another; any more are other waiters.
        if Arc::strong_count(&self.gate) == 2 {
            map.remove(self.key);
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct NvdSummary {
    pub id: String,
    pub source_identifier: String,
    pub published: String,
    pub last_modified: String,
    pub vuln_status: String,
    pub description: String,
    /// Every CVSS score on the record: the NVD's own (`Primary`) first, then newest version first.
    pub cvss: Vec<Cvss>,
    /// CISA's SSVC decision, when CISA has published one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssvc: Option<Ssvc>,
    pub cwes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cisa_exploit_add: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cisa_action_due: Option<String>,
    /// Number of distinct vulnerable CPE matches before the cap on `affected`.
    pub affected_count: usize,
    /// Vulnerable CPE matches, at most 50: products the description names first, then version
    /// ranges and all-version matches, then single versions, then matches with no version (`-`).
    /// Platform-only matches are omitted.
    pub affected: Vec<AffectedProduct>,
    /// Number of distinct references tagged `Exploit`.
    pub exploit_reference_count: usize,
    pub reference_count: usize,
    /// At most 20 references: `Exploit` first, then `Vendor Advisory`, then the rest in NVD order.
    pub references: Vec<Reference>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Cvss {
    pub version: String,
    /// Absent when the record carries a vector without a score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<String>,
    /// `Primary` is the NVD's own assessment; `Secondary` comes from the CNA or another source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric_type: Option<String>,
    pub source: String,
    pub vector: String,
    /// NETWORK, ADJACENT_NETWORK or ADJACENT, LOCAL, or PHYSICAL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_vector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_complexity: Option<String>,
    /// NONE, LOW or HIGH. CVSS v3.x and v4.0 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges_required: Option<String>,
    /// NONE, SINGLE or MULTIPLE. CVSS v2 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<String>,
    /// NONE or REQUIRED in v2 and v3.x; NONE, PASSIVE or ACTIVE in v4.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_interaction: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Ssvc {
    /// `none`, `poc` (public proof of concept) or `active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploitation: Option<String>,
    /// `yes` or `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatable: Option<String>,
    /// `partial` or `total`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_impact: Option<String>,
    pub role: String,
    pub version: String,
    pub timestamp: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub struct AffectedProduct {
    pub cpe: String,
    pub vendor: String,
    pub product: String,
    /// `*` covers every version the range fields allow.
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_start_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_start_excluding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_end_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Reference {
    pub url: String,
    pub tags: Vec<String>,
}

impl From<RawCve> for NvdSummary {
    fn from(raw: RawCve) -> Self {
        let description = raw
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .or(raw.descriptions.first())
            .map(|d| d.value.clone())
            .unwrap_or_default();
        let metrics = raw.metrics.unwrap_or_default();
        let ssvc = metrics.ssvc_v203.into_iter().next().map(Ssvc::from);
        let mut cvss: Vec<Cvss> = [
            metrics.cvss_metric_v40,
            metrics.cvss_metric_v31,
            metrics.cvss_metric_v30,
            metrics.cvss_metric_v2,
        ]
        .into_iter()
        .flatten()
        .map(Cvss::from)
        .collect();
        cvss.sort_by_key(|c| c.metric_type.as_deref() != Some("Primary"));
        let (affected_count, affected) = affected_products(raw.configurations, &description);
        let mut cwes: Vec<String> = raw
            .weaknesses
            .iter()
            .flat_map(|w| w.description.iter())
            .map(|d| d.value.clone())
            .filter(|v| v.starts_with("CWE-"))
            .collect();
        cwes.sort();
        cwes.dedup();
        let mut references: Vec<Reference> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for r in raw.references {
            match index.get(&r.url) {
                Some(&i) => {
                    let tags = &mut references[i].tags;
                    for tag in r.tags {
                        if !tags.contains(&tag) {
                            tags.push(tag);
                        }
                    }
                }
                None => {
                    index.insert(r.url.clone(), references.len());
                    references.push(Reference {
                        url: r.url,
                        tags: r.tags,
                    });
                }
            }
        }
        references.sort_by_key(|r| reference_rank(&r.tags));
        let exploit_reference_count = references
            .iter()
            .filter(|r| r.tags.iter().any(|t| t == "Exploit"))
            .count();
        let reference_count = references.len();
        references.truncate(MAX_REFERENCES);
        Self {
            id: raw.id,
            source_identifier: raw.source_identifier,
            published: raw.published,
            last_modified: raw.last_modified,
            vuln_status: raw.vuln_status,
            description,
            cvss,
            ssvc,
            cwes,
            cisa_exploit_add: raw.cisa_exploit_add,
            cisa_action_due: raw.cisa_action_due,
            affected_count,
            affected,
            exploit_reference_count,
            reference_count,
            references,
        }
    }
}

impl From<RawMetric> for Cvss {
    fn from(m: RawMetric) -> Self {
        let d = m.cvss_data;
        Self {
            version: d.version,
            base_score: d.base_score,
            base_severity: d.base_severity.or(m.base_severity),
            metric_type: m.metric_type,
            source: m.source,
            vector: d.vector_string,
            attack_vector: d.attack_vector.or(d.access_vector),
            attack_complexity: d.attack_complexity.or(d.access_complexity),
            privileges_required: d.privileges_required,
            authentication: d.authentication,
            user_interaction: d.user_interaction.or(m
                .user_interaction_required
                .map(|r| if r { "REQUIRED" } else { "NONE" }.to_string())),
        }
    }
}

impl From<RawSsvc> for Ssvc {
    fn from(raw: RawSsvc) -> Self {
        let option = |key: &str| {
            raw.ssvc_data
                .options
                .iter()
                .find_map(|o| o.get(key))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        };
        Self {
            exploitation: option("exploitation"),
            automatable: option("automatable"),
            technical_impact: option("technicalImpact"),
            role: raw.ssvc_data.role.clone(),
            version: raw.ssvc_data.version.clone(),
            timestamp: raw.ssvc_data.timestamp.clone(),
            source: raw.source,
        }
    }
}

fn reference_rank(tags: &[String]) -> u8 {
    if tags.iter().any(|t| t == "Exploit") {
        0
    } else if tags.iter().any(|t| t == "Vendor Advisory") {
        1
    } else {
        2
    }
}

/// Returns the number of distinct vulnerable matches and the first `MAX_AFFECTED` of them.
fn affected_products(
    configurations: Vec<RawConfiguration>,
    description: &str,
) -> (usize, Vec<AffectedProduct>) {
    let mut seen = HashSet::new();
    let mut affected = Vec::new();
    for m in configurations
        .into_iter()
        .flat_map(|c| c.nodes)
        .flat_map(|n| n.cpe_match)
        .filter(|m| m.vulnerable)
    {
        let fields = cpe_fields(&m.criteria);
        let field = |i: usize| fields.get(i).copied().unwrap_or_default().to_string();
        let product = AffectedProduct {
            vendor: field(3),
            product: field(4),
            version: field(5),
            cpe: m.criteria.clone(),
            version_start_including: m.version_start_including,
            version_start_excluding: m.version_start_excluding,
            version_end_including: m.version_end_including,
            version_end_excluding: m.version_end_excluding,
        };
        if seen.insert(product.clone()) {
            affected.push(product);
        }
    }
    let count = affected.len();
    let description = description.to_lowercase();
    affected.sort_by_cached_key(|p| (!named_in(&description, &p.product), affected_rank(p)));
    affected.truncate(MAX_AFFECTED);
    (count, affected)
}

/// True when `product`, with underscores read as spaces, starts a word in the lowercase `text`.
fn named_in(text: &str, product: &str) -> bool {
    let name = product.replace('\\', "").replace('_', " ").to_lowercase();
    if name.len() < 3 {
        return false;
    }
    text.match_indices(&name).any(|(i, _)| {
        text[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Ranges and `*` describe a product line; a single version is narrower; `-` carries no version.
fn affected_rank(p: &AffectedProduct) -> u8 {
    let ranged = p.version_start_including.is_some()
        || p.version_start_excluding.is_some()
        || p.version_end_including.is_some()
        || p.version_end_excluding.is_some();
    match p.version.as_str() {
        _ if ranged => 0,
        "*" => 0,
        "-" | "" => 2,
        _ => 1,
    }
}

/// Splits a CPE 2.3 formatted string on colons that are not escaped with a backslash.
pub(crate) fn cpe_fields(cpe: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in cpe.char_indices() {
        match c {
            '\\' if !escaped => escaped = true,
            ':' if !escaped => {
                fields.push(&cpe[start..i]);
                start = i + 1;
            }
            _ => escaped = false,
        }
    }
    fields.push(&cpe[start..]);
    fields
}

#[derive(Deserialize)]
struct NvdResponse {
    #[serde(default, rename = "totalResults")]
    total_results: usize,
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Deserialize)]
struct CpeResponse {
    #[serde(default)]
    products: Vec<CpeEntry>,
}

#[derive(Deserialize)]
struct CpeEntry {
    cpe: CpeName,
}

#[derive(Deserialize)]
struct CpeName {
    #[serde(rename = "cpeName")]
    cpe_name: String,
}

#[derive(Deserialize)]
struct Vulnerability {
    cve: RawCve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCve {
    id: String,
    #[serde(default)]
    source_identifier: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    last_modified: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<LangValue>,
    metrics: Option<RawMetrics>,
    #[serde(default)]
    weaknesses: Vec<Weakness>,
    #[serde(default)]
    references: Vec<RawReference>,
    #[serde(default)]
    configurations: Vec<RawConfiguration>,
    cisa_exploit_add: Option<String>,
    cisa_action_due: Option<String>,
}

#[derive(Deserialize)]
struct LangValue {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawMetrics {
    #[serde(default)]
    cvss_metric_v40: Vec<RawMetric>,
    #[serde(default)]
    cvss_metric_v31: Vec<RawMetric>,
    #[serde(default)]
    cvss_metric_v30: Vec<RawMetric>,
    #[serde(default)]
    cvss_metric_v2: Vec<RawMetric>,
    #[serde(default, rename = "ssvcV203")]
    ssvc_v203: Vec<RawSsvc>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetric {
    #[serde(default)]
    source: String,
    #[serde(rename = "type")]
    metric_type: Option<String>,
    base_severity: Option<String>,
    user_interaction_required: Option<bool>,
    cvss_data: RawCvssData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCvssData {
    #[serde(default)]
    version: String,
    #[serde(default)]
    vector_string: String,
    base_score: Option<f64>,
    base_severity: Option<String>,
    attack_vector: Option<String>,
    access_vector: Option<String>,
    attack_complexity: Option<String>,
    access_complexity: Option<String>,
    privileges_required: Option<String>,
    authentication: Option<String>,
    user_interaction: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSsvc {
    #[serde(default)]
    source: String,
    ssvc_data: RawSsvcData,
}

#[derive(Deserialize)]
struct RawSsvcData {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    options: Vec<HashMap<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct RawConfiguration {
    #[serde(default)]
    nodes: Vec<RawNode>,
}

#[derive(Deserialize)]
struct RawNode {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<RawCpeMatch>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCpeMatch {
    #[serde(default)]
    vulnerable: bool,
    #[serde(default)]
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

#[derive(Deserialize)]
struct Weakness {
    #[serde(default)]
    description: Vec<LangValue>,
}

#[derive(Deserialize)]
struct RawReference {
    url: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(json: &str) -> NvdSummary {
        NvdSummary::from(serde_json::from_str::<RawCve>(json).unwrap())
    }

    #[test]
    fn orders_nvd_primary_score_before_newer_cna_scores() {
        let s = summary(
            r#"{"id":"CVE-2024-0001","metrics":{
                "cvssMetricV40":[{"source":"cna@example.com","type":"Secondary","cvssData":{"version":"4.0","vectorString":"CVSS:4.0/AV:N","baseScore":9.3,"baseSeverity":"CRITICAL","attackVector":"NETWORK","privilegesRequired":"NONE","userInteraction":"PASSIVE"}}],
                "cvssMetricV31":[
                    {"source":"cna@example.com","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":9.8,"baseSeverity":"CRITICAL"}},
                    {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:L","baseScore":7.8,"baseSeverity":"HIGH","attackVector":"LOCAL","attackComplexity":"LOW","privilegesRequired":"LOW","userInteraction":"NONE"}}]}}"#,
        );
        let order: Vec<(&str, &str)> = s
            .cvss
            .iter()
            .map(|c| (c.version.as_str(), c.source.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("3.1", "nvd@nist.gov"),
                ("4.0", "cna@example.com"),
                ("3.1", "cna@example.com")
            ]
        );
        let nvd = &s.cvss[0];
        assert_eq!(nvd.attack_vector.as_deref(), Some("LOCAL"));
        assert_eq!(nvd.attack_complexity.as_deref(), Some("LOW"));
        assert_eq!(nvd.privileges_required.as_deref(), Some("LOW"));
        assert_eq!(nvd.user_interaction.as_deref(), Some("NONE"));
        assert_eq!(s.cvss[1].user_interaction.as_deref(), Some("PASSIVE"));
        assert!(summary(r#"{"id":"CVE-2024-0001"}"#).cvss.is_empty());
    }

    #[test]
    fn maps_cvss_v2_fields() {
        let s = summary(
            r#"{"id":"CVE-2010-0001","metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","baseSeverity":"HIGH","userInteractionRequired":false,
                "cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P","baseScore":7.5,"accessVector":"NETWORK","accessComplexity":"LOW","authentication":"NONE"}}]}}"#,
        );
        let v2 = &s.cvss[0];
        assert_eq!(v2.base_severity.as_deref(), Some("HIGH"));
        assert_eq!(v2.attack_vector.as_deref(), Some("NETWORK"));
        assert_eq!(v2.attack_complexity.as_deref(), Some("LOW"));
        assert_eq!(v2.authentication.as_deref(), Some("NONE"));
        assert_eq!(v2.user_interaction.as_deref(), Some("NONE"));
        assert!(v2.privileges_required.is_none());
    }

    #[test]
    fn reads_cisa_ssvc_decision() {
        let s = summary(
            r#"{"id":"CVE-2024-6387","metrics":{"ssvcV203":[{"source":"134c704f-9b21-4f2e-91b3-4a467353bcc0",
                "ssvcData":{"timestamp":"2024-07-02T13:18:34.695298Z","id":"CVE-2024-6387","options":[{"exploitation":"poc"},{"automatable":"no"},{"technicalImpact":"total"}],"role":"CISA Coordinator","version":"2.0.3"}}]}}"#,
        );
        let ssvc = s.ssvc.unwrap();
        assert_eq!(ssvc.exploitation.as_deref(), Some("poc"));
        assert_eq!(ssvc.automatable.as_deref(), Some("no"));
        assert_eq!(ssvc.technical_impact.as_deref(), Some("total"));
        assert_eq!(ssvc.role, "CISA Coordinator");
        assert!(summary(r#"{"id":"CVE-2024-0001"}"#).ssvc.is_none());
    }

    #[test]
    fn ranks_exploit_then_advisory_references_and_dedups_by_url() {
        let mut refs: Vec<String> = (0..30)
            .map(|i| format!(r#"{{"url":"https://other.example/{i}"}}"#))
            .collect();
        refs.push(r#"{"url":"https://vendor.example/a","tags":["Vendor Advisory"]}"#.into());
        refs.push(r#"{"url":"https://poc.example/1","tags":["Third Party Advisory"]}"#.into());
        refs.push(r#"{"url":"https://poc.example/1","tags":["Exploit"]}"#.into());
        refs.push(r#"{"url":"https://poc.example/2","tags":["Exploit"]}"#.into());
        let s = summary(&format!(
            r#"{{"id":"CVE-2024-0001","references":[{}]}}"#,
            refs.join(",")
        ));
        assert_eq!(s.reference_count, 33);
        assert_eq!(s.exploit_reference_count, 2);
        assert_eq!(s.references.len(), MAX_REFERENCES);
        let urls: Vec<&str> = s.references.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(
            urls[..4],
            [
                "https://poc.example/1",
                "https://poc.example/2",
                "https://vendor.example/a",
                "https://other.example/0"
            ]
        );
        assert_eq!(
            s.references[0].tags,
            vec!["Third Party Advisory", "Exploit"]
        );
    }

    #[test]
    fn missing_base_score_stays_absent_and_nulls_are_not_serialized() {
        let s = summary(
            r#"{"id":"CVE-2024-0001","metrics":{"cvssMetricV31":[{"source":"cna@example.com","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N"}}]},
                "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}]}"#,
        );
        assert_eq!(s.cvss[0].base_score, None);
        let json = serde_json::to_value(&s).unwrap();
        assert!(json["cvss"][0].get("base_score").is_none());
        assert!(json["cvss"][0].get("attack_vector").is_none());
        assert!(json.get("ssvc").is_none());
        assert!(json["affected"][0].get("version_end_excluding").is_none());
        assert_eq!(json["affected"][0]["version"], "1.0");
    }

    #[test]
    fn product_must_start_a_word_in_the_description() {
        let text = "apache log4j2 jndi features. openssh's server. streaming videos. web os.";
        assert!(named_in(text, "log4j"));
        assert!(named_in(text, "openssh"));
        assert!(named_in(text, "streaming_videos"));
        assert!(
            !named_in(text, "eos"),
            "eos inside videos is not a word start"
        );
        assert!(
            !named_in(text, "os"),
            "names under three characters never match"
        );
        assert!(!named_in(text, "6bk1602-0aa12-0tp0_firmware"));
    }

    #[test]
    fn orders_products_named_in_the_description_first() {
        let s = summary(
            r#"{"id":"CVE-2021-44228","descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI features do not protect against attacker controlled endpoints."}],
                "configurations":[{"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:o:siemens:6bk1602-0aa12-0tp0_firmware:*:*:*:*:*:*:*:*","versionEndExcluding":"2.7.0"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:cisco:webex:-:*:*:*:*:*:*:*"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionStartIncluding":"2.13.0","versionEndExcluding":"2.15.0"}]}]}]}"#,
        );
        let order: Vec<(&str, &str)> = s
            .affected
            .iter()
            .map(|a| (a.product.as_str(), a.version.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("log4j", "*"),
                ("log4j", "2.0"),
                ("6bk1602-0aa12-0tp0_firmware", "*"),
                ("webex", "-")
            ]
        );
    }

    #[test]
    fn orders_ranged_matches_before_single_versions_and_unversioned_ones() {
        let s = summary(
            r#"{"id":"CVE-2024-0001","configurations":[{"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:o:acme:router_firmware:-:*:*:*:*:*:*:*"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"}]}]}]}"#,
        );
        let order: Vec<(&str, &str)> = s
            .affected
            .iter()
            .map(|a| (a.product.as_str(), a.version.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("widget", "*"),
                ("gadget", "*"),
                ("widget", "1.0"),
                ("router_firmware", "-")
            ]
        );
    }

    #[test]
    fn lists_distinct_vulnerable_cpe_matches_up_to_the_cap() {
        let mut matches = vec![
            r#"{"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*","versionStartIncluding":"8.5","versionEndExcluding":"9.8"}"#.to_string(),
            r#"{"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*","versionStartIncluding":"8.5","versionEndExcluding":"9.8"}"#.to_string(),
            r#"{"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}"#.to_string(),
            r#"{"vulnerable":true,"criteria":"cpe:2.3:a:acme:web\\:server:1.0:*:*:*:*:*:*:*"}"#.to_string(),
        ];
        matches.extend((0..60).map(|i| {
            format!(
                r#"{{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:{i}.0:*:*:*:*:*:*:*"}}"#
            )
        }));
        let s = summary(&format!(
            r#"{{"id":"CVE-2024-6387","configurations":[{{"nodes":[{{"operator":"OR","cpeMatch":[{}]}}]}}]}}"#,
            matches.join(",")
        ));
        assert_eq!(s.affected_count, 62);
        assert_eq!(s.affected.len(), MAX_AFFECTED);
        let ssh = &s.affected[0];
        assert_eq!(
            (ssh.vendor.as_str(), ssh.product.as_str()),
            ("openbsd", "openssh")
        );
        assert_eq!(ssh.version, "*");
        assert_eq!(ssh.version_start_including.as_deref(), Some("8.5"));
        assert_eq!(ssh.version_end_excluding.as_deref(), Some("9.8"));
        assert_eq!(s.affected[1].product, r"web\:server");
        assert_eq!(s.affected[1].version, "1.0");
        assert!(s.affected.iter().all(|a| a.vendor != "linux"));
    }
}
