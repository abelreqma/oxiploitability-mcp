use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::NVD_NOTICE;
use crate::cna::{CnaClient, CveOrgSummary};
use crate::component::Component;
use crate::cve::{BatchError, CveId};
use crate::epss::{EpssBatch, EpssClient, EpssScore};
use crate::http::HttpError;
use crate::impact::{self, Impact};
use crate::kev::{KevBatch, KevCatalog, KevEntry};
use crate::lookup::{
    ProductAnswer, ScanAnswer, ScanTarget, Sources, kev_text, nvd_vector, product_cves, scan_sbom,
    summary_line,
};
use crate::nvd::{NvdClient, NvdSummary};
use crate::osv::OsvClient;
use crate::poc::{self, CAUTION, PocClient, PocRepo};

const ENRICH_POC_REPOS: usize = 10;
const ENRICH_CONCURRENCY: usize = 8;
/// NVD allows 50 requests per 30 s with a key, so 100 CVEs need just over 30 s plus NVD's own
/// response time.
const ENRICH_NVD_DEADLINE: Duration = Duration::from_secs(40);
const ENRICH_POC_DEADLINE: Duration = Duration::from_secs(15);
/// Runs after the NVD phase; both together stay under the usual 60 s MCP client timeout.
const ENRICH_CVE_ORG_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Oxiploitability {
    nvd: Arc<NvdClient>,
    epss: Arc<EpssClient>,
    kev: Arc<KevCatalog>,
    osv: Arc<OsvClient>,
    cna: Arc<CnaClient>,
    poc: Arc<PocClient>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CveParam {
    /// A CVE identifier such as CVE-2023-38606. Case-insensitive.
    pub cve_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CveListParam {
    /// Up to 100 CVE identifiers such as CVE-2023-38606. Case-insensitive.
    pub cve_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProductParam {
    /// A product name such as "nginx" or "Apache Tomcat", a package URL such as
    /// pkg:npm/lodash@4.17.20, or a CPE 2.3 string.
    pub product: String,
    /// Only CVEs affecting this version. Omit for the product's full history.
    pub version: Option<String>,
    /// Package ecosystem when `product` is a package name: npm, PyPI, Maven, Go, crates.io,
    /// RubyGems, NuGet, Packagist and others OSV supports.
    pub ecosystem: Option<String>,
    /// Findings to return, 1 to 100. Defaults to 25.
    pub limit: Option<u32>,
    /// Return each finding's full description instead of its first sentence.
    pub detail: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PocParam {
    /// A CVE identifier such as CVE-2017-0144. Case-insensitive.
    pub cve_id: String,
    /// Repositories to return, 1 to 100. Defaults to 25; `total` counts all of them.
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PocAnswer {
    pub cve_id: String,
    /// Number of repositories listed for the CVE.
    pub total: usize,
    /// Most starred first.
    pub repos: Vec<PocRepo>,
    /// The index the repositories came from.
    pub source: String,
    pub caution: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SbomParam {
    /// Path on this machine to a CycloneDX JSON, SPDX JSON or SPDX tag-value SBOM, or to a
    /// lockfile: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements*.txt, poetry.lock,
    /// Pipfile.lock, uv.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock,
    /// packages.lock.json or gradle.lockfile. A project directory is searched for those files and
    /// for SBOMs named bom.json, sbom.json, *.cdx.json, *.spdx.json or *.spdx. Give this or
    /// `image`.
    pub path: Option<String>,
    /// A container image reference such as nginx:1.25 or ghcr.io/org/app:tag, read with Trivy or
    /// Syft. Give this or `path`.
    pub image: Option<String>,
    /// Findings to return, 1 to 100. Defaults to 25; the report file holds all of them.
    pub limit: Option<u32>,
    /// Return each finding's full description instead of its first sentence.
    pub detail: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct NvdResult {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<NvdSummary>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnrichParam {
    /// One CVE identifier such as CVE-2021-44228. Case-insensitive. Give this, `cve_ids`, or
    /// both.
    pub cve_id: Option<String>,
    /// Up to 100 CVE identifiers. Case-insensitive; duplicates are checked once.
    pub cve_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EnrichAnswer {
    /// The full record's fields, at the top level, when one CVE was asked for.
    #[serde(flatten)]
    pub record: Option<Enrichment>,
    /// One compact row per CVE in request order, when several were asked for; enrich_cve with
    /// one of them returns its full record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<EnrichRow>,
    /// CVEs whose NVD record could not be read in time or does not exist, so their record comes
    /// from CVE.org.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_cve_org: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// One CVE's signals in a batch. Fields other than `cve_id`, `in_kev`, `summary`, `source` and
/// `url` are omitted when empty.
#[derive(Debug, Serialize, JsonSchema)]
pub struct EnrichRow {
    pub cve_id: String,
    /// True when CISA lists the CVE as known exploited; null when that cannot be determined.
    pub in_kev: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_date_added: Option<String>,
    /// `Known` when CISA lists the CVE as used in ransomware campaigns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ransomware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f64>,
    /// The record's first CVSS score: NVD's own when it has one, else the CNA's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_severity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwes: Vec<String>,
    /// Each impact with its evidence, such as `RCE (CWE-502)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impact: Vec<String>,
    /// Public PoC repositories the index lists; absent when the index could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc_repos: Option<usize>,
    /// The description's first sentence.
    pub summary: String,
    /// `nvd`, `cve.org`, or `none` when neither record could be read.
    pub source: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Fields other than `cve_id` and `in_kev` are omitted when empty.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Enrichment {
    pub cve_id: String,
    /// True when CISA lists the CVE as known exploited. When the KEV catalog cannot be read,
    /// true if the NVD record carries a CISA listing date, otherwise null.
    pub in_kev: Option<bool>,
    /// What an attacker gains, such as RCE or DoS, derived from the CWE ids, description or
    /// CVSS vector of the NVD record, or of the CVE.org record when NVD's is missing, rather
    /// than stated by either.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impact: Vec<Impact>,
    /// The CVE.org record, given when the NVD record is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_org: Option<CveOrgSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_org_error: Option<String>,
    /// The most starred public PoC repositories from the nomi-sec/PoC-in-GitHub index, with the
    /// total count; `total` is 0 when the index lists none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc: Option<PocAnswer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvd: Option<NvdSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvd_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<EpssScore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev: Option<KevEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_error: Option<String>,
}

#[tool_router]
impl Oxiploitability {
    pub fn new(
        nvd: NvdClient,
        epss: EpssClient,
        kev: KevCatalog,
        osv: OsvClient,
        cna: CnaClient,
        poc: PocClient,
    ) -> Self {
        Self {
            nvd: Arc::new(nvd),
            epss: Arc::new(epss),
            kev: Arc::new(kev),
            osv: Arc::new(osv),
            cna: Arc::new(cna),
            poc: Arc::new(poc),
            tool_router: Self::tool_router() + Self::lookup_router(),
        }
    }

    #[tool(
        name = "nvd_cve",
        annotations(read_only_hint = true, open_world_hint = true),
        description = "Fetch only the NIST NVD record for one CVE: description, every CVSS score (NVD and CNA) with attack vector, privileges required and user interaction, CISA's SSVC decision (exploitation none/poc/active, automatable, technical impact), affected products as CPE matches with version ranges, CWEs, dates, and references with exploit links first. Rate limited by NVD. enrich_cve returns this record plus EPSS, KEV, impact and public PoCs in one call and is the default."
    )]
    pub async fn nvd_cve(
        &self,
        Parameters(CveParam { cve_id }): Parameters<CveParam>,
    ) -> Result<Json<NvdResult>, String> {
        let id = parse_one(&cve_id)?;
        let cve = self.nvd.lookup(&id).await.map_err(upstream)?;
        Ok(Json(NvdResult {
            found: cve.is_some(),
            cve,
        }))
    }

    #[tool(
        name = "epss_scores",
        annotations(read_only_hint = true, open_world_hint = true),
        description = "Fetch FIRST EPSS scores for up to 100 CVEs: the probability (0 to 1) that each is exploited in the wild within the next 30 days, plus its percentile among all scored CVEs."
    )]
    pub async fn epss_scores(
        &self,
        Parameters(CveListParam { cve_ids }): Parameters<CveListParam>,
    ) -> Result<Json<EpssBatch>, String> {
        let ids = parse_many(&cve_ids)?;
        Ok(Json(self.epss.scores(&ids).await.map_err(upstream)?))
    }

    #[tool(
        name = "kev_lookup",
        annotations(read_only_hint = true, open_world_hint = true),
        description = "Check up to 100 CVEs against the CISA Known Exploited Vulnerabilities catalog. Returns the catalog entry (date added, due date, required action, ransomware use) for each listed CVE."
    )]
    pub async fn kev_lookup(
        &self,
        Parameters(CveListParam { cve_ids }): Parameters<CveListParam>,
    ) -> Result<Json<KevBatch>, String> {
        let ids = parse_many(&cve_ids)?;
        Ok(Json(self.kev.lookup(&ids).await.map_err(upstream)?))
    }

    #[tool(
        name = "enrich_cve",
        annotations(read_only_hint = true, open_world_hint = true),
        description = "The default tool for any question about one or more CVEs, up to 100 per call. Combines nvd_cve, epss_scores, kev_lookup and poc_search. For one CVE, the answer is the full record at the top level: the NVD record (CVSS scores, CISA SSVC decision, affected products, CWE, exploit references), the impact (RCE, DoS, privilege escalation and others, derived from the CWE ids, description or CVSS vector with the evidence for each), the FIRST EPSS probability and percentile, the CISA KEV entry, and the most starred public PoC repositories with their total. For several, rows holds one compact row per CVE in request order (KEV, ransomware use, EPSS, CVSS, CWEs, impact with evidence, PoC count, first sentence of the description and the record's link) to triage from; call again with one CVE for its full record. NVD is asked for up to 40 s; CVEs it does not answer in time, or has no record for, use their CVE.org record (CNA and CISA ADP data) instead and are listed in from_cve_org. Each source is best-effort; a failure is reported in an *_error field or errors while the others still return, and in_kev is null when KEV membership cannot be determined. PoC repositories are unvetted and some are malicious: review them and run them only in an isolated lab."
    )]
    pub async fn enrich_cve(
        &self,
        Parameters(p): Parameters<EnrichParam>,
    ) -> Result<Json<EnrichAnswer>, String> {
        let raw: Vec<String> = p
            .cve_id
            .into_iter()
            .chain(p.cve_ids.unwrap_or_default())
            .collect();
        let ids = parse_many(&raw)?;
        Ok(Json(self.enrich(ids).await))
    }
}

#[tool_router(router = lookup_router, vis = "pub")]
impl Oxiploitability {
    #[tool(
        name = "product_cves",
        annotations(read_only_hint = true, open_world_hint = true),
        description = "List known CVEs for a product or package, optionally at one version, with CVSS, CISA KEV status and EPSS for each, ranked known-exploited first, then EPSS, then CVSS. Accepts a product name (\"nginx\", \"Apache Tomcat\"), a package URL, a CPE 2.3 string, or a package name plus ecosystem. Product names are matched through NVD; packages through OSV. Well-known vulnerability nicknames such as EternalBlue, Log4Shell or Dirty Pipe resolve to their CVEs. CVEs NVD has not mapped to products yet are found by description and checked against the CVE.org record: confirmed when it names the product and version, listed under other_products when it names a different product, and marked confirmed: false otherwise. An ambiguous name returns candidates instead. The action field gives the installed version, candidate fixed versions, the upgrade that clears every advisory with a listed fix, KEV, EPSS and PoC signals, and what still needs verification. in_kev is null when the KEV catalog could not be read. Use enrich_cve for full detail on one CVE. Without a version, products with thousands of CVEs (Windows, Linux kernel) return only the newest CVEs, marked partial."
    )]
    pub async fn product_cves(
        &self,
        Parameters(p): Parameters<ProductParam>,
    ) -> Result<Json<ProductAnswer>, String> {
        let component = to_component(p.product, p.version, p.ecosystem);
        let sources = self.sources();
        let lookup = product_cves(
            &sources,
            &component,
            limit(p.limit),
            p.detail.unwrap_or(false),
        );
        // Answers before the usual 60 s MCP client timeout when NVD is slow.
        match tokio::time::timeout(Duration::from_secs(50), lookup).await {
            Ok(answer) => Ok(Json(answer?)),
            Err(_) => Err(
                "NVD did not answer within 50 s; try again, or give a version to narrow the search"
                    .to_string(),
            ),
        }
    }

    #[tool(
        name = "scan_sbom",
        annotations(read_only_hint = false, open_world_hint = true),
        description = "Check every component of an SBOM (CycloneDX JSON, SPDX JSON or SPDX tag-value), a lockfile, a project directory, or a container image for known CVEs. A directory is searched for lockfiles and SBOMs, skipping hidden and dependency directories, and each result names the files that list the component. Packages are checked through OSV, other components through NVD. Returns one action per vulnerable component (installed version, advisories with source links, KEV, EPSS, whether the PoC index lists a public exploit, candidate fixed versions, the upgrade that clears them, and what still needs verification), the top findings ranked known-exploited first, then EPSS, then CVSS, checked and unchecked component counts, and the components that could not be checked with the reason. in_kev is null when the KEV catalog could not be read. Creates a new report next to the file, in the scanned directory, or in the temp directory for an image; existing reports are preserved and repeat scans get numbered names. Image scans need Trivy or Syft installed."
    )]
    pub async fn scan_sbom(
        &self,
        Parameters(p): Parameters<SbomParam>,
    ) -> Result<Json<ScanAnswer>, String> {
        let target = match (p.path.as_deref(), p.image.as_deref()) {
            (Some(path), None) => ScanTarget::File(path),
            (None, Some(image)) => ScanTarget::Image(image),
            _ => return Err("give exactly one of path or image".to_string()),
        };
        Ok(Json(
            scan_sbom(
                &self.sources(),
                target,
                limit(p.limit),
                p.detail.unwrap_or(false),
            )
            .await?,
        ))
    }

    #[tool(
        name = "poc_search",
        annotations(read_only_hint = true, open_world_hint = true),
        description = "Find public proof-of-concept exploit repositories on GitHub for one CVE, from the nomi-sec/PoC-in-GitHub index. Returns each repository's URL, description, stars, forks and dates, most starred first, plus the total count. The repositories are not vetted and some are fake or malicious: treat them as leads to review, never run them outside an isolated lab. Resolve a nickname such as EternalBlue to its CVE ids with product_cves first."
    )]
    pub async fn poc_search(
        &self,
        Parameters(p): Parameters<PocParam>,
    ) -> Result<Json<PocAnswer>, String> {
        let id = parse_one(&p.cve_id)?;
        let repos = self.poc.search(&id).await.map_err(upstream)?;
        Ok(Json(poc_answer(&id, repos, limit(p.limit))))
    }
}

fn row(e: &Enrichment) -> EnrichRow {
    let (description, score, severity, cwes, source, url) = match (&e.nvd, &e.cve_org) {
        (Some(n), _) => (
            n.description.as_str(),
            n.cvss.first().and_then(|c| c.base_score),
            n.cvss.first().and_then(|c| c.base_severity.clone()),
            n.cwes.clone(),
            "nvd",
            format!("https://nvd.nist.gov/vuln/detail/{}", e.cve_id),
        ),
        (None, Some(o)) => (
            o.description.as_str(),
            o.cvss.first().and_then(|c| c.base_score),
            o.cvss.first().and_then(|c| c.base_severity.clone()),
            o.cwes.clone(),
            "cve.org",
            o.url.clone(),
        ),
        (None, None) => (
            "",
            None,
            None,
            Vec::new(),
            "none",
            format!("https://www.cve.org/CVERecord?id={}", e.cve_id),
        ),
    };
    let mut errors = Vec::new();
    if e.nvd.is_none() && e.cve_org.is_none() {
        errors.extend(e.nvd_error.iter().map(|m| format!("NVD: {m}")));
        errors.extend(e.cve_org_error.iter().map(|m| format!("CVE.org: {m}")));
    }
    errors.extend(e.poc_error.iter().map(|m| format!("PoC index: {m}")));
    EnrichRow {
        cve_id: e.cve_id.clone(),
        in_kev: e.in_kev,
        kev_date_added: e.kev.as_ref().map(|k| k.date_added.clone()),
        ransomware: e
            .kev
            .as_ref()
            .map(|k| k.known_ransomware_campaign_use.clone())
            .filter(|r| r == "Known"),
        epss: e.epss.as_ref().map(|s| s.epss),
        epss_percentile: e.epss.as_ref().map(|s| s.percentile),
        cvss_score: score,
        cvss_severity: severity,
        cwes,
        impact: e
            .impact
            .iter()
            .map(|i| format!("{} ({})", i.kind, i.evidence))
            .collect(),
        poc_repos: e.poc.as_ref().map(|p| p.total),
        summary: summary_line(description),
        source: source.to_string(),
        url,
        errors,
    }
}

/// Runs `fetch` for every id, at most `ENRICH_CONCURRENCY` at a time, and returns the results
/// that finished before `deadline`, keyed by CVE id.
async fn fan_out<T, F, Fut>(
    ids: &[CveId],
    deadline: Duration,
    fetch: F,
) -> HashMap<String, Result<T, HttpError>>
where
    F: Fn(CveId) -> Fut,
    Fut: Future<Output = Result<T, HttpError>> + Send + 'static,
    T: Send + 'static,
{
    let gate = Arc::new(Semaphore::new(ENRICH_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for id in ids {
        let (key, work, gate) = (id.as_str().to_string(), fetch(id.clone()), gate.clone());
        tasks.spawn(async move {
            let _permit = gate.acquire_owned().await;
            (key, work.await)
        });
    }
    let mut out = HashMap::new();
    let collect = async {
        while let Some(joined) = tasks.join_next().await {
            if let Ok((key, result)) = joined {
                out.insert(key, result);
            }
        }
    };
    let _ = tokio::time::timeout(deadline, collect).await;
    out
}

fn poc_answer(id: &CveId, mut repos: Vec<PocRepo>, limit: usize) -> PocAnswer {
    let total = repos.len();
    repos.truncate(limit);
    PocAnswer {
        cve_id: id.as_str().to_string(),
        total,
        repos,
        source: poc::index_url(id),
        caution: CAUTION.to_string(),
    }
}

impl Oxiploitability {
    async fn enrich(&self, ids: Vec<CveId>) -> EnrichAnswer {
        let batch = ids.len() > 1;
        let (nvd, poc, epss, kev) = {
            let (nvd, poc) = (self.nvd.clone(), self.poc.clone());
            tokio::join!(
                fan_out(&ids, ENRICH_NVD_DEADLINE, move |id| {
                    let nvd = nvd.clone();
                    async move { nvd.lookup(&id).await }
                }),
                fan_out(&ids, ENRICH_POC_DEADLINE, move |id| {
                    let poc = poc.clone();
                    async move { poc.search(&id).await }
                }),
                self.epss.scores(&ids),
                self.kev.lookup(&ids)
            )
        };
        let mut warnings = Vec::new();
        let missing: Vec<CveId> = ids
            .iter()
            .filter(|id| !matches!(nvd.get(id.as_str()), Some(Ok(Some(_)))))
            .cloned()
            .collect();
        let unanswered = ids
            .iter()
            .filter(|id| !nvd.contains_key(id.as_str()))
            .count();
        if unanswered > 0 {
            warnings.push(format!(
                "NVD answered {} of {} CVEs within {} s at {} requests per 30 s; the rest use their CVE.org record, and a repeat call fetches them from NVD",
                ids.len() - unanswered,
                ids.len(),
                ENRICH_NVD_DEADLINE.as_secs(),
                self.nvd.requests_per_window()
            ));
        }
        let cna = (*self.cna).clone();
        let cve_org = fan_out(&missing, ENRICH_CVE_ORG_DEADLINE, move |id| {
            let cna = cna.clone();
            async move { cna.summary(id.as_str()).await }
        })
        .await;
        let (epss, epss_error) = split(epss);
        let (kev, kev_error) = split(kev);
        if batch {
            warnings.extend(epss_error.iter().map(|e| format!("EPSS unavailable: {e}")));
            warnings.extend(kev_error.iter().map(|e| {
                format!("KEV unavailable, so in_kev is null unless NVD records a CISA listing: {e}")
            }));
        }

        let mut nvd = nvd;
        let mut poc = poc;
        let mut cve_org = cve_org;
        let mut from_cve_org = Vec::new();
        let results: Vec<Enrichment> = ids
            .iter()
            .map(|id| {
                let key = id.as_str();
                let (record, nvd_error) = match nvd.remove(key) {
                    Some(Ok(Some(n))) => (Some(n), None),
                    Some(Ok(None)) => (None, Some("NVD has no record for this CVE".to_string())),
                    Some(Err(e)) => (None, Some(e.to_string())),
                    None => (
                        None,
                        Some(format!(
                            "NVD did not answer within {} s",
                            ENRICH_NVD_DEADLINE.as_secs()
                        )),
                    ),
                };
                let (org, cve_org_error) = match (&record, cve_org.remove(key)) {
                    (Some(_), _) => (None, None),
                    (None, Some(Ok(Some(s)))) => (Some(s), None),
                    (None, Some(Ok(None))) => {
                        (None, Some("CVE.org has no record for this CVE".to_string()))
                    }
                    (None, Some(Err(e))) => (None, Some(e.to_string())),
                    (None, None) => (
                        None,
                        Some(format!(
                            "CVE.org did not answer within {} s",
                            ENRICH_CVE_ORG_DEADLINE.as_secs()
                        )),
                    ),
                };
                if org.is_some() {
                    from_cve_org.push(key.to_string());
                }
                let mut impact = match (&record, &org) {
                    (Some(n), _) => impact::classify(&n.cwes, &n.description, nvd_vector(n)),
                    (None, Some(o)) => impact::classify(
                        &o.cwes,
                        &o.description,
                        o.cvss
                            .iter()
                            .map(|c| c.vector.as_str())
                            .find(|v| !v.is_empty()),
                    ),
                    (None, None) => Vec::new(),
                };
                let kev_entry = kev
                    .as_ref()
                    .map(|b| b.listed.iter().find(|k| k.cve_id == key).cloned());
                if let Some(Some(k)) = &kev_entry {
                    impact::refine(&mut impact, "CISA KEV", &kev_text(k));
                }
                let in_kev = match &kev_entry {
                    Some(entry) => Some(entry.is_some()),
                    None => record
                        .as_ref()
                        .and_then(|n| n.cisa_exploit_add.as_ref())
                        .map(|_| true),
                };
                let (poc, poc_error) = match poc.remove(key) {
                    Some(Ok(list)) => (Some(poc_answer(id, list, ENRICH_POC_REPOS)), None),
                    Some(Err(e)) => (None, Some(e.to_string())),
                    None => (
                        None,
                        Some(format!(
                            "the PoC index did not answer within {} s",
                            ENRICH_POC_DEADLINE.as_secs()
                        )),
                    ),
                };
                Enrichment {
                    cve_id: key.to_string(),
                    in_kev,
                    impact,
                    cve_org: org,
                    cve_org_error,
                    poc,
                    poc_error,
                    nvd: record,
                    nvd_error,
                    epss: epss
                        .as_ref()
                        .and_then(|b| b.scores.iter().find(|s| s.cve == key).cloned()),
                    epss_error: epss_error.clone(),
                    kev: kev_entry.flatten(),
                    kev_error: kev_error.clone(),
                }
            })
            .collect();
        let (record, rows) = match batch {
            true => (None, results.iter().map(row).collect()),
            false => (results.into_iter().next(), Vec::new()),
        };
        EnrichAnswer {
            record,
            rows,
            from_cve_org,
            warnings,
        }
    }

    fn sources(&self) -> Sources<'_> {
        Sources {
            nvd: &self.nvd,
            epss: &self.epss,
            kev: &self.kev,
            osv: &self.osv,
            cna: &self.cna,
            poc: &self.poc,
        }
    }
}

fn limit(raw: Option<u32>) -> usize {
    raw.unwrap_or(25).clamp(1, 100) as usize
}

fn to_component(product: String, version: Option<String>, ecosystem: Option<String>) -> Component {
    let product = product.trim().to_string();
    let (purl, cpe) = if product.starts_with("pkg:") {
        (Some(product.clone()), None)
    } else if product.starts_with("cpe:") {
        (None, Some(product.clone()))
    } else {
        (None, None)
    };
    Component {
        name: product,
        version,
        purl,
        cpe,
        ecosystem,
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Oxiploitability {
    fn get_info(&self) -> ServerConfig {
        let key_note = if self.nvd.has_api_key() {
            format!(
                "An NVD API key is configured ({} NVD requests per 30 s).",
                self.nvd.requests_per_window()
            )
        } else {
            format!(
                "No NVD API key is configured ({} NVD requests per 30 s). Set NVD_API to raise the limit.",
                self.nvd.requests_per_window()
            )
        };
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
                    .with_title("Oxiploitability")
                    .with_website_url(env!("CARGO_PKG_REPOSITORY")),
            )
            .with_instructions(format!(
            "Sourced, evidence-aware CVE research from NIST NVD (CVSS, CWE, description, references), \
             FIRST EPSS (30-day exploitation probability), CISA KEV (confirmed exploitation), \
             OSV.dev (package advisories) and CVE.org (CNA records). Every finding names its source \
             and links to its record: cite them, and treat confirmed: false findings as leads, not \
             facts. \
             Use enrich_cve by default for one CVE or a batch of up to 100: it combines the NVD record (or the CVE.org record when NVD is slow or has none), impact, EPSS, KEV and public PoCs in one call. Use epss_scores or kev_lookup when only that one signal is needed, product_cves to ask which CVEs affect a product, package or vulnerability nickname, scan_sbom to check an SBOM, a lockfile or a container image, and poc_search to find public proof-of-concept repositories for a CVE, which are unvetted leads. \
             {key_note} {NVD_NOTICE}"
        ))
    }
}

fn parse_one(raw: &str) -> Result<CveId, String> {
    CveId::parse(raw).map_err(|e| e.to_string())
}

fn parse_many(raw: &[String]) -> Result<Vec<CveId>, String> {
    CveId::parse_batch(raw).map_err(|e: BatchError| e.to_string())
}

fn upstream(e: HttpError) -> String {
    e.to_string()
}

fn split<T>(r: Result<T, HttpError>) -> (Option<T>, Option<String>) {
    match r {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn fan_out_returns_what_finished_before_the_deadline() {
        let ids: Vec<CveId> = (1..=20)
            .map(|n| CveId::parse(&format!("CVE-2024-{n:04}")).unwrap())
            .collect();
        let started = tokio::time::Instant::now();
        let deadline = Duration::from_millis(9_500);
        let done = fan_out(&ids, deadline, |id| async move {
            let n: u64 = id.as_str()[9..].parse().unwrap();
            tokio::time::sleep(Duration::from_secs(n)).await;
            Ok::<_, HttpError>(n)
        })
        .await;
        assert_eq!(started.elapsed(), deadline);
        let mut finished: Vec<u64> = done.into_values().map(Result::unwrap).collect();
        finished.sort();
        // Eight run at once, so the ninth starts when the first ends at 1 s and ends at 10 s.
        assert_eq!(
            finished,
            (1..=8).collect::<Vec<_>>(),
            "work past the deadline is dropped"
        );
    }
}
