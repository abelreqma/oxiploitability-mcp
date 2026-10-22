use std::cmp::Ordering;

use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::http::{HttpError, read_json};

pub const DEFAULT_BASE_URL: &str = "https://cveawg.mitre.org/api/cve";
const SERVICE: &str = "CVE.org";
const MAX_BODY: usize = 2 * 1024 * 1024;
const NO_BOUND: [&str; 6] = ["", "0", "*", "-", "n/a", "unspecified"];

/// Reads CVE records from CVE.org, where the CNA (and CISA's ADP enrichment) list the affected
/// products and versions before NVD analyzes a CVE.
#[derive(Clone)]
pub struct CnaClient {
    http: Client,
    base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub versions: Vec<VersionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionEntry {
    pub version: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Affected,
    NotAffected,
    Unknown,
}

/// The parts of a CVE.org record used when NVD has no record for a CVE or could not be asked in
/// time.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CveOrgSummary {
    /// PUBLISHED or REJECTED.
    pub state: String,
    /// The CNA that assigned the CVE.
    pub assigner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    pub description: String,
    /// CWE ids from the CNA and ADP containers.
    pub cwes: Vec<String>,
    /// CVSS scores from the CNA, then from ADP containers such as CISA's, newest version first
    /// within each.
    pub cvss: Vec<CveOrgCvss>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CveOrgCvss {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<String>,
    pub vector: String,
    /// `cna`, or `adp:` and the provider's short name, such as `adp:CISA-ADP`.
    pub source: String,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default, rename = "cveMetadata")]
    metadata: Metadata,
    #[serde(default)]
    containers: Containers,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    #[serde(default)]
    state: String,
    #[serde(default)]
    assigner_short_name: String,
    date_published: Option<String>,
}

#[derive(Deserialize, Default)]
struct Containers {
    cna: Option<Container>,
    #[serde(default)]
    adp: Vec<Container>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Container {
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    problem_types: Vec<ProblemType>,
    #[serde(default)]
    metrics: Vec<Metric>,
    #[serde(default)]
    provider_metadata: Provider,
}

#[derive(Deserialize)]
struct ProblemType {
    #[serde(default)]
    descriptions: Vec<ProblemDescription>,
}

#[derive(Deserialize)]
struct ProblemDescription {
    #[serde(rename = "cweId")]
    cwe_id: Option<String>,
}

#[derive(Deserialize)]
struct Metric {
    #[serde(rename = "cvssV4_0")]
    v40: Option<RawCvss>,
    #[serde(rename = "cvssV3_1")]
    v31: Option<RawCvss>,
    #[serde(rename = "cvssV3_0")]
    v30: Option<RawCvss>,
    #[serde(rename = "cvssV2_0")]
    v20: Option<RawCvss>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCvss {
    #[serde(default)]
    version: String,
    base_score: Option<f64>,
    base_severity: Option<String>,
    #[serde(default)]
    vector_string: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Provider {
    #[serde(default)]
    short_name: String,
}

#[derive(Deserialize)]
struct Description {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

impl CnaClient {
    pub fn new(http: Client) -> Self {
        Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// The CVE's record on CVE.org, or `None` when CVE.org has no record for it.
    pub async fn summary(&self, cve: &str) -> Result<Option<CveOrgSummary>, HttpError> {
        let record = match self.record(cve).await {
            Ok(record) => record,
            Err(HttpError::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let Containers { cna, adp } = record.containers;
        let description = cna
            .as_ref()
            .and_then(|c| english(&c.descriptions))
            .unwrap_or_default();
        let mut cwes: Vec<String> = Vec::new();
        let mut cvss: Vec<CveOrgCvss> = Vec::new();
        for c in cna.iter().chain(&adp) {
            for id in c
                .problem_types
                .iter()
                .flat_map(|p| &p.descriptions)
                .filter_map(|d| d.cwe_id.clone())
            {
                if id.starts_with("CWE-") && !cwes.contains(&id) {
                    cwes.push(id);
                }
            }
            let source = match cna.as_ref().is_some_and(|n| std::ptr::eq(n, c)) {
                true => "cna".to_string(),
                false => format!("adp:{}", c.provider_metadata.short_name),
            };
            for m in &c.metrics {
                for raw in [&m.v40, &m.v31, &m.v30, &m.v20].into_iter().flatten() {
                    cvss.push(CveOrgCvss {
                        version: raw.version.clone(),
                        base_score: raw.base_score,
                        base_severity: raw.base_severity.clone(),
                        vector: raw.vector_string.clone(),
                        source: source.clone(),
                    });
                }
            }
        }
        Ok(Some(CveOrgSummary {
            state: record.metadata.state,
            assigner: record.metadata.assigner_short_name,
            published: record.metadata.date_published,
            description,
            cwes,
            cvss,
            url: format!("https://www.cve.org/CVERecord?id={cve}"),
        }))
    }

    /// Every affected entry the CNA and ADP containers list for one CVE.
    pub async fn affected(&self, cve: &str) -> Result<Vec<Affected>, HttpError> {
        let containers = self.record(cve).await?.containers;
        Ok(containers
            .cna
            .into_iter()
            .chain(containers.adp)
            .flat_map(|c| c.affected)
            .collect())
    }

    /// The CNA's English description of one CVE, the text NVD also shows.
    pub async fn description(&self, cve: &str) -> Result<Option<String>, HttpError> {
        let cna = self.record(cve).await?.containers.cna;
        Ok(cna.and_then(|c| english(&c.descriptions)))
    }

    async fn record(&self, cve: &str) -> Result<Record, HttpError> {
        let resp = self
            .http
            .get(format!("{}/{cve}", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(HttpError::Status {
                service: SERVICE,
                status: resp.status().as_u16(),
            });
        }
        read_json(SERVICE, resp, MAX_BODY).await
    }
}

/// The English description, or else the first one.
fn english(descriptions: &[Description]) -> Option<String> {
    descriptions
        .iter()
        .find(|d| d.lang.starts_with("en"))
        .or(descriptions.first())
        .map(|d| d.value.trim().to_string())
        .filter(|d| !d.is_empty())
}

fn normalize(s: &str) -> String {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// True when the entry names `product` (an NVD product token such as `tomcat`), either exactly
/// or after the vendor's first word, as in "Apache Tomcat".
pub fn names_product(a: &Affected, product: &str) -> bool {
    let named = normalize(&a.product);
    let vendor = normalize(&a.vendor);
    let first = vendor.split('_').next().unwrap_or_default();
    named == product
        || (!first.is_empty() && named.strip_prefix(&format!("{first}_")) == Some(product))
}

/// The entry's vendor and product, or `None` when the CNA left them as placeholders.
pub fn label(a: &Affected) -> Option<String> {
    let concrete = |s: &str| !matches!(normalize(s).as_str(), "" | "n_a" | "na" | "null");
    concrete(&a.product).then(|| format!("{} {}", a.vendor, a.product).trim().to_string())
}

/// Whether `version` falls in any range the entries mark as affected.
pub fn version_verdict(entries: &[VersionEntry], version: &str) -> Verdict {
    let mut unknown = entries.is_empty();
    for e in entries {
        if e.status.as_deref() != Some("affected") {
            continue;
        }
        match in_entry(e, version) {
            Some(true) => return Verdict::Affected,
            Some(false) => {}
            None => unknown = true,
        }
    }
    if unknown {
        Verdict::Unknown
    } else {
        Verdict::NotAffected
    }
}

fn in_entry(e: &VersionEntry, v: &str) -> Option<bool> {
    let base = e.version.as_deref().unwrap_or_default().trim();
    let upper = e
        .less_than
        .as_deref()
        .map(|u| (u, false))
        .or(e.less_than_or_equal.as_deref().map(|u| (u, true)));
    if let Some((upper, inclusive)) = upper {
        let above_lower = NO_BOUND.contains(&base) || compare(v, base) != Ordering::Less;
        let below_upper = match (upper.trim(), inclusive) {
            ("*", _) => true,
            (u, true) => compare(v, u) != Ordering::Greater,
            (u, false) => compare(v, u) == Ordering::Less,
        };
        return Some(above_lower && below_upper);
    }
    if base.contains('<') || base.contains('>') || base.contains('=') {
        return base
            .split(',')
            .map(|clause| constraint(clause.trim(), v))
            .collect::<Option<Vec<bool>>>()
            .map(|all| all.into_iter().all(|ok| ok));
    }
    if NO_BOUND.contains(&base) || base.contains(' ') {
        return None;
    }
    Some(compare(v, base) == Ordering::Equal)
}

/// One `op version` clause such as `< 2.4.1` or `>= 2.0`.
fn constraint(clause: &str, v: &str) -> Option<bool> {
    let (op, rest) = ["<=", ">=", "<", ">", "="]
        .iter()
        .find_map(|op| clause.strip_prefix(op).map(|rest| (*op, rest.trim())))?;
    if rest.is_empty() || rest.contains(' ') {
        return None;
    }
    let ord = compare(v, rest);
    Some(match op {
        "<=" => ord != Ordering::Greater,
        ">=" => ord != Ordering::Less,
        "<" => ord == Ordering::Less,
        ">" => ord == Ordering::Greater,
        _ => ord == Ordering::Equal,
    })
}

/// Compares dotted versions segment by segment: numbers numerically, words alphabetically, and
/// a number above a word, so 1.0 sorts after 1.0-rc1. A leading `v` is ignored.
pub fn compare(a: &str, b: &str) -> Ordering {
    let parts = |s: &str| -> Vec<String> {
        s.trim()
            .trim_start_matches(['v', 'V'])
            .split(['.', '-', '_', '+', '~'])
            .map(str::to_lowercase)
            .collect()
    };
    let (a, b) = (parts(a), parts(b));
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).map(String::as_str).unwrap_or("0");
        let y = b.get(i).map(String::as_str).unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(version: &str, lt: Option<&str>, lte: Option<&str>) -> VersionEntry {
        VersionEntry {
            version: Some(version.to_string()),
            less_than: lt.map(str::to_string),
            less_than_or_equal: lte.map(str::to_string),
            status: Some("affected".to_string()),
        }
    }

    #[test]
    fn compares_versions_numerically_with_prereleases_first() {
        assert_eq!(compare("2.10.0", "2.9.9"), Ordering::Greater);
        assert_eq!(compare("v1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(compare("1.0-rc1", "1.0"), Ordering::Less);
        assert_eq!(compare("9.0.0.M1", "9.0.0"), Ordering::Less);
    }

    #[test]
    fn structured_ranges_and_comparator_strings_decide_the_version() {
        let ranged = [entry("2.0.0", Some("2.4.1"), None)];
        assert_eq!(version_verdict(&ranged, "2.3.0"), Verdict::Affected);
        assert_eq!(version_verdict(&ranged, "2.4.1"), Verdict::NotAffected);
        assert_eq!(version_verdict(&ranged, "1.9"), Verdict::NotAffected);
        let open_lower = [entry("0", None, Some("9.8"))];
        assert_eq!(version_verdict(&open_lower, "9.8"), Verdict::Affected);
        let ghsa_style = [entry(">= 2.0, < 2.4.1", None, None)];
        assert_eq!(version_verdict(&ghsa_style, "2.4.0"), Verdict::Affected);
        assert_eq!(version_verdict(&ghsa_style, "1.5"), Verdict::NotAffected);
        let exact = [entry("1.18.0", None, None)];
        assert_eq!(version_verdict(&exact, "1.18.0"), Verdict::Affected);
        assert_eq!(version_verdict(&exact, "1.19.0"), Verdict::NotAffected);
    }

    #[test]
    fn unparseable_or_missing_ranges_are_unknown() {
        assert_eq!(version_verdict(&[], "1.0"), Verdict::Unknown);
        let prose = [entry("2.0-beta9 through 2.15.0", None, None)];
        assert_eq!(version_verdict(&prose, "2.14.1"), Verdict::Unknown);
        let unspecified = [entry("unspecified", None, None)];
        assert_eq!(version_verdict(&unspecified, "1.0"), Verdict::Unknown);
        let mut unaffected = entry("1.0", None, None);
        unaffected.status = Some("unaffected".to_string());
        assert_eq!(version_verdict(&[unaffected], "1.0"), Verdict::NotAffected);
    }

    #[test]
    fn product_names_match_exactly_or_after_the_vendor_word() {
        let a = |vendor: &str, product: &str| Affected {
            vendor: vendor.to_string(),
            product: product.to_string(),
            versions: Vec::new(),
        };
        assert!(names_product(
            &a("Apache Software Foundation", "Apache Tomcat"),
            "tomcat"
        ));
        assert!(names_product(&a("F5", "NGINX"), "nginx"));
        assert!(!names_product(&a("0xJacky", "nginx-ui"), "nginx"));
        assert_eq!(
            label(&a("0xJacky", "nginx-ui")).as_deref(),
            Some("0xJacky nginx-ui")
        );
        assert_eq!(label(&a("n/a", "n/a")), None);
    }
}
