use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packageurl::PackageUrl;
use schemars::JsonSchema;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::cna::{self, Affected, CnaClient, Verdict};
use crate::component::{Component, NotCheckedReason, NvdTarget, OsvQuery, Route, route};
use crate::cve::CveId;
use crate::epss::EpssClient;
use crate::http::HttpError;
use crate::impact::{self, Impact};
use crate::kev::{KevCatalog, KevEntry};
use crate::nickname;
use crate::nvd::{CpeProduct, NvdClient, NvdSummary};
use crate::osv::{OsvClient, OsvVuln};
use crate::poc::{self, PocClient};
use crate::sbom;

const OSV_CONCURRENCY: usize = 8;
const MAX_SBOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 100;
const MAX_WALK_ENTRIES: usize = 20_000;
const MAX_WALK_DEPTH: usize = 8;
/// Dependency and build output directories, which hold other projects' manifests.
const SKIPPED_DIRS: &[&str] = &["node_modules", "target", "vendor", "venv", "__pycache__"];
const MAX_COMPONENTS: usize = 5_000;
const MAX_POC_LOOKUPS: usize = 50;
const OSV_DEADLINE: Duration = Duration::from_secs(25);
const NVD_DEADLINE: Duration = Duration::from_secs(40);
const POC_DEADLINE: Duration = Duration::from_secs(5);
/// PoC lookups stop here so the call returns before the usual 60 s MCP client timeout.
const TOTAL_DEADLINE: Duration = Duration::from_secs(45);
/// Fetching 100 CPE-heavy KEV records takes NVD up to about 40 s for Windows-sized products.
const KEV_DEADLINE: Duration = Duration::from_secs(40);
const CNA_DEADLINE: Duration = Duration::from_secs(10);
const SUMMARY_CHARS: usize = 200;

pub struct Sources<'a> {
    pub nvd: &'a NvdClient,
    pub epss: &'a EpssClient,
    pub kev: &'a KevCatalog,
    pub osv: &'a OsvClient,
    pub cna: &'a CnaClient,
    pub poc: &'a PocClient,
}

/// One known vulnerability with its exploitability signals.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Finding {
    pub cve: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub summary: String,
    /// What an attacker gains, derived from the CWE ids and description, most severe first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impact: Vec<Impact>,
    /// The full description, returned when `detail` is set and always written to scan reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    /// True when CISA lists the CVE as known exploited; null when the KEV catalog could not be
    /// read.
    pub in_kev: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_versions: Vec<String>,
    /// False when only the description names the product: NVD has not mapped the CVE to
    /// products yet, so neither the product nor the version is confirmed.
    pub confirmed: bool,
    /// What matched this CVE: `nvd-cpe` (NVD's product data), `cve.org-cna` (the CNA's record on
    /// CVE.org), `nvd-description` (only the description names the product), `nickname`, or
    /// `osv:<advisory id>`.
    pub source: String,
    /// The record behind `source`.
    pub url: String,
    /// The SBOM component this finding belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    /// The scanned files that list the component.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Public PoC repositories the nomi-sec/PoC-in-GitHub index lists for the CVE; absent when
    /// the index was not checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc_repos: Option<usize>,
    /// Set when the text came from a distro notice that covers several CVEs, such as a Debian
    /// DSA or an Ubuntu USN, rather than from the CVE itself.
    #[serde(skip)]
    pub notice_text: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ProductAnswer {
    /// What the question was matched to: an NVD product as part:product, or a package query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
    /// Products the name could mean; set instead of findings when the name is ambiguous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    /// Number of CVEs found, including any beyond the fetched pages.
    pub total: usize,
    /// CVEs in CISA KEV: NVD's count over every match for NVD products, else among the findings;
    /// null when neither could be read.
    pub kev: Option<usize>,
    pub unconfirmed: usize,
    /// Description-only matches whose CVE.org record names a different product, kept out of
    /// `findings`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_products: Vec<OtherProduct>,
    /// True when NVD lists more CVEs than were fetched; give a version to narrow the answer.
    pub partial: bool,
    /// Ranked: known exploited first, then EPSS, then CVSS score.
    pub findings: Vec<Finding>,
    /// What to do about the product, built from every finding before `limit` applies. Absent for
    /// nicknames, which can span several products.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// What to do about one component: its advisories, the upgrade that clears them, and what the
/// sources could not settle.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Action {
    pub component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// True when any advisory is in CISA KEV; null when KEV status is unknown for some.
    pub in_kev: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_epss: Option<f64>,
    /// Every impact kind the advisories indicate, most severe first, such as RCE or DoS.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impacts: Vec<String>,
    /// True when the PoC index lists a repository for any advisory; null when none was found
    /// and some advisories were not checked.
    pub poc: Option<bool>,
    /// The lowest version above the installed one that every advisory with a listed fix marks
    /// as fixed. Absent without an installed version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_to: Option<String>,
    /// Every fixed version the advisories list, lowest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_versions: Vec<String>,
    /// Advisories that list no fixed version, so `upgrade_to` does not clear them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_fix_listed: Vec<String>,
    /// Ranked like findings.
    pub advisories: Vec<Advisory>,
    /// What the sources could not settle and a person should check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs_verification: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Advisory {
    pub cve: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub confirmed: bool,
    pub source: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impact: Vec<Impact>,
    pub in_kev: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_versions: Vec<String>,
    /// PoC repositories listed for the CVE; null when the index was not checked. The index is
    /// per CVE: the advisory's match decides whether it applies to the installed version.
    pub poc_repos: Option<usize>,
    /// The PoC index entry, when it lists repositories.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc_index: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct OtherProduct {
    pub cve: String,
    /// Vendor and product as the CVE.org record names them.
    pub product: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct NotChecked {
    pub component: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(flatten)]
    pub reason: NotCheckedReason,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ScannedFile {
    /// Path relative to the scanned directory, or the file name for a single file.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub components: usize,
    /// Why the file was not read; its components are not counted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ScanAnswer {
    /// The inventory format, or `directory` for a project directory.
    pub format: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<ScannedFile>,
    /// Distinct components across every file.
    pub components: usize,
    /// Components every applicable source answered for.
    pub checked_components: usize,
    /// Components listed in `not_checked`; their vulnerabilities are unknown.
    pub not_checked_components: usize,
    pub vulnerable_components: usize,
    pub total: usize,
    /// CVEs in CISA KEV among the findings; null when the KEV catalog could not be read.
    pub kev: Option<usize>,
    /// One per vulnerable component, ranked known exploited first, then EPSS. The report file
    /// holds all.
    pub actions: Vec<Action>,
    /// Ranked: known exploited first, then EPSS, then CVSS score. The report file holds all.
    pub findings: Vec<Finding>,
    /// True when `actions` or `findings` were cut to `limit`.
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<NotChecked>,
    /// Path of the JSON report with every finding, written next to the SBOM or in the
    /// scanned directory.
    pub report: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Answers "which CVEs affect this product or package", optionally at one version.
pub async fn product_cves(
    src: &Sources<'_>,
    c: &Component,
    limit: usize,
    detail: bool,
) -> Result<ProductAnswer, String> {
    let started = Instant::now();
    let mut answer = ProductAnswer {
        matched: None,
        candidates: Vec::new(),
        total: 0,
        kev: None,
        unconfirmed: 0,
        other_products: Vec::new(),
        partial: false,
        findings: Vec::new(),
        action: None,
        warnings: Vec::new(),
    };
    let mut kev_total = None;
    let plain_name = c.purl.is_none() && c.cpe.is_none() && c.ecosystem.is_none();
    let nickname = plain_name.then(|| nickname::lookup(&c.name)).flatten();
    let by_nickname = nickname.is_some();
    if let Some((display, ids)) = nickname {
        answer.matched = Some(format!("nickname: {display}"));
        for id in ids {
            let id = CveId::parse(id).map_err(|e| e.to_string())?;
            match src.nvd.lookup(&id).await {
                Ok(Some(s)) => answer.findings.push(from_nvd(&s, "nickname", "")),
                Ok(None) => answer.warnings.push(format!("NVD has no record for {id}")),
                Err(e) => answer.warnings.push(format!("{id}: {e}")),
            }
        }
        answer.total = answer.findings.len();
    } else {
        match route(c, false) {
            Route::NotChecked(reason) => return Err(describe(&reason)),
            Route::Osv(q) => {
                let vulns = src.osv.query(&q).await.map_err(|e| e.to_string())?;
                answer.matched = Some(describe_query(&q));
                answer.findings = merge_duplicates(vulns.iter().flat_map(from_osv).collect());
                describe_notices(src.cna, &mut answer.findings, &mut answer.warnings).await;
                answer.total = answer.findings.len();
            }
            Route::Nvd { target, version } => {
                let (match_string, product) = match target {
                    NvdTarget::Cpe {
                        part,
                        vendor,
                        product,
                    } => {
                        answer.matched = Some(format!("{part}:{vendor}:{product}"));
                        (format!("cpe:2.3:{part}:{vendor}:{product}"), product)
                    }
                    NvdTarget::Name(name) => {
                        let products = src
                            .nvd
                            .cpe_products(&name)
                            .await
                            .map_err(|e| e.to_string())?;
                        match choose_product(&name, products) {
                            Ok(p) => {
                                answer.matched =
                                    Some(format!("{}:{} (any vendor)", p.part, p.product));
                                (format!("cpe:2.3:{}:*:{}", p.part, p.product), p.product)
                            }
                            Err(candidates) if candidates.is_empty() => {
                                answer.warnings.push(format!(
                                    "NVD's product dictionary has no entry matching {name:?}"
                                ));
                                return Ok(answer);
                            }
                            Err(candidates) => {
                                answer.candidates = candidates;
                                return Ok(answer);
                            }
                        }
                    }
                };
                let phrase = product.replace('_', " ");
                let mut described_kept = 0;
                let version = version.as_deref();
                // Without a key NVD allows 5 requests per 30 s, so only the essential ones are sent.
                let full = src.nvd.has_api_key();
                let (search, kev_count, kev_search, described) = tokio::join!(
                    src.nvd.search_cves(&match_string, version, false),
                    src.nvd.count_kev(&match_string, version),
                    async {
                        match full {
                            true => Some(
                                tokio::time::timeout(
                                    KEV_DEADLINE,
                                    src.nvd.search_cves(&match_string, version, true),
                                )
                                .await,
                            ),
                            false => None,
                        }
                    },
                    async {
                        match full {
                            true => Some(src.nvd.search_description(&phrase).await),
                            false => None,
                        }
                    }
                );
                if !full {
                    answer.warnings.push(
                    "no NVD API key: KEV-listed CVEs beyond the newest 50 and description-only matches are skipped to stay within NVD's keyless rate limit; set NVD_API to include them"
                        .to_string(),
                );
                }
                let search = search.map_err(|e| e.to_string())?;
                let mut records = search.records;
                kev_total = kev_count.ok();
                match kev_search {
                None => {}
                Some(Ok(Ok(kev))) => {
                    let seen: HashSet<String> = records.iter().map(|s| s.id.clone()).collect();
                    records.extend(kev.records.into_iter().filter(|s| !seen.contains(&s.id)));
                }
                Some(Ok(Err(e))) => answer.warnings.push(format!("KEV search failed: {e}")),
                Some(Err(_)) => answer.warnings.push(format!(
                    "fetching KEV-listed CVEs took longer than {} s; kev is NVD's count, but only KEV entries among the newest CVEs are listed",
                    KEV_DEADLINE.as_secs()
                )),
            }
                answer.partial = search.total > records.len();
                answer.findings = records
                    .iter()
                    .map(|s| from_nvd(s, "nvd-cpe", &product))
                    .collect();
                match described {
                    None => {}
                    Some(Ok(records)) => {
                        let seen: HashSet<String> =
                            answer.findings.iter().map(|f| f.cve.clone()).collect();
                        let extra: Vec<&NvdSummary> =
                            records.iter().filter(|s| !seen.contains(&s.id)).collect();
                        let ids = extra.iter().map(|s| s.id.clone()).collect();
                        let checks = match tokio::time::timeout(
                            CNA_DEADLINE,
                            cna_checks(src.cna, ids, &product, version),
                        )
                        .await
                        {
                            Ok(checks) => checks,
                            Err(_) => {
                                answer.warnings.push(format!(
                                    "CVE.org did not answer within {} s; description matches stay unconfirmed",
                                    CNA_DEADLINE.as_secs()
                                ));
                                HashMap::new()
                            }
                        };
                        for s in extra {
                            let mut f = from_nvd(s, "nvd-description", &product);
                            match checks.get(&s.id) {
                                Some(CnaCheck::Confirmed) => {
                                    f.confirmed = true;
                                    f.source = "cve.org-cna".to_string();
                                    f.url = format!("https://www.cve.org/CVERecord?id={}", s.id);
                                }
                                Some(CnaCheck::NotAffected) => continue,
                                Some(CnaCheck::Other(name)) => {
                                    answer.other_products.push(OtherProduct {
                                        cve: s.id.clone(),
                                        product: name.clone(),
                                    });
                                    continue;
                                }
                                Some(CnaCheck::Unknown) | None => {}
                            }
                            described_kept += 1;
                            answer.unconfirmed += usize::from(!f.confirmed);
                            answer.findings.push(f);
                        }
                    }
                    Some(Err(e)) => answer
                        .warnings
                        .push(format!("description search failed: {e}")),
                }
                answer.total = search.total + described_kept;
            }
        }
    }
    enrich(&mut answer.findings, src, &mut answer.warnings).await;
    rank(&mut answer.findings);
    answer.kev = kev_total.or_else(|| kev_count(&answer.findings));
    let poc_deadline = (Instant::now() + POC_DEADLINE).min(started + TOTAL_DEADLINE);
    poc_check(
        src.poc,
        &mut answer.findings,
        poc_deadline,
        &mut answer.warnings,
    )
    .await;
    if !by_nickname && !answer.findings.is_empty() {
        let component = answer.matched.clone().unwrap_or_else(|| label(c));
        let findings: Vec<&Finding> = answer.findings.iter().collect();
        answer.action = Some(action(component, installed_version(c), &findings));
    }
    answer.findings.truncate(limit);
    if !detail {
        drop_descriptions(&mut answer.findings);
    }
    Ok(answer)
}

/// Checks every component of a CycloneDX or SPDX SBOM and writes a JSON report next to it.
pub enum ScanTarget<'a> {
    File(&'a str),
    Image(&'a str),
}

pub async fn scan_sbom(
    src: &Sources<'_>,
    target: ScanTarget<'_>,
    limit: usize,
    detail: bool,
) -> Result<ScanAnswer, String> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let mut files = Vec::new();
    // Each inventory's components with the file that lists them; empty for an image.
    let mut inputs: Vec<(String, Vec<Component>)> = Vec::new();
    let (format, report_path) = match target {
        ScanTarget::File(path) => {
            let root =
                std::fs::canonicalize(path).map_err(|e| format!("cannot open {path:?}: {e}"))?;
            if root.is_dir() {
                let found = discover(&root, &mut warnings);
                if found.is_empty() {
                    return Err(format!(
                        "no supported lockfile or SBOM found under {}",
                        root.display()
                    ));
                }
                let mut read_bytes = 0;
                for p in found {
                    let rel = p.strip_prefix(&root).unwrap_or(&p).display().to_string();
                    let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    read_bytes += size;
                    let parsed = if read_bytes > MAX_DIRECTORY_BYTES {
                        Err(format!(
                            "skipped: the scan reads at most {MAX_DIRECTORY_BYTES} bytes in total"
                        ))
                    } else {
                        read_inventory(&p)
                            .and_then(|(name, _, bytes)| sbom::parse_file(&name, &bytes))
                    };
                    match parsed {
                        Ok(s) => {
                            files.push(ScannedFile {
                                path: rel.clone(),
                                format: Some(s.format.to_string()),
                                components: s.components.len(),
                                error: None,
                            });
                            inputs.push((rel, s.components));
                        }
                        Err(e) => files.push(ScannedFile {
                            path: rel,
                            format: None,
                            components: 0,
                            error: Some(e),
                        }),
                    }
                }
                ("directory".to_string(), root.join("oxiploitability.json"))
            } else {
                let (file_name, path, bytes) = read_inventory(&root)?;
                let parsed = sbom::parse_file(&file_name, &bytes)?;
                let report = path.with_file_name(format!("{file_name}.oxiploitability.json"));
                files.push(ScannedFile {
                    path: file_name.clone(),
                    format: Some(parsed.format.to_string()),
                    components: parsed.components.len(),
                    error: None,
                });
                inputs.push((file_name, parsed.components));
                (parsed.format.to_string(), report)
            }
        }
        ScanTarget::Image(image) => {
            let (tool, bytes) = sbom::from_image(image).await?;
            let parsed = sbom::parse(&bytes)?;
            let safe: String = image
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let report = std::env::temp_dir().join(format!("oxiploitability-{safe}.json"));
            inputs.push((String::new(), parsed.components));
            (format!("{} from {tool}", parsed.format), report)
        }
    };

    // A component listed by several files is checked once.
    let mut components: Vec<Component> = Vec::new();
    let mut files_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut seen = HashSet::new();
    for (file, list) in inputs {
        for c in list {
            let l = label(&c);
            let known = files_of.entry(l.clone()).or_default();
            if !file.is_empty() && !known.contains(&file) {
                known.push(file.clone());
            }
            if seen.insert(l) {
                components.push(c);
            }
        }
    }

    let mut findings = Vec::new();
    let mut not_checked = Vec::new();
    let mut osv_jobs = Vec::new();
    let mut nvd_jobs: Vec<(String, NvdTarget, String)> = Vec::new();
    for (i, c) in components.iter().enumerate() {
        let label = label(c);
        if i >= MAX_COMPONENTS {
            not_checked.push(NotChecked {
                component: label,
                files: Vec::new(),
                reason: NotCheckedReason::ComponentLimit,
            });
            continue;
        }
        match route(c, true) {
            Route::Osv(q) => osv_jobs.push((label, q)),
            Route::Nvd { target, version } => {
                nvd_jobs.push((label, target, version.unwrap_or_default()))
            }
            Route::NotChecked(reason) => not_checked.push(NotChecked {
                component: label,
                files: Vec::new(),
                reason,
            }),
        }
    }

    let gate = Arc::new(Semaphore::new(OSV_CONCURRENCY));
    let mut tasks = JoinSet::new();
    let mut pending: HashSet<String> = HashSet::new();
    for (label, q) in osv_jobs {
        let (osv, gate) = (src.osv.clone(), gate.clone());
        pending.insert(label.clone());
        tasks.spawn(async move {
            let _permit = gate.acquire_owned().await;
            (label, osv.query(&q).await)
        });
    }
    let osv_deadline = started + OSV_DEADLINE;
    let mut timed_out = false;
    loop {
        let remaining = osv_deadline.saturating_duration_since(Instant::now());
        let joined = match tokio::time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(joined)) => joined,
            Ok(None) => break,
            Err(_) => {
                timed_out = true;
                tasks.abort_all();
                break;
            }
        };
        let Ok((label, result)) = joined else {
            continue;
        };
        pending.remove(&label);
        match result {
            Ok(vulns) => findings.extend(vulns.iter().flat_map(from_osv).map(|f| Finding {
                component: Some(label.clone()),
                ..f
            })),
            Err(e) => not_checked.push(NotChecked {
                component: label,
                files: Vec::new(),
                reason: NotCheckedReason::Upstream {
                    error: e.to_string(),
                },
            }),
        }
    }
    for label in pending {
        let reason = match timed_out {
            true => NotCheckedReason::TimeBudget,
            false => NotCheckedReason::Upstream {
                error: "the OSV query task failed".to_string(),
            },
        };
        not_checked.push(NotChecked {
            component: label,
            files: Vec::new(),
            reason,
        });
    }

    describe_notices(src.cna, &mut findings, &mut warnings).await;

    // NVD lookups stop at a deadline so the call returns before the usual 60 s MCP client timeout.
    let deadline = started + NVD_DEADLINE;
    let mut resolved: HashMap<String, Result<(String, String), NotCheckedReason>> = HashMap::new();
    for (label, target, version) in nvd_jobs {
        if Instant::now() >= deadline {
            not_checked.push(NotChecked {
                component: label,
                files: Vec::new(),
                reason: NotCheckedReason::NvdBudget,
            });
            continue;
        }
        let target = match target {
            NvdTarget::Cpe {
                part,
                vendor,
                product,
            } => Ok((format!("cpe:2.3:{part}:{vendor}:{product}"), product)),
            NvdTarget::Name(name) => {
                if !resolved.contains_key(&name) {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let r = match tokio::time::timeout(remaining, src.nvd.cpe_products(&name))
                        .await
                        .unwrap_or_else(|_| Err(HttpError::TimedOut))
                    {
                        Err(HttpError::TimedOut) => Err(NotCheckedReason::NvdBudget),
                        Ok(products) => match choose_product(&name, products) {
                            Ok(p) => Ok((format!("cpe:2.3:{}:*:{}", p.part, p.product), p.product)),
                            Err(c) if c.is_empty() => Err(NotCheckedReason::UnknownName),
                            Err(candidates) => Err(NotCheckedReason::AmbiguousName { candidates }),
                        },
                        Err(e) => Err(NotCheckedReason::Upstream {
                            error: e.to_string(),
                        }),
                    };
                    resolved.insert(name.clone(), r);
                }
                resolved[&name].clone()
            }
        };
        let (match_string, product) = match target {
            Ok(t) => t,
            Err(reason) => {
                not_checked.push(NotChecked {
                    component: label,
                    files: Vec::new(),
                    reason,
                });
                continue;
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(
            remaining,
            src.nvd.search_cves(&match_string, Some(&version), false),
        )
        .await
        .unwrap_or_else(|_| Err(HttpError::TimedOut))
        {
            Err(HttpError::TimedOut) => not_checked.push(NotChecked {
                component: label,
                files: Vec::new(),
                reason: NotCheckedReason::NvdBudget,
            }),
            Ok(search) => findings.extend(search.records.iter().map(|s| Finding {
                component: Some(label.clone()),
                ..from_nvd(s, "nvd-cpe", &product)
            })),
            Err(e) => not_checked.push(NotChecked {
                component: label,
                files: Vec::new(),
                reason: NotCheckedReason::Upstream {
                    error: e.to_string(),
                },
            }),
        }
    }

    let mut findings = merge_duplicates(findings);
    enrich(&mut findings, src, &mut warnings).await;
    rank(&mut findings);
    let poc_deadline = (Instant::now() + POC_DEADLINE).min(started + TOTAL_DEADLINE);
    poc_check(src.poc, &mut findings, poc_deadline, &mut warnings).await;
    for f in &mut findings {
        f.files = f
            .component
            .as_ref()
            .and_then(|c| files_of.get(c))
            .cloned()
            .unwrap_or_default();
    }
    for n in &mut not_checked {
        n.files = files_of.get(&n.component).cloned().unwrap_or_default();
    }

    let installed: HashMap<String, Option<String>> = components
        .iter()
        .map(|c| (label(c), installed_version(c)))
        .collect();
    let mut groups: Vec<(String, Vec<&Finding>)> = Vec::new();
    let mut group_of: HashMap<&str, usize> = HashMap::new();
    for f in &findings {
        let Some(c) = f.component.as_deref() else {
            continue;
        };
        let i = *group_of.entry(c).or_insert_with(|| {
            groups.push((c.to_string(), Vec::new()));
            groups.len() - 1
        });
        groups[i].1.push(f);
    }
    let mut actions: Vec<Action> = groups
        .into_iter()
        .map(|(c, list)| {
            let mut a = action(c.clone(), installed.get(&c).cloned().flatten(), &list);
            a.files = files_of.get(&c).cloned().unwrap_or_default();
            a
        })
        .collect();
    rank_actions(&mut actions);

    let mut answer = ScanAnswer {
        format,
        files,
        components: components.len(),
        checked_components: components.len().saturating_sub(not_checked.len()),
        not_checked_components: not_checked.len(),
        vulnerable_components: actions.len(),
        total: findings.len(),
        kev: kev_count(&findings),
        truncated: findings.len() > limit || actions.len() > limit,
        actions,
        findings,
        not_checked,
        report: report_path.display().to_string(),
        warnings,
    };
    write_report(&report_path, &mut answer)?;
    answer.actions.truncate(limit);
    answer.findings.truncate(limit);
    if !detail {
        drop_descriptions(&mut answer.findings);
    }
    Ok(answer)
}

/// Finds supported lockfiles and SBOMs under `root`, skipping symlinks, hidden directories and
/// dependency directories, and stopping at the depth, entry and file limits with a warning.
fn discover(root: &Path, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    let mut entries_seen = 0;
    let mut too_deep = false;
    'walk: while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            warnings.push(format!("cannot read directory {}", dir.display()));
            continue;
        };
        for entry in entries.flatten() {
            entries_seen += 1;
            if entries_seen > MAX_WALK_ENTRIES {
                warnings.push(format!(
                    "stopped walking the directory after {MAX_WALK_ENTRIES} entries; scan subdirectories separately"
                ));
                break 'walk;
            }
            // file_type does not follow symlinks, so a link out of the tree is never read.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                if name.starts_with('.') || SKIPPED_DIRS.contains(&name.as_str()) {
                    continue;
                }
                match depth < MAX_WALK_DEPTH {
                    true => stack.push((entry.path(), depth + 1)),
                    false => too_deep = true,
                }
            } else if kind.is_file() && sbom::is_inventory(&name) {
                if found.len() == MAX_FILES {
                    warnings.push(format!(
                        "found more than {MAX_FILES} lockfiles and SBOMs; only the first {MAX_FILES} were scanned"
                    ));
                    break 'walk;
                }
                found.push(entry.path());
            }
        }
    }
    if too_deep {
        warnings.push(format!(
            "directories deeper than {MAX_WALK_DEPTH} levels were not searched"
        ));
    }
    found.sort();
    found
}

/// Opens a regular file under the size cap, refusing `.env` files.
fn read_inventory(path: &Path) -> Result<(String, std::path::PathBuf, Vec<u8>), String> {
    let path =
        std::fs::canonicalize(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    if file_name == ".env" || file_name.starts_with(".env.") {
        return Err("refusing to read a .env file".to_string());
    }
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > MAX_SBOM_BYTES {
        return Err(format!("SBOM exceeds {MAX_SBOM_BYTES} bytes"));
    }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    Ok((file_name, path, bytes))
}

enum CnaCheck {
    Confirmed,
    NotAffected,
    Other(String),
    Unknown,
}

/// Replaces distro notice text with each CVE's own description from CVE.org. When CVE.org is
/// slow or has no description, the notice text stays and a warning says so.
async fn describe_notices(cna: &CnaClient, findings: &mut [Finding], warnings: &mut Vec<String>) {
    let mut ids: Vec<String> = findings
        .iter()
        .filter(|f| f.notice_text)
        .map(|f| f.cve.clone())
        .collect();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return;
    }
    let gate = Arc::new(Semaphore::new(OSV_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for id in ids {
        let (cna, gate) = (cna.clone(), gate.clone());
        tasks.spawn(async move {
            let _permit = gate.acquire_owned().await;
            let description = cna.description(&id).await;
            (id, description)
        });
    }
    let mut texts: HashMap<String, String> = HashMap::new();
    let collect = async {
        while let Some(joined) = tasks.join_next().await {
            if let Ok((id, Ok(Some(text)))) = joined {
                texts.insert(id, text);
            }
        }
    };
    let finished = tokio::time::timeout(CNA_DEADLINE, collect).await.is_ok();
    let mut kept = 0;
    for f in findings.iter_mut().filter(|f| f.notice_text) {
        match texts.get(&f.cve) {
            Some(text) => {
                f.summary = summary_line(text);
                impact::merge(&mut f.impact, impact::classify(&[], text, None));
                f.description = Some(text.clone());
                f.notice_text = false;
            }
            None => kept += 1,
        }
    }
    if kept > 0 {
        let why = if finished {
            "CVE.org had no description"
        } else {
            "CVE.org did not answer in time"
        };
        warnings.push(format!(
            "{kept} distro-notice findings keep the notice title as their summary: {why}"
        ));
    }
}

/// Checks each CVE's CVE.org record for `product` and, when given, `version`.
async fn cna_checks(
    cna: &CnaClient,
    ids: Vec<String>,
    product: &str,
    version: Option<&str>,
) -> HashMap<String, CnaCheck> {
    let gate = Arc::new(Semaphore::new(OSV_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for id in ids {
        let (cna, gate) = (cna.clone(), gate.clone());
        tasks.spawn(async move {
            let _permit = gate.acquire_owned().await;
            let affected = cna.affected(&id).await;
            (id, affected)
        });
    }
    let mut checks = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        let Ok((id, affected)) = joined else {
            continue;
        };
        let check = match affected {
            Ok(affected) => judge(&affected, product, version),
            Err(_) => CnaCheck::Unknown,
        };
        checks.insert(id, check);
    }
    checks
}

fn judge(affected: &[Affected], product: &str, version: Option<&str>) -> CnaCheck {
    let named: Vec<&Affected> = affected
        .iter()
        .filter(|a| cna::names_product(a, product))
        .collect();
    if named.is_empty() {
        return affected
            .iter()
            .find_map(cna::label)
            .map_or(CnaCheck::Unknown, CnaCheck::Other);
    }
    let Some(v) = version else {
        return CnaCheck::Confirmed;
    };
    let verdicts: Vec<Verdict> = named
        .iter()
        .map(|a| cna::version_verdict(&a.versions, v))
        .collect();
    if verdicts.contains(&Verdict::Affected) {
        CnaCheck::Confirmed
    } else if verdicts.iter().all(|v| *v == Verdict::NotAffected) {
        CnaCheck::NotAffected
    } else {
        CnaCheck::Unknown
    }
}

/// KEV-listed findings, or `None` when KEV status is unknown for any of them.
fn kev_count(findings: &[Finding]) -> Option<usize> {
    findings.iter().map(|f| f.in_kev.map(usize::from)).sum()
}

/// The version a component is at: its package URL's version, else its own version field.
fn installed_version(c: &Component) -> Option<String> {
    c.purl
        .as_deref()
        .and_then(|p| PackageUrl::from_str(p).ok())
        .and_then(|p| p.version().map(str::to_string))
        .or_else(|| c.version.clone())
        .filter(|v| !v.trim().is_empty())
}

/// Looks up PoC repositories for the highest-ranked CVEs, at most `MAX_POC_LOOKUPS` and until
/// `deadline`. CVEs left unchecked keep `poc_repos` unset.
async fn poc_check(
    poc: &PocClient,
    findings: &mut [Finding],
    deadline: Instant,
    warnings: &mut Vec<String>,
) {
    let mut ids: Vec<CveId> = Vec::new();
    let mut seen = HashSet::new();
    for f in findings.iter() {
        if let Ok(id) = CveId::parse(&f.cve)
            && seen.insert(f.cve.clone())
        {
            ids.push(id);
        }
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut failed = 0;
    for id in ids.iter().take(MAX_POC_LOOKUPS) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, poc.search(id)).await {
            Ok(Ok(repos)) => {
                counts.insert(id.as_str().to_string(), repos.len());
            }
            Ok(Err(_)) => failed += 1,
            Err(_) => break,
        }
    }
    for f in findings.iter_mut() {
        f.poc_repos = counts.get(&f.cve).copied();
    }
    let unchecked = ids.len() - counts.len();
    if unchecked > 0 {
        warnings.push(format!(
            "the PoC index was not checked for {unchecked} CVEs ({failed} lookups failed; the rest exceeded the limit of {MAX_POC_LOOKUPS} lookups or {} s)",
            POC_DEADLINE.as_secs()
        ));
    }
}

/// Builds the action for one component from its findings, already ranked.
fn action(component: String, installed: Option<String>, findings: &[&Finding]) -> Action {
    let mut needs = Vec::new();
    let in_kev = if findings.iter().any(|f| f.in_kev == Some(true)) {
        Some(true)
    } else if findings.iter().all(|f| f.in_kev.is_some()) {
        Some(false)
    } else {
        needs.push("KEV status unknown: the CISA catalog could not be read".to_string());
        None
    };
    let poc = if findings.iter().any(|f| f.poc_repos.is_some_and(|n| n > 0)) {
        needs.push(
            "public PoC repositories are unvetted and some carry malware; review the code and run it only in an isolated lab"
                .to_string(),
        );
        Some(true)
    } else if findings.iter().all(|f| f.poc_repos.is_some()) {
        Some(false)
    } else {
        None
    };
    let poc_unchecked: Vec<&str> = findings
        .iter()
        .filter(|f| f.poc_repos.is_none() && f.cve.starts_with("CVE-"))
        .map(|f| f.cve.as_str())
        .collect();
    if !poc_unchecked.is_empty() {
        needs.push(format!(
            "PoC index not checked for {}",
            poc_unchecked.join(", ")
        ));
    }
    let not_cves: Vec<&str> = findings
        .iter()
        .filter(|f| !f.cve.starts_with("CVE-"))
        .map(|f| f.cve.as_str())
        .collect();
    if !not_cves.is_empty() {
        needs.push(format!(
            "{} have no CVE id; KEV, EPSS and the PoC index cover CVEs only",
            not_cves.join(", ")
        ));
    }
    for f in findings.iter().filter(|f| !f.confirmed) {
        needs.push(format!(
            "{}: only the description names the product; confirm the product and version",
            f.cve
        ));
    }
    let impacts = impact::kinds(findings.iter().map(|f| f.impact.as_slice()));
    let no_impact: Vec<&str> = findings
        .iter()
        .filter(|f| f.impact.is_empty())
        .map(|f| f.cve.as_str())
        .collect();
    if !no_impact.is_empty() {
        needs.push(format!(
            "impact unknown for {}: no CWE id, description phrase or CVSS impact metric maps to an impact",
            no_impact.join(", ")
        ));
    }

    let mut fixed_versions: Vec<String> = Vec::new();
    let mut no_fix_listed = Vec::new();
    let mut targets: Vec<&str> = Vec::new();
    for f in findings {
        if f.fixed_versions.is_empty() {
            no_fix_listed.push(f.cve.clone());
            continue;
        }
        for v in &f.fixed_versions {
            if !fixed_versions.contains(v) {
                fixed_versions.push(v.clone());
            }
        }
        let Some(installed) = installed.as_deref() else {
            continue;
        };
        // The lowest fix above the installed version, which picks the fix on the installed
        // release line when an advisory lists several.
        let above = f
            .fixed_versions
            .iter()
            .filter(|v| cna::compare(v, installed) == Ordering::Greater)
            .min_by(|a, b| cna::compare(a, b));
        match above {
            Some(v) => targets.push(v),
            None => needs.push(format!(
                "{}: every listed fix ({}) is at or below {installed}; check whether the advisory applies",
                f.cve,
                f.fixed_versions.join(", ")
            )),
        }
    }
    fixed_versions.sort_by(|a, b| cna::compare(a, b));
    let upgrade_to = targets
        .into_iter()
        .max_by(|a, b| cna::compare(a, b))
        .map(str::to_string);
    if installed.is_none() {
        needs.push(
            "no installed version given: the advisories cover the product's history, not one version"
                .to_string(),
        );
    }
    if !no_fix_listed.is_empty() {
        needs.push(format!(
            "no fixed version listed for {}; check the vendor advisory",
            no_fix_listed.join(", ")
        ));
    }
    let dotted = |v: &str| {
        v.trim_start_matches(['v', 'V'])
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
    };
    if upgrade_to.is_some() && !installed.iter().chain(&fixed_versions).all(|v| dotted(v)) {
        needs.push(
            "upgrade_to compares versions segment by segment; confirm it with the ecosystem's own version rules"
                .to_string(),
        );
    }

    let advisories = findings
        .iter()
        .map(|f| Advisory {
            cve: f.cve.clone(),
            aliases: f.aliases.clone(),
            confirmed: f.confirmed,
            source: f.source.clone(),
            url: f.url.clone(),
            impact: f.impact.clone(),
            in_kev: f.in_kev,
            epss: f.epss,
            fixed_versions: f.fixed_versions.clone(),
            poc_repos: f.poc_repos,
            poc_index: f
                .poc_repos
                .filter(|n| *n > 0)
                .and_then(|_| CveId::parse(&f.cve).ok())
                .map(|id| poc::index_url(&id)),
        })
        .collect();
    Action {
        component,
        installed_version: installed,
        files: Vec::new(),
        in_kev,
        max_epss: findings
            .iter()
            .filter_map(|f| f.epss)
            .max_by(|a, b| a.total_cmp(b)),
        impacts,
        poc,
        upgrade_to,
        fixed_versions,
        no_fix_listed,
        advisories,
        needs_verification: needs,
    }
}

/// Known exploited first, then highest EPSS, then most advisories.
fn rank_actions(actions: &mut [Action]) {
    actions.sort_by(|a, b| {
        b.in_kev
            .cmp(&a.in_kev)
            .then_with(|| match (a.max_epss, b.max_epss) {
                (Some(x), Some(y)) => y.total_cmp(&x),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
            .then_with(|| b.advisories.len().cmp(&a.advisories.len()))
    });
}

fn drop_descriptions(findings: &mut [Finding]) {
    for f in findings {
        f.description = None;
    }
}

fn write_report(path: &Path, answer: &mut ScanAnswer) -> Result<(), String> {
    for suffix in 0..1000 {
        let candidate = if suffix == 0 {
            path.to_path_buf()
        } else {
            path.with_extension(format!("{suffix}.json"))
        };
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create report {}: {e}", candidate.display())),
        };
        answer.report = candidate.display().to_string();
        let json = serde_json::to_vec_pretty(answer).map_err(|e| e.to_string())?;
        return file
            .write_all(&json)
            .map_err(|e| format!("cannot write report {}: {e}", candidate.display()));
    }
    Err(format!(
        "cannot find an unused report name for {}",
        path.display()
    ))
}

fn label(c: &Component) -> String {
    match (&c.purl, &c.version) {
        (Some(purl), _) => purl.clone(),
        (None, Some(v)) => format!("{} {v}", c.name),
        (None, None) => c.name.clone(),
    }
}

fn describe(reason: &NotCheckedReason) -> String {
    match reason {
        NotCheckedReason::InvalidPurl => "the package URL could not be parsed".to_string(),
        NotCheckedReason::OsPackageWithoutDistro => {
            "a deb or apk package URL needs a distro qualifier such as distro=debian-12".to_string()
        }
        other => format!("{other:?}"),
    }
}

fn describe_query(q: &OsvQuery) -> String {
    match (&q.purl, &q.name, &q.ecosystem) {
        (Some(purl), _, _) => purl.clone(),
        (None, Some(name), Some(eco)) => format!("{eco}/{name}"),
        _ => String::new(),
    }
}

/// Picks the product a name means: an exact product token, optionally after a vendor word, unless
/// a product whose name contains that token has three times its entries; otherwise a group with
/// three times the entries of the next. Returns up to ten candidates when neither applies, or none
/// when the dictionary has no match.
pub fn choose_product(name: &str, products: Vec<CpeProduct>) -> Result<CpeProduct, Vec<String>> {
    let wanted: String = name
        .trim()
        .to_lowercase()
        .split(|c: char| c.is_whitespace() || c == '-')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    let exact = |p: &CpeProduct| {
        p.product == wanted
            || wanted.split_once('_').is_some_and(|(vendor, rest)| {
                p.product == rest && p.vendors.iter().any(|v| v == vendor)
            })
    };
    // The dictionary sample includes unrelated products whose titles share a word, so only a
    // product whose name contains the wanted token can outrank an exact match.
    let rival = products
        .iter()
        .filter(|p| p.product != wanted && p.product.contains(&wanted))
        .map(|p| p.entries)
        .max()
        .unwrap_or(0);
    if let Some(p) = products.iter().find(|p| exact(p))
        && rival < 3 * p.entries
    {
        return Ok(p.clone());
    }
    match products.as_slice() {
        [] => Err(Vec::new()),
        [only] => Ok(only.clone()),
        [first, second, ..] if first.entries >= 3 * second.entries => Ok(first.clone()),
        _ => Err(products
            .iter()
            .take(10)
            .map(|p| {
                format!(
                    "{}:{} (vendors: {})",
                    p.part,
                    p.product,
                    p.vendors.join(", ")
                )
            })
            .collect()),
    }
}

/// A KEV entry's vulnerability name and description, which often name the impact, such as
/// "Remote Code Execution Vulnerability".
pub fn kev_text(k: &KevEntry) -> String {
    format!("{}. {}", k.vulnerability_name, k.short_description)
}

/// The first CVSS vector on the record, NVD's own when it has one.
pub fn nvd_vector(s: &NvdSummary) -> Option<&str> {
    s.cvss
        .iter()
        .map(|c| c.vector.as_str())
        .find(|v| !v.is_empty())
}

fn from_nvd(s: &NvdSummary, source: &str, product: &str) -> Finding {
    let cvss = s.cvss.first();
    let mut fixed: Vec<String> = Vec::new();
    for a in s.affected.iter().filter(|a| a.product == product) {
        if let Some(v) = &a.version_end_excluding
            && !fixed.contains(v)
        {
            fixed.push(v.clone());
        }
    }
    Finding {
        cve: s.id.clone(),
        aliases: Vec::new(),
        summary: summary_line(&s.description),
        impact: impact::classify(&s.cwes, &s.description, nvd_vector(s)),
        description: Some(s.description.clone()).filter(|d| !d.is_empty()),
        cvss_score: cvss.and_then(|c| c.base_score),
        cvss_severity: cvss.and_then(|c| c.base_severity.clone()),
        cvss_vector: cvss.map(|c| c.vector.clone()).filter(|v| !v.is_empty()),
        in_kev: None,
        kev_date_added: None,
        epss: None,
        epss_percentile: None,
        published: Some(s.published.clone()).filter(|p| !p.is_empty()),
        fixed_versions: fixed,
        confirmed: source != "nvd-description",
        source: source.to_string(),
        url: format!("https://nvd.nist.gov/vuln/detail/{}", s.id),
        component: None,
        files: Vec::new(),
        poc_repos: None,
        notice_text: false,
    }
}

/// One finding per CVE the record names in `aliases` or `upstream` (Debian and Ubuntu notices
/// list their CVEs as upstream), or one under the OSV id when it names none.
fn from_osv(v: &OsvVuln) -> Vec<Finding> {
    let mut cves: Vec<&String> = Vec::new();
    for id in v.aliases.iter().chain(&v.upstream) {
        if id.starts_with("CVE-") && !cves.contains(&id) {
            cves.push(id);
        }
    }
    let vector = v
        .severity
        .iter()
        .find(|s| s.kind == "CVSS_V3")
        .or(v.severity.first())
        .map(|s| s.score.clone());
    let mut fixed: Vec<String> = Vec::new();
    for e in v
        .affected
        .iter()
        .flat_map(|a| &a.ranges)
        .filter(|r| r.kind != "GIT")
        .flat_map(|r| &r.events)
    {
        if let Some(f) = &e.fixed
            && !fixed.contains(f)
        {
            fixed.push(f.clone());
        }
    }
    let text = if v.summary.is_empty() {
        &v.details
    } else {
        &v.summary
    };
    let full = if v.details.is_empty() {
        &v.summary
    } else {
        &v.details
    };
    let cwes: Vec<String> = v
        .database_specific
        .as_ref()
        .and_then(|d| d.get("cwe_ids"))
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
        .filter_map(|c| c.as_str().map(str::to_string))
        .collect();
    let base = Finding {
        cve: v.id.clone(),
        aliases: Vec::new(),
        summary: summary_line(text),
        impact: impact::classify(&cwes, full, vector.as_deref()),
        description: Some(full.clone()).filter(|d| !d.is_empty()),
        // OSV gives a CVSS vector, not a score, and no CVSS calculator is used.
        cvss_score: None,
        cvss_severity: v
            .database_specific
            .as_ref()
            .and_then(|d| d.get("severity"))
            .and_then(|s| s.as_str())
            .map(str::to_uppercase),
        cvss_vector: vector,
        in_kev: None,
        kev_date_added: None,
        epss: None,
        epss_percentile: None,
        published: v.published.clone(),
        fixed_versions: fixed,
        confirmed: true,
        source: format!("osv:{}", v.id),
        url: format!("https://osv.dev/vulnerability/{}", v.id),
        component: None,
        files: Vec::new(),
        poc_repos: None,
        notice_text: false,
    };
    if cves.is_empty() {
        return vec![base];
    }
    cves.into_iter()
        .map(|cve| Finding {
            cve: cve.clone(),
            aliases: vec![v.id.clone()],
            notice_text: !v.aliases.contains(cve),
            ..base.clone()
        })
        .collect()
}

/// Merges findings for the same CVE and component, as when OSV has both a GHSA and a PYSEC
/// record for one CVE.
fn merge_duplicates(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: Vec<Finding> = Vec::new();
    let mut index: HashMap<(String, Option<String>), usize> = HashMap::new();
    for f in findings {
        let key = (f.cve.clone(), f.component.clone());
        let Some(&i) = index.get(&key) else {
            index.insert(key, merged.len());
            merged.push(f);
            continue;
        };
        let m = &mut merged[i];
        for a in f.aliases {
            if !m.aliases.contains(&a) {
                m.aliases.push(a);
            }
        }
        for v in f.fixed_versions {
            if !m.fixed_versions.contains(&v) {
                m.fixed_versions.push(v);
            }
        }
        impact::merge(&mut m.impact, f.impact);
        m.cvss_severity = m.cvss_severity.take().or(f.cvss_severity);
        m.cvss_vector = m.cvss_vector.take().or(f.cvss_vector);
        m.published = m.published.take().or(f.published);
        m.description = m.description.take().or(f.description);
    }
    merged
}

/// The first sentence of `text`, at most `SUMMARY_CHARS` characters.
pub fn summary_line(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let end = text.find(". ").map(|i| i + 1).unwrap_or(text.len());
    text[..end].chars().take(SUMMARY_CHARS).collect()
}

async fn enrich(findings: &mut [Finding], src: &Sources<'_>, warnings: &mut Vec<String>) {
    let mut ids: Vec<CveId> = Vec::new();
    for f in findings.iter() {
        if let Ok(id) = CveId::parse(&f.cve)
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        // KEV lists CVEs only, so findings without a CVE id are known not to be listed.
        for f in findings.iter_mut() {
            f.in_kev = Some(false);
        }
        return;
    }
    match src.epss.scores(&ids).await {
        Ok(batch) => {
            let by_id: HashMap<&str, _> =
                batch.scores.iter().map(|s| (s.cve.as_str(), s)).collect();
            for f in findings.iter_mut() {
                if let Some(s) = by_id.get(f.cve.as_str()) {
                    f.epss = Some(s.epss);
                    f.epss_percentile = Some(s.percentile);
                }
            }
        }
        Err(e) => warnings.push(format!("EPSS unavailable: {e}")),
    }
    match src.kev.lookup(&ids).await {
        Ok(batch) => {
            let by_id: HashMap<&str, _> = batch
                .listed
                .iter()
                .map(|k| (k.cve_id.as_str(), k))
                .collect();
            for f in findings.iter_mut() {
                let entry = by_id.get(f.cve.as_str());
                f.in_kev = Some(entry.is_some());
                f.kev_date_added = entry.map(|k| k.date_added.clone());
                if let Some(k) = entry {
                    impact::refine(&mut f.impact, "CISA KEV", &kev_text(k));
                }
            }
        }
        Err(e) => warnings.push(format!("KEV unavailable, so in_kev is null: {e}")),
    }
}

fn rank(findings: &mut [Finding]) {
    let desc = |a: Option<f64>, b: Option<f64>| match (a, b) {
        (Some(a), Some(b)) => b.partial_cmp(&a).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    findings.sort_by(|a, b| {
        b.in_kev
            .cmp(&a.in_kev)
            .then_with(|| desc(a.epss, b.epss))
            .then_with(|| desc(a.cvss_score, b.cvss_score))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn product(part: &str, name: &str, vendors: &[&str], entries: usize) -> CpeProduct {
        CpeProduct {
            part: part.to_string(),
            product: name.to_string(),
            vendors: vendors.iter().map(|v| v.to_string()).collect(),
            entries,
        }
    }

    #[test]
    fn chooses_exact_token_vendor_prefixed_name_or_dominant_group() {
        let tomcat = vec![
            product(
                "a",
                "tomcat",
                &["apache", "apache_software_foundation"],
                438,
            ),
            product("a", "tomcat_native", &["apache"], 41),
        ];
        assert_eq!(
            choose_product("Apache Tomcat", tomcat).unwrap().product,
            "tomcat"
        );
        let nginx = vec![
            product("a", "nginx_ingress_controller", &["kubernetes"], 900),
            product("a", "nginx", &["nginx", "igor_sysoev"], 893),
        ];
        assert_eq!(choose_product("nginx", nginx).unwrap().product, "nginx");
        let dominant = vec![
            product("o", "fortios", &["fortinet"], 300),
            product("a", "fortios_ips", &["fortinet"], 20),
        ];
        assert_eq!(
            choose_product("forti os", dominant).unwrap().product,
            "fortios"
        );
    }

    #[test]
    fn unrelated_products_in_the_sample_do_not_outrank_an_exact_name() {
        let sample = vec![
            product("a", "insight_diagnostics", &["hp"], 30),
            product("a", "itunes", &["apple"], 20),
            product("o", "windows_7", &["microsoft"], 4),
        ];
        assert_eq!(
            choose_product("Windows 7", sample).unwrap().product,
            "windows_7"
        );
    }

    #[test]
    fn close_groups_without_exact_token_are_candidates() {
        let exchange = vec![
            product("a", "exchange_server", &["microsoft"], 40),
            product("a", "exchange_online", &["microsoft"], 30),
        ];
        let candidates = choose_product("exchange", exchange).unwrap_err();
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].starts_with("a:exchange_server"));
        assert!(
            choose_product("nothing", Vec::new())
                .unwrap_err()
                .is_empty()
        );
    }

    fn vuln(id: &str, aliases: &[&str], upstream: &[&str]) -> OsvVuln {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        OsvVuln {
            id: id.to_string(),
            aliases: own(aliases),
            upstream: own(upstream),
            summary: format!("{id} summary"),
            details: String::new(),
            published: None,
            severity: Vec::new(),
            affected: Vec::new(),
            database_specific: None,
        }
    }

    #[test]
    fn git_range_commits_are_not_fixed_versions() {
        let mut v = vuln("GHSA-x84v-xcm2-53pg", &["CVE-2018-18074"], &[]);
        v.affected = serde_json::from_value(serde_json::json!([{"ranges": [
            {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "c45d7c49ea75133e52ab22a8e9e13173938e36ff"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}
        ]}]))
        .unwrap();
        assert_eq!(from_osv(&v)[0].fixed_versions, ["2.20.0"]);
    }

    #[test]
    fn debian_notice_yields_one_finding_per_upstream_cve() {
        let dla = vuln(
            "DLA-3942-1",
            &[],
            &["CVE-2023-5678", "CVE-2024-0727", "DEBIAN-CVE-2023-5678"],
        );
        let f = from_osv(&dla);
        let cves: Vec<&str> = f.iter().map(|f| f.cve.as_str()).collect();
        assert_eq!(cves, ["CVE-2023-5678", "CVE-2024-0727"]);
        assert!(f.iter().all(|f| f.aliases == ["DLA-3942-1"]));
        assert_eq!(from_osv(&vuln("GHSA-xxxx", &[], &[]))[0].cve, "GHSA-xxxx");
    }

    #[test]
    fn records_for_the_same_cve_merge() {
        let mut ghsa = vuln("GHSA-j8r2-6x86-q33q", &["CVE-2023-32681"], &[]);
        ghsa.database_specific = Some(serde_json::json!({ "severity": "MODERATE" }));
        let pysec = vuln("PYSEC-2023-74", &["CVE-2023-32681"], &[]);
        let merged = merge_duplicates(
            from_osv(&pysec)
                .into_iter()
                .chain(from_osv(&ghsa))
                .collect(),
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].aliases, ["PYSEC-2023-74", "GHSA-j8r2-6x86-q33q"]);
        assert_eq!(merged[0].cvss_severity.as_deref(), Some("MODERATE"));
    }

    #[test]
    fn exact_name_loses_to_a_much_larger_product() {
        let exchange = vec![
            product("a", "exchange_server", &["microsoft"], 60),
            product("a", "exchange", &["oracle"], 5),
        ];
        assert_eq!(
            choose_product("exchange", exchange).unwrap().product,
            "exchange_server"
        );
        let close = vec![
            product("a", "exchange_server", &["microsoft"], 12),
            product("a", "exchange", &["oracle"], 5),
        ];
        assert_eq!(
            choose_product("exchange", close).unwrap().product,
            "exchange"
        );
    }

    #[test]
    fn ranks_kev_then_epss_then_cvss() {
        let row = |cve: &str, kev: bool, epss: Option<f64>, score: Option<f64>| Finding {
            in_kev: Some(kev),
            epss,
            cvss_score: score,
            ..from_osv(&vuln(cve, &[], &[])).remove(0)
        };
        let mut f = vec![
            row("A", false, Some(0.9), Some(9.8)),
            row("B", true, Some(0.1), Some(5.0)),
            row("C", false, None, Some(10.0)),
            row("D", false, Some(0.9), Some(7.0)),
        ];
        rank(&mut f);
        let ids: Vec<&str> = f.iter().map(|f| f.cve.as_str()).collect();
        assert_eq!(ids, ["B", "A", "D", "C"]);
    }

    #[test]
    fn action_upgrades_past_every_listed_fix_and_flags_the_rest() {
        let row = |cve: &str, fixed: &[&str], poc: Option<usize>| Finding {
            fixed_versions: fixed.iter().map(|v| v.to_string()).collect(),
            in_kev: Some(false),
            poc_repos: poc,
            ..from_osv(&vuln(cve, &[], &[])).remove(0)
        };
        let a = row("CVE-1", &["2.3.1", "2.12.2", "2.15.0"], Some(0));
        let b = row("CVE-2", &["2.16.0"], Some(2));
        let c = row("CVE-3", &[], None);
        let plan = action("log4j".into(), Some("2.12.1".into()), &[&a, &b, &c]);
        assert_eq!(plan.upgrade_to.as_deref(), Some("2.16.0"));
        assert_eq!(plan.fixed_versions, ["2.3.1", "2.12.2", "2.15.0", "2.16.0"]);
        assert_eq!(plan.no_fix_listed, ["CVE-3"]);
        assert_eq!(plan.in_kev, Some(false));
        assert_eq!(plan.poc, Some(true));
        assert!(
            plan.needs_verification
                .iter()
                .any(|n| n == "PoC index not checked for CVE-3")
        );

        let plan = action("log4j".into(), None, &[&a]);
        assert_eq!(
            plan.upgrade_to, None,
            "no upgrade without an installed version"
        );
        assert_eq!(plan.poc, Some(false));
        let unknown = Finding {
            in_kev: None,
            ..a.clone()
        };
        assert_eq!(action("x".into(), None, &[&unknown]).in_kev, None);
    }

    #[test]
    fn summary_is_the_first_sentence_capped() {
        assert_eq!(summary_line("First part. Second part."), "First part.");
        assert_eq!(
            summary_line("Issue summary: Processing some\nASN.1 identifiers.\n\nImpact"),
            "Issue summary: Processing some ASN.1 identifiers."
        );
        assert_eq!(
            summary_line(&"x".repeat(500)).chars().count(),
            SUMMARY_CHARS
        );
    }
}
