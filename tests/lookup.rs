use std::path::PathBuf;
use std::time::Duration;

use oxiploitability_mcp::cna::CnaClient;
use oxiploitability_mcp::component::Component;
use oxiploitability_mcp::epss::EpssClient;
use oxiploitability_mcp::http::client;
use oxiploitability_mcp::kev::KevCatalog;
use oxiploitability_mcp::lookup::{ScanTarget, Sources, product_cves, scan_sbom};
use oxiploitability_mcp::nvd::NvdClient;
use oxiploitability_mcp::osv::OsvClient;
use oxiploitability_mcp::poc::PocClient;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEV_FIXTURE: &str = include_str!("fixtures/kev_small.json");
const EPSS_BODY: &str = r#"{"data":[{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-10-21"},{"cve":"CVE-2021-23017","epss":"0.500000000","percentile":"0.990000000","date":"2026-10-21"}]}"#;
const UNANALYZED: &str = r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-9999","published":"2026-10-01T00:00:00.000","vulnStatus":"Awaiting Analysis","descriptions":[{"lang":"en","value":"nginx before 1.29 mishandles something. More text."}]}}]}"#;

struct Upstreams {
    server: MockServer,
    nvd: NvdClient,
    epss: EpssClient,
    kev: KevCatalog,
    osv: OsvClient,
    cna: CnaClient,
    poc: PocClient,
}

impl Upstreams {
    async fn new() -> Self {
        let server = MockServer::start().await;
        let uri = server.uri();
        Mock::given(method("GET"))
            .and(path("/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(EPSS_BODY, "application/json"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(KEV_FIXTURE, "application/json"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/osv/query"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                include_str!("fixtures/osv_query_log4j.json"),
                "application/json",
            ))
            .mount(&server)
            .await;
        Self {
            nvd: NvdClient::new(client(), Some("test-key".into()))
                .with_base_url(format!("{uri}/cves"))
                .with_cpe_url(format!("{uri}/cpes"))
                .with_retry_backoff(Duration::ZERO),
            epss: EpssClient::new(client()).with_base_url(format!("{uri}/epss")),
            kev: KevCatalog::new(client()).with_url(format!("{uri}/kev.json")),
            osv: OsvClient::new(client()).with_base_url(format!("{uri}/osv")),
            cna: CnaClient::new(client()).with_base_url(format!("{uri}/cna")),
            poc: PocClient::new(client()).with_base_url(format!("{uri}/poc")),
            server,
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

    async fn mount_nginx(&self) {
        self.mount_kev(r#"{"totalResults":0,"vulnerabilities":[]}"#)
            .await;
        Mock::given(method("GET"))
            .and(path("/cpes"))
            .and(query_param("keywordSearch", "nginx"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(include_str!("fixtures/cpe_nginx.json"), "application/json"),
            )
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/cves"))
            .and(query_param("virtualMatchString", "cpe:2.3:a:*:nginx"))
            .and(query_param("versionStart", "1.18.0"))
            .and(query_param("versionEndType", "including"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                include_str!("fixtures/nvd_search_nginx_1.18.0.json"),
                "application/json",
            ))
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/cves"))
            .and(query_param("keywordSearch", "nginx"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(UNANALYZED, "application/json"))
            .mount(&self.server)
            .await;
    }
}

impl Upstreams {
    /// Answers NVD's KEV-only searches ahead of the broader mocks.
    async fn mount_kev(&self, body: &'static str) {
        Mock::given(method("GET"))
            .and(path("/cves"))
            .and(query_param("hasKev", ""))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .with_priority(1)
            .mount(&self.server)
            .await;
    }
}

fn component(name: &str, version: Option<&str>, purl: Option<&str>) -> Component {
    Component {
        name: name.to_string(),
        version: version.map(str::to_string),
        purl: purl.map(str::to_string),
        cpe: None,
        ecosystem: None,
    }
}

#[tokio::test]
async fn product_name_and_version_resolve_through_nvd_and_rank() {
    let up = Upstreams::new().await;
    up.mount_nginx().await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.matched.as_deref(), Some("a:nginx (any vendor)"));
    assert_eq!(
        a.total, 7,
        "6 confirmed from the version search plus 1 description match"
    );
    assert_eq!(a.unconfirmed, 1);
    assert_eq!(a.kev, Some(0));
    assert!(!a.partial);
    assert_eq!(
        a.findings[0].cve, "CVE-2021-23017",
        "highest EPSS first when nothing is in KEV"
    );
    let unconfirmed = a
        .findings
        .iter()
        .find(|f| f.cve == "CVE-2026-9999")
        .unwrap();
    assert!(!unconfirmed.confirmed);
    assert_eq!(
        unconfirmed.summary,
        "nginx before 1.29 mishandles something."
    );
    assert!(
        a.findings
            .iter()
            .filter(|f| f.cve != "CVE-2026-9999")
            .all(|f| f.confirmed && f.cvss_severity.is_some())
    );
}

#[tokio::test]
async fn package_url_goes_to_osv_with_kev_and_epss() {
    let up = Upstreams::new().await;
    let purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
    let a = product_cves(&up.sources(), &component(purl, None, Some(purl)), 25, false)
        .await
        .unwrap();
    assert_eq!(a.matched.as_deref(), Some(purl));
    let f = &a.findings[0];
    assert_eq!(f.cve, "CVE-2021-44228");
    assert_eq!(f.in_kev, Some(true));
    assert_eq!(f.kev_date_added.as_deref(), Some("2021-12-10"));
    assert_eq!(f.epss, Some(0.99999));
    assert_eq!(f.cvss_severity.as_deref(), Some("CRITICAL"));
    assert!(f.aliases.contains(&"GHSA-jfh8-c2jp-5v3q".to_string()));
    assert!(f.fixed_versions.contains(&"2.15.0".to_string()));
    let action = a.action.unwrap();
    assert_eq!(action.component, purl);
    assert_eq!(action.installed_version.as_deref(), Some("2.14.1"));
    assert_eq!(action.upgrade_to.as_deref(), Some("2.15.0"));
    assert_eq!(action.poc, Some(false));
}

#[tokio::test]
async fn ambiguous_name_returns_candidates_and_no_findings() {
    let up = Upstreams::new().await;
    let names: Vec<String> = (0..10)
        .map(|i| {
            format!(
                r#"{{"cpe":{{"cpeName":"cpe:2.3:a:microsoft:exchange_server:{i}:*:*:*:*:*:*:*"}}}}"#
            )
        })
        .chain((0..8).map(|i| {
            format!(
                r#"{{"cpe":{{"cpeName":"cpe:2.3:a:microsoft:exchange_online:{i}:*:*:*:*:*:*:*"}}}}"#
            )
        }))
        .collect();
    Mock::given(method("GET"))
        .and(path("/cpes"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(r#"{{"products":[{}]}}"#, names.join(",")),
            "application/json",
        ))
        .mount(&up.server)
        .await;
    let a = product_cves(&up.sources(), &component("exchange", None, None), 25, false)
        .await
        .unwrap();
    assert!(a.findings.is_empty());
    assert_eq!(a.candidates.len(), 2);
    let requests = up.server.received_requests().await.unwrap();
    assert!(
        requests.iter().all(|r| r.url.path() != "/cves"),
        "no CVE search for an ambiguous name"
    );
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "oxiploitability-test-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn sbom_scan_checks_components_reports_gaps_and_writes_report() {
    let up = Upstreams::new().await;
    up.mount_nginx().await;
    let dir = temp_dir("scan");
    let sbom = dir.join("bom.json");
    std::fs::write(
        &sbom,
        r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
            {"name":"libssl1.1","purl":"pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3"},
            {"name":"nginx","version":"1.18.0"},
            {"name":"mystery"}]}"#,
    )
    .unwrap();
    let a = scan_sbom(
        &up.sources(),
        ScanTarget::File(sbom.to_str().unwrap()),
        3,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.format, "cyclonedx-json");
    assert_eq!(a.components, 4);
    assert_eq!(a.vulnerable_components, 2);
    assert_eq!(a.findings.len(), 3);
    assert!(a.truncated);
    assert_eq!(a.findings[0].cve, "CVE-2021-44228");
    assert_eq!(
        a.findings[0].component.as_deref(),
        Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    );
    let reasons: Vec<String> = a
        .not_checked
        .iter()
        .map(|n| {
            serde_json::to_value(n).unwrap()["reason"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(reasons, ["os_package_without_distro", "no_version"]);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("bom.json.oxiploitability.json")).unwrap())
            .unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), a.total);
    assert!(
        report["findings"][0]["description"].is_string(),
        "reports always carry full descriptions"
    );
    assert!(a.findings.iter().all(|f| f.description.is_none()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn sbom_scan_preserves_existing_reports_and_uses_new_names() {
    let up = Upstreams::new().await;
    let dir = temp_dir("report-collision");
    let sbom = dir.join("bom.json");
    std::fs::write(&sbom, r#"{"bomFormat":"CycloneDX","components":[]}"#).unwrap();
    let original = dir.join("bom.json.oxiploitability.json");
    std::fs::write(&original, "existing report").unwrap();

    let first = scan_sbom(
        &up.sources(),
        ScanTarget::File(sbom.to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap();
    let second = scan_sbom(
        &up.sources(),
        ScanTarget::File(sbom.to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(&original).unwrap(),
        "existing report"
    );
    assert_eq!(
        first.report,
        std::fs::canonicalize(dir.join("bom.json.oxiploitability.1.json"))
            .unwrap()
            .display()
            .to_string()
    );
    assert_eq!(
        second.report,
        std::fs::canonicalize(dir.join("bom.json.oxiploitability.2.json"))
            .unwrap()
            .display()
            .to_string()
    );
    for answer in [first, second] {
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&answer.report).unwrap()).unwrap();
        assert_eq!(report["report"], answer.report);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn sbom_scan_does_not_follow_existing_report_symlink() {
    let up = Upstreams::new().await;
    let dir = temp_dir("report-symlink");
    let sbom = dir.join("bom.json");
    std::fs::write(&sbom, r#"{"bomFormat":"CycloneDX","components":[]}"#).unwrap();
    let target = dir.join("keep.txt");
    std::fs::write(&target, "keep this").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("bom.json.oxiploitability.json")).unwrap();

    let answer = scan_sbom(
        &up.sources(),
        ScanTarget::File(sbom.to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap();

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep this");
    assert_eq!(
        answer.report,
        std::fs::canonicalize(dir.join("bom.json.oxiploitability.1.json"))
            .unwrap()
            .display()
            .to_string()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn sbom_scan_refuses_dotenv_and_directories() {
    let up = Upstreams::new().await;
    let dir = temp_dir("refuse");
    std::fs::write(dir.join(".env"), "KEY=value").unwrap();
    let err = scan_sbom(
        &up.sources(),
        ScanTarget::File(dir.join(".env").to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap_err();
    assert!(err.contains(".env"));
    assert!(
        scan_sbom(
            &up.sources(),
            ScanTarget::File(dir.to_str().unwrap()),
            25,
            false
        )
        .await
        .is_err()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn kev_cves_beyond_the_newest_page_are_added_and_ranked_first() {
    let up = Upstreams::new().await;
    up.mount_kev(
        r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","published":"2021-12-10T10:15:09.143","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Old KEV-listed flaw."}]}}]}"#,
    )
    .await;
    up.mount_nginx().await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.kev, Some(1), "the KEV count comes from NVD's KEV search");
    assert_eq!(a.findings[0].cve, "CVE-2021-44228");
    assert_eq!(a.findings[0].in_kev, Some(true));
    assert!(a.findings[0].confirmed);
    assert_eq!(
        a.findings.len(),
        8,
        "6 newest, 1 from the KEV page, 1 description match"
    );
}

#[tokio::test]
async fn without_a_key_only_essential_nvd_requests_are_sent() {
    let mut up = Upstreams::new().await;
    up.nvd = NvdClient::new(client(), None)
        .with_base_url(format!("{}/cves", up.server.uri()))
        .with_cpe_url(format!("{}/cpes", up.server.uri()))
        .with_retry_backoff(Duration::ZERO);
    up.mount_nginx().await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.total, 6);
    assert_eq!(a.unconfirmed, 0);
    assert!(a.warnings[0].starts_with("no NVD API key"));
    let nvd_requests = up
        .server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == "/cves" || r.url.path() == "/cpes")
        .count();
    assert_eq!(nvd_requests, 4, "resolve, count, newest page, KEV count");
}

async fn mount_cna(up: &Upstreams, vendor: &str, product: &str, version: &str) {
    Mock::given(method("GET"))
        .and(path("/cna/CVE-2026-9999"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(
                r#"{{"containers":{{"cna":{{"affected":[{{"vendor":"{vendor}","product":"{product}","versions":[{{"version":"{version}","status":"affected"}}]}}]}}}}}}"#
            ),
            "application/json",
        ))
        .mount(&up.server)
        .await;
}

#[tokio::test]
async fn cna_record_confirms_a_description_match_for_the_product_and_version() {
    let up = Upstreams::new().await;
    up.mount_nginx().await;
    mount_cna(&up, "F5", "NGINX", "< 1.29.0").await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.unconfirmed, 0);
    assert_eq!(a.total, 7);
    let f = a
        .findings
        .iter()
        .find(|f| f.cve == "CVE-2026-9999")
        .unwrap();
    assert!(f.confirmed);
    assert_eq!(f.source, "cve.org-cna");
    assert_eq!(f.url, "https://www.cve.org/CVERecord?id=CVE-2026-9999");
}

#[tokio::test]
async fn cna_record_for_another_product_or_out_of_range_version_leaves_findings() {
    let up = Upstreams::new().await;
    up.mount_nginx().await;
    mount_cna(&up, "0xJacky", "nginx-ui", "< 2.4.1").await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        false,
    )
    .await
    .unwrap();
    assert!(a.findings.iter().all(|f| f.cve != "CVE-2026-9999"));
    assert_eq!(a.other_products.len(), 1);
    assert_eq!(a.other_products[0].product, "0xJacky nginx-ui");
    assert_eq!((a.total, a.unconfirmed), (6, 0));

    let up = Upstreams::new().await;
    up.mount_nginx().await;
    mount_cna(&up, "F5", "NGINX", ">= 1.25.0, < 1.29.0").await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        false,
    )
    .await
    .unwrap();
    assert!(a.findings.iter().all(|f| f.cve != "CVE-2026-9999"));
    assert_eq!((a.total, a.unconfirmed), (6, 0));
}

#[tokio::test]
async fn nickname_resolves_to_its_cves() {
    let up = Upstreams::new().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/nvd_cve_2023_38606.json"),
            "application/json",
        ))
        .mount(&up.server)
        .await;
    let a = product_cves(
        &up.sources(),
        &component("Eternal Blue", None, None),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        a.matched.as_deref(),
        Some("nickname: EternalBlue (MS17-010)")
    );
    assert!(a.findings.iter().all(|f| f.source == "nickname"));
    let mut asked: Vec<String> = up
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter_map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "cveId")
                .map(|(_, v)| v.into_owned())
        })
        .collect();
    asked.sort();
    assert_eq!(
        asked,
        [
            "CVE-2017-0143",
            "CVE-2017-0144",
            "CVE-2017-0145",
            "CVE-2017-0146",
            "CVE-2017-0147",
            "CVE-2017-0148"
        ]
    );
}

#[tokio::test]
async fn lockfile_scan_queries_osv_by_ecosystem_and_writes_a_report() {
    let up = Upstreams::new().await;
    let dir = temp_dir("lockfile");
    let lock = dir.join("package-lock.json");
    std::fs::write(&lock, include_bytes!("fixtures/lock/package-lock.json")).unwrap();
    let a = scan_sbom(
        &up.sources(),
        ScanTarget::File(lock.to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.format, "npm-lock");
    assert_eq!(a.components, 2);
    let bodies: Vec<serde_json::Value> = up
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/osv/query")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert!(bodies.iter().any(|b| b["package"]["name"] == "lodash"
        && b["package"]["ecosystem"] == "npm"
        && b["version"] == "4.17.20"));
    assert!(dir.join("package-lock.json.oxiploitability.json").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

const LOG4J_BOM: &str = r#"{"bomFormat":"CycloneDX","components":[
    {"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}"#;

async fn mount_log4j_poc(up: &Upstreams) {
    Mock::given(method("GET"))
        .and(path("/poc/2021/CVE-2021-44228.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/poc_cve_2017_0144.json"),
            "application/json",
        ))
        .mount(&up.server)
        .await;
}

#[tokio::test]
async fn directory_scan_finds_inventories_names_their_files_and_plans_upgrades() {
    let up = Upstreams::new().await;
    mount_log4j_poc(&up).await;
    let dir = temp_dir("directory");
    for sub in ["app", "sub", "node_modules/dep", ".git"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::write(
        dir.join("app/package-lock.json"),
        include_bytes!("fixtures/lock/package-lock.json"),
    )
    .unwrap();
    for p in [
        "bom.json",
        "sub/bom.json",
        "node_modules/dep/bom.json",
        ".git/bom.json",
    ] {
        std::fs::write(dir.join(p), LOG4J_BOM).unwrap();
    }
    std::fs::write(dir.join("broken.cdx.json"), "not json").unwrap();
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();

    let a = scan_sbom(
        &up.sources(),
        ScanTarget::File(dir.to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.format, "directory");
    let paths: Vec<&str> = a.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "app/package-lock.json",
            "bom.json",
            "broken.cdx.json",
            "sub/bom.json"
        ],
        "hidden and dependency directories are skipped"
    );
    assert!(a.files[2].error.is_some());
    assert_eq!(a.components, 3, "log4j-core listed twice is checked once");
    assert_eq!((a.checked_components, a.not_checked_components), (3, 0));
    assert_eq!(a.kev, Some(3));

    let log4j = a
        .actions
        .iter()
        .find(|x| x.component.contains("log4j-core"))
        .unwrap();
    assert_eq!(log4j.files, ["bom.json", "sub/bom.json"]);
    assert_eq!(log4j.installed_version.as_deref(), Some("2.14.1"));
    assert_eq!(log4j.upgrade_to.as_deref(), Some("2.15.0"));
    assert_eq!(log4j.in_kev, Some(true));
    assert_eq!(log4j.poc, Some(true));
    assert_eq!(log4j.impacts, ["RCE", "DoS"], "from the advisory's CWE ids");
    assert_eq!(log4j.advisories[0].impact[0].evidence, "CWE-502");
    let advisory = &log4j.advisories[0];
    assert_eq!(advisory.cve, "CVE-2021-44228");
    assert!(advisory.poc_repos.unwrap() > 0);
    assert!(
        advisory
            .poc_index
            .as_deref()
            .unwrap()
            .ends_with("2021/CVE-2021-44228.json")
    );
    assert!(advisory.url.starts_with("https://osv.dev/vulnerability/"));
    assert!(
        a.findings
            .iter()
            .filter(|f| f
                .component
                .as_deref()
                .is_some_and(|c| c.contains("log4j-core")))
            .all(|f| f.files == ["bom.json", "sub/bom.json"])
    );
    assert_eq!(
        a.report,
        std::fs::canonicalize(dir.join("oxiploitability.json"))
            .unwrap()
            .display()
            .to_string()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn unreadable_kev_catalog_leaves_kev_status_unknown() {
    let mut up = Upstreams::new().await;
    up.kev = KevCatalog::new(client()).with_url(format!("{}/missing-kev.json", up.server.uri()));
    let dir = temp_dir("kev-unknown");
    let sbom = dir.join("bom.json");
    std::fs::write(&sbom, LOG4J_BOM).unwrap();
    let a = scan_sbom(
        &up.sources(),
        ScanTarget::File(sbom.to_str().unwrap()),
        25,
        false,
    )
    .await
    .unwrap();
    assert_eq!(a.kev, None);
    assert!(a.findings.iter().all(|f| f.in_kev.is_none()));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&a.report).unwrap()).unwrap();
    assert!(report["findings"][0]["in_kev"].is_null());
    assert!(report["kev"].is_null());
    let action = &a.actions[0];
    assert_eq!(action.in_kev, None);
    assert_eq!(
        action.poc,
        Some(false),
        "the PoC index lists nothing for it"
    );
    assert!(
        action
            .needs_verification
            .iter()
            .any(|n| n.starts_with("KEV status unknown"))
    );
    assert!(a.warnings.iter().any(|w| w.starts_with("KEV unavailable")));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn image_references_are_validated_before_any_tool_runs() {
    let up = Upstreams::new().await;
    for bad in ["--output=/etc/passwd", "nginx latest", "", "a;b"] {
        let err = scan_sbom(&up.sources(), ScanTarget::Image(bad), 25, false)
            .await
            .unwrap_err();
        assert!(
            err.contains("not a valid image reference"),
            "{bad:?}: {err}"
        );
    }
}

#[tokio::test]
async fn findings_name_their_source_and_link_their_record() {
    let up = Upstreams::new().await;
    up.mount_nginx().await;
    let a = product_cves(
        &up.sources(),
        &component("nginx", Some("1.18.0"), None),
        25,
        true,
    )
    .await
    .unwrap();
    let cpe = a
        .findings
        .iter()
        .find(|f| f.cve == "CVE-2021-23017")
        .unwrap();
    assert_eq!(cpe.source, "nvd-cpe");
    assert_eq!(cpe.url, "https://nvd.nist.gov/vuln/detail/CVE-2021-23017");
    assert!(cpe.description.as_deref().unwrap().len() > cpe.summary.len());
    let described = a
        .findings
        .iter()
        .find(|f| f.cve == "CVE-2026-9999")
        .unwrap();
    assert_eq!(described.source, "nvd-description");
    assert!(!described.confirmed);

    let purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
    let a = product_cves(&up.sources(), &component(purl, None, Some(purl)), 25, false)
        .await
        .unwrap();
    let log4shell = &a.findings[0];
    assert_eq!(log4shell.source, "osv:GHSA-jfh8-c2jp-5v3q");
    assert_eq!(
        log4shell.url,
        "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"
    );
    assert!(
        log4shell.description.is_none(),
        "descriptions only with detail"
    );
}

#[tokio::test]
async fn distro_notice_findings_use_each_cves_own_description() {
    let up = Upstreams::new().await;
    Mock::given(method("POST"))
        .and(path("/osv/query"))
        .and(body_partial_json(serde_json::json!({"package": {"ecosystem": "Debian:11"}})))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"vulns":[{"id":"DLA-3942-1","summary":"openssl - security update","upstream":["CVE-2023-5678","CVE-2024-0727","DEBIAN-CVE-2023-5678"]}]}"#,
            "application/json",
        ))
        .with_priority(1)
        .mount(&up.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cna/CVE-2023-5678"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"containers":{"cna":{"descriptions":[{"lang":"en","value":"Generating excessively long X9.42 DH keys may be slow. More detail."}]}}}"#,
            "application/json",
        ))
        .mount(&up.server)
        .await;
    let purl = "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u3?upstream=openssl&distro=debian-11";
    let a = product_cves(&up.sources(), &component(purl, None, Some(purl)), 25, true)
        .await
        .unwrap();
    let described = a
        .findings
        .iter()
        .find(|f| f.cve == "CVE-2023-5678")
        .unwrap();
    assert_eq!(
        described.summary,
        "Generating excessively long X9.42 DH keys may be slow."
    );
    assert!(
        described
            .description
            .as_deref()
            .unwrap()
            .ends_with("More detail.")
    );
    assert_eq!(described.source, "osv:DLA-3942-1");
    let missing = a
        .findings
        .iter()
        .find(|f| f.cve == "CVE-2024-0727")
        .unwrap();
    assert_eq!(missing.summary, "openssl - security update");
    assert!(
        a.warnings
            .iter()
            .any(|w| w.starts_with("1 distro-notice findings keep"))
    );
}
