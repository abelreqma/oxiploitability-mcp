use std::time::Duration;

use oxiploitability_mcp::cna::CnaClient;
use oxiploitability_mcp::cve::CveId;
use oxiploitability_mcp::epss::EpssClient;
use oxiploitability_mcp::http::{HttpError, client};
use oxiploitability_mcp::kev::KevCatalog;
use oxiploitability_mcp::nvd::NvdClient;
use oxiploitability_mcp::osv::OsvClient;
use oxiploitability_mcp::poc::PocClient;
use oxiploitability_mcp::server::Oxiploitability;
use rmcp::handler::server::wrapper::Parameters;
use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NVD_FIXTURE: &str = include_str!("fixtures/nvd_cve_2023_38606.json");
const KEV_FIXTURE: &str = include_str!("fixtures/kev_small.json");
const EPSS_BODY: &str = r#"{"status":"OK","status-code":200,"version":"1.0","access":"public","total":2,"offset":0,"limit":100,"data":[{"cve":"CVE-2023-38606","epss":"0.028990000","percentile":"0.868270000","date":"2026-10-21"},{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-10-21"}]}"#;

fn id(s: &str) -> CveId {
    CveId::parse(s).unwrap()
}

#[tokio::test]
async fn nvd_lookup_parses_record_and_sends_key_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .and(query_param("cveId", "CVE-2023-38606"))
        .and(header("apiKey", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(NVD_FIXTURE, "application/json"))
        .expect(1)
        .mount(&server)
        .await;

    let nvd = NvdClient::new(client(), Some("test-key".into()))
        .with_base_url(format!("{}/cves", server.uri()));
    assert!(nvd.has_api_key());
    assert_eq!(nvd.requests_per_window(), 50);

    let rec = nvd
        .lookup(&id("cve-2023-38606"))
        .await
        .unwrap()
        .expect("record present");
    assert_eq!(rec.id, "CVE-2023-38606");
    assert_eq!(rec.vuln_status, "Analyzed");
    assert_eq!(rec.cvss.len(), 2, "NVD and CISA ADP scores side by side");
    let cvss = &rec.cvss[0];
    assert_eq!(cvss.version, "3.1");
    assert_eq!(cvss.base_score, Some(5.5));
    assert_eq!(cvss.base_severity.as_deref(), Some("MEDIUM"));
    assert_eq!(cvss.source, "nvd@nist.gov");
    assert_eq!(cvss.metric_type.as_deref(), Some("Primary"));
    assert_eq!(cvss.attack_vector.as_deref(), Some("LOCAL"));
    assert_eq!(rec.cvss[1].metric_type.as_deref(), Some("Secondary"));
    let ssvc = rec.ssvc.as_ref().expect("CISA SSVC decision present");
    assert_eq!(ssvc.exploitation.as_deref(), Some("active"));
    assert_eq!(ssvc.automatable.as_deref(), Some("no"));
    assert_eq!(ssvc.technical_impact.as_deref(), Some("partial"));
    assert_eq!(rec.affected_count, 9);
    assert_eq!(rec.affected[0].vendor, "apple");
    assert_eq!(rec.affected[0].product, "ipados");
    assert_eq!(rec.affected[0].version, "*");
    assert_eq!(
        rec.affected[0].version_end_excluding.as_deref(),
        Some("15.7.8")
    );
    assert_eq!(rec.exploit_reference_count, 0);
    assert_eq!(rec.cisa_exploit_add.as_deref(), Some("2023-07-26"));
    assert!(rec.description.starts_with("This issue was addressed"));
    assert!(rec.cwes.is_empty(), "NVD-CWE-noinfo must be filtered out");
    assert_eq!(
        rec.reference_count, 8,
        "duplicate reference urls are merged"
    );
    assert_eq!(rec.reference_count, rec.references.len());

    let again = nvd.lookup(&id("CVE-2023-38606")).await.unwrap();
    assert!(
        again.is_some(),
        "second lookup is served from cache; mock expects exactly one call"
    );
}

#[tokio::test]
async fn nvd_lookup_without_key_uses_public_limit_and_handles_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-10-21T20:12:33.238","vulnerabilities":[]}"#,
            "application/json",
        ))
        .mount(&server)
        .await;

    let nvd = NvdClient::new(client(), Some("   ".into()))
        .with_base_url(format!("{}/cves", server.uri()));
    assert!(!nvd.has_api_key());
    assert_eq!(nvd.requests_per_window(), 5);
    assert!(nvd.lookup(&id("CVE-0000-0000")).await.unwrap().is_none());
    let received = server.received_requests().await.unwrap();
    assert!(received.iter().all(|r| !r.headers.contains_key("apiKey")));
}

#[tokio::test]
async fn nvd_errors_surface_status_and_size_limits() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/forbidden"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/huge"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![b'x'; 5 * 1024 * 1024], "application/json"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let nvd = NvdClient::new(client(), None)
        .with_base_url(format!("{}/forbidden", server.uri()))
        .with_retry_backoff(Duration::ZERO);
    assert!(matches!(
        nvd.lookup(&id("CVE-2023-38606")).await,
        Err(HttpError::Status { status: 403, .. })
    ));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        3,
        "a rate-limit status is retried twice before it surfaces"
    );

    let nvd = NvdClient::new(client(), None)
        .with_base_url(format!("{}/missing", server.uri()))
        .with_retry_backoff(Duration::ZERO);
    assert!(matches!(
        nvd.lookup(&id("CVE-2023-38606")).await,
        Err(HttpError::Status { status: 404, .. })
    ));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        4,
        "other statuses are not retried"
    );

    let nvd = NvdClient::new(client(), None).with_base_url(format!("{}/huge", server.uri()));
    assert!(matches!(
        nvd.lookup(&id("CVE-2023-38606")).await,
        Err(HttpError::TooLarge { .. })
    ));
}

#[tokio::test]
async fn nvd_retries_a_transient_failure_then_caches_the_record() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(NVD_FIXTURE, "application/json"))
        .mount(&server)
        .await;

    let nvd = NvdClient::new(client(), None)
        .with_base_url(format!("{}/cves", server.uri()))
        .with_retry_backoff(Duration::ZERO);
    let rec = nvd.lookup(&id("CVE-2023-38606")).await.unwrap();
    assert_eq!(rec.unwrap().id, "CVE-2023-38606");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn nvd_concurrent_lookups_of_one_cve_share_a_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(NVD_FIXTURE, "application/json")
                .set_delay(Duration::from_millis(200)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let nvd = NvdClient::new(client(), None).with_base_url(format!("{}/cves", server.uri()));
    let cve = id("CVE-2023-38606");
    let (a, b, c) = tokio::join!(nvd.lookup(&cve), nvd.lookup(&cve), nvd.lookup(&cve));
    for rec in [a, b, c] {
        assert_eq!(rec.unwrap().unwrap().id, "CVE-2023-38606");
    }
}

#[tokio::test]
async fn epss_batch_reports_scores_and_misses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .and(query_param(
            "cve",
            "CVE-2023-38606,CVE-2021-44228,CVE-2024-0001",
        ))
        .and(query_param("limit", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(EPSS_BODY, "application/json"))
        .expect(1)
        .mount(&server)
        .await;

    let epss = EpssClient::new(client()).with_base_url(format!("{}/epss", server.uri()));
    let ids = [
        id("CVE-2023-38606"),
        id("CVE-2021-44228"),
        id("CVE-2024-0001"),
    ];
    let batch = epss.scores(&ids).await.unwrap();
    assert_eq!(batch.scores.len(), 2);
    assert_eq!(batch.scores[0].cve, "CVE-2023-38606");
    assert!((batch.scores[0].epss - 0.02899).abs() < 1e-9);
    assert!((batch.scores[1].percentile - 1.0).abs() < 1e-9);
    assert_eq!(batch.not_found, vec!["CVE-2024-0001"]);

    let cached = epss.scores(&ids[..2]).await.unwrap();
    assert_eq!(
        cached.scores.len(),
        2,
        "both ids are cached, so no second request is made"
    );
    let miss = epss.scores(&ids[2..]).await.unwrap();
    assert_eq!(
        miss.not_found,
        vec!["CVE-2024-0001"],
        "an unscored id is cached too, so no second request is made"
    );
}

#[tokio::test]
async fn epss_malformed_row_is_not_cached_as_unscored() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"data":[{"cve":"CVE-2024-0001","epss":"n/a","percentile":"0.5","date":"2026-10-21"}]}"#,
            "application/json",
        ))
        .expect(2)
        .mount(&server)
        .await;

    let epss = EpssClient::new(client()).with_base_url(format!("{}/epss", server.uri()));
    for _ in 0..2 {
        let batch = epss.scores(&[id("CVE-2024-0001")]).await.unwrap();
        assert_eq!(batch.not_found, vec!["CVE-2024-0001"]);
    }
}

#[tokio::test]
async fn kev_loads_once_then_revalidates_with_etag() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(KEV_FIXTURE, "application/json")
                .insert_header("etag", "\"abc123\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let kev = KevCatalog::new(client()).with_url(format!("{}/kev.json", server.uri()));
    let batch = kev
        .lookup(&[id("cve-2021-44228"), id("CVE-2024-0001")])
        .await
        .unwrap();
    assert_eq!(batch.catalog_version, "2026.10.21");
    assert_eq!(batch.catalog_size, 2);
    assert_eq!(batch.listed.len(), 1);
    assert_eq!(batch.listed[0].cve_id, "CVE-2021-44228");
    assert_eq!(batch.listed[0].known_ransomware_campaign_use, "Known");
    assert_eq!(batch.listed[0].cwes.len(), 4);
    let json = serde_json::to_value(&batch.listed[0]).unwrap();
    assert_eq!(json["cve_id"], "CVE-2021-44228");
    assert_eq!(json["date_added"], "2021-12-10");
    assert!(json.get("cveID").is_none(), "output keys are snake_case");
    assert_eq!(batch.not_listed, vec!["CVE-2024-0001"]);

    let second = kev.lookup(&[id("CVE-2023-38606")]).await.unwrap();
    assert_eq!(
        second.listed.len(),
        1,
        "within the refresh window no request is sent"
    );
}

#[tokio::test]
async fn kev_refresh_sends_if_none_match_after_first_load() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(KEV_FIXTURE, "application/json")
                .insert_header("etag", "\"abc123\""),
        )
        .mount(&server)
        .await;

    let kev = KevCatalog::new(client()).with_url(format!("{}/kev.json", server.uri()));
    kev.lookup(&[id("CVE-2021-44228")]).await.unwrap();
    assert!(kev.force_refresh().await.is_ok());
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(
        received[1]
            .headers
            .get("if-none-match")
            .unwrap()
            .to_str()
            .unwrap(),
        "\"abc123\""
    );
    let batch = kev.lookup(&[id("CVE-2021-44228")]).await.unwrap();
    assert_eq!(batch.listed.len(), 1, "a 304 keeps the loaded catalog");
}

#[tokio::test]
async fn kev_first_load_failure_is_an_error_but_later_failures_serve_stale() {
    let server = MockServer::start().await;
    let kev = KevCatalog::new(client()).with_url(format!("{}/missing.json", server.uri()));
    assert!(matches!(
        kev.lookup(&[id("CVE-2021-44228")]).await,
        Err(HttpError::Status { status: 404, .. })
    ));

    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(KEV_FIXTURE, "application/json"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let kev = KevCatalog::new(client()).with_url(format!("{}/kev.json", server.uri()));
    assert_eq!(
        kev.lookup(&[id("CVE-2021-44228")])
            .await
            .unwrap()
            .listed
            .len(),
        1
    );
    assert!(kev.force_refresh().await.is_err());
    assert_eq!(
        kev.lookup(&[id("CVE-2021-44228")])
            .await
            .unwrap()
            .listed
            .len(),
        1
    );
}

#[tokio::test]
async fn kev_failed_refresh_backs_off_instead_of_retrying_every_call() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(KEV_FIXTURE, "application/json"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let kev = KevCatalog::new(client())
        .with_url(format!("{}/kev.json", server.uri()))
        .with_refresh_after(Duration::ZERO);
    for _ in 0..3 {
        let batch = kev.lookup(&[id("CVE-2021-44228")]).await.unwrap();
        assert_eq!(batch.listed.len(), 1);
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "one load, one failed refresh, then the retry is deferred"
    );
}

#[tokio::test]
async fn kev_lookup_serves_cached_catalog_while_a_refresh_runs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(KEV_FIXTURE, "application/json"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(KEV_FIXTURE, "application/json")
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&server)
        .await;

    let kev = KevCatalog::new(client())
        .with_url(format!("{}/kev.json", server.uri()))
        .with_refresh_after(Duration::ZERO);
    let ids = [id("CVE-2021-44228")];
    kev.lookup(&ids).await.unwrap();

    let refreshing = kev.lookup(&ids);
    let concurrent = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let start = std::time::Instant::now();
        let batch = kev.lookup(&ids).await.unwrap();
        (start.elapsed(), batch)
    };
    let (refreshed, (waited, batch)) = tokio::join!(refreshing, concurrent);
    refreshed.unwrap();
    assert_eq!(batch.listed.len(), 1);
    assert!(
        waited < Duration::from_millis(250),
        "the second lookup waited {waited:?} for a refresh another lookup was running"
    );
}

#[tokio::test]
async fn enrich_cve_in_kev_is_unknown_only_without_any_kev_signal() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .and(query_param("cveId", "CVE-2023-38606"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(NVD_FIXTURE, "application/json"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(EPSS_BODY, "application/json"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let svc = Oxiploitability::new(
        NvdClient::new(client(), None)
            .with_base_url(format!("{}/cves", server.uri()))
            .with_retry_backoff(Duration::ZERO),
        EpssClient::new(client()).with_base_url(format!("{}/epss", server.uri())),
        KevCatalog::new(client()).with_url(format!("{}/kev.json", server.uri())),
        OsvClient::new(client()).with_base_url(format!("{}/osv", server.uri())),
        CnaClient::new(client()).with_base_url(format!("{}/cna", server.uri())),
        PocClient::new(client()).with_base_url(format!("{}/poc", server.uri())),
    );
    let enrich = |cve_id: &str| {
        svc.enrich_cve(Parameters(oxiploitability_mcp::server::EnrichParam {
            cve_id: Some(cve_id.into()),
            cve_ids: None,
        }))
    };

    let out = enrich("CVE-2023-38606").await.unwrap().0.record.unwrap();
    assert!(out.kev_error.is_some());
    assert_eq!(
        out.in_kev,
        Some(true),
        "the NVD record carries a CISA listing date"
    );

    let out = enrich("CVE-2021-44228").await.unwrap().0.record.unwrap();
    assert!(out.kev_error.is_some() && out.nvd_error.is_some());
    assert_eq!(out.in_kev, None);
}

#[tokio::test]
async fn enrich_cve_combines_sources_and_isolates_failures() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
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

    let svc = Oxiploitability::new(
        NvdClient::new(client(), None)
            .with_base_url(format!("{}/cves", server.uri()))
            .with_retry_backoff(Duration::ZERO),
        EpssClient::new(client()).with_base_url(format!("{}/epss", server.uri())),
        KevCatalog::new(client()).with_url(format!("{}/kev.json", server.uri())),
        OsvClient::new(client()).with_base_url(format!("{}/osv", server.uri())),
        CnaClient::new(client()).with_base_url(format!("{}/cna", server.uri())),
        PocClient::new(client()).with_base_url(format!("{}/poc", server.uri())),
    );

    let out = svc
        .enrich_cve(Parameters(oxiploitability_mcp::server::EnrichParam {
            cve_id: Some("cve-2021-44228".into()),
            cve_ids: None,
        }))
        .await
        .unwrap()
        .0
        .record
        .unwrap();
    assert_eq!(out.cve_id, "CVE-2021-44228");
    assert_eq!(out.in_kev, Some(true));
    assert_eq!(out.impact[0].kind, "RCE", "named by the KEV entry");
    assert_eq!(out.impact[0].evidence, "CISA KEV: code execution");
    assert!(out.nvd.is_none());
    assert_eq!(out.nvd_error.as_deref(), Some("NVD returned HTTP 503"));
    assert!((out.epss.unwrap().epss - 0.99999).abs() < 1e-9);
    assert!(out.epss_error.is_none());
    assert_eq!(out.kev.unwrap().vendor_project, "Apache");

    let bad = svc
        .enrich_cve(Parameters(oxiploitability_mcp::server::EnrichParam {
            cve_id: Some("not-a-cve".into()),
            cve_ids: None,
        }))
        .await;
    assert!(bad.is_err());
    let empty = svc
        .enrich_cve(Parameters(oxiploitability_mcp::server::EnrichParam {
            cve_id: None,
            cve_ids: None,
        }))
        .await;
    assert!(empty.is_err());
    let batch_err = svc
        .kev_lookup(Parameters(oxiploitability_mcp::server::CveListParam {
            cve_ids: vec![],
        }))
        .await;
    assert!(batch_err.is_err());
}

#[tokio::test]
async fn poc_search_reads_the_index_most_starred_first_and_caches() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/poc/2017/CVE-2017-0144.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/poc_cve_2017_0144.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let poc = PocClient::new(client()).with_base_url(format!("{}/poc", server.uri()));
    let repos = poc.search(&id("cve-2017-0144")).await.unwrap();
    assert_eq!(repos.len(), 3);
    assert_eq!(repos[0].repo, "peterpt/eternal_scanner");
    assert_eq!(repos[0].url, "https://github.com/peterpt/eternal_scanner");
    assert_eq!(repos[0].stars, 339);
    assert!(repos.windows(2).all(|w| w[0].stars >= w[1].stars));
    assert!(
        repos[1].description.is_none(),
        "null descriptions are omitted"
    );
    assert_eq!(poc.search(&id("CVE-2017-0144")).await.unwrap().len(), 3);
}

#[tokio::test]
async fn poc_search_treats_a_missing_index_file_as_no_pocs_and_other_errors_as_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/poc/2024/CVE-2024-0002.json"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let poc = PocClient::new(client()).with_base_url(format!("{}/poc", server.uri()));
    assert!(poc.search(&id("CVE-2099-0001")).await.unwrap().is_empty());
    assert!(matches!(
        poc.search(&id("CVE-2024-0002")).await,
        Err(HttpError::Status { status: 503, .. })
    ));
}
