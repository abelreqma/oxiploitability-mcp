use std::collections::HashMap;
use std::time::Duration;

use oxiploitability_mcp::cna::CnaClient;
use oxiploitability_mcp::epss::EpssClient;
use oxiploitability_mcp::http::client;
use oxiploitability_mcp::kev::KevCatalog;
use oxiploitability_mcp::nvd::NvdClient;
use oxiploitability_mcp::osv::OsvClient;
use oxiploitability_mcp::poc::PocClient;
use oxiploitability_mcp::server::Oxiploitability;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NVD_FIXTURE: &str = include_str!("fixtures/nvd_cve_2023_38606.json");
const KEV_FIXTURE: &str = include_str!("fixtures/kev_small.json");
const EPSS_BODY: &str = r#"{"status":"OK","status-code":200,"version":"1.0","access":"public","total":2,"offset":0,"limit":100,"data":[{"cve":"CVE-2023-38606","epss":"0.028990000","percentile":"0.868270000","date":"2026-10-21"},{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-10-21"}]}"#;

async fn mock_upstreams() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .and(query_param("cveId", "CVE-2024-0002"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cves"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(NVD_FIXTURE, "application/json"))
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
    Mock::given(method("POST"))
        .and(path("/osv/query"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/osv_query_log4j.json"),
            "application/json",
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/poc/2017/CVE-2017-0144.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/poc_cve_2017_0144.json"),
            "application/json",
        ))
        .mount(&server)
        .await;
    server
}

async fn connect(server: &MockServer) -> RunningService<RoleClient, ()> {
    let svc = Oxiploitability::new(
        NvdClient::new(client(), Some("test-key".into()))
            .with_base_url(format!("{}/cves", server.uri()))
            .with_retry_backoff(Duration::ZERO),
        EpssClient::new(client()).with_base_url(format!("{}/epss", server.uri())),
        KevCatalog::new(client()).with_url(format!("{}/kev.json", server.uri())),
        OsvClient::new(client()).with_base_url(format!("{}/osv", server.uri())),
        CnaClient::new(client()).with_base_url(format!("{}/cna", server.uri())),
        PocClient::new(client()).with_base_url(format!("{}/poc", server.uri())),
    );
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        svc.serve(server_io).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_io).await.unwrap()
}

async fn call(peer: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(args) = args else {
        unreachable!("arguments are a JSON object")
    };
    peer.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
        .await
        .unwrap()
}

fn error_text(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true));
    result.content[0].as_text().unwrap().text.clone()
}

#[tokio::test]
async fn structured_results_match_advertised_output_schemas() {
    let server = mock_upstreams().await;
    let peer = connect(&server).await;

    let tools = peer.list_all_tools().await.unwrap();
    let schemas: HashMap<String, JsonObject> = tools
        .iter()
        .map(|t| {
            let schema = t
                .output_schema
                .as_ref()
                .expect("every tool has an output schema");
            (t.name.to_string(), (**schema).clone())
        })
        .collect();
    assert_eq!(schemas.len(), 7);
    for t in &tools {
        let a = t.annotations.as_ref().expect("every tool is annotated");
        let writes_report = t.name == "scan_sbom";
        assert_eq!(a.read_only_hint, Some(!writes_report), "{}", t.name);
        assert_eq!(a.open_world_hint, Some(true), "{}", t.name);
    }

    let listed = ["CVE-2021-44228", "CVE-2023-38606", "CVE-2099-0001"];
    let calls = [
        ("nvd_cve", json!({ "cve_id": "CVE-2023-38606" })),
        ("epss_scores", json!({ "cve_ids": listed })),
        ("kev_lookup", json!({ "cve_ids": listed })),
        ("enrich_cve", json!({ "cve_id": "CVE-2021-44228" })),
        (
            "product_cves",
            json!({ "product": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }),
        ),
        (
            "poc_search",
            json!({ "cve_id": "cve-2017-0144", "limit": 2 }),
        ),
    ];
    for (tool, args) in calls {
        let result = call(&peer, tool, args).await;
        assert_ne!(
            result.is_error,
            Some(true),
            "{tool} failed: {:?}",
            result.content
        );
        let output = result.structured_content.expect("structured content");
        let validator = jsonschema::validator_for(&Value::Object(schemas[tool].clone())).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&output)
            .map(|e| e.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "{tool} output violates its schema: {errors:?}"
        );
    }

    let kev = call(&peer, "kev_lookup", json!({ "cve_ids": listed })).await;
    assert_eq!(
        kev.structured_content.unwrap()["listed"][0]["cve_id"],
        "CVE-2021-44228"
    );

    let one = call(&peer, "enrich_cve", json!({ "cve_id": "CVE-2017-0144" }))
        .await
        .structured_content
        .unwrap();
    let enriched = &one;
    assert_eq!(
        enriched["cve_id"], "CVE-2017-0144",
        "one CVE answers at the top level"
    );
    let poc_total = enriched["poc"]["total"].as_u64().unwrap();
    assert!(poc_total > 0, "PoCs come from the index in the same call");
    let shown = enriched["poc"]["repos"].as_array().unwrap().len() as u64;
    assert_eq!(shown, poc_total.min(10));
    assert!(enriched["nvd"].is_object() && enriched["epss_error"].is_null());
    assert!(one["rows"].is_null(), "one CVE gets the full record");

    peer.cancel().await.unwrap();
}

#[tokio::test]
async fn enrich_cve_batches_and_falls_back_to_cve_org_when_nvd_fails() {
    let server = mock_upstreams().await;
    Mock::given(method("GET"))
        .and(path("/cna/CVE-2024-0002"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"cveMetadata":{"state":"PUBLISHED","assignerShortName":"GitHub_M","datePublished":"2024-01-02T00:00:00Z"},
                "containers":{"cna":{"descriptions":[{"lang":"en","value":"Reflected markup in the search page."}],
                  "problemTypes":[{"descriptions":[{"cweId":"CWE-79","type":"CWE"}]}],
                  "metrics":[{"cvssV3_1":{"version":"3.1","baseScore":6.1,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}]},
                "adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":6.1,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}]}]}}"#,
            "application/json",
        ))
        .mount(&server)
        .await;
    let repos: Vec<Value> = (0..12)
        .map(|i| {
            json!({ "full_name": format!("u/poc{i}"), "html_url": format!("https://github.com/u/poc{i}"),
                    "stargazers_count": i, "created_at": "2021-12-10T00:00:00Z", "pushed_at": "2021-12-10T00:00:00Z" })
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/poc/2021/CVE-2021-44228.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repos))
        .mount(&server)
        .await;
    let peer = connect(&server).await;
    let schema = peer
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.name == "enrich_cve")
        .unwrap()
        .output_schema
        .unwrap();

    let answer = call(
        &peer,
        "enrich_cve",
        json!({ "cve_ids": ["CVE-2017-0144", "cve-2021-44228", "CVE-2024-0002", "CVE-2017-0144"] }),
    )
    .await
    .structured_content
    .unwrap();
    let validator = jsonschema::validator_for(&Value::Object((*schema).clone())).unwrap();
    assert!(validator.is_valid(&answer));

    assert!(answer["cve_id"].is_null(), "a batch returns rows only");
    let rows = answer["rows"].as_array().unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r["cve_id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        ["CVE-2017-0144", "CVE-2021-44228", "CVE-2024-0002"],
        "request order, duplicates checked once"
    );
    assert_eq!(rows[0]["source"], "nvd");
    assert_eq!(rows[1]["in_kev"], true);
    assert_eq!(rows[1]["kev_date_added"], "2021-12-10");
    assert_eq!(rows[1]["poc_repos"], 12);
    assert!((rows[1]["epss"].as_f64().unwrap() - 0.99999).abs() < 1e-9);

    let fallback = &rows[2];
    assert_eq!(fallback["source"], "cve.org");
    assert_eq!(
        fallback["url"],
        "https://www.cve.org/CVERecord?id=CVE-2024-0002"
    );
    assert_eq!(fallback["cwes"], json!(["CWE-79"]));
    assert_eq!(fallback["cvss_score"], 6.1);
    assert_eq!(fallback["impact"], json!(["XSS (CWE-79)"]));
    assert_eq!(fallback["summary"], "Reflected markup in the search page.");
    assert!(
        fallback["errors"].is_null(),
        "the NVD failure is covered by the fallback"
    );
    assert_eq!(answer["from_cve_org"], json!(["CVE-2024-0002"]));

    let full = call(&peer, "enrich_cve", json!({ "cve_id": "CVE-2024-0002" }))
        .await
        .structured_content
        .unwrap();
    let record = &full;
    assert_eq!(record["nvd_error"], "NVD returned HTTP 503");
    assert_eq!(record["cve_org"]["assigner"], "GitHub_M");
    assert_eq!(record["cve_org"]["cvss"][0]["source"], "cna");
    assert_eq!(record["cve_org"]["cvss"][1]["source"], "adp:CISA-ADP");
    assert_eq!(record["impact"][0]["evidence"], "CWE-79");

    peer.cancel().await.unwrap();
}

#[tokio::test]
async fn invalid_input_and_upstream_failures_are_tool_errors() {
    let server = mock_upstreams().await;
    let peer = connect(&server).await;

    let bad_id = call(&peer, "nvd_cve", json!({ "cve_id": "not-a-cve" })).await;
    assert!(error_text(&bad_id).contains("invalid CVE id"));

    let bad_batch = call(
        &peer,
        "kev_lookup",
        json!({ "cve_ids": ["CVE-2021-44228", "nope"] }),
    )
    .await;
    assert!(error_text(&bad_batch).contains("nope"));

    let empty = call(&peer, "epss_scores", json!({ "cve_ids": [] })).await;
    assert!(error_text(&empty).contains("at least one"));

    let upstream = call(&peer, "nvd_cve", json!({ "cve_id": "CVE-2024-0002" })).await;
    assert_eq!(error_text(&upstream), "NVD returned HTTP 503");

    peer.cancel().await.unwrap();
}
