use anyhow::Context;
use oxiploitability_mcp::cna::CnaClient;
use oxiploitability_mcp::epss::EpssClient;
use oxiploitability_mcp::kev::KevCatalog;
use oxiploitability_mcp::nvd::NvdClient;
use oxiploitability_mcp::osv::OsvClient;
use oxiploitability_mcp::poc::PocClient;
use oxiploitability_mcp::server::Oxiploitability;
use oxiploitability_mcp::{NVD_NOTICE, http};
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let api_key = std::env::var("NVD_API").ok();
    let http = http::client();
    let nvd = NvdClient::new(http.clone(), api_key);
    tracing::info!(
        nvd_api_key = nvd.has_api_key(),
        nvd_requests_per_30s = nvd.requests_per_window(),
        "{NVD_NOTICE}"
    );
    let service = Oxiploitability::new(
        nvd,
        EpssClient::new(http.clone()),
        KevCatalog::new(http.clone()),
        OsvClient::new(http.clone()),
        CnaClient::new(http.clone()),
        PocClient::new(http),
    );

    let running = service
        .serve(stdio())
        .await
        .context("failed to start MCP server on stdio")?;
    running
        .waiting()
        .await
        .context("MCP server exited with an error")?;
    Ok(())
}
