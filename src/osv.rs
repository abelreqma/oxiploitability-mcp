use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

use crate::component::OsvQuery;
use crate::http::{HttpError, read_json};

pub const DEFAULT_BASE_URL: &str = "https://api.osv.dev/v1";
const SERVICE: &str = "OSV";
const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_PAGES: usize = 10;

#[derive(Clone)]
pub struct OsvClient {
    http: Client,
    base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub database_specific: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    /// `ECOSYSTEM`, `SEMVER` or `GIT`; a `GIT` range's events are commit hashes.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvEvent {
    pub fixed: Option<String>,
}

#[derive(Deserialize)]
struct QueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
    next_page_token: Option<String>,
}

impl OsvClient {
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

    /// Every vulnerability OSV lists for one package query, following pagination.
    pub async fn query(&self, q: &OsvQuery) -> Result<Vec<OsvVuln>, HttpError> {
        let url = format!("{}/query", self.base_url);
        let mut vulns = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut body = q.to_json();
            if let Some(t) = &token {
                body["page_token"] = Value::String(t.clone());
            }
            let resp = self.http.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                return Err(HttpError::Status {
                    service: SERVICE,
                    status: resp.status().as_u16(),
                });
            }
            let page: QueryResponse = read_json(SERVICE, resp, MAX_BODY).await?;
            vulns.extend(page.vulns);
            match page.next_page_token.filter(|t| !t.is_empty()) {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        Ok(vulns)
    }
}
