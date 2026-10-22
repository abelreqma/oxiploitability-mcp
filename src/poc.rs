use std::time::Duration;

use reqwest::{Client, StatusCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cache::TtlCache;
use crate::cve::CveId;
use crate::http::{HttpError, read_json};

pub const DEFAULT_BASE_URL: &str =
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master";
const SERVICE: &str = "PoC-in-GitHub";
const MAX_BODY: usize = 8 * 1024 * 1024;
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const CACHE_ENTRIES: usize = 2_000;
pub const CAUTION: &str = "Public repositories found by nomi-sec/PoC-in-GitHub, not vetted. Some \
    PoC repositories are fake or carry malware: read the code and run it only in an isolated lab.";

/// The index entry on GitHub that lists the PoC repositories for one CVE.
pub fn index_url(id: &CveId) -> String {
    format!(
        "https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{}/{}.json",
        &id.as_str()[4..8],
        id.as_str()
    )
}

/// Reads the nomi-sec/PoC-in-GitHub index, which lists the GitHub repositories that publish a
/// proof of concept for each CVE.
pub struct PocClient {
    http: Client,
    base_url: String,
    cache: TtlCache<Vec<PocRepo>>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct PocRepo {
    pub repo: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub stars: u64,
    pub forks: u64,
    pub created: String,
    pub pushed: String,
}

#[derive(Deserialize)]
struct RawRepo {
    full_name: String,
    html_url: String,
    description: Option<String>,
    #[serde(default)]
    stargazers_count: u64,
    #[serde(default)]
    forks_count: u64,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    pushed_at: String,
}

impl PocClient {
    pub fn new(http: Client) -> Self {
        Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
            cache: TtlCache::new(CACHE_TTL, CACHE_ENTRIES),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// The PoC repositories listed for one CVE, most starred first; empty when none are listed.
    pub async fn search(&self, id: &CveId) -> Result<Vec<PocRepo>, HttpError> {
        if let Some(hit) = self.cache.get(id.as_str()) {
            return Ok(hit);
        }
        let year = &id.as_str()[4..8];
        let url = format!("{}/{year}/{}.json", self.base_url, id.as_str());
        let resp = self.http.get(url).send().await?;
        let repos = match resp.status() {
            StatusCode::NOT_FOUND => Vec::new(),
            s if s.is_success() => {
                let raw: Vec<RawRepo> = read_json(SERVICE, resp, MAX_BODY).await?;
                let mut repos: Vec<PocRepo> = raw
                    .into_iter()
                    .map(|r| PocRepo {
                        repo: r.full_name,
                        url: r.html_url,
                        description: r.description.filter(|d| !d.trim().is_empty()),
                        stars: r.stargazers_count,
                        forks: r.forks_count,
                        created: r.created_at,
                        pushed: r.pushed_at,
                    })
                    .collect();
                repos.sort_by(|a, b| b.stars.cmp(&a.stars).then_with(|| b.pushed.cmp(&a.pushed)));
                repos
            }
            s => {
                return Err(HttpError::Status {
                    service: SERVICE,
                    status: s.as_u16(),
                });
            }
        };
        self.cache.insert(id.as_str().to_string(), repos.clone());
        Ok(repos)
    }
}
