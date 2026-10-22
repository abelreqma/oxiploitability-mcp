use std::collections::{HashMap, HashSet};
use std::time::Duration;

use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cache::TtlCache;
use crate::cve::CveId;
use crate::http::{HttpError, read_json};

pub const DEFAULT_BASE_URL: &str = "https://api.first.org/data/v1/epss";
const SERVICE: &str = "EPSS";
const CACHE_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const CACHE_ENTRIES: usize = 20_000;
const MAX_BODY: usize = 1024 * 1024;
/// The `cve` query parameter is limited to 2000 characters by the API.
const MAX_PARAM_CHARS: usize = 2000;
/// The API pages at 100 records, so one request never asks for more than that.
const MAX_IDS_PER_REQUEST: usize = 100;

pub struct EpssClient {
    http: Client,
    base_url: String,
    /// `None` records a CVE that EPSS does not score.
    cache: TtlCache<Option<EpssScore>>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct EpssScore {
    pub cve: String,
    /// Probability of exploitation activity in the next 30 days, 0 to 1.
    pub epss: f64,
    /// Fraction of all scored CVEs with an EPSS at or below this one, 0 to 1.
    pub percentile: f64,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct EpssBatch {
    pub scores: Vec<EpssScore>,
    pub not_found: Vec<String>,
}

impl EpssClient {
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

    pub async fn scores(&self, ids: &[CveId]) -> Result<EpssBatch, HttpError> {
        let mut found: HashMap<String, EpssScore> = HashMap::new();
        let mut misses: Vec<&CveId> = Vec::new();
        for id in ids {
            match self.cache.get(id.as_str()) {
                Some(Some(hit)) => {
                    found.insert(id.as_str().to_string(), hit);
                }
                Some(None) => {}
                None => misses.push(id),
            }
        }
        let mut malformed: HashSet<String> = HashSet::new();
        for chunk in chunk_ids(&misses) {
            let resp = self
                .http
                .get(&self.base_url)
                .query(&[("cve", chunk.as_str()), ("limit", "100")])
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                return Err(HttpError::Status {
                    service: SERVICE,
                    status: status.as_u16(),
                });
            }
            let body: EpssResponse = read_json(SERVICE, resp, MAX_BODY).await?;
            for row in body.data {
                let cve = row.cve.clone();
                match EpssScore::try_from(row) {
                    Ok(score) => {
                        self.cache.insert(score.cve.clone(), Some(score.clone()));
                        found.insert(score.cve.clone(), score);
                    }
                    Err(e) => {
                        tracing::warn!(%cve, error = %e, "skipping malformed EPSS row");
                        malformed.insert(cve);
                    }
                }
            }
        }
        for id in &misses {
            if !found.contains_key(id.as_str()) && !malformed.contains(id.as_str()) {
                self.cache.insert(id.as_str().to_string(), None);
            }
        }
        let mut scores = Vec::with_capacity(found.len());
        let mut not_found = Vec::new();
        for id in ids {
            match found.remove(id.as_str()) {
                Some(s) => scores.push(s),
                None => not_found.push(id.as_str().to_string()),
            }
        }
        Ok(EpssBatch { scores, not_found })
    }
}

fn chunk_ids(ids: &[&CveId]) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut count = 0;
    for id in ids {
        let s = id.as_str();
        let needed = if current.is_empty() {
            s.len()
        } else {
            s.len() + 1
        };
        if count == MAX_IDS_PER_REQUEST || current.len() + needed > MAX_PARAM_CHARS {
            chunks.push(std::mem::take(&mut current));
            count = 0;
        }
        if !current.is_empty() {
            current.push(',');
        }
        current.push_str(s);
        count += 1;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[derive(Deserialize)]
struct EpssResponse {
    #[serde(default)]
    data: Vec<EpssRow>,
}

#[derive(Deserialize)]
struct EpssRow {
    cve: String,
    epss: String,
    percentile: String,
    #[serde(default)]
    date: String,
}

impl TryFrom<EpssRow> for EpssScore {
    type Error = std::num::ParseFloatError;

    fn try_from(row: EpssRow) -> Result<Self, Self::Error> {
        Ok(Self {
            cve: row.cve,
            epss: row.epss.parse()?,
            percentile: row.percentile.parse()?,
            date: row.date,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_respect_count_and_length_limits() {
        let ids: Vec<CveId> = (0..250)
            .map(|i| CveId::parse(&format!("CVE-2024-{i:05}")).unwrap())
            .collect();
        let refs: Vec<&CveId> = ids.iter().collect();
        let chunks = chunk_ids(&refs);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].split(',').count(), 100);
        assert_eq!(chunks[2].split(',').count(), 50);
        for c in &chunks {
            assert!(c.len() <= MAX_PARAM_CHARS);
        }
        assert!(chunk_ids(&[]).is_empty());
    }
}
