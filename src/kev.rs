use std::collections::HashMap;
use std::time::{Duration, Instant};

use reqwest::Client;
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::cve::CveId;
use crate::http::{HttpError, read_json};

pub const DEFAULT_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const SERVICE: &str = "KEV";
const REFRESH_AFTER: Duration = Duration::from_secs(60 * 60);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(5 * 60);
const MAX_BODY: usize = 64 * 1024 * 1024;

/// In-memory copy of the CISA KEV catalog, refreshed with conditional requests.
pub struct KevCatalog {
    http: Client,
    url: String,
    refresh_after: Duration,
    state: RwLock<KevState>,
    refresh_lock: Mutex<()>,
}

#[derive(Default)]
struct KevState {
    etag: Option<String>,
    fetched_at: Option<Instant>,
    retry_at: Option<Instant>,
    catalog_version: String,
    date_released: String,
    entries: HashMap<String, KevEntry>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub known_ransomware_campaign_use: String,
    pub notes: String,
    pub cwes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct KevBatch {
    pub catalog_version: String,
    pub date_released: String,
    pub catalog_size: usize,
    pub listed: Vec<KevEntry>,
    pub not_listed: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevFeed {
    #[serde(default)]
    catalog_version: String,
    #[serde(default)]
    date_released: String,
    #[serde(default)]
    vulnerabilities: Vec<RawKevEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    short_description: String,
    #[serde(default)]
    required_action: String,
    #[serde(default)]
    due_date: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    cwes: Vec<String>,
}

impl From<RawKevEntry> for KevEntry {
    fn from(raw: RawKevEntry) -> Self {
        Self {
            cve_id: raw.cve_id.to_ascii_uppercase(),
            vendor_project: raw.vendor_project,
            product: raw.product,
            vulnerability_name: raw.vulnerability_name,
            date_added: raw.date_added,
            short_description: raw.short_description,
            required_action: raw.required_action,
            due_date: raw.due_date,
            known_ransomware_campaign_use: raw.known_ransomware_campaign_use,
            notes: raw.notes,
            cwes: raw.cwes,
        }
    }
}

impl KevCatalog {
    pub fn new(http: Client) -> Self {
        Self {
            http,
            url: DEFAULT_URL.to_string(),
            refresh_after: REFRESH_AFTER,
            state: RwLock::new(KevState::default()),
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    pub fn with_refresh_after(mut self, refresh_after: Duration) -> Self {
        self.refresh_after = refresh_after;
        self
    }

    pub async fn lookup(&self, ids: &[CveId]) -> Result<KevBatch, HttpError> {
        self.ensure_fresh().await?;
        let state = self.state.read().await;
        let mut listed = Vec::new();
        let mut not_listed = Vec::new();
        for id in ids {
            match state.entries.get(id.as_str()) {
                Some(e) => listed.push(e.clone()),
                None => not_listed.push(id.as_str().to_string()),
            }
        }
        Ok(KevBatch {
            catalog_version: state.catalog_version.clone(),
            date_released: state.date_released.clone(),
            catalog_size: state.entries.len(),
            listed,
            not_listed,
        })
    }

    /// Revalidates the catalog now, regardless of age.
    pub async fn force_refresh(&self) -> Result<(), HttpError> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh().await
    }

    /// With a catalog loaded, a lookup that finds a refresh already running serves the cached
    /// catalog instead of waiting for it.
    async fn ensure_fresh(&self) -> Result<(), HttpError> {
        if self.is_fresh().await {
            return Ok(());
        }
        let loaded = !self.state.read().await.entries.is_empty();
        let _guard = match self.refresh_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) if loaded => return Ok(()),
            Err(_) => self.refresh_lock.lock().await,
        };
        if self.is_fresh().await {
            return Ok(());
        }
        match self.refresh().await {
            Ok(()) => Ok(()),
            Err(e) => {
                let mut state = self.state.write().await;
                if state.entries.is_empty() {
                    Err(e)
                } else {
                    state.retry_at = Some(Instant::now() + RETRY_AFTER_FAILURE);
                    tracing::warn!(error = %e, "KEV refresh failed; serving the cached catalog");
                    Ok(())
                }
            }
        }
    }

    /// A failed refresh with a cached catalog defers the next attempt until `retry_at`.
    async fn is_fresh(&self) -> bool {
        let state = self.state.read().await;
        let now = Instant::now();
        state
            .fetched_at
            .is_some_and(|t| now.duration_since(t) < self.refresh_after)
            || state.retry_at.is_some_and(|t| now < t)
    }

    async fn refresh(&self) -> Result<(), HttpError> {
        let etag = self.state.read().await.etag.clone();
        let mut req = self.http.get(&self.url);
        if let Some(tag) = &etag {
            req = req.header(IF_NONE_MATCH, tag);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status == StatusCode::NOT_MODIFIED {
            let mut state = self.state.write().await;
            state.fetched_at = Some(Instant::now());
            state.retry_at = None;
            tracing::debug!("KEV catalog unchanged");
            return Ok(());
        }
        if !status.is_success() {
            return Err(HttpError::Status {
                service: SERVICE,
                status: status.as_u16(),
            });
        }
        let new_etag = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let feed: KevFeed = read_json(SERVICE, resp, MAX_BODY).await?;
        let entries: HashMap<String, KevEntry> = feed
            .vulnerabilities
            .into_iter()
            .map(KevEntry::from)
            .map(|e| (e.cve_id.clone(), e))
            .collect();
        tracing::info!(version = %feed.catalog_version, entries = entries.len(), "KEV catalog loaded");
        let mut state = self.state.write().await;
        *state = KevState {
            etag: new_etag,
            fetched_at: Some(Instant::now()),
            retry_at: None,
            catalog_version: feed.catalog_version,
            date_released: feed.date_released,
            entries,
        };
        Ok(())
    }
}
