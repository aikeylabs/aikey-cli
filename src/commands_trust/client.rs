//! HTTP client for trust-local (`http://127.0.0.1:8801` by default).
//!
//! Synchronous (ureq) — same pattern as `platform_client.rs`. All endpoints
//! are localhost so timeouts are short. trust-local being unreachable is the
//! primary error case (user hasn't installed degrade-detector yet).

use serde::Deserialize;
use std::time::Duration;

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8801";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Result of `POST /v1/verify` (202 Accepted).
#[derive(Debug, Deserialize)]
pub(crate) struct VerifyAcceptResponse {
    pub verify_id: String,
    pub status: String,
    pub triggered_at: i64,
}

/// Result of `GET /v1/verify/{verify_id}`.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct VerifyDetail {
    pub verify_id: String,
    pub alias_name: String,
    pub provider_id: String,
    pub model: String,
    pub triggered_at: i64,
    pub completed_at: Option<i64>,
    pub status: String,
    pub progress: Option<VerifyProgress>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
    pub scoring_detail: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct VerifyProgress {
    pub n_done: i64,
    pub n_total: i64,
    pub current_qid: Option<String>,
}

/// Result of `GET /v1/status` (no alias) — list view.
#[derive(Debug, Deserialize)]
pub(crate) struct StatusList {
    pub items: Vec<StatusSummary>,
}

/// Result of `GET /v1/status/{alias}` — summary plus history.
/// Also one entry of StatusList.items.
#[derive(Debug, Deserialize)]
pub(crate) struct StatusSummary {
    pub alias_name: String,
    pub provider_id: String,
    pub model: String,
    pub updated_at: i64,
    pub last_verified_at: Option<i64>,
    pub last_verify_result: String,
    pub s_combined: Option<f64>,
    pub anomaly_suggested: bool,
    #[serde(default)]
    pub cascade_history: Vec<HistoryEntry>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryEntry {
    pub verify_id: String,
    pub triggered_at: i64,
    pub completed_at: Option<i64>,
    pub status: String,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
}

/// Sync response common shape.
#[derive(Debug, Deserialize)]
pub(crate) struct SyncResponse {
    pub sync_type: String,
    #[serde(default)]
    pub results: Vec<SyncResult>,
    pub state: SyncState,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SyncResult {
    pub status: String,
    pub version: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SyncState {
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
}

/// Thin HTTP wrapper. Constructs URLs from env override or default; performs
/// `ureq` calls with a short timeout. Errors are propagated as `anyhow::Error`
/// for the command layer to format.
pub(crate) struct TrustClient {
    base_url: String,
    timeout: Duration,
}

impl TrustClient {
    pub fn new() -> Self {
        let base_url = std::env::var("DEGRADE_DETECTOR_LOCAL_URL")
            .unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Returns a generic error message users see when trust-local is unreachable.
    /// Centralised so the install prompt stays in sync everywhere.
    pub(crate) fn unreachable_hint(&self) -> String {
        format!(
            "trust-local not reachable at {} — install it with:\n  \
             curl -fsSL https://raw.githubusercontent.com/aikeylabs/degrade-detector/main/scripts/install_service.sh | bash\n\
             Or override URL via: export DEGRADE_DETECTOR_LOCAL_URL=...",
            self.base_url
        )
    }

    pub fn post_verify(
        &self,
        alias: &str,
        provider: &str,
        model: &str,
        force: bool,
    ) -> Result<VerifyAcceptResponse, ureq::Error> {
        let url = format!("{}/v1/verify", self.base_url);
        let resp = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build()
            .post(&url)
            .send_json(serde_json::json!({
                "alias_name": alias,
                "provider_id": provider,
                "model": model,
                "force": force,
            }))?;
        Ok(resp.into_json()?)
    }

    pub fn get_verify(&self, verify_id: &str) -> Result<VerifyDetail, ureq::Error> {
        let url = format!("{}/v1/verify/{}", self.base_url, verify_id);
        let resp = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build()
            .get(&url)
            .call()?;
        Ok(resp.into_json()?)
    }

    pub fn list_status(&self) -> Result<StatusList, ureq::Error> {
        let url = format!("{}/v1/status", self.base_url);
        let resp = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build()
            .get(&url)
            .call()?;
        Ok(resp.into_json()?)
    }

    pub fn get_status(&self, alias: &str) -> Result<StatusSummary, ureq::Error> {
        let url = format!("{}/v1/status/{}", self.base_url, alias);
        let resp = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build()
            .get(&url)
            .call()?;
        Ok(resp.into_json()?)
    }

    pub fn post_sync_baseline(&self) -> Result<SyncResponse, ureq::Error> {
        let url = format!("{}/v1/sync/baseline", self.base_url);
        let resp = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build()
            .post(&url)
            .send_json(serde_json::json!({}))?;
        Ok(resp.into_json()?)
    }

    pub fn post_sync_questions(&self) -> Result<SyncResponse, ureq::Error> {
        let url = format!("{}/v1/sync/questions", self.base_url);
        let resp = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build()
            .post(&url)
            .send_json(serde_json::json!({}))?;
        Ok(resp.into_json()?)
    }
}
