//! HTTP client for aikey-control-service.
//!
//! Uses `ureq` (blocking, no async) to keep the CLI dependency footprint small.
//!
//! Authentication:
//!   - OAuth device flow: `start_cli_login` → `poll_cli_login` → tokens saved locally.
//!   - Silent renewal: `do_refresh_token` uses the stored refresh token.
//!   - Authenticated requests require a Bearer access_token via `PlatformClient::new`.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Returned by POST /accounts/login (legacy password flow — compat only).
#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub account: AccountInfo,
}

#[derive(Debug, Deserialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub email: String,
}

// ── OAuth device flow types ──────────────────────────────────────────────────

/// Returned by POST /v1/auth/cli/login/init
///
/// The CLI opens the browser login page with the session credentials; the user
/// enters their email in the browser and the backend sends the activation email.
#[derive(Debug, Deserialize)]
pub struct InitSessionResponse {
    pub login_session_id: String,
    pub device_code: String,
    pub poll_interval_seconds: u64,
    pub expires_in_seconds: u64,
}

/// Returned by POST /v1/auth/cli/login/start
#[derive(Debug, Deserialize)]
pub struct StartSessionResponse {
    pub login_session_id: String,
    pub device_code: String,
    pub masked_email: String,
    pub poll_interval_seconds: u64,
    pub expires_in_seconds: u64,
}

/// Returned by POST /v1/auth/cli/login/poll and /v1/auth/cli/login/exchange.
///
/// `status` is one of: "pending" | "approved" | "denied" | "expired" | "token_claimed"
/// Token fields are non-None when `status == "approved"`.
#[derive(Debug, Deserialize)]
pub struct PollResponse {
    pub status: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub account: Option<AccountInfo>,
}

/// Returned by POST /v1/auth/cli/token/refresh
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Returned by GET /accounts/me/sync-version.
#[derive(Debug, Deserialize)]
pub struct SyncVersionResponse {
    pub account_id: String,
    pub sync_version: i64,
}

/// One item from GET /accounts/me/managed-keys-snapshot.
/// JSON field names match `VirtualKeyCacheEntry` in storage.rs for direct merge.
#[derive(Debug, Deserialize, Clone)]
pub struct ManagedKeySnapshotItem {
    pub virtual_key_id: String,
    pub org_id: String,
    pub seat_id: String,
    pub alias: String,
    pub provider_code: String,
    pub protocol_type: String,
    pub base_url: String,
    #[serde(default)]
    pub supported_providers: Vec<String>,
    #[serde(default)]
    pub provider_base_urls: std::collections::HashMap<String, String>,
    pub credential_id: String,
    pub credential_revision: String,
    pub virtual_key_revision: String,
    pub key_status: String,
    pub share_status: String,
    /// "active" | "inactive" — pre-computed by server.
    pub effective_status: String,
    /// "" | "seat_disabled" | "key_revoked" | "key_expired" | "not_claimed"
    pub effective_reason: String,
    /// Unix timestamp (seconds) when the key expires. `None` = no expiry.
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub sync_version: i64,
}

/// Returned by GET /accounts/me/managed-keys-snapshot.
#[derive(Debug, Deserialize)]
pub struct ManagedKeysSnapshotResponse {
    pub sync_version: i64,
    pub keys: Vec<ManagedKeySnapshotItem>,
}

/// One item from GET /accounts/me/all-keys
#[derive(Debug, Deserialize, Clone)]
pub struct KeyItem {
    pub virtual_key_id: String,
    pub org_id: String,
    pub seat_id: String,
    pub alias: String,
    pub provider_code: String,
    pub key_status: String,
    pub share_status: String,
    /// Provider codes this key supports (e.g. `["anthropic"]`).
    /// Added in v0.7; older servers return an empty array via `#[serde(default)]`.
    #[serde(default)]
    pub supported_providers: Vec<String>,
}

/// One binding target inside a protocol slot from GET /virtual-keys/{id}/delivery.
#[derive(Debug, Deserialize)]
pub struct BindingTarget {
    pub binding_id: String,
    pub provider_code: String,
    pub base_url: String,
    /// Plaintext real provider key — store encrypted, never log.
    pub provider_key: String,
    pub credential_id: String,
    pub credential_revision: String,
    pub priority: i32,
    pub fallback_role: String,
}

/// One protocol slot inside a delivery payload.
#[derive(Debug, Deserialize)]
pub struct ProtocolSlot {
    pub protocol_type: String,
    pub binding_targets: Vec<BindingTarget>,
}

/// Full delivery payload from GET /virtual-keys/{id}/delivery.
///
/// The server groups provider keys by protocol type into `slots`.
/// Each slot holds one or more `binding_targets` ordered by priority.
/// The CLI picks `slots[0].binding_targets[0]` for the primary key.
/// `provider_key` is returned in plaintext over TLS; the CLI re-encrypts
/// it with the vault AES key before storing locally.
#[derive(Debug, Deserialize)]
pub struct DeliveryPayload {
    pub virtual_key_id: String,
    pub org_id: String,
    pub seat_id: String,
    pub alias: String,
    pub current_revision: String,
    pub key_status: String,
    pub share_status: String,
    /// All provider codes supported by active bindings in this delivery.
    /// Used by the CLI to write the correct env vars into ~/.aikey/active.env.
    /// Added in v0.7; older servers omit this field (defaults to empty vec).
    #[serde(default)]
    pub supported_providers: Vec<String>,
    /// Grouped by protocol_type; targets ordered by priority ASC.
    /// Use `slots[0].binding_targets[0]` for the primary binding.
    pub slots: Vec<ProtocolSlot>,
}

impl DeliveryPayload {
    /// Returns the primary (first) binding target, if any.
    pub fn primary_binding(&self) -> Option<&BindingTarget> {
        self.slots.first()?.binding_targets.first()
    }

    /// Returns the protocol type of the primary slot.
    pub fn primary_protocol_type(&self) -> &str {
        self.slots.first().map(|s| s.protocol_type.as_str()).unwrap_or("openai_compatible")
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Authenticated client for aikey-control-service.
pub struct PlatformClient {
    base_url: String,
    jwt: String,
}

impl PlatformClient {
    /// Creates a new client using a JWT already stored in `platform_account`.
    pub fn new(base_url: &str, jwt: &str) -> Self {
        PlatformClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            jwt: jwt.to_string(),
        }
    }

    // ── Legacy auth (compat-only, password flow) ─────────────────────────────

    /// POST /accounts/login — legacy password login, kept for admin bootstrap.
    /// Members should use `start_cli_login` / `poll_cli_login` instead.
    pub fn login(base_url: &str, email: &str, password: &str) -> Result<LoginResponse, String> {
        let url = format!("{}/accounts/login", base_url.trim_end_matches('/'));
        let body = serde_json::json!({ "email": email, "password": password });

        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("login request failed: {}", e))?;

        resp.into_json::<LoginResponse>()
            .map_err(|e| format!("failed to parse login response: {}", e))
    }

    // ── OAuth device flow ─────────────────────────────────────────────────────

    /// POST /v1/auth/cli/login/init — creates an empty login session (no email).
    /// The CLI opens the browser web UI with the returned credentials; the user
    /// enters their email in the browser, then the CLI polls for approval.
    pub fn init_cli_login(
        base_url: &str,
        client_version: &str,
        os_platform: &str,
    ) -> Result<InitSessionResponse, String> {
        let url = format!("{}/v1/auth/cli/login/init", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "client_name": "aikey-cli",
            "client_version": client_version,
            "os_platform": os_platform,
        });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("login init failed: {}", e))?;
        resp.into_json::<InitSessionResponse>()
            .map_err(|e| format!("failed to parse login init response: {}", e))
    }

    /// POST /v1/auth/cli/login/start — creates a login session and triggers
    /// the activation email.  No JWT required.
    pub fn start_cli_login(
        base_url: &str,
        email: &str,
        client_version: &str,
        os_platform: &str,
    ) -> Result<StartSessionResponse, String> {
        let url = format!("{}/v1/auth/cli/login/start", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "email": email,
            "client_name": "aikey-cli",
            "client_version": client_version,
            "os_platform": os_platform,
        });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("login start failed: {}", e))?;
        resp.into_json::<StartSessionResponse>()
            .map_err(|e| format!("failed to parse login start response: {}", e))
    }

    /// POST /v1/auth/cli/login/poll — checks session status.
    /// Returns tokens when `status == "approved"`.  No JWT required.
    pub fn poll_cli_login(
        base_url: &str,
        session_id: &str,
        device_code: &str,
    ) -> Result<PollResponse, String> {
        let url = format!("{}/v1/auth/cli/login/poll", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "login_session_id": session_id,
            "device_code": device_code,
        });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("poll request failed: {}", e))?;
        resp.into_json::<PollResponse>()
            .map_err(|e| format!("failed to parse poll response: {}", e))
    }

    /// POST /v1/auth/cli/login/exchange — redeems a one-time login_token
    /// (copy-paste fallback shown on the web activation page).  No JWT required.
    pub fn exchange_login_token(
        base_url: &str,
        session_id: &str,
        login_token: &str,
    ) -> Result<PollResponse, String> {
        let url = format!("{}/v1/auth/cli/login/exchange", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "login_session_id": session_id,
            "login_token": login_token,
        });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("exchange request failed: {}", e))?;
        resp.into_json::<PollResponse>()
            .map_err(|e| format!("failed to parse exchange response: {}", e))
    }

    /// POST /v1/auth/cli/token/refresh — issues a new access_token using the
    /// stored refresh_token.  No JWT required.
    pub fn do_refresh_token(
        base_url: &str,
        refresh_token: &str,
    ) -> Result<RefreshResponse, String> {
        let url = format!("{}/v1/auth/cli/token/refresh", base_url.trim_end_matches('/'));
        let body = serde_json::json!({ "refresh_token": refresh_token });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("token refresh failed: {}", e))?;
        resp.into_json::<RefreshResponse>()
            .map_err(|e| format!("failed to parse refresh response: {}", e))
    }

    // ---- Key discovery ------------------------------------------------------

    /// GET /accounts/me/pending-keys
    /// GET /accounts/me/all-keys
    pub fn get_all_keys(&self) -> Result<Vec<KeyItem>, String> {
        let url = format!("{}/accounts/me/all-keys", self.base_url);

        let resp = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| format!("all-keys request failed: {}", e))?;

        let data: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("failed to parse all-keys response: {}", e))?;

        serde_json::from_value(data["keys"].clone())
            .map_err(|e| format!("failed to deserialise keys: {}", e))
    }

    // ---- Snapshot sync (Phase B) --------------------------------------------

    /// GET /accounts/me/sync-version
    /// Returns the current server-side sync_version for the account.
    /// The CLI compares this with `local_seen_sync_version` to decide whether
    /// to pull a fresh snapshot.
    pub fn get_sync_version(&self) -> Result<SyncVersionResponse, String> {
        let url = format!("{}/accounts/me/sync-version", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(2))
            .build();
        let resp = agent.get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| format!("sync-version request failed: {}", e))?;
        resp.into_json::<SyncVersionResponse>()
            .map_err(|e| format!("failed to parse sync-version response: {}", e))
    }

    /// GET /accounts/me/managed-keys-snapshot
    /// Fetches the full account-dimension projection of the current key state.
    /// Also triggers a server-side refresh of `account_managed_virtual_keys`,
    /// so the returned `sync_version` is always fresh.
    pub fn get_managed_keys_snapshot(&self) -> Result<ManagedKeysSnapshotResponse, String> {
        let url = format!("{}/accounts/me/managed-keys-snapshot", self.base_url);
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(2))
            .build();
        let resp = agent.get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| format!("managed-keys-snapshot request failed: {}", e))?;
        resp.into_json::<ManagedKeysSnapshotResponse>()
            .map_err(|e| format!("failed to parse managed-keys-snapshot response: {}", e))
    }

    // ---- Key delivery -------------------------------------------------------

    /// GET /virtual-keys/{id}/delivery
    /// Returns full payload including plaintext provider key (over TLS).
    pub fn get_key_delivery(&self, virtual_key_id: &str) -> Result<DeliveryPayload, String> {
        let url = format!("{}/virtual-keys/{}/delivery", self.base_url, virtual_key_id);

        let resp = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| format!("delivery request failed: {}", e))?;

        resp.into_json::<DeliveryPayload>()
            .map_err(|e| format!("failed to parse delivery payload: {}", e))
    }

    /// POST /virtual-keys/{id}/claim
    /// Marks the key as claimed on the server side (idempotent).
    pub fn claim_key(&self, virtual_key_id: &str) -> Result<(), String> {
        let url = format!("{}/virtual-keys/{}/claim", self.base_url, virtual_key_id);

        ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .set("Content-Type", "application/json")
            .send_string("{}")
            .map_err(|e| format!("claim request failed: {}", e))?;

        Ok(())
    }
}
