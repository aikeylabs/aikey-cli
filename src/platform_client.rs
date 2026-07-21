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
    /// The account's login handle. For an SSO member who first logged in
    /// through Feishu without an email, this is the SYNTHETIC handle
    /// (`sso+feishu.<32hex>@sso.local`) — an internal identifier, never
    /// something to show a human. Use [`AccountInfo::display_label`].
    pub email: String,
    /// Human-readable identity, composed server-side as
    /// `李承熙 · feishu:6ad2973d` — display name plus a short discriminator so
    /// two colleagues with the same name stay distinguishable.
    ///
    /// Optional because older servers do not send it; the CLI falls back to
    /// `email`, which is the correct value on every email-based account and
    /// the only value those servers have.
    #[serde(default)]
    pub display_identity: Option<String>,
}

impl AccountInfo {
    /// What a human is shown after logging in.
    ///
    /// 🔴 Decision contract (damon, 2026-07-21): the terminal shows
    /// `Logged in as 李承熙 · feishu:6ad2973d`. The synthetic handle must NOT
    /// be shown — an SSO member has no idea what `sso+feishu.<32hex>@sso.local`
    /// is, cannot type it anywhere, and it puts a digest of their Feishu
    /// union_id on screen and into terminal scrollback.
    ///
    /// Empty-string guard, not just `Option`: a server that sends
    /// `"display_identity": ""` would otherwise print a blank name, which reads
    /// as "logged in as nobody". Same shape as the `unwrap_or(account_id)`
    /// fallback the provider-OAuth poll already uses in commands_auth.
    pub fn display_label(&self) -> &str {
        match self.display_identity.as_deref() {
            Some(label) if !label.trim().is_empty() => label,
            _ => &self.email,
        }
    }
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

/// Returned by POST /v1/auth/cli/login/poll.
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

/// Returned by POST /v1/auth/cli/login/exchange.
///
/// The copy-paste fallback exchange is not a polling endpoint: success is
/// represented by HTTP 200 plus the token payload, with no `status` field.
#[derive(Debug, Deserialize)]
struct LoginTokenExchangeResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub account: AccountInfo,
}

impl From<LoginTokenExchangeResponse> for PollResponse {
    fn from(value: LoginTokenExchangeResponse) -> Self {
        PollResponse {
            status: "approved".to_string(),
            access_token: Some(value.access_token),
            refresh_token: Some(value.refresh_token),
            token_type: value.token_type,
            expires_in: value.expires_in,
            account: Some(value.account),
        }
    }
}

/// Returned by POST /v1/auth/cli/token/refresh
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Returned by POST /v1/digital-employees/register (host self-registration).
#[derive(Debug, Deserialize)]
pub struct RegisterDigitalEmployeeResponse {
    pub refresh_token: String,
    pub seat_id: String,
    pub org_id: String,
    pub account_id: String,
    pub display_name: String,
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
    /// Oauth-group binding target (N6). Present only when the VK's binding targets
    /// a oauth_group instead of a single credential. `None` for direct-bind VKs.
    #[serde(default)]
    pub oauth_group_id: Option<String>,
    /// Seat's ranked candidate set for a group-bound VK (N6): array of
    /// `{account_id, identity, provider_code, priority, assigned}`. `None`/absent
    /// for direct-bind VKs. Stored verbatim into the cache as JSON text.
    #[serde(default)]
    pub group_accounts: Option<serde_json::Value>,
    /// The group's routing knobs JSON (exhaustion_signals / util_cap / ratios),
    /// for the proxy's offline routing (N6 follow-up). `"{}"`/absent for
    /// direct-bind VKs. Stored verbatim into the cache.
    #[serde(default)]
    pub routing_config: Option<String>,
    /// The OAuth group's human-facing name (oauth_group.alias), so /user/vault +
    /// `aikey use` can label WHICH group a VK belongs to — a member in multiple
    /// groups gets one VK per group and picks by name (2026-07-01). `None`/empty for
    /// direct-bind VKs or an unnamed group.
    #[serde(default)]
    pub group_alias: Option<String>,
}

/// Returned by GET /accounts/me/managed-keys-snapshot.
#[derive(Debug, Deserialize)]
pub struct ManagedKeysSnapshotResponse {
    pub sync_version: i64,
    pub keys: Vec<ManagedKeySnapshotItem>,
    /// Enterprise quota rules applicable to this account's seats (design
    /// §0.5/§5.2). `None` when the server is an older/quota-less edition (field
    /// absent) — the CLI then leaves its quota cache untouched. `Some` (even
    /// with an empty `subjects`) is the authoritative full set and triggers a
    /// full-replace of the local quota cache, so deleting the last quota for a
    /// seat propagates as an empty list that clears stale rules.
    #[serde(default)]
    pub quota: Option<QuotaSnapshot>,
    /// The deployment's key-delivery contract, told to us EXPLICITLY by the
    /// server (2026-07-13). `None` = an older control plane that predates the
    /// field; the client then falls back to inferring the form the old way
    /// (a resolved cluster node ⇒ central), so nothing regresses.
    ///
    /// Why this exists: the client used to infer its form purely from whether a
    /// cluster node had ever been resolved into the local sidecar. That guess
    /// desynced from the server's rule in BOTH directions — a fresh machine on a
    /// central cluster tried to download material and ate an opaque 403, while a
    /// box carrying a stray CLUSTER_DELIVERY_ORG_ID refused delivery though it
    /// was not a cluster at all. The server knows; now it says so.
    #[serde(default)]
    pub key_delivery_form: Option<String>,
}

/// How this deployment delivers key material — the client mirror of the
/// server's `config.KeyDeliveryForm` (single source of truth lives there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDeliveryForm {
    /// Material is delivered to this machine; sync downloads it as usual.
    /// (Personal, plain Production, and cluster form-⓪.)
    Local,
    /// Material never leaves the cluster's central nodes — per-VK delivery is
    /// refused BY DESIGN. The client must NOT ask for material; it routes tools
    /// at its resolved node instead. (Cluster form-①.)
    Central,
}

impl KeyDeliveryForm {
    /// Parse the wire value, falling back to the legacy inference when the field
    /// is absent (older server): a resolved cluster node meant "central".
    ///
    /// Fail-safe direction matters: an UNRECOGNIZED value must not silently relax
    /// the "keys stay central" guarantee, so anything we don't understand on a
    /// cluster is treated as Central.
    pub fn from_wire(wire: Option<&str>, has_cluster_node: bool) -> Self {
        match wire.map(|w| w.trim().to_ascii_lowercase()) {
            Some(w) if w == "local" => Self::Local,
            Some(w) if w == "central" => Self::Central,
            // Unknown value from a newer/garbled server: fail safe.
            Some(_) => {
                if has_cluster_node {
                    Self::Central
                } else {
                    Self::Local
                }
            }
            // Legacy server (no field): the historical inference.
            None => {
                if has_cluster_node {
                    Self::Central
                } else {
                    Self::Local
                }
            }
        }
    }

    pub fn is_central(self) -> bool {
        matches!(self, Self::Central)
    }
}

#[cfg(test)]
mod key_delivery_form_tests {
    use super::KeyDeliveryForm;

    #[test]
    fn explicit_server_contract_wins_over_inference() {
        // The whole point: the server's word beats the sidecar guess. A fresh
        // machine (no node yet) on a central cluster must NOT try to download.
        assert_eq!(
            KeyDeliveryForm::from_wire(Some("central"), false),
            KeyDeliveryForm::Central
        );
        // And a box that happens to have a stale node sidecar but whose server
        // says "local" must download normally (the 2026-07-13 incident shape).
        assert_eq!(
            KeyDeliveryForm::from_wire(Some("local"), true),
            KeyDeliveryForm::Local
        );
    }

    #[test]
    fn legacy_server_falls_back_to_node_inference() {
        assert_eq!(
            KeyDeliveryForm::from_wire(None, true),
            KeyDeliveryForm::Central
        );
        assert_eq!(
            KeyDeliveryForm::from_wire(None, false),
            KeyDeliveryForm::Local
        );
    }

    #[test]
    fn unknown_value_fails_safe_on_a_cluster() {
        assert_eq!(
            KeyDeliveryForm::from_wire(Some("teleport"), true),
            KeyDeliveryForm::Central
        );
        assert_eq!(
            KeyDeliveryForm::from_wire(Some("teleport"), false),
            KeyDeliveryForm::Local
        );
    }

    #[test]
    fn case_and_whitespace_insensitive() {
        assert_eq!(
            KeyDeliveryForm::from_wire(Some("  LOCAL "), true),
            KeyDeliveryForm::Local
        );
    }
}

/// The quota payload inlined in the delivery snapshot. Mirrors the server's
/// `quota.RulesSnapshot`.
#[derive(Debug, Deserialize, Clone)]
pub struct QuotaSnapshot {
    #[serde(default)]
    pub subjects: Vec<QuotaSubjectSnapshot>,
    /// D-U8/P6: deployment-global edge price summary `{version, models}` for the
    /// proxy's local usd pricing. Kept as raw JSON — the CLI only persists it for
    /// the proxy to parse. Absent (old/summary-less server) leaves the cached
    /// summary untouched.
    #[serde(default)]
    pub price_tiers: Option<serde_json::Value>,
}

/// One quota subject (a seat or a group of seats). `rules` is kept as raw JSON:
/// the CLI only persists it for the proxy to parse, so it doesn't need the Rule
/// shape and stays forward-compatible with rule-schema evolution.
#[derive(Debug, Deserialize, Clone)]
pub struct QuotaSubjectSnapshot {
    pub subject_id: String,
    pub subject_kind: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub rules: serde_json::Value,
    /// Stage 4 回填: per-(metric,period) current-period used baseline. Kept as
    /// raw JSON — the CLI only persists it for the proxy to seed its counter.
    #[serde(default)]
    pub baselines: serde_json::Value,
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
        self.slots
            .first()
            .map(|s| s.protocol_type.as_str())
            .unwrap_or("openai_compatible")
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Three-way answer from `resolve_cluster_node` (2026-06-12).
///
/// Why not `Option<String>`: persisted cluster routing may only be CLEARED on
/// an authoritative "this org has no cluster" (404). Auth failures / network
/// blips must be distinguishable so callers keep last-known-good routing
/// instead of silently downgrading a cluster employee to the (material-less)
/// local route. See `resolve_cluster_node` docs for the incident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterNodeResolution {
    /// On a cluster; routes to this `host:port` (advertise address).
    Node(String),
    /// Authoritative 404 `not_a_cluster` — safe to clear persisted routing.
    NotACluster,
    /// Auth failure / transport error / unexpected shape — topology UNKNOWN;
    /// callers must leave persisted routing untouched.
    Unknown(String),
}

/// Authenticated client for aikey-control-service.
pub struct PlatformClient {
    base_url: String,
    jwt: String,
}

/// Outcome of `PlatformClient::probe_token`. Discriminates the three
/// cases callers actually act on differently, instead of forcing every
/// caller to re-parse error strings.
///
/// - `Invalid` — server replied 401 with `BIZ_AUTH_TOKEN_INVALID`. This
///   happens after a backend reset rotates `JWT_SECRET`: the local
///   token's `exp` claim still says it's valid, but the new server can't
///   verify the signature. The cached token is permanently dead;
///   refresh-then-retry MAY help (server may still know our
///   refresh_token if only access tokens rotated) but typically requires
///   `aikey login`. Callers should treat this as "stop using this token".
/// - `Expired` — vanilla 401/403 without the invalidated marker. Same
///   refresh-then-retry path as the normal expiry case.
/// - `Offline` — couldn't talk to the server (transport error, timeout,
///   server 5xx, etc.). The token is presumed-valid; the caller should
///   carry on with the cached token and let the next operation surface
///   the real failure.
#[derive(Debug)]
pub enum TokenProbeError {
    Invalid,
    Expired,
    Offline,
}

impl std::fmt::Display for TokenProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(
                f,
                "server does not recognise this token (likely server reset)"
            ),
            Self::Expired => write!(f, "token expired"),
            Self::Offline => write!(f, "server unreachable"),
        }
    }
}

impl std::error::Error for TokenProbeError {}

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
        let url = format!(
            "{}/v1/auth/cli/login/exchange",
            base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "login_session_id": session_id,
            "login_token": login_token,
        });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("exchange request failed: {}", e))?;
        resp.into_json::<LoginTokenExchangeResponse>()
            .map(PollResponse::from)
            .map_err(|e| format!("failed to parse exchange response: {}", e))
    }

    /// POST /v1/auth/cli/token/refresh — issues a new access_token using the
    /// stored refresh_token.  No JWT required.
    pub fn do_refresh_token(
        base_url: &str,
        refresh_token: &str,
    ) -> Result<RefreshResponse, String> {
        let url = format!(
            "{}/v1/auth/cli/token/refresh",
            base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({ "refresh_token": refresh_token });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| {
                // Why: distinguish auth rejection (login expired, need re-login)
                // from transient failures (network, server error, DNS) so the CLI
                // can give the user the correct next step.
                match e {
                    ureq::Error::Status(status, _) if status == 401 || status == 403 => {
                        format!("login expired (HTTP {})", status)
                    }
                    _ => format!("token refresh failed: {}", e),
                }
            })?;
        resp.into_json::<RefreshResponse>()
            .map_err(|e| format!("failed to parse refresh response: {}", e))
    }

    /// GET /accounts/me — minimal authenticated probe.
    ///
    /// Returns `Ok(())` when the server accepts the supplied access token,
    /// `Err(TokenProbeError::Invalid)` when the server explicitly rejects
    /// it as cryptographically unrecognised (BIZ_AUTH_TOKEN_INVALID,
    /// produced after a backend reset that rotates JWT_SECRET — the
    /// rejection is permanent until re-login), `Err(TokenProbeError::Expired)`
    /// for ordinary HTTP-401 expiry, and `Err(TokenProbeError::Offline)`
    /// when the request can't reach the server (transport / DNS / timeout).
    ///
    /// We use `/accounts/me` because it's the cheapest authenticated GET
    /// the master server exposes — no DB join, no per-org work — and is
    /// guaranteed available on every control plane (Personal / Trial /
    /// Production). The 2-second timeout is set so a `aikey web` call
    /// can't be wedged offline by a slow probe; on offline, the caller
    /// falls back to the cached token (the URL still gets to the browser,
    /// where the SPA's existing 401 handling takes over).
    pub fn probe_token(base_url: &str, jwt: &str) -> Result<(), TokenProbeError> {
        let url = format!("{}/accounts/me", base_url.trim_end_matches('/'));
        let resp = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", jwt))
            .timeout(std::time::Duration::from_secs(2))
            .call();
        match resp {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(401, response)) | Err(ureq::Error::Status(403, response)) => {
                // The backend distinguishes "invalidated signature" from
                // "ordinary expiry" via the `error` field. Read the body
                // best-effort; if we can't parse it we conservatively call
                // it `Expired` so the caller does a normal refresh first
                // (cheap) before nuking the session.
                let body = response.into_string().unwrap_or_default();
                if body.contains("BIZ_AUTH_TOKEN_INVALID")
                    || body.contains("token is invalid")
                    || body.contains("令牌无效")
                {
                    Err(TokenProbeError::Invalid)
                } else {
                    Err(TokenProbeError::Expired)
                }
            }
            // Any other status (5xx, 404 on weird deployments, etc.) — treat
            // as transient. Don't claim the token is bad on the basis of a
            // server error.
            Err(ureq::Error::Status(_, _)) => Err(TokenProbeError::Offline),
            Err(ureq::Error::Transport(_)) => Err(TokenProbeError::Offline),
        }
    }

    /// POST /v1/digital-employees/register — self-register this host as a
    /// digital employee using an org join token. No JWT required (the join
    /// token in the body is the credential). Returns the daemon refresh_token.
    pub fn register_digital_employee(
        base_url: &str,
        join_token: &str,
        host_info: &str,
        display_name: &str,
    ) -> Result<RegisterDigitalEmployeeResponse, String> {
        let url = format!(
            "{}/v1/digital-employees/register",
            base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "join_token": join_token,
            "host_info": host_info,
            "display_name": display_name,
        });
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::Status(status, _) if status == 401 => {
                    "join token is invalid, revoked, or expired".to_string()
                }
                ureq::Error::Status(status, ref r) => {
                    format!("register failed (HTTP {}): {}", status, r.status_text())
                }
                _ => format!("register request failed: {}", e),
            })?;
        resp.into_json::<RegisterDigitalEmployeeResponse>()
            .map_err(|e| format!("failed to parse register response: {}", e))
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

    /// GET /accounts/me/cluster-node — form-① employee node resolve (P5).
    /// The employee holds ONLY its user JWT here; control brokers the hub
    /// resolve with the infra token server-side (never sent to the cli).
    ///
    /// 2026-06-12 three-way result (was `Option<String>`): the old shape
    /// collapsed EVERY failure — including 401 "your token is dead" and
    /// network blips — into `None`, and callers treated `None` as the
    /// authoritative "this org is not a cluster" answer and CLEARED the
    /// persisted node (`clear_cluster_node`). A server-side token rejection
    /// during sync therefore silently downgraded a cluster employee to the
    /// local-proxy route, which has NO key material on a cluster → every
    /// later call failed 503 NO_ACTIVE_KEY until a manual `aikey use`.
    /// The two mis-judgement costs are asymmetric: keeping a stale node is
    /// visible and self-corrects on the next resolve; wrongly clearing it is
    /// silent and dead-ends. So callers may only clear persisted routing on
    /// `NotACluster` (authoritative 404); `Unknown` keeps last-known-good.
    /// Bug: E2E case 2026-06-11 §L8 次生缺口.
    pub fn resolve_cluster_node(&self) -> ClusterNodeResolution {
        let url = format!("{}/accounts/me/cluster-node", self.base_url);
        let resp = match ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
        {
            Ok(r) => r,
            // 404 is the endpoint's designed "not_a_cluster" answer — the one
            // authoritative signal that this org has no cluster routing.
            Err(ureq::Error::Status(404, _)) => return ClusterNodeResolution::NotACluster,
            // 401/403/5xx/transport: says nothing about cluster topology —
            // auth problem or transient failure. Callers must not touch
            // persisted routing state.
            Err(e) => return ClusterNodeResolution::Unknown(e.to_string()),
        };
        let data: serde_json::Value = match resp.into_json() {
            Ok(d) => d,
            Err(e) => return ClusterNodeResolution::Unknown(format!("parse: {}", e)),
        };
        if data["ok"].as_bool() != Some(true) {
            // 2xx but ok!=true is an unexpected shape, not an authoritative
            // "no cluster" — treat as Unknown rather than clearing routes.
            return ClusterNodeResolution::Unknown("response ok!=true".to_string());
        }
        match data["addr"].as_str().filter(|s| !s.is_empty()) {
            Some(addr) => ClusterNodeResolution::Node(addr.to_string()),
            // ok:true with no addr = control says cluster exists but no live
            // node right now — transient (nodes down), not "no cluster".
            None => ClusterNodeResolution::Unknown("no live node".to_string()),
        }
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
        let resp = agent
            .get(&url)
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
        let resp = agent
            .get(&url)
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

#[cfg(test)]
mod cluster_resolve_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// One-shot mock control: answers a single HTTP request with `status` +
    /// `body`, then exits. Returns the bound base_url.
    fn mock_control(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    404 => "Not Found",
                    _ => "X",
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status, reason, body.len(), body
                );
            }
        });
        format!("http://{}", addr)
    }

    fn mock_control_draining_request(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 512];
                let mut header_end = None;
                while header_end.is_none() {
                    match s.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                        }
                    }
                }
                if let Some(pos) = header_end {
                    let headers = String::from_utf8_lossy(&buf[..pos + 4]).to_ascii_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    let already_read = buf.len().saturating_sub(pos + 4);
                    let mut remaining = content_length.saturating_sub(already_read);
                    while remaining > 0 {
                        match s.read(&mut tmp) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => remaining = remaining.saturating_sub(n),
                        }
                    }
                }
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    404 => "Not Found",
                    _ => "X",
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    reason,
                    body.len(),
                    body
                );
            }
        });
        format!("http://{}", addr)
    }

    // 2026-06-12 fence (L8 次生缺口): the three-way resolution semantics.
    // If a refactor ever collapses 401 back into "not a cluster", a dead
    // token during sync will again clear persisted cluster routing and
    // strand the employee on the material-less local route (503).

    #[test]
    fn resolve_404_is_authoritative_not_a_cluster() {
        let c = PlatformClient::new(&mock_control(404, r#"{"error":"not_a_cluster"}"#), "jwt");
        assert_eq!(c.resolve_cluster_node(), ClusterNodeResolution::NotACluster);
    }

    #[test]
    fn resolve_401_is_unknown_never_not_a_cluster() {
        let c = PlatformClient::new(&mock_control(401, r#"{"error":"unauthorized"}"#), "dead");
        match c.resolve_cluster_node() {
            ClusterNodeResolution::Unknown(_) => {}
            other => panic!("401 must be Unknown (keep routing), got {:?}", other),
        }
    }

    #[test]
    fn resolve_200_returns_node_addr() {
        let c = PlatformClient::new(
            &mock_control(
                200,
                r#"{"ok":true,"addr":"120.77.34.110:27200","node_id":"node-1"}"#,
            ),
            "jwt",
        );
        assert_eq!(
            c.resolve_cluster_node(),
            ClusterNodeResolution::Node("120.77.34.110:27200".to_string())
        );
    }

    #[test]
    fn resolve_transport_error_is_unknown() {
        // Port 0 → connection refused: transport failure, NOT "no cluster".
        let c = PlatformClient::new("http://127.0.0.1:0", "jwt");
        match c.resolve_cluster_node() {
            ClusterNodeResolution::Unknown(_) => {}
            other => panic!("transport error must be Unknown, got {:?}", other),
        }
    }

    #[test]
    fn exchange_login_token_accepts_statusless_token_body() {
        let base = mock_control_draining_request(
            200,
            r#"{"access_token":"jwt-123","refresh_token":"rt-456","token_type":"Bearer","expires_in":3600,"account":{"account_id":"acct-1","email":"admin@aikey.local"}}"#,
        );

        let resp = PlatformClient::exchange_login_token(&base, "session-1", "login-token-1")
            .expect("statusless exchange token payload should parse");

        assert_eq!(resp.status, "approved");
        assert_eq!(resp.access_token.as_deref(), Some("jwt-123"));
        assert_eq!(resp.refresh_token.as_deref(), Some("rt-456"));
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.expires_in, Some(3600));
        let account = resp.account.expect("account should be preserved");
        assert_eq!(account.account_id, "acct-1");
        assert_eq!(account.email, "admin@aikey.local");
        // A server that predates display_identity must still parse — the field
        // is absent here, and that is the whole point of this assertion.
        assert_eq!(account.display_label(), "admin@aikey.local");
    }

    /// 🔴 Decision contract (damon, 2026-07-21): after a Feishu first login the
    /// terminal shows `Logged in as 李承熙 · feishu:6ad2973d`, never the
    /// synthetic handle. This pins the value `finish_login` prints.
    ///
    /// 🔴 MUTATION PROOF — verbatim, 2026-07-21. Revert display_label to
    /// `&self.email`:
    ///   assertion `left == right` failed: the synthetic handle must never
    ///   reach a human
    ///     left: "sso+feishu.6ad2973d1e4b4c2f8a9b0c1d2e3f4a5b@sso.local"
    ///    right: "李承熙 · feishu:6ad2973d"
    #[test]
    fn display_label_prefers_display_identity_over_synthetic_handle() {
        let poll: PollResponse = serde_json::from_str(
            r#"{"status":"approved","access_token":"jwt","refresh_token":"rt","expires_in":3600,
                "account":{"account_id":"acct-1",
                           "email":"sso+feishu.6ad2973d1e4b4c2f8a9b0c1d2e3f4a5b@sso.local",
                           "display_identity":"李承熙 · feishu:6ad2973d"}}"#,
        )
        .expect("poll payload with display_identity should parse");

        let account = poll.account.expect("account present");
        assert_eq!(
            account.display_label(),
            "李承熙 · feishu:6ad2973d",
            "the synthetic handle must never reach a human"
        );
        assert!(
            !account.display_label().contains("@sso.local"),
            "display label leaked the synthetic handle: {}",
            account.display_label()
        );
    }

    /// An empty display_identity is a server bug, not a display name. Falling
    /// back keeps `Logged in as ` from rendering with nothing after it.
    #[test]
    fn display_label_falls_back_when_display_identity_is_blank() {
        let poll: PollResponse = serde_json::from_str(
            r#"{"status":"approved",
                "account":{"account_id":"a","email":"user@corp.com","display_identity":"   "}}"#,
        )
        .expect("blank display_identity should parse");
        assert_eq!(
            poll.account.expect("account present").display_label(),
            "user@corp.com"
        );
    }
}
