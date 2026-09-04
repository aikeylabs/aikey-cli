//! HTTP client for aikey-control-service.
//!
//! Uses `ureq` (blocking, no async) to keep the CLI dependency footprint small.
//!
//! Authentication:
//!   - OAuth device flow: `start_cli_login` → `poll_cli_login` → tokens saved locally.
//!   - Silent renewal: `do_refresh_token` uses the stored refresh token.
//!   - Authenticated requests require a Bearer access_token via `PlatformClient::new`.

use crate::control_plane_error::explain;
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
    /// SSO side-paths this deployment has enabled (2026-08-18, D2-A).
    /// `#[serde(default)]` because older servers omit the field entirely —
    /// an email-only deployment's wire is unchanged, and against an old
    /// server this simply parses as "no SSO here".
    #[serde(default)]
    pub sso_providers: Vec<SsoProviderEntry>,
}

/// One enabled SSO provider, as advertised by /init. The authorize PATH is a
/// client-side constant (`/v1/auth/cli/login/sso/{code}/authorize`) — the
/// server deliberately does not ship it per-response; the pattern is already a
/// two-sided contract shared with the server-rendered login page.
#[derive(Debug, Clone, Deserialize)]
pub struct SsoProviderEntry {
    pub code: String,
    pub display_name: String,
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
    /// Legacy single-binding protocol projection. New servers also return the
    /// binding-granular `bindings` array below; keep this field as a fallback
    /// for rolling upgrades.
    #[serde(default)]
    pub protocol_type: String,
    /// Exact Provider+Protocol axes for every active VK binding. The lightweight
    /// metadata sync must consume these instead of inventing one protocol from
    /// `provider_code` (Mock Provider is intentionally multi-protocol).
    #[serde(default)]
    pub bindings: Vec<KeyBindingAxis>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyBindingAxis {
    pub protocol: String,
    pub provider: String,
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
    /// Which org route-group TEMPLATE generated this chain (P0a upstream
    /// fallback, task 0b.8). Empty when the chain predates route groups.
    ///
    /// `serde(default)` is load-bearing: an OLDER control plane omits both
    /// fields entirely, and a newer CLI must keep working against it. The
    /// server side omits them too (`omitempty`) so that "no group" and "a group
    /// whose id is empty" stay distinguishable rather than collapsing into "".
    #[serde(default)]
    pub route_group_id: String,
    /// Human-readable template name, for `aikey use` summaries. Cosmetic: the
    /// id is what carries provenance.
    #[serde(default)]
    pub group_name: String,
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
    /// Route-group template (id, name) for a protocol slot (task 1.3).
    ///
    /// Slot-level rather than per-target on purpose: every hop of one chain
    /// shares a template — the control plane's composite FK / trigger makes a
    /// mismatch unstorable — so a per-hop copy could only ever disagree with
    /// itself. Empty strings mean "no group", which is a legitimate state (a
    /// legacy chain, or Personal) and must stay distinguishable from a group
    /// whose id happens to be blank.
    pub fn route_group_for(&self, protocol_type: &str) -> (&str, &str) {
        for slot in &self.slots {
            if !protocol_type.is_empty() && slot.protocol_type != protocol_type {
                continue;
            }
            return (slot.route_group_id.as_str(), slot.group_name.as_str());
        }
        ("", "")
    }

    /// Returns the primary (first) binding target, if any.
    pub fn primary_binding(&self) -> Option<&BindingTarget> {
        self.slots.first()?.binding_targets.first()
    }

    /// P1e (design D-11): find the binding target for a specific
    /// (protocol_type, provider_code) so each per-binding cache row pulls ITS
    /// OWN credential material — a VK can carry e.g. GLM(zhipu key) AND the
    /// official Anthropic(official key), one per slot/target, each with its own
    /// `provider_key`. An empty `protocol_type` matches any slot (older cache
    /// rows). Returns the matched slot's protocol_type alongside the target.
    pub fn binding_for(
        &self,
        protocol_type: &str,
        provider_code: &str,
    ) -> Option<(&str, &BindingTarget)> {
        for slot in &self.slots {
            if !protocol_type.is_empty() && slot.protocol_type != protocol_type {
                continue;
            }
            for bt in &slot.binding_targets {
                if bt.provider_code == provider_code {
                    return Some((slot.protocol_type.as_str(), bt));
                }
            }
        }
        None
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

/// Extracts the licensed company name from a `/v1/license/status` body.
///
/// 🔴 Split out from the fetch so it can be tested. The rules below are the ones
/// with consequences, and none of them is exercised by anything that needs a
/// socket — leaving them inside an HTTP call would have meant the only way to
/// check them was to read them.
pub(crate) fn parse_licensed_company_name(body: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;

    // 🔴 The schema version is checked rather than ignored. The status shape is
    // versioned precisely so a client that cannot read it says nothing — and
    // here "says nothing" is the correct behaviour, because a watermark rendered
    // from a misread document would display the WRONG company name. A blank
    // watermark is a missing feature; a wrong one is a false statement about who
    // this deployment belongs to, printed on the surface people trust most.
    if parsed.get("schema_version").and_then(|v| v.as_u64()) != Some(1) {
        return None;
    }
    // Both shapes carry it: the administrator's full Status nests it under
    // `identity`, and a member's reduced view (MemberStatus — one field, by
    // design) has it at the top level. A member running `aikey status` must see
    // the same watermark an administrator does; that is the point of the
    // watermark.
    let name = parsed
        .get("identity")
        .and_then(|i| i.get("company_name"))
        .or_else(|| parsed.get("company_name"))
        .and_then(|v| v.as_str())?
        .trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

impl PlatformClient {
    /// Creates a new client using a JWT already stored in `platform_account`.
    // ── Control-plane time budgets (2026-09-04) ──────────────────────────────
    //
    // Every call in this file talks to a master that, in a private deployment,
    // fails by BLACK-HOLING packets (dropped, no RST). Unbounded, such a call
    // hangs for the OS connect/read retry budget — tens of seconds with no
    // feedback. On 2026-09-04, 11 of 13 calls here had no budget at all.
    //
    // Two budgets, not ten hand-picked numbers: the distinction that actually
    // changes the right answer is "is a human watching a spinner right now?".
    // Anything finer would be numbers without a reason behind them.
    /// A human is staring at a spinner and will read "it is broken" into any
    /// longer wait. Only `init_cli_login` qualifies: aikey-tray's panel claims
    /// a browser window opened the moment the CLI process starts, so THIS call's
    /// budget is the lifetime of that claim.
    pub(crate) const BUDGET_INTERACTIVE: std::time::Duration = std::time::Duration::from_secs(5);
    /// Everything else: background, retryable, or already behind its own
    /// progress output. Generous on purpose — a loaded private-deployment
    /// master is allowed to be slow (`start_cli_login` even sends mail
    /// server-side). Too tight would turn "slow but alive" into "cannot sign
    /// in", which is a worse bug than the one being fixed.
    pub(crate) const BUDGET_STANDARD: std::time::Duration = std::time::Duration::from_secs(15);
    /// Read-only probe with a cached fallback: failing fast costs nothing, and
    /// two of these sit on `aikey web`'s hot path.
    pub(crate) const BUDGET_PROBE: std::time::Duration = std::time::Duration::from_secs(2);

    /// A ureq agent that actually honours `budget` — including the TCP connect.
    ///
    /// 🔴 WHY AN AGENT AND NOT A PER-REQUEST `.timeout()` (2026-09-04, learned
    /// the hard way). ureq's request-level `.timeout()` does NOT bound the
    /// connect phase; that is `timeout_connect`, an AGENT setting whose default
    /// is 30s. A master that BLACK-HOLES packets never completes the connect, so
    /// a request-level budget never gets a chance to apply.
    ///
    /// Measured on winpc2 the same day, against a black-holed address, WITH a
    /// 5s request-level timeout already in place: **21.21s**, ending in Windows
    /// `os error 10060` — the OS connect timeout, not our budget. The first fix
    /// bounded the read phase and left the real-world failure untouched; the
    /// fence missed it because it used a server that ACCEPTS the connection.
    /// `timeout_connect` takes precedence over `timeout` for that phase (ureq
    /// 2.12 agent.rs:405), so both are set here and the tighter one wins.
    ///
    /// A bare AgentBuilder carries no proxy config — the same posture as the
    /// `ureq::post` calls it replaces, and deliberate: see the note on
    /// `commands_proxy::fetch_compliance_packs`. Do not make it proxy-aware.
    ///
    /// bugfix: workflow/CI/bugfix/2026-09-04-tray-claims-browser-opened-before-master-reached.md
    fn bounded(budget: std::time::Duration) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout_connect(budget)
            .timeout(budget)
            .build()
    }

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

        let resp = Self::bounded(Self::BUDGET_STANDARD).post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("login request failed: {}", explain(base_url, e)))?;

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
        // 🔴 5s budget (2026-09-04, user decision "5s 弹登录失败吧").
        //
        // WHY this call in particular: it is the FIRST thing both the browser
        // and the --sso flows do, and the browser is only opened AFTER it
        // returns. Until it does, aikey-tray's panel already shows "请在刚打开
        // 的浏览器窗口完成授权" — a window that does not exist yet. Unbounded,
        // that false sentence stood for the OS connect timeout (tens of seconds
        // against a black-holed host, which is exactly how a private-deployment
        // master fails: packets dropped, no RST). Bounded, the panel flips to a
        // real error with the real reason within 5s.
        //
        // WHY 5s and not the 2s its siblings use: probe_token/licensed_company_name
        // are read-only probes with a cached fallback, so failing fast costs
        // nothing. This POST CREATES a login session on the server, and a loaded
        // private-deployment master is allowed to be slow — a 2s budget would
        // turn "slow but alive" into "cannot sign in", trading one bug for a
        // worse one.
        //
        // bugfix: workflow/CI/bugfix/2026-09-04-tray-claims-browser-opened-before-master-reached.md
        let resp = Self::bounded(Self::BUDGET_INTERACTIVE).post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("login init failed: {}", explain(base_url, e)))?;
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
        let resp = Self::bounded(Self::BUDGET_STANDARD).post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("login start failed: {}", explain(base_url, e)))?;
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
        let resp = Self::bounded(Self::BUDGET_STANDARD).post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("poll request failed: {}", explain(base_url, e)))?;
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
        let resp = Self::bounded(Self::BUDGET_STANDARD).post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("exchange request failed: {}", explain(base_url, e)))?;
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
        let resp = Self::bounded(Self::BUDGET_STANDARD).post(&url)
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
                    _ => format!("token refresh failed: {}", explain(base_url, e)),
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
        let resp = Self::bounded(Self::BUDGET_PROBE).get(&url)
            .set("Authorization", &format!("Bearer {}", jwt))
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

    /// GET /v1/license/status — the licensed company name, for the CLI's
    /// identity watermark (技术方案 §7.1 「三处身份水印」的第三处).
    ///
    /// 🔴 What a watermark is for. The other two — the web login page and the
    /// settings page — exist so that a deployment cannot be quietly passed off as
    /// somebody else's. The CLI is the surface a developer looks at every day,
    /// and it was the one place the licensed name never appeared, so a resold or
    /// copied deployment looked exactly like a legitimate one from the seat that
    /// spends the most hours in front of it.
    ///
    /// 🚫 It is DISPLAY, not enforcement. Nothing about this call decides
    /// anything: the name is rendered, and licence state is decided in the
    /// control plane where it is signed. A CLI that acted on this answer would be
    /// a CLI whose licensing could be changed with a local proxy.
    ///
    /// 🔴 Returns None on every failure, deliberately and without an error type.
    /// The alternative is that a slow or absent control service makes
    /// `aikey status` fail — turning an identity display into a new way for the
    /// daily-driver command to break. Personal has no licence surface at all and
    /// answers 404, which is the ordinary case rather than a fault.
    ///
    /// The 2-second timeout matches probe_token's, for the same reason recorded
    /// there: this runs inside an interactive command.
    pub fn licensed_company_name(base_url: &str, jwt: &str) -> Option<String> {
        let url = format!("{}/v1/license/status", base_url.trim_end_matches('/'));
        let body = Self::bounded(Self::BUDGET_PROBE).get(&url)
            .set("Authorization", &format!("Bearer {}", jwt))
            .call()
            .ok()?
            .into_string()
            .ok()?;
        parse_licensed_company_name(&body)
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
        let resp = Self::bounded(Self::BUDGET_STANDARD).post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::Status(status, _) if status == 401 => {
                    "join token is invalid, revoked, or expired".to_string()
                }
                ureq::Error::Status(status, ref r) => {
                    format!("register failed (HTTP {}): {}", status, r.status_text())
                }
                _ => format!("register request failed: {}", explain(base_url, e)),
            })?;
        resp.into_json::<RegisterDigitalEmployeeResponse>()
            .map_err(|e| format!("failed to parse register response: {}", e))
    }

    // ---- Key discovery ------------------------------------------------------

    /// GET /accounts/me/pending-keys
    /// GET /accounts/me/all-keys
    pub fn get_all_keys(&self) -> Result<Vec<KeyItem>, String> {
        let url = format!("{}/accounts/me/all-keys", self.base_url);

        let resp = Self::bounded(Self::BUDGET_STANDARD).get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| format!("all-keys request failed: {}", explain(&self.base_url, e)))?;

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
        let resp = match Self::bounded(Self::BUDGET_STANDARD).get(&url)
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
            .build();
        let resp = agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| {
                format!(
                    "sync-version request failed: {}",
                    explain(&self.base_url, e)
                )
            })?;
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
            .build();
        let resp = agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| {
                format!(
                    "managed-keys-snapshot request failed: {}",
                    explain(&self.base_url, e)
                )
            })?;
        resp.into_json::<ManagedKeysSnapshotResponse>()
            .map_err(|e| format!("failed to parse managed-keys-snapshot response: {}", e))
    }

    // ---- Key delivery -------------------------------------------------------

    /// GET /virtual-keys/{id}/delivery
    /// Returns full payload including plaintext provider key (over TLS).
    pub fn get_key_delivery(&self, virtual_key_id: &str) -> Result<DeliveryPayload, String> {
        let url = format!("{}/virtual-keys/{}/delivery", self.base_url, virtual_key_id);

        let resp = Self::bounded(Self::BUDGET_STANDARD).get(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .call()
            .map_err(|e| format!("delivery request failed: {}", explain(&self.base_url, e)))?;

        resp.into_json::<DeliveryPayload>()
            .map_err(|e| format!("failed to parse delivery payload: {}", e))
    }

    /// POST /virtual-keys/{id}/claim
    /// Marks the key as claimed on the server side (idempotent).
    pub fn claim_key(&self, virtual_key_id: &str) -> Result<(), String> {
        let url = format!("{}/virtual-keys/{}/claim", self.base_url, virtual_key_id);

        Self::bounded(Self::BUDGET_STANDARD).post(&url)
            .set("Authorization", &format!("Bearer {}", self.jwt))
            .set("Content-Type", "application/json")
            .send_string("{}")
            .map_err(|e| format!("claim request failed: {}", explain(&self.base_url, e)))?;

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

// ── Task 6.4, L2 (contract) ────────────────────────────────────────────────
//
// The matrix's L2 row is the same for all three editions: "`binding_targets` 的
// priority 顺序在金库里保住了；老代理收到新列静默忽略". The vault-INSERT half is
// fenced textually in storage_platform.rs (`task_1_3_…`, with its own note on why
// a round-trip test stayed green against the injected regression). This module
// covers the WIRE half — what the CLI parses, in both compatibility directions.
#[cfg(test)]
mod chain_wire_contract_tests {
    use super::*;

    /// L2 — priority order and per-hop values survive deserialization.
    ///
    /// 🔴 The targets arrive DELIBERATELY out of order here. The server documents
    /// "targets ordered by priority ASC", and the tempting reading is that the
    /// client may therefore trust position. This asserts the values ride along
    /// per hop, so a consumer sorts by `priority` rather than by arrival — the
    /// same reason candidate_chain.go sorts again after the registry already did.
    #[test]
    fn task_6_4_l2_binding_target_order_and_values_survive_the_wire() {
        let json = r#"{
            "virtual_key_id":"vk-1","org_id":"o1","seat_id":"s1","alias":"k","current_revision":"r1",
            "key_status":"active","share_status":"claimed",
            "slots":[{"protocol_type":"anthropic","binding_targets":[
              {"binding_id":"b3","provider_code":"openai","base_url":"https://o",
               "provider_key":"k3","credential_id":"c3","credential_revision":"r",
               "priority":3,"fallback_role":"fallback"},
              {"binding_id":"b1","provider_code":"anthropic","base_url":"https://a",
               "provider_key":"k1","credential_id":"c1","credential_revision":"r",
               "priority":1,"fallback_role":"primary"},
              {"binding_id":"b2","provider_code":"zhipu","base_url":"https://z",
               "provider_key":"k2","credential_id":"c2","credential_revision":"r",
               "priority":2,"fallback_role":"fallback"}
            ]}]
        }"#;
        let payload: DeliveryPayload = serde_json::from_str(json).expect("parse delivery payload");
        let targets = &payload.slots[0].binding_targets;
        assert_eq!(targets.len(), 3, "a hop was dropped in deserialization");

        let mut got: Vec<(i32, &str, &str)> = targets
            .iter()
            .map(|t| {
                (
                    t.priority,
                    t.provider_code.as_str(),
                    t.fallback_role.as_str(),
                )
            })
            .collect();
        got.sort_by_key(|t| t.0);
        assert_eq!(
            got,
            vec![
                (1, "anthropic", "primary"),
                (2, "zhipu", "fallback"),
                (3, "openai", "fallback"),
            ],
            "priority / fallback_role did not survive the wire per hop. Losing them here \
             discards the administrator's order before the vault ever sees it, and every \
             downstream test would still pass — the chain would simply run in arrival order."
        );
    }

    /// L2 — a NEWER control plane's extra columns must not break an OLDER reader.
    ///
    /// 🔴 This is true today only because nothing on this path sets
    /// `serde(deny_unknown_fields)`. That is a silent property: adding it
    /// anywhere would compile, pass every existing test, and then make every
    /// deployed older CLI fail to parse delivery the moment the server grows a
    /// field — an outage triggered by a server-side change, on clients nobody
    /// touched. The payload below carries fields this struct has never heard of.
    #[test]
    fn task_6_4_l2_unknown_future_columns_are_ignored_not_rejected() {
        let json = r#"{
            "virtual_key_id":"vk-1","org_id":"o1","seat_id":"s1","alias":"k","current_revision":"r1",
            "key_status":"active","share_status":"claimed",
            "a_field_from_the_future":{"nested":[1,2,3]},
            "slots":[{"protocol_type":"anthropic","some_future_slot_field":"x",
              "binding_targets":[
              {"binding_id":"b1","provider_code":"anthropic","base_url":"https://a",
               "provider_key":"k1","credential_id":"c1","credential_revision":"r",
               "priority":1,"fallback_role":"primary",
               "weight":7,"health_hint":"green"}
            ]}]
        }"#;
        let payload: DeliveryPayload = serde_json::from_str(json)
            .expect("an older reader must IGNORE unknown fields, not reject the payload");
        assert_eq!(payload.slots[0].binding_targets[0].priority, 1);
    }

    /// L2, the other direction — an OLDER control plane omits the new fields
    /// entirely and a NEWER CLI must still work. This is what `serde(default)`
    /// on the route-group fields buys, and it is the upgrade order most
    /// deployments actually have (clients update before the server).
    #[test]
    fn task_6_4_l2_missing_route_group_fields_default_rather_than_fail() {
        let json = r#"{
            "virtual_key_id":"vk-1","org_id":"o1","seat_id":"s1","alias":"k","current_revision":"r1",
            "key_status":"active","share_status":"claimed",
            "slots":[{"protocol_type":"anthropic","binding_targets":[
              {"binding_id":"b1","provider_code":"anthropic","base_url":"https://a",
               "provider_key":"k1","credential_id":"c1","credential_revision":"r",
               "priority":1,"fallback_role":"primary"}
            ]}]
        }"#;
        let payload: DeliveryPayload = serde_json::from_str(json)
            .expect("a payload from an older control plane must still parse");
        let (gid, gname) = payload.route_group_for("anthropic");
        assert_eq!(
            (gid, gname),
            ("", ""),
            "absent route-group fields must default to empty — empty means 'no group', which is \
             a legitimate state (a legacy chain, or Personal) and must stay distinguishable"
        );
    }

    /// The fence that keeps the two tests above meaningful.
    #[test]
    fn task_6_4_l2_delivery_structs_never_deny_unknown_fields() {
        // 🔴 Match the ATTRIBUTE, not the words. The first version of this fence
        // searched the whole file for the bare string and failed on its own
        // failure message — a test that cannot survive describing what it checks
        // gets weakened until it says nothing.
        let offenders: Vec<usize> = include_str!("platform_client.rs")
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                t.starts_with("#[") && t.contains("deny_unknown_fields")
            })
            .map(|(i, _)| i + 1)
            .collect();
        assert!(
            offenders.is_empty(),
            "platform_client.rs applies serde's unknown-field rejection at line(s) {offenders:?}. \
             Every deployed older CLI would then fail to parse delivery as soon as the control \
             plane adds a field — a client-side outage caused by a server-side change, on clients \
             nobody upgraded."
        );
    }
}

#[cfg(test)]
mod licensed_company_name_tests {
    // 技术方案 §7.1「三处身份水印」的第三处：aikey CLI。
    //
    // 🔴 水印的失败模式不是「没显示」，是「显示错了」。前者是缺个功能；后者是在
    // 开发者每天都看的那个界面上，就「这套部署属于谁」这件事印了一句假话。下面每
    // 条测试都是围着这个区别写的。
    use super::parse_licensed_company_name;

    const COMPANY: &str = "深圳示例科技有限公司";

    #[test]
    fn an_administrators_status_renders_the_company_name() {
        let body = format!(
            r#"{{"schema_version":1,"applicable":true,"identity":{{"company_name":"{COMPANY}","serial":"a1b2c3"}}}}"#
        );
        assert_eq!(parse_licensed_company_name(&body).as_deref(), Some(COMPANY));
    }

    #[test]
    fn a_members_reduced_status_renders_the_same_name() {
        // MemberStatus is one field by design. A member must see the same
        // watermark an administrator does — a watermark only administrators can
        // see is not a watermark.
        let body = format!(r#"{{"schema_version":1,"company_name":"{COMPANY}"}}"#);
        assert_eq!(parse_licensed_company_name(&body).as_deref(), Some(COMPANY));
    }

    #[test]
    fn a_future_schema_renders_nothing_rather_than_guessing() {
        let body = format!(r#"{{"schema_version":2,"identity":{{"company_name":"{COMPANY}"}}}}"#);
        assert_eq!(
            parse_licensed_company_name(&body),
            None,
            "a newer status shape was read anyway. The field this client happens to \
             recognise may not mean the same thing in that shape, and printing it \
             would be a false statement about who this deployment belongs to"
        );
    }

    #[test]
    fn a_document_that_is_not_a_licence_status_renders_nothing() {
        for body in [
            r#"{"company_name":"somebody else"}"#, // no schema_version at all
            r#"{"schema_version":1}"#,             // right shape, no name
            r#"{"schema_version":1,"identity":{"company_name":"   "}}"#, // blank
            r#"not json at all"#,
            r#""#,
        ] {
            assert_eq!(
                parse_licensed_company_name(body),
                None,
                "rendered a watermark from {body:?}"
            );
        }
    }

    #[test]
    fn the_name_is_rendered_byte_for_byte() {
        // specs/license-identity requires every surface to show the same string.
        // 🚫 No truncation, no width limit, no ellipsis: a shortened legal name
        // is not the legal name, and this value's whole job is to be comparable
        // against a contract.
        let long = "北京某某某某某某某某某某某某某某某某某某科技发展有限责任公司";
        let body = format!(r#"{{"schema_version":1,"company_name":"{long}"}}"#);
        assert_eq!(parse_licensed_company_name(&body).as_deref(), Some(long));

        // Surrounding whitespace IS trimmed — that is transport noise, not part
        // of the name — but nothing INSIDE it is touched. A name whose internal
        // spacing was normalised would stop matching the business licence it is
        // supposed to be comparable against.
        let inner = "AiKey  Labs   (Shenzhen)";
        let body = format!(r#"{{"schema_version":1,"company_name":"  {inner}  "}}"#);
        assert_eq!(parse_licensed_company_name(&body).as_deref(), Some(inner));
    }
}

// ── Every control-plane call must go through bounded() (2026-09-04) ─────────
#[cfg(test)]
mod control_plane_agent_fence {
    //! 🔴 The invariant this file learned the hard way.
    //!
    //! The FIRST attempt at this fence asserted "every ureq call sets
    //! `.timeout(`". It went green, and the bug survived: a request-level
    //! timeout does not bound the TCP connect, and a black-holed master never
    //! completes one. Measured on winpc2 with that "fix" installed: **21.21s**
    //! to fail, ending in Windows `os error 10060` — the OS connect timeout.
    //!
    //! So the invariant is not "a timeout is set somewhere". It is: **the call
    //! goes through `PlatformClient::bounded()`**, the one constructor that sets
    //! `timeout_connect`. Asserting the mechanism instead of the symptom is the
    //! whole lesson — the symptom test agreed with a broken fix.
    //!
    //! Deterministic on purpose (source scan, no network): the connect phase
    //! cannot be exercised reliably in a unit test — reproducing it needs an
    //! address that black-holes packets, which depends on the box's network.
    //! The empirical half lives in the bugfix as a measured before/after on a
    //! real Windows machine; this half makes sure nobody re-introduces a bare
    //! call afterwards.
    //!
    //! bugfix: workflow/CI/bugfix/2026-09-04-tray-claims-browser-opened-before-master-reached.md
    const SELF_MODULE: &str = "mod control_plane_agent_fence";

    /// Built at runtime so this file does not contain the needles it scans for.
    fn needles() -> [String; 2] {
        [
            format!("{}::post(", "ureq"),
            format!("{}::get(", "ureq"),
        ]
    }

    #[test]
    fn no_bare_ureq_calls_outside_the_bounded_constructor() {
        let src = include_str!("platform_client.rs");
        // Everything from this module onward is fence code, not product code.
        let product = &src[..src.find(SELF_MODULE).unwrap_or(src.len())];
        let mut offenders = Vec::new();
        for (n, line) in product.lines().enumerate() {
            if needles().iter().any(|nd| line.contains(nd.as_str())) {
                // The constructor itself is the one legitimate site.
                if line.contains("AgentBuilder") {
                    continue;
                }
                offenders.push(format!("line {}: {}", n + 1, line.trim()));
            }
        }
        assert!(
            offenders.is_empty(),
            "control-plane call(s) bypassing PlatformClient::bounded():\n  {}\n\n             A bare ureq call inherits ureq's 30s connect default, and a master \
             that black-holes packets never completes the connect — the request \
             budget never applies (winpc2 2026-09-04: 21.21s, os error 10060). \
             Route it through bounded(BUDGET_PROBE / BUDGET_INTERACTIVE / \
             BUDGET_STANDARD).",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn bounded_actually_sets_the_connect_timeout() {
        let src = include_str!("platform_client.rs");
        let body_start = src.find("fn bounded(budget:").expect("bounded() exists");
        let body = &src[body_start..body_start + 400];
        assert!(
            body.contains("timeout_connect("),
            "bounded() no longer sets timeout_connect — every call in this file \
             silently reverts to ureq's 30s connect default, which is the exact \
             defect this constructor exists to prevent."
        );
    }
}

// ── Control-plane budget fence (2026-09-04) ──────────────────────────────────
#[cfg(test)]
mod control_plane_budget_fence {
    //! Written BEFORE the 10 remaining calls were bounded (user instruction:
    //! "修复之前要有充分围栏测试，避免引发其他问题"), so that the fence is proven
    //! to catch the defect rather than merely agreeing with the fix.
    //!
    //! Two claims, and the SECOND one is the reason this file exists:
    //!
    //!   1. a hung master must not hang the CLI  — RED before the fix
    //!   2. a SLOW BUT ALIVE master must still succeed — GREEN before AND after
    //!
    //! Claim 2 is the regression guard. The realistic way to break this code is
    //! not "forgot a timeout", it is "picked one that is too small", which turns
    //! a slow private-deployment master into one nobody can sign in to — worse
    //! than the bug being fixed. Claim 2 fails the moment a budget drops under
    //! the server delay.
    //!
    //! Why timing assertions and not response fixtures: proving "the round trip
    //! completed" needs only `elapsed >= server_delay` — had the call timed out
    //! early it would have returned BEFORE the server ever replied. That holds
    //! for all ten calls without building ten response shapes, so the fence does
    //! not rot when a DTO changes.
    //!
    //! bugfix: workflow/CI/bugfix/2026-09-04-tray-claims-browser-opened-before-master-reached.md
    use super::PlatformClient;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Server delay used by the "slow but alive" claim. Comfortably longer than
    /// any plausible LAN round trip, comfortably shorter than every budget.
    const SLOW_REPLY: Duration = Duration::from_secs(1);
    /// Slack over a budget before we call a bounded call "unbounded".
    const MARGIN: Duration = Duration::from_secs(4);

    /// Spawns a local server. `reply_after == None` means "accept the
    /// connection and never answer" — the black-holed-master shape, and the
    /// only one that reproduces an unbounded wait deterministically (an
    /// unroutable IP would depend on the CI box's network).
    fn spawn(reply_after: Option<Duration>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    // Drain what arrived; the request is small enough to land in
                    // one read, and nothing here needs to parse it.
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    match reply_after {
                        Some(d) => {
                            std::thread::sleep(d);
                            let _ = stream.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                  Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                            );
                            let _ = stream.flush();
                        }
                        // Hold the connection open forever: park, keeping the
                        // stream alive. Dropping it would send EOF and the
                        // client would return promptly — the opposite of the
                        // situation under test.
                        None => loop {
                            std::thread::sleep(Duration::from_secs(3600));
                        },
                    }
                });
            }
        });
        base
    }

    type Call = (&'static str, fn(&str), Duration);

    /// Every call in this file, paired with the budget it is meant to honour.
    /// `init_cli_login` is included so the interactive budget is covered by the
    /// same two claims as the rest.
    fn calls() -> Vec<Call> {
        vec![
            ("init_cli_login", |b| { let _ = PlatformClient::init_cli_login(b, "v", "os"); }, PlatformClient::BUDGET_INTERACTIVE),
            ("login", |b| { let _ = PlatformClient::login(b, "e@x.test", "p"); }, PlatformClient::BUDGET_STANDARD),
            ("start_cli_login", |b| { let _ = PlatformClient::start_cli_login(b, "e@x.test", "v", "os"); }, PlatformClient::BUDGET_STANDARD),
            ("poll_cli_login", |b| { let _ = PlatformClient::poll_cli_login(b, "s", "d"); }, PlatformClient::BUDGET_STANDARD),
            ("exchange_login_token", |b| { let _ = PlatformClient::exchange_login_token(b, "s", "t"); }, PlatformClient::BUDGET_STANDARD),
            ("do_refresh_token", |b| { let _ = PlatformClient::do_refresh_token(b, "rt"); }, PlatformClient::BUDGET_STANDARD),
            ("register_digital_employee", |b| { let _ = PlatformClient::register_digital_employee(b, "jt", "host", "name"); }, PlatformClient::BUDGET_STANDARD),
            ("get_all_keys", |b| { let _ = PlatformClient::new(b, "jwt").get_all_keys(); }, PlatformClient::BUDGET_STANDARD),
            ("resolve_cluster_node", |b| { let _ = PlatformClient::new(b, "jwt").resolve_cluster_node(); }, PlatformClient::BUDGET_STANDARD),
            ("get_key_delivery", |b| { let _ = PlatformClient::new(b, "jwt").get_key_delivery("vk"); }, PlatformClient::BUDGET_STANDARD),
            ("claim_key", |b| { let _ = PlatformClient::new(b, "jwt").claim_key("vk"); }, PlatformClient::BUDGET_STANDARD),
        ]
    }

    /// Runs every call against `base` in parallel and reports how long each
    /// took. Calls that have not returned by `deadline` are reported as
    /// unbounded rather than hanging the test run.
    fn run_all(base: &str, deadline: Duration) -> (Vec<(String, Duration)>, Vec<String>) {
        let (tx, rx) = mpsc::channel();
        let mut pending: Vec<String> = Vec::new();
        for (name, f, _) in calls() {
            pending.push(name.to_string());
            let tx = tx.clone();
            let base = base.to_string();
            // Detached on purpose: a thread stuck in an unbounded call cannot be
            // joined, and the whole point is to report that instead of hanging.
            std::thread::spawn(move || {
                let t0 = Instant::now();
                f(&base);
                let _ = tx.send((name.to_string(), t0.elapsed()));
            });
        }
        drop(tx);
        let started = Instant::now();
        let mut done = Vec::new();
        while !pending.is_empty() {
            let left = deadline.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok((name, took)) => {
                    pending.retain(|p| p != &name);
                    done.push((name, took));
                }
                Err(_) => break,
            }
        }
        (done, pending)
    }

    #[test]
    fn slow_but_alive_master_still_succeeds() {
        let base = spawn(Some(SLOW_REPLY));
        let budgets = calls();
        let (done, never_returned) = run_all(&base, Duration::from_secs(60));
        assert!(
            never_returned.is_empty(),
            "these calls never came back against a server that DID answer in {:?}: {:?}",
            SLOW_REPLY, never_returned
        );
        for (name, took) in done {
            let budget = budgets.iter().find(|(n, _, _)| *n == name).map(|(_, _, b)| *b).expect("known call");
            // The load-bearing assertion: a call that returned EARLIER than the
            // server's reply cannot have completed the round trip — it timed
            // out. That is the "budget too small" regression.
            assert!(
                took >= SLOW_REPLY,
                "{name} returned in {took:?}, before the server replied at {SLOW_REPLY:?} — \
                 its budget ({budget:?}) is too small, so a slow-but-alive master now looks \
                 unreachable. That is a worse bug than the unbounded wait this fence guards."
            );
            assert!(
                took < budget,
                "{name} took {took:?}, over its own {budget:?} budget on a healthy server"
            );
        }
    }

    #[test]
    fn hung_master_does_not_hang_the_cli() {
        let base = spawn(None);
        let budgets = calls();
        let longest = budgets.iter().map(|(_, _, b)| *b).max().expect("non-empty");
        let (done, never_returned) = run_all(&base, longest + MARGIN);
        assert!(
            never_returned.is_empty(),
            "control-plane call(s) still unbounded against a master that accepts the \
             connection and never answers: {:?}\n\
             This is the 2026-09-04 winpc2 shape — the CLI waits on the OS retry \
             budget while the UI tells the user something is happening. Give each \
             one a budget (PlatformClient::BUDGET_STANDARD / BUDGET_INTERACTIVE).",
            never_returned
        );
        for (name, took) in done {
            let budget = budgets.iter().find(|(n, _, _)| *n == name).map(|(_, _, b)| *b).expect("known call");
            assert!(
                took <= budget + MARGIN,
                "{name} took {took:?} against a hung server, past its {budget:?} budget"
            );
        }
    }
}
