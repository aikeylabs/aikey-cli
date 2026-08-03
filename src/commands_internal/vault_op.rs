//! `_internal vault-op` 子命令：vault 加密/写操作入口
//!
//! # Phase 分工
//! - Phase A：`verify`
//! - Phase B（本次）：`add` / `batch_import` / `update_secret` / `delete`
//!
//! # Audit 接入（Phase F 完成）
//! 所有 mutating actions 在 vault 写成功后，调用
//! `audit::log_audit_event_from_vault_key(&key, operation, alias, success)` 写 audit_log。
//! 派生路径：HMAC-SHA256(vault_key, "AK_AUDIT_V2:audit-v1") → audit_key
//! 详见 `audit.rs::derive_audit_key_from_vault_key` 的决策注释。
//! 响应中 `audit_logged: true` 标志位给 Go 侧感知。
//! Audit 失败**不**回滚 vault 写（best-effort），但会降级到 `audit_logged: false` + warning。

use serde::Deserialize;
use serde_json::json;

use crate::audit::{self, AuditOperation};
use crate::credential_type::CredentialType;
use crate::crypto;
use crate::storage;
// storage_platform is a submodule re-exported via `pub use storage::*`
// on storage. Call its functions through `storage::...` directly.
use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::{decode_vault_key, emit, emit_error};

/// best-effort audit：失败不回滚 vault 写，只记 warning + 返回 false
fn try_log_audit(key: &[u8; 32], op: AuditOperation, alias: Option<&str>, success: bool) -> bool {
    match audit::log_audit_event_from_vault_key(key, op, alias, success) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("[_internal audit WARN] {} {:?}: {}", op.as_str(), alias, e);
            false
        }
    }
}

/// Hook coverage v1 §H2 / §2.3: report rc-wire status to the Web envelope.
///
/// Phase Y (2026-05-07): Layer 1 (hook file render) is now done by the
/// lifecycle funnel tail, NOT by this function. Callers that already
/// have a `LifecycleOutcome` (i.e., all mutating handlers after the
/// 2026-05-07 batch_import fix) MUST use `merge_hook_status_from_outcome`
/// to avoid double-rendering Layer 1.
///
/// This function (no-outcome variant) is retained for two scenarios:
///   1. handlers that don't run lifecycle (read-only / metadata)
///   2. fallback when lifecycle was skipped (no binding changes touched)
///
/// Independently of Layer 1, `hook_rc_wired` is always read from disk
/// here — it's a passive grep of `~/.zshrc`/`~/.bashrc`, not a write.
fn hook_status_for_envelope() -> serde_json::Value {
    let (file_installed, failure_reason) = crate::commands_account::web_install_hook_file_layer1();
    let rc_wired = crate::commands_account::shell_rc_has_aikey_block();
    json!({
        "hook_file_installed": file_installed,
        "hook_rc_wired": rc_wired,
        "hook_failure_reason": failure_reason.map(|r| r.as_envelope_str()),
    })
}

/// Phase Y (2026-05-07): outcome-aware hook status. Reads `hook_file_installed`
/// + `hook_failure_reason` from the `LifecycleOutcome` (populated by the
/// funnel's tail step 4) instead of re-rendering Layer 1. `hook_rc_wired`
/// is still grep'd from disk (it's an independent passive read).
///
/// Use this from any handler that has just run lifecycle. Falls back to a
/// fresh Layer 1 render when `outcome` reports the tail didn't run
/// (e.g. no-op event with no binding touch) — guards against vault_op
/// emitting `file_installed=false` for pure passive operations.
fn hook_status_from_outcome(
    outcome: &crate::commands_account::LifecycleOutcome,
) -> serde_json::Value {
    let rc_wired = crate::commands_account::shell_rc_has_aikey_block();
    if outcome.active_env_refreshed {
        // Tail ran — outcome carries authoritative fields.
        json!({
            "hook_file_installed": outcome.hook_file_installed,
            "hook_rc_wired": rc_wired,
            "hook_failure_reason": outcome.hook_failure_reason.map(|r| r.as_envelope_str()),
        })
    } else {
        // Tail skipped (event was a no-op for bindings). Fall back to a
        // fresh Layer 1 render so the envelope still reports correct
        // file_installed state (not the default `false`).
        let (file_installed, failure_reason) =
            crate::commands_account::web_install_hook_file_layer1();
        json!({
            "hook_file_installed": file_installed,
            "hook_rc_wired": rc_wired,
            "hook_failure_reason": failure_reason.map(|r| r.as_envelope_str()),
        })
    }
}

/// Merge the hook-status fields into an existing `serde_json::Value`
/// object. Avoids each handler having to spell out the three fields.
/// Idempotent: a future caller adding more fields elsewhere won't
/// collide because we only write the three known keys.
///
/// Phase Y (2026-05-07): when caller has a `LifecycleOutcome`, prefer
/// `merge_hook_status_from_outcome` to avoid Layer 1 double-render.
fn merge_hook_status(base: serde_json::Value) -> serde_json::Value {
    let mut obj = base;
    if let serde_json::Value::Object(ref mut map) = obj {
        let hook = hook_status_for_envelope();
        if let serde_json::Value::Object(hook_map) = hook {
            for (k, v) in hook_map {
                map.insert(k, v);
            }
        }
    }
    obj
}

/// Phase Y (2026-05-07): outcome-aware merge. Same shape as
/// `merge_hook_status` but reads Layer 1 status from the funnel outcome
/// instead of re-rendering. Callers with lifecycle MUST prefer this.
fn merge_hook_status_from_outcome(
    base: serde_json::Value,
    outcome: &crate::commands_account::LifecycleOutcome,
) -> serde_json::Value {
    let mut obj = base;
    if let serde_json::Value::Object(ref mut map) = obj {
        let hook = hook_status_from_outcome(outcome);
        if let serde_json::Value::Object(hook_map) = hook {
            for (k, v) in hook_map {
                map.insert(k, v);
            }
        }
    }
    obj
}

// ========== action-specific payload types ==========

#[derive(Debug, Deserialize)]
struct AddPayload {
    alias: String,
    secret_plaintext: String,
    /// Single-protocol shorthand (backward compat with older callers).
    /// If both `provider` and `providers` are given, `providers` wins.
    #[serde(default)]
    provider: Option<String>,
    /// Multi-protocol set (aligned with batch_import + `aikey add --providers`).
    /// 2026-04-24: added so Web "Add key" no longer silently drops this field.
    #[serde(default)]
    providers: Option<Vec<String>>,
    /// Optional per-entry base URL override.
    #[serde(default)]
    base_url: Option<String>,
    /// "error" (default) | "replace"
    #[serde(default = "default_on_conflict")]
    on_conflict: String,
}

#[derive(Debug, Deserialize)]
struct BatchImportPayload {
    items: Vec<BatchImportItem>,
    /// "error" (default) | "skip" | "replace"
    #[serde(default = "default_on_conflict")]
    on_conflict: String,
    // 2026-04-23: removed `job_id` / `source_type` / `source_hash` payload
    // fields together with the `import_jobs` / `import_items` tables
    // (collapsed into v1.0.4-alpha migration). They were the only write-side
    // users of those tables, and the only read-side consumer (history page)
    // never landed. `#[serde(deny_unknown_fields)]` is intentionally NOT
    // enabled on this struct, so older callers still sending these fields
    // get them silently ignored — no protocol break.
}

#[derive(Debug, Deserialize)]
struct BatchImportItem {
    alias: String,
    secret_plaintext: String,
    /// Single-protocol shorthand (backward compat with older callers).
    /// If both `provider` and `providers` are given, `providers` wins.
    #[serde(default)]
    provider: Option<String>,
    /// v4.1 Stage 5+: Multi-protocol binding (aggregator gateways like 0011 /
    /// openrouter / yunwu often serve multiple API protocols). Stored to
    /// `entries.supported_providers` as a JSON array. `provider_code` is set to
    /// `providers[0]` for routing-default compatibility with existing `aikey use`.
    #[serde(default)]
    providers: Option<Vec<String>>,
    /// v4.1 Stage 7+: Per-entry base URL override (optional).
    /// None or empty string → leave entries.base_url NULL (use provider default).
    /// Non-empty → stored via `storage::set_entry_base_url(alias, Some(url))`.
    #[serde(default)]
    base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateSecretPayload {
    alias: String,
    new_secret_plaintext: String,
}

#[derive(Debug, Deserialize)]
struct DeletePayload {
    alias: String,
}

fn default_on_conflict() -> String {
    "error".to_string()
}

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "verify" => handle_verify(env),
        "metadata" => handle_metadata(env),
        "add" => handle_add(env),
        "batch_import" => handle_batch_import(env),
        "update_secret" => handle_update_secret(env),
        "delete" => handle_delete(env),
        "delete_target" => handle_delete_target(env),
        "record_usage" => handle_record_usage(env),
        "record_test_result" => handle_record_test_result(env),
        "test" => handle_test(env),
        "test_raw" => handle_test_raw(env),
        "use" => handle_use(env),
        "cluster_apply_snapshot" => handle_cluster_apply_snapshot(env),
        other => {
            emit_error(
                req_id,
                "I_UNKNOWN_ACTION",
                format!("unknown vault-op action: '{}'", other),
            );
        }
    }
}

// ========== cluster_apply_snapshot ==========
//
// Applies an org-wide credential snapshot (the control plane's
// POST /internal/org/{orgID}/key-delivery response) into this node's
// managed_virtual_keys_cache. Invoked by the cluster daemon (aikey-hub) as a
// subprocess: `AK_VAULT_PATH=<node vault.db> aikey _internal vault-op` with
// action=cluster_apply_snapshot and the delivery JSON on stdin.
//
// Reuses the public delivered-key core `commands_account::upsert_delivered_key`
// (internal-command-reuses-public-core), so cluster cache rows go through the
// exact same encrypt+upsert path as the account-scoped `aikey key sync`.
// owner_account_id is taken per-VK from the payload (the seat's claimer) — the
// P0-2 multi-user attribution fix; a single fallback account would mis-bill.

/// serde backstop for the cluster wire: accept explicit JSON `null` on
/// collection fields (→ empty collection).
///
/// WHY: the Go control plane serializes a nil slice/map as `null`, not
/// `[]`/`{}`. `#[serde(default)]` only covers an ABSENT field — an explicit
/// `null` still enters the Vec/HashMap deserializer and errors, and because
/// the snapshot is applied as ONE unit, a single null field sinks the ENTIRE
/// cluster apply (the node stops receiving credential updates). Hit twice on
/// the real wire: `slots: null` (bugfix 2026-07-16) and `accounts: null`
/// inside oauth_group_runtime (bugfix 2026-07-18, staging cluster outage).
/// Producers are fixed to emit `[]`, but the worker must stay robust to a
/// wire-shape variant an older / different-version control can still produce.
fn null_to_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    use serde::Deserialize;
    Ok(Option::<T>::deserialize(de)?.unwrap_or_default())
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ClusterSnapshotPayload {
    org_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    virtual_keys: Vec<ClusterVk>,
    /// FULL quota snapshot (seat + GROUP subjects, members, rules, baselines) —
    /// the same structure the cli channel ships. Preferred over the flattened
    /// per-VK `seat_quota` when present, so worker enforcers receive group
    /// quotas too (设计: update/20260612-集群worker组级配额下发-通道结构统一;
    /// gap live-confirmed in E2E case L10c: worker subjects=0 under a group
    /// rule). Kept as raw JSON values where the proxy owns the schema —
    /// the daemon only persists, mirroring QuotaSubjectSnapshot in
    /// platform_client.rs (the cli-channel twin).
    #[serde(default)]
    quota_snapshot: Option<ClusterQuotaSnapshot>,
    /// org-wide seat-keyed OAuth token bundle (alpha.5, §3.2) — the material
    /// for group-backed VKs. Absent from old controls → group VKs (if any)
    /// keep their last-known group_runtime (no clobber on partial upgrade).
    #[serde(default)]
    oauth_group_runtime: Option<ClusterGroupRuntime>,
    /// Optional node master password. When present, aikey derives the vault key
    /// itself (single source of truth for the Argon2id derivation) instead of
    /// the caller passing a pre-derived `vault_key_hex`. Used by the cluster
    /// daemon (a same-host subprocess), so the daemon never re-implements crypto.
    #[serde(default)]
    master_password: Option<String>,
    /// Org compliance config. When present + enabled, this node activates the
    /// global compliance filter by declaring a "cluster-compliance" pseudo
    /// app_record with filter_stages (the detector binary must be deployed at
    /// the conventional apps path, else the proxy 501-fails loud). The filter
    /// applies to ALL traffic, incl. team VKs (confirmed 2026-06-05).
    #[serde(default)]
    compliance: Option<ComplianceConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct ComplianceConfig {
    enabled: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    packs: Vec<String>,
}

/// The pseudo app_record slug whose filter_stages toggles cluster-wide compliance.
const COMPLIANCE_SLUG: &str = "cluster-compliance";

/// Counts from one cluster snapshot apply.
pub(crate) struct ClusterApplyResult {
    pub applied: usize,
    pub skipped: usize,
    pub staled: usize,
    /// Rows deleted because this snapshot delivered their VK under a different
    /// (protocol, provider). Reported rather than done quietly: a sweep that
    /// removes rows without saying so is indistinguishable from one that is
    /// broken, and this is the count an operator needs when a pool misbehaves.
    pub superseded: usize,
    /// None when the payload carried no compliance block; Some(enabled) after the
    /// cluster-compliance filter was set (true) / cleared (false).
    pub compliance_enabled: Option<bool>,
    /// R6: false when a compliance block was present but its DB writes failed.
    /// true when no compliance block OR the writes succeeded. The handler turns
    /// false into an error envelope so the daemon retries (never reports a filter
    /// active when the toggle write actually failed).
    pub compliance_ok: bool,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterVk {
    virtual_key_id: String,
    owner_account_id: String,
    seat_id: String,
    #[serde(default)]
    alias: String,
    key_status: String,
    virtual_key_revision: String,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default, deserialize_with = "null_to_default")]
    slots: Vec<ClusterSlot>,
    /// Per-seat quota rows (metric, period, used, limit) from the org delivery.
    /// Written to quota_rules_cache so the proxy enforces (2c). Same seat repeats
    /// across the seat's VKs — deduped by seat_id when building cache entries.
    #[serde(default, deserialize_with = "null_to_default")]
    seat_quota: Vec<ClusterSeatQuota>,
    /// Group-VK fields (alpha.5 online-agent, §3.2/§3.3). oauth_group_id marks a
    /// group-backed VK: it arrives with NO slots (its material rides the
    /// payload's `oauth_group_runtime`) and is written through the group path.
    /// token_seat_id is the seat whose member tokens this VK borrows — the
    /// PARENT seat for an agent VK (INV-A, projected by master at delivery).
    #[serde(default)]
    oauth_group_id: Option<String>,
    #[serde(default)]
    token_seat_id: Option<String>,
    /// Protocol of the group binding (group rows only; slot-less).
    #[serde(default)]
    protocol_type: Option<String>,
}

// ---- oauth_group_runtime (alpha.5, §3.2): org-wide seat-keyed OAuth tokens ----
//
// NOTE deliberately NO refresh field anywhere in these shapes (master never
// sends one; a stray field would be dropped by serde and never stored).

#[derive(Debug, Default, serde::Deserialize)]
struct ClusterGroupRuntime {
    #[serde(default, deserialize_with = "null_to_default")]
    groups: Vec<ClusterRuntimeGroup>,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterRuntimeGroup {
    oauth_group_id: String,
    #[serde(default)]
    provider_code: String,
    #[serde(default)]
    routing_config: String,
    /// null-tolerant (not just `default`): the 2026-07-18 staging outage was a
    /// group with zero deliverable OAuth accounts wiring `"accounts": null` —
    /// the plain Vec deserializer rejected it and the whole snapshot apply
    /// failed on every node.
    #[serde(default, deserialize_with = "null_to_default")]
    accounts: Vec<ClusterRuntimeAccount>,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterRuntimeAccount {
    #[serde(default)]
    account_id: String,
    credential_id: String,
    #[serde(default)]
    identity: String,
    #[serde(default)]
    protocol_type: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    external_id: String,
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    window_max_util_pct: Option<i64>,
    #[serde(default)]
    window_status: String,
    #[serde(default)]
    window_reset_at: Option<i64>,
    #[serde(default)]
    window_7d_max_util_pct: Option<i64>,
    #[serde(default)]
    window_7d_status: String,
    #[serde(default)]
    window_7d_reset_at: Option<i64>,
    /// Per-account egress proxy (§11.7, P7). Non-secret operational routing
    /// config — projected PLAINTEXT into group_runtime material (not encrypted,
    /// unlike access_token). "" when unset → proxy uses its node-level egress
    /// chain.
    #[serde(default)]
    egress_proxy_url: String,
    /// seat_id → token. The apply projects member_tokens[token_seat_id] per VK.
    /// null-tolerant like the Vec fields: a Go nil map also wires as `null`.
    #[serde(default, deserialize_with = "null_to_default")]
    member_tokens: std::collections::HashMap<String, ClusterMemberToken>,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterMemberToken {
    access_token: String,
    #[serde(default)]
    token_expires_at: i64,
}

#[derive(Debug, serde::Deserialize, Clone)]
struct ClusterSeatQuota {
    metric: String,
    period: String,
    #[serde(default)]
    used: f64,
    #[serde(default)]
    limit: f64,
}

/// org delivery's `quota_snapshot` — mirrors control's quota.RulesSnapshot /
/// the cli channel's QuotaSnapshot. rules/baselines stay raw JSON (proxy owns
/// that schema; the daemon only persists).
#[derive(Debug, serde::Deserialize)]
struct ClusterQuotaSnapshot {
    #[serde(default, deserialize_with = "null_to_default")]
    subjects: Vec<ClusterQuotaSubject>,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterQuotaSubject {
    subject_id: String,
    subject_kind: String,
    #[serde(default, deserialize_with = "null_to_default")]
    members: Vec<String>,
    #[serde(default)]
    rules: serde_json::Value,
    #[serde(default)]
    baselines: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterSlot {
    protocol_type: String,
    #[serde(default, deserialize_with = "null_to_default")]
    targets: Vec<ClusterTarget>,
    /// Route-group template provenance (task 1.3). `serde(default)` so a NEWER
    /// daemon keeps working against an OLDER control plane that omits them.
    #[serde(default)]
    route_group_id: String,
    #[serde(default)]
    group_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct ClusterTarget {
    /// The control plane's id for this hop. The org-delivery wire has always
    /// carried it; the daemon dropped it, so cooldown, stickiness and the
    /// fallback event all keyed on an empty string. `serde(default)` keeps a new
    /// daemon working against an older control plane that omits it.
    #[serde(default)]
    binding_id: String,
    provider_code: String,
    base_url: String,
    real_key: String,
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    credential_revision: String,
    /// Primary/fallback position (task 1.3). The org-delivery endpoint has always
    /// emitted these; the daemon simply never read them, which is why Cluster
    /// could not honour a configured chain either.
    ///
    /// Defaults reproduce pre-upgrade behavior: priority 1, role "primary".
    #[serde(default = "cluster_default_priority")]
    priority: i64,
    #[serde(default = "cluster_default_fallback_role")]
    fallback_role: String,
}

fn cluster_default_priority() -> i64 {
    1
}

fn cluster_default_fallback_role() -> String {
    "primary".to_string()
}

fn handle_cluster_apply_snapshot(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: ClusterSnapshotPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("cluster_apply_snapshot payload invalid: {}", e),
            );
            return;
        }
    };

    // Resolve the vault key (master_password → aikey derives, else vault_key_hex),
    // strict-verified against password_hash before any encrypt write (2026-05-11
    // incident guard). Operates on the AK_VAULT_PATH node vault.db.
    let key = match resolve_cluster_vault_key(&env, &payload) {
        Ok(k) => k,
        Err((code, msg)) => {
            emit_error(req_id, code, msg);
            return;
        }
    };

    let r = apply_cluster_snapshot(&key, &payload);

    // R6: compliance toggle write failed → error (not a faked success) so the
    // daemon retries instead of believing the filter is active.
    if !r.compliance_ok {
        emit_error(
            req_id,
            "CLUSTER_COMPLIANCE_WRITE_FAILED",
            "compliance filter toggle write failed (see node stderr)",
        );
        return;
    }
    // R7: a non-empty snapshot that applied ZERO keys is a real failure, not a
    // success with applied:0 (HTTP-200-≠-wrote anti-pattern). Surface it so the
    // daemon retries/alarms rather than treating the empty cache as healthy.
    if !payload.virtual_keys.is_empty() && r.applied == 0 {
        emit_error(
            req_id,
            "CLUSTER_APPLY_ALL_FAILED",
            format!(
                "all {} virtual keys failed to apply (skipped={})",
                payload.virtual_keys.len(),
                r.skipped
            ),
        );
        return;
    }

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "org_id": payload.org_id,
            "applied": r.applied,
            "skipped": r.skipped,
            "staled": r.staled,
            "superseded": r.superseded,
            "compliance_enabled": r.compliance_enabled,
        }),
    ));
}

/// Resolves the 32-byte vault key for a cluster apply. Prefers
/// payload.master_password — aikey derives via its own crypto::derive_key_with_params
/// so the Argon2id derivation has a single source of truth and the daemon needs no
/// crypto. Falls back to the envelope's pre-derived vault_key_hex (Go-bridge style).
/// Strict-verified against password_hash before return (2026-05-11 incident guard).
pub(crate) fn resolve_cluster_vault_key(
    env: &StdinEnvelope,
    payload: &ClusterSnapshotPayload,
) -> Result<[u8; 32], (&'static str, String)> {
    storage::ensure_vault_exists().map_err(|e| ("I_VAULT_NOT_INITIALIZED", format!("{}", e)))?;

    let key: [u8; 32] = match payload.master_password.as_deref().filter(|s| !s.is_empty()) {
        Some(pw) => {
            let salt = storage::get_salt().map_err(|e| ("I_VAULT_NOT_INITIALIZED", e))?;
            let (m, t, p) = storage::get_kdf_params().map_err(|e| ("I_INTERNAL", e))?;
            let derived = crate::crypto::derive_key_with_params(
                &secrecy::SecretString::new(pw.to_string()),
                &salt,
                m,
                t,
                p,
            )
            .map_err(|e| ("I_INTERNAL", e))?;
            let mut k = [0u8; 32];
            k.copy_from_slice(derived.as_slice());
            k
        }
        None => decode_vault_key(&env.vault_key_hex)?,
    };

    storage::verify_vault_key(&key).map_err(|e| ("I_VAULT_KEY_INVALID", e))?;
    Ok(key)
}

/// Applies one GROUP-backed VK (alpha.5, §3.3): upserts the structural cache row
/// (oauth_group_id / routing_config / group_accounts — same columns the member
/// rail's structural sync writes) and then writes `group_runtime` — the
/// map[account_id]material JSON the proxy reader (vkeys.GroupRuntimeAccount)
/// already parses on the member rail, so the proxy hot path needs ZERO changes.
///
/// INV-A is enforced HERE: each account's secret is the token of
/// `member_tokens[vk.token_seat_id]` — master set token_seat_id to the PARENT
/// seat for agent VKs. A seat with no usable token becomes a needs_login row
/// (proxy answers LOGIN_REQUIRED for that account, distinct from absent).
///
/// At-rest format contract: AES-256-GCM with the vault derived key, 12-byte
/// nonce, nonce/ciphertext base64(std) in secret_nonce/secret_ciphertext —
/// byte-compatible with the proxy writer supervisor.buildGroupRuntimeJSON.
/// PURE projection of one group's bundle into (group_accounts refs,
/// group_runtime material map) for ONE borrowing seat (token_seat). Split out
/// of apply_group_vk so the INV-A projection + at-rest format are unit-testable
/// without a vault. See apply_group_vk's doc for the format contract.
fn build_group_runtime_material(
    key: &[u8; 32],
    g: &ClusterRuntimeGroup,
    token_seat: &str,
) -> Result<
    (
        Vec<serde_json::Value>,
        serde_json::Map<String, serde_json::Value>,
    ),
    String,
> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut refs: Vec<serde_json::Value> = Vec::new();
    let mut material = serde_json::Map::new();
    for a in g.accounts.iter().filter(|a| a.enabled) {
        refs.push(serde_json::json!({
            "account_id": a.account_id,
            "identity": a.identity,
            "provider_code": g.provider_code,
            "protocol_type": a.protocol_type,
            "base_url": a.base_url,
            "priority": a.priority,
            "assigned": false,
            "credential_id": a.credential_id,
        }));
        let mut m = serde_json::Map::new();
        m.insert("credential_type".into(), "oauth_account".into());
        if !a.identity.is_empty() {
            m.insert("identity".into(), a.identity.clone().into());
        }
        if !g.provider_code.is_empty() {
            m.insert("provider_code".into(), g.provider_code.clone().into());
        }
        if !a.protocol_type.is_empty() {
            m.insert("protocol_type".into(), a.protocol_type.clone().into());
        }
        if !a.base_url.is_empty() {
            m.insert("base_url".into(), a.base_url.clone().into());
        }
        m.insert("priority".into(), a.priority.into());
        // Per-account egress proxy (§11.7, P7): account-level routing config,
        // written PLAINTEXT (non-secret) and OUTSIDE the token match — it
        // applies to the account regardless of whether the borrowed seat has a
        // usable token. "" → omitted, so the proxy falls back to its node-level
        // egress chain (byte-unchanged material for accounts with no override).
        if !a.egress_proxy_url.is_empty() {
            m.insert("egress_proxy_url".into(), a.egress_proxy_url.clone().into());
        }
        match a.member_tokens.get(token_seat) {
            Some(tok) if !tok.access_token.is_empty() => {
                let (nonce, ct) = crate::crypto::encrypt(key, tok.access_token.as_bytes())?;
                m.insert("secret_nonce".into(), b64.encode(nonce).into());
                m.insert("secret_ciphertext".into(), b64.encode(ct).into());
                if tok.token_expires_at > 0 {
                    m.insert("expires_at".into(), tok.token_expires_at.into());
                }
                if !a.external_id.is_empty() {
                    m.insert("external_id".into(), a.external_id.clone().into());
                }
                if let Some(w) = a.window_max_util_pct {
                    m.insert("window_max_util_pct".into(), w.into());
                }
                if !a.window_status.is_empty() {
                    m.insert("window_status".into(), a.window_status.clone().into());
                }
                if let Some(w) = a.window_reset_at {
                    m.insert("window_reset_at".into(), w.into());
                }
                if let Some(w) = a.window_7d_max_util_pct {
                    m.insert("window_7d_max_util_pct".into(), w.into());
                }
                if !a.window_7d_status.is_empty() {
                    m.insert("window_7d_status".into(), a.window_7d_status.clone().into());
                }
                if let Some(w) = a.window_7d_reset_at {
                    m.insert("window_7d_reset_at".into(), w.into());
                }
            }
            _ => {
                // No usable token for the borrowed seat → explicit needs_login
                // marker (P1 semantics): the proxy returns LOGIN_REQUIRED for
                // THIS account, and the member (the agent's parent) is the one
                // who must log in.
                m.insert("needs_login".into(), true.into());
            }
        }
        material.insert(a.account_id.clone(), serde_json::Value::Object(m));
    }
    Ok((refs, material))
}

fn apply_group_vk(
    key: &[u8; 32],
    payload: &ClusterSnapshotPayload,
    vk: &ClusterVk,
    gid: &str,
) -> Result<String, String> {
    let bundle = payload
        .oauth_group_runtime
        .as_ref()
        .and_then(|rt| rt.groups.iter().find(|g| g.oauth_group_id == gid));
    let token_seat = vk.token_seat_id.as_deref().unwrap_or(&vk.seat_id);

    let (provider_code, routing_config) = bundle
        .map(|g| (g.provider_code.clone(), g.routing_config.clone()))
        .unwrap_or_default();
    let entry_provider_code = provider_code.clone();

    // group_accounts refs (ranking candidates) + group_runtime material map.
    let (refs, material) = match bundle {
        Some(g) => build_group_runtime_material(key, g, token_seat)?,
        None => (Vec::new(), serde_json::Map::new()),
    };

    let entry = storage::VirtualKeyCacheEntry {
        // Group VKs are mutually exclusive with route groups (I37), so there is no
        // chain hop to identify — the account axis owns their failover. Empty is
        // the honest value, not a placeholder.
        binding_id: String::new(),
        virtual_key_id: vk.virtual_key_id.clone(),
        org_id: payload.org_id.clone(),
        seat_id: vk.seat_id.clone(),
        alias: vk.alias.clone(),
        provider_code: provider_code.clone(),
        // 🔴 This is the OAUTH-GROUP path. Group VKs are mutually exclusive with
        // route groups (I37): their candidates are pool accounts, and the account
        // axis already has its own failover. So the chain columns stay at their
        // pre-upgrade defaults here — a route group on a group VK would be a group
        // nothing ever reads, which is "configured but not in effect" all over again.
        priority: 1,
        fallback_role: "primary".to_string(),
        route_group_id: String::new(),
        route_group_name: String::new(),
        protocol_type: vk.protocol_type.clone().unwrap_or_default(),
        base_url: String::new(), // group routing resolves per-account upstream, not via a static base_url
        credential_id: String::new(),
        credential_revision: String::new(),
        virtual_key_revision: vk.virtual_key_revision.clone(),
        key_status: vk.key_status.clone(),
        share_status: "claimed".to_string(),
        local_state: "synced_inactive".to_string(),
        expires_at: vk.expires_at,
        provider_key_nonce: None, // no static key material on a group VK
        provider_key_ciphertext: None,
        synced_at: 0,
        local_alias: None,
        supported_providers: if provider_code.is_empty() {
            Vec::new()
        } else {
            vec![provider_code]
        },
        provider_base_urls: std::collections::HashMap::new(),
        owner_account_id: Some(vk.owner_account_id.clone()),
        owner_email: None,
        group_runtime: None, // written below via the dedicated setter (upsert fences it)
        extra: None,
        oauth_group_id: Some(gid.to_string()),
        group_accounts: Some(serde_json::to_string(&refs).unwrap_or_else(|_| "[]".to_string())),
        routing_config: if routing_config.is_empty() {
            Some("{}".to_string())
        } else {
            Some(routing_config)
        },
        group_alias: None,
    };
    storage::upsert_virtual_key_cache(&entry)?;

    // Material write is separate on purpose: the structural upsert fences
    // group_runtime out of DO UPDATE SET (member-rail proxy ownership); on a
    // worker node THIS apply is the sole writer. When the bundle is absent
    // (old control), skip — keep the last-known material instead of clobbering.
    if bundle.is_some() {
        storage::set_group_runtime_for_vk(
            &vk.virtual_key_id,
            &serde_json::Value::Object(material).to_string(),
        )?;
    }
    // The provider_code this row was written under. The caller records it so the
    // binding-grain sweep can tell "the pool moved to a new provider_code" from
    // "the pool is gone" — the row's own identity under the P1e cache key.
    Ok(entry_provider_code)
}

/// Core of cluster_apply_snapshot: encrypt + upsert each VK (owner taken per-VK
/// from the payload) into managed_virtual_keys_cache, then mark any cached VK not
/// in the snapshot stale. Pure of stdin/stdout so it's unit-testable. The caller
/// MUST have already verified `key` (handle does so via resolve_cluster_vault_key).
pub(crate) fn apply_cluster_snapshot(
    key: &[u8; 32],
    payload: &ClusterSnapshotPayload,
) -> ClusterApplyResult {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    // Binding grain, matching the cache's own key. The VK-grain `seen` above
    // cannot see a row whose provider_code changed under a VK that is still
    // delivered — which is exactly what took every OAuth pool offline.
    let mut seen_bindings: HashSet<String> = HashSet::new();
    let binding_key = |vk: &str, proto: &str, prov: &str| format!("{vk}\u{1f}{proto}\u{1f}{prov}");
    let mut applied = 0usize;
    let mut skipped = 0usize;

    for vk in &payload.virtual_keys {
        // Group-backed VK (alpha.5): slot-less by design — its material rides
        // oauth_group_runtime, joined here via token_seat_id (§3.3 projection).
        if let Some(gid) = vk.oauth_group_id.as_deref().filter(|s| !s.is_empty()) {
            match apply_group_vk(key, payload, vk, gid) {
                Ok(written_provider) => {
                    applied += 1;
                    seen.insert(vk.virtual_key_id.clone());
                    seen_bindings.insert(binding_key(
                        &vk.virtual_key_id,
                        vk.protocol_type.as_deref().unwrap_or_default(),
                        &written_provider,
                    ));
                }
                Err(e) => {
                    eprintln!(
                        "[_internal cluster_apply WARN] group vk {}: {}",
                        vk.virtual_key_id, e
                    );
                    skipped += 1;
                }
            }
            continue;
        }
        // 🔴 EVERY hop of the chain has to land in the vault, not just the first.
        //
        // This used to take `slots[0].targets[0]` and call it "the primary
        // binding" — correct while a (key, protocol) had exactly one upstream,
        // and silently wrong the moment P0a made it a chain. The org-delivery
        // wire carries all the hops (task 1.3) and the cache is keyed by
        // (virtual_key_id, protocol_type, provider_code), so nothing below this
        // line was ever the limitation: the writer simply dropped hops 2..n on
        // the floor.
        //
        // How it presents, which is why it took a cluster to find: the control
        // plane is right, the console shows the chain, the delivery payload
        // contains both hops — and the runtime answers
        // UPSTREAM_FALLBACK_UNCONFIGURED, "this key has only one upstream
        // configured … ask your administrator to add a fallback upstream". The
        // administrator has already added it. The error blames the one person
        // who did their part, and every place they would look to check is
        // correct. 🚫 That is why this must never degrade to writing fewer hops
        // than were delivered.
        if !vk.slots.iter().any(|s| !s.targets.is_empty()) {
            skipped += 1;
            continue;
        }

        // supported_providers + provider_base_urls across all slot targets
        // (order-preserving dedup), mirroring the account sync's derivation.
        let mut supported_providers: Vec<String> = Vec::new();
        let mut provider_base_urls: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for s in &vk.slots {
            for t in &s.targets {
                if t.provider_code.is_empty() {
                    continue;
                }
                if !supported_providers.contains(&t.provider_code) {
                    supported_providers.push(t.provider_code.clone());
                }
                provider_base_urls.insert(t.provider_code.clone(), t.base_url.clone());
            }
        }

        // One cache row per hop. 🔴 A partial write is reported as a failure for
        // the whole key rather than counted as applied: a chain missing its
        // fallback is the exact silent degradation this loop exists to prevent,
        // and "applied" is what the operator reads to decide the sync is healthy.
        let mut wrote = 0usize;
        let mut hop_err: Option<String> = None;
        for slot in &vk.slots {
            for target in &slot.targets {
                let dk = crate::commands_account::DeliveredKey {
                    virtual_key_id: vk.virtual_key_id.clone(),
                    org_id: payload.org_id.clone(),
                    seat_id: vk.seat_id.clone(),
                    alias: vk.alias.clone(),
                    provider_code: target.provider_code.clone(),
                    // Task 1.3 — Cluster reads the chain from the org-delivery wire.
                    priority: target.priority,
                    fallback_role: target.fallback_role.clone(),
                    binding_id: target.binding_id.clone(),
                    route_group_id: slot.route_group_id.clone(),
                    route_group_name: slot.group_name.clone(),
                    protocol_type: slot.protocol_type.clone(),
                    base_url: target.base_url.clone(),
                    credential_id: target.credential_id.clone(),
                    credential_revision: target.credential_revision.clone(),
                    virtual_key_revision: vk.virtual_key_revision.clone(),
                    key_status: vk.key_status.clone(),
                    // Org-delivered keys are inherently claimed (they belong to a seat).
                    share_status: "claimed".to_string(),
                    // synced_inactive: valid + synced, not a local "active" selection
                    // (cluster has no `aikey use`). The cluster proxy serves managed keys
                    // by VK token, not by local_state (Phase 4).
                    local_state: "synced_inactive".to_string(),
                    expires_at: vk.expires_at,
                    local_alias: None,
                    supported_providers: supported_providers.clone(),
                    provider_base_urls: provider_base_urls.clone(),
                    owner_account_id: Some(vk.owner_account_id.clone()),
                };
                match crate::commands_account::upsert_delivered_key(key, &dk, &target.real_key) {
                    Ok(_) => {
                        wrote += 1;
                        seen_bindings.insert(binding_key(
                            &vk.virtual_key_id,
                            &slot.protocol_type,
                            &target.provider_code,
                        ));
                    }
                    Err(e) => {
                        if hop_err.is_none() {
                            hop_err = Some(format!(
                                "{} hop {}/{}: {}",
                                slot.protocol_type, target.provider_code, target.priority, e
                            ));
                        }
                    }
                }
            }
        }

        match hop_err {
            None if wrote > 0 => {
                applied += 1;
                seen.insert(vk.virtual_key_id.clone());
            }
            e => {
                eprintln!(
                    "[_internal cluster_apply WARN] vk {}: wrote {} hop(s){}",
                    vk.virtual_key_id,
                    wrote,
                    e.map(|m| format!("; {}", m)).unwrap_or_default()
                );
                skipped += 1;
            }
        }
    }

    // Any cached VK belonging to THIS org but absent from this snapshot is
    // revoked/removed upstream → mark stale so the proxy stops it. R2 fix: scope
    // the sweep to payload.org_id (mirrors the account path's owner guard at
    // commands_account/mod.rs). Even though a node vault is meant to be
    // single-org, an unscoped sweep would clobber another org's / a co-resident
    // personal-sync's routes if that invariant is ever violated — defensive +
    // matches the established pattern. R4-style: a cache read error is now a WARN
    // (was a silent skip that could leave revoked keys serving).
    //
    // 🔴 The sweep above is VK-GRAIN, and that is not enough (2026-08-03). The
    // cache is keyed `(virtual_key_id, protocol_type, provider_code)` since P1e,
    // so when a delivered VK's provider_code CHANGES — an OAuth pool projects an
    // empty one until its provider resolves, then the real one — the new row is
    // INSERTED beside the old rather than replacing it. The VK is still in the
    // snapshot, so `seen` contains it and nothing here ever looked again. Both
    // staging workers accumulated one such pair per pool, and the proxy read them
    // as two chain entries at the defaulted priority 1: 409
    // PROVIDER_ROUTE_AMBIGUOUS on every OAuth pool call.
    //
    // So a row under a VK this snapshot DID deliver, at a (protocol, provider)
    // the snapshot did NOT deliver, is superseded and is DELETED — the row is not
    // "a key that went away" (which is what stale means and what the proxy can
    // still serve), it is a duplicate identity of a key that is right here.
    //
    // 🚫 Deliberately not applied to a VK missing from the snapshot entirely.
    // That stays mark-stale, unchanged: it is the revoked/removed case, and
    // deleting it here would discard local material the account path is
    // responsible for.
    let mut staled = 0usize;
    let mut superseded = 0usize;
    match storage::list_virtual_key_cache() {
        Ok(cached) => {
            for entry in cached {
                if entry.org_id != payload.org_id {
                    continue; // not this org — never touch it
                }
                if !seen.contains(&entry.virtual_key_id) {
                    if entry.local_state != "stale" {
                        let _ =
                            storage::set_virtual_key_local_state(&entry.virtual_key_id, "stale");
                        staled += 1;
                    }
                    continue;
                }
                if !seen_bindings.contains(&binding_key(
                    &entry.virtual_key_id,
                    &entry.protocol_type,
                    &entry.provider_code,
                )) {
                    match storage::delete_virtual_key_cache_binding(
                        &entry.virtual_key_id,
                        &entry.protocol_type,
                        &entry.provider_code,
                    ) {
                        Ok(()) => superseded += 1,
                        Err(e) => eprintln!(
                            "[_internal cluster_apply WARN] superseded binding {} ({}/{}) not removed ({}); \
                             it will keep appearing as an extra chain entry",
                            entry.virtual_key_id, entry.provider_code, entry.protocol_type, e
                        ),
                    }
                }
            }
            if superseded > 0 {
                eprintln!(
                    "[_internal cluster_apply] removed {} superseded binding row(s)",
                    superseded
                );
            }
        }
        Err(e) => {
            eprintln!(
                "[_internal cluster_apply WARN] list cache for stale-sweep failed (revoked keys may keep serving): {}",
                e
            );
        }
    }

    // Compliance enablement (P6): toggle the cluster-wide compliance filter to
    // match the org config. We declare a "cluster-compliance" pseudo app_record
    // and set/clear its filter_stages — the proxy's filter hook activates on ANY
    // app_record with non-null filter_stages and applies to ALL traffic (incl.
    // team VKs, confirmed 2026-06-05). The detector binary must be deployed at
    // <apps_dir>/cluster-compliance/bin/cluster-compliance (Phase 8 / hub-install),
    // else the proxy 501-fails loud — so enabling here without the binary is a
    // deploy error, surfaced loudly rather than silently serving unfiltered.
    // Reuses the public app cores (internal-command-reuses-public-core).
    // R6 fix: track whether the compliance writes actually succeeded. Previously
    // upsert/set/clear errors were eprintln-and-continue, yet we still reported
    // compliance_enabled=Some(true) — claiming success on a failed write
    // ("失败要显眼" violation). Now compliance_ok=false propagates to the result;
    // the handler turns it into an error envelope so the daemon retries instead
    // of believing the filter is active.
    let mut compliance_ok = true;
    let compliance_enabled = match &payload.compliance {
        None => None,
        Some(cfg) => {
            // Ensure the pseudo-app row exists (set_/clear_ filter_stages are UPDATEs).
            if let Err(e) = crate::commands_app::upsert_app_record(
                COMPLIANCE_SLUG,
                "Cluster Compliance",
                "aikey",
                &[],
                "third-party", // app_kind CHECK allows only 'third-party'|'first-party'
                false,
                &[],
            ) {
                eprintln!(
                    "[_internal cluster_apply WARN] compliance app_record upsert: {}",
                    e
                );
                compliance_ok = false;
            }
            let res = if cfg.enabled {
                crate::commands_app::set_app_filter_stages(
                    COMPLIANCE_SLUG,
                    &["pre_forward".to_string()],
                    None,
                    None,
                )
            } else {
                crate::commands_app::clear_app_filter_stages(COMPLIANCE_SLUG)
            };
            if let Err(e) = res {
                eprintln!(
                    "[_internal cluster_apply WARN] compliance filter set/clear: {}",
                    e
                );
                compliance_ok = false;
            }
            // packs are the detector's rule config; their distribution to the
            // detector is handled separately (compliance pack distribution) — we
            // only log how many the org has so the activation is auditable here.
            eprintln!(
                "[_internal cluster_apply] compliance enabled={} packs={} write_ok={}",
                cfg.enabled,
                cfg.packs.len(),
                compliance_ok
            );
            Some(cfg.enabled)
        }
    };

    // Quota (2c): write the delivered quota into quota_rules_cache so the
    // proxy enforces `used >= limit` (enforce.go hard block).
    //
    // PREFERRED path (2026-06-12, 通道结构统一): `quota_snapshot` carries the
    // FULL subject set (seat + GROUP, members, rules, baselines) — persist it
    // VERBATIM via full-replace; the proxy's group enforcement (seat→group
    // reverse index) needs exactly this. The authoritative-full-set semantics
    // match the cli channel: an empty subjects list still full-replaces, so
    // deleting the last rule propagates as a cleared cache.
    if let Some(snap) = &payload.quota_snapshot {
        let entries: Vec<storage::QuotaRuleCacheEntry> = snap
            .subjects
            .iter()
            .map(|sub| storage::QuotaRuleCacheEntry {
                subject_id: sub.subject_id.clone(),
                subject_kind: sub.subject_kind.clone(),
                members_json: if sub.members.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&sub.members).unwrap_or_else(|_| "[]".to_string()))
                },
                rules_json: sub.rules.to_string(),
                baseline_json: if sub.baselines.is_null() {
                    None
                } else {
                    Some(sub.baselines.to_string())
                },
            })
            .collect();
        let n = entries.len();
        if let Err(e) = storage::replace_quota_rules_cache(&entries) {
            eprintln!("[_internal cluster_apply WARN] quota cache write: {}", e);
        } else {
            eprintln!(
                "[_internal cluster_apply] quota: {} subject(s) cached (full snapshot)",
                n
            );
        }
    } else
    // FALLBACK (old control without quota_snapshot): the flattened per-seat
    // view. seat-only — group quotas are NOT carried on this leg (the very
    // gap the snapshot path closes); thresholds aren't delivered so rules get
    // empty thresholds[] — the hard block on limit_amount still fires.
    // Full-replace, deduped by seat; empty delivery clears the cache.
    {
        use std::collections::HashMap;
        let mut by_seat: HashMap<&str, &Vec<ClusterSeatQuota>> = HashMap::new();
        for vk in &payload.virtual_keys {
            if !vk.seat_quota.is_empty() {
                by_seat.entry(vk.seat_id.as_str()).or_insert(&vk.seat_quota);
            }
        }
        let entries: Vec<storage::QuotaRuleCacheEntry> = by_seat
            .iter()
            .map(|(seat_id, items)| {
                let rules: Vec<serde_json::Value> = items
                    .iter()
                    .map(|q| {
                        json!({"metric": q.metric, "period": q.period, "limit_amount": q.limit, "thresholds": []})
                    })
                    .collect();
                let baselines: Vec<serde_json::Value> = items
                    .iter()
                    .map(|q| json!({"metric": q.metric, "period": q.period, "used": q.used}))
                    .collect();
                storage::QuotaRuleCacheEntry {
                    subject_id: seat_id.to_string(),
                    subject_kind: "seat".to_string(),
                    members_json: None,
                    rules_json: serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string()),
                    baseline_json: Some(
                        serde_json::to_string(&baselines).unwrap_or_else(|_| "[]".to_string()),
                    ),
                }
            })
            .collect();
        let n = entries.len();
        if let Err(e) = storage::replace_quota_rules_cache(&entries) {
            eprintln!("[_internal cluster_apply WARN] quota cache write: {}", e);
        } else if n > 0 {
            eprintln!("[_internal cluster_apply] quota: {} seat(s) cached", n);
        }
    }

    let _ = storage::bump_vault_change_seq();

    ClusterApplyResult {
        applied,
        skipped,
        staled,
        superseded,
        compliance_enabled,
        compliance_ok,
    }
}

// ========== helpers ==========

/// 解码 vault_key_hex + 校验 vault 存在 + 打开连接。任何失败直接 emit error 并返回 None。
fn prepare_vault(env: &StdinEnvelope) -> Option<([u8; 32], rusqlite::Connection)> {
    let req_id = env.request_id.clone();

    let key = match decode_vault_key(&env.vault_key_hex) {
        Ok(k) => k,
        Err((code, msg)) => {
            emit_error(req_id, code, msg);
            return None;
        }
    };

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id.clone(), "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return None;
    }

    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => {
            emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e));
            return None;
        }
    };

    // 在所有 mutating ops 之前校验 key（用 password_hash 或空 vault 兜底）
    if let Err((code, msg)) = verify_key_against_vault(&conn, &key) {
        emit_error(env.request_id.clone(), code, msg);
        return None;
    }

    Some((key, conn))
}

/// 校验 vault_key 与 config.password_hash 一致。
///
/// 2026-05-11 重构：从前这里有一份与 `executor::verify_password_internal`
/// 平行的实现，并附带一条「无 password_hash + 空 vault 兜底 Ok(())」的
/// 静默接受分支。该分支正是 2026-05-11 team-key 解密不一致事件的成因，
/// 已在 `storage::verify_vault_key` 中收紧为严格匹配，此处委托过去以保持
/// 单一真相源；返回值再包成本模块的 `I_VAULT_KEY_INVALID` 错误码。
///
/// `_conn` 参数保留供日后扩展，但目前 storage::verify_vault_key 内部自己
/// 打开连接以保证它对 password_hash 的读取与最终写入路径同源（避免事务
/// 视图差异）。
fn verify_key_against_vault(
    _conn: &rusqlite::Connection,
    key: &[u8; 32],
) -> Result<(), (&'static str, String)> {
    storage::verify_vault_key(key).map_err(|msg| ("I_VAULT_KEY_INVALID", msg))
}

/// 把 plaintext 加密为 (nonce, ciphertext)
fn encrypt_with_key(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), (&'static str, String)> {
    crypto::encrypt(key, plaintext).map_err(|e| ("I_INTERNAL", format!("encrypt failed: {}", e)))
}

/// 检查 alias 是否已存在
fn alias_exists(conn: &rusqlite::Connection, alias: &str) -> Result<bool, (&'static str, String)> {
    conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE alias = ?",
        [alias],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(|e| ("I_INTERNAL", format!("check alias failed: {}", e)))
}

// ========== verify ==========

fn handle_verify(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let (_key, _conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return, // emit_error 已在 prepare_vault 内发出
    };
    emit(&ResultEnvelope::ok(
        req_id,
        json!({"verified": true, "method": "password_hash"}),
    ));
}

// ========== metadata ==========
//
// Pre-unlock metadata query used by Go local-server: returns the vault's KDF
// salt + Argon2id parameters so the caller can derive `vault_key_hex` locally
// before invoking `verify`. No secret is exposed; only rekey-inert public
// params. Follows the same "format-check only" pattern as `parse`: the stdin
// `vault_key_hex` field is required by protocol but not matched against the
// vault (the caller doesn't have it yet).
//
// Why a separate action (not an unlock-that-takes-password): keeps the
// password off stdin, so the only place the password lives is the Go
// process handling the unlock HTTP request, and only for the Argon2id call.
// Envelope contract stays action-agnostic (all actions still carry
// vault_key_hex).
fn handle_metadata(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    // Format-validate only (placeholder 64-char hex is fine; real hex also fine).
    if let Err((code, msg)) = decode_vault_key(&env.vault_key_hex) {
        emit_error(req_id, code, msg);
        return;
    }

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }
    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => {
            emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e));
            return;
        }
    };

    // Salt: canonical key is `master_salt`; fall back to legacy `salt`.
    let salt: Vec<u8> = match conn.query_row(
        "SELECT value FROM config WHERE key = 'master_salt'",
        [],
        |r| r.get(0),
    ) {
        Ok(v) => v,
        Err(_) => match conn.query_row("SELECT value FROM config WHERE key = 'salt'", [], |r| {
            r.get(0)
        }) {
            Ok(v) => v,
            Err(e) => {
                emit_error(
                    req_id,
                    "I_VAULT_NOT_INITIALIZED",
                    format!("vault missing master_salt: {}", e),
                );
                return;
            }
        },
    };

    // KDF params: stored as 4-byte LE uint32, default to Argon2id params if absent.
    let read_u32 = |k: &str, default: u32| -> u32 {
        conn.query_row("SELECT value FROM config WHERE key = ?", [k], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .ok()
        .filter(|v| v.len() == 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .unwrap_or(default)
    };
    let m_cost = read_u32("kdf_m_cost", 65536);
    let t_cost = read_u32("kdf_t_cost", 3);
    let p_cost = read_u32("kdf_p_cost", 4);
    let key_len = 32u32;

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "salt_hex": hex::encode(&salt),
            "kdf": {
                "algorithm": "argon2id",
                "m_cost": m_cost,
                "t_cost": t_cost,
                "p_cost": p_cost,
                "key_len": key_len,
            },
        }),
    ));
}

// ========== add ==========

fn handle_add(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: AddPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("add payload invalid: {}", e),
            );
            return;
        }
    };

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // Resolve providers: `providers` (multi, preferred) > `provider` (single, legacy)
    let providers_input: Vec<String> = payload
        .providers
        .clone()
        .or_else(|| payload.provider.clone().map(|p| vec![p]))
        .unwrap_or_default();

    // Decode on_conflict string → typed enum.
    let on_conflict = match payload.on_conflict.as_str() {
        "replace" => crate::commands_account::OnConflict::Replace,
        "skip" => crate::commands_account::OnConflict::Skip,
        _ => crate::commands_account::OnConflict::Error,
    };

    // Delegate to the shared core. Handles alias validation, canonical
    // provider normalization, encryption, entries write, supported_providers
    // + provider_code + base_url metadata writes in a single place.
    let outcome = match crate::commands_account::apply_add_core_on_conn(
        &conn,
        &key,
        &payload.alias,
        payload.secret_plaintext.as_bytes(),
        &providers_input,
        payload.base_url.as_deref(),
        on_conflict,
    ) {
        Ok(o) => o,
        Err(msg) => {
            // Map a handful of well-known error strings to stable error_codes
            // so the Go layer / front-end can key off them without parsing
            // human text. Everything else falls through as I_INTERNAL.
            let code = if msg.contains("already exists") {
                "I_CREDENTIAL_CONFLICT"
            } else if msg.contains("alias")
                && (msg.contains("empty") || msg.contains("exceeds") || msg.contains("control"))
            {
                "I_STDIN_INVALID_JSON"
            } else {
                "I_INTERNAL"
            };
            emit_error(req_id, code, msg);
            return;
        }
    };

    // Route token — outside core because it opens its own connection
    // (can't live in a transaction). Single-add here isn't in a tx so it's
    // fine. Best-effort: missing route_token isn't a hard failure, the
    // entry is still usable until a later `ensure_entry_route_token` fills it.
    let _ = storage::ensure_entry_route_token(&outcome.alias);

    // Auto-assign as Primary + refresh active.env. Mirrors the CLI's
    // `Commands::Add` post-write block in main.rs:1093-1099 — without
    // these two calls, a key added via the web UI silently lacks a
    // provider binding and the proxy/shell never picks it up. (Per
    // CLAUDE.md `_internal must reuse public command core` — both
    // entry points should produce identical state.) Best-effort:
    // failures here don't roll back the entry write that already
    // succeeded; the metadata can be reconciled later by `aikey use
    // <alias>`.
    // Single funnel: Added event runs auto_assign_primaries → refresh →
    // apply_third_party_cli_configs. Bugfix history pinned by the
    // CredentialLifecycleEvent variant docs.
    let lifecycle = crate::commands_account::apply_credential_lifecycle(
        crate::commands_account::CredentialLifecycleEvent::Added {
            source_type: "personal",
            source_ref: &outcome.alias,
            providers: &outcome.providers,
        },
        crate::audit::VerifiedVaultKey::new(key).ok().as_ref(),
    )
    .unwrap_or_default();
    let newly_primary = lifecycle.newly_primary.clone();
    let active_env_refreshed = lifecycle.active_env_refreshed;

    let audit_logged = try_log_audit(&key, AuditOperation::Add, Some(&outcome.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        merge_hook_status_from_outcome(
            json!({
                "alias": outcome.alias,
                "action_taken": outcome.action.as_str(),
                "provider": outcome.primary_provider,
                "providers": outcome.providers,
                "newly_primary_providers": newly_primary,
                "active_env_refreshed": active_env_refreshed,
                "audit_logged": audit_logged,
            }),
            &lifecycle,
        ),
    ));
}

// ========== batch_import ==========

fn handle_batch_import(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: BatchImportPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("batch_import payload invalid: {}", e),
            );
            return;
        }
    };
    if payload.items.is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "items must be non-empty");
        return;
    }

    // Batch-scope dedup check (items[i].alias duplicated within this call).
    // This can't be delegated to apply_add_core — it needs the full item
    // list in scope. Per-item validation + conflict-against-DB checks ARE
    // delegated (see below). Matches v4.1 Stage 14+ BUG-01 fix.
    if payload.on_conflict == "error" {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for it in &payload.items {
            if !seen.insert(&it.alias) {
                emit_error(
                    req_id,
                    "I_CREDENTIAL_CONFLICT",
                    format!("alias '{}' is duplicated within this batch (set on_conflict=skip|replace, or dedupe client-side)", it.alias),
                );
                return;
            }
        }
    }

    let (key, mut conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // Typed on_conflict for the shared core.
    let on_conflict = match payload.on_conflict.as_str() {
        "replace" => crate::commands_account::OnConflict::Replace,
        "skip" => crate::commands_account::OnConflict::Skip,
        _ => crate::commands_account::OnConflict::Error,
    };

    // G-5 P0 review fix (2026-04-23): entire batch write set runs in a
    // single IMMEDIATE transaction. Any failure mid-batch triggers ROLLBACK
    // via Transaction::Drop — callers see either "all committed" or "none
    // committed", never half-written vault state.
    //
    // Audit log writes stay outside the transaction (best-effort, as before).
    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(t) => t,
        Err(e) => {
            emit_error(
                req_id,
                "I_INTERNAL",
                format!("begin batch transaction: {}", e),
            );
            return;
        }
    };

    let mut inserted = 0usize;
    let mut replaced = 0usize;
    let mut skipped = 0usize;
    let mut item_reports = Vec::with_capacity(payload.items.len());
    let mut per_item_audit: Vec<String> = Vec::with_capacity(payload.items.len());
    // Bugfix 2026-05-07: capture (canonical_alias, canonical_providers) per
    // Inserted/Replaced item so we can run the lifecycle funnel after the
    // entries-write tx commits. Without this, batch_import wrote vault
    // entries but never auto-promoted to primary, never refreshed
    // active.env, never synced toml regions — symptom: web import +
    // CLI `claude` ran with no env routing at all. Phase 5 lifecycle
    // refactor wired 11 callers but missed batch_import; the user
    // surfaced this on 2026-05-07.
    let mut lifecycle_inputs: Vec<(String, Vec<String>)> = Vec::with_capacity(payload.items.len());

    for it in &payload.items {
        // Resolve providers: `providers` (multi, preferred) > `provider` (single).
        let providers_input: Vec<String> = match &it.providers {
            Some(ps) if !ps.is_empty() => ps.clone(),
            _ => it.provider.clone().map(|p| vec![p]).unwrap_or_default(),
        };

        // Delegate per-item write to the shared core (same helper as single
        // `aikey add` and `_internal vault-op add`). Handles alias validation,
        // canonical provider normalization, conflict policy, encryption,
        // and all three metadata writes atomically inside this transaction.
        let outcome = match crate::commands_account::apply_add_core_on_conn(
            &tx,
            &key,
            &it.alias,
            it.secret_plaintext.as_bytes(),
            &providers_input,
            it.base_url.as_deref(),
            on_conflict,
        ) {
            Ok(o) => o,
            Err(msg) => {
                let code = if msg.contains("already exists") {
                    "I_CREDENTIAL_CONFLICT"
                } else if msg.contains("alias")
                    && (msg.contains("empty") || msg.contains("exceeds") || msg.contains("control"))
                {
                    "I_INVALID_ALIAS"
                } else {
                    "I_INTERNAL"
                };
                emit_error(req_id, code, format!("item '{}': {}", it.alias, msg));
                return; // tx drops → ROLLBACK
            }
        };

        match outcome.action {
            crate::commands_account::AddAction::Inserted => {
                inserted += 1;
                per_item_audit.push(outcome.alias.clone());
                lifecycle_inputs.push((outcome.alias.clone(), outcome.providers.clone()));
            }
            crate::commands_account::AddAction::Replaced => {
                replaced += 1;
                per_item_audit.push(outcome.alias.clone());
                // Replaced rows still need lifecycle: the secret changed,
                // primary may need to be re-pointed (esp. when this alias
                // already was primary — preserve it). Treat as Added so
                // auto_assign re-evaluates against current binding state.
                lifecycle_inputs.push((outcome.alias.clone(), outcome.providers.clone()));
            }
            crate::commands_account::AddAction::Skipped => {
                skipped += 1;
            }
        }
        item_reports.push(json!({"alias": outcome.alias, "action": outcome.action.as_str()}));
    }

    // Commit — all writes land atomically.
    if let Err(e) = tx.commit() {
        emit_error(
            req_id,
            "I_INTERNAL",
            format!("commit batch transaction: {}", e),
        );
        return;
    }

    // Route token generation (post-commit — each call opens its own
    // connection, can't live in the transaction). Best-effort per item;
    // failures log and continue (entry still usable, route_token fills
    // in on next ensure_entry_route_token call).
    for alias in &per_item_audit {
        let _ = storage::ensure_entry_route_token(alias);
    }

    // Post-commit audit fan-out (best-effort; matches single-entry add handler).
    let mut audit_failures = 0usize;
    for alias in &per_item_audit {
        if !try_log_audit(&key, AuditOperation::Import, Some(alias.as_str()), true) {
            audit_failures += 1;
        }
    }

    // Lifecycle funnel — auto_assign + refresh active.env + apply third-
    // party CLI configs. Bugfix 2026-05-07: previously omitted, leaving
    // imported keys with no binding rows, no active.env update, no toml
    // sync. Run AFTER the entries-write tx commits because the funnel
    // opens its own DB connection (and would deadlock on the held tx).
    // Failure here doesn't roll back the entries write; the binding
    // can be reconciled later by `aikey use <alias>` (matches the
    // best-effort posture of vault_op handle_add).
    let lifecycle_events: Vec<crate::commands_account::CredentialLifecycleEvent> = lifecycle_inputs
        .iter()
        .map(
            |(alias, providers)| crate::commands_account::CredentialLifecycleEvent::Added {
                source_type: "personal",
                source_ref: alias.as_str(),
                providers: providers.as_slice(),
            },
        )
        .collect();
    let lifecycle_outcomes = crate::commands_account::apply_credential_lifecycle_batch(
        &lifecycle_events,
        crate::audit::VerifiedVaultKey::new(key).ok().as_ref(),
    )
    .unwrap_or_default();
    let total_newly_primary: Vec<String> = lifecycle_outcomes
        .iter()
        .flat_map(|o| o.newly_primary.clone())
        .collect();
    // active_env_refreshed: true iff the funnel ran the tail and at least
    // one outcome reports it. The batch flavor runs the tail once after
    // all writes succeed, so all outcomes share the same value — but we
    // OR them together to be defensive against future funnel changes.
    let active_env_refreshed = lifecycle_outcomes.iter().any(|o| o.active_env_refreshed);
    // Phase Y: any outcome will do for hook fields — tail runs once, all
    // outcomes share the same hook_file_installed / hook_failure_reason.
    // Default outcome (empty events list path) reports tail-skipped,
    // which the merge_hook_status_from_outcome helper falls back to a
    // fresh Layer 1 render for.
    let representative_outcome = lifecycle_outcomes.first().cloned().unwrap_or_default();

    emit(&ResultEnvelope::ok(
        req_id,
        merge_hook_status_from_outcome(
            json!({
                "total": payload.items.len(),
                "inserted": inserted,
                "replaced": replaced,
                "skipped": skipped,
                "items": item_reports,
                "audit_logged": audit_failures == 0,
                "audit_failures": audit_failures,
                "newly_primary_providers": total_newly_primary,
                "active_env_refreshed": active_env_refreshed,
            }),
            &representative_outcome,
        ),
    ));
}

// ========== update_secret ==========

fn handle_update_secret(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: UpdateSecretPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("update_secret payload invalid: {}", e),
            );
            return;
        }
    };

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // 必须已存在（区别于 add 的 UPSERT）
    match alias_exists(&conn, &payload.alias) {
        Ok(false) => {
            emit_error(
                req_id,
                "I_CREDENTIAL_NOT_FOUND",
                format!(
                    "alias '{}' does not exist (use add to create)",
                    payload.alias
                ),
            );
            return;
        }
        Err((c, m)) => {
            emit_error(req_id, c, m);
            return;
        }
        Ok(true) => {}
    }

    let (nonce, ciphertext) = match encrypt_with_key(&key, payload.new_secret_plaintext.as_bytes())
    {
        Ok(t) => t,
        Err((c, m)) => {
            emit_error(req_id, c, m);
            return;
        }
    };
    // `prepare_vault` already verified this key; going through the verified
    // door anyway keeps the guarantee at the write site rather than in a
    // caller's memory (see storage::store_entry_verified).
    if let Err(e) = storage::store_entry_verified(&payload.alias, &key, &nonce, &ciphertext) {
        emit_error(req_id, "I_INTERNAL", format!("store_entry failed: {}", e));
        return;
    }

    let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "alias": payload.alias,
            "action_taken": "updated",
            "audit_logged": audit_logged,
        }),
    ));
}

// ========== delete ==========

fn handle_delete(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: DeletePayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("delete payload invalid: {}", e),
            );
            return;
        }
    };

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    match alias_exists(&conn, &payload.alias) {
        Ok(false) => {
            emit_error(
                req_id,
                "I_CREDENTIAL_NOT_FOUND",
                format!("alias '{}' does not exist", payload.alias),
            );
            return;
        }
        Err((c, m)) => {
            emit_error(req_id, c, m);
            return;
        }
        Ok(true) => {}
    }

    if let Err(e) = storage::delete_entry(&payload.alias) {
        emit_error(req_id, "I_INTERNAL", format!("delete_entry failed: {}", e));
        return;
    }

    // Single funnel: Removed event runs reconcile → refresh → apply.
    let _ = crate::commands_account::apply_credential_lifecycle(
        crate::commands_account::CredentialLifecycleEvent::Removed {
            source_type: "personal",
            source_ref: &payload.alias,
        },
        crate::audit::VerifiedVaultKey::new(key).ok().as_ref(),
    );

    let audit_logged = try_log_audit(&key, AuditOperation::Delete, Some(&payload.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "alias": payload.alias,
            "action_taken": "deleted",
            "audit_logged": audit_logged,
        }),
    ));
}

// ========== delete_target ==========
//
// Target-aware delete for the unified User Vault Web protocol (§2.0).
// Payload: `{ "target": "personal" | "oauth" | "team", "id": "..." }`
//
// Why a separate action (not overload `delete`): `delete` has a stable
// payload shape (`{alias: String}`) used by other callers (main.rs, import
// flow). Keeping them distinct means the unified-target contract can evolve
// without back-compat risk to existing consumers.
fn handle_delete_target(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("delete_target payload invalid: {}", e),
            );
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    match payload.target.as_str() {
        "personal" => {
            // id == alias for personal target
            match alias_exists(&conn, &payload.id) {
                Ok(false) => {
                    emit_error(
                        req_id,
                        "I_CREDENTIAL_NOT_FOUND",
                        format!("alias '{}' does not exist", payload.id),
                    );
                    return;
                }
                Err((c, m)) => {
                    emit_error(req_id, c, m);
                    return;
                }
                Ok(true) => {}
            }
            if let Err(e) = storage::delete_entry(&payload.id) {
                emit_error(req_id, "I_INTERNAL", format!("delete_entry failed: {}", e));
                return;
            }
            // Single funnel: Removed event runs reconcile → refresh → apply.
            let lifecycle = crate::commands_account::apply_credential_lifecycle(
                crate::commands_account::CredentialLifecycleEvent::Removed {
                    source_type: "personal",
                    source_ref: &payload.id,
                },
                crate::audit::VerifiedVaultKey::new(key).ok().as_ref(),
            )
            .unwrap_or_default();
            let audit_logged = try_log_audit(&key, AuditOperation::Delete, Some(&payload.id), true);
            emit(&ResultEnvelope::ok(
                req_id,
                merge_hook_status_from_outcome(
                    json!({
                        "target": "personal",
                        "id": payload.id,
                        "action_taken": "deleted",
                        "audit_logged": audit_logged,
                    }),
                    &lifecycle,
                ),
            ));
        }
        "oauth" => {
            // Existence check first so we can return a precise NOT_FOUND.
            match storage::get_provider_account(&payload.id) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    emit_error(
                        req_id,
                        "I_CREDENTIAL_NOT_FOUND",
                        format!("provider_account_id '{}' does not exist", payload.id),
                    );
                    return;
                }
                Err(e) => {
                    emit_error(req_id, "I_INTERNAL", format!("get_provider_account: {}", e));
                    return;
                }
            }
            // storage::delete_provider_account cascades provider_account_tokens.
            if let Err(e) = storage::delete_provider_account(&payload.id) {
                emit_error(
                    req_id,
                    "I_INTERNAL",
                    format!("delete_provider_account failed: {}", e),
                );
                return;
            }
            // BR-rc.5 fix (2026-05-25, Phase A.2 of vault-oauth web↔CLI
            // path parity audit): apply Removed lifecycle — was missing
            // here while the "personal" branch above (line ~936) had it.
            // Without this, deleting an OAuth account via Web vault
            // page left:
            //   - orphan rows in user_profile_provider_bindings still
            //     pointing at the now-deleted provider_account_id
            //     (`aikey use` interactive picker would surface them as
            //     "active binding to source_ref=… but provider_accounts
            //     row absent")
            //   - ~/.aikey/active.env still referencing the deleted
            //     OAuth's route_token (shell env stale → claude/codex/
            //     kimi commands would 401)
            //   - ~/.claude/settings.json / ~/.codex/config.toml /
            //     ~/.kimi/config.toml still pointing at the deleted
            //     account_id (third-party CLI configs not reconciled)
            //
            // source_type is "personal_oauth_account" (DB canonical
            // string per credential_type.rs:23). Same pattern as the
            // CLI-side `aikey auth logout` path: lifecycle reconciles
            // bindings to a replacement primary if one exists, else
            // clears the binding.
            //
            // See bugfix 20260525-vault-oauth-delete-missing-lifecycle.md
            // and the sibling bug 20260525-vault-oauth-route-token-not-
            // generated-by-web-broker.md (same web↔CLI asymmetry pattern,
            // different missing call).
            let lifecycle = crate::commands_account::apply_credential_lifecycle(
                crate::commands_account::CredentialLifecycleEvent::Removed {
                    source_type: "personal_oauth_account",
                    source_ref: &payload.id,
                },
                crate::audit::VerifiedVaultKey::new(key).ok().as_ref(),
            )
            .unwrap_or_default();
            let audit_logged = try_log_audit(&key, AuditOperation::Delete, Some(&payload.id), true);
            emit(&ResultEnvelope::ok(
                req_id,
                merge_hook_status_from_outcome(
                    json!({
                        "target": "oauth",
                        "id": payload.id,
                        "action_taken": "deleted",
                        "audit_logged": audit_logged,
                    }),
                    &lifecycle,
                ),
            ));
        }
        "team" => {
            emit_error(
                req_id,
                "I_UNKNOWN_TARGET",
                "target 'team' is reserved for future use and not implemented in v1.0",
            );
        }
        other => {
            emit_error(
                req_id,
                "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other),
            );
        }
    }
}

// ========== record_usage ==========
//
// Bumps per-key usage telemetry: `last_used_at` = caller-supplied unix
// seconds (or now() if omitted), `use_count` = use_count + 1. Intended
// to be called from aikey-proxy after a successful credential
// resolution so the User Vault Web page can show "Last used 4m ago"
// and "12,345 uses" per key.
//
// Payload: `{ "target": "personal"|"oauth", "id": "...", "ts": <i64?> }`.
// `ts` is optional — omitted means "now on the cli host", which keeps
// proxy code clean when it doesn't care about exact request time.
//
// Security: this action does NOT verify the vault_key. Bumping a
// counter doesn't leak secrets and proxy usually runs before or
// without the user's interactive unlock; requiring a master password
// just to record usage would be pathological. The action is still
// gated at the Go layer by service-token / JWT auth like every other
// endpoint.
fn handle_record_usage(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
        #[serde(default)]
        ts: Option<i64>,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("record_usage payload: {}", e),
            );
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }

    let ts = payload.ts.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });

    let affected = match payload.target.as_str() {
        "personal" => storage::bump_entry_usage(&payload.id, ts),
        "oauth" => storage::bump_oauth_usage(&payload.id, ts),
        "team" => {
            emit_error(
                req_id,
                "I_UNKNOWN_TARGET",
                "target 'team' is reserved for future use and not implemented in v1.0",
            );
            return;
        }
        other => {
            emit_error(
                req_id,
                "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other),
            );
            return;
        }
    };

    match affected {
        Ok(0) => emit_error(
            req_id,
            "I_CREDENTIAL_NOT_FOUND",
            format!("{} '{}' not found", payload.target, payload.id),
        ),
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({
                "target": payload.target,
                "id": payload.id,
                "ts": ts,
                "rows_affected": n,
            }),
        )),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("record_usage: {}", e)),
    }
}

// ========== record_test_result ==========
//
// Persists the most-recent connectivity-test outcome for a key into the
// `extra` JSON column at `$.last_test`. Called by `_internal test` after
// the run_connectivity_suite finishes, and by `aikey test` for parity so
// the CLI and Web Test Connection button feed the same "Last test" column
// on the Vault page.
//
// Payload:
//   { "target": "personal"|"oauth"|"team",
//     "id": "...",
//     "result": { at: i64, status: "pass"|"fail",
//                 latency_ms?: i64, error_code?: String,
//                 error_message?: String, suggestion?: String,
//                 suite_results?: [...] } }
//
// `result` is opaque to this handler — we serialise it back to JSON and
// json_set it under `$.last_test`. The shape contract lives at the writer
// (run_connectivity_suite → JSON envelope) so adding a new field there
// doesn't need a change here.
//
// Security stance mirrors record_usage: no vault_key verification (the
// stored value contains only status + latency + error code, no secret
// material; the Go layer's service-token / JWT auth still gates the call).
//
// Team scope: schema column exists on managed_virtual_keys_cache but is
// not yet wired through the storage layer (see VirtualKeyCacheEntry doc
// — INSERT OR REPLACE in upsert_virtual_key_cache would wipe extra on
// every `aikey key sync`; needs an ON CONFLICT DO UPDATE refactor first).
// Until then this action returns I_NOT_IMPLEMENTED for target=team rather
// than silently dropping the result — the Web should surface that as a
// "Test ran but result not persisted for team keys yet" hint.
fn handle_record_test_result(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
        result: serde_json::Value,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("record_test_result payload: {}", e),
            );
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }
    if !payload.result.is_object() {
        emit_error(
            req_id,
            "I_STDIN_INVALID_JSON",
            "result must be a JSON object",
        );
        return;
    }

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }

    let result_json = match serde_json::to_string(&payload.result) {
        Ok(s) => s,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", format!("serialise result: {}", e));
            return;
        }
    };

    let affected = match payload.target.as_str() {
        "personal" => storage::merge_entry_extra(&payload.id, "$.last_test", &result_json),
        "oauth" => storage::merge_oauth_extra(&payload.id, "$.last_test", &result_json),
        "team" => storage::merge_team_extra(&payload.id, "$.last_test", &result_json),
        other => {
            emit_error(
                req_id,
                "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other),
            );
            return;
        }
    };

    match affected {
        Ok(0) => emit_error(
            req_id,
            "I_CREDENTIAL_NOT_FOUND",
            format!("{} '{}' not found", payload.target, payload.id),
        ),
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({
                "target": payload.target,
                "id": payload.id,
                "rows_affected": n,
            }),
        )),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("record_test_result: {}", e)),
    }
}

// ========== test (connectivity probe + persist) ==========
//
// Runs the same connectivity suite that `aikey test <alias> --json` runs
// from the terminal, aggregates one "Last test" snapshot, persists it to
// the vault at `extra.$.last_test`, and emits the full result envelope
// back to the caller. Used by the Web "Test Connection" button — keeps
// CLI and Web parity by sharing `run_connectivity_suite` as the single
// core (internal-command-reuses-public-core principle).
//
// Payload:
//   { "target": "personal"|"oauth"|"team",
//     "id": "<alias|provider_account_id|virtual_key_id>" }
//
// Why `target` is taken explicitly (rather than resolving from id alone):
// `targets_from_alias` already disambiguates by trying personal → team →
// oauth in order, but the persist sink differs by kind (merge_entry_extra
// vs. merge_oauth_extra) and we need to pick the right one BEFORE we
// know which probe succeeded. Caller (Go layer) knows the kind from the
// vault list response, so it tells us.
//
// Aggregation rule for `last_test.status`:
//   - pass: any probe row has api_ok = true
//   - fail: otherwise
//   - latency_ms: min api_ms across passing rows (when status = pass),
//     else max ping_ms across rows (so the user sees the slowest hop).
//   - error_code / error_message: from the first failing row when fail,
//     omitted when pass.
//   - suite_results: raw per-row JSON from outcome.json_results, so the
//     popup can show per-provider breakdown without a follow-up call.
//
// Security: no vault_key verification (same stance as record_test_result
// — written value contains no secret material).
fn handle_test(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("test payload: {}", e),
            );
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }
    if !matches!(payload.target.as_str(), "personal" | "oauth" | "team") {
        emit_error(
            req_id,
            "I_UNKNOWN_TARGET",
            format!(
                "unknown target '{}' (expected personal|oauth|team)",
                payload.target
            ),
        );
        return;
    }

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }

    // Proxy must be up — the suite probes via proxy for every credential
    // kind. Same exit-condition as `aikey test`'s pre-flight.
    if !crate::commands_proxy::proxy_is_running_managed() {
        emit_error(
            req_id,
            "I_PROXY_NOT_RUNNING",
            "aikey-proxy is not running. Run `aikey proxy start` and retry.",
        );
        return;
    }
    let proxy_port = crate::commands_proxy::proxy_port();

    // Resolve targets via the shared helper. `targets_from_alias` tries
    // personal → team → oauth; we filter to the caller's declared target
    // kind so a Web-side "test this OAuth key" doesn't accidentally hit a
    // personal alias that happens to share the same name.
    // A1 (2026-06-11): for team targets, resolve + persist THIS user's cluster
    // node first (best-effort), mirroring `aikey use`. On a cluster the VK's key
    // material is central, so the probe must route to the node — without a
    // persisted node `targets_from_alias`'s cluster branch can't fire and a Web
    // "Test Connection" run BEFORE any `aikey use` surfaced a misleading
    // I_CREDENTIAL_NOT_FOUND / 404. on_cluster drives the A2 error below.
    // Bug: workflow/CI/bugfix/20260611-cluster-form1-connectivity-test-404.md
    let mut on_cluster = false;
    if payload.target == "team" {
        on_cluster = crate::commands_account::try_resolve_and_persist_cluster_node();
    }

    let mut targets =
        crate::commands_project::targets_from_alias(&payload.id, None, None, proxy_port);
    use crate::commands_project::CredentialKind;
    let expected_kind = match payload.target.as_str() {
        "personal" => Some(CredentialKind::PersonalApi),
        "oauth" => Some(CredentialKind::OAuth),
        "team" => Some(CredentialKind::ManagedTeam),
        _ => None,
    };
    if let Some(want) = expected_kind {
        targets.retain(|t| t.kind == want);
    }
    if targets.is_empty() {
        // A2 (2026-06-11): give a cluster-aware, actionable error instead of the
        // misleading "credential not found" when the VK actually exists but
        // couldn't be turned into a probe target.
        if payload.target == "team" && on_cluster {
            // We ARE on a cluster (node resolved) yet still couldn't build a
            // target — transient resolve/persist or token-derivation issue, not
            // a missing credential.
            emit_error(
                req_id,
                "I_CLUSTER_NODE_UNRESOLVED",
                format!(
                    "team key '{}' is a cluster key (material stays central); its node was resolved but a probe target could not be built — retry, or check control/hub connectivity",
                    payload.id
                ),
            );
            return;
        }
        emit_error(
            req_id,
            "I_CREDENTIAL_NOT_FOUND",
            format!(
                "no {target} credential matches id '{id}'{hint}",
                target = payload.target,
                id = payload.id,
                // A team key shows in the list (metadata synced) but can't be
                // probed until its key material is downloaded locally — guide
                // the user to the recovery command instead of a bare
                // "credential not found". 2026-06-17 user-reported.
                hint = if payload.target == "team" {
                    " — if this team key was just issued/claimed, run `aikey key sync` (or `aikey use <alias>`) to download its key material first, then retry"
                } else {
                    ""
                }
            ),
        );
        return;
    }

    // 2026-05-26 Option β follow-up (user-reported "OAuth Add Key Test
    // still shows skipped"): only the OAuth Web-modal Test path needs the
    // proxy row. Other targets (personal / team) keep show_proxy_row=false
    // — that's the long-standing single-cred post-save convention shared
    // with `aikey test <alias>` (CLI single-alias mode, main.rs:2167).
    //
    // For OAuth specifically:
    //   - show_proxy_row=true (so the row appears)
    //   - probe_oauth_account_id=Some(payload.id) (sends `aikey_probe_<id>`
    //     Tier2Probe so proxy resolves the SPECIFIC account via broker
    //     EnsureFresh + ResolveCredential, NOT aikey_active_<provider>
    //     which would resolve to whichever binding is currently active —
    //     web OAuth add doesn't propagate lifecycle, so the just-added
    //     account is unlikely to be active yet, Phase A.1 deferred)
    let is_oauth = payload.target == "oauth";
    let opts = crate::commands_project::SuiteOptions {
        show_proxy_row: is_oauth,
        header_label: None,
        password: None,
        proxy_port,
        show_key_column: false,
        probe_raw_bearer: None,
        probe_raw_base_url: None,
        probe_oauth_account_id: if is_oauth {
            Some(payload.id.clone())
        } else {
            None
        },
    };
    let outcome =
        crate::commands_project::run_connectivity_suite(targets, opts, /*json_mode*/ true);

    // Aggregate + persist via the shared helper. Same code path the
    // public `aikey test` CLI uses, so the row a Web user sees after
    // clicking Test connection is byte-identical to what a terminal
    // user sees after running `aikey test`. Internal-command-reuses-
    // public-core principle.
    let persisted_results = crate::commands_project::persist_test_outcome(&outcome);

    // Find the entry that matches the caller's (target, id). With a
    // single-credential probe targets are filtered to one CredentialKind,
    // so there's at-most-one matching result; we still pick by source_ref
    // == id to stay correct if `targets_from_alias` ever resolves to
    // multiple credentials of the same kind.
    let expected_kind_filter = expected_kind;
    let matched = persisted_results
        .into_iter()
        .find(|p| Some(p.target_kind) == expected_kind_filter && p.source_ref == payload.id);
    let (persisted, last_test) = match matched {
        Some(p) => (p.persisted, p.last_test),
        None => {
            // Shouldn't happen — we already returned early if targets
            // was empty — but if persist_test_outcome somehow drops the
            // group (e.g. all rows had a different source_ref than the
            // payload's id, which can occur if targets_from_alias did
            // alias→canonical translation), fall back to a synthesized
            // record so the caller still sees a structured failure.
            eprintln!(
                "[_internal test WARN] no persisted result matched (target={}, id={})",
                payload.target, payload.id
            );
            (
                false,
                json!({
                    "at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    "status": "fail",
                    "error_code": "I_INTERNAL_NO_MATCH",
                    "error_message": "probe completed but result aggregation didn't match the requested target",
                }),
            )
        }
    };

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "target": payload.target,
            "id": payload.id,
            "persisted": persisted,
            "last_test": last_test,
        }),
    ));
}

// ========== test_raw (pre-save connectivity probe) ==========
//
// Runs the same connectivity suite that `aikey add` runs after a user
// fills in the new-key form — but without ever touching the vault. The
// Web Add-Key Guided flow (spec §3.1 / §5.1) calls this action from
// page 2's Run-test button so the user can see Ping(D) / API / Chat
// outcomes BEFORE deciding whether to Save / Save-anyway / Cancel.
//
// Reuses three pieces of `aikey add` 's existing pre-save plumbing
// (internal-command-reuses-public-core principle):
//   1. `targets_from_new_personal_key`: builds one ad-hoc TestTarget per
//      selected provider, plaintext bearer, no vault row needed.
//   2. `run_connectivity_suite`: the same probe runner the CLI invokes.
//   3. `aggregate_test_outcome`: the same record-build aggregator
//      `aikey test` writes to `extra.$.last_test` — minus the vault
//      write (there's no row to write to yet).
//
// Payload:
//   { "providers": ["openai","anthropic", ...],  // ≥ 1 required
//     "secret":    "<plaintext>",
//     "alias_hint": "<source_ref label, only used in JSON output>",
//     "base_url":  "<optional override>" }
//
// Returns: `{ providers, last_test }` — `last_test` matches the
// VaultLastTest shape so the Web popup can render it identically to
// the post-save row.
//
// Security:
//   - The plaintext secret never lands on disk. It flows through stdin
//     into the probe agent which makes a direct upstream HTTP call and
//     drops the bearer when the response is read.
//   - This action does NOT require vault_key_hex (no vault touch).
//   - No persistence — caller is expected to follow up with
//     `vault-op add` if the user chooses Save / Save-anyway.
fn handle_test_raw(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        providers: Vec<String>,
        secret: String,
        #[serde(default)]
        alias_hint: String,
        #[serde(default)]
        base_url: String,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("test_raw payload: {}", e),
            );
            return;
        }
    };

    if payload.providers.is_empty() {
        emit_error(
            req_id,
            "I_STDIN_INVALID_JSON",
            "test_raw requires at least one provider",
        );
        return;
    }
    if payload.secret.trim().is_empty() {
        emit_error(
            req_id,
            "I_STDIN_INVALID_JSON",
            "test_raw requires a non-empty secret",
        );
        return;
    }

    // alias_hint only appears in json_results / suite_results.source_ref;
    // it never lands in any vault row. Default to a stable sentinel so
    // multiple pre-save probes from the same session aren't lumped into
    // one group when the caller forgets to supply one.
    let alias_hint = if payload.alias_hint.trim().is_empty() {
        "_pre_save_probe".to_string()
    } else {
        payload.alias_hint.clone()
    };
    let base_url_override = if payload.base_url.trim().is_empty() {
        None
    } else {
        Some(payload.base_url.as_str())
    };

    let targets = crate::commands_project::targets_from_new_personal_key(
        &alias_hint,
        payload.secret.trim(),
        &payload.providers,
        base_url_override,
    );
    if targets.is_empty() {
        emit_error(
            req_id,
            "I_INTERNAL",
            "test_raw: target construction yielded zero targets",
        );
        return;
    }

    // 2026-05-26 (spec: roadmap20260320/技术实现/update/20260526-pre-save-
    // proxy-probe-raw.md, Phase 2.B): turn proxy row ON for pre-save probes,
    // using the new aikey_probe_raw_* path. The plaintext key flows to proxy
    // via X-Aikey-Probe-Bearer header (kept off vault, off reporter); proxy
    // forwards using that bearer directly without binding lookup. Net effect:
    // user sees a real "this key + proxy → provider" health signal in the
    // Web Test connectivity modal, not a hard-coded "skipped" row.
    //
    // Pre-2026-05-26 behavior (kept here as a comment for soul-reading why):
    //   show_proxy_row: false + UI hard-coded "skipped"
    //   rationale (turned out wrong): "proxy row would always show skipped
    //   because the key isn't in vault yet". Actually proxy's old aikey_active_*
    //   path tests whatever's currently active — not the new key — which is
    //   misleading semantics, not "skipped". probe_raw fixes the root cause.
    let opts = crate::commands_project::SuiteOptions {
        show_proxy_row: true,
        header_label: None,
        password: None,
        proxy_port: crate::commands_proxy::proxy_port(),
        show_key_column: false,
        probe_raw_bearer: Some(payload.secret.trim().to_string()),
        probe_raw_base_url: if payload.base_url.trim().is_empty() {
            None
        } else {
            Some(payload.base_url.trim().to_string())
        },
        // test_raw is pre-save API key flow. OAuth never goes through here
        // (its broker.Save already wrote the row → goes through handle_test
        // by id, which uses probe_oauth_account_id). Always None here.
        probe_oauth_account_id: None,
    };
    let outcome =
        crate::commands_project::run_connectivity_suite(targets, opts, /*json_mode*/ true);

    // Aggregate WITHOUT persisting. With targets_from_new_personal_key
    // producing one PersonalApi TestTarget per provider — all sharing
    // the same source_ref=alias_hint — aggregate collapses them into
    // exactly one record per spec §10.5 any-ok semantics.
    let records = crate::commands_project::aggregate_test_outcome(&outcome);
    let last_test = records
        .into_iter()
        .next()
        .map(|r| r.last_test)
        .unwrap_or_else(|| {
            json!({
                "at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                "status": "fail",
                "error_code": "I_INTERNAL_NO_AGGREGATE",
                "error_message": "probe completed but aggregation produced no record",
            })
        });

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "providers": payload.providers,
            "alias_hint": alias_hint,
            "last_test": last_test,
        }),
    ));
}

// ========== use (provider-binding switch) ==========
//
// Non-interactive counterpart of the `aikey use <alias>` CLI command. Writes
// `user_profile_provider_bindings` for every provider the target key serves,
// then refreshes `~/.aikey/active.env` so the shell precmd hook picks it up.
//
// Payload: `{ "target": "personal" | "oauth", "id": "..." }`
//   - personal → id is the alias
//   - oauth    → id is the provider_account_id
//   - team is rejected (reserved for future use, same rule as delete_target)
//
// Per-provider semantics: one binding per provider_code. Activating a personal
// key that supports multiple providers writes one binding per provider. OAuth
// accounts are always single-provider by construction.
//
// Interactive pieces from `commands_account::handle_key_use` that are
// deliberately omitted here (belong to the CLI, not the Web API):
//   - provider-selection prompt when `supported_providers` has > 1 entry —
//     Web path binds ALL supported providers (matches `aikey use` non-interactive
//     mode). A future UI refinement can add a provider_override field.
//   - shell hook install / Codex / Kimi / statusline auto-configuration —
//     those modify the user's home dir outside vault and are Web-UI-inappropriate.
//     If the user later runs `aikey use` from CLI those get installed on-demand.
//
// Why not "unset": the Web UI contract is "one active per provider, swap to
// replace" — there's no unset button. If a future requirement needs "clear
// routing for provider X", that's a distinct `use_unset` action, not an
// overload of this one.
fn handle_use(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
        /// 阶段7 web consent replay (D9/方案B): after the browser modal the
        /// web re-invokes this same `use` with `"granted"`/`"denied"` instead
        /// of a dedicated `_internal desktop-op` command. Optional — absent
        /// on every ordinary use.
        #[serde(default)]
        desktop_consent: Option<String>,
        /// "不再提示" checkbox state accompanying `desktop_consent`.
        #[serde(default)]
        desktop_remember: bool,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("use payload invalid: {}", e),
            );
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }

    let (key, _conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // Resolve providers + key_source_type based on target.
    let (source_type, providers): (CredentialType, Vec<String>) = match payload.target.as_str() {
        "personal" => {
            let metas = match storage::list_entries_with_metadata() {
                Ok(v) => v,
                Err(e) => {
                    emit_error(
                        req_id,
                        "I_INTERNAL",
                        format!("list_entries_with_metadata: {}", e),
                    );
                    return;
                }
            };
            let meta = match metas.into_iter().find(|m| m.alias == payload.id) {
                Some(m) => m,
                None => {
                    emit_error(
                        req_id,
                        "I_CREDENTIAL_NOT_FOUND",
                        format!("alias '{}' does not exist", payload.id),
                    );
                    return;
                }
            };
            // Prefer the v1.0.2+ multi-provider list; fall back to the legacy
            // single provider_code. An entry with neither is unbindable —
            // refuse rather than silently no-op.
            let providers: Vec<String> = meta
                .supported_providers
                .clone()
                .filter(|v| !v.is_empty())
                .or_else(|| meta.provider_code.clone().map(|p| vec![p]))
                .unwrap_or_default();
            if providers.is_empty() {
                emit_error(req_id, "I_KEY_NO_PROVIDER",
                    format!("key '{}' has no provider assignment; add one with `aikey secret set --provider`", payload.id));
                return;
            }
            (CredentialType::PersonalApiKey, providers)
        }
        "oauth" => {
            let acct = match storage::get_provider_account(&payload.id) {
                Ok(Some(a)) => a,
                Ok(None) => {
                    emit_error(
                        req_id,
                        "I_CREDENTIAL_NOT_FOUND",
                        format!("provider_account_id '{}' does not exist", payload.id),
                    );
                    return;
                }
                Err(e) => {
                    emit_error(req_id, "I_INTERNAL", format!("get_provider_account: {}", e));
                    return;
                }
            };
            (CredentialType::PersonalOAuthAccount, vec![acct.provider])
        }
        "team" => {
            // Stage 7-1 (active-state cross-shell sync, 2026-04-27):
            // team-target binding switch via the unified protocol. Looks up
            // the vk by id, allowing virtual_key_id, local_alias, or server
            // alias as input — same resolution order the CLI's interactive
            // picker uses, so Web and CLI accept the same identifiers.
            //
            // Validation gate: only `local_state in (active, synced_inactive)`
            // and `key_status == active` count as "usable". Anything else
            // (revoked, scope-disabled, stale snapshot) is rejected with an
            // explicit code so the Web UI can surface the right message.
            let entries = match storage::list_virtual_key_cache() {
                Ok(v) => v,
                Err(e) => {
                    emit_error(
                        req_id,
                        "I_INTERNAL",
                        format!("list_virtual_key_cache: {}", e),
                    );
                    return;
                }
            };
            // Resolution order: exact virtual_key_id → local_alias → server alias.
            // Exact id wins so a user who typed the canonical vk_xxx form is
            // never ambiguous with a local nickname.
            let entry = entries
                .iter()
                .find(|e| e.virtual_key_id == payload.id)
                .or_else(|| {
                    entries
                        .iter()
                        .find(|e| e.local_alias.as_deref() == Some(payload.id.as_str()))
                })
                .or_else(|| entries.iter().find(|e| e.alias == payload.id))
                .cloned();
            let entry = match entry {
                Some(e) => e,
                None => {
                    emit_error(
                        req_id,
                        "I_CREDENTIAL_NOT_FOUND",
                        format!(
                            "team key '{}' not found in local cache (run `aikey key sync`)",
                            payload.id
                        ),
                    );
                    return;
                }
            };
            // Reject keys that the user shouldn't / can't activate. Each
            // local_state has a distinct error code so the Web UI can
            // tailor the surface message; the proxy will not route through
            // any of these regardless.
            //
            // 2026-05-12 rc.3 fix: `prompt_dismissed` was missing from the
            // ok arm — it fell into the `other` catch-all and emitted
            // I_KEY_DISABLED, even though the key is valid (user just
            // dismissed the auto-claim banner). The state is documented
            // in storage_platform.rs as "user dismissed the accept banner;
            // no longer prompted" — explicitly the same routability class
            // as `synced_inactive`. The vault page's `team_effective_status`
            // (commands_internal/query.rs) already maps it to "active",
            // so the UI shows Use and the handler must accept it.
            match entry.local_state.as_str() {
                "active" | "synced_inactive" | "prompt_dismissed" => {}
                "disabled_by_account_scope"
                | "disabled_by_account_status"
                | "disabled_by_seat_status"
                | "disabled_by_key_status" => {
                    emit_error(
                        req_id,
                        "I_KEY_DISABLED",
                        format!(
                            "team key '{}' is disabled (state={})",
                            payload.id, entry.local_state
                        ),
                    );
                    return;
                }
                "stale" => {
                    emit_error(
                        req_id,
                        "I_KEY_STALE",
                        format!(
                            "team key '{}' is stale (run `aikey key sync` to refresh)",
                            payload.id
                        ),
                    );
                    return;
                }
                other => {
                    emit_error(
                        req_id,
                        "I_KEY_DISABLED",
                        format!("team key '{}' is not usable (state={})", payload.id, other),
                    );
                    return;
                }
            }
            if entry.key_status != "active" {
                emit_error(
                    req_id,
                    "I_KEY_DISABLED",
                    format!(
                        "team key '{}' has server status '{}'",
                        payload.id, entry.key_status
                    ),
                );
                return;
            }
            // Phase 3B (2026-05-11): if the local cache has metadata but
            // ciphertext was never delivered, the binding would write but
            // the proxy couldn't actually route. Auto-trigger a snapshot
            // sync using the bridge's already-derived vault_key — the web
            // session has the vault_key (from the unlock POST + cookie),
            // not the password, so we can't take the CLI's session-based
            // path. The new `*_with_vault_key` variant skips the Argon2id
            // step. If sync still can't deliver ciphertext (network down,
            // server lost the key blob, etc.), fail loudly with
            // `I_KEY_NOT_DELIVERED` so the Web UI can prompt the user
            // (e.g. "run `aikey key sync` from a terminal" — the CLI
            // session might have additional sync paths).
            let mut entry = entry;
            // On a cluster, a central key's material stays on the central node and
            // the proxy routes via the node — no local ciphertext is needed (by
            // design). Only require local delivery off-cluster. This mirrors
            // `activate`'s cluster branch and the picker's `key_material_reachable`,
            // so the web set-route stops 422'ing central keys (2026-06-15).
            let on_cluster = crate::commands_account::read_cluster_node().is_some();
            if !entry.key_material_reachable(on_cluster) {
                match crate::commands_account::run_full_snapshot_sync_with_vault_key(&key) {
                    Ok(_) => {
                        // Re-read the entry — the sync may have populated
                        // ciphertext + flipped local_state.
                        if let Ok(Some(refreshed)) =
                            storage::get_virtual_key_cache(&entry.virtual_key_id)
                        {
                            entry = refreshed;
                        }
                    }
                    Err(e) => {
                        // Sync attempt itself failed (network / token expired).
                        // Fall through to the reachability check below — we'll
                        // emit a clearer error there if still missing.
                        eprintln!(
                            "[vault_op handle_use WARN] auto-sync for team key '{}' failed: {}",
                            entry.alias, e
                        );
                    }
                }
                if !entry.key_material_reachable(on_cluster) {
                    emit_error(
                        req_id,
                        "I_KEY_NOT_DELIVERED",
                        format!(
                            "Team key '{}' was not delivered (ciphertext missing). \
                                Try running `aikey key sync` in a terminal, or contact \
                                your team admin to re-issue the key.",
                            entry.alias
                        ),
                    );
                    return;
                }
            }
            // Provider list: prefer multi-protocol `supported_providers`,
            // fall back to single `provider_code`. Identical priority to
            // the personal target branch above (single source of truth).
            let providers: Vec<String> = if !entry.supported_providers.is_empty() {
                entry.supported_providers.clone()
            } else if !entry.provider_code.is_empty() {
                vec![entry.provider_code.clone()]
            } else {
                emit_error(
                    req_id,
                    "I_KEY_NO_PROVIDER",
                    format!("team key '{}' has no provider assignment", payload.id),
                );
                return;
            };
            // Use the canonical vk_id as the binding's key_source_ref —
            // not the user-supplied identifier, which could have been a
            // local_alias / server alias. This keeps `provider_bindings.
            // key_source_ref` aligned with virtual_key_cache.virtual_key_id
            // for joinable lookups.
            (CredentialType::ManagedVirtualKey, providers)
        }
        other => {
            emit_error(
                req_id,
                "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other),
            );
            return;
        }
    };

    // Re-resolve the canonical key_ref for team targets so write_bindings_canonical
    // gets the vk_id even when payload.id was a local_alias / server alias.
    // For personal/oauth, payload.id IS already canonical (alias / account_id).
    let canonical_key_ref: String = match payload.target.as_str() {
        "team" => {
            // Safe to expect: we already validated entry exists above.
            storage::list_virtual_key_cache()
                .ok()
                .and_then(|v| {
                    v.into_iter()
                        .find(|e| {
                            e.virtual_key_id == payload.id
                                || e.local_alias.as_deref() == Some(payload.id.as_str())
                                || e.alias == payload.id
                        })
                        .map(|e| e.virtual_key_id)
                })
                .unwrap_or_else(|| payload.id.clone())
        }
        _ => payload.id.clone(),
    };

    // 阶段7 consent replay, step 1 — REMEMBERED answers land in the pref
    // BEFORE the lifecycle runs, so the funnel's reconcile reads them
    // naturally (plan §4.2 timing): granted+remember → always;
    // denied+remember → never.
    if payload.desktop_remember {
        match payload.desktop_consent.as_deref() {
            Some("granted") => {
                let _ = crate::global_config::set_claude_desktop_consent("always");
            }
            Some("denied") => {
                let _ = crate::global_config::set_claude_desktop_consent("never");
            }
            _ => {}
        }
    }

    // Single funnel: Switched event runs write_bindings_canonical → refresh
    // → apply_third_party_cli_configs.
    let lifecycle = match crate::commands_account::apply_credential_lifecycle(
        crate::commands_account::CredentialLifecycleEvent::Switched {
            source_type: source_type.as_str(),
            source_ref: &canonical_key_ref,
            providers: &providers,
        },
        crate::audit::VerifiedVaultKey::new(key).ok().as_ref(),
    ) {
        Ok(o) => o,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", e);
            return;
        }
    };
    let refresh_ok = lifecycle.active_env_refreshed;

    // 阶段7 consent replay, step 2 — a ONE-SHOT grant (granted without
    // remember) leaves no pref for the funnel to read, so the funnel just
    // reported needs_consent again; honor the grant now with a direct
    // takeover and overwrite the wire field (plan §4.2).
    let mut desktop_switch = lifecycle.desktop_switch;
    if payload.desktop_consent.as_deref() == Some("granted")
        && !payload.desktop_remember
        && desktop_switch.is_some_and(|d| d.needs_consent)
    {
        if let Some(paths) = crate::commands_account::claude_desktop::desktop_paths() {
            desktop_switch = Some(crate::commands_account::claude_desktop::perform_takeover(
                &paths,
                crate::commands_proxy::proxy_port(),
            ));
        }
    }

    let audit_logged = try_log_audit(&key, AuditOperation::Exec, Some(&canonical_key_ref), true);

    let mut data = json!({
        "target": payload.target,
        "id": canonical_key_ref,
        "input_id": payload.id,
        "activated_providers": providers,
        "active_env_refreshed": refresh_ok,
        "audit_logged": audit_logged,
    });
    // Optional wire field (careful-api: absent unless the funnel actually
    // evaluated Desktop). Web reads needs_consent → modal, restart_required
    // → toast hint (P3).
    if let Some(d) = desktop_switch {
        data["desktop_switch"] = serde_json::to_value(d).unwrap_or(serde_json::Value::Null);
    }

    emit(&ResultEnvelope::ok(
        req_id,
        merge_hook_status_from_outcome(data, &lifecycle),
    ));
}

// ============================================================================
// Phase Y (2026-05-07) — hook_status_from_outcome / merge_hook_status_from_outcome tests
// ============================================================================
//
// Pin the contract that vault_op envelope's hook fields reflect the
// `LifecycleOutcome` populated by the funnel tail (instead of double-
// rendering Layer 1). Tests cover the outcome path, the no-tail fallback
// path, and the merge shape.
//
// The helpers also call `shell_rc_has_aikey_block()` which reads
// HOME/SHELL env. We isolate via a tmpdir + ENV_MUTATION_LOCK so this
// module doesn't race with session.rs / shell_integration tests.

#[cfg(test)]
mod hook_envelope_tests {
    use super::*;
    use crate::commands_account::{HookFailureReason, LifecycleOutcome};
    use crate::test_env_lock::ENV_MUTATION_LOCK;

    /// Small RAII-ish helper: set HOME + SHELL for the lifetime of a closure,
    /// restore on exit. Same pattern as shell_integration's run_shell_rc_check.
    fn with_home_shell<F, R>(home: &std::path::Path, shell: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let prev_home = std::env::var("HOME").ok();
        let prev_shell = std::env::var("SHELL").ok();
        let prev_no_hook = std::env::var("AIKEY_NO_HOOK").ok();
        unsafe {
            std::env::set_var("HOME", home.to_str().unwrap());
            std::env::set_var("SHELL", shell);
            // Default off — individual tests opt-in by setting AIKEY_NO_HOOK
            // before calling f().
            std::env::remove_var("AIKEY_NO_HOOK");
        }
        let result = f();
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_shell {
                Some(v) => std::env::set_var("SHELL", v),
                None => std::env::remove_var("SHELL"),
            }
            match prev_no_hook {
                Some(v) => std::env::set_var("AIKEY_NO_HOOK", v),
                None => std::env::remove_var("AIKEY_NO_HOOK"),
            }
        }
        result
    }

    #[test]
    fn outcome_path_uses_outcome_fields_when_tail_ran() {
        // When LifecycleOutcome.active_env_refreshed=true, the helper MUST
        // read hook_file_installed / hook_failure_reason from the outcome
        // (not call web_install_hook_file_layer1 again). This is the whole
        // point of Phase Y — eliminate double Layer 1 renders per envelope.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            // Set an unambiguously fake reason. If the helper falls through
            // to web_install_hook_file_layer1, it would report the real
            // host's state (likely None in this temp HOME) — the assertion
            // below would fail.
            hook_file_installed: false,
            hook_failure_reason: Some(HookFailureReason::IoError),
            ..Default::default()
        };

        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            hook_status_from_outcome(&outcome)
        });

        assert_eq!(json["hook_file_installed"], serde_json::json!(false));
        assert_eq!(json["hook_failure_reason"], serde_json::json!("io_error"));
        // rc_wired is independently grep'd; tmp HOME with no .zshrc → false
        assert_eq!(json["hook_rc_wired"], serde_json::json!(false));
    }

    #[test]
    fn outcome_path_passes_through_success_state() {
        // Mirror of the previous test for the success case: outcome reports
        // file_installed=true with no failure_reason; merge MUST surface
        // those exact values to the envelope.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            hook_file_installed: true,
            hook_failure_reason: None,
            ..Default::default()
        };

        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            hook_status_from_outcome(&outcome)
        });

        assert_eq!(json["hook_file_installed"], serde_json::json!(true));
        assert_eq!(json["hook_failure_reason"], serde_json::json!(null));
    }

    #[test]
    fn fallback_path_runs_fresh_layer1_when_tail_skipped() {
        // When the funnel didn't run its tail (no_op event with no binding
        // touch), outcome.active_env_refreshed=false and outcome's hook
        // fields are at their default (false / None). The helper MUST
        // fall back to a fresh Layer 1 render so the envelope still
        // reports an accurate file_installed (not the misleading default
        // false).
        //
        // We force a known fallback result by setting AIKEY_NO_HOOK=1,
        // which makes web_install_hook_file_layer1 short-circuit to
        // (false, AikeyNoHook). If the helper instead read outcome's
        // hook_failure_reason=None directly, the assertion would fail.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome::default(); // active_env_refreshed=false

        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            unsafe { std::env::set_var("AIKEY_NO_HOOK", "1") };
            let r = hook_status_from_outcome(&outcome);
            unsafe { std::env::remove_var("AIKEY_NO_HOOK") };
            r
        });

        assert_eq!(json["hook_file_installed"], serde_json::json!(false));
        assert_eq!(
            json["hook_failure_reason"],
            serde_json::json!("aikey_no_hook")
        );
    }

    #[test]
    fn merge_preserves_base_fields_and_adds_three_hook_fields() {
        // Pin the merge contract: base fields untouched, exactly the three
        // documented hook fields added. A future caller adding a fourth
        // hook-related field would need to update the merge function AND
        // this test in lockstep — the assertion's exact-key list is the
        // contract.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            hook_file_installed: true,
            hook_failure_reason: None,
            ..Default::default()
        };
        let base = serde_json::json!({
            "alias": "foo",
            "newly_primary_providers": ["anthropic"],
        });

        let merged = with_home_shell(tmp.path(), "/bin/zsh", || {
            merge_hook_status_from_outcome(base.clone(), &outcome)
        });

        // Base fields preserved
        assert_eq!(merged["alias"], serde_json::json!("foo"));
        assert_eq!(
            merged["newly_primary_providers"],
            serde_json::json!(["anthropic"])
        );
        // Three hook fields added — exact key set, no others
        assert!(merged.get("hook_file_installed").is_some());
        assert!(merged.get("hook_rc_wired").is_some());
        assert!(merged.get("hook_failure_reason").is_some());
    }

    #[test]
    fn rc_wired_grep_picks_up_v3_block_in_zshrc() {
        // Independent verification that hook_rc_wired correctly reflects
        // disk state — sanity check that the helper isn't always returning
        // the default false. Pre-write a v3 marker block to tmp/.zshrc;
        // helper should report rc_wired=true.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let zshrc = tmp.path().join(".zshrc");
        std::fs::write(
            &zshrc,
            "# user content\n\
             # aikey shell hook v3 begin\n\
             [[ -f ~/.aikey/hook.zsh ]] && source ~/.aikey/hook.zsh\n\
             # aikey shell hook v3 end\n",
        )
        .expect("write zshrc");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            hook_file_installed: true,
            ..Default::default()
        };
        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            hook_status_from_outcome(&outcome)
        });

        assert_eq!(json["hook_rc_wired"], serde_json::json!(true));
    }

    /// FENCE (alpha.5 §3.3, INV-A projection): a group VK's material is built
    /// from member_tokens[token_seat] — for an agent VK master sets token_seat
    /// to the PARENT, so the encrypted secret MUST round-trip to the PARENT's
    /// token (never another seat's). Seats without a usable token become
    /// explicit needs_login rows; the wire carries NO refresh material.
    #[test]
    fn group_runtime_material_projects_parent_token() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let key = [7u8; 32];

        let mut tokens_a = std::collections::HashMap::new();
        tokens_a.insert(
            "seat-parent".to_string(),
            ClusterMemberToken {
                access_token: "parent-token-AAA".into(),
                token_expires_at: 4200,
            },
        );
        tokens_a.insert(
            "seat-other".to_string(),
            ClusterMemberToken {
                access_token: "other-token-BBB".into(),
                token_expires_at: 4300,
            },
        );
        let g = ClusterRuntimeGroup {
            oauth_group_id: "g1".into(),
            provider_code: "anthropic".into(),
            routing_config: "{}".into(),
            accounts: vec![
                ClusterRuntimeAccount {
                    account_id: "acc-1".into(),
                    credential_id: "cred-1".into(),
                    identity: "a@x.io".into(),
                    protocol_type: "anthropic".into(),
                    base_url: "http://mock-provider.aikey.internal/anthropic".into(),
                    external_id: "ext-1".into(),
                    priority: 1,
                    enabled: true,
                    window_max_util_pct: Some(80),
                    window_status: "ok".into(),
                    window_reset_at: None,
                    window_7d_max_util_pct: Some(88),
                    window_7d_status: "active".into(),
                    window_7d_reset_at: None,
                    egress_proxy_url: "socks5://10.0.0.9:1080".into(),
                    member_tokens: tokens_a,
                },
                ClusterRuntimeAccount {
                    account_id: "acc-2".into(),
                    credential_id: "cred-2".into(),
                    identity: String::new(),
                    protocol_type: String::new(),
                    base_url: String::new(),
                    external_id: String::new(),
                    priority: 2,
                    enabled: true,
                    window_max_util_pct: None,
                    window_status: String::new(),
                    window_reset_at: None,
                    window_7d_max_util_pct: None,
                    window_7d_status: String::new(),
                    window_7d_reset_at: None,
                    egress_proxy_url: String::new(), // no override → falls back to node chain
                    member_tokens: std::collections::HashMap::new(), // parent never logged in
                },
                ClusterRuntimeAccount {
                    account_id: "acc-off".into(),
                    credential_id: "cred-off".into(),
                    identity: String::new(),
                    protocol_type: String::new(),
                    base_url: String::new(),
                    external_id: String::new(),
                    priority: 3,
                    enabled: false, // disabled → excluded entirely
                    window_max_util_pct: None,
                    window_status: String::new(),
                    window_reset_at: None,
                    window_7d_max_util_pct: None,
                    window_7d_status: String::new(),
                    window_7d_reset_at: None,
                    egress_proxy_url: String::new(),
                    member_tokens: std::collections::HashMap::new(),
                },
            ],
        };

        // token_seat = the PARENT (what master stamps for an agent VK).
        let (refs, material) =
            build_group_runtime_material(&key, &g, "seat-parent").expect("build");

        assert_eq!(refs.len(), 2, "disabled account must not appear in refs");
        assert_eq!(
            material.len(),
            2,
            "disabled account must not appear in material"
        );

        // acc-1: encrypted secret round-trips to the PARENT's token (INV-A).
        let m1 = material["acc-1"].as_object().unwrap();
        let nonce = b64.decode(m1["secret_nonce"].as_str().unwrap()).unwrap();
        let ct = b64
            .decode(m1["secret_ciphertext"].as_str().unwrap())
            .unwrap();
        let plain = crate::crypto::decrypt(&key, &nonce, &ct).expect("decrypt");
        assert_eq!(
            String::from_utf8(plain.to_vec()).unwrap(),
            "parent-token-AAA",
            "material must be the PARENT seat's token, never another seat's"
        );
        assert_eq!(m1["expires_at"], serde_json::json!(4200));
        assert_eq!(m1["external_id"], serde_json::json!("ext-1"));
        assert_eq!(m1["credential_type"], serde_json::json!("oauth_account"));
        assert_eq!(m1["window_7d_max_util_pct"], serde_json::json!(88));
        assert_eq!(m1["protocol_type"], serde_json::json!("anthropic"));
        assert_eq!(
            m1["base_url"],
            serde_json::json!("http://mock-provider.aikey.internal/anthropic")
        );
        assert_eq!(refs[0]["protocol_type"], serde_json::json!("anthropic"));
        assert!(m1.get("needs_login").is_none());
        // Per-account egress proxy (§11.7, P7): projected PLAINTEXT, account-level.
        assert_eq!(
            m1["egress_proxy_url"],
            serde_json::json!("socks5://10.0.0.9:1080"),
            "configured egress must project to node vault material"
        );

        // acc-2: parent has no token → explicit needs_login, no secret fields.
        let m2 = material["acc-2"].as_object().unwrap();
        assert_eq!(m2["needs_login"], serde_json::json!(true));
        assert!(m2.get("secret_ciphertext").is_none());
        // Empty egress override is OMITTED → proxy falls back to its node-level
        // egress chain (byte-unchanged material for accounts with no override).
        assert!(
            m2.get("egress_proxy_url").is_none(),
            "blank egress must be omitted, not written as empty string"
        );

        // Structural no-refresh invariant on the serialized bytes.
        let wire = serde_json::Value::Object(material).to_string();
        assert!(
            !wire.to_lowercase().contains("refresh"),
            "group_runtime wire must carry no refresh material: {wire}"
        );
    }

    /// FENCE (五跳合约, hop 1→3): a VERBATIM sample of master's org
    /// key-delivery response (handler_org_delivery.go orgVirtualKey +
    /// groupruntime.OrgGroupRuntime wire tags) must deserialize into
    /// ClusterSnapshotPayload with every group field populated. Catches JSON
    /// key drift between repos — if master renames a tag, this red-lines on
    /// the cli side instead of silently deserializing defaults (the daemon
    /// relays verbatim, so master⇄cli is the only drift surface).
    #[test]
    fn cluster_payload_parses_master_group_wire_sample() {
        let sample = serde_json::json!({
            "org_id": "org-cluster",
            "virtual_keys": [{
                "virtual_key_id": "vk-agent",
                "owner_account_id": "acct-svc",
                "seat_id": "seat-agent",
                "alias": "team-oauth-pool",
                "key_status": "active",
                "virtual_key_revision": "r1",
                // A group VK carries NO slots on the real org-delivery wire. The
                // master OMITS the field (json:"slots,omitempty"); this fixture must
                // mirror that (absent, NOT "[]") — the earlier "[]" masked a real bug
                // where the master emitted "slots": null and this parse rejected it,
                // failing the whole cluster apply (bugfix 2026-07-16, caught by the
                // cross-process TestWorkerClusterApply_PullsTeamOauthAccountsAndVK).
                "oauth_group_id": "g1",
                "token_seat_id": "seat-parent",
                "protocol_type": "anthropic"
            }],
            "oauth_group_runtime": {
                "groups": [{
                    "oauth_group_id": "g1",
                    "provider_code": "anthropic",
                    "routing_config": "{}",
                    "accounts": [{
                        "account_id": "acc-1",
                        "credential_id": "cred-1",
                        "identity": "a@x.io",
                        "external_id": "ext-1",
                        "priority": 1,
                        "enabled": true,
                        "egress_proxy_url": "socks5://10.0.0.9:1080",
                        "member_tokens": {
                            "seat-parent": {
                                "access_token": "tok-abc",
                                "token_expires_at": 4200,
                                "token_status": "logged_in"
                            }
                        }
                    }]
                }]
            }
        });
        let p: ClusterSnapshotPayload =
            serde_json::from_value(sample).expect("master wire sample must parse");
        let vk = &p.virtual_keys[0];
        assert_eq!(vk.oauth_group_id.as_deref(), Some("g1"));
        assert_eq!(vk.token_seat_id.as_deref(), Some("seat-parent"));
        assert_eq!(vk.protocol_type.as_deref(), Some("anthropic"));
        let g = &p.oauth_group_runtime.as_ref().expect("runtime").groups[0];
        assert_eq!(g.provider_code, "anthropic");
        let a = &g.accounts[0];
        assert_eq!(a.account_id, "acc-1");
        assert!(a.enabled);
        assert_eq!(
            a.egress_proxy_url, "socks5://10.0.0.9:1080",
            "per-account egress_proxy_url must survive the master<->cli wire (§11.7)"
        );
        assert_eq!(
            a.member_tokens
                .get("seat-parent")
                .map(|t| t.access_token.as_str()),
            Some("tok-abc"),
            "seat-keyed member_tokens must survive the wire"
        );
    }

    // Regression (bugfix 2026-07-18, staging cluster outage): a Go nil
    // slice/map wires as EXPLICIT `null`, which `#[serde(default)]` alone does
    // NOT cover — and one null field failed the ENTIRE snapshot apply, so both
    // staging workers received no credential updates for hours. The live trigger
    // was `"accounts": null` (an active OAuth group with zero deliverable
    // accounts); this fixture nulls EVERY collection field of the cluster wire
    // so any future field regressing to a plain Vec/HashMap turns this red.
    #[test]
    fn cluster_payload_tolerates_explicit_null_collections() {
        let sample = serde_json::json!({
            "org_id": "org-cluster",
            "virtual_keys": [{
                "virtual_key_id": "vk-1",
                "owner_account_id": "acct-1",
                "seat_id": "seat-1",
                "key_status": "active",
                "virtual_key_revision": "r1",
                "slots": null,       // 2026-07-16 wire shape (old control)
                "seat_quota": null
            }],
            "oauth_group_runtime": {
                "groups": [{
                    "oauth_group_id": "g-empty",
                    "provider_code": "anthropic",
                    "accounts": null // 2026-07-18 live staging wire shape
                }]
            },
            "quota_snapshot": { "subjects": null },
            "compliance": { "enabled": false, "packs": null }
        });
        let p: ClusterSnapshotPayload = serde_json::from_value(sample)
            .expect("explicit null collections must parse as empty, not fail the whole apply");
        assert!(p.virtual_keys[0].slots.is_empty());
        assert!(p.virtual_keys[0].seat_quota.is_empty());
        let g = &p.oauth_group_runtime.as_ref().expect("runtime").groups[0];
        assert_eq!(g.oauth_group_id, "g-empty");
        assert!(g.accounts.is_empty());
        assert!(p
            .quota_snapshot
            .as_ref()
            .expect("quota")
            .subjects
            .is_empty());

        // top-level nulls: virtual_keys / groups themselves
        let top_null = serde_json::json!({
            "org_id": "org-cluster",
            "virtual_keys": null,
            "oauth_group_runtime": { "groups": null }
        });
        let p2: ClusterSnapshotPayload =
            serde_json::from_value(top_null).expect("top-level null arrays must parse");
        assert!(p2.virtual_keys.is_empty());
        assert!(p2
            .oauth_group_runtime
            .as_ref()
            .expect("runtime")
            .groups
            .is_empty());

        // member_tokens: a Go nil map is `null` too
        let null_map = serde_json::json!({
            "org_id": "org-cluster",
            "oauth_group_runtime": { "groups": [{
                "oauth_group_id": "g1",
                "accounts": [{ "credential_id": "c1", "member_tokens": null }]
            }]}
        });
        let p3: ClusterSnapshotPayload =
            serde_json::from_value(null_map).expect("null member_tokens map must parse");
        assert!(
            p3.oauth_group_runtime.as_ref().expect("runtime").groups[0].accounts[0]
                .member_tokens
                .is_empty()
        );
    }
}
