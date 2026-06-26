//! Platform account, team key cache, provider bindings, and config helpers.
//!
//! Extracted from `storage.rs` for maintainability — all items are re-exported
//! by the parent module so existing callers are unaffected.

use super::{get_vault_path, open_connection, open_connection_readonly};
use crate::credential_type::CredentialType;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Platform account (control-service login session)
// ---------------------------------------------------------------------------

/// Singleton row in the `platform_account` table.
///
/// `jwt_token` holds the current OAuth access_token (Bearer).
/// `refresh_token` is the long-lived opaque token for silent renewal.
/// `token_expires_at` is the Unix timestamp when the access_token expires.
/// When `token_expires_at` is `None` the row was created by an older CLI version
/// and the token may still be valid (legacy 24-hour window).
#[derive(Debug, Clone)]
pub struct PlatformAccount {
    pub account_id: String,
    pub email: String,
    pub jwt_token: String, // current access_token (Bearer)
    pub control_url: String,
    pub logged_in_at: i64,
    pub refresh_token: Option<String>, // OAuth refresh token; None on legacy rows
    pub token_expires_at: Option<i64>, // Unix epoch when access_token expires
}

/// Upserts the singleton platform_account row (id = 1).
pub fn save_platform_account(
    account_id: &str,
    email: &str,
    jwt_token: &str,
    control_url: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT OR REPLACE INTO platform_account
             (id, account_id, email, jwt_token, control_url, logged_in_at)
         VALUES (1, ?1, ?2, ?3, ?4, strftime('%s', 'now'))",
        params![account_id, email, jwt_token, control_url],
    )
    .map_err(|e| format!("Failed to save platform account: {}", e))?;
    Ok(())
}

/// Updates only the control_url of the existing platform_account row.
pub fn update_platform_control_url(new_url: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE platform_account SET control_url = ?1 WHERE id = 1",
        params![new_url],
    )
    .map_err(|e| format!("Failed to update control_url: {}", e))?;
    Ok(())
}

/// Returns the stored platform account, or `None` if not logged in.
pub fn get_platform_account() -> Result<Option<PlatformAccount>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result = conn.query_row(
        "SELECT account_id, email, jwt_token, control_url, logged_in_at,
                refresh_token, token_expires_at
           FROM platform_account WHERE id = 1",
        [],
        |row| {
            Ok(PlatformAccount {
                account_id: row.get(0)?,
                email: row.get(1)?,
                jwt_token: row.get(2)?,
                control_url: row.get(3)?,
                logged_in_at: row.get(4)?,
                refresh_token: row.get(5)?,
                token_expires_at: row.get(6)?,
            })
        },
    );
    match result {
        Ok(acc) => Ok(Some(acc)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to read platform account: {}", e)),
    }
}

/// Upserts the singleton platform_account row with OAuth token data.
///
/// `access_token` is the short-lived Bearer JWT (1 h).
/// `refresh_token` is the long-lived opaque renewal token (30 d).
/// `token_expires_at` is the Unix timestamp when `access_token` expires.
pub fn save_oauth_session(
    account_id: &str,
    email: &str,
    access_token: &str,
    refresh_token: &str,
    token_expires_at: i64,
    control_url: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT OR REPLACE INTO platform_account
             (id, account_id, email, jwt_token, control_url, logged_in_at,
              refresh_token, token_expires_at)
         VALUES (1, ?1, ?2, ?3, ?4, strftime('%s', 'now'), ?5, ?6)",
        params![
            account_id,
            email,
            access_token,
            control_url,
            refresh_token,
            token_expires_at
        ],
    )
    .map_err(|e| format!("Failed to save OAuth session: {}", e))?;
    Ok(())
}

/// Updates only the access_token and its expiry after a silent refresh.
pub fn update_access_token(access_token: &str, token_expires_at: i64) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE platform_account SET jwt_token = ?1, token_expires_at = ?2 WHERE id = 1",
        params![access_token, token_expires_at],
    )
    .map_err(|e| format!("Failed to update access token: {}", e))?;
    Ok(())
}

/// Updates access_token, refresh_token, and expiry after a token refresh.
/// Call this whenever the server returns both tokens (e.g. POST /v1/auth/cli/token/refresh).
pub fn update_tokens(
    access_token: &str,
    refresh_token: &str,
    token_expires_at: i64,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE platform_account SET jwt_token = ?1, refresh_token = ?2, token_expires_at = ?3 WHERE id = 1",
        params![access_token, refresh_token, token_expires_at],
    )
    .map_err(|e| format!("Failed to update tokens: {}", e))?;
    Ok(())
}

/// Deletes the platform_account row (logout).
pub fn clear_platform_account() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute("DELETE FROM platform_account WHERE id = 1", [])
        .map_err(|e| format!("Failed to clear platform account: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Active key configuration (global mutex for proxy routing)
// ---------------------------------------------------------------------------

/// Holds the currently-active key selection written by `aikey use`.
/// Stored as three TEXT entries in the `config` table.
///
/// `key_type` = "team" | "personal" | "" (empty = nothing active)
/// `key_ref`  = virtual_key_id (team) OR alias (personal)
/// `providers` = JSON array of provider codes the active key supports
#[derive(Debug, Clone)]
pub struct ActiveKeyConfig {
    pub key_type: CredentialType,
    pub key_ref: String,
    pub providers: Vec<String>,
}

const ACTIVE_KEY_TYPE_KEY: &str = "active_key_type";
const ACTIVE_KEY_REF_KEY: &str = "active_key_ref";
const ACTIVE_KEY_PROVIDERS_KEY: &str = "active_key_providers";

/// Returns the current active key config, or `None` if no key is active.
pub fn get_active_key_config() -> Result<Option<ActiveKeyConfig>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;

    let key_type: Option<String> = conn
        .query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            params![ACTIVE_KEY_TYPE_KEY],
            |row| row.get(0),
        )
        .ok();

    match key_type.as_deref() {
        None | Some("") => return Ok(None),
        _ => {}
    }

    let key_ref: String = conn
        .query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            params![ACTIVE_KEY_REF_KEY],
            |row| row.get(0),
        )
        .unwrap_or_default();

    let providers_json: String = conn
        .query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            params![ACTIVE_KEY_PROVIDERS_KEY],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "[]".to_string());

    let providers: Vec<String> = serde_json::from_str(&providers_json).unwrap_or_default();

    Ok(Some(ActiveKeyConfig {
        key_type: CredentialType::from_db_str(&key_type.unwrap_or_default()),
        key_ref,
        providers,
    }))
}

/// Persists the active key configuration (upserts three config rows).
pub fn set_active_key_config(cfg: &ActiveKeyConfig) -> Result<(), String> {
    let conn = open_connection()?;
    let providers_json = serde_json::to_string(&cfg.providers)
        .map_err(|e| format!("Failed to serialize providers: {}", e))?;

    for (k, v) in &[
        (ACTIVE_KEY_TYPE_KEY, cfg.key_type.as_str()),
        (ACTIVE_KEY_REF_KEY, cfg.key_ref.as_str()),
    ] {
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![k, v.as_bytes().to_vec()],
        )
        .map_err(|e| format!("Failed to write active key config '{}': {}", k, e))?;
    }
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        params![ACTIVE_KEY_PROVIDERS_KEY, providers_json.as_bytes().to_vec()],
    )
    .map_err(|e| format!("Failed to write active key config providers: {}", e))?;

    Ok(())
}

/// Drops all rows from `managed_virtual_keys_cache`.
/// NOTE: Prefer `disable_keys_for_account_scope` on account switch —
/// it keeps the ciphertext rows so the previous account can access them again
/// after re-login, while still preventing the new account from using those keys.
pub fn clear_virtual_key_cache() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute("DELETE FROM managed_virtual_keys_cache", [])
        .map_err(|e| format!("Failed to clear virtual key cache: {}", e))?;
    Ok(())
}

/// One row to persist into the client-side `quota_rules_cache` (Phase 2 — design
/// §0.5/§5.2). A lean mirror of the server's `SubjectSnapshot`; `rules_json` is
/// the raw rules JSON array (the proxy parses it, the CLI just stores it).
pub struct QuotaRuleCacheEntry {
    pub subject_id: String,
    pub subject_kind: String,
    pub members_json: Option<String>, // JSON [seat_id...] for group; None for seat
    pub rules_json: String,           // JSON array of rules
    pub baseline_json: Option<String>, // Stage 4: JSON [{metric,period,used}]; None when absent
}

/// Full-replaces the `quota_rules_cache` with the snapshot's applicable subjects
/// (design §0.5/§5.2). The delivery snapshot is the authoritative full set for
/// this account's seats, so a transactional DELETE-then-INSERT keeps the proxy's
/// 5s read seeing a consistent set (and an empty `entries` clears stale rules
/// after the last quota is deleted). Caller treats failures as best-effort.
pub fn replace_quota_rules_cache(entries: &[QuotaRuleCacheEntry]) -> Result<(), String> {
    let mut conn = open_connection()?;
    let tx = conn
        .transaction()
        .map_err(|e| format!("quota cache tx: {}", e))?;
    tx.execute("DELETE FROM quota_rules_cache", [])
        .map_err(|e| format!("clear quota_rules_cache: {}", e))?;
    for e in entries {
        tx.execute(
            "INSERT INTO quota_rules_cache (subject_id, subject_kind, members, rules, baseline, synced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s', 'now'))",
            rusqlite::params![e.subject_id, e.subject_kind, e.members_json, e.rules_json, e.baseline_json],
        )
        .map_err(|err| format!("insert quota rule {}: {}", e.subject_id, err))?;
    }
    tx.commit()
        .map_err(|e| format!("commit quota_rules_cache: {}", e))?;
    Ok(())
}

/// Config key for the deployment-global edge price summary (design D-U8/P6).
pub const QUOTA_PRICE_SUMMARY_KEY: &str = "quota.price_summary";

/// Upserts the deployment-global edge price summary JSON (D-U8/P6) as a singleton
/// `config` row for the proxy to read for local usd pricing. Reuses the existing
/// config kv table — no new table; the summary is global (not per-subject), so it
/// doesn't belong in `quota_rules_cache`. Best-effort like the rules cache.
/// Only called when the snapshot carries `price_tiers`; an absent field leaves the
/// last-good summary untouched (resilient to an old / summary-less server).
pub fn set_quota_price_summary(summary_json: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        rusqlite::params![QUOTA_PRICE_SUMMARY_KEY, summary_json.as_bytes().to_vec()],
    )
    .map_err(|e| format!("write quota price summary: {}", e))?;
    Ok(())
}

/// Clears `provider_key_nonce` / `provider_key_ciphertext` on all active
/// (non-disabled) managed virtual keys, so a subsequent
/// `run_full_snapshot_sync` will treat them as `needs_download` and pull
/// fresh ciphertext encrypted under the current `vault_key`.
///
/// Used exclusively by `aikey key sync --force-reencrypt` — the user-facing
/// recovery path when a vault holds team-key ciphertext that the current
/// `vault_key` cannot decrypt (e.g. proxy logs
/// "managed key: decryption failed, skipping" followed by 401
/// "Route token not found in registry" from the wrapper preflight). See
/// `aikeylabs/workflow/CI/bugfix/2026-05-11-team-key-decrypt-inconsistent.md`.
///
/// Returns the number of rows that had ciphertext cleared. Rows already
/// without ciphertext (pending_claim / not-yet-delivered) are not touched
/// and not counted, so a `0` return reliably means "no active team key
/// currently carries ciphertext locally — re-encrypt is a no-op".
///
/// Scoped to `key_status = 'active'` and excludes `local_state LIKE
/// 'disabled_by_%'` to avoid waking up keys that the server has revoked
/// or that the current account no longer owns; the regular snapshot sync
/// owns the lifecycle of those flags.
pub fn clear_managed_key_ciphertexts() -> Result<usize, String> {
    let conn = open_connection()?;
    let n = conn
        .execute(
            "UPDATE managed_virtual_keys_cache
                SET provider_key_nonce      = NULL,
                    provider_key_ciphertext = NULL
              WHERE key_status = 'active'
                AND COALESCE(local_state, '') NOT LIKE 'disabled_by_%'
                AND provider_key_ciphertext IS NOT NULL",
            [],
        )
        .map_err(|e| format!("Failed to clear managed key ciphertexts: {}", e))?;
    Ok(n)
}

/// On account switch: marks all cached keys not owned by `new_account_id` as
/// `disabled_by_account_scope`.
///
/// Keys are preserved so they remain available if the user logs back into the
/// previous account.  Proxy and `aikey use` both reject any key whose
/// `local_state` is not `active`, so scope-disabled keys are effectively inert
/// until the owning account is active again.
///
/// Pre-v0.8 rows where `owner_account_id IS NULL` are also scope-disabled —
/// they will be restored to `synced_inactive` the next time a sync runs under
/// the account that originally accepted them.
pub fn disable_keys_for_account_scope(new_account_id: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_state = 'disabled_by_account_scope',
                synced_at   = strftime('%s', 'now')
          WHERE (owner_account_id IS NULL OR owner_account_id != ?1)
            AND local_state != 'disabled_by_account_scope'",
        params![new_account_id],
    )
    .map_err(|e| format!("Failed to scope-disable keys for account switch: {}", e))?;
    Ok(())
}

/// Clears all three active key config rows (no key active).
pub fn clear_active_key_config() -> Result<(), String> {
    let conn = open_connection()?;
    for k in &[
        ACTIVE_KEY_TYPE_KEY,
        ACTIVE_KEY_REF_KEY,
        ACTIVE_KEY_PROVIDERS_KEY,
    ] {
        conn.execute("DELETE FROM config WHERE key = ?1", params![k])
            .map_err(|e| format!("Failed to clear active key config '{}': {}", k, e))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generic text config helpers
// ---------------------------------------------------------------------------

const SESSION_BACKEND_KEY: &str = "session.backend";

/// Read a plain-text config value. Returns `None` if the key is absent or the
/// vault does not exist yet.
pub fn get_text_config(key: &str) -> Option<String> {
    let db_path = get_vault_path().ok()?;
    if !db_path.exists() {
        return None;
    }
    let conn = open_connection().ok()?;
    conn.query_row(
        "SELECT CAST(value AS TEXT) FROM config WHERE key = ?",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// Write a plain-text config value. Silent on failure.
pub fn set_text_config(key: &str, value: &str) {
    if let Ok(conn) = open_connection() {
        let _ = conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![key, value],
        );
    }
}

/// Returns the user's preferred session backend: `"keychain"`, `"file"`, `"disabled"`,
/// or `None` if the user has not yet been asked.
pub fn get_session_backend_pref() -> Option<String> {
    get_text_config(SESSION_BACKEND_KEY)
}

/// Persist the session backend preference.
pub fn set_session_backend_pref(pref: &str) {
    set_text_config(SESSION_BACKEND_KEY, pref);
}

// ---------------------------------------------------------------------------
// Seat status cache (background sync)
// ---------------------------------------------------------------------------

const SEAT_STATUS_CACHE_KEY: &str = "account.seat_statuses";
const LAST_STATUS_SYNC_KEY: &str = "account.last_status_sync";

/// Persist seat statuses as a JSON string: `{"seat_id": "active"|"suspended"|...}`.
pub fn set_seat_status_cache(json: &str) {
    set_text_config(SEAT_STATUS_CACHE_KEY, json);
}

/// Read the cached seat statuses JSON. Returns `None` if never synced.
pub fn get_seat_status_cache() -> Option<String> {
    get_text_config(SEAT_STATUS_CACHE_KEY)
}

/// Record the Unix timestamp of the last successful status sync.
pub fn set_last_status_sync(ts: i64) {
    set_text_config(LAST_STATUS_SYNC_KEY, &ts.to_string());
}

/// Read the Unix timestamp of the last successful status sync.
pub fn get_last_status_sync() -> i64 {
    get_text_config(LAST_STATUS_SYNC_KEY)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Snapshot sync version (Phase C incremental sync)
// ---------------------------------------------------------------------------

const LOCAL_SEEN_SYNC_VERSION_KEY: &str = "account.local_seen_sync_version";

/// Read the last sync_version the CLI successfully pulled from the server.
/// Returns 0 if never synced (ensures first run triggers an initial pull,
/// since the server starts at version >= 1).
pub fn get_local_seen_sync_version() -> i64 {
    get_text_config(LOCAL_SEEN_SYNC_VERSION_KEY)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
}

/// Persist the sync_version returned by the last successful snapshot pull.
pub fn set_local_seen_sync_version(v: i64) {
    set_text_config(LOCAL_SEEN_SYNC_VERSION_KEY, &v.to_string());
}

const LAST_MATERIAL_SYNC_VERSION_KEY: &str = "account.last_material_sync_version";

/// Read the sync_version at which managed-key MATERIAL (the encrypted
/// `provider_key_ciphertext`) was last fully downloaded.
///
/// Why this exists, separate from `local_seen_sync_version` (bugfix
/// 2026-06-16, form-⓪ credential rotation not refreshing the local key):
/// the snapshot carries only metadata — the real provider key is fetched on a
/// separate delivery channel and `apply_snapshot_to_cache` deliberately
/// PRESERVES the existing ciphertext (it is a local field, see
/// 20260324-provider-key-本地 CLI 表ER图.md). The lightweight background sync
/// advances `local_seen_sync_version` without re-downloading material, so a
/// credential/VK rotation (which bumps `sync_version`, see 数据同步方案.md
/// §4.1.2) would otherwise leave the local ciphertext stale forever. This
/// account-level marker lets the full sync detect "material is older than the
/// current server state" and re-pull. Account-level (not per-VK) by design:
/// coarse re-download of all the account's material on any bump is cheap at
/// employee scale and keeps sync-tracking state in `config.account.*` where the
/// design (本地 CLI 表ER图 §3.3) and existing keys
/// (`account.local_seen_sync_version`, `account.last_status_sync`) already put
/// it. Returns 0 if never stamped (first full sync downloads everything).
pub fn get_last_material_sync_version() -> i64 {
    get_text_config(LAST_MATERIAL_SYNC_VERSION_KEY)
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
}

/// Persist the sync_version after a full key-material download pass completes
/// cleanly. A pass with any delivery-fetch failure must leave this un-advanced
/// so the next full sync retries the stale material.
pub fn set_last_material_sync_version(v: i64) {
    set_text_config(LAST_MATERIAL_SYNC_VERSION_KEY, &v.to_string());
}

// ---------------------------------------------------------------------------
// Team-managed virtual key cache
// ---------------------------------------------------------------------------

/// Row from `managed_virtual_keys_cache`.
#[derive(Debug, Clone)]
pub struct VirtualKeyCacheEntry {
    pub virtual_key_id: String,
    pub org_id: String,
    pub seat_id: String,
    /// Server-assigned alias (authoritative, never modified locally).
    pub alias: String,
    pub provider_code: String,
    pub protocol_type: String,
    pub base_url: String,
    pub credential_id: String,
    pub credential_revision: String,
    pub virtual_key_revision: String,
    pub key_status: String,
    pub share_status: String,
    /// Controls CLI and proxy behaviour. Valid values:
    /// - `active`                    — currently selected key; proxy routes through it.
    /// - `synced_inactive`           — known and valid but not selected.
    /// - `prompt_dismissed`          — user dismissed the accept banner; no longer prompted.
    /// - `disabled_by_account_scope` — belongs to a different account; cannot be activated.
    /// - `disabled_by_account_status`— server: owning account is disabled.
    /// - `disabled_by_seat_status`   — server: owning seat is suspended/revoked.
    /// - `disabled_by_key_status`    — server: key itself is revoked/expired.
    /// - `stale`                     — not returned by last server snapshot; may be outdated.
    pub local_state: String,
    pub expires_at: Option<i64>,
    pub provider_key_nonce: Option<Vec<u8>>,
    pub provider_key_ciphertext: Option<Vec<u8>>,
    pub synced_at: i64,
    /// User-set local display name (`aikey key alias`). `None` → use server alias.
    pub local_alias: Option<String>,
    /// Provider codes this key supports (e.g. `["anthropic"]`), parsed from JSON.
    /// Populated from delivery payload slots at accept/sync time.
    /// Used by `aikey use` to write the correct provider env vars.
    pub supported_providers: Vec<String>,
    /// Per-provider upstream base URLs (JSON object). Keys: provider code, Values: base URL.
    /// Populated from delivery payload slots; empty map until first key accept/sync.
    pub provider_base_urls: std::collections::HashMap<String, String>,
    /// The `account_id` that last synced/accepted this key. `None` for pre-v0.8 rows.
    /// Used to scope-disable keys when the user switches to a different account.
    pub owner_account_id: Option<String>,
    /// Generic per-key extension JSON blob — same shape contract as
    /// `storage::SecretMetadata::extra`. Stores connectivity-test results
    /// at `$.last_test` (written by `_internal vault-op record_test_result`
    /// / `test` with target=team) and any future per-key facts users add.
    ///
    /// CRITICAL invariant: `upsert_virtual_key_cache` MUST NOT include
    /// `extra` in its UPDATE SET — every `aikey key sync` calls upsert,
    /// and if sync ever overwrites this column the user's recorded
    /// test results disappear silently. The 2026-05-22 refactor switched
    /// upsert from `INSERT OR REPLACE` (which wipes unlisted columns) to
    /// `INSERT ... ON CONFLICT(virtual_key_id) DO UPDATE SET <only
    /// sync-authoritative fields>` exactly to enforce this.
    pub extra: Option<serde_json::Value>,
    /// Seat-group binding target (N6, server-owned). Folded from the snapshot's
    /// `oauth_group_id`. `None` for direct-bind VKs. Unlike `extra`, this IS in
    /// the upsert's DO UPDATE SET (server is authoritative).
    pub oauth_group_id: Option<String>,
    /// Seat's ranked candidate set for a group-bound VK (N6, server-owned),
    /// stored as raw JSON text `[{account_id, identity, provider_code, priority,
    /// assigned}]`. Folded from the snapshot. `None` for direct-bind VKs. The
    /// volatile token/window material is NOT here — it rides `group_runtime`
    /// (channel ③, N7), a separate column this writer does not touch.
    pub group_accounts: Option<String>,
    /// The group's routing knobs JSON (N6, server-owned), folded from the
    /// snapshot. `None`/`"{}"` for direct-bind VKs. The proxy reads it to
    /// classify exhaustion (exhaustion_signals) + apply switch/cooldown knobs.
    /// In the upsert's DO UPDATE SET (server authoritative).
    pub routing_config: Option<String>,
}

impl VirtualKeyCacheEntry {
    /// Whether this team key's provider key material is REACHABLE for routing —
    /// the single rule `aikey use` (picker + alias), the web set-route bridge, and
    /// `activate` must agree on. Material is reachable when it was delivered to the
    /// local vault (`provider_key_ciphertext`), OR — in central key mode — when the
    /// client is on a cluster AND the seat is claimed: the key stays on the central
    /// node and the proxy routes via the node (no local ciphertext, by design).
    ///
    /// WHY this helper (2026-06-15): only the `use <alias>` path was cluster-aware,
    /// so a central key showed in `aikey ls` but was hidden by the interactive
    /// picker (it required a local ciphertext) and rejected by the web set-route
    /// (`I_KEY_NOT_DELIVERED` → 422). One predicate keeps the three paths from
    /// diverging again. `claimed` is required so an unclaimed (pending_claim) seat
    /// is never treated as usable just because the client is on a cluster.
    pub fn key_material_reachable(&self, on_cluster: bool) -> bool {
        // Group VKs (oauth_group_id set) carry NO local key material BY DESIGN —
        // the per-account credential is pulled by the proxy via channel ③ (group
        // runtime), so routing works without local ciphertext, exactly like a
        // cluster central key. Without this, `use` / web set-route 422'd a group
        // VK with I_KEY_NOT_DELIVERED ("该密钥尚未下发") even though it routes
        // fine. Same empty-local-material root cause as the connectivity-probe
        // ciphertext guard (targets.rs) and the proxy group-route path. (2026-06-26)
        self.provider_key_ciphertext.is_some()
            || (on_cluster && self.share_status == "claimed")
            || self.oauth_group_id.is_some()
    }
}

/// Inserts a new row or updates the sync-authoritative fields of an
/// existing row, keyed by `virtual_key_id`.
///
/// 2026-05-22 — switched from `INSERT OR REPLACE` to
/// `INSERT ... ON CONFLICT DO UPDATE`. The previous form deletes the
/// old row and re-inserts, which silently wipes any column the writer
/// doesn't include in its INSERT list. That destroyed user-owned
/// per-key state every `aikey key sync` — notably the new
/// `extra` JSON blob that holds connectivity-test results
/// (`extra.$.last_test`), favourites, tags, and other future per-key
/// facts.
///
/// The new form lists every field this writer owns (the columns the
/// server is authoritative over) in the DO UPDATE SET clause. Any
/// column not in that list — currently `extra`, and `cache_schema_version`
/// which is constant — survives the upsert intact. Adding a future
/// "user-owned" column for team rows is now safe: leave it out of
/// SET and sync won't touch it.
///
/// `provider_key_nonce` / `provider_key_ciphertext` may be `None` until
/// the key is accepted.
pub fn upsert_virtual_key_cache(entry: &VirtualKeyCacheEntry) -> Result<(), String> {
    let conn = open_connection()?;
    let supported_providers_json =
        serde_json::to_string(&entry.supported_providers).unwrap_or_else(|_| "[]".to_string());
    let provider_base_urls_json =
        serde_json::to_string(&entry.provider_base_urls).unwrap_or_else(|_| "{}".to_string());
    conn.execute(
        "INSERT INTO managed_virtual_keys_cache (
             virtual_key_id, org_id, seat_id, alias,
             provider_code, protocol_type, base_url,
             credential_id, credential_revision, virtual_key_revision,
             key_status, share_status, local_state,
             expires_at,
             provider_key_nonce, provider_key_ciphertext,
             cache_schema_version, synced_at,
             local_alias, supported_providers,
             provider_base_urls, owner_account_id,
             oauth_group_id, group_accounts, routing_config
         ) VALUES (
             ?1,  ?2,  ?3,  ?4,
             ?5,  ?6,  ?7,
             ?8,  ?9,  ?10,
             ?11, ?12, ?13,
             ?14,
             ?15, ?16,
             1,   strftime('%s', 'now'),
             ?17, ?18,
             ?19, ?20,
             ?21, ?22, ?23
         )
         ON CONFLICT(virtual_key_id) DO UPDATE SET
             org_id                  = excluded.org_id,
             seat_id                 = excluded.seat_id,
             alias                   = excluded.alias,
             provider_code           = excluded.provider_code,
             protocol_type           = excluded.protocol_type,
             base_url                = excluded.base_url,
             credential_id           = excluded.credential_id,
             credential_revision     = excluded.credential_revision,
             virtual_key_revision    = excluded.virtual_key_revision,
             key_status              = excluded.key_status,
             share_status            = excluded.share_status,
             local_state             = excluded.local_state,
             expires_at              = excluded.expires_at,
             provider_key_nonce      = excluded.provider_key_nonce,
             provider_key_ciphertext = excluded.provider_key_ciphertext,
             synced_at               = strftime('%s', 'now'),
             local_alias             = excluded.local_alias,
             supported_providers     = excluded.supported_providers,
             provider_base_urls      = excluded.provider_base_urls,
             owner_account_id        = excluded.owner_account_id,
             oauth_group_id           = excluded.oauth_group_id,
             group_accounts          = excluded.group_accounts,
             routing_config          = excluded.routing_config
             /* extra: DELIBERATELY OMITTED — user-owned column. See doc
                comment above and on VirtualKeyCacheEntry::extra. */
             /* my_assignment_override / group_runtime / routing_config: OMITTED —
                written by other channels (routing poll N12 / channel ③ N7), not
                this structural sync. Same fence rationale as extra. */
             /* cache_schema_version: omitted because it's a constant. */",
        params![
            entry.virtual_key_id,
            entry.org_id,
            entry.seat_id,
            entry.alias,
            entry.provider_code,
            entry.protocol_type,
            entry.base_url,
            entry.credential_id,
            entry.credential_revision,
            entry.virtual_key_revision,
            entry.key_status,
            entry.share_status,
            entry.local_state,
            entry.expires_at,
            entry.provider_key_nonce,
            entry.provider_key_ciphertext,
            entry.local_alias,
            supported_providers_json,
            provider_base_urls_json,
            entry.owner_account_id,
            entry.oauth_group_id,
            entry.group_accounts,
            entry.routing_config,
        ],
    )
    .map_err(|e| format!("Failed to upsert virtual key cache: {}", e))?;
    Ok(())
}

/// Parses a JSON array string into a `Vec<String>`, returning empty vec on failure.
fn parse_providers_json(json: Option<String>) -> Vec<String> {
    json.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Parses a JSON object string into a `HashMap<String, String>`, returning empty map on failure.
fn parse_base_urls_json(json: Option<String>) -> std::collections::HashMap<String, String> {
    json.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Returns all cached virtual key entries (write connection with migrations).
pub fn list_virtual_key_cache() -> Result<Vec<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(vec![]);
    }
    query_virtual_key_cache(&open_connection()?)
}

/// Returns all cached virtual key entries (read-only, no migrations).
pub fn list_virtual_key_cache_readonly() -> Result<Vec<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(vec![]);
    }
    query_virtual_key_cache(&open_connection_readonly()?)
}

// ── managed_virtual_keys_cache column cascade ──────────────────────────
//
// Three tiers, tried newest→oldest so each vault generation reads as many
// real columns as it has, projecting literal NULL for columns it predates:
//   GROUP  — post oauth_group (v1.0.1-alpha.3): + oauth_group_id + group_accounts
//   FULL   — post 2026-05-22 (has `extra`, but no oauth_group columns)
//   LEGACY — pre-2026-05-22 (no extra either)
//
// CRITICAL: the fixed column ORDER is shared by row_to_virtual_key_cache's
// index-based reads — extra is ALWAYS index 21, oauth_group_id 22,
// group_accounts 23. The middle (FULL) tier projects NULL for 22/23 but a
// REAL extra at 21, so a vault that has extra but not yet the oauth_group
// columns still reads its `extra` (no regression — the old 2-tier cascade
// would have dropped to LEGACY and lost extra). Why a cascade at all:
// `list_virtual_key_cache_readonly` opens read-only (no migrations), so a
// vault not yet write-migrated must still be served.
// Columns 0..=20 are identical across tiers; only the trailing 21/22/23/24
// (extra / oauth_group_id / group_accounts / routing_config) differ. Fixed
// indices are shared by row_to_virtual_key_cache's index reads — the middle
// (FULL) tier keeps a REAL extra at 21 and NULLs the oauth_group columns, so a
// vault with extra but not yet the oauth_group migration still reads its extra
// (no LEGACY-fallthrough regression). Kept as full literals (no string-concat
// crate) for a single grep-able source per tier.
//
// Newest: real extra + real oauth_group columns.
const VK_CACHE_COLUMNS_GROUP: &str = "virtual_key_id, org_id, seat_id, alias, \
     provider_code, protocol_type, base_url, \
     credential_id, credential_revision, virtual_key_revision, \
     key_status, share_status, local_state, \
     expires_at, \
     provider_key_nonce, provider_key_ciphertext, \
     synced_at, local_alias, supported_providers, \
     provider_base_urls, owner_account_id, extra, oauth_group_id, group_accounts, routing_config";
// Middle: real extra, no oauth_group columns yet (project NULL at 22/23).
const VK_CACHE_COLUMNS_FULL: &str = "virtual_key_id, org_id, seat_id, alias, \
     provider_code, protocol_type, base_url, \
     credential_id, credential_revision, virtual_key_revision, \
     key_status, share_status, local_state, \
     expires_at, \
     provider_key_nonce, provider_key_ciphertext, \
     synced_at, local_alias, supported_providers, \
     provider_base_urls, owner_account_id, extra, NULL, NULL, NULL";
// Oldest: no extra, no oauth_group columns.
const VK_CACHE_COLUMNS_LEGACY: &str = "virtual_key_id, org_id, seat_id, alias, \
     provider_code, protocol_type, base_url, \
     credential_id, credential_revision, virtual_key_revision, \
     key_status, share_status, local_state, \
     expires_at, \
     provider_key_nonce, provider_key_ciphertext, \
     synced_at, local_alias, supported_providers, \
     provider_base_urls, owner_account_id, NULL, NULL, NULL, NULL";

/// Single mapping from a SELECT row (in the column order declared by
/// `VK_CACHE_COLUMNS_*` above) to a struct. Centralised here so adding
/// future columns is a one-place edit; previously this mapping was
/// copy-pasted in three call sites and drifted easily.
fn row_to_virtual_key_cache(row: &rusqlite::Row) -> rusqlite::Result<VirtualKeyCacheEntry> {
    // Parse `extra` opportunistically — corrupt blob (shouldn't happen,
    // writers always go through json_set) is treated as None so a bad
    // row doesn't break the whole list query.
    let extra = row
        .get::<_, Option<String>>(21)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    Ok(VirtualKeyCacheEntry {
        virtual_key_id: row.get(0)?,
        org_id: row.get(1)?,
        seat_id: row.get(2)?,
        alias: row.get(3)?,
        provider_code: row.get(4)?,
        protocol_type: row.get(5)?,
        base_url: row.get(6)?,
        credential_id: row.get(7)?,
        credential_revision: row.get(8)?,
        virtual_key_revision: row.get(9)?,
        key_status: row.get(10)?,
        share_status: row.get(11)?,
        local_state: row.get(12)?,
        expires_at: row.get(13)?,
        provider_key_nonce: row.get(14)?,
        provider_key_ciphertext: row.get(15)?,
        synced_at: row.get(16)?,
        local_alias: row.get(17)?,
        supported_providers: parse_providers_json(row.get(18)?),
        provider_base_urls: parse_base_urls_json(row.get(19)?),
        owner_account_id: row.get(20)?,
        extra,
        // 22/23/24: oauth_group columns (NULL in the FULL/LEGACY tiers → None).
        oauth_group_id: row.get::<_, Option<String>>(22).unwrap_or(None),
        group_accounts: row.get::<_, Option<String>>(23).unwrap_or(None),
        routing_config: row.get::<_, Option<String>>(24).unwrap_or(None),
    })
}

fn query_virtual_key_cache(conn: &Connection) -> Result<Vec<VirtualKeyCacheEntry>, String> {
    let order = " FROM managed_virtual_keys_cache ORDER BY COALESCE(local_alias, alias)";
    let mut stmt = conn
        .prepare(&format!("SELECT {}{}", VK_CACHE_COLUMNS_GROUP, order))
        .or_else(|_| conn.prepare(&format!("SELECT {}{}", VK_CACHE_COLUMNS_FULL, order)))
        .or_else(|_| conn.prepare(&format!("SELECT {}{}", VK_CACHE_COLUMNS_LEGACY, order)))
        .map_err(|e| format!("Failed to prepare list query: {}", e))?;

    let rows = stmt
        .query_map([], row_to_virtual_key_cache)
        .map_err(|e| format!("Failed to query virtual key cache: {}", e))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to read virtual key cache rows: {}", e))
}

/// Returns a single cached entry by virtual_key_id, or `None`.
pub fn get_virtual_key_cache(virtual_key_id: &str) -> Result<Option<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    // Cascade newest→oldest; only a schema error (missing column) falls through,
    // never QueryReturnedNoRows (that's the real "absent" answer).
    let sel = |cols: &str| {
        format!(
            "SELECT {} FROM managed_virtual_keys_cache WHERE virtual_key_id = ?1",
            cols
        )
    };
    let result = conn
        .query_row(&sel(VK_CACHE_COLUMNS_GROUP), params![virtual_key_id], row_to_virtual_key_cache)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(&sel(VK_CACHE_COLUMNS_FULL), params![virtual_key_id], row_to_virtual_key_cache),
        })
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(&sel(VK_CACHE_COLUMNS_LEGACY), params![virtual_key_id], row_to_virtual_key_cache),
        });
    match result {
        Ok(entry) => Ok(Some(entry)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get virtual key cache entry: {}", e)),
    }
}

/// Looks up a cached entry by alias (tries `local_alias` first, then `alias`).
/// Returns `None` if no entry matches.
pub fn get_virtual_key_cache_by_alias(alias: &str) -> Result<Option<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let where_clause = "WHERE local_alias = ?1 OR alias = ?1 \
         ORDER BY CASE WHEN local_alias = ?1 THEN 0 ELSE 1 END LIMIT 1";
    // Try GROUP columns first (includes oauth_group_id / group_accounts /
    // routing_config), then FULL, then LEGACY — mirrors get_virtual_key_cache
    // (by id). Before this, the by-alias path only tried FULL+LEGACY, so
    // oauth_group_id was ALWAYS None when a VK was resolved by alias → every
    // group-VK-by-alias caller (e.g. `aikey use <group-vk-alias>`) saw a VK with
    // no group membership and fell into the "key not delivered" error, because
    // the group exemptions all key off oauth_group_id. The by-id path (web
    // set-route passes the vk_id) read GROUP and worked, which masked this on the
    // alias path. (2026-06-26)
    let result = conn
        .query_row(
            &format!(
                "SELECT {} FROM managed_virtual_keys_cache {}",
                VK_CACHE_COLUMNS_GROUP, where_clause
            ),
            params![alias],
            row_to_virtual_key_cache,
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM managed_virtual_keys_cache {}",
                    VK_CACHE_COLUMNS_FULL, where_clause
                ),
                params![alias],
                row_to_virtual_key_cache,
            ),
        })
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM managed_virtual_keys_cache {}",
                    VK_CACHE_COLUMNS_LEGACY, where_clause
                ),
                params![alias],
                row_to_virtual_key_cache,
            ),
        });
    match result {
        Ok(entry) => Ok(Some(entry)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!(
            "Failed to get virtual key cache entry by alias: {}",
            e
        )),
    }
}

/// Sets all team virtual key entries to `local_state = 'synced_inactive'`.
/// Called by `aikey use` before activating a new key (global mutex).
pub fn set_all_virtual_keys_inactive() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_state = 'synced_inactive',
                synced_at   = strftime('%s', 'now')
          WHERE local_state = 'active'",
        [],
    )
    .map_err(|e| format!("Failed to deactivate all virtual keys: {}", e))?;
    Ok(())
}

/// Returns the `provider_code` stored for a personal key (entries table), or `None`.
/// Returns `None` if the entry does not exist or has no provider code.
pub fn get_entry_provider_code(alias: &str) -> Result<Option<String>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result: rusqlite::Result<Option<String>> = conn.query_row(
        "SELECT provider_code FROM entries WHERE alias = ?1",
        params![alias],
        |row| row.get(0),
    );
    match result {
        Ok(code) => Ok(code),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get entry provider_code: {}", e)),
    }
}

/// Sets the `provider_code` for a personal key entry.
/// Pass `None` to clear the provider code.
pub fn set_entry_provider_code(alias: &str, provider_code: Option<&str>) -> Result<(), String> {
    let conn = open_connection()?;
    let rows = conn
        .execute(
            "UPDATE entries SET provider_code = ?1 WHERE alias = ?2",
            params![provider_code, alias],
        )
        .map_err(|e| format!("Failed to set entry provider_code: {}", e))?;
    if rows == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }
    Ok(())
}

/// Sets the `supported_providers` JSON array for a personal key entry.
pub fn set_entry_supported_providers(alias: &str, providers: &[String]) -> Result<(), String> {
    let conn = open_connection()?;
    set_entry_supported_providers_on_conn(&conn, alias, providers)
}

/// G-5 fix (2026-04-23): connection-scoped variant so batch_import can include
/// provider metadata writes in the same transaction as the entry insert.
pub(crate) fn set_entry_supported_providers_on_conn(
    conn: &rusqlite::Connection,
    alias: &str,
    providers: &[String],
) -> Result<(), String> {
    let json = serde_json::to_string(providers)
        .map_err(|e| format!("Failed to serialize providers: {}", e))?;
    let rows = conn
        .execute(
            "UPDATE entries SET supported_providers = ?1 WHERE alias = ?2",
            params![json, alias],
        )
        .map_err(|e| format!("Failed to set supported_providers: {}", e))?;
    if rows == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }
    Ok(())
}

/// Returns the custom upstream `base_url` for a personal key entry.
/// Returns `None` if not set (proxy or SDK uses provider default).
pub fn get_entry_base_url(alias: &str) -> Result<Option<String>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result: rusqlite::Result<Option<String>> = conn.query_row(
        "SELECT base_url FROM entries WHERE alias = ?1",
        params![alias],
        |row| row.get(0),
    );
    match result {
        Ok(url) => Ok(url),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(_) => Ok(None), // column may not exist on older vaults
    }
}

/// Sets the custom upstream `base_url` for a personal key entry.
/// Pass `None` to clear (proxy will fall back to the provider default).
pub fn set_entry_base_url(alias: &str, base_url: Option<&str>) -> Result<(), String> {
    let conn = open_connection()?;
    set_entry_base_url_on_conn(&conn, alias, base_url)
}

/// G-5 fix (2026-04-23): connection-scoped variant so batch_import can include
/// base_url writes in the same transaction as the entry insert.
pub(crate) fn set_entry_base_url_on_conn(
    conn: &rusqlite::Connection,
    alias: &str,
    base_url: Option<&str>,
) -> Result<(), String> {
    let rows = conn
        .execute(
            "UPDATE entries SET base_url = ?1 WHERE alias = ?2",
            params![base_url, alias],
        )
        .map_err(|e| format!("Failed to set entry base_url: {}", e))?;
    if rows == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }
    Ok(())
}

/// Sets a user-defined local alias for a cached key.
/// Pass `None` to clear the local alias and revert to the server alias.
pub fn set_virtual_key_local_alias(
    virtual_key_id: &str,
    local_alias: Option<&str>,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_alias = ?1, synced_at = strftime('%s', 'now')
          WHERE virtual_key_id = ?2",
        params![local_alias, virtual_key_id],
    )
    .map_err(|e| format!("Failed to update local_alias: {}", e))?;
    Ok(())
}

/// Sets `local_state` for a cached key (e.g., `"active"` or `"synced_inactive"`).
pub fn set_virtual_key_local_state(virtual_key_id: &str, local_state: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_state = ?1, synced_at = strftime('%s', 'now')
          WHERE virtual_key_id = ?2",
        params![local_state, virtual_key_id],
    )
    .map_err(|e| format!("Failed to update local_state: {}", e))?;
    Ok(())
}

/// Updates `share_status` in the local cache (mirrors server state after claim).
pub fn set_virtual_key_share_status_local(
    virtual_key_id: &str,
    share_status: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET share_status = ?1, synced_at = strftime('%s', 'now')
          WHERE virtual_key_id = ?2",
        params![share_status, virtual_key_id],
    )
    .map_err(|e| format!("Failed to update share_status: {}", e))?;
    Ok(())
}

// ---- User profile provider bindings CRUD ----

/// A per-provider key source binding within a user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderBinding {
    pub profile_id: String,
    pub provider_code: String,
    pub key_source_type: CredentialType,
    pub key_source_ref: String, // alias (personal), virtual_key_id (team), or provider_account_id (oauth)
    pub updated_at: Option<i64>,
}

impl ProviderBinding {
    /// Returns key_source_type as a string for backward-compatible comparisons.
    /// Existing callers can use this during incremental migration from string to enum.
    pub fn key_source_type_str(&self) -> &str {
        self.key_source_type.as_str()
    }
}

/// Returns all provider bindings for the given profile (write connection with migrations).
pub fn list_provider_bindings(profile_id: &str) -> Result<Vec<ProviderBinding>, String> {
    query_provider_bindings(&open_connection()?, profile_id)
}

/// Returns all provider bindings for the given profile (read-only, no migrations).
pub fn list_provider_bindings_readonly(profile_id: &str) -> Result<Vec<ProviderBinding>, String> {
    query_provider_bindings(&open_connection_readonly()?, profile_id)
}

fn query_provider_bindings(
    conn: &Connection,
    profile_id: &str,
) -> Result<Vec<ProviderBinding>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT profile_id, provider_code, key_source_type, key_source_ref, updated_at
               FROM user_profile_provider_bindings
              WHERE profile_id = ?1
              ORDER BY provider_code",
        )
        .map_err(|e| format!("Failed to prepare provider bindings query: {}", e))?;

    let rows = stmt
        .query_map(params![profile_id], |row| {
            let raw_type: String = row.get(2)?;
            Ok(ProviderBinding {
                profile_id: row.get(0)?,
                provider_code: row.get(1)?,
                key_source_type: CredentialType::from_db_str(&raw_type),
                key_source_ref: row.get(3)?,
                updated_at: row.get(4).ok(),
            })
        })
        .map_err(|e| format!("Failed to query provider bindings: {}", e))?
        .collect::<SqlResult<Vec<ProviderBinding>>>()
        .map_err(|e| format!("Failed to collect provider bindings: {}", e))?;

    Ok(rows)
}

/// Returns the binding for a specific provider in a profile, or `None`.
pub fn get_provider_binding(
    profile_id: &str,
    provider_code: &str,
) -> Result<Option<ProviderBinding>, String> {
    let conn = open_connection()?;
    let result = conn.query_row(
        "SELECT profile_id, provider_code, key_source_type, key_source_ref, updated_at
           FROM user_profile_provider_bindings
          WHERE profile_id = ?1 AND provider_code = ?2",
        params![profile_id, provider_code],
        |row| {
            let raw_type: String = row.get(2)?;
            Ok(ProviderBinding {
                profile_id: row.get(0)?,
                provider_code: row.get(1)?,
                key_source_type: CredentialType::from_db_str(&raw_type),
                key_source_ref: row.get(3)?,
                updated_at: row.get(4).ok(),
            })
        },
    );
    match result {
        Ok(b) => Ok(Some(b)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get provider binding: {}", e)),
    }
}

/// Kimi family provider_code 集合 — 互斥单元。
///
/// 2026-05-08 Kimi family 互斥落地(详见 roadmap20260320/技术实现/update/
/// 20260508-Kimi-family互斥-active-env统一KIMI写入.md 决策 #1 + #2):
/// 同 profile 内最多 1 个 active primary binding,任一激活会 deactivate 其它两个。
///
/// **包含 deprecated 'kimi'**: rc.1 时期写入的 binding row 仍可能 provider_code='kimi'
/// (no migration),互斥识别必须包含此字面量;否则老 binding 与新 kimi_code/moonshot
/// 同时活时,active.env 的 KIMI_* 写入会出现覆盖竞态。
///
/// **不用 registry-driven**: deprecated 'kimi' 已不在 provider_registry.yaml 顶级
/// entries(仅作 oauth_alias on kimi_code),按 family 读 registry 会漏。硬编码三元素
/// 数组虽然散弹,但稳定可读,family 成员变动需要显式审视(不会无意中漂移)。
///
/// `pub(crate)` 暴露给同 crate 内 profile_activation::auto_assign_primaries_for_key
/// (fill-empty-only 检查)和 profile_activation::regenerate_active_env(corrupt state
/// pre-scan)使用,避免散弹复制粘贴。
pub(crate) const KIMI_FAMILY_CODES: &[&str] = &["kimi_code", "moonshot", "kimi"];

/// Sets (upserts) a provider binding in a profile.
///
/// 2026-05-08 Kimi family 互斥强制点(详见上面 KIMI_FAMILY_CODES doc):
/// 写入 Kimi family 任一 provider_code 之前,先在同事务里 DELETE 同 family 其它
/// 成员的 binding。这样所有 lifecycle event(Switched/Added/team-sync/reconcile)
/// 自动遵守"同 profile 内 Kimi family 最多 1 个 primary"的数据库不变量,**不需
/// 要在每个调用方分别加互斥检查**。
///
/// 注意:此函数仅保证"如果写,则同 family 仅一个"。**caller 是否应该写**(例如
/// Added 路径的 fill-empty-only 语义)由调用方判断;此函数不做 fill-empty 决策。
pub fn set_provider_binding(
    profile_id: &str,
    provider_code: &str,
    key_source_type: &str,
    key_source_ref: &str,
) -> Result<(), String> {
    let mut conn = open_connection()?;
    let tx = conn.transaction().map_err(|e| format!("begin tx: {}", e))?;

    // family 互斥: 写入 Kimi family code 时,先 deactivate 同 family 其它成员
    if KIMI_FAMILY_CODES.contains(&provider_code) {
        for other in KIMI_FAMILY_CODES.iter().filter(|c| **c != provider_code) {
            tx.execute(
                "DELETE FROM user_profile_provider_bindings
                  WHERE profile_id = ?1 AND provider_code = ?2",
                params![profile_id, other],
            )
            .map_err(|e| format!("family mutex deactivate {}: {}", other, e))?;
        }
    }

    // UPSERT 主体写入
    tx.execute(
        "INSERT INTO user_profile_provider_bindings
            (profile_id, provider_code, key_source_type, key_source_ref, updated_at)
         VALUES (?1, ?2, ?3, ?4, strftime('%s', 'now'))
         ON CONFLICT (profile_id, provider_code) DO UPDATE SET
            key_source_type = excluded.key_source_type,
            key_source_ref  = excluded.key_source_ref,
            updated_at      = excluded.updated_at",
        params![profile_id, provider_code, key_source_type, key_source_ref],
    )
    .map_err(|e| format!("Failed to set provider binding: {}", e))?;

    tx.commit()
        .map_err(|e| format!("commit binding tx: {}", e))?;
    Ok(())
}

/// Removes a provider binding from a profile.
/// Returns true if a row was actually deleted.
pub fn remove_provider_binding(profile_id: &str, provider_code: &str) -> Result<bool, String> {
    let conn = open_connection()?;
    let rows = conn
        .execute(
            "DELETE FROM user_profile_provider_bindings
              WHERE profile_id = ?1 AND provider_code = ?2",
            params![profile_id, provider_code],
        )
        .map_err(|e| format!("Failed to remove provider binding: {}", e))?;
    Ok(rows > 0)
}

/// Phase 3B C (2026-05-11): removes ALL bindings of a given `key_source_type`,
/// regardless of `key_source_ref`. Used by `aikey logout` to wipe team-key
/// bindings (`key_source_type='managed_virtual_key'`) so a subsequent login
/// to a different account doesn't reactivate stale rows pointing at vk_ids
/// the new account doesn't own — the "ghost binding" issue documented in
/// requirements/2026-05-11-aikey-web-local-first-team-merge.md R3.
///
/// Returns the list of (provider_code, key_source_ref) tuples whose bindings
/// were removed, so the caller can refresh active.env / proxy state for the
/// affected providers.
pub fn remove_bindings_by_key_source_type(
    profile_id: &str,
    key_source_type: &str,
) -> Result<Vec<(String, String)>, String> {
    let conn = open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT provider_code, key_source_ref FROM user_profile_provider_bindings
              WHERE profile_id = ?1 AND key_source_type = ?2",
        )
        .map_err(|e| format!("Failed to prepare bulk binding cleanup query: {}", e))?;
    let affected: Vec<(String, String)> = stmt
        .query_map(params![profile_id, key_source_type], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| format!("Failed to query affected bindings: {}", e))?
        .collect::<SqlResult<Vec<(String, String)>>>()
        .map_err(|e| format!("Failed to collect affected bindings: {}", e))?;
    if !affected.is_empty() {
        conn.execute(
            "DELETE FROM user_profile_provider_bindings
              WHERE profile_id = ?1 AND key_source_type = ?2",
            params![profile_id, key_source_type],
        )
        .map_err(|e| format!("Failed to bulk-remove bindings by type: {}", e))?;
    }
    Ok(affected)
}

/// Removes all bindings that reference a specific key source.
/// Used when a key is deleted to clean up any dangling bindings.
/// Returns the list of provider_codes whose bindings were removed.
pub fn remove_bindings_by_key_source(
    profile_id: &str,
    key_source_type: &str,
    key_source_ref: &str,
) -> Result<Vec<String>, String> {
    let conn = open_connection()?;

    let mut stmt = conn
        .prepare(
            "SELECT provider_code FROM user_profile_provider_bindings
              WHERE profile_id = ?1 AND key_source_type = ?2 AND key_source_ref = ?3",
        )
        .map_err(|e| format!("Failed to prepare binding cleanup query: {}", e))?;

    let affected: Vec<String> = stmt
        .query_map(
            params![profile_id, key_source_type, key_source_ref],
            |row| row.get(0),
        )
        .map_err(|e| format!("Failed to query affected bindings: {}", e))?
        .collect::<SqlResult<Vec<String>>>()
        .map_err(|e| format!("Failed to collect affected bindings: {}", e))?;

    if !affected.is_empty() {
        conn.execute(
            "DELETE FROM user_profile_provider_bindings
              WHERE profile_id = ?1 AND key_source_type = ?2 AND key_source_ref = ?3",
            params![profile_id, key_source_type, key_source_ref],
        )
        .map_err(|e| format!("Failed to remove bindings for key: {}", e))?;
    }

    Ok(affected)
}

// ---------------------------------------------------------------------------
// Provider OAuth accounts (read-only from CLI side; proxy manages tokens)
// ---------------------------------------------------------------------------

/// Provider account metadata (no token data — tokens are managed by proxy).
#[derive(Debug, Clone)]
pub struct ProviderAccountInfo {
    pub provider_account_id: String,
    pub provider: String,
    pub auth_type: String,
    pub credential_type: CredentialType,
    pub status: String,
    pub external_id: Option<String>,
    /// Original/immutable account identity from the OAuth provider (typically
    /// email, falls back to user_id / external_id when the upstream login
    /// flow doesn't return an email). Renames must NOT touch this field — see
    /// `local_alias`.
    pub display_identity: Option<String>,
    pub org_uuid: Option<String>,
    pub account_tier: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Monotonic counter of recorded usages, bumped by
    /// `_internal vault-op record_usage`. Added with the route_token /
    /// telemetry batch (current registry: v1.0.4-alpha); old vaults default
    /// to 0 (NOT NULL DEFAULT 0 on the column).
    pub use_count: Option<i64>,
    /// User-set local label written by the OAuth rename path. NULL means
    /// "never renamed"; callers should fall back to `display_identity` for
    /// a stable label. Added v1.0.1-alpha.1 (post-GA); pre-migration vaults
    /// project NULL via the column-list fallback below. The split
    /// (display_identity vs local_alias) lets the UI detect "this account
    /// has been renamed" by `local_alias.is_some()` and render the original
    /// identity as a separate row instead of overwriting it.
    pub local_alias: Option<String>,
    /// Generic per-account extension JSON blob — see
    /// `storage::SecretMetadata::extra` for the contract. First consumer
    /// is `$.last_test` (connectivity-test result), written by
    /// `_internal vault-op record_test_result`. Any future per-account
    /// fact nests as a sibling subkey via the same json_set() write path.
    pub extra: Option<serde_json::Value>,
}

impl ProviderAccountInfo {
    /// User-facing label following the v1.0.1-alpha.1 precedence:
    ///   local_alias (if user has renamed) → display_identity → account_id.
    /// Use this anywhere the CLI prints "this account" / "this key" to the
    /// user, so renamed accounts show the new alias instead of the
    /// original email. For sites that *specifically* want the immutable
    /// upstream identity (audit logs, dedup keys, OAuth-provider lookups)
    /// keep reading `display_identity` directly.
    pub fn effective_label(&self) -> &str {
        self.local_alias
            .as_deref()
            .or(self.display_identity.as_deref())
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.provider_account_id)
    }
}

fn row_to_provider_account(row: &rusqlite::Row) -> rusqlite::Result<ProviderAccountInfo> {
    let raw_ctype: String = row.get(3)?;
    // `extra` stored as TEXT (JSON object); parse opportunistically — a
    // corrupt blob (writers always go through json_set) is treated the
    // same as None so it can't break the list query.
    let extra = row
        .get::<_, Option<String>>(13)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    Ok(ProviderAccountInfo {
        provider_account_id: row.get(0)?,
        provider: row.get(1)?,
        auth_type: row.get(2)?,
        credential_type: CredentialType::from_db_str(&raw_ctype),
        status: row.get(4)?,
        external_id: row.get(5)?,
        display_identity: row.get(6)?,
        org_uuid: row.get(7)?,
        account_tier: row.get(8)?,
        created_at: row.get(9)?,
        last_used_at: row.get(10)?,
        use_count: row.get(11).ok(),
        local_alias: row.get(12).ok().flatten(),
        extra,
    })
}

// Four-tier column list cascade — each tier corresponds to a vault that
// stopped at a particular schema generation:
//   FULL              — post 2026-05-22 (has use_count AND local_alias AND extra)
//   NO_EXTRA          — post v1.0.1-alpha.1 but pre extra (literal NULL)
//   NO_LOCAL_ALIAS    — has use_count but predates v1.0.1-alpha.1
//                       (literal NULL for local_alias + extra)
//   LEGACY            — predates use_count too (literal 0 + NULL + NULL)
// Callers prepare(FULL) → fallback NO_EXTRA → fallback NO_LOCAL_ALIAS →
// fallback LEGACY. Read-only paths that open a vault without running
// migrations rely on this cascade; write paths see FULL after upgrade_all.
const PROVIDER_ACCOUNT_COLUMNS_FULL: &str =
    "provider_account_id, provider, auth_type, credential_type, status, \
     external_id, display_identity, org_uuid, account_tier, created_at, last_used_at, \
     use_count, local_alias, extra";
const PROVIDER_ACCOUNT_COLUMNS_NO_EXTRA: &str =
    "provider_account_id, provider, auth_type, credential_type, status, \
     external_id, display_identity, org_uuid, account_tier, created_at, last_used_at, \
     use_count, local_alias, NULL";
const PROVIDER_ACCOUNT_COLUMNS_NO_LOCAL_ALIAS: &str =
    "provider_account_id, provider, auth_type, credential_type, status, \
     external_id, display_identity, org_uuid, account_tier, created_at, last_used_at, \
     use_count, NULL, NULL";
const PROVIDER_ACCOUNT_COLUMNS_LEGACY: &str =
    "provider_account_id, provider, auth_type, credential_type, status, \
     external_id, display_identity, org_uuid, account_tier, created_at, last_used_at, \
     0, NULL, NULL";

/// List all provider OAuth accounts (write connection with migrations).
pub fn list_provider_accounts() -> Result<Vec<ProviderAccountInfo>, String> {
    query_provider_accounts(&open_connection()?)
}

/// List all provider OAuth accounts (read-only, no migrations).
pub fn list_provider_accounts_readonly() -> Result<Vec<ProviderAccountInfo>, String> {
    match open_connection_readonly() {
        Ok(conn) => query_provider_accounts(&conn),
        Err(_) => Ok(vec![]), // vault doesn't exist or can't open — no accounts
    }
}

fn query_provider_accounts(conn: &Connection) -> Result<Vec<ProviderAccountInfo>, String> {
    // Four-tier prepare cascade — see PROVIDER_ACCOUNT_COLUMNS_* constants
    // for the schema generations each tier corresponds to. If all fail,
    // the table itself doesn't exist yet (very old vault) — return empty,
    // same as before.
    let mut stmt = match conn
        .prepare(&format!(
            "SELECT {} FROM provider_accounts ORDER BY provider, created_at",
            PROVIDER_ACCOUNT_COLUMNS_FULL
        ))
        .or_else(|_| {
            conn.prepare(&format!(
                "SELECT {} FROM provider_accounts ORDER BY provider, created_at",
                PROVIDER_ACCOUNT_COLUMNS_NO_EXTRA
            ))
        })
        .or_else(|_| {
            conn.prepare(&format!(
                "SELECT {} FROM provider_accounts ORDER BY provider, created_at",
                PROVIDER_ACCOUNT_COLUMNS_NO_LOCAL_ALIAS
            ))
        })
        .or_else(|_| {
            conn.prepare(&format!(
                "SELECT {} FROM provider_accounts ORDER BY provider, created_at",
                PROVIDER_ACCOUNT_COLUMNS_LEGACY
            ))
        }) {
        Ok(s) => s,
        Err(_) => return Ok(vec![]),
    };

    let rows = stmt
        .query_map([], |row| row_to_provider_account(row))
        .map_err(|e| format!("Failed to query provider accounts: {}", e))?
        .collect::<SqlResult<Vec<ProviderAccountInfo>>>()
        .map_err(|e| format!("Failed to collect provider accounts: {}", e))?;

    Ok(rows)
}

/// Get a specific provider account by ID.
pub fn get_provider_account(id: &str) -> Result<Option<ProviderAccountInfo>, String> {
    let conn = open_connection()?;
    let result = conn
        .query_row(
            &format!(
                "SELECT {} FROM provider_accounts WHERE provider_account_id = ?1",
                PROVIDER_ACCOUNT_COLUMNS_FULL
            ),
            params![id],
            |row| row_to_provider_account(row),
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM provider_accounts WHERE provider_account_id = ?1",
                    PROVIDER_ACCOUNT_COLUMNS_NO_EXTRA
                ),
                params![id],
                |row| row_to_provider_account(row),
            ),
        })
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM provider_accounts WHERE provider_account_id = ?1",
                    PROVIDER_ACCOUNT_COLUMNS_NO_LOCAL_ALIAS
                ),
                params![id],
                |row| row_to_provider_account(row),
            ),
        })
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM provider_accounts WHERE provider_account_id = ?1",
                    PROVIDER_ACCOUNT_COLUMNS_LEGACY
                ),
                params![id],
                |row| row_to_provider_account(row),
            ),
        });
    match result {
        Ok(info) => Ok(Some(info)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get provider account: {}", e)),
    }
}

/// Find provider accounts by provider code (e.g., "claude", "codex", "kimi").
pub fn get_provider_accounts_by_provider(
    provider: &str,
) -> Result<Vec<ProviderAccountInfo>, String> {
    let conn = open_connection()?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM provider_accounts WHERE provider = ?1 ORDER BY created_at",
            PROVIDER_ACCOUNT_COLUMNS_FULL
        ))
        .or_else(|_| {
            conn.prepare(&format!(
                "SELECT {} FROM provider_accounts WHERE provider = ?1 ORDER BY created_at",
                PROVIDER_ACCOUNT_COLUMNS_NO_EXTRA
            ))
        })
        .or_else(|_| {
            conn.prepare(&format!(
                "SELECT {} FROM provider_accounts WHERE provider = ?1 ORDER BY created_at",
                PROVIDER_ACCOUNT_COLUMNS_NO_LOCAL_ALIAS
            ))
        })
        .or_else(|_| {
            conn.prepare(&format!(
                "SELECT {} FROM provider_accounts WHERE provider = ?1 ORDER BY created_at",
                PROVIDER_ACCOUNT_COLUMNS_LEGACY
            ))
        })
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map(params![provider], |row| row_to_provider_account(row))
        .map_err(|e| format!("Failed to query: {}", e))?
        .collect::<SqlResult<Vec<ProviderAccountInfo>>>()
        .map_err(|e| format!("Failed to collect: {}", e))?;

    Ok(rows)
}

/// Find a provider account by external_id (for dedup on re-login).
pub fn get_provider_account_by_external_id(
    provider: &str,
    external_id: &str,
) -> Result<Option<ProviderAccountInfo>, String> {
    let conn = open_connection()?;
    let result = conn
        .query_row(
            &format!(
                "SELECT {} FROM provider_accounts WHERE provider = ?1 AND external_id = ?2",
                PROVIDER_ACCOUNT_COLUMNS_FULL
            ),
            params![provider, external_id],
            |row| row_to_provider_account(row),
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM provider_accounts WHERE provider = ?1 AND external_id = ?2",
                    PROVIDER_ACCOUNT_COLUMNS_NO_EXTRA
                ),
                params![provider, external_id],
                |row| row_to_provider_account(row),
            ),
        })
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM provider_accounts WHERE provider = ?1 AND external_id = ?2",
                    PROVIDER_ACCOUNT_COLUMNS_NO_LOCAL_ALIAS
                ),
                params![provider, external_id],
                |row| row_to_provider_account(row),
            ),
        })
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Err(e),
            _ => conn.query_row(
                &format!(
                    "SELECT {} FROM provider_accounts WHERE provider = ?1 AND external_id = ?2",
                    PROVIDER_ACCOUNT_COLUMNS_LEGACY
                ),
                params![provider, external_id],
                |row| row_to_provider_account(row),
            ),
        });
    match result {
        Ok(info) => Ok(Some(info)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!(
            "Failed to get provider account by external_id: {}",
            e
        )),
    }
}

/// Atomically bump usage telemetry on an OAuth provider account: set
/// `last_used_at` to the caller-supplied unix seconds, increment
/// `use_count`. Returns rows affected (0 if id is unknown). Proxy calls
/// this via `_internal vault-op record_usage` after a successful
/// credential resolution.
pub fn bump_oauth_usage(id: &str, ts: i64) -> Result<usize, String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE provider_accounts SET last_used_at = ?1, use_count = COALESCE(use_count, 0) + 1 WHERE provider_account_id = ?2",
        params![ts, id],
    )
    .map_err(|e| format!("bump_oauth_usage UPDATE: {}", e))
}

/// Atomically merge a value into the `extra` JSON column at the given JSON
/// path (e.g. `$.last_test`). See `storage::merge_entry_extra` for the
/// concurrent-safety rationale. `value_json` must be valid JSON.
/// Returns rows affected; 0 means the id is unknown.
pub fn merge_oauth_extra(id: &str, json_path: &str, value_json: &str) -> Result<usize, String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE provider_accounts SET extra = json_set(COALESCE(extra, '{}'), ?1, json(?2)) WHERE provider_account_id = ?3",
        params![json_path, value_json, id],
    )
    .map_err(|e| format!("merge_oauth_extra UPDATE: {}", e))
}

/// Atomically merge a value into the `extra` JSON column on
/// `managed_virtual_keys_cache` at the given JSON path. Same
/// concurrent-safety + payload-shape contract as `merge_entry_extra` /
/// `merge_oauth_extra`. Lookup is by `virtual_key_id` (the team row's
/// stable identifier — `local_alias` and the server alias may both
/// change). Returns rows affected; 0 means the id is unknown.
///
/// This is the team-row companion to merge_entry_extra / merge_oauth_extra
/// and only became safe to surface after the 2026-05-22 upsert refactor
/// (see `upsert_virtual_key_cache` doc): under the old INSERT OR REPLACE
/// every `aikey key sync` would wipe whatever this writer just wrote.
pub fn merge_team_extra(
    virtual_key_id: &str,
    json_path: &str,
    value_json: &str,
) -> Result<usize, String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache SET extra = json_set(COALESCE(extra, '{}'), ?1, json(?2)) WHERE virtual_key_id = ?3",
        params![json_path, value_json, virtual_key_id],
    )
    .map_err(|e| format!("merge_team_extra UPDATE: {}", e))
}

/// Delete a provider account and its tokens (cascade not enforced by SQLite,
/// so we delete both explicitly).
pub fn delete_provider_account(id: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "DELETE FROM provider_account_tokens WHERE provider_account_id = ?1",
        params![id],
    )
    .map_err(|e| format!("Failed to delete provider account tokens: {}", e))?;

    conn.execute(
        "DELETE FROM provider_accounts WHERE provider_account_id = ?1",
        params![id],
    )
    .map_err(|e| format!("Failed to delete provider account: {}", e))?;

    Ok(())
}

/// Get the token expiry timestamp for a provider account (no decryption needed).
pub fn get_provider_token_expires_at(account_id: &str) -> Result<Option<i64>, String> {
    let conn = open_connection()?;
    let result = conn.query_row(
        "SELECT token_expires_at FROM provider_account_tokens WHERE provider_account_id = ?1",
        params![account_id],
        |row| row.get::<_, Option<i64>>(0),
    );
    match result {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get token expiry: {}", e)),
    }
}

/// Update the status of a provider account.
pub fn update_provider_account_status(id: &str, status: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE provider_accounts SET status = ?2 WHERE provider_account_id = ?1",
        params![id, status],
    )
    .map_err(|e| format!("Failed to update provider account status: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod key_material_reachable_tests {
    use super::*;

    /// Build a minimal cache entry with only the two fields the predicate reads
    /// (ciphertext + share_status) varied; everything else is a benign default.
    fn entry(ciphertext: Option<Vec<u8>>, share_status: &str) -> VirtualKeyCacheEntry {
        VirtualKeyCacheEntry {
            virtual_key_id: "vk-1".into(),
            org_id: "org".into(),
            seat_id: "seat".into(),
            alias: "k".into(),
            provider_code: "anthropic".into(),
            protocol_type: "anthropic".into(),
            base_url: String::new(),
            credential_id: "c".into(),
            credential_revision: String::new(),
            virtual_key_revision: String::new(),
            key_status: "active".into(),
            share_status: share_status.into(),
            local_state: "synced_inactive".into(),
            expires_at: None,
            provider_key_nonce: None,
            provider_key_ciphertext: ciphertext,
            synced_at: 0,
            local_alias: None,
            supported_providers: vec![],
            provider_base_urls: std::collections::HashMap::new(),
            owner_account_id: None,
            extra: None,
            oauth_group_id: None,
            group_accounts: None,
            routing_config: None,
        }
    }

    #[test]
    fn central_claimed_key_reachable_on_cluster_without_ciphertext() {
        // The central-key fix: no local ciphertext + on a cluster + claimed → the
        // proxy routes via the central node, so the key IS usable. Previously this
        // returned false → picker hid it, web set-route 422'd it.
        assert!(entry(None, "claimed").key_material_reachable(true));
    }

    #[test]
    fn no_ciphertext_off_cluster_not_reachable() {
        // Off-cluster with no delivered ciphertext = genuinely not delivered.
        assert!(!entry(None, "claimed").key_material_reachable(false));
    }

    #[test]
    fn pending_claim_not_reachable_even_on_cluster() {
        // An unclaimed seat must never be treated as usable just because the
        // client is on a cluster.
        assert!(!entry(None, "pending_claim").key_material_reachable(true));
    }

    #[test]
    fn delivered_ciphertext_reachable_regardless_of_cluster() {
        assert!(entry(Some(vec![1, 2, 3]), "claimed").key_material_reachable(false));
        assert!(entry(Some(vec![1, 2, 3]), "claimed").key_material_reachable(true));
    }
}
