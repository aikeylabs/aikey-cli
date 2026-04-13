//! Platform account, team key cache, provider bindings, and config helpers.
//!
//! Extracted from `storage.rs` for maintainability — all items are re-exported
//! by the parent module so existing callers are unaffected.

use super::{open_connection, get_vault_path};
use rusqlite::{params, Result as SqlResult};
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
    pub jwt_token: String,         // current access_token (Bearer)
    pub control_url: String,
    pub logged_in_at: i64,
    pub refresh_token: Option<String>,    // OAuth refresh token; None on legacy rows
    pub token_expires_at: Option<i64>,    // Unix epoch when access_token expires
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
        params![account_id, email, access_token, control_url, refresh_token, token_expires_at],
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
    pub key_type: String,
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
        key_type: key_type.unwrap_or_default(),
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
    for k in &[ACTIVE_KEY_TYPE_KEY, ACTIVE_KEY_REF_KEY, ACTIVE_KEY_PROVIDERS_KEY] {
        conn.execute(
            "DELETE FROM config WHERE key = ?1",
            params![k],
        )
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
    ).ok()
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
}

/// Inserts or replaces a cache entry.
/// `provider_key_nonce` / `provider_key_ciphertext` may be `None` until the key is accepted.
pub fn upsert_virtual_key_cache(entry: &VirtualKeyCacheEntry) -> Result<(), String> {
    let conn = open_connection()?;
    let supported_providers_json = serde_json::to_string(&entry.supported_providers)
        .unwrap_or_else(|_| "[]".to_string());
    let provider_base_urls_json = serde_json::to_string(&entry.provider_base_urls)
        .unwrap_or_else(|_| "{}".to_string());
    conn.execute(
        "INSERT OR REPLACE INTO managed_virtual_keys_cache (
             virtual_key_id, org_id, seat_id, alias,
             provider_code, protocol_type, base_url,
             credential_id, credential_revision, virtual_key_revision,
             key_status, share_status, local_state,
             expires_at,
             provider_key_nonce, provider_key_ciphertext,
             cache_schema_version, synced_at,
             local_alias, supported_providers,
             provider_base_urls, owner_account_id
         ) VALUES (
             ?1,  ?2,  ?3,  ?4,
             ?5,  ?6,  ?7,
             ?8,  ?9,  ?10,
             ?11, ?12, ?13,
             ?14,
             ?15, ?16,
             1,   strftime('%s', 'now'),
             ?17, ?18,
             ?19, ?20
         )",
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
        ],
    )
    .map_err(|e| format!("Failed to upsert virtual key cache: {}", e))?;
    Ok(())
}

/// Parses a JSON array string into a `Vec<String>`, returning empty vec on failure.
fn parse_providers_json(json: Option<String>) -> Vec<String> {
    json.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Parses a JSON object string into a `HashMap<String, String>`, returning empty map on failure.
fn parse_base_urls_json(json: Option<String>) -> std::collections::HashMap<String, String> {
    json.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Returns all cached virtual key entries.
pub fn list_virtual_key_cache() -> Result<Vec<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(vec![]);
    }
    let conn = open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT virtual_key_id, org_id, seat_id, alias,
                    provider_code, protocol_type, base_url,
                    credential_id, credential_revision, virtual_key_revision,
                    key_status, share_status, local_state,
                    expires_at,
                    provider_key_nonce, provider_key_ciphertext,
                    synced_at, local_alias, supported_providers,
                    provider_base_urls, owner_account_id
               FROM managed_virtual_keys_cache
              ORDER BY COALESCE(local_alias, alias)",
        )
        .map_err(|e| format!("Failed to prepare list query: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
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
            })
        })
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
    let result = conn.query_row(
        "SELECT virtual_key_id, org_id, seat_id, alias,
                provider_code, protocol_type, base_url,
                credential_id, credential_revision, virtual_key_revision,
                key_status, share_status, local_state,
                expires_at,
                provider_key_nonce, provider_key_ciphertext,
                synced_at, local_alias, supported_providers,
                provider_base_urls, owner_account_id
           FROM managed_virtual_keys_cache
          WHERE virtual_key_id = ?1",
        params![virtual_key_id],
        |row| {
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
            })
        },
    );
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
    let result = conn.query_row(
        "SELECT virtual_key_id, org_id, seat_id, alias,
                provider_code, protocol_type, base_url,
                credential_id, credential_revision, virtual_key_revision,
                key_status, share_status, local_state,
                expires_at,
                provider_key_nonce, provider_key_ciphertext,
                synced_at, local_alias, supported_providers,
                provider_base_urls, owner_account_id
           FROM managed_virtual_keys_cache
          WHERE local_alias = ?1 OR alias = ?1
          ORDER BY CASE WHEN local_alias = ?1 THEN 0 ELSE 1 END
          LIMIT 1",
        params![alias],
        |row| {
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
            })
        },
    );
    match result {
        Ok(entry) => Ok(Some(entry)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get virtual key cache entry by alias: {}", e)),
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
    let rows = conn.execute(
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
    let json = serde_json::to_string(providers)
        .map_err(|e| format!("Failed to serialize providers: {}", e))?;
    let conn = open_connection()?;
    let rows = conn.execute(
        "UPDATE entries SET supported_providers = ?1 WHERE alias = ?2",
        params![json, alias],
    ).map_err(|e| format!("Failed to set supported_providers: {}", e))?;
    if rows == 0 { return Err(format!("Entry '{}' not found", alias)); }
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
    let rows = conn.execute(
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
    pub key_source_type: String,   // "personal" or "team"
    pub key_source_ref: String,    // alias (personal) or virtual_key_id (team)
    pub updated_at: Option<i64>,
}

/// Returns all provider bindings for the given profile, ordered by provider_code.
pub fn list_provider_bindings(profile_id: &str) -> Result<Vec<ProviderBinding>, String> {
    let conn = open_connection()?;
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
            Ok(ProviderBinding {
                profile_id:      row.get(0)?,
                provider_code:   row.get(1)?,
                key_source_type: row.get(2)?,
                key_source_ref:  row.get(3)?,
                updated_at:      row.get(4).ok(),
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
            Ok(ProviderBinding {
                profile_id:      row.get(0)?,
                provider_code:   row.get(1)?,
                key_source_type: row.get(2)?,
                key_source_ref:  row.get(3)?,
                updated_at:      row.get(4).ok(),
            })
        },
    );
    match result {
        Ok(b) => Ok(Some(b)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get provider binding: {}", e)),
    }
}

/// Sets (upserts) a provider binding in a profile.
pub fn set_provider_binding(
    profile_id: &str,
    provider_code: &str,
    key_source_type: &str,
    key_source_ref: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
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
    Ok(())
}

/// Removes a provider binding from a profile.
/// Returns true if a row was actually deleted.
pub fn remove_provider_binding(
    profile_id: &str,
    provider_code: &str,
) -> Result<bool, String> {
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
        .query_map(params![profile_id, key_source_type, key_source_ref], |row| {
            row.get(0)
        })
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
