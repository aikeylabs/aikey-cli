//! Database migrations for the CLI vault.
//!
//! Each version module has upgrade() and rollback() functions.
//! Registry is ordered oldest → newest. Rollback walks newest → oldest.
//!
//! Adding a new version:
//!   1. Create a `pub mod v1_0_3_alpha { ... }` with upgrade() + rollback()
//!   2. Add it to VERSIONS array below
//!   3. Call it from upgrade_all()

use rusqlite::Connection;

/// Version entry for the migration registry.
struct VersionMigration {
    version: &'static str,
    upgrade: fn(&Connection) -> Result<(), String>,
    rollback: fn(&Connection) -> Result<(), String>,
}

/// Ordered registry: oldest to newest. Each entry's rollback undoes its upgrade.
static VERSIONS: &[VersionMigration] = &[
    // v1.0.0 is the canonical baseline (post-2026-05-01 fold + 2026-05-06
    // stub cleanup). It owns the entire vault schema bootstrap.
    // Defense A: baseline.rollback() is a no-op so even if rollback_to()
    // reached it (defense B at the runner level also rejects unknown
    // targets), vault tables are NEVER dropped.
    VersionMigration {
        version: "1.0.0",
        upgrade: v1_0_0_baseline::upgrade,
        rollback: v1_0_0_baseline::rollback,
    },
    // 2026-05-08 baseline-fold history (pre-GA changes folded into v1.0.0):
    //   - provider_accounts.local_alias 列 (原 v1.0.1-alpha.1,误命名;baseline
    //     CREATE TABLE 已含此列,alpha.1 module 删除,无 vault 受影响);
    //   - Kimi 双平台拆分: provider_code 'kimi' → 'kimi_code' / 'moonshot'。
    //     **不做数据迁移**:旧 rc.1 testers 走 `uninstall.sh + reinstall` 路径
    //     (与 2026-05-01 把 v1.0.{2..5}-alpha 折回 baseline 时同样的 "no
    //     upgrade path" 处理); CLI provider_registry.yaml 仍把 'kimi' 留作
    //     deprecated alias,防御性兜底。
    //
    // Why fold pattern: 当前 released = v1.0.0-rc.1; next pending = v1.0.0-rc.2;
    // pre-GA 改动直接进 baseline 是项目惯例 (workflow/CD/version-naming.md §3),
    // CLI vault 无 schema_migrations 跟踪表(纯 idempotency 模型),fold 零孤儿风险。
    //
    // 详见 roadmap20260320/技术实现/update/20260508-Kimi双平台拆分-moonshot与kimi-code.md
    // §"版本周期决策" 节。
];

/// Run all upgrades up to the current binary version.
pub fn upgrade_all(conn: &Connection) -> Result<(), String> {
    for v in VERSIONS {
        (v.upgrade)(conn)?;
    }
    Ok(())
}

/// Rollback vault schema from current state down to target version.
/// Walks the registry in reverse, calling rollback() for each version
/// that is AFTER the target. Supports crossing multiple versions.
///
/// Example: current=v1.0.4, target=v1.0.1
///   → rollback v1.0.4, v1.0.3, v1.0.2 (in that order)
///   → stop (v1.0.1 is the target, not rolled back)
///
/// Defense B (D plan PR8): rolling back to a target NOT in the registry
/// is rejected up-front. The legacy behavior fell through to
/// "rollback everything" on unknown target, which silently destroyed
/// version-introduced tables (and would have destroyed baseline tables
/// too if v1_0_0_baseline.rollback weren't a no-op — defense A). This
/// function now returns Err for unknown targets and leaves the vault
/// untouched. Historical aliases ("v1.0.1-alpha", "v1.0.1-baseline") are
/// recognised and mapped to the canonical "v1.0.0" baseline, so muscle
/// memory from pre-baseline-fold typings still works.
pub fn rollback_to(conn: &Connection, target: &str) -> Result<(), String> {
    let target_norm = target.strip_prefix('v').unwrap_or(target);

    // Recognise published-version aliases for the baseline. Users typed
    // `aikey db rollback --to v1.0.1-alpha` for the entire pre-D era;
    // accepting it keeps the muscle memory working without weakening
    // the unknown-target rejection.
    // Post-2026-05-01 baseline fold: the legacy registry name
    // "1.0.1-baseline" + the public-tag forms "v1.0.1-alpha" / "v1.0.1"
    // all alias to the new canonical baseline "1.0.0". Mirrors the same
    // alias map in aikey-config-tool/pkg/dbmigrate/versions/registry.go.
    let target_canonical = match target_norm {
        "1.0.1-alpha" | "1.0.1" | "1.0.1-baseline" => "1.0.0",
        other => other,
    };

    let target_idx = VERSIONS.iter().position(|v| v.version == target_canonical);
    let target_idx = match target_idx {
        Some(idx) => idx,
        None => {
            eprintln!(
                "[db rollback] target {} not in registry — refusing to rollback (safe-no-op)",
                target
            );
            return Err(format!("unknown target version: {}", target));
        }
    };

    // Versions strictly after target_idx are rolled back; the target
    // itself stays.
    let start = target_idx + 1;

    if start >= VERSIONS.len() {
        eprintln!(
            "[db rollback] Nothing to rollback (target={} is current or newer)",
            target
        );
        return Ok(());
    }

    // Walk newest → oldest
    for i in (start..VERSIONS.len()).rev() {
        let v = &VERSIONS[i];
        eprintln!("[db rollback] Rolling back {}", v.version);
        (v.rollback)(conn)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// v1.0.0 — canonical vault baseline (post-2026-05-06 stub cleanup)
// ---------------------------------------------------------------------------
//
// History: this module was originally `v_1_0_1_baseline` registered as
// "1.0.1-baseline" (Order 1010). On 2026-05-01 it was renamed and
// promoted to the canonical v1.0.0 baseline (Order 1000). On 2026-05-06
// the 4 pre-baseline alpha modules (v1_0_{2,3,4,5}_alpha) were physically
// deleted; their CREATE TABLE statements (provider_accounts +
// provider_account_tokens + platform_account.refresh_token /
// token_expires_at) are now part of THIS baseline module.
//
// Why baseline as code: previously the CLI vault's initial schema lived in
// storage.rs::apply_migrations, outside the migration registry. That meant
// rollback_to() with an unknown target would fall through to "rollback
// everything", and version modules' rollbacks would happily DROP the
// version-introduced tables — but the baseline tables were never
// registered, so they were untouched and the user was left with an
// inconsistent partial-state vault.
//
// Defense A: baseline.rollback() is intentionally a no-op. Even if
// rollback_to("v0.0.0-fake") falls through to "rollback all" (defense B
// at the runner level prevents this — defense in depth), the baseline
// tables ARE retained because there's nothing to drop.

pub mod v1_0_0_baseline {
    use rusqlite::{params, Connection};

    /// Returns true if the given column exists on the given table.
    /// Module-private duplicate of storage.rs's old has_column — moved
    /// here so storage.rs has no migration-specific helpers left.
    fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name=?1",
                table
            ),
            [column],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false)
    }

    /// Adds a column to a table if it does not already exist.
    fn ensure_column(conn: &Connection, table: &str, col: &str, ddl: &str) -> Result<(), String> {
        if !has_column(conn, table, col) {
            conn.execute(ddl, [])
                .map_err(|e| format!("Failed to add {}.{}: {}", table, col, e))?;
        }
        Ok(())
    }

    /// Forward migration: ensure the baseline vault schema. All statements
    /// are guarded with IF NOT EXISTS or has_column probes so re-runs are
    /// no-ops. This is the canonical CLI vault baseline — storage.rs no
    /// longer contains parallel DDL.
    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        // Core tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure config table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL UNIQUE,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                version_tag INTEGER NOT NULL DEFAULT 1,
                metadata TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure entries table: {}", e))?;

        // Profiles and bindings
        conn.execute(
            "CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                is_active INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure profiles table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_name TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT 'default',
                alias TEXT NOT NULL,
                FOREIGN KEY (profile_name) REFERENCES profiles(name),
                UNIQUE(profile_name, domain)
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure bindings table: {}", e))?;

        // domain column on older bindings tables (predates the FK above).
        if !has_column(conn, "bindings", "domain") {
            conn.execute(
                "ALTER TABLE bindings ADD COLUMN domain TEXT NOT NULL DEFAULT 'default'",
                [],
            )
            .map_err(|e| format!("Failed to add domain column to bindings: {}", e))?;
        }

        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_profile_domain ON bindings(profile_name, domain)",
            [],
        )
        .map_err(|e| format!("Failed to ensure bindings index: {}", e))?;

        // Events table for usage tracking
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                provider TEXT,
                alias TEXT,
                command TEXT,
                exit_code INTEGER,
                duration_ms INTEGER,
                secrets_count INTEGER,
                error TEXT,
                project TEXT,
                env TEXT,
                profile TEXT,
                ok INTEGER NOT NULL DEFAULT 0,
                error_type TEXT
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure events table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            [],
        )
        .map_err(|e| format!("Failed to ensure events index: {}", e))?;

        // Platform account (global identity).
        // refresh_token + token_expires_at retrofit in 2026-05-06 stub
        // cleanup (was a v1.0.2-alpha ALTER; baseline absorbs natively).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS platform_account (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                account_id        TEXT NOT NULL,
                email             TEXT NOT NULL,
                jwt_token         TEXT NOT NULL,
                control_url       TEXT NOT NULL,
                logged_in_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                refresh_token     TEXT,
                token_expires_at  INTEGER
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure platform_account table: {}", e))?;

        // OAuth provider accounts (Claude, Codex, Kimi).
        // Retrofit in 2026-05-06 stub cleanup: was created by
        // v1_0_3_alpha module (now deleted). All final-state columns
        // (display_identity, local_alias, route_token, use_count)
        // included natively for fresh-install correctness.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS provider_accounts (
                provider_account_id  TEXT PRIMARY KEY,
                provider             TEXT NOT NULL,
                auth_type            TEXT NOT NULL,
                credential_type      TEXT NOT NULL DEFAULT 'personal_oauth_account',
                status               TEXT NOT NULL DEFAULT 'active',
                external_id          TEXT,
                -- display_identity: original/immutable account identity from
                -- the OAuth provider (typically email, falls back to
                -- external_id / alias when the upstream login flow doesn't
                -- return an email). Renames must NOT touch this column —
                -- see local_alias.
                display_identity     TEXT,
                -- local_alias: user-set local label, written by `aikey
                -- rename` and the web Vault rename action. NULL means
                -- \"never renamed\"; callers fall back to display_identity.
                local_alias          TEXT,
                org_uuid             TEXT,
                account_tier         TEXT,
                created_at           INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                last_used_at         INTEGER,
                owner_type           TEXT NOT NULL DEFAULT 'local_user',
                route_token          TEXT,
                use_count            INTEGER NOT NULL DEFAULT 0,
                UNIQUE(provider, external_id)
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure provider_accounts table: {}", e))?;

        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_accounts_route_token \
             ON provider_accounts(route_token) WHERE route_token IS NOT NULL",
            [],
        )
        .map_err(|e| format!("Failed to ensure idx_provider_accounts_route_token: {}", e))?;

        // OAuth tokens (separate table for AES-GCM encrypted access /
        // refresh tokens; see D3 design decision in the original
        // v1_0_3_alpha module's docstring before the 2026-05-06 fold).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS provider_account_tokens (
                provider_account_id      TEXT PRIMARY KEY,
                access_token_nonce       BLOB,
                access_token_ciphertext  BLOB,
                refresh_token_nonce      BLOB,
                refresh_token_ciphertext BLOB,
                token_expires_at         INTEGER,
                token_metadata           TEXT,
                updated_at               INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (provider_account_id) REFERENCES provider_accounts(provider_account_id)
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure provider_account_tokens table: {}", e))?;

        // Team-managed virtual key cache
        conn.execute(
            "CREATE TABLE IF NOT EXISTS managed_virtual_keys_cache (
                virtual_key_id       TEXT PRIMARY KEY,
                org_id               TEXT NOT NULL,
                seat_id              TEXT NOT NULL,
                alias                TEXT NOT NULL,
                provider_code        TEXT NOT NULL,
                protocol_type        TEXT NOT NULL DEFAULT 'openai_compatible',
                base_url             TEXT NOT NULL,
                credential_id        TEXT NOT NULL,
                credential_revision  TEXT NOT NULL,
                virtual_key_revision TEXT NOT NULL,
                key_status           TEXT NOT NULL DEFAULT 'active',
                share_status         TEXT NOT NULL DEFAULT 'pending_claim',
                local_state          TEXT NOT NULL DEFAULT 'synced_inactive',
                expires_at           INTEGER,
                provider_key_nonce      BLOB,
                provider_key_ciphertext BLOB,
                cache_schema_version INTEGER NOT NULL DEFAULT 1,
                synced_at            INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure managed_virtual_keys_cache table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mvkc_local_state ON managed_virtual_keys_cache(local_state)",
            [],
        )
        .map_err(|e| format!("Failed to ensure managed_virtual_keys_cache index: {}", e))?;

        // managed_virtual_keys_cache column retrofits.
        for (col, ddl) in &[
            (
                "local_alias",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN local_alias TEXT",
            ),
            (
                "supported_providers",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN supported_providers TEXT",
            ),
            (
                "provider_base_urls",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN provider_base_urls TEXT",
            ),
            (
                "owner_account_id",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN owner_account_id TEXT",
            ),
        ] {
            ensure_column(conn, "managed_virtual_keys_cache", col, ddl)?;
        }

        // entries routing column retrofits.
        for (col, ddl) in &[
            (
                "provider_code",
                "ALTER TABLE entries ADD COLUMN provider_code TEXT",
            ),
            ("base_url", "ALTER TABLE entries ADD COLUMN base_url TEXT"),
        ] {
            ensure_column(conn, "entries", col, ddl)?;
        }

        ensure_column(
            conn,
            "entries",
            "supported_providers",
            "ALTER TABLE entries ADD COLUMN supported_providers TEXT",
        )?;

        // route_token (entries) — added pre-D as part of baseline; the
        // dedicated v1.0.4 module also adds this for upgraded vaults
        // that pre-date the column being part of baseline. Both paths
        // are idempotent via has_column guard.
        ensure_column(
            conn,
            "entries",
            "route_token",
            "ALTER TABLE entries ADD COLUMN route_token TEXT",
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_route_token \
             ON entries(route_token) WHERE route_token IS NOT NULL",
            [],
        )
        .map_err(|e| format!("Failed to create idx_entries_route_token: {}", e))?;

        // route_token on provider_accounts — only if provider_accounts
        // exists (created later by v1.0.3-alpha). On a fresh boot the
        // version modules run AFTER baseline, so on the first pass
        // provider_accounts doesn't exist yet — the v1.0.4 module's
        // upgrade adds the column when provider_accounts is materialised.
        // On subsequent boots the table exists and we backfill here too
        // for belt-and-braces consistency with pre-D vaults.
        if has_column(conn, "provider_accounts", "provider_account_id") {
            ensure_column(
                conn,
                "provider_accounts",
                "route_token",
                "ALTER TABLE provider_accounts ADD COLUMN route_token TEXT",
            )?;
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_accounts_route_token \
                 ON provider_accounts(route_token) WHERE route_token IS NOT NULL",
                [],
            )
            .map_err(|e| format!("Failed to create idx_provider_accounts_route_token: {}", e))?;
        }

        // user_profiles + user_profile_provider_bindings (predates D
        // registry's v1.0.2 module, which also creates them — both
        // idempotent).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_profiles (
                id TEXT PRIMARY KEY,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure user_profiles: {}", e))?;
        conn.execute(
            "INSERT OR IGNORE INTO user_profiles (id, is_active) VALUES ('default', 1)",
            [],
        )
        .map_err(|e| format!("Failed to seed default profile: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_profile_provider_bindings (
                profile_id TEXT NOT NULL,
                provider_code TEXT NOT NULL,
                key_source_type TEXT NOT NULL,
                key_source_ref TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (profile_id, provider_code),
                FOREIGN KEY (profile_id) REFERENCES user_profiles(id)
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure user_profile_provider_bindings: {}", e))?;

        migrate_active_key_config_to_default_profile(conn)?;

        // platform_account OAuth columns (predates v1.0.2's same retrofit;
        // both are idempotent).
        for (col, ddl) in &[
            (
                "refresh_token",
                "ALTER TABLE platform_account ADD COLUMN refresh_token TEXT",
            ),
            (
                "token_expires_at",
                "ALTER TABLE platform_account ADD COLUMN token_expires_at INTEGER",
            ),
        ] {
            ensure_column(conn, "platform_account", col, ddl)?;
        }

        // events column retrofits.
        for (col, ddl) in &[
            ("project", "ALTER TABLE events ADD COLUMN project TEXT"),
            ("env", "ALTER TABLE events ADD COLUMN env TEXT"),
            ("profile", "ALTER TABLE events ADD COLUMN profile TEXT"),
            (
                "ok",
                "ALTER TABLE events ADD COLUMN ok INTEGER NOT NULL DEFAULT 0",
            ),
            ("error_type", "ALTER TABLE events ADD COLUMN error_type TEXT"),
        ] {
            ensure_column(conn, "events", col, ddl)?;
        }

        // 2026-05-08 Kimi 双平台拆分 — **不做数据迁移**。
        // Why: 当前 released = v1.0.0-rc.1 (pre-GA),next = v1.0.0-rc.2;按项目
        // pre-GA "no upgrade path" 惯例 (类比 2026-05-01 把 v1.0.{2..5}-alpha
        // 折回 baseline 时让 internal testers `uninstall.sh + reinstall`),旧
        // provider_code='kimi' 的 vault 数据通过 reinstall 重建,而非在线迁移。
        // CLI binary 的 provider_registry.yaml 仍把 'kimi' 留作 deprecated alias,
        // 防御性地保护任何手工构造或迁移残留的旧数据。
        //
        // 详见 roadmap20260320/技术实现/update/20260508-Kimi双平台拆分-moonshot与kimi-code.md
        // §"版本周期决策" 节。
        Ok(())
    }

    /// One-time migration: carry legacy active_key_config into provider
    /// bindings. Sentinel-guarded so re-runs are no-ops after first
    /// success.
    fn migrate_active_key_config_to_default_profile(conn: &Connection) -> Result<(), String> {
        const SENTINEL: &str = "v1_profile_migration_done";
        let done: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM config WHERE key = ?1",
                params![SENTINEL],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if done {
            return Ok(());
        }

        let key_type: Option<String> = conn
            .query_row(
                "SELECT CAST(value AS TEXT) FROM config WHERE key = 'active_key_type'",
                [],
                |r| r.get(0),
            )
            .ok();
        let key_type = match key_type.as_deref() {
            None | Some("") => {
                mark_migration(conn, SENTINEL)?;
                return Ok(());
            }
            Some(t) => t.to_string(),
        };
        let key_ref: String = conn
            .query_row(
                "SELECT CAST(value AS TEXT) FROM config WHERE key = 'active_key_ref'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let pjson: String = conn
            .query_row(
                "SELECT CAST(value AS TEXT) FROM config WHERE key = 'active_key_providers'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "[]".into());
        let providers: Vec<String> = serde_json::from_str(&pjson).unwrap_or_default();
        if key_ref.is_empty() || providers.is_empty() {
            mark_migration(conn, SENTINEL)?;
            return Ok(());
        }
        for p in &providers {
            conn.execute(
                "INSERT OR IGNORE INTO user_profile_provider_bindings (profile_id, provider_code, key_source_type, key_source_ref) VALUES ('default', ?1, ?2, ?3)",
                params![p, key_type, key_ref],
            )
            .map_err(|e| format!("migrate binding {}: {}", p, e))?;
        }
        mark_migration(conn, SENTINEL)
    }

    fn mark_migration(conn: &Connection, sentinel: &str) -> Result<(), String> {
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![sentinel, b"1".to_vec()],
        )
        .map_err(|e| format!("write sentinel '{}': {}", sentinel, e))?;
        Ok(())
    }

    /// Defense A: baseline rollback is a no-op. The CLI's rollback_to()
    /// historically fell back to start=0 (rollback everything) when the
    /// target was unknown — that path used to silently DROP the version
    /// modules' tables but leave the baseline-introduced ones alone (because
    /// baseline wasn't registered). Now that baseline IS registered, a
    /// "rollback everything" path WOULD reach this function. We intentionally
    /// reject the operation at the module level so vault data is never
    /// destroyed by an accidental rollback chain.
    ///
    /// PR8 added defense B at the runner level (rollback_to refuses unknown
    /// targets) — the two defenses are independent, and either alone is
    /// sufficient to protect user data.
    pub fn rollback(_: &Connection) -> Result<(), String> {
        eprintln!("[db rollback] v1.0.0 baseline is irreversible — vault tables retained");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Builds a fresh in-memory vault with the baseline + every version
    /// migration applied. Used as the starting state for rollback tests.
    fn fresh_vault() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory");
        upgrade_all(&conn).expect("upgrade_all");
        conn
    }

    fn table_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    /// T15-A from the test plan, defense B layer: rolling back to an
    /// unknown target must return Err and leave the vault completely
    /// untouched.
    #[test]
    fn defense_b_rollback_to_unknown_target_returns_err() {
        let conn = fresh_vault();

        let result = rollback_to(&conn, "v0.0.0-fake");
        assert!(
            result.is_err(),
            "defense B should reject unknown target (got Ok)"
        );

        // No tables were dropped — both baseline and version tables
        // survive intact.
        for tbl in &[
            "config",
            "entries",
            "profiles",
            "bindings",
            "events",
            "platform_account",
            "managed_virtual_keys_cache",
            "user_profiles",
            "provider_accounts",
        ] {
            assert!(
                table_exists(&conn, tbl),
                "table {} was dropped by failed rollback (defense B failed)",
                tbl
            );
        }
    }

    /// Defense A inner layer: even with defense B disabled (i.e. baseline
    /// being THE rollback target, not unknown), the baseline rollback
    /// must be a no-op. We model this by rolling back directly to the
    /// canonical baseline name.
    ///
    /// Post-2026-05-01 fold: baseline canonical name is "v1.0.0" (was
    /// "v1.0.1-baseline" pre-fold). The legacy alias still maps via
    /// rollback_to's normaliser at the call site if needed.
    #[test]
    fn defense_a_baseline_rollback_is_no_op() {
        let conn = fresh_vault();

        rollback_to(&conn, "v1.0.0").expect("rollback to baseline canonical name");

        // Baseline tables intact.
        for tbl in &["config", "entries", "profiles", "bindings"] {
            assert!(
                table_exists(&conn, tbl),
                "baseline table {} dropped (defense A failed)",
                tbl
            );
        }
    }

    // T15-B was deleted 2026-05-06 along with the pre-baseline alpha
    // modules. The test asserted "rolling back to v1.0.1-alpha drops
    // v1.0.2/3/4-introduced tables" — but post-fold all those tables
    // are part of the v1.0.0 baseline, so rollback to baseline is
    // a no-op (defense A) and nothing gets dropped. The chain-rollback
    // semantic the test exercised no longer exists.

    /// upgrade_all is idempotent: running it twice on the same connection
    /// must succeed without errors. Mirrors the server-side
    /// TestUpgradeTo_IdempotentSQLite invariant.
    #[test]
    fn upgrade_all_is_idempotent() {
        let conn = Connection::open_in_memory().expect("open");
        upgrade_all(&conn).expect("first upgrade_all");
        upgrade_all(&conn).expect("second upgrade_all (must be idempotent)");
    }

    // T26 + cycle test were both deleted 2026-05-06: they exercised the
    // multi-version chain (rollback to v1.0.2-alpha then re-upgrade
    // through v1.0.3, v1.0.4) which no longer exists post-fold. After
    // the 2026-05-08 second fold (v1.0.1-alpha.1 + Kimi split also
    // absorbed into v1.0.0 baseline), the registry is again single-version
    // — no chain to test partial-state recovery against. Re-add tests when
    // the next post-GA cycle lands and produces a real chain.
}
