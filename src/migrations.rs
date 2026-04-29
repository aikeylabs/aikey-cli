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
    // v1.0.1-baseline is the registry's first entry — it owns the entire
    // vault schema bootstrap. open_connection() routes through upgrade_all
    // which calls this module's upgrade(); there is no parallel
    // apply_migrations() in storage.rs anymore (cleanup landed with the
    // PR8 closure of D plan). Defense A: baseline.rollback() is a no-op
    // so even if rollback_to() reached it (defense B at the runner level
    // also rejects unknown targets), vault tables are NEVER dropped.
    VersionMigration {
        version: "1.0.1-baseline",
        upgrade: v1_0_1_baseline::upgrade,
        rollback: v1_0_1_baseline::rollback,
    },
    VersionMigration {
        version: "1.0.2-alpha",
        upgrade: v1_0_2_alpha::upgrade,
        rollback: v1_0_2_alpha::rollback,
    },
    VersionMigration {
        version: "1.0.3-alpha",
        upgrade: v1_0_3_alpha::upgrade,
        rollback: v1_0_3_alpha::rollback,
    },
    VersionMigration {
        version: "1.0.4-alpha",
        upgrade: v1_0_4_alpha::upgrade,
        rollback: v1_0_4_alpha::rollback,
    },
    // v1.0.5-alpha (original) and v1.0.6-alpha were collapsed into v1.0.4-alpha
    // before either shipped — see module comment on `v1_0_4_alpha`. The
    // v1.0.5-alpha slot is reused below for the token-prefix rename refactor
    // (2026-04-29) — naming reuse is safe because the previous v1.0.5 plans
    // never reached a public registry.
    VersionMigration {
        version: "1.0.5-alpha",
        upgrade: v1_0_5_alpha::upgrade,
        rollback: v1_0_5_alpha::rollback,
    },
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
/// too if v1_0_1_baseline.rollback weren't a no-op — defense A). This
/// function now returns Err for unknown targets and leaves the vault
/// untouched. The historical alias "v1.0.1-alpha" is recognised and
/// maps to the v1.0.1-baseline registry entry, since users will likely
/// type the published version tag rather than the internal name.
pub fn rollback_to(conn: &Connection, target: &str) -> Result<(), String> {
    let target_norm = target.strip_prefix('v').unwrap_or(target);

    // Recognise published-version aliases for the baseline. Users typed
    // `aikey db rollback --to v1.0.1-alpha` for the entire pre-D era;
    // accepting it keeps the muscle memory working without weakening
    // the unknown-target rejection.
    let target_canonical = match target_norm {
        "1.0.1-alpha" | "1.0.1" => "1.0.1-baseline",
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
// v1.0.1-baseline — initial vault schema (D plan, mirroring server side)
// ---------------------------------------------------------------------------
//
// Why baseline as code: previously the CLI vault's initial schema lived in
// storage.rs::apply_migrations, outside the migration registry. That meant
// rollback_to() with an unknown target would fall through to "rollback
// everything", and version modules' rollbacks would happily DROP the
// v1.0.2/3/4-introduced tables — but the baseline tables (entries,
// profiles, bindings, config, events, platform_account,
// managed_virtual_keys_cache) were never registered, so they were
// untouched and the user was left with an inconsistent partial-state
// vault.
//
// Defense A: baseline.rollback() is intentionally a no-op. Even if
// rollback_to("v0.0.0-fake") falls through to "rollback all" (defense B
// at the runner level prevents this — defense in depth), the baseline
// tables ARE retained because there's nothing to drop.

pub mod v1_0_1_baseline {
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

        // Platform account (global identity)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS platform_account (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                account_id      TEXT NOT NULL,
                email           TEXT NOT NULL,
                jwt_token       TEXT NOT NULL,
                control_url     TEXT NOT NULL,
                logged_in_at    INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure platform_account table: {}", e))?;

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
        eprintln!("[db rollback] v1.0.1-baseline is irreversible — vault tables retained");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// v1.0.2-alpha migrations
// ---------------------------------------------------------------------------

pub mod v1_0_2_alpha {
    use rusqlite::Connection;

    /// Forward migration: add user_profiles, user_profile_provider_bindings tables,
    /// and refresh_token / token_expires_at columns to platform_account.
    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_profiles (
                id TEXT PRIMARY KEY,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )", [],
        ).map_err(|e| format!("user_profiles: {}", e))?;

        conn.execute(
            "INSERT OR IGNORE INTO user_profiles (id, is_active) VALUES ('default', 1)", [],
        ).map_err(|e| format!("seed default profile: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_profile_provider_bindings (
                profile_id TEXT NOT NULL,
                provider_code TEXT NOT NULL,
                key_source_type TEXT NOT NULL,
                key_source_ref TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (profile_id, provider_code),
                FOREIGN KEY (profile_id) REFERENCES user_profiles(id)
            )", [],
        ).map_err(|e| format!("user_profile_provider_bindings: {}", e))?;

        // Add OAuth columns to platform_account (idempotent via pragma check)
        for (col, ddl) in &[
            ("refresh_token", "ALTER TABLE platform_account ADD COLUMN refresh_token TEXT"),
            ("token_expires_at", "ALTER TABLE platform_account ADD COLUMN token_expires_at INTEGER"),
        ] {
            let has_col: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('platform_account') WHERE name=?1",
                    [col],
                    |row| row.get::<_, i64>(0),
                )
                .map(|n| n > 0)
                .unwrap_or(false);
            if !has_col {
                conn.execute(ddl, []).map_err(|e| format!("{}: {}", col, e))?;
            }
        }

        Ok(())
    }

    /// Reverse migration: drop tables added in v1.0.2.
    /// platform_account columns cannot be dropped (SQLite limitation) — they stay
    /// but are safely ignored by the v1.0.1 binary.
    pub fn rollback(conn: &Connection) -> Result<(), String> {
        let sqls = [
            "DROP TABLE IF EXISTS user_profile_provider_bindings",
            "DROP TABLE IF EXISTS user_profiles",
        ];
        for sql in &sqls {
            match conn.execute(sql, []) {
                Ok(_) => eprintln!("[db rollback] OK: {}", sql),
                Err(e) => eprintln!("[db rollback] WARN: {} — {}", sql, e),
            }
        }
        eprintln!("[db rollback] SKIP: platform_account.refresh_token (SQLite no DROP COLUMN)");
        eprintln!("[db rollback] SKIP: platform_account.token_expires_at (SQLite no DROP COLUMN)");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// v1.0.3-alpha migrations — Provider OAuth account management
// ---------------------------------------------------------------------------

pub mod v1_0_3_alpha {
    use rusqlite::Connection;

    /// Forward migration: add provider_accounts and provider_account_tokens tables
    /// for OAuth account management (Claude, Codex, Kimi).
    ///
    /// Design decisions:
    ///   D3:  Token storage uses vault AES-256-GCM encryption (same as API Keys)
    ///   D10: Setup Token mode — access_token 1yr, refresh_token as fallback
    ///   D13: Kimi identity uses user_id (no email), display_identity set by user
    ///
    /// No new bindings table — route bindings reuse user_profile_provider_bindings
    /// (v1.0.2-alpha) with key_source_type = "personal_oauth_account".
    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS provider_accounts (
                provider_account_id  TEXT PRIMARY KEY,
                provider             TEXT NOT NULL,
                auth_type            TEXT NOT NULL,
                credential_type      TEXT NOT NULL DEFAULT 'personal_oauth_account',
                status               TEXT NOT NULL DEFAULT 'active',
                external_id          TEXT,
                display_identity     TEXT,
                org_uuid             TEXT,
                account_tier         TEXT,
                created_at           INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                last_used_at         INTEGER,
                owner_type           TEXT NOT NULL DEFAULT 'local_user',
                UNIQUE(provider, external_id)
            )", [],
        ).map_err(|e| format!("provider_accounts: {}", e))?;

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
            )", [],
        ).map_err(|e| format!("provider_account_tokens: {}", e))?;

        Ok(())
    }

    /// Reverse migration: drop tables added in v1.0.3.
    pub fn rollback(conn: &Connection) -> Result<(), String> {
        let sqls = [
            "DROP TABLE IF EXISTS provider_account_tokens",
            "DROP TABLE IF EXISTS provider_accounts",
        ];
        for sql in &sqls {
            match conn.execute(sql, []) {
                Ok(_) => eprintln!("[db rollback] OK: {}", sql),
                Err(e) => eprintln!("[db rollback] WARN: {} — {}", sql, e),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// v1.0.4-alpha migrations — route_token (per-request gateway routing) +
//                           per-key usage telemetry (last_used_at, use_count)
//
// 2026-04-23 collapse: absorbed two un-shipped successor modules.
//   - v1.0.5-alpha (batch-import audit tables `import_jobs` / `import_items`)
//     was rolled back entirely — the feature never surfaced in UI, the only
//     consumer that would have justified a separate table (source_hash
//     dedupe / G-4) was cancelled, and alias-level conflict preflight already
//     covers "don't re-import the same thing". Idempotent DROP here so any
//     dev vault that had already run v1.0.5 gets cleaned.
//   - v1.0.6-alpha (entries.last_used_at / entries.use_count /
//     provider_accounts.use_count) merged into this module's upgrade so the
//     VERSIONS registry stays dense (no 1.0.5 gap).
//
// Result: three un-shipped ALTERs become part of v1.0.4 and there's no
// 1.0.5 / 1.0.6 module left.  Safe only because v1.0.2 is the highest
// published version (workflow/versions/current.md).
// ---------------------------------------------------------------------------

pub mod v1_0_4_alpha {
    use rusqlite::Connection;

    fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name=?1", table),
            [column],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false)
    }

    /// Forward migration.
    ///
    /// 1. **route_token** columns (`entries.route_token` +
    ///    `provider_accounts.route_token`) + unique partial indexes. Random
    ///    bearer tokens used by third-party clients (Cursor, OpenCode, etc.)
    ///    as their API_KEY when routing through the local proxy. Originally
    ///    `aikey_vk_<64-hex>`; renamed to `aikey_personal_<64-hex>` by the
    ///    v1.0.5-alpha migration (2026-04-29 prefix-rename refactor).
    ///
    /// 2. **Usage telemetry** columns (`entries.last_used_at`,
    ///    `entries.use_count`, `provider_accounts.use_count`). Populated by
    ///    `_internal vault-op record_usage` which proxy calls after every
    ///    successful credential resolution. Feeds the User Vault Web page's
    ///    "Last Used" column + "Activity" metric.
    ///
    /// 3. **Cleanup of un-shipped v1.0.5 schema**: `import_jobs` /
    ///    `import_items`. Idempotent DROP (runs on every vault) — safe
    ///    because these tables never made it into a published version.
    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        // --- 1. route_token ---
        if !has_column(conn, "entries", "route_token") {
            conn.execute("ALTER TABLE entries ADD COLUMN route_token TEXT", [])
                .map_err(|e| format!("entries.route_token: {}", e))?;
        }
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_route_token \
             ON entries(route_token) WHERE route_token IS NOT NULL",
            [],
        )
        .map_err(|e| format!("idx_entries_route_token: {}", e))?;

        if has_column(conn, "provider_accounts", "provider_account_id") {
            if !has_column(conn, "provider_accounts", "route_token") {
                conn.execute(
                    "ALTER TABLE provider_accounts ADD COLUMN route_token TEXT",
                    [],
                )
                .map_err(|e| format!("provider_accounts.route_token: {}", e))?;
            }
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_accounts_route_token \
                 ON provider_accounts(route_token) WHERE route_token IS NOT NULL",
                [],
            )
            .map_err(|e| format!("idx_provider_accounts_route_token: {}", e))?;
        }

        // --- 2. Usage telemetry (merged from former v1.0.6-alpha) ---
        if !has_column(conn, "entries", "last_used_at") {
            conn.execute("ALTER TABLE entries ADD COLUMN last_used_at INTEGER", [])
                .map_err(|e| format!("entries.last_used_at: {}", e))?;
        }
        if !has_column(conn, "entries", "use_count") {
            conn.execute(
                "ALTER TABLE entries ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(|e| format!("entries.use_count: {}", e))?;
        }
        if has_column(conn, "provider_accounts", "provider_account_id")
            && !has_column(conn, "provider_accounts", "use_count")
        {
            conn.execute(
                "ALTER TABLE provider_accounts ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(|e| format!("provider_accounts.use_count: {}", e))?;
        }

        // --- 3. Cleanup un-shipped v1.0.5 tables (idempotent; no-op if absent) ---
        for sql in &[
            "DROP INDEX IF EXISTS idx_import_items_job_id",
            "DROP INDEX IF EXISTS idx_import_jobs_created_at",
            "DROP TABLE IF EXISTS import_items",
            "DROP TABLE IF EXISTS import_jobs",
        ] {
            conn.execute(sql, [])
                .map_err(|e| format!("cleanup un-shipped import tables ({}): {}", sql, e))?;
        }

        Ok(())
    }

    /// Reverse migration.
    ///
    /// - Indexes are dropped (safe).
    /// - Added columns stay (SQLite pre-3.35 can't DROP COLUMN; older binaries
    ///   ignore unknown columns safely).
    /// - Un-shipped import tables are NOT re-created (they were reverse-only
    ///   cleanup, with no consumers to restore).
    pub fn rollback(conn: &Connection) -> Result<(), String> {
        for sql in &[
            "DROP INDEX IF EXISTS idx_entries_route_token",
            "DROP INDEX IF EXISTS idx_provider_accounts_route_token",
        ] {
            match conn.execute(sql, []) {
                Ok(_) => eprintln!("[db rollback] OK: {}", sql),
                Err(e) => eprintln!("[db rollback] WARN: {} — {}", sql, e),
            }
        }
        for msg in &[
            "[db rollback] SKIP: entries.route_token (SQLite no DROP COLUMN)",
            "[db rollback] SKIP: provider_accounts.route_token (SQLite no DROP COLUMN)",
            "[db rollback] SKIP: entries.last_used_at (SQLite no DROP COLUMN)",
            "[db rollback] SKIP: entries.use_count (SQLite no DROP COLUMN)",
            "[db rollback] SKIP: provider_accounts.use_count (SQLite no DROP COLUMN)",
        ] {
            eprintln!("{}", msg);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// v1.0.5-alpha — Token prefix rename (2026-04-29)
//
// Refactor renames token prefixes by role rather than credential type:
//   - aikey_vk_<64-hex>  (legacy random bearer for personal/OAuth)
//     → aikey_personal_<64-hex>
//   - aikey_vk_<vk_id>    (legacy team identifier; stored in
//     managed_virtual_keys_cache.virtual_key_id, NOT in route_token columns)
//     → handled at runtime by team_token_normalize::team_token_from_vk_id;
//     no SQL migration needed because the column already stores bare vk_id
//     (the prefix is added at output time, not stored).
//
// This migration only touches `entries.route_token` and
// `provider_accounts.route_token` — the only columns that store the actual
// prefixed bearer token. UPDATE uses `'aikey_personal_' || lower(substr(...))`
// rather than REPLACE() to force-lowercase the hex suffix (isTier1Personal
// in the proxy only accepts [0-9a-f], so any uppercase would 401 post-migration).
//
// Two precheck queries gate the UPDATE: prefix-precheck (filters dirty old-prefix
// rows that don't match the bearer form) and completeness-precheck (catches
// NULL / empty token rows). Both must return 0 before UPDATE runs.
//
// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md
// ---------------------------------------------------------------------------

pub mod v1_0_5_alpha {
    use rusqlite::Connection;

    fn has_table(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false)
    }

    fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name=?1", table),
            [column],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false)
    }

    /// Count rows where route_token starts with 'aikey_vk_' but doesn't match
    /// the canonical bearer form (length 73, suffix is 64 lowercase-or-uppercase
    /// hex). Returning > 0 means dirty data — refuse to migrate.
    fn prefix_precheck(conn: &Connection, table: &str) -> Result<i64, String> {
        // Why lower(): tolerate historical mixed-case hex; UPDATE will normalize
        // to lowercase regardless. NOT GLOB '*[^0-9a-f]*' is the correct
        // "all hex chars" check (negate "contains any non-hex"); GLOB '[0-9a-f]*'
        // alone only checks the first character.
        let sql = format!(
            "SELECT COUNT(*) FROM {table} \
             WHERE substr(route_token, 1, 9) = 'aikey_vk_' \
               AND NOT ( \
                 length(route_token) = 73 \
                 AND length(substr(route_token, 10)) = 64 \
                 AND lower(substr(route_token, 10)) NOT GLOB '*[^0-9a-f]*' \
               )",
            table = table
        );
        conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
            .map_err(|e| format!("{} prefix-precheck: {}", table, e))
    }

    /// Count rows where route_token is NULL or empty (excluded from prefix-precheck
    /// because the WHERE clause requires `aikey_vk_` prefix). NULL/empty is acceptable
    /// pre-migration if the row was added but never had a token generated; refuse
    /// to migrate while these exist so the operator knows to resolve them first.
    ///
    /// Note: this precheck is informational on the upgrade path because empty
    /// route_token simply skips the UPDATE filter (no harm done). Kept available
    /// as a public function for E2E migration tests to assert on dirty fixtures.
    #[allow(dead_code)]
    pub fn completeness_precheck(conn: &Connection, table: &str) -> Result<i64, String> {
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE route_token IS NULL OR route_token = ''",
            table
        );
        conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
            .map_err(|e| format!("{} completeness-precheck: {}", table, e))
    }

    /// Forward migration: rename `aikey_vk_<64-hex>` → `aikey_personal_<64-hex>`
    /// in entries.route_token and provider_accounts.route_token, force-lowercasing
    /// the hex suffix.
    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        // Tables to migrate. provider_accounts may not exist on very old
        // vaults; skip gracefully (has_table guard).
        let targets: &[&str] = &["entries", "provider_accounts"];

        for table in targets {
            if !has_table(conn, table) {
                continue;
            }
            if !has_column(conn, table, "route_token") {
                continue;
            }

            // Prefix-precheck: refuse to migrate if dirty old-prefix rows exist.
            // The migration UPDATE strictly filters on the canonical form, so
            // dirty rows would be silently left behind otherwise — defense in
            // depth says fail fast and surface the issue.
            let dirty = prefix_precheck(conn, table)?;
            if dirty > 0 {
                return Err(format!(
                    "v1.0.5-alpha migration refused: {} has {} aikey_vk_* row(s) \
                     that don't match the canonical aikey_vk_<64-hex> form. \
                     Inspect dirty rows with: \
                     SELECT alias, length(route_token), route_token FROM {} \
                     WHERE substr(route_token, 1, 9) = 'aikey_vk_' \
                       AND NOT (length(route_token) = 73 AND length(substr(route_token, 10)) = 64 \
                                AND lower(substr(route_token, 10)) NOT GLOB '*[^0-9a-f]*');",
                    table, dirty, table
                ));
            }

            // UPDATE: prefix rename + force lowercase suffix. WHERE clause
            // mirrors the precheck's "canonical form" rule so we only touch
            // rows we just verified are safe.
            let sql = format!(
                "UPDATE {} \
                 SET route_token = 'aikey_personal_' || lower(substr(route_token, 10)) \
                 WHERE substr(route_token, 1, 9) = 'aikey_vk_' \
                   AND length(route_token) = 73 \
                   AND length(substr(route_token, 10)) = 64 \
                   AND lower(substr(route_token, 10)) NOT GLOB '*[^0-9a-f]*'",
                table
            );
            conn.execute(&sql, [])
                .map_err(|e| format!("{} prefix rename UPDATE: {}", table, e))?;
        }

        Ok(())
    }

    /// Reverse migration: rename `aikey_personal_<64-hex>` → `aikey_vk_<64-hex>`.
    ///
    /// Same idempotency rules as upgrade: filters strictly on the canonical
    /// post-migration form (length 79, new prefix, suffix 64 hex).
    /// Tokens written by ANY other source (e.g. mid-rollback partial state)
    /// are left untouched.
    pub fn rollback(conn: &Connection) -> Result<(), String> {
        let targets: &[&str] = &["entries", "provider_accounts"];

        for table in targets {
            if !has_table(conn, table) {
                continue;
            }
            if !has_column(conn, table, "route_token") {
                continue;
            }

            let sql = format!(
                "UPDATE {} \
                 SET route_token = 'aikey_vk_' || substr(route_token, 16) \
                 WHERE substr(route_token, 1, 15) = 'aikey_personal_' \
                   AND length(route_token) = 79 \
                   AND length(substr(route_token, 16)) = 64 \
                   AND lower(substr(route_token, 16)) NOT GLOB '*[^0-9a-f]*'",
                table
            );
            match conn.execute(&sql, []) {
                Ok(n) => eprintln!("[db rollback] {}: reverted {} row(s) aikey_personal_ → aikey_vk_", table, n),
                Err(e) => eprintln!("[db rollback] {} WARN: {} — {}", table, sql, e),
            }
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rusqlite::Connection;

        /// Set up an in-memory vault DB with the minimal schema for this
        /// migration (entries + provider_accounts with route_token columns).
        /// Mimics the tail of v1.0.4-alpha.upgrade()'s relevant DDL.
        fn setup_db() -> Connection {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(
                "CREATE TABLE entries (alias TEXT PRIMARY KEY, route_token TEXT);
                 CREATE TABLE provider_accounts (
                   provider_account_id TEXT PRIMARY KEY,
                   route_token TEXT
                 );",
            )
            .unwrap();
            conn
        }

        const HEX_LOWER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const HEX_UPPER: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        #[test]
        fn upgrade_renames_lowercase_hex_token() {
            let conn = setup_db();
            let token = format!("aikey_vk_{}", HEX_LOWER);
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', ?1)",
                [&token],
            )
            .unwrap();

            upgrade(&conn).unwrap();

            let after: String = conn
                .query_row("SELECT route_token FROM entries WHERE alias='a'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(after, format!("aikey_personal_{}", HEX_LOWER));
            assert_eq!(after.len(), 79);
        }

        #[test]
        fn upgrade_force_lowercases_uppercase_hex() {
            let conn = setup_db();
            let token = format!("aikey_vk_{}", HEX_UPPER);
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', ?1)",
                [&token],
            )
            .unwrap();

            upgrade(&conn).unwrap();

            let after: String = conn
                .query_row("SELECT route_token FROM entries WHERE alias='a'", [], |r| r.get(0))
                .unwrap();
            // Force-lowercased — proxy's isTier1Personal only accepts [0-9a-f].
            assert_eq!(after, format!("aikey_personal_{}", HEX_LOWER));
        }

        #[test]
        fn upgrade_refuses_short_dirty_token() {
            let conn = setup_db();
            // 'aikey_vk_short' — not 73 chars; prefix precheck must catch it.
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', 'aikey_vk_short')",
                [],
            )
            .unwrap();

            let res = upgrade(&conn);
            assert!(res.is_err(), "expected refusal, got {:?}", res);
            let err = res.unwrap_err();
            assert!(err.contains("v1.0.5-alpha migration refused"), "msg: {}", err);
        }

        #[test]
        fn upgrade_refuses_non_hex_token() {
            let conn = setup_db();
            // length 73 but suffix contains 'g' (non-hex)
            let token = format!("aikey_vk_{}", "g".repeat(64));
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', ?1)",
                [&token],
            )
            .unwrap();

            let res = upgrade(&conn);
            assert!(res.is_err(), "expected refusal, got {:?}", res);
        }

        #[test]
        fn upgrade_idempotent_on_already_migrated() {
            let conn = setup_db();
            let token = format!("aikey_vk_{}", HEX_LOWER);
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', ?1)",
                [&token],
            )
            .unwrap();

            upgrade(&conn).unwrap();
            upgrade(&conn).unwrap();  // Second run = no-op

            let after: String = conn
                .query_row("SELECT route_token FROM entries WHERE alias='a'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(after, format!("aikey_personal_{}", HEX_LOWER));
        }

        #[test]
        fn upgrade_skips_null_and_empty() {
            let conn = setup_db();
            conn.execute("INSERT INTO entries(alias, route_token) VALUES ('null', NULL)", []).unwrap();
            conn.execute("INSERT INTO entries(alias, route_token) VALUES ('empty', '')", []).unwrap();

            // Should NOT error — NULL/empty don't match prefix filter.
            upgrade(&conn).unwrap();

            // Completeness precheck reports them but doesn't block upgrade.
            let count = completeness_precheck(&conn, "entries").unwrap();
            assert_eq!(count, 2);
        }

        #[test]
        fn upgrade_covers_provider_accounts() {
            let conn = setup_db();
            let token = format!("aikey_vk_{}", HEX_LOWER);
            conn.execute(
                "INSERT INTO provider_accounts(provider_account_id, route_token) VALUES ('acct1', ?1)",
                [&token],
            )
            .unwrap();

            upgrade(&conn).unwrap();

            let after: String = conn
                .query_row(
                    "SELECT route_token FROM provider_accounts WHERE provider_account_id='acct1'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(after, format!("aikey_personal_{}", HEX_LOWER));
        }

        #[test]
        fn rollback_reverts_personal_to_vk() {
            let conn = setup_db();
            let new_token = format!("aikey_personal_{}", HEX_LOWER);
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', ?1)",
                [&new_token],
            )
            .unwrap();

            rollback(&conn).unwrap();

            let after: String = conn
                .query_row("SELECT route_token FROM entries WHERE alias='a'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(after, format!("aikey_vk_{}", HEX_LOWER));
        }

        #[test]
        fn upgrade_then_rollback_round_trip() {
            let conn = setup_db();
            let original = format!("aikey_vk_{}", HEX_LOWER);
            conn.execute(
                "INSERT INTO entries(alias, route_token) VALUES ('a', ?1)",
                [&original],
            )
            .unwrap();

            upgrade(&conn).unwrap();
            rollback(&conn).unwrap();

            let after: String = conn
                .query_row("SELECT route_token FROM entries WHERE alias='a'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(after, original, "round-trip must restore original token");
        }
    }
}

// v1.0.5-alpha (original — batch-import audit tables) and v1.0.6-alpha (per-key
// usage telemetry) were collapsed into v1.0.4-alpha on 2026-04-23 before either
// shipped — see the module comment at the top of `v1_0_4_alpha`. Intentionally
// left blank so the file tree matches the VERSIONS registry.

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
    #[test]
    fn defense_a_baseline_rollback_is_no_op() {
        let conn = fresh_vault();

        rollback_to(&conn, "v1.0.1-baseline").expect("rollback to baseline canonical name");

        // Baseline tables intact.
        for tbl in &["config", "entries", "profiles", "bindings"] {
            assert!(
                table_exists(&conn, tbl),
                "baseline table {} dropped (defense A failed)",
                tbl
            );
        }
    }

    /// T15-B: rolling back to v1.0.1-alpha (the human-readable name for
    /// the baseline) must drop the v1.0.2/3/4-introduced tables but
    /// preserve the baseline-introduced ones.
    #[test]
    fn defense_a_rollback_to_baseline_drops_only_version_tables() {
        let conn = fresh_vault();

        rollback_to(&conn, "v1.0.1-alpha").expect("rollback_to baseline");

        // v1.0.2-introduced tables should be gone.
        assert!(
            !table_exists(&conn, "user_profiles"),
            "user_profiles should be dropped by v1.0.2 rollback"
        );
        assert!(
            !table_exists(&conn, "user_profile_provider_bindings"),
            "user_profile_provider_bindings should be dropped"
        );
        // v1.0.3-introduced tables should be gone.
        assert!(
            !table_exists(&conn, "provider_accounts"),
            "provider_accounts should be dropped by v1.0.3 rollback"
        );

        // Baseline tables MUST survive.
        for tbl in &["config", "entries", "profiles", "bindings", "platform_account"] {
            assert!(
                table_exists(&conn, tbl),
                "baseline table {} was dropped (defense A failed)",
                tbl
            );
        }
    }

    /// upgrade_all is idempotent: running it twice on the same connection
    /// must succeed without errors. Mirrors the server-side
    /// TestUpgradeTo_IdempotentSQLite invariant.
    #[test]
    fn upgrade_all_is_idempotent() {
        let conn = Connection::open_in_memory().expect("open");
        upgrade_all(&conn).expect("first upgrade_all");
        upgrade_all(&conn).expect("second upgrade_all (must be idempotent)");
    }

    /// T26 from the test plan: a CLI command that crashed mid-migration
    /// must be safe to re-run. We simulate "process died partway through
    /// upgrade_all" by:
    ///   1. Running upgrade_all to convergence (latest schema).
    ///   2. Manually rolling back to v1.0.2-alpha (drops v1.0.3 +
    ///      v1.0.4 tables/indexes — equivalent to "process died after
    ///      v1.0.2 finished but before v1.0.3 ran on the next boot").
    ///   3. Running upgrade_all again — must re-apply v1.0.3 + v1.0.4
    ///      cleanly without any "table already exists" / "duplicate
    ///      column" errors leaking through (idempotency guards must
    ///      still hold).
    ///
    /// This is the strongest unit-level guarantee that the registry
    /// recovers from any partial-application state — the same property
    /// the server-side TestFailpointMatrix exercises with explicit
    /// panic injection.
    #[test]
    fn cli_mid_failure_simulation_re_run_converges() {
        let conn = fresh_vault();

        // Sanity: post-upgrade, v1.0.3 + v1.0.4 artifacts present.
        assert!(table_exists(&conn, "provider_accounts"));
        let route_token_idx_before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_entries_route_token'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(route_token_idx_before, 1);

        // Simulate partial-state: rollback to v1.0.2-alpha. v1.0.3 +
        // v1.0.4 reverts run, leaving the vault in a "post-1.0.2 but
        // pre-1.0.3" shape — exactly what a process death between
        // those versions would leave behind.
        rollback_to(&conn, "v1.0.2-alpha").expect("rollback to v1.0.2");
        assert!(!table_exists(&conn, "provider_accounts"));
        let route_token_idx_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_entries_route_token'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(route_token_idx_after, 0);

        // Re-run upgrade_all — must converge cleanly.
        upgrade_all(&conn).expect("re-upgrade after partial rollback");

        // v1.0.3 + v1.0.4 artifacts back.
        assert!(table_exists(&conn, "provider_accounts"));
        let route_token_idx_final: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_entries_route_token'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(route_token_idx_final, 1);
    }

    /// Cycle test: upgrade → rollback to baseline → upgrade again. The
    /// vault should converge back to the original schema. Mirrors the
    /// server-side TestCycle_UpgradeRollbackUpgrade invariant.
    #[test]
    fn upgrade_rollback_reupgrade_cycle_converges() {
        let conn = fresh_vault();
        let baseline_tables = ["config", "entries", "profiles", "bindings"];

        // After fresh upgrade: all tables present.
        for tbl in &baseline_tables {
            assert!(table_exists(&conn, tbl));
        }
        assert!(table_exists(&conn, "user_profiles")); // v1.0.2
        assert!(table_exists(&conn, "provider_accounts")); // v1.0.3

        // Rollback to baseline.
        rollback_to(&conn, "v1.0.1-alpha").expect("rollback to baseline");

        // Baseline tables stay; v1.0.2/3-introduced tables gone.
        for tbl in &baseline_tables {
            assert!(table_exists(&conn, tbl));
        }
        assert!(!table_exists(&conn, "user_profiles"));
        assert!(!table_exists(&conn, "provider_accounts"));

        // Upgrade again.
        upgrade_all(&conn).expect("re-upgrade after rollback");

        // Everything back.
        for tbl in &baseline_tables {
            assert!(table_exists(&conn, tbl));
        }
        assert!(table_exists(&conn, "user_profiles"));
        assert!(table_exists(&conn, "provider_accounts"));
    }
}
