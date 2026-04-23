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
    // v1.0.1-alpha is baseline — no migration needed (tables created by storage.rs init)
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
    // v1.0.5-alpha and v1.0.6-alpha were collapsed into v1.0.4-alpha before
    // either migration shipped — see module comment on `v1_0_4_alpha`. No
    // registry entries for these versions. (2026-04-23)
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
pub fn rollback_to(conn: &Connection, target: &str) -> Result<(), String> {
    let target_norm = target.strip_prefix('v').unwrap_or(target);

    // Find the index of the target version (-1 means "before all versions" = rollback everything)
    let target_idx = VERSIONS.iter().position(|v| v.version == target_norm);

    // Collect versions to rollback: everything after target_idx, in reverse order
    let start = match target_idx {
        Some(idx) => idx + 1, // don't rollback the target itself
        None => {
            // Target not in registry — could be a baseline version (v1.0.1)
            // or an unknown version. Rollback everything if target looks older.
            // Why: v1.0.1-alpha is baseline (no entry in VERSIONS), rolling back
            // to it means undoing ALL version migrations.
            0
        }
    };

    if start >= VERSIONS.len() {
        eprintln!("[db rollback] Nothing to rollback (target={} is current or newer)", target);
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
    ///    aikey_vk_ tokens used by third-party clients (Cursor, OpenCode,
    ///    etc.) as their API_KEY when routing through the local proxy.
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

// v1.0.5-alpha (batch-import audit tables) and v1.0.6-alpha (per-key usage
// telemetry) were collapsed into v1.0.4-alpha on 2026-04-23 before either
// shipped — see the module comment at the top of `v1_0_4_alpha`. Intentionally
// left blank so the file tree matches the VERSIONS registry.
