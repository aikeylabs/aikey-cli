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
    // v1.0.5-alpha: 批量导入审计表（Stage 2 Phase F）
    // import_jobs  — 每次批量导入的聚合记录
    // import_items — 每个被导入凭证的明细审计
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
// v1.0.4-alpha migrations — Route token for per-request API gateway routing
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

    /// Forward migration: add route_token columns to entries and provider_accounts.
    /// Route tokens are random aikey_vk_ tokens used by third-party clients
    /// (Cursor, OpenCode, etc.) as their API_KEY when routing through the local proxy.
    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        // entries.route_token
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

        // provider_accounts.route_token (table may not exist if v1.0.3 was skipped)
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

        Ok(())
    }

    /// Reverse migration: columns cannot be dropped in SQLite — they stay
    /// but are safely ignored by older binaries.
    pub fn rollback(conn: &Connection) -> Result<(), String> {
        // Drop indexes (safe, older versions don't use them)
        for sql in &[
            "DROP INDEX IF EXISTS idx_entries_route_token",
            "DROP INDEX IF EXISTS idx_provider_accounts_route_token",
        ] {
            match conn.execute(sql, []) {
                Ok(_) => eprintln!("[db rollback] OK: {}", sql),
                Err(e) => eprintln!("[db rollback] WARN: {} — {}", sql, e),
            }
        }
        eprintln!("[db rollback] SKIP: entries.route_token (SQLite no DROP COLUMN)");
        eprintln!("[db rollback] SKIP: provider_accounts.route_token (SQLite no DROP COLUMN)");
        Ok(())
    }
}

pub mod v1_0_5_alpha {
    //! v1.0.5-alpha: 批量导入审计表（Stage 2 Phase F）
    //!
    //! 新增 2 张表：
    //! - `import_jobs`：每次批量导入的聚合记录（job_id 由 Go local-server 生成 UUID）
    //! - `import_items`：每条被导入凭证的明细（FK 到 job_id）
    //!
    //! Why：原 audit_log 只记"what happened"，不关联"哪次 import"。批量导入一次 50 条时
    //! audit_log 会产生 50 条 Add 事件，没有 grouping key。import_jobs/items 提供"以 job 为单位"
    //! 的视角，便于前端在 /user/import/history 展示"某次导入" + 明细展开。

    use rusqlite::Connection;

    pub fn upgrade(conn: &Connection) -> Result<(), String> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS import_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL UNIQUE,
                source_type TEXT,
                source_hash TEXT,
                created_at INTEGER NOT NULL,
                completed_at INTEGER,
                total_items INTEGER NOT NULL DEFAULT 0,
                inserted_count INTEGER NOT NULL DEFAULT 0,
                replaced_count INTEGER NOT NULL DEFAULT 0,
                skipped_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'in_progress'
            )",
            [],
        )
        .map_err(|e| format!("create import_jobs: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_import_jobs_created_at \
             ON import_jobs(created_at DESC)",
            [],
        )
        .map_err(|e| format!("idx_import_jobs_created_at: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS import_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                alias TEXT NOT NULL,
                action TEXT NOT NULL,
                provider_code TEXT,
                created_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("create import_items: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_import_items_job_id \
             ON import_items(job_id)",
            [],
        )
        .map_err(|e| format!("idx_import_items_job_id: {}", e))?;

        Ok(())
    }

    pub fn rollback(conn: &Connection) -> Result<(), String> {
        for sql in &[
            "DROP INDEX IF EXISTS idx_import_items_job_id",
            "DROP INDEX IF EXISTS idx_import_jobs_created_at",
            "DROP TABLE IF EXISTS import_items",
            "DROP TABLE IF EXISTS import_jobs",
        ] {
            match conn.execute(sql, []) {
                Ok(_) => eprintln!("[db rollback] OK: {}", sql),
                Err(e) => eprintln!("[db rollback] WARN: {} — {}", sql, e),
            }
        }
        Ok(())
    }
}
