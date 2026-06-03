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
            // 2026-05-22: generic per-key extension JSON blob, scoped to
            // metadata that isn't worth its own column (transient,
            // user-driven, or open-ended). Single column keeps the schema
            // surface narrow — any future per-key fact (favourites, tags,
            // notes, custom labels, …) nests under a top-level key without
            // requiring a migration. First consumer is connectivity-test
            // results at `$.last_test`:
            //   { last_test: { at, status, latency_ms, error_code?,
            //                  error_message?, suggestion?, suite_results? } }
            // Writers must use SQLite's `json_set(COALESCE(extra,'{}'),
            // '$.<key>', json(?))` so concurrent updates to different
            // subkeys don't clobber each other.
            (
                "extra",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN extra TEXT",
            ),
        ] {
            ensure_column(conn, "managed_virtual_keys_cache", col, ddl)?;
        }

        // Enterprise quota rules cache (Phase 2 — design §0.5/§5.2). The proxy
        // is a client-side component with no access to the control DB, so quota
        // rules ride the delivery snapshot the same way managed keys do: the CLI
        // pulls the seat's applicable subjects from the snapshot and writes them
        // here; the proxy reads this table on its 5s vault sync to build its
        // in-memory rule snapshot + seat→group reverse index. This is a derived
        // client mirror of control's quota_subject — NOT a source of truth.
        // Shape mirrors the snapshot's SubjectSnapshot (lean: id/kind/members/
        // rules only). Full-replaced on each sync (the snapshot is the complete
        // applicable set for this account's seats).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS quota_rules_cache (
                subject_id    TEXT PRIMARY KEY,
                subject_kind  TEXT NOT NULL,
                members       TEXT,
                rules         TEXT NOT NULL DEFAULT '[]',
                baseline      TEXT,
                synced_at     INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure quota_rules_cache table: {}", e))?;

        // Stage 4 回填: per-(metric,period) current-period used baseline, JSON
        // array. Retrofit for vaults that created quota_rules_cache before this
        // column existed (the CREATE TABLE IF NOT EXISTS above is a no-op there).
        ensure_column(
            conn,
            "quota_rules_cache",
            "baseline",
            "ALTER TABLE quota_rules_cache ADD COLUMN baseline TEXT",
        )?;

        // entries routing column retrofits.
        for (col, ddl) in &[
            (
                "provider_code",
                "ALTER TABLE entries ADD COLUMN provider_code TEXT",
            ),
            ("base_url", "ALTER TABLE entries ADD COLUMN base_url TEXT"),
            // 2026-05-22 retrofit for an old-vault gap: storage.rs's
            // query_entries_with_metadata expected `last_used_at` and
            // `use_count` columns (v1.0.6+ telemetry), but the baseline
            // CREATE TABLE for `entries` never declared them and there
            // was no ALTER retrofit either. Old vaults silently fell
            // through to a column-projection fallback that aliased the
            // entire trailing range (including `extra`!) to literal
            // NULLs — so the Vault page's Last test column never
            // rendered any data, regardless of whether the write side
            // had stamped it correctly. Adding the explicit ALTERs here
            // closes the gap; storage.rs cascade still has the literal
            // fallbacks as belt-and-braces for any vault we can't reach
            // through a write conn.
            (
                "last_used_at",
                "ALTER TABLE entries ADD COLUMN last_used_at INTEGER",
            ),
            (
                "use_count",
                "ALTER TABLE entries ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
            ),
            // 2026-05-22: see managed_virtual_keys_cache.extra above for the
            // generic-extension-blob rationale; same shape and same
            // json_set() write contract apply here.
            ("extra", "ALTER TABLE entries ADD COLUMN extra TEXT"),
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

            // local_alias on provider_accounts — retrofit for rc.1 vaults.
            //
            // 2026-05-08 baseline-fold-bugfix: when v_1_0_1_alpha_1.go was
            // folded back into baseline (per §3 pre-GA pending file rule),
            // its `ALTER TABLE provider_accounts ADD COLUMN local_alias`
            // step was lost — fresh installs got the column via the
            // updated CREATE TABLE on line ~315, but EXISTING rc.1 vaults
            // (where the table was created without the column) would not
            // get it back via CREATE TABLE IF NOT EXISTS (no-op).
            //
            // main.rs reads `acct.local_alias` in 14+ sites (`aikey list`,
            // `aikey use`, `aikey rename`, web Vault page, etc.). Without
            // this retrofit, rc.1 → rc.2 upgrade breaks "no such column"
            // on first read.
            //
            // Same pattern as route_token above: idempotent has_column
            // probe + ALTER. Belt-and-braces for upgrade safety.
            ensure_column(
                conn,
                "provider_accounts",
                "local_alias",
                "ALTER TABLE provider_accounts ADD COLUMN local_alias TEXT",
            )?;

            // 2026-05-22: generic per-key extension JSON blob — see
            // managed_virtual_keys_cache.extra (above) for the rationale and
            // json_set() write contract. Same gating as route_token /
            // local_alias above: only run when provider_accounts exists.
            ensure_column(
                conn,
                "provider_accounts",
                "extra",
                "ALTER TABLE provider_accounts ADD COLUMN extra TEXT",
            )?;
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
            (
                "error_type",
                "ALTER TABLE events ADD COLUMN error_type TEXT",
            ),
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

        // 2026-05-20 第三方 Agent 接入 (App pipeline) — 两张新表 fold 进 baseline。
        // Why fold (而非新版本 module): 当前 released = v1.0.0 RC 系列 (pre-GA),
        // 项目惯例 (workflow/CD/version-naming.md §3 + 上文 fold pattern) 是
        // pre-GA 改动直接进 baseline,internal testers 走 `uninstall.sh + reinstall`,
        // 无 in-place 升级路径需求。
        //
        // Schema 设计 spec:
        //   - 主方案 §11.C "App Key 撤销传播" 与 §11 schema 示例
        //   - 实施路线图 §3.2.1.B
        //   - ER 图 §1.2 / §1.3 / §2.2
        //
        // 关键决策点 (route_token 字段):
        //   - app_keys.route_token = **明文** aikey_app_<64hex> (不是 hash)。
        //     Why: aikey-proxy 的 vkeys.Registry byToken map 用明文 token 做 key
        //     (跟 entries.route_token / provider_accounts.route_token 同模式),
        //     Authorization header 来的就是明文,hash 后无法匹配。
        //     vault 文件已经 Argon2id + AES-256-GCM 加密保护,route_token 作为
        //     vault 内字段已经受保护,不需要在 vault 之上再 hash。
        //   - app_keys.token_hash = 可选 sha256(route_token),仅用于审计场景
        //     (e.g., 日志只想 log hash 不想 log 明文 token),写或不写 proxy 行为不变。
        //
        // Phase 0 spike 验证 (Day 2 报告):
        //   roadmap20260320/技术实现/阶段4-增值版/2026-05-20-Phase0-spike-day2.md §3
        // 2026-05-21 Phase 2 阶段 0: column renamed `protocols` → `upstreams`.
        // Why: `protocols` was ambiguous (was it inbound URL wire-format or
        // upstream provider?). Phase 2's protocol-translator splits the two
        // — inbound is always OpenAI shape; the field declares which UPSTREAM
        // PROVIDERS the Agent will route to via body.model. See LangChain
        // wire-protocol research at roadmap20260320/技术实现/protocol-translator/langchain-wire-protocol-research.md
        // for the alignment rationale. Pre-GA fold (no in-place upgrade);
        // existing dev vaults need `uninstall.sh + reinstall`.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_records (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                vendor TEXT,
                upstreams TEXT NOT NULL,
                app_kind TEXT NOT NULL DEFAULT 'third-party',
                follow_user_active INTEGER NOT NULL DEFAULT 0,
                -- B-mode (credential-mode-architecture SPEC §1.1 + §3.1):
                --   bound_alias = snapshot of the active key at install time;
                --   first-party apps that want a stable identity reference
                --   (without following later aikey use changes) set this and
                --   clear follow_user_active. Mutex with follow_user_active
                --   enforced by ensure_first_party_app_keys self-heal +
                --   aikey app create/update command validation (see SPEC §3.2).
                --   Not a DDL CHECK because retrofitting one on an existing
                --   table requires a costly table rebuild and the SPEC
                --   explicitly assigns enforcement to the migrations + CLI
                --   layer.
                bound_alias TEXT,
                bound_at INTEGER,
                -- D-mode (observe_user_active, SPEC §1.4 / §3.1):
                --   observe_streams      — JSON array, simple-string or
                --                          object form (payload_level).
                --   observe_consent_*    — audit fields for payload_level=full.
                observe_streams TEXT,
                observe_consent_at INTEGER,
                observe_consent_email TEXT,
                -- E-mode (sync_filter, SPEC §1.5.4):
                --   filter_stages         — JSON array of stage names
                --                           (pre_forward today). Non-empty
                --                           rows return 501 today (no impl);
                --                           shipped now to lock the contract
                --                           for P4.
                --   filter_priority       — chain ordering; smaller = earlier.
                --   filter_timeout_policy — fail_open | fail_closed.
                --   filter_record_allow   — 0/1; whether the local self-view
                --                           records allow (clean-scan) events.
                --                           Default 0 (off, save space). The
                --                           proxy reads it and passes it to the
                --                           detector as env so the detector can
                --                           skip emitting allow events at source.
                filter_stages TEXT,
                filter_priority INTEGER,
                filter_timeout_policy TEXT,
                filter_record_allow INTEGER NOT NULL DEFAULT 0,
                requested_permissions TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                CHECK (app_kind IN ('third-party', 'first-party')),
                CHECK (follow_user_active IN (0, 1))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure app_records: {}", e))?;

        // filter_record_allow retrofit (2026-06-03): unlike the other
        // app_records columns (CREATE-TABLE-only per the note below), this one
        // is added to an ALREADY-DEPLOYED table — dev/real vaults that already
        // ran the prior baseline have app_records WITHOUT it, and forcing an
        // uninstall+reinstall to gain one boolean flag is unacceptable. So we
        // ALTER-retrofit idempotently (same has_column-guarded pattern the
        // `entries` table uses). The CREATE TABLE above carries it for fresh
        // installs; this keeps the two in lockstep.
        ensure_column(
            conn,
            "app_records",
            "filter_record_allow",
            "ALTER TABLE app_records ADD COLUMN filter_record_allow INTEGER NOT NULL DEFAULT 0",
        )?;

        // No ALTER TABLE retrofit for the OTHER `app_records` columns: this
        // table was added 2026-05-20 and is still pre-GA, so the project
        // convention (see `entries` ALTER history vs the Kimi-split fold note at
        // the top of this file) is "modify CREATE TABLE in-place, dev users
        // uninstall+reinstall". The B/D/E columns sit in the CREATE TABLE
        // statement above as the single source of truth.
        //
        // Drift防退化: keep the CREATE TABLE column list in lockstep with
        // the Go side's pragma_table_info fence test
        // (app_pipeline_tables_created_by_baseline below).

        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_keys (
                key_id TEXT PRIMARY KEY,
                app_slug TEXT NOT NULL REFERENCES app_records(slug) ON DELETE CASCADE,
                route_token TEXT NOT NULL UNIQUE,
                token_hash TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at INTEGER,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                last_used_at INTEGER,
                CHECK (status IN ('active', 'paused', 'revoked'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure app_keys: {}", e))?;

        // Indexes — 跟主方案 §11.C / 路线图 §3.2.1.B 一致。
        //   - idx_app_keys_route_token: UNIQUE 已经隐式建索引, 显式声明仅为可读
        //     (Registry 命中走 in-memory map, 不真打 DB)。
        //   - idx_app_keys_token_hash: PARTIAL index 只对非 NULL 行建, 减少体积
        //     (MVP 多数 token_hash=NULL)。
        //   - idx_app_keys_slug_status: 让 "按 slug 找 active" 走 index scan
        //     (Registry 启动加载 + revoke/rotate 批量更新都用这个 prefix)。
        for (name, ddl) in &[
            (
                "idx_app_keys_route_token",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_app_keys_route_token ON app_keys(route_token)",
            ),
            (
                "idx_app_keys_token_hash",
                "CREATE INDEX IF NOT EXISTS idx_app_keys_token_hash ON app_keys(token_hash) WHERE token_hash IS NOT NULL",
            ),
            (
                "idx_app_keys_slug_status",
                "CREATE INDEX IF NOT EXISTS idx_app_keys_slug_status ON app_keys(app_slug, status)",
            ),
        ] {
            conn.execute(ddl, [])
                .map_err(|e| format!("Failed to ensure index {}: {}", name, e))?;
        }

        // Zero-config first-party app registration. The `degrade-detector`
        // app's Bearer is a compiled-in CONSTANT, not a per-install
        // random — every vault gets the same row on baseline upgrade.
        //
        // Why: trust-local was repeatedly losing its env-injected Bearer
        // across launchd restarts (no plist mechanism to persist it),
        // causing silent Check failures. Decision 2026-05-22 (user):
        // 稳定性 > Bearer 唯一性. The Bearer is NOT a secret —
        // aikey-proxy is loopback-only and vault holds the actual
        // upstream credentials. See requirements/
        // 2026-05-22-l3-rhythm-signal-design-rules.md §1.3.
        //
        // Coupling: the constant below MUST match
        // `degrade-detector/server_local/services/check_orchestrator.py
        // ::FIRST_PARTY_APP_KEY`. Renaming requires updating both.
        ensure_first_party_app_keys(conn)?;

        // Delivery-integrity source identity (2026-05-30). One vault = one
        // upload "source"; the proxy stamps this on every reported event so the
        // collector can detect per-source sequence gaps. Seeded HERE (in the
        // idempotent baseline that upgrade_all runs on every command) rather
        // than only at vault init, so EXISTING vaults get backfilled too — the
        // CLI vault uses a single-baseline pure-idempotency model (no numbered
        // migration dispatch), so a new value belongs in this upgrade path, the
        // same as ensure_first_party_app_keys above. INSERT OR IGNORE keeps an
        // already-present identity stable. Must match the proxy reader
        // (supervisor.go SourceIdentityKey) and storage.rs SOURCE_IDENTITY_KEY.
        conn.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES ('runtime.source_identity', ?)",
            rusqlite::params![crate::storage::new_source_identity().as_bytes().to_vec()],
        )
        .map_err(|e| format!("Failed to seed source_identity: {}", e))?;

        Ok(())
    }

    /// First-party Bearer registered by baseline upgrade. Same on every
    /// install (zero-config trust-local). Human-readable for log
    /// inspection — does NOT match the strict `aikey_app_<64 hex>` form
    /// that aikey-proxy's ClassifyToken normally enforces.
    ///
    /// Acceptance: aikey-proxy explicitly whitelists this exact value in
    /// `firstPartyAppBearerWhitelist` across 3 packages (dispatch /
    /// vault / supervisor). Vault Registry loader + proxy dispatch both
    /// short-circuit the strict-form check when the token matches the
    /// whitelist. See SPEC §1.3 for the security model.
    ///
    /// Twin constant lives at
    /// `degrade-detector/server_local/services/check_orchestrator.py::FIRST_PARTY_APP_KEY`;
    /// both must change together (plus all 3 Go whitelist entries).
    pub(super) const DEGRADE_DETECTOR_FIRST_PARTY_BEARER: &str =
        "aikey_app_internal_degrade_detector_v1";

    /// Ensure the first-party `degrade-detector` app + Bearer exists in
    /// vault AND is in `status='active'`.
    ///
    /// **Self-healing behavior** (2026-05-23 fix): if a prior
    /// `aikey app rotate degrade-detector` or `aikey app revoke
    /// degrade-detector` marked the constant Bearer row `status='revoked'`,
    /// this function flips it back to `'active'` on every aikey-cli
    /// command run. Otherwise the zero-config zero-touch promise breaks
    /// the moment a user runs any bulk-revoke command — they'd then
    /// need to know there's an internal magic key to manually revive.
    ///
    /// Idempotent: when the row already exists with `status='active'`,
    /// the UPDATE matches zero rows changed (no-op) and INSERT OR IGNORE
    /// keeps the existing PK / route_token.
    fn ensure_first_party_app_keys(conn: &Connection) -> Result<(), String> {
        // app_records row — INSERT OR IGNORE keeps any existing row's
        // app_kind / follow_user_active untouched (idempotent on PK=slug).
        conn.execute(
            "INSERT OR IGNORE INTO app_records
             (slug, name, vendor, upstreams, app_kind, follow_user_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "degrade-detector",
                // User-facing display name follows the project naming
                // convention pinned 2026-05-23 in trust-check/index.tsx:
                // user-facing UI uses "Trust Check" (action name + sidebar
                // + route + CSS namespace). "Degrade Detector" stays as
                // the marketing / repo-path / manifest name only. This
                // INSERT is the "vault row exists" fallback for paths
                // where install_service.sh's upsert never runs (vault
                // locked, CLI missing, etc.) — must match the install
                // script's --name "Trust Check" to avoid display drift.
                "Trust Check",
                "AiKey Labs",
                r#"["anthropic"]"#, // JSON array, matches register/list code
                "first-party",
                1_i64, // follow_user_active = true
            ],
        )
        .map_err(|e| format!("ensure first-party app_record: {}", e))?;

        // 1. INSERT (or skip if already there).
        conn.execute(
            "INSERT OR IGNORE INTO app_keys
             (key_id, app_slug, route_token, status)
             VALUES (?1, ?2, ?3, 'active')",
            params![
                "internal-degrade-detector-v1",
                "degrade-detector",
                DEGRADE_DETECTOR_FIRST_PARTY_BEARER,
            ],
        )
        .map_err(|e| format!("ensure first-party app_key (insert): {}", e))?;

        // 2. Self-heal: if the row was previously revoked / paused (e.g.
        // by `aikey app rotate degrade-detector` bulk-revoking all
        // existing keys before issuing a new one), flip it back to
        // active. The constant Bearer is the zero-config promise; users
        // shouldn't have to know it exists to "un-revoke" it.
        conn.execute(
            "UPDATE app_keys SET status='active'
             WHERE key_id=?1 AND status != 'active'",
            params!["internal-degrade-detector-v1"],
        )
        .map_err(|e| format!("ensure first-party app_key (self-heal): {}", e))?;

        // 2b. D-mode default subscription (2026-05-23, SPEC §3.3):
        //
        // degrade-detector's L1 rhythm fingerprint is sourced from the
        // user_chat event stream (real conversations the user has via
        // their primary credential), so the first-party row must always
        // declare that subscription. Self-heal pattern matches the
        // B-mode upgrade below — set only when observe_streams is NULL
        // (covers fresh-install + pre-P3 retrofit), never overwrite a
        // user-customised value.
        //
        // payload_level defaults to "metadata"; observe_consent_* stay
        // NULL because metadata-level subscriptions don't carry body
        // bytes (SPEC §1.4.2). If a future Agent (e.g., compliance)
        // wants `full` body, it must go through `aikey app create
        // --observe-full <stream>` which prompts the user explicitly.
        conn.execute(
            "UPDATE app_records
                SET observe_streams = '[\"user_chat\"]',
                    updated_at      = strftime('%s', 'now')
              WHERE slug='degrade-detector'
                AND observe_streams IS NULL",
            [],
        )
        .map_err(|e| format!("ensure first-party observe_streams: {}", e))?;

        // 3. B-mode self-upgrade — DISABLED 2026-05-23 ("Mode A trial"):
        //
        // Per product decision 2026-05-23, the Trust Check (degrade-detector)
        // app reverts to Mode A so its bound credential dynamically follows
        // `aikey use` instead of staying snapshotted. The day-to-day UX
        // win is "the binding shown on /user/apps matches the key the user
        // currently has active". Trade-off: SPEC §6.1's "alias↔active
        // label deception" guard is partially re-introduced for App pipeline
        // traffic (the manual Check button is unaffected because it uses
        // Mode C `/probe/<alias>/v1/messages` which carries the alias
        // explicitly — see degrade-detector/server_local/services/
        // check_orchestrator.py:312-318). When M2 lands real L3 cascade
        // verify that calls `/apps/degrade-detector/v1/messages`, the L3
        // baseline-stability question must be revisited — either pin Mode
        // B back on, or design L3 to tolerate active-key switches.
        //
        // Why we ENFORCE Mode A instead of just not running the upgrade:
        // existing vaults that already went through the now-disabled
        // upgrade path carry stale `bound_alias` values. The proxy
        // resolver short-circuits on non-empty bound_alias even when
        // follow_user_active=1, so we MUST clear bound_alias to actually
        // reach the default-profile lookup. Idempotent: rows already in
        // A mode with NULL bound_alias are a no-op.
        enforce_mode_a_for_degrade_detector(conn)?;

        Ok(())
    }

    /// 2026-05-23 — Mode A enforcement for degrade-detector. Counter-
    /// migration to `self_upgrade_degrade_detector_to_b_mode` (now
    /// disabled): flip any row in Mode B back to Mode A. Must run on
    /// every CLI startup so a stray `aikey app register --first-party
    /// --follow-user-active=false` re-create can't silently land users
    /// back in Mode B.
    fn enforce_mode_a_for_degrade_detector(conn: &Connection) -> Result<(), String> {
        conn.execute(
            "UPDATE app_records
                SET follow_user_active = 1,
                    bound_alias        = NULL,
                    bound_at           = NULL,
                    updated_at         = strftime('%s', 'now')
              WHERE slug='degrade-detector'
                AND (follow_user_active = 0 OR bound_alias IS NOT NULL)",
            [],
        )
        .map_err(|e| format!("enforce Mode A for degrade-detector: {}", e))?;

        Ok(())
    }

    /// Try to flip the degrade-detector app_records row from A mode
    /// (follow_user_active=1, bound_alias IS NULL) to B mode by
    /// snapshotting the user's current active credential.
    ///
    /// Returns Ok(()) in three cases:
    ///   - row not in A mode (already B mode, or row absent) → no-op
    ///   - no active key set yet → no-op (will retry next time)
    ///   - active key is a team key → no-op (B mode only supports
    ///     personal + OAuth aliases; team-active users stay in A mode)
    ///   - upgrade performed → row patched, returns Ok
    ///
    /// Surfaces error only on real DB failures.
    fn self_upgrade_degrade_detector_to_b_mode(conn: &Connection) -> Result<(), String> {
        // Read the current row state. If the row is not in A mode (i.e.
        // already in B mode, or revoked/missing), there's nothing to do.
        let in_legacy_a_mode: bool = conn
            .query_row(
                "SELECT 1 FROM app_records
                  WHERE slug='degrade-detector'
                    AND follow_user_active=1
                    AND bound_alias IS NULL",
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !in_legacy_a_mode {
            return Ok(());
        }

        // Resolve the user's active credential to a probe-pipeline-style
        // alias name. None means "no active set" or "team-active" — both
        // map to "stay in A mode" (no-op).
        let Some(alias_name) = resolve_active_alias_for_b_mode(conn)? else {
            return Ok(());
        };

        conn.execute(
            "UPDATE app_records
                SET follow_user_active = 0,
                    bound_alias = ?1,
                    bound_at = strftime('%s', 'now'),
                    updated_at = strftime('%s', 'now')
              WHERE slug='degrade-detector'
                AND follow_user_active = 1
                AND bound_alias IS NULL",
            params![alias_name],
        )
        .map_err(|e| format!("upgrade degrade-detector to B mode: {}", e))?;

        Ok(())
    }

    /// Read the user's current active credential and return its alias
    /// form (suitable for vault.GetAliasCredential lookup in aikey-proxy).
    ///
    /// Maps:
    ///   - active_key_type='personal'               → active_key_ref (already an alias)
    ///   - active_key_type='personal_oauth_account' → provider_accounts.local_alias (if set, non-empty)
    ///                                                else display_identity
    ///   - active_key_type='team'                   → None (team aliases unsupported)
    ///   - missing config rows / unknown type       → None
    fn resolve_active_alias_for_b_mode(conn: &Connection) -> Result<Option<String>, String> {
        let read_text = |key: &str| -> Result<Option<String>, String> {
            conn.query_row(
                "SELECT CAST(value AS TEXT) FROM config WHERE key=?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("read config {}: {}", key, other)),
            })
        };

        let (Some(key_type), Some(key_ref)) =
            (read_text("active_key_type")?, read_text("active_key_ref")?)
        else {
            return Ok(None);
        };

        match key_type.as_str() {
            "personal" => Ok(Some(key_ref)),
            "personal_oauth_account" => {
                let alias: Option<String> = conn
                    .query_row(
                        "SELECT COALESCE(NULLIF(local_alias, ''), display_identity)
                           FROM provider_accounts
                          WHERE provider_account_id = ?1",
                        params![key_ref],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(format!(
                            "lookup oauth alias for account_id={}: {}",
                            key_ref, other
                        )),
                    })?;
                Ok(alias.filter(|s| !s.is_empty()))
            }
            // team / unknown → stay in A mode
            _ => Ok(None),
        }
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
    use rusqlite::{params, Connection};

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

    /// Delivery-integrity regression (2026-06-01, caught by live E2E): an
    /// EXISTING vault (config table already present, no source_identity) must
    /// get `runtime.source_identity` backfilled by upgrade_all — otherwise the
    /// proxy logs "source_identity missing" and emits v1 events without a
    /// source_seq, silently disabling gap detection. The original migrate_v8
    /// approach was dead code (CLI vault has no numbered-migration dispatch);
    /// the fix seeds in baseline::upgrade, which upgrade_all runs every time.
    #[test]
    fn upgrade_all_backfills_source_identity_on_existing_vault() {
        let conn = Connection::open_in_memory().expect("open");
        // Simulate a pre-feature vault: config table exists, no source_identity.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
            [],
        )
        .unwrap();
        let before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM config WHERE key='runtime.source_identity'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, 0, "precondition: no source_identity yet");

        upgrade_all(&conn).expect("upgrade_all");

        let id: String = conn
            .query_row(
                "SELECT CAST(value AS TEXT) FROM config WHERE key='runtime.source_identity'",
                [],
                |r| r.get(0),
            )
            .expect("source_identity must be backfilled by upgrade_all");
        assert_eq!(id.len(), 36, "must be a UUID (8-4-4-4-12), got {:?}", id);
        assert_eq!(id.matches('-').count(), 4, "UUID dash layout");

        // Stable across re-runs (INSERT OR IGNORE never overwrites).
        upgrade_all(&conn).expect("second upgrade_all");
        let id2: String = conn
            .query_row(
                "SELECT CAST(value AS TEXT) FROM config WHERE key='runtime.source_identity'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(id, id2, "source_identity must be stable across upgrades");
    }

    /// 2026-05-08 fold-bugfix regression test:
    ///
    /// Simulates an rc.1 vault state (provider_accounts table created
    /// WITHOUT local_alias column — that's the shape rc.1's baseline
    /// produced before the 2026-05-08 mid-cycle fold absorbed the
    /// v_1_0_1_alpha_1 column add into baseline.go's CREATE TABLE).
    ///
    /// Then runs upgrade_all() (rc.2 binary's path) and asserts:
    ///   1. provider_accounts.local_alias column is NOW present
    ///   2. existing row's data is preserved
    ///   3. column accepts NULL (the historical default for rc.1 rows)
    ///
    /// Without the ensure_column ALTER retrofit at line ~470, this
    /// test would fail — `CREATE TABLE IF NOT EXISTS` is a no-op when
    /// the table exists, so the new column from baseline's CREATE
    /// TABLE statement never lands on rc.1 vaults.
    ///
    /// This is the regression guard for the rc.1 → rc.2 in-place
    /// upgrade path (covered live by the personal upgrade simulation
    /// at workflow/versions/upgrade-simulations/.../personal/).
    #[test]
    fn rc1_to_rc2_provider_accounts_local_alias_retrofit() {
        let conn = Connection::open_in_memory().expect("open");

        // Simulate rc.1's provider_accounts shape: 14 columns INCLUDING
        // route_token (added by the legacy v_1_0_4_alpha module that
        // shipped with rc.1's registry) but NOT local_alias (which was
        // added later by v_1_0_1_alpha_1 between rc.1 and rc.2 — the
        // file folded back into baseline by 2026-05-08 fold).
        //
        // Verified against the 2026-05-06 personal upgrade-simulation's
        // pre-migration.json which captured rc.1's actual vault and
        // recorded `provider_accounts: 14 columns, has_local_alias: 0`.
        conn.execute_batch(
            "CREATE TABLE provider_accounts (
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
                route_token          TEXT,
                use_count            INTEGER NOT NULL DEFAULT 0,
                UNIQUE(provider, external_id)
            );
            INSERT INTO provider_accounts (provider_account_id, provider, auth_type, display_identity)
            VALUES ('test-acct-rc1', 'anthropic', 'oauth', 'test@rc1.example.com');",
        )
        .expect("seed rc.1-shape provider_accounts");

        // Sanity: pre-upgrade column count is 14 (rc.1 baseline shape).
        let pre_cols = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('provider_accounts')",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(pre_cols, 14, "rc.1-shape table should have 14 columns");

        // Run upgrade_all (rc.2's path).
        upgrade_all(&conn).expect("upgrade_all on rc.1-shape vault");

        // Assert local_alias is now present.
        let has_local_alias: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('provider_accounts') WHERE name='local_alias'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            has_local_alias, 1,
            "local_alias retrofit failed — rc.1 → rc.2 upgrade would break"
        );

        // Assert pre-existing row preserved.
        let display: String = conn
            .query_row(
                "SELECT display_identity FROM provider_accounts WHERE provider_account_id='test-acct-rc1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(display, "test@rc1.example.com");

        // Assert local_alias is NULL for the pre-existing row (ALTER ADD COLUMN
        // doesn't backfill — this is the documented rc.1 → rc.2 behavior).
        let local_alias: Option<String> = conn
            .query_row(
                "SELECT local_alias FROM provider_accounts WHERE provider_account_id='test-acct-rc1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            local_alias.is_none(),
            "pre-existing rc.1 row's local_alias should be NULL after retrofit"
        );

        // Idempotent: re-running must succeed.
        upgrade_all(&conn).expect("second upgrade_all must be idempotent");
    }

    // T26 + cycle test were both deleted 2026-05-06: they exercised the
    // multi-version chain (rollback to v1.0.2-alpha then re-upgrade
    // through v1.0.3, v1.0.4) which no longer exists post-fold. After
    // the 2026-05-08 second fold (v1.0.1-alpha.1 + Kimi split also
    // absorbed into v1.0.0 baseline), the registry is again single-version
    // — no chain to test partial-state recovery against. Re-add tests when
    // the next post-GA cycle lands and produces a real chain.

    // ---------------------------------------------------------------------
    // 2026-05-20 App pipeline tables (third-party Agent 接入) regression tests.
    // ---------------------------------------------------------------------

    /// app_records + app_keys tables are created by baseline.upgrade() with
    /// the documented schema shape (columns + indexes). This pins the
    /// schema-Code coherence invariant (CLAUDE.md "Schema-Code 一致性") —
    /// if anyone alters the CREATE TABLE statements without updating Reader
    /// code on the Go side, this test catches the column-name drift.
    #[test]
    fn app_pipeline_tables_created_by_baseline() {
        let conn = fresh_vault();

        assert!(
            table_exists(&conn, "app_records"),
            "app_records table must be created by baseline.upgrade()"
        );
        assert!(
            table_exists(&conn, "app_keys"),
            "app_keys table must be created by baseline.upgrade()"
        );

        // Pin exact column set so any future schema drift is caught here
        // (rather than at runtime when proxy/CLI SELECTs explode).
        let app_records_cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('app_records') ORDER BY cid")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            app_records_cols,
            vec![
                "slug",
                "name",
                "vendor",
                "upstreams",
                "app_kind",
                "follow_user_active",
                // 2026-05-23 P2: B-mode columns (credential-mode-architecture SPEC §3.1).
                "bound_alias",
                "bound_at",
                // 2026-05-23 P3: D-mode columns (observe_user_active, SPEC §1.4 / §3.1).
                "observe_streams",
                "observe_consent_at",
                "observe_consent_email",
                // 2026-05-23 P3: E-mode columns — protocol-contract only,
                // proxy returns 501 when any row has filter_stages set
                // (SPEC §1.5.7). Columns ship now to lock the schema
                // before the implementation lands in P4.
                "filter_stages",
                "filter_priority",
                "filter_timeout_policy",
                "requested_permissions",
                "created_at",
                "updated_at",
            ],
            "app_records columns drifted — keep in lockstep with credential-mode-architecture SPEC §3.1"
        );

        let app_keys_cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('app_keys') ORDER BY cid")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            app_keys_cols,
            vec![
                "key_id",
                "app_slug",
                "route_token",
                "token_hash",
                "status",
                "expires_at",
                "created_at",
                "last_used_at",
            ],
            "app_keys columns drifted — Day 2 spike route_token decision broken"
        );

        // Indexes pin: route_token UNIQUE + token_hash PARTIAL + slug_status composite.
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='app_keys' AND name LIKE 'idx_app_keys_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 3, "app_keys must have 3 named indexes");
    }

    /// Zero-config first-party Bearer is registered by baseline upgrade.
    /// The `degrade-detector` app + its compiled-in Bearer must exist
    /// in vault after `upgrade_all()` so trust-local can talk to
    /// aikey-proxy without env-injection ceremony. See SPEC
    /// requirements/2026-05-22-l3-rhythm-signal-design-rules.md §1.3
    /// and the matching Python constant in trust-local.
    #[test]
    fn first_party_app_keys_registered_by_baseline() {
        let conn = fresh_vault();

        // app_records row present, marked first-party + follow_user_active.
        let (slug, name, app_kind, follow): (String, String, String, i64) = conn
            .query_row(
                "SELECT slug, name, app_kind, follow_user_active
                   FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("degrade-detector app_records row missing after baseline upgrade");
        assert_eq!(slug, "degrade-detector");
        assert_eq!(name, "Trust Check");
        assert_eq!(app_kind, "first-party");
        assert_eq!(follow, 1);

        // app_keys row present, status=active, with the compiled-in
        // Bearer constant. The route_token MUST equal the Python
        // FIRST_PARTY_APP_KEY in
        // degrade-detector/server_local/services/check_orchestrator.py
        // — drift here breaks zero-config trust-local.
        let (route_token, status): (String, String) = conn
            .query_row(
                "SELECT route_token, status FROM app_keys
                  WHERE app_slug='degrade-detector'
                    AND key_id='internal-degrade-detector-v1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("first-party Bearer row missing after baseline upgrade");
        assert_eq!(route_token, "aikey_app_internal_degrade_detector_v1");
        assert_eq!(status, "active");
        // Format note: this value DOES NOT match the strict
        // `aikey_app_<64 hex>` form — it relies on aikey-proxy's
        // `firstPartyAppBearerWhitelist` to be accepted. The 3 Go
        // whitelist entries (proxy/dispatch, vault/route_token_form,
        // supervisor/team_token_normalize) and the Python twin in
        // check_orchestrator.py must all carry this exact string.
        assert!(route_token.starts_with("aikey_app_"));
    }

    /// Self-heal: if the constant Bearer row is `status='revoked'`
    /// (e.g. after `aikey app rotate degrade-detector` or a manual
    /// `aikey app revoke`), the next baseline-upgrade run MUST flip
    /// it back to `'active'`. Zero-config promise: users never need
    /// to know this internal key exists.
    ///
    /// Origin: 2026-05-23 — `aikey app rotate` bulk-revoked all 17
    /// degrade-detector app_keys including ours, breaking the Check
    /// button with APP_KEY_NOT_FOUND. INSERT OR IGNORE skipped the
    /// revoked row, leaving it inactive.
    #[test]
    fn first_party_app_key_self_heals_if_revoked() {
        let conn = fresh_vault();

        // Pre-condition: baseline already left the row in active state.
        let status: String = conn
            .query_row(
                "SELECT status FROM app_keys WHERE key_id='internal-degrade-detector-v1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "active");

        // Simulate `aikey app rotate / revoke` flipping it.
        conn.execute(
            "UPDATE app_keys SET status='revoked'
             WHERE key_id='internal-degrade-detector-v1'",
            [],
        )
        .unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM app_keys WHERE key_id='internal-degrade-detector-v1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "revoked", "fixture step failed");

        // Re-run baseline upgrade.
        super::upgrade_all(&conn).unwrap();

        // Row should be back to active.
        let status: String = conn
            .query_row(
                "SELECT status FROM app_keys WHERE key_id='internal-degrade-detector-v1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            status, "active",
            "ensure_first_party_app_keys must self-heal revoked rows"
        );
    }

    /// Re-running baseline upgrade must NOT clobber existing app_keys —
    /// idempotent INSERT OR IGNORE. If a user has rotated to a custom
    /// Bearer, that row stays alongside the constant.
    #[test]
    fn first_party_app_keys_idempotent_across_runs() {
        let conn = fresh_vault();

        // First baseline upgrade ran via fresh_vault. Add a synthetic
        // "custom" Bearer row (mimicking a `aikey app register` from
        // before this migration shipped) and re-run upgrade.
        conn.execute(
            "INSERT INTO app_keys (key_id, app_slug, route_token, status)
             VALUES ('synthetic-rotated', 'degrade-detector', 'aikey_app_synthetic', 'active')",
            [],
        )
        .unwrap();

        // Re-run baseline upgrade — must be a no-op for both rows.
        super::upgrade_all(&conn).unwrap();

        // Both rows still present.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM app_keys WHERE app_slug='degrade-detector'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2, "constant + synthetic Bearers must coexist");
    }

    // ---------------------------------------------------------------------
    // P2 mode B self-upgrade tests (2026-05-23, credential-mode-architecture
    // SPEC §3.3 / §6.1). The degrade-detector row must auto-flip from A
    // mode (follow_user_active=1, bound_alias=NULL) to B mode whenever
    // a personal or OAuth active credential is set — but stay in A mode
    // when there's no active or the active is a team key.
    // ---------------------------------------------------------------------

    /// No-active case: a brand-new vault with `aikey use` never run leaves
    /// degrade-detector in A mode. The self-upgrade is a no-op (will retry
    /// next CLI run, after the first `aikey use`).
    #[test]
    fn degrade_detector_stays_in_a_mode_when_no_active() {
        let conn = fresh_vault();

        // No active_key_* rows inserted → upgrade_all is essentially a re-run.
        super::upgrade_all(&conn).unwrap();

        let (follow, bound): (i64, Option<String>) = conn
            .query_row(
                "SELECT follow_user_active, bound_alias FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(follow, 1, "no active → must stay in A mode (follow=1)");
        assert!(bound.is_none(), "no active → bound_alias must be NULL");
    }

    /// Personal-active case: `aikey use my-personal-key` (active_key_type=personal,
    /// active_key_ref=alias) — self-upgrade picks the alias verbatim as
    /// bound_alias and flips to B mode.
    #[test]
    #[ignore = "Mode A trial 2026-05-23: B-mode self-upgrade currently disabled — see migrations.rs enforce_mode_a_for_degrade_detector. Re-enable when M2 L3 cascade lands and baseline stability needs Mode B back."]
    fn degrade_detector_upgrades_to_b_mode_for_personal_active() {
        let conn = fresh_vault();

        // Simulate `aikey use my-personal-key` writes.
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_type', 'personal')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_ref', 'my-personal-key')",
            [],
        )
        .unwrap();

        super::upgrade_all(&conn).unwrap();

        let (follow, bound, bound_at): (i64, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT follow_user_active, bound_alias, bound_at FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            follow, 0,
            "personal active → must flip to B mode (follow=0)"
        );
        assert_eq!(
            bound.as_deref(),
            Some("my-personal-key"),
            "bound_alias must be the personal alias verbatim"
        );
        assert!(
            bound_at.is_some(),
            "bound_at must be set when transitioning to B mode"
        );
    }

    /// OAuth-active case: active_key_ref is the provider_account_id, not the
    /// alias. The self-upgrade must dereference it to local_alias (or
    /// display_identity fallback) so bound_alias is suitable for
    /// vault.GetAliasCredential lookup in aikey-proxy.
    #[test]
    #[ignore = "Mode A trial 2026-05-23: see degrade_detector_upgrades_to_b_mode_for_personal_active"]
    fn degrade_detector_upgrades_to_b_mode_for_oauth_active_uses_display_identity() {
        let conn = fresh_vault();

        // Seed an OAuth account row + corresponding active config.
        conn.execute(
            "INSERT INTO provider_accounts \
             (provider_account_id, provider, auth_type, display_identity, status) \
             VALUES ('acct-abc', 'anthropic', 'oauth', 'user@host.com', 'active')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_type', 'personal_oauth_account')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_ref', 'acct-abc')",
            [],
        )
        .unwrap();

        super::upgrade_all(&conn).unwrap();

        let bound: Option<String> = conn
            .query_row(
                "SELECT bound_alias FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            bound.as_deref(),
            Some("user@host.com"),
            "OAuth active → bound_alias must dereference to display_identity (suitable for GetAliasCredential)"
        );
    }

    /// OAuth-active with local_alias rename takes precedence over display_identity.
    #[test]
    #[ignore = "Mode A trial 2026-05-23: see degrade_detector_upgrades_to_b_mode_for_personal_active"]
    fn degrade_detector_upgrades_to_b_mode_oauth_local_alias_wins() {
        let conn = fresh_vault();

        conn.execute(
            "INSERT INTO provider_accounts \
             (provider_account_id, provider, auth_type, display_identity, local_alias, status) \
             VALUES ('acct-xyz', 'anthropic', 'oauth', 'noisy@email.com', 'my-renamed', 'active')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_type', 'personal_oauth_account')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_ref', 'acct-xyz')",
            [],
        )
        .unwrap();

        super::upgrade_all(&conn).unwrap();

        let bound: Option<String> = conn
            .query_row(
                "SELECT bound_alias FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            bound.as_deref(),
            Some("my-renamed"),
            "local_alias must win over display_identity when set"
        );
    }

    /// Team-active case: bound_alias requires GetAliasCredential support,
    /// which only resolves personal + OAuth today. Team users stay in A mode
    /// — graceful fallback rather than picking a non-resolvable alias.
    #[test]
    fn degrade_detector_stays_in_a_mode_for_team_active() {
        let conn = fresh_vault();

        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_type', 'team')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_ref', 'vk-team-123')",
            [],
        )
        .unwrap();

        super::upgrade_all(&conn).unwrap();

        let (follow, bound): (i64, Option<String>) = conn
            .query_row(
                "SELECT follow_user_active, bound_alias FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(follow, 1, "team active → stay in A mode (follow=1)");
        assert!(
            bound.is_none(),
            "team active → bound_alias must remain NULL"
        );
    }

    /// Mode A trial 2026-05-23: enforce_mode_a_for_degrade_detector
    /// must keep degrade-detector in A mode (follow=1, bound_alias=NULL)
    /// even when an active credential is set — explicit counter-test to
    /// the (now-ignored) `degrade_detector_upgrades_to_b_mode_*` cases.
    #[test]
    fn degrade_detector_stays_in_a_mode_under_mode_a_trial() {
        let conn = fresh_vault();

        // Simulate `aikey use my-personal-key` — under the legacy B-mode
        // self-upgrade this would have flipped to follow=0 + bound_alias.
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_type', 'personal')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_ref', 'my-personal-key')",
            [],
        )
        .unwrap();
        super::upgrade_all(&conn).unwrap();

        // Second run simulates a subsequent CLI invocation after the user
        // switched active to a different key. Mode A enforcement must keep
        // the row in A regardless of intervening state.
        conn.execute(
            "UPDATE config SET value='other-key' WHERE key='active_key_ref'",
            [],
        )
        .unwrap();
        super::upgrade_all(&conn).unwrap();

        let (follow, bound, bound_at): (i64, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT follow_user_active, bound_alias, bound_at FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(follow, 1, "Mode A trial: follow_user_active must remain 1");
        assert!(bound.is_none(), "Mode A trial: bound_alias must be NULL so proxy resolver falls through to default profile");
        assert!(
            bound_at.is_none(),
            "Mode A trial: bound_at must be cleared when bound_alias is cleared"
        );
    }

    /// Idempotence: once a row is in B mode, subsequent upgrade_all runs
    /// MUST NOT overwrite bound_alias even if active has changed since.
    /// The user's snapshot is sticky — that's the whole point of B mode.
    #[test]
    #[ignore = "Mode A trial 2026-05-23: see degrade_detector_upgrades_to_b_mode_for_personal_active"]
    fn degrade_detector_b_mode_sticky_across_runs() {
        let conn = fresh_vault();

        // First active → upgrade to B mode with bound_alias='first-key'.
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_type', 'personal')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('active_key_ref', 'first-key')",
            [],
        )
        .unwrap();
        super::upgrade_all(&conn).unwrap();

        // Simulate `aikey use second-key` → active_key_ref changes.
        conn.execute(
            "UPDATE config SET value='second-key' WHERE key='active_key_ref'",
            [],
        )
        .unwrap();
        super::upgrade_all(&conn).unwrap();

        let bound: Option<String> = conn
            .query_row(
                "SELECT bound_alias FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            bound.as_deref(),
            Some("first-key"),
            "bound_alias must stay sticky on subsequent runs — re-binding requires explicit aikey app update"
        );
    }

    // ---------------------------------------------------------------------
    // P3 mode D + E schema tests (2026-05-23, credential-mode-architecture
    // SPEC §1.4 / §1.5 / §3.1). The columns ship on every install and the
    // degrade-detector row gets a default ["user_chat"] subscription so
    // its L1 rhythm fingerprint pipeline has a guaranteed data source.
    // ---------------------------------------------------------------------

    /// Fresh install: degrade-detector subscribes to user_chat by default
    /// (metadata-level — no consent fields needed).
    #[test]
    fn degrade_detector_default_subscribes_to_user_chat() {
        let conn = fresh_vault();

        let (streams, consent_at, consent_email): (Option<String>, Option<i64>, Option<String>) =
            conn.query_row(
                "SELECT observe_streams, observe_consent_at, observe_consent_email
                   FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            streams.as_deref(),
            Some(r#"["user_chat"]"#),
            "first-party self-heal must default-subscribe to user_chat (metadata-level)"
        );
        assert!(
            consent_at.is_none(),
            "metadata-only subscription must not require consent"
        );
        assert!(
            consent_email.is_none(),
            "metadata-only subscription must not require consent"
        );
    }

    /// Stickiness: if the user customises observe_streams (e.g. adds the
    /// probe stream too), the self-heal must NOT overwrite it on every
    /// CLI run.
    #[test]
    fn degrade_detector_observe_streams_sticky_across_runs() {
        let conn = fresh_vault();

        // User manually expands the subscription.
        conn.execute(
            r#"UPDATE app_records SET observe_streams = '["user_chat","probe"]' WHERE slug='degrade-detector'"#,
            [],
        )
        .unwrap();

        super::upgrade_all(&conn).unwrap();

        let streams: Option<String> = conn
            .query_row(
                "SELECT observe_streams FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            streams.as_deref(),
            Some(r#"["user_chat","probe"]"#),
            "self-heal must not overwrite a user-customised observe_streams"
        );
    }

    /// E-mode contract columns exist and default to NULL (no app is a
    /// filter app on fresh install).
    #[test]
    fn e_mode_contract_columns_default_null() {
        let conn = fresh_vault();

        let (stages, priority, timeout): (Option<String>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT filter_stages, filter_priority, filter_timeout_policy
                   FROM app_records WHERE slug='degrade-detector'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(
            stages.is_none(),
            "filter_stages must default NULL — degrade-detector is NOT a filter app"
        );
        assert!(
            priority.is_none(),
            "filter_priority must default NULL when filter_stages is NULL"
        );
        assert!(
            timeout.is_none(),
            "filter_timeout_policy must default NULL when filter_stages is NULL"
        );
    }

    /// ON DELETE CASCADE: deleting an app_records row must cascade-delete
    /// all its app_keys rows. Critical invariant — without this, uninstall
    /// leaves orphan keys that proxy might still load into Registry,
    /// producing ghost tokens that can still authenticate.
    ///
    /// Why this test exists: SQLite CASCADE requires `PRAGMA foreign_keys = ON`
    /// at the connection level, not at the schema level. fresh_vault() uses
    /// `Connection::open_in_memory()` directly (NOT through storage::open_connection),
    /// so we must enable the pragma here. The pragma is set by
    /// storage.rs::open_connection in real runtime — that pragma assertion is
    /// indirectly verified by the broader storage_test suite.
    #[test]
    fn app_keys_cascade_delete_on_app_records_drop() {
        let conn = fresh_vault();
        conn.pragma_update(None, "foreign_keys", "ON")
            .expect("enable foreign_keys pragma");

        conn.execute(
            "INSERT INTO app_records (slug, name, upstreams) VALUES (?1, ?2, ?3)",
            params!["test-agent", "Test Agent", "[\"openai\"]"],
        )
        .expect("insert app_records");

        conn.execute(
            "INSERT INTO app_keys (key_id, app_slug, route_token) VALUES (?1, ?2, ?3)",
            params![
                "key-uuid-1",
                "test-agent",
                "aikey_app_aaaa0000111122223333444455556666777788889999aaaabbbbccccddddeeee"
            ],
        )
        .expect("insert app_keys");

        let pre: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM app_keys WHERE app_slug='test-agent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pre, 1, "precondition: 1 app_key row inserted");

        // CASCADE-trigger: delete the parent app_records row.
        // SECURITY NOTE: This requires PRAGMA foreign_keys = ON at the
        // connection level (set by storage::open_connection). If that
        // pragma is ever dropped, this test fails loud.
        conn.execute("DELETE FROM app_records WHERE slug='test-agent'", [])
            .expect("delete app_records");

        let post: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM app_keys WHERE app_slug='test-agent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            post, 0,
            "CASCADE failed — orphan app_keys row survived parent delete (foreign_keys pragma broken?)"
        );
    }

    /// CHECK constraints on app_records.app_kind + follow_user_active and
    /// app_keys.status pin the value-set invariants from 主方案 §11.1.
    /// Without these, a buggy writer could insert app_kind='admin' or
    /// status='deleted' and Reader code would silently route on it.
    #[test]
    fn app_pipeline_check_constraints() {
        let conn = fresh_vault();

        // app_kind must be in {'third-party', 'first-party'}.
        let bad_kind = conn.execute(
            "INSERT INTO app_records (slug, name, upstreams, app_kind) VALUES ('x', 'X', '[]', 'admin')",
            [],
        );
        assert!(
            bad_kind.is_err(),
            "app_kind='admin' must be rejected by CHECK"
        );

        // follow_user_active must be 0 or 1.
        let bad_follow = conn.execute(
            "INSERT INTO app_records (slug, name, upstreams, follow_user_active) VALUES ('y', 'Y', '[]', 2)",
            [],
        );
        assert!(
            bad_follow.is_err(),
            "follow_user_active=2 must be rejected by CHECK"
        );

        // status must be in {'active', 'paused', 'revoked'}.
        conn.execute(
            "INSERT INTO app_records (slug, name, upstreams) VALUES ('z', 'Z', '[\"openai\"]')",
            [],
        )
        .unwrap();
        let bad_status = conn.execute(
            "INSERT INTO app_keys (key_id, app_slug, route_token, status) VALUES ('k1', 'z', 'aikey_app_xx', 'deleted')",
            [],
        );
        assert!(
            bad_status.is_err(),
            "status='deleted' must be rejected by CHECK"
        );

        // route_token UNIQUE: two app_keys cannot share the same route_token.
        conn.execute(
            "INSERT INTO app_keys (key_id, app_slug, route_token) VALUES ('k1', 'z', 'aikey_app_unique')",
            [],
        )
        .unwrap();
        let dup_token = conn.execute(
            "INSERT INTO app_keys (key_id, app_slug, route_token) VALUES ('k2', 'z', 'aikey_app_unique')",
            [],
        );
        assert!(
            dup_token.is_err(),
            "duplicate route_token must be rejected by UNIQUE constraint"
        );
    }
}
