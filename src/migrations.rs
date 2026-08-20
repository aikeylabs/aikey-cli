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

// ---------------------------------------------------------------------------
// Per-build replay marker (vault-page lock-convoy fix, 2026-07-07)
// ---------------------------------------------------------------------------

/// `config` table key recording which binary BUILD last replayed the schema.
const SCHEMA_REPLAYED_BY_KEY: &str = "schema.replayed_by";

/// Identity of THIS binary for the replay marker. Includes the git revision
/// (not just the version string) so dev/dirty builds sharing a version
/// number still re-replay after a rebuild — a stale skip on a schema-
/// changing dev build would be a debugging nightmare.
fn current_schema_marker() -> String {
    format!(
        "{}:{}",
        env!("CARGO_PKG_VERSION"),
        env!("AIKEY_BUILD_REVISION")
    )
}

/// Outcome of [`ensure_schema_current`] — exposed so tests can assert the
/// fast path actually skipped.
#[derive(Debug, PartialEq, Eq)]
pub enum SchemaEnsure {
    /// Marker matched this build — no write connection was opened.
    SkippedFresh,
    /// Full idempotent replay ran (first contact of this build, or marker
    /// unreadable) and the marker was updated.
    Replayed,
}

/// Pre-dispatch schema convergence with a read-only fast path.
///
/// Why this exists (2026-07-07 vault-page lock convoy, Windows live box):
/// the vault has NO migration ledger — convergence = replaying the whole
/// idempotent baseline. Several statements in that replay (`INSERT OR
/// IGNORE` self-heal rows) are real write attempts that take SQLite's
/// write lock even when they end up ignoring. Running that on EVERY
/// command was fine for humans, but `_internal` bridge children are
/// spawned by the web console many times per page load plus background
/// polls — N concurrent replays queued on the vault write lock inflated a
/// 52ms call to 1.2-3.3s (measured), and the vault page crawled.
///
/// The schema can only change when the BINARY changes, so the replay is
/// now gated on a per-build marker in the `config` table:
/// - marker == this build (read-only probe, no write lock) → skip;
/// - anything else (missing marker / other build / unreadable / legacy
///   vault without the row) → full replay, then stamp the marker.
///
/// Trade-off (user-approved 2026-07-07): self-heal frequency drops from
/// "every command" to "once per binary build". Hand-damaged vault content
/// between upgrades now needs an explicit `aikey db upgrade` (which still
/// force-replays unconditionally) instead of healing on the next command.
///
/// Errors are returned for the caller to ignore-or-log — same "schema
/// convergence must never block the command itself" stance as before.
pub fn ensure_schema_current(vault_path: &std::path::Path) -> Result<SchemaEnsure, String> {
    let marker = current_schema_marker();

    // Fast path: probe over a NORMAL connection, not SQLITE_OPEN_READ_ONLY.
    //
    // Why not read-only (2026-07-07 Windows live regression of this very
    // fix): opening a WAL database read-only depends on adopting the -shm
    // mapping — exactly the fragile step behind the Go side's CANTOPEN(14)
    // class on Windows. The RO open failed routinely there, every probe
    // fell through to the full replay, and the write-lock convoy this
    // marker exists to kill came right back (measured: `_internal rules`
    // median 1.5s with the marker binary deployed, min 53ms ≈ solo-replay
    // cost — the fast path was never taken). A default-mode connection
    // avoids -shm adoption; the probe still only SELECTs, and WAL readers
    // never block on writers, so it stays contention-free. busy_timeout
    // guards the non-WAL edge. Probe failure of any kind (no config table
    // yet, BLOB value, corrupt db) falls through to the replay, which owns
    // real error handling.
    let probe = Connection::open(vault_path).ok().and_then(|conn| {
        let _ = conn.busy_timeout(std::time::Duration::from_millis(1000));
        conn.query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            [SCHEMA_REPLAYED_BY_KEY],
            |row| row.get::<_, String>(0),
        )
        .ok()
    });
    if probe.as_deref() == Some(marker.as_str()) {
        return Ok(SchemaEnsure::SkippedFresh);
    }

    let conn =
        Connection::open(vault_path).map_err(|e| format!("open vault for schema replay: {}", e))?;
    upgrade_all(&conn)?;
    stamp_schema_marker(&conn)?;
    Ok(SchemaEnsure::Replayed)
}

/// Record that THIS build has replayed the schema. Also called by the
/// explicit `aikey db upgrade` path so a manual force-replay flips the
/// next command onto the read-only fast path.
pub fn stamp_schema_marker(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        rusqlite::params![SCHEMA_REPLAYED_BY_KEY, current_schema_marker()],
    )
    .map_err(|e| format!("stamp schema marker: {}", e))?;
    Ok(())
}

/// Remove the replay marker. Called after `aikey db rollback` so the next
/// command re-converges the schema (preserves the pre-marker behavior
/// where any command after a same-binary rollback immediately re-upgraded;
/// the documented rollback flow installs an older binary next, whose own
/// marker differs anyway).
pub fn clear_schema_marker(conn: &Connection) {
    let _ = conn.execute(
        "DELETE FROM config WHERE key = ?1",
        [SCHEMA_REPLAYED_BY_KEY],
    );
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
        if has_column(conn, table, col) {
            return Ok(());
        }
        match conn.execute(ddl, []) {
            Ok(_) => Ok(()),
            Err(_) if has_column(conn, table, col) => {
                // Concurrent first-run schema replays can both observe the
                // column as absent. SQLite serializes their ALTER statements;
                // after the winner commits, the loser sees "duplicate column".
                // Re-read schema truth instead of treating that harmless race
                // as a broken vault. Preserve every other failure below.
                Ok(())
            }
            Err(error) => Err(format!("Failed to add {}.{}: {}", table, col, error)),
        }
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
                protocol_type        TEXT NOT NULL DEFAULT '',
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

        // Team-managed virtual key cache.
        //
        // P1e / design D-11 (解 R-D): the grain is ONE ROW PER BINDING
        // `(virtual_key_id, protocol_type, provider_code)` with the provider key
        // ciphertext RIDING EACH ROW — so one VK can carry GLM(GLM key) AND the
        // official Anthropic(official key) at once, each binding's material and
        // upstream resolved independently. The pre-P1e grain was one-VK-one-row
        // with a SCALAR credential (multiple providers were half-expressed via
        // the `supported_providers`/`provider_base_urls` blobs, which only ever
        // carried URLs — never a second protocol or a second key). Fresh installs
        // get the composite-PK shape here; existing one-VK-one-row DBs are rebuilt
        // in place by the idempotent re-grain block after the column retrofits
        // below. `cache_schema_version` = 2 marks the binding grain.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS managed_virtual_keys_cache (
                virtual_key_id       TEXT NOT NULL,
                org_id               TEXT NOT NULL,
                seat_id              TEXT NOT NULL,
                alias                TEXT NOT NULL,
                provider_code        TEXT NOT NULL DEFAULT '',
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
                cache_schema_version INTEGER NOT NULL DEFAULT 2,
                synced_at            INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (virtual_key_id, protocol_type, provider_code)
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
            // 2026-07-31: the delivery wire's binding id for this hop. Cooldown,
            // stickiness and the fallback event's from/to_binding_id all key on a
            // hop's identity, and without this column they keyed on an empty
            // string — which made cooldown a silent no-op rather than a failure.
            // Nullable and empty on old vaults: "unknown", never a made-up id.
            (
                "binding_id",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN binding_id TEXT NOT NULL DEFAULT ''",
            ),
            // 2026-06-24 (master v1.0.1-alpha.3): oauth_group fold. When a VK's
            // binding target is a oauth_group, the whole group folds into THIS
            // row — no separate client cache tables (技术方案 §2.3).
            //   oauth_group_id          != NULL marks a group-backed VK
            //   group_accounts         candidate-list metadata JSON (from the
            //                          materialized view; structural sync)
            //   routing_config         group hash/schedule/util_cap knobs JSON
            //   my_assignment_override seat's current routed account per protocol
            //                          JSON {protocol:account_id} — written by the
            //                          routing-override POLL, NOT structural sync;
            //                          empty = pure pkg/seatassign hash default
            //   group_runtime          JSON {account_id:{token ciphertext,
            //                          window_max_util_pct, window_reset_at}} via
            //                          channel ③ (volatile; NEVER refresh_token)
            (
                "oauth_group_id",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN oauth_group_id TEXT",
            ),
            (
                "group_accounts",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN group_accounts TEXT",
            ),
            (
                "routing_config",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN routing_config TEXT",
            ),
            (
                "my_assignment_override",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN my_assignment_override TEXT",
            ),
            (
                "group_runtime",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN group_runtime TEXT",
            ),
            (
                // owner_email: the owner account's email, stamped by key sync
                // (parallel to owner_account_id) so /user/vault can show
                // "Owner: <email>" — persists after that account logs out.
                "owner_email",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN owner_email TEXT",
            ),
            (
                // group_alias: the OAuth group's name (server-synced from the
                // managed-keys-snapshot, parallel to oauth_group_id/routing_config) so
                // /user/vault + `aikey use` can label WHICH group a VK belongs to — a
                // member in multiple groups gets one VK per group (2026-07-01).
                "group_alias",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN group_alias TEXT",
            ),
            // ── P0a upstream fallback (tasks 1.2 / 1.2b / 1.8) ─────────────
            //
            // 🔴 Task 1.8 — ROLLBACK SEMANTICS, claimed explicitly: there is NO
            // automatic rollback for these four columns, and that is a decision
            // rather than an omission.
            //
            // The vault cache is a REBUILDABLE PROJECTION of the control plane.
            // If it ever needs undoing, deleting the vault and letting it re-sync
            // is both simpler and safer than a `DROP COLUMN`: SQLite's DROP COLUMN
            // is version-gated (unavailable before 3.35) and forces a full table
            // rebuild — i.e. it would reintroduce exactly the re-grain hazard that
            // task 1.10's fence exists to guard, in order to remove a column whose
            // presence is harmless.
            //
            // Leaving the columns in place after a downgrade is safe: an older
            // binary simply never selects them.
            //
            // The control plane has carried the primary/fallback chain since the
            // baseline schema (managed_provider_bindings.priority /
            // .fallback_role, plus idx_mpb_vk_protocol_priority), and delivery
            // has shipped it on binding_targets all along. The vault was the
            // one place that DROPPED it — so the proxy could not know what
            // order the administrator configured.
            //
            // 🔴 Defaults reproduce pre-upgrade behavior EXACTLY: every existing
            // row becomes priority=1 / 'primary', i.e. "all primary, no
            // fallback", which is precisely how the runtime behaved before this
            // change. An upgrade must not alter routing on its own.
            (
                "priority",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN priority INTEGER NOT NULL DEFAULT 1",
            ),
            (
                "fallback_role",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN fallback_role TEXT NOT NULL DEFAULT 'primary'",
            ),
            // Route-group provenance (task 1.2b). DEFAULT '' rather than NULL so
            // the "legacy row" branch keys on emptiness consistently with
            // user_profile_provider_bindings.binding_provider_code, which has
            // been NOT NULL DEFAULT '' since it was introduced.
            //
            // 🔴 Existing rows get '' → they land in the LEGACY branch of the
            // three-state pin derivation, so behavior before and after the
            // upgrade is identical.
            (
                "route_group_id",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN route_group_id TEXT NOT NULL DEFAULT ''",
            ),
            (
                "route_group_name",
                "ALTER TABLE managed_virtual_keys_cache ADD COLUMN route_group_name TEXT NOT NULL DEFAULT ''",
            ),
        ] {
            ensure_column(conn, "managed_virtual_keys_cache", col, ddl)?;
        }

        // ── P1e / design D-11: re-grain managed_virtual_keys_cache in place ──
        //
        // A pre-P1e vault has this table with a SINGLE-column primary key
        // (`virtual_key_id`). SQLite cannot change a primary key with ALTER, so
        // move to the binding grain `(virtual_key_id, protocol_type, provider_code)`
        // via the canonical create-copy-swap. Guard: only run when the live table
        // still has exactly one PK column — fresh installs (created composite above)
        // and already-migrated vaults have three, so this is a no-op on re-run
        // (idempotent; safe to execute on every startup).
        //
        // Backfill semantics (🔴 lossless, one-way faithful): each existing
        // one-VK-one-row row becomes EXACTLY ONE binding row — its scalar
        // `(protocol_type, provider_code)` are already the composite key, and its
        // `provider_key_ciphertext` rides that row unchanged. The extra providers
        // that lived URL-only in `supported_providers`/`provider_base_urls` are NOT
        // exploded into credential-less binding rows (they have no key material —
        // that was exactly the pre-P1e limitation); they stay on the primary
        // binding row's blobs and are superseded when the re-grained server
        // projection re-syncs real per-binding material. NO ciphertext is decrypted,
        // re-encrypted, or moved across the encryption boundary here — the BLOB is
        // copied byte-for-byte, so the vault_key derivation and AES-GCM envelope are
        // untouched (第 1 级安全评审 §1e.4: this migration does not widen the
        // plaintext exposure window).
        let cache_pk_cols: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('managed_virtual_keys_cache') WHERE pk > 0",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if cache_pk_cols == 1 {
            // Rebuild inside one transaction so a crash mid-migration leaves the
            // old table intact (all-or-nothing; 🚫 no partial grain).
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| format!("mvkc re-grain: begin tx: {}", e))?;
            tx.execute_batch(
                "CREATE TABLE managed_virtual_keys_cache__p1e_new (
                    virtual_key_id       TEXT NOT NULL,
                    org_id               TEXT NOT NULL,
                    seat_id              TEXT NOT NULL,
                    alias                TEXT NOT NULL,
                    provider_code        TEXT NOT NULL DEFAULT '',
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
                    cache_schema_version INTEGER NOT NULL DEFAULT 2,
                    synced_at            INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    local_alias            TEXT,
                    supported_providers    TEXT,
                    provider_base_urls     TEXT,
                    owner_account_id       TEXT,
                    extra                  TEXT,
                    oauth_group_id         TEXT,
                    group_accounts         TEXT,
                    routing_config         TEXT,
                    my_assignment_override TEXT,
                    group_runtime          TEXT,
                    owner_email            TEXT,
                    group_alias            TEXT,
                    priority               INTEGER NOT NULL DEFAULT 1,
                    fallback_role          TEXT NOT NULL DEFAULT 'primary',
                    route_group_id         TEXT NOT NULL DEFAULT '',
                    route_group_name       TEXT NOT NULL DEFAULT '',
                    binding_id             TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (virtual_key_id, protocol_type, provider_code)
                );
                 INSERT INTO managed_virtual_keys_cache__p1e_new (
                    virtual_key_id, org_id, seat_id, alias,
                    provider_code, protocol_type, base_url,
                    credential_id, credential_revision, virtual_key_revision,
                    key_status, share_status, local_state, expires_at,
                    provider_key_nonce, provider_key_ciphertext,
                    cache_schema_version, synced_at,
                    local_alias, supported_providers, provider_base_urls, owner_account_id,
                    extra, oauth_group_id, group_accounts, routing_config,
                    my_assignment_override, group_runtime, owner_email, group_alias,
                    priority, fallback_role, route_group_id, route_group_name,
                    binding_id
                 )
                 SELECT
                    virtual_key_id, org_id, seat_id, alias,
                    provider_code, protocol_type, base_url,
                    credential_id, credential_revision, virtual_key_revision,
                    key_status, share_status, local_state, expires_at,
                    provider_key_nonce, provider_key_ciphertext,
                    2, synced_at,
                    local_alias, supported_providers, provider_base_urls, owner_account_id,
                    extra, oauth_group_id, group_accounts, routing_config,
                    my_assignment_override, group_runtime, owner_email, group_alias,
                    priority, fallback_role, route_group_id, route_group_name,
                    binding_id
                 FROM managed_virtual_keys_cache;
                 DROP TABLE managed_virtual_keys_cache;
                 ALTER TABLE managed_virtual_keys_cache__p1e_new RENAME TO managed_virtual_keys_cache;",
            )
            .map_err(|e| format!("mvkc re-grain rebuild: {}", e))?;
            tx.commit()
                .map_err(|e| format!("mvkc re-grain: commit: {}", e))?;
        }

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mvkc_local_state ON managed_virtual_keys_cache(local_state)",
            [],
        )
        .map_err(|e| format!("Failed to re-ensure managed_virtual_keys_cache index after re-grain: {}", e))?;

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

        // quota_local_usage — proxy-OWNED local usage increment, persisted as a
        // write-behind crash-recovery checkpoint so an OFFLINE proxy restart does
        // not forget usage accrued since the last server baseline (design
        // update/20260605-企业版配额限流-本地用量状态持久化与重启恢复.md, P0).
        // Distinct from quota_rules_cache (CLI-written, server config mirror): the
        // PROXY is the sole writer here and the CLI never touches it — so a sync's
        // DELETE+rebuild of quota_rules_cache cannot wipe it. `increment` = used
        // beyond the server baseline; reconciled to 0 by the proxy's monotonic-max
        // (P8) once the server baseline catches up.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS quota_local_usage (
                subject_id  TEXT NOT NULL,
                metric      TEXT NOT NULL,
                period_key  TEXT NOT NULL,
                increment   REAL NOT NULL DEFAULT 0,
                updated_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (subject_id, metric, period_key)
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure quota_local_usage table: {}", e))?;

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
                "protocol_type",
                "ALTER TABLE provider_accounts ADD COLUMN protocol_type TEXT NOT NULL DEFAULT ''",
            )?;
            conn.execute(
                "UPDATE provider_accounts
                    SET protocol_type = CASE lower(provider)
                        WHEN 'anthropic' THEN 'anthropic'
                        WHEN 'claude' THEN 'anthropic'
                        WHEN 'openai' THEN 'openai_compatible'
                        WHEN 'codex' THEN 'openai_compatible'
                        WHEN 'kimi' THEN 'openai_compatible'
                        WHEN 'kimi_code' THEN 'openai_compatible'
                        ELSE protocol_type
                    END
                  WHERE protocol_type = ''",
                [],
            )
            .map_err(|e| format!("Failed to backfill provider account protocol: {}", e))?;

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
                binding_provider_code TEXT NOT NULL DEFAULT '',
                protocol_type TEXT NOT NULL DEFAULT '',
                key_source_type TEXT NOT NULL,
                key_source_ref TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (profile_id, provider_code),
                FOREIGN KEY (profile_id) REFERENCES user_profiles(id)
            )",
            [],
        )
        .map_err(|e| format!("Failed to ensure user_profile_provider_bindings: {}", e))?;

        // P0a upstream fallback (task 1.2b): which route group a local `aikey use`
        // pin refers to.
        //
        // 🔴 ONE column only — deliberately NO `pin_scope` (rev8.2 deleted the
        // planned one). Pin scope is DERIVED from
        // (route_group_id, binding_provider_code):
        //
        //   ''    | —      → LEGACY row, existing behavior unchanged
        //   set   | ''     → pin the GROUP (default; failover still happens)
        //   set   | set    → pin ONE HOP (no failover; the CLI must say so)
        //
        // Two independently writable fields could contradict each other —
        // `pin_scope=group` while also naming one provider has no legal meaning
        // and nothing would stop it being written. Same reasoning as I19's
        // refusal of an independently editable `fallback_role`: make the invalid
        // state unrepresentable instead of documenting which field wins.
        //
        // DEFAULT '' matches binding_provider_code's existing convention, so an
        // upgraded row is indistinguishable from a legacy one — which is exactly
        // what keeps behavior identical across the upgrade.
        ensure_column(
            conn,
            "user_profile_provider_bindings",
            "route_group_id",
            "ALTER TABLE user_profile_provider_bindings ADD COLUMN route_group_id TEXT NOT NULL DEFAULT ''",
        )?;

        // 2026-07-21 Provider/Protocol/client-route split. The released table
        // name and `provider_code` primary-key column are retained for online
        // upgrade compatibility, but that key is now the client-route slot
        // (`anthropic`, `openai`, `kimi`, ...). The actual upstream Provider
        // and Protocol live in the two additive columns below. This lets one
        // Provider (notably `mock`) be selected independently for Claude and
        // Codex without adding another table or guessing from timestamps.
        ensure_column(
            conn,
            "user_profile_provider_bindings",
            "binding_provider_code",
            "ALTER TABLE user_profile_provider_bindings ADD COLUMN binding_provider_code TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            conn,
            "user_profile_provider_bindings",
            "protocol_type",
            "ALTER TABLE user_profile_provider_bindings ADD COLUMN protocol_type TEXT NOT NULL DEFAULT ''",
        )?;
        conn.execute(
            "UPDATE user_profile_provider_bindings
                SET binding_provider_code = provider_code
              WHERE binding_provider_code = ''",
            [],
        )
        .map_err(|e| format!("Failed to backfill binding provider identity: {}", e))?;

        migrate_active_key_config_to_default_profile(conn)?;
        migrate_provider_bindings_to_client_routes(conn)?;

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
                -- Maximum user-impacting action emitted by the filter.
                -- full = preserve Bundle mask/block; warn = emergency logical
                -- rollback while retaining findings and audit events.
                filter_max_action TEXT NOT NULL DEFAULT 'full'
                    CHECK (filter_max_action IN ('full', 'warn')),
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
        ensure_column(
            conn,
            "app_records",
            "filter_max_action",
            "ALTER TABLE app_records ADD COLUMN filter_max_action TEXT NOT NULL DEFAULT 'full' CHECK (filter_max_action IN ('full', 'warn'))",
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
        // `ai-degrade-detector/server_local/services/check_orchestrator.py
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

        activate_compliance_wave2_once(conn)?;

        Ok(())
    }

    /// Apply the user-approved Wave 2 migration exactly once to vaults where
    /// ai-compliance-detector was installed before mask/block became the
    /// production default.
    ///
    /// The marker is deliberately separate from the per-build schema replay
    /// marker. Baseline DDL is replayed after every binary update, but a later
    /// user choice to disable compliance must survive those updates. The
    /// SAVEPOINT makes the state change and marker atomic: an interrupted
    /// upgrade can neither mark an unapplied migration nor repeatedly override
    /// a user choice.
    fn activate_compliance_wave2_once(conn: &Connection) -> Result<(), String> {
        const MARKER: &str = "migration.compliance_wave2_mask_block_enabled";

        conn.execute_batch(
            "SAVEPOINT compliance_wave2_activation;
             UPDATE app_records
                SET filter_stages = '[\"pre_forward\"]',
                    filter_priority = COALESCE(filter_priority, 10),
                    filter_timeout_policy = COALESCE(filter_timeout_policy, 'fail_open'),
                    filter_max_action = 'full',
                    updated_at = strftime('%s', 'now')
              WHERE slug = 'ai-compliance-detector'
                AND NOT EXISTS (SELECT 1 FROM config WHERE key = 'migration.compliance_wave2_mask_block_enabled')
                -- 2026-08-19: never force the filter back on over an EXPLICIT
                -- user disable (marker written by clear_app_filter_stages,
                -- removed by any explicit re-enable). A default-activation
                -- wave upgrades defaults, it does not overrule user choices.
                AND NOT EXISTS (SELECT 1 FROM config WHERE key = 'user.filter_disabled.ai-compliance-detector');
             INSERT OR IGNORE INTO config (key, value)
                  VALUES ('migration.compliance_wave2_mask_block_enabled', '1');
             RELEASE compliance_wave2_activation;",
        )
        .map_err(|e| {
            let _ = conn.execute_batch("ROLLBACK TO compliance_wave2_activation; RELEASE compliance_wave2_activation;");
            format!("activate compliance Wave 2 migration {}: {}", MARKER, e)
        })?;

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
    /// `ai-degrade-detector/server_local/services/check_orchestrator.py::FIRST_PARTY_APP_KEY`;
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
        // explicitly — see ai-degrade-detector/server_local/services/
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
                "INSERT OR IGNORE INTO user_profile_provider_bindings
                    (profile_id, provider_code, binding_provider_code, key_source_type, key_source_ref)
                 VALUES ('default', ?1, ?1, ?2, ?3)",
                params![p, key_type, key_ref],
            )
            .map_err(|e| format!("migrate binding {}: {}", p, e))?;
        }
        mark_migration(conn, SENTINEL)
    }

    /// Re-grains the released `(profile, provider_code)` selection rows into
    /// `(profile, client_route)` rows while retaining the actual Provider and
    /// Protocol as independent columns. This is deliberately replay-safe:
    /// baseline migrations run on every binary upgrade, including existing
    /// vaults that already contain a `mock` selection written by the first
    /// resident-Mock implementation.
    fn migrate_provider_bindings_to_client_routes(conn: &Connection) -> Result<(), String> {
        #[derive(Debug)]
        struct LegacyBinding {
            profile_id: String,
            old_route: String,
            provider_code: String,
            protocol_type: String,
            source_type: String,
            source_ref: String,
            updated_at: i64,
        }

        let rows = {
            let mut stmt = conn
                .prepare(
                    "SELECT profile_id, provider_code, binding_provider_code,
                            protocol_type, key_source_type, key_source_ref, updated_at
                       FROM user_profile_provider_bindings",
                )
                .map_err(|e| format!("prepare client-route binding migration: {}", e))?;
            let mapped = stmt
                .query_map([], |row| {
                    Ok(LegacyBinding {
                        profile_id: row.get(0)?,
                        old_route: row.get(1)?,
                        provider_code: row.get(2)?,
                        protocol_type: row.get(3)?,
                        source_type: row.get(4)?,
                        source_ref: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(|e| format!("query client-route binding migration: {}", e))?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("read client-route binding migration: {}", e))?
        };

        let fingerprint = crate::commands_internal::parse::provider_fingerprint::instance();
        for row in rows {
            let mut provider_code =
                crate::provider_registry::canonical(&row.provider_code).to_string();
            let mut protocol_type = row.protocol_type.clone();

            if row.source_type == "personal_oauth_account" {
                if let Ok((account_provider, account_protocol)) = conn.query_row(
                    "SELECT provider, protocol_type FROM provider_accounts
                      WHERE provider_account_id = ?1",
                    params![row.source_ref],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                ) {
                    provider_code =
                        crate::provider_registry::canonical(&account_provider).to_string();
                    if protocol_type.is_empty() {
                        protocol_type = account_protocol;
                    }
                }
            }

            if protocol_type.is_empty()
                && matches!(row.source_type.as_str(), "team" | "managed_virtual_key")
            {
                let mut stmt = conn
                    .prepare(
                        "SELECT DISTINCT protocol_type
                           FROM managed_virtual_keys_cache
                          WHERE virtual_key_id = ?1
                            AND (lower(provider_code) = lower(?2) OR provider_code = '')
                            AND protocol_type <> ''
                          ORDER BY protocol_type",
                    )
                    .map_err(|e| format!("prepare managed binding protocol lookup: {}", e))?;
                let protocols = stmt
                    .query_map(params![row.source_ref, provider_code], |r| {
                        r.get::<_, String>(0)
                    })
                    .map_err(|e| format!("query managed binding protocol: {}", e))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("read managed binding protocol: {}", e))?;
                if protocols.len() == 1 {
                    protocol_type = protocols[0].clone();
                }
            }

            if protocol_type.is_empty() {
                let protocols = fingerprint.protocols_for_provider(&provider_code);
                if protocols.len() == 1 {
                    protocol_type = protocols[0].clone();
                }
            }

            // A multi-protocol Provider without recoverable protocol cannot be
            // projected into a client route. Keeping the legacy `mock` key
            // would recreate a fake Mock protocol group and could send traffic
            // through an arbitrary dialect, so discard only that stale active
            // selection; the credential remains available for explicit reselect.
            if provider_code == "mock" && protocol_type.is_empty() {
                conn.execute(
                    "DELETE FROM user_profile_provider_bindings
                      WHERE profile_id = ?1 AND provider_code = ?2",
                    params![row.profile_id, row.old_route],
                )
                .map_err(|e| format!("remove ambiguous legacy Mock binding: {}", e))?;
                continue;
            }

            let client_route =
                crate::provider_registry::client_route_for_binding(&provider_code, &protocol_type);
            conn.execute(
                "INSERT INTO user_profile_provider_bindings
                    (profile_id, provider_code, binding_provider_code, protocol_type,
                     key_source_type, key_source_ref, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (profile_id, provider_code) DO UPDATE SET
                    binding_provider_code = excluded.binding_provider_code,
                    protocol_type = excluded.protocol_type,
                    key_source_type = excluded.key_source_type,
                    key_source_ref = excluded.key_source_ref,
                    updated_at = excluded.updated_at
                 WHERE excluded.updated_at >= user_profile_provider_bindings.updated_at",
                params![
                    row.profile_id,
                    client_route,
                    provider_code,
                    protocol_type,
                    row.source_type,
                    row.source_ref,
                    row.updated_at
                ],
            )
            .map_err(|e| format!("upsert migrated client-route binding: {}", e))?;
            if client_route != row.old_route {
                conn.execute(
                    "DELETE FROM user_profile_provider_bindings
                      WHERE profile_id = ?1 AND provider_code = ?2",
                    params![row.profile_id, row.old_route],
                )
                .map_err(|e| format!("remove legacy provider-keyed binding: {}", e))?;
            }
        }
        Ok(())
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

    #[test]
    fn compliance_wave2_enables_an_existing_detector_exactly_once() {
        let conn = fresh_vault();
        conn.execute(
            "DELETE FROM config WHERE key='migration.compliance_wave2_mask_block_enabled'",
            [],
        )
        .expect("simulate a pre-Wave-2 vault");
        conn.execute(
            "INSERT INTO app_records
                (slug, name, vendor, upstreams, app_kind, filter_stages,
                 filter_priority, filter_timeout_policy, filter_max_action)
             VALUES
                ('ai-compliance-detector', 'AI Compliance Detector', 'AiKey Labs', '[]',
                 'first-party', NULL, NULL, NULL, 'warn')",
            [],
        )
        .expect("seed an installed but disabled detector");

        upgrade_all(&conn).expect("apply the Wave 2 activation");
        let activated: (String, i64, String, String) = conn
            .query_row(
                "SELECT filter_stages, filter_priority, filter_timeout_policy, filter_max_action
                   FROM app_records WHERE slug='ai-compliance-detector'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read activated detector");
        assert_eq!(
            activated,
            (
                "[\"pre_forward\"]".to_string(),
                10,
                "fail_open".to_string(),
                "full".to_string()
            )
        );

        conn.execute(
            "UPDATE app_records SET filter_stages=NULL WHERE slug='ai-compliance-detector'",
            [],
        )
        .expect("simulate the user's later explicit disable");
        upgrade_all(&conn).expect("replay the idempotent baseline");

        let stages: Option<String> = conn
            .query_row(
                "SELECT filter_stages FROM app_records WHERE slug='ai-compliance-detector'",
                [],
                |row| row.get(0),
            )
            .expect("read user-controlled state after replay");
        assert_eq!(
            stages, None,
            "a later schema replay must not override the user's post-migration choice"
        );
    }

    /// 2026-08-19 (filterpipe-501 triage相邻发现): a user who explicitly
    /// disabled the filter BEFORE Wave 2 arrives must not have it forced back
    /// on by the activation migration. The explicit choice is recorded by
    /// clear_app_filter_stages (config marker); the wave honors it.
    #[test]
    fn compliance_wave2_respects_pre_wave_explicit_user_disable() {
        let conn = fresh_vault();
        conn.execute(
            "DELETE FROM config WHERE key='migration.compliance_wave2_mask_block_enabled'",
            [],
        )
        .expect("simulate a pre-Wave-2 vault");
        conn.execute(
            "INSERT INTO app_records
                (slug, name, vendor, upstreams, app_kind, filter_stages,
                 filter_priority, filter_timeout_policy, filter_max_action)
             VALUES
                ('ai-compliance-detector', 'AI Compliance Detector', 'AiKey Labs', '[]',
                 'first-party', '[\"pre_forward\"]', 10, 'fail_open', 'full')",
            [],
        )
        .expect("seed an enabled detector");
        // The user's explicit disable, via the REAL production core (which
        // also records the do-not-override marker).
        crate::commands_app::clear_app_filter_stages_with_conn(&conn, "ai-compliance-detector")
            .expect("explicit user disable");

        upgrade_all(&conn).expect("apply Wave 2 over the disabled vault");

        let stages: Option<String> = conn
            .query_row(
                "SELECT filter_stages FROM app_records WHERE slug='ai-compliance-detector'",
                [],
                |row| row.get(0),
            )
            .expect("read state after wave");
        assert_eq!(
            stages, None,
            "Wave 2 must not force the filter back on over an explicit user disable"
        );

        // An explicit re-enable clears the marker: the next default-activation
        // wave treats this vault normally again.
        crate::commands_app::set_app_filter_stages_with_conn(
            &conn,
            "ai-compliance-detector",
            &["pre_forward".to_string()],
            None,
            None,
        )
        .expect("explicit re-enable");
        let marker: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM config WHERE key='user.filter_disabled.ai-compliance-detector'",
                [],
                |row| row.get(0),
            )
            .expect("read marker");
        assert_eq!(marker, 0, "explicit enable must clear the disable marker");
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

    #[test]
    fn legacy_mock_binding_is_rekeyed_to_its_protocol_client_route() {
        let conn = fresh_vault();
        conn.execute(
            "INSERT INTO managed_virtual_keys_cache
                (virtual_key_id, org_id, seat_id, alias, provider_code,
                 protocol_type, base_url, credential_id,
                 credential_revision, virtual_key_revision, supported_providers)
             VALUES ('vk-mock-a', 'o1', 's1', 'mock-a', '',
                     'anthropic', '', 'c1', '1', '1', '[\"mock\"]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_profile_provider_bindings
                (profile_id, provider_code, binding_provider_code, protocol_type,
                 key_source_type, key_source_ref, updated_at)
             VALUES ('default', 'mock', 'mock', '', 'team', 'vk-mock-a', 42)",
            [],
        )
        .unwrap();

        upgrade_all(&conn).expect("replay migration");

        let got: (String, String, String) = conn
            .query_row(
                "SELECT provider_code, binding_provider_code, protocol_type
                   FROM user_profile_provider_bindings WHERE profile_id='default'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(got, ("anthropic".into(), "mock".into(), "anthropic".into()));
    }

    #[test]
    fn ambiguous_legacy_mock_binding_is_removed_instead_of_becoming_a_mock_route() {
        let conn = fresh_vault();
        for protocol in ["anthropic", "openai_compatible"] {
            conn.execute(
                "INSERT INTO managed_virtual_keys_cache
                    (virtual_key_id, org_id, seat_id, alias, provider_code,
                     protocol_type, base_url, credential_id,
                     credential_revision, virtual_key_revision)
                 VALUES ('vk-mock-both', 'o1', 's1', 'mock-both', 'mock',
                         ?1, 'http://mock', ?2, '1', '1')",
                params![protocol, format!("c-{protocol}")],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO user_profile_provider_bindings
                (profile_id, provider_code, binding_provider_code, protocol_type,
                 key_source_type, key_source_ref, updated_at)
             VALUES ('default', 'mock', 'mock', '', 'team', 'vk-mock-both', 42)",
            [],
        )
        .unwrap();

        upgrade_all(&conn).expect("replay migration");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM user_profile_provider_bindings
                  WHERE profile_id='default' AND provider_code='mock'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "fake Mock client route must not survive upgrade");
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

    /// N0 (master v1.0.1-alpha.3 oauth_group fold): the 5 oauth_group columns are
    /// retrofitted onto managed_virtual_keys_cache by upgrade_all — group data
    /// folds into the VK row, no separate client cache tables (技术方案 §2.3).
    #[test]
    fn oauth_group_fold_columns_retrofit_on_managed_virtual_keys_cache() {
        let conn = Connection::open_in_memory().expect("open");
        upgrade_all(&conn).expect("upgrade_all");
        for col in [
            "oauth_group_id",
            "group_accounts",
            "routing_config",
            "my_assignment_override",
            "group_runtime",
        ] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('managed_virtual_keys_cache') WHERE name=?1",
                    [col],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                n, 1,
                "managed_virtual_keys_cache.{} missing after upgrade_all",
                col
            );
        }
        // Idempotent: ensure_column absorbs the duplicate-column error on re-run.
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
                // 2026-06-03: filter_record_allow boolean — proxy reads
                // it to decide whether the detector emits allow events.
                // Retrofitted via ensure_column for existing vaults; the
                // baseline CREATE TABLE carries it for fresh installs.
                "filter_record_allow",
                // 2026-08-11: operational enforcement ceiling. Existing
                // vaults are idempotently retrofitted with full.
                "filter_max_action",
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
        // ai-degrade-detector/server_local/services/check_orchestrator.py
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

    /// 2026-07-07 vault-page lock-convoy fix: the marker lifecycle.
    /// First contact replays + stamps; second call takes the read-only
    /// fast path (SkippedFresh — this is the load-bearing assertion: it
    /// proves no write connection is needed once stamped); clearing the
    /// marker (db rollback path) re-arms the replay.
    #[test]
    fn schema_marker_gates_replay_and_clear_rearms() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.db");
        // Create the file with a baseline replay so the fast path has a
        // config table to probe.
        assert_eq!(
            ensure_schema_current(&vault).unwrap(),
            SchemaEnsure::Replayed,
            "first contact must replay"
        );
        assert_eq!(
            ensure_schema_current(&vault).unwrap(),
            SchemaEnsure::SkippedFresh,
            "same build must skip via the read-only probe"
        );
        // Tampered marker (≈ different build stamped it) → replay again.
        {
            let conn = Connection::open(&vault).unwrap();
            conn.execute(
                "UPDATE config SET value='0.0.0:other' WHERE key='schema.replayed_by'",
                [],
            )
            .unwrap();
        }
        assert_eq!(
            ensure_schema_current(&vault).unwrap(),
            SchemaEnsure::Replayed,
            "foreign marker must trigger a fresh replay"
        );
        // Rollback path clears the marker → next command re-converges.
        {
            let conn = Connection::open(&vault).unwrap();
            clear_schema_marker(&conn);
        }
        assert_eq!(
            ensure_schema_current(&vault).unwrap(),
            SchemaEnsure::Replayed,
            "cleared marker must re-arm the replay"
        );
    }

    /// The replay stays idempotent under the marker scheme: a legacy vault
    /// (schema present, no marker row — every pre-fix install looks like
    /// this) must replay once without error and then fast-path.
    #[test]
    fn legacy_vault_without_marker_replays_once_then_skips() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.db");
        {
            // Simulate a pre-marker vault: full schema, no marker row.
            let conn = Connection::open(&vault).unwrap();
            upgrade_all(&conn).unwrap();
        }
        assert_eq!(
            ensure_schema_current(&vault).unwrap(),
            SchemaEnsure::Replayed,
            "legacy vault (no marker) must converge via replay"
        );
        assert_eq!(
            ensure_schema_current(&vault).unwrap(),
            SchemaEnsure::SkippedFresh
        );
    }

    // ── P0a upstream fallback · tasks 1.2 / 1.2b / 1.6 / 1.7 / 1.10 ─────────

    /// Local column probe. `v1_0_0_baseline::has_column` is module-private on
    /// purpose (it is an implementation detail of the retrofit loop), and this
    /// change is not a reason to widen its visibility just for tests.
    fn col_exists(conn: &Connection, table: &str, column: &str) -> bool {
        conn.prepare(&format!("PRAGMA table_info({})", table))
            .and_then(|mut stmt| {
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let name: String = row.get(1)?;
                    if name == column {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .unwrap_or(false)
    }

    /// The four columns this change adds to the vault cache.
    const FALLBACK_CACHE_COLUMNS: [&str; 4] = [
        "priority",
        "fallback_role",
        "route_group_id",
        "route_group_name",
    ];

    /// Task 1.10 — 🔴 the generic fence, and the reason it is generic.
    ///
    /// `managed_virtual_keys_cache` is maintained in TWO places that must agree:
    /// the column-retrofit loop (runs first) and the P1e re-grain block (runs
    /// after, with THREE hand-written column lists — CREATE, INSERT, SELECT).
    ///
    /// Add a column to the loop but not to the rebuild lists and, on a *pre-P1e*
    /// vault: the patch adds the column to the old table → the rebuild creates a
    /// new table without it → copies → drops the old one → **the column is gone,
    /// along with its data**.
    ///
    /// 🔴 Why no existing test catches it: a fresh install never enters the
    /// rebuild block (its PK is already composite), and the existing re-grain
    /// test only asserts the primary key changed and the ciphertext survived
    /// byte-for-byte — never the complete column set. CI stays green.
    ///
    /// So this fence is written for EVERY column, not just this change's four:
    /// it protects the next one too. (The same hazard shape exists in the control
    /// plane — v1_0_1_alpha3_oauth_group.go rebuilds
    /// managed_provider_bindings unconditionally — which was only ever documented
    /// here, for the vault.)
    #[test]
    fn task_1_10_every_retrofitted_column_is_also_in_the_p1e_rebuild_block() {
        let src = include_str!("migrations.rs");

        // The retrofit loop's DDL statements are the authoritative list of
        // columns this table can gain.
        let mut retrofitted: Vec<String> = Vec::new();
        for line in src.lines() {
            // Built by concatenation so the full literal never appears
            // contiguously in this file — otherwise the scanner matches its own
            // needle and reports `";` as a missing column. (It did, on the first
            // run. A self-matching source scanner is a standing trap.)
            let needle = concat!("ALTER TABLE managed_virtual_keys_cache ", "ADD COLUMN ");
            if let Some(idx) = line.find(needle) {
                let rest = &line[idx + needle.len()..];
                if let Some(col) = rest.split_whitespace().next() {
                    retrofitted.push(col.to_string());
                }
            }
        }
        assert!(
            retrofitted.len() >= 12,
            "found only {} retrofitted columns — the scanner stopped matching, so this fence is \
             silently watching nothing (worse than absent: it reads as coverage)",
            retrofitted.len()
        );

        // Isolate the rebuild block so a mention in the retrofit loop cannot
        // vouch for the rebuild.
        let block_start = src
            .find("CREATE TABLE managed_virtual_keys_cache__p1e_new")
            .expect("P1e rebuild block not found — did it move or get renamed?");
        let block_end = src[block_start..]
            .find("RENAME TO managed_virtual_keys_cache")
            .map(|o| block_start + o)
            .expect("P1e rebuild block end not found");
        let rebuild = &src[block_start..block_end];

        let missing: Vec<&String> = retrofitted
            .iter()
            .filter(|col| !rebuild.contains(col.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "column(s) {:?} are added by the retrofit loop but absent from the P1e rebuild block.\n\
             On a pre-P1e vault the rebuild will create a table without them, copy, drop the old \
             table — and the columns plus their data are gone. A fresh install never enters that \
             block, and the existing re-grain test only checks the primary key and the ciphertext, \
             so CI would stay green.",
            missing
        );
    }

    /// Tasks 1.2 / 1.2b — the four columns exist on a fresh install, and their
    /// defaults reproduce pre-upgrade behavior exactly.
    #[test]
    fn fallback_columns_exist_with_behavior_preserving_defaults() {
        let vault = fresh_vault();
        for col in FALLBACK_CACHE_COLUMNS {
            assert!(
                col_exists(&vault, "managed_virtual_keys_cache", col),
                "managed_virtual_keys_cache.{} missing after a full upgrade",
                col
            );
        }
        assert!(
            col_exists(&vault, "user_profile_provider_bindings", "route_group_id"),
            "the pin table did not gain route_group_id"
        );

        // 🔴 rev8.2: scope is DERIVED, so the pin table must NOT have gained a
        // second, contradictable field.
        assert!(
            !col_exists(&vault, "user_profile_provider_bindings", "pin_scope"),
            "pin_scope column exists. Scope is derived from \
             (route_group_id, binding_provider_code); storing it alongside them permits a row \
             saying `pin_scope=group` while also naming one provider — a state with no legal \
             meaning that nothing prevents"
        );

        vault
            .execute(
                "INSERT INTO managed_virtual_keys_cache
                   (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                    base_url, credential_id, credential_revision, virtual_key_revision)
                 VALUES ('vk1','o1','s1','k','anthropic','anthropic','https://x','c1','r1','r1')",
                [],
            )
            .expect("insert legacy-shaped row");
        let (prio, role, gid): (i64, String, String) = vault
            .query_row(
                "SELECT priority, fallback_role, route_group_id
                   FROM managed_virtual_keys_cache WHERE virtual_key_id='vk1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("read defaults");
        assert_eq!(
            (prio, role.as_str(), gid.as_str()),
            (1, "primary", ""),
            "defaults must reproduce pre-upgrade behavior: all primary, no fallback, no group. \
             An upgrade that changes routing on its own is the worst outcome here"
        );
    }

    /// Builds a genuine **pre-P1e** vault: the one-VK-one-row cache with a
    /// SINGLE-column primary key, carrying real rows.
    ///
    /// 🔴 Task 1.6: "🚫 fresh-install 单测不算". This is the only shape that
    /// exercises the re-grain path at all.
    fn pre_p1e_vault() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE managed_virtual_keys_cache (
                virtual_key_id       TEXT NOT NULL PRIMARY KEY,
                org_id               TEXT NOT NULL,
                seat_id              TEXT NOT NULL,
                alias                TEXT NOT NULL,
                provider_code        TEXT NOT NULL DEFAULT '',
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
                synced_at            INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );",
        )
        .expect("create pre-P1e cache");
        conn.execute(
            "INSERT INTO managed_virtual_keys_cache
               (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                base_url, credential_id, credential_revision, virtual_key_revision,
                provider_key_nonce, provider_key_ciphertext)
             VALUES ('vk-old','o1','s1','legacy-key','anthropic','anthropic',
                     'https://api.anthropic.com','c-old','r1','r1', ?1, ?2)",
            params![vec![7u8, 7, 7], vec![9u8, 9, 9, 9]],
        )
        .expect("seed legacy row");
        conn
    }

    /// Tasks 1.6 + 1.10 — 🔴 the live counterpart of the static fence.
    ///
    /// Upgrade a real pre-P1e vault and assert the four columns SURVIVE the
    /// re-grain, that the ciphertext is still byte-identical, and that the
    /// primary key really did become composite (i.e. the rebuild ran, so this
    /// test actually exercised the dangerous path).
    #[test]
    fn task_1_6_pre_p1e_vault_keeps_fallback_columns_through_the_regrain() {
        let vault = pre_p1e_vault();
        upgrade_all(&vault).expect("upgrade a pre-P1e vault");

        let pk_cols: i64 = vault
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('managed_virtual_keys_cache') WHERE pk > 0",
                [],
                |r| r.get(0),
            )
            .expect("count pk cols");
        assert_eq!(
            pk_cols, 3,
            "the re-grain did not run, so this test did not exercise the rebuild path and proves \
             nothing about column survival"
        );

        for col in FALLBACK_CACHE_COLUMNS {
            assert!(
                col_exists(&vault, "managed_virtual_keys_cache", col),
                "{} was LOST in the P1e re-grain — the retrofit loop added it to the old table, \
                 then the rebuild created a new table without it",
                col
            );
        }

        let (prio, role, nonce, cipher): (i64, String, Vec<u8>, Vec<u8>) = vault
            .query_row(
                "SELECT priority, fallback_role, provider_key_nonce, provider_key_ciphertext
                   FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-old'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("read migrated row");
        assert_eq!(
            (prio, role.as_str()),
            (1, "primary"),
            "an existing row must come out of the re-grain with pre-upgrade behavior"
        );
        // The re-grain must not touch the encryption boundary.
        assert_eq!(nonce, vec![7u8, 7, 7], "nonce changed during re-grain");
        assert_eq!(
            cipher,
            vec![9u8, 9, 9, 9],
            "ciphertext changed during re-grain — the BLOB must be copied byte-for-byte"
        );
    }

    /// Task 6.7 (rev5) — the re-grain must preserve the ORDER, not just the columns.
    ///
    /// 🔴 `task_1_6_…` above cannot make this claim, and that is worth spelling
    /// out because it looks like it does. It seeds ONE row on a vault where the
    /// columns do not exist yet, so the retrofit gives that row the DEFAULT
    /// `priority = 1 / fallback_role = 'primary'` — and then asserts it reads
    /// back as 1/'primary'. Replacing the SELECT's `priority, fallback_role`
    /// with the literals `1, 'primary'` leaves that test GREEN (measured
    /// 2026-07-31). A fence that cannot tell "copied" from "reset to the value I
    /// happen to be expecting" is not fencing the rebuild.
    ///
    /// What a reset actually costs: a vault that has already synced real
    /// per-binding priorities comes out of the re-grain with every hop flattened
    /// to priority 1. Every candidate then shares a priority, which is the one
    /// case `duplicatePriority` calls genuinely ambiguous — so the chain stops
    /// serving with PROVIDER_ROUTE_AMBIGUOUS, on a configuration the
    /// administrator never touched, during an upgrade.
    ///
    /// The state built here — fallback columns present AND populated, primary key
    /// still single-column — is the one that distinguishes the two behaviours. It
    /// is reachable in the field: the column patch and the re-grain are separate
    /// statements, so a vault patched and synced before an interrupted upgrade
    /// sits exactly here.
    ///
    /// 能红: put literals back into the re-grain's SELECT → this fails.
    #[test]
    fn task_6_7_regrain_preserves_configured_priority_order_not_just_the_columns() {
        let vault = pre_p1e_vault();
        // Bring the columns in the way the retrofit loop does, then populate them
        // with DISTINCT, non-default values — the whole point is that the values
        // must not be reproducible by a default.
        for ddl in [
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN priority INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN fallback_role TEXT NOT NULL DEFAULT 'primary'",
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN route_group_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN route_group_name TEXT NOT NULL DEFAULT ''",
        ] {
            vault.execute(ddl, []).expect("patch column onto the pre-P1e table");
        }
        // 🔴 THREE separate keys, not three hops of one. A pre-P1e vault has
        // `virtual_key_id` as its whole primary key, so "one key, several hops"
        // is not representable there — which is precisely why the re-grain
        // exists. Distinct values across distinct rows still separate "copied
        // the column" from "wrote the default", which is what this fences.
        vault
            .execute(
                "UPDATE managed_virtual_keys_cache
                    SET priority = 1, fallback_role = 'primary',
                        route_group_id = 'rg-1', route_group_name = 'prod chain'
                  WHERE virtual_key_id = 'vk-old'",
                [],
            )
            .expect("configure hop 1");
        for (vk, provider, prio, role) in [
            ("vk-two", "zhipu", 2_i64, "fallback"),
            ("vk-three", "openai", 3_i64, "fallback"),
        ] {
            vault
                .execute(
                    "INSERT INTO managed_virtual_keys_cache
                       (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                        base_url, credential_id, credential_revision, virtual_key_revision,
                        priority, fallback_role, route_group_id, route_group_name)
                     VALUES (?1,'o1','s1','legacy-key',?2,'anthropic',
                             'https://example.test','c-old','r1','r1',?3,?4,'rg-1','prod chain')",
                    params![vk, provider, prio, role],
                )
                .expect("seed extra row");
        }

        upgrade_all(&vault).expect("upgrade a patched-but-not-re-grained vault");

        let pk_cols: i64 = vault
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('managed_virtual_keys_cache') WHERE pk > 0",
                [],
                |r| r.get(0),
            )
            .expect("count pk cols");
        assert_eq!(
            pk_cols, 3,
            "the re-grain did not run, so this test proves nothing about the rebuild"
        );

        let mut stmt = vault
            .prepare(
                "SELECT provider_code, priority, fallback_role, route_group_name
                   FROM managed_virtual_keys_cache ORDER BY priority",
            )
            .expect("prepare");
        let got: Vec<(String, i64, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();

        assert_eq!(
            got,
            vec![
                ("anthropic".to_string(), 1, "primary".to_string(), "prod chain".to_string()),
                ("zhipu".to_string(), 2, "fallback".to_string(), "prod chain".to_string()),
                ("openai".to_string(), 3, "fallback".to_string(), "prod chain".to_string()),
            ],
            "the re-grain did not carry the administrator's configured order through the rebuild.\n\
             Flattening every hop to the default collapses the chain into one priority band, which \n\
             the runtime treats as genuinely un-orderable (PROVIDER_ROUTE_AMBIGUOUS) — a chain that \n\
             stops serving because of an upgrade, not a change."
        );
    }

    /// Task 1.7 — applying the migration twice is a no-op.
    #[test]
    fn task_1_7_column_patch_is_idempotent_across_two_runs() {
        let vault = pre_p1e_vault();
        upgrade_all(&vault).expect("first upgrade");
        vault
            .execute(
                "UPDATE managed_virtual_keys_cache SET priority=2, fallback_role='fallback',
                   route_group_id='rg-x', route_group_name='chain' WHERE virtual_key_id='vk-old'",
                [],
            )
            .expect("simulate synced values");

        upgrade_all(&vault).expect("second upgrade must be a no-op");

        let (prio, role, gid, gname): (i64, String, String, String) = vault
            .query_row(
                "SELECT priority, fallback_role, route_group_id, route_group_name
                   FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-old'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("read after replay");
        assert_eq!(
            (prio, role.as_str(), gid.as_str(), gname.as_str()),
            (2, "fallback", "rg-x", "chain"),
            "the second run overwrote synced chain values. A migration that resets routing on \
             every startup would silently undo what the control plane delivered"
        );
    }

    /// Task 1.3 — the chain must SURVIVE a write→read round trip through the
    /// real upsert and the real tiered SELECT.
    ///
    /// 🔴 Why this is not redundant with the column tests above: the columns can
    /// exist, the struct can carry the values, and the sync can still drop them —
    /// which is exactly what happened before this change. Delivery has always
    /// shipped priority/fallback_role on binding_targets; the vault's INSERT
    /// simply did not list them, so they were silently discarded at the last
    /// step. Asserting "the column exists" would not have caught that.
    #[test]
    fn task_1_3_chain_survives_the_upsert_and_select_round_trip() {
        let vault = fresh_vault();
        // Two hops of one chain, written the way a delivery sync writes them.
        vault
            .execute(
                "INSERT INTO managed_virtual_keys_cache
                   (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                    base_url, credential_id, credential_revision, virtual_key_revision,
                    priority, fallback_role, route_group_id, route_group_name)
                 VALUES ('vk1','o1','s1','k','anthropic','anthropic','https://a','c1','r1','r1',
                         1,'primary','rg-main','main-chain')",
                [],
            )
            .expect("insert primary hop");
        vault
            .execute(
                "INSERT INTO managed_virtual_keys_cache
                   (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                    base_url, credential_id, credential_revision, virtual_key_revision,
                    priority, fallback_role, route_group_id, route_group_name)
                 VALUES ('vk1','o1','s1','k','zhipu','anthropic','https://z','c2','r1','r1',
                         2,'fallback','rg-main','main-chain')",
                [],
            )
            .expect("insert fallback hop");

        // 🔴 Task 1.4's discipline applied to the vault read: ORDER BY priority,
        // never implicit row order. SQLite makes no promise without it, and an
        // implicit order is the classic silent bug — right today, wrong after some
        // unrelated change, and never logged.
        let mut stmt = vault
            .prepare(
                "SELECT provider_code, priority, fallback_role, route_group_id, route_group_name
                   FROM managed_virtual_keys_cache
                  WHERE virtual_key_id='vk1' AND protocol_type='anthropic'
                  ORDER BY priority ASC",
            )
            .expect("prepare chain read");
        let rows: Vec<(String, i64, String, String, String)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();

        assert_eq!(rows.len(), 2, "both hops must persist as separate rows");
        assert_eq!(
            (rows[0].0.as_str(), rows[0].1, rows[0].2.as_str()),
            ("anthropic", 1, "primary"),
            "the primary hop must come back first with its order intact"
        );
        assert_eq!(
            (rows[1].0.as_str(), rows[1].1, rows[1].2.as_str()),
            ("zhipu", 2, "fallback"),
            "the fallback hop must keep priority 2 — if the sync drops it, every hop reads as \
             priority 1 and the proxy cannot tell primary from fallback"
        );
        for row in &rows {
            assert_eq!(
                (row.3.as_str(), row.4.as_str()),
                ("rg-main", "main-chain"),
                "every hop of one chain carries the same template provenance"
            );
        }
    }
}
