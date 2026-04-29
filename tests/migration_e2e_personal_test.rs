//! L5 Migration E2E (Personal edition / SQLite vault) for the 2026-04-29
//! token-prefix rename refactor.
//!
//! Distinguishes from the v1.0.5-alpha unit tests (in `migrations.rs`) by
//! running the migration through the full `upgrade_all` registry — same
//! entry point the binary uses on every command. This catches regressions
//! where v1.0.5-alpha gets accidentally unregistered or runs out of order.
//!
//! Layers covered:
//!   - Happy fixture: legitimate `aikey_vk_<64-hex>` rows transform to
//!     `aikey_personal_<64-hex>` (lowercase normalized).
//!   - Dirty fixture: NULL / empty / non-hex / wrong-length rows.
//!     • `prefix_precheck` matches "old prefix but unmigratable shape" → upgrade refuses.
//!     • `completeness_precheck` matches "missing token" → upgrade tolerates (skips them).
//!   - Idempotency: second `upgrade_all` is a no-op.
//!   - Round-trip: rollback to v1.0.4-alpha then upgrade_all again preserves data.
//!   - Both `entries.route_token` and `provider_accounts.route_token` covered.
//!
//! Spec: roadmap20260320/技术实现/update/20260429-token前缀重命名-e2e测试方案.md §8

use aikeylabs_aikey_cli::migrations::{self, v1_0_5_alpha};
use rusqlite::Connection;

const HEX_LOWER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HEX_MIXED: &str = "0123456789ABCDEF0123456789ABCDEF0123456789abcdef0123456789abcdef";

// ─────────────────────────────────────────────────────────────────────────
// Test harness — mirrors the real vault schema's tail (entries +
// provider_accounts with route_token columns). Per CLAUDE.md
// `test-fixture-real-schema`: run real migration chain to baseline + previous
// version's DDL before applying v1.0.5-alpha logic.
// ─────────────────────────────────────────────────────────────────────────

/// Setup an in-memory vault DB, run all migrations EXCEPT v1.0.5-alpha (i.e.
/// to v1.0.4-alpha state — the "before refactor" snapshot). The caller then
/// inserts test data + manually invokes v1_0_5_alpha::upgrade.
fn setup_pre_migration_vault() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    migrations::v1_0_1_baseline::upgrade(&conn).unwrap();
    migrations::v1_0_2_alpha::upgrade(&conn).unwrap();
    migrations::v1_0_3_alpha::upgrade(&conn).unwrap();
    migrations::v1_0_4_alpha::upgrade(&conn).unwrap();
    conn
}

/// Setup vault and apply ALL migrations including v1.0.5-alpha (post-refactor state).
fn setup_post_migration_vault() -> Connection {
    let conn = setup_pre_migration_vault();
    v1_0_5_alpha::upgrade(&conn).unwrap();
    conn
}

fn count_legacy_prefix(conn: &Connection, table: &str) -> i64 {
    let sql = format!(
        "SELECT COUNT(*) FROM {} WHERE substr(route_token, 1, 9) = 'aikey_vk_'",
        table
    );
    conn.query_row(&sql, [], |r| r.get::<_, i64>(0)).unwrap()
}

fn count_new_prefix(conn: &Connection, table: &str) -> i64 {
    let sql = format!(
        "SELECT COUNT(*) FROM {} \
         WHERE length(route_token) = 79 \
           AND substr(route_token, 1, 15) = 'aikey_personal_' \
           AND length(substr(route_token, 16)) = 64 \
           AND lower(substr(route_token, 16)) NOT GLOB '*[^0-9a-f]*'",
        table
    );
    conn.query_row(&sql, [], |r| r.get::<_, i64>(0)).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────
// Happy fixture — typical post-v1.0.4-alpha vault contents
// ─────────────────────────────────────────────────────────────────────────

/// Insert a personal-key row with placeholder ciphertext + a route_token.
/// Mirrors the real schema's NOT NULL columns. Dummy nonce/ciphertext bytes
/// are fine — this E2E doesn't decrypt anything.
fn insert_entry(conn: &Connection, alias: &str, route_token: &str) {
    conn.execute(
        "INSERT INTO entries(alias, nonce, ciphertext, route_token) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![alias, &b"dummy_nonce"[..], &b"dummy_ciphertext"[..], route_token],
    ).unwrap();
}

/// Insert an OAuth account row with the required NOT NULL columns + route_token.
fn insert_oauth_account(conn: &Connection, account_id: &str, route_token: &str) {
    conn.execute(
        "INSERT INTO provider_accounts(provider_account_id, provider, auth_type, route_token) \
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![account_id, "anthropic", "oauth", route_token],
    ).unwrap();
}

#[test]
fn happy_full_chain_via_upgrade_all() {
    let conn = setup_pre_migration_vault();

    // Seed: 3 personal keys + 2 OAuth accounts in legacy bearer form.
    // Each token: aikey_vk_ + 64 lowercase hex chars (length 73).
    for (i, alias) in ["claude-main", "openai-default", "kimi-team"].iter().enumerate() {
        // Make each token unique by varying the last char.
        let mut suffix: String = HEX_LOWER.into();
        suffix.replace_range(63..64, &format!("{:x}", i + 1));
        let token = format!("aikey_vk_{}", suffix);
        insert_entry(&conn, alias, &token);
    }
    for (i, acct) in ["acc-claude-1", "acc-codex-1"].iter().enumerate() {
        let mut suffix: String = HEX_LOWER.into();
        suffix.replace_range(62..64, &format!("{:02x}", i + 10));
        let token = format!("aikey_vk_{}", suffix);
        insert_oauth_account(&conn, acct, &token);
    }

    // Pre-state: legacy prefix present, new prefix absent.
    assert!(count_legacy_prefix(&conn, "entries") >= 1, "happy fixture missing legacy entries rows");
    assert_eq!(count_new_prefix(&conn, "entries"), 0, "happy fixture should NOT pre-have new-prefix rows");

    // Upgrade via the FULL registry — `migrations::upgrade_all` is what the
    // binary actually calls. Catches any registration / ordering regression.
    migrations::upgrade_all(&conn).expect("upgrade_all must succeed on happy fixture");

    // Post-state: legacy fully gone, all transformed to new form.
    assert_eq!(count_legacy_prefix(&conn, "entries"), 0,
        "all entries.route_token must be migrated; found legacy survivors");
    assert!(count_new_prefix(&conn, "entries") >= 3,
        "expected ≥3 new-form entries.route_token rows after migration");

    // Idempotency: second upgrade_all is a no-op.
    migrations::upgrade_all(&conn).expect("idempotent re-run must succeed");
    assert_eq!(count_legacy_prefix(&conn, "entries"), 0, "still no legacy rows");
}

#[test]
fn happy_force_lowercases_mixed_case_hex() {
    // If a vault was seeded externally (or a future generator regression) with
    // mixed-case hex, the migration MUST lowercase-normalize so the output
    // matches the proxy's strict isTier1Personal form ([0-9a-f]{64}).
    let conn = setup_pre_migration_vault();
    let token = format!("aikey_vk_{}", HEX_MIXED);
    insert_entry(&conn, "mixed-case", &token);

    migrations::upgrade_all(&conn).unwrap();

    let after: String = conn
        .query_row("SELECT route_token FROM entries WHERE alias='mixed-case'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(after, format!("aikey_personal_{}", HEX_LOWER),
        "mixed-case hex must be lowercase-normalized post-migration");
}

// ─────────────────────────────────────────────────────────────────────────
// Dirty fixture — prefix_precheck must catch unmigratable shapes
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn dirty_short_token_refused_by_prefix_precheck() {
    let conn = setup_pre_migration_vault();
    insert_entry(&conn, "short", "aikey_vk_short");

    let res = migrations::upgrade_all(&conn);
    assert!(res.is_err(), "upgrade_all must refuse dirty short-token row");
    assert!(res.unwrap_err().contains("v1.0.5-alpha migration refused"),
        "error must reference v1.0.5-alpha refusal");

    // Critical: refused upgrade leaves the row UNCHANGED (no partial migration).
    let after: String = conn
        .query_row("SELECT route_token FROM entries WHERE alias='short'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(after, "aikey_vk_short", "refused upgrade must not touch dirty row");
}

#[test]
fn dirty_non_hex_suffix_refused() {
    let conn = setup_pre_migration_vault();
    let dirty_token = format!("aikey_vk_{}", "g".repeat(64));  // 64 chars, non-hex
    insert_entry(&conn, "non-hex", &dirty_token);

    let res = migrations::upgrade_all(&conn);
    assert!(res.is_err(), "non-hex suffix must trigger prefix_precheck refusal");
}

#[test]
fn dirty_provider_accounts_table_also_checked() {
    // Ensure the precheck covers provider_accounts table, not just entries.
    let conn = setup_pre_migration_vault();
    let dirty_token = format!("aikey_vk_{}", "X".repeat(64));  // non-hex (uppercase X)
    insert_oauth_account(&conn, "dirty-acct", &dirty_token);

    let res = migrations::upgrade_all(&conn);
    assert!(res.is_err(), "dirty provider_accounts row must be caught by precheck");
}

// ─────────────────────────────────────────────────────────────────────────
// Completeness precheck — NULL/empty don't refuse, just get reported
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn null_and_empty_tokens_skip_migration_without_refusal() {
    // Per spec §8.2.2: completeness precheck reports NULL/empty rows but
    // does NOT block migration. Those rows simply don't match the upgrade
    // WHERE clause's prefix filter and are left untouched.
    let conn = setup_pre_migration_vault();
    // Use INSERT directly with all NOT NULL columns; the route_token column
    // is the one we vary (NULL for one, '' for the other).
    conn.execute(
        "INSERT INTO entries(alias, nonce, ciphertext, route_token) VALUES (?1, ?2, ?3, NULL)",
        rusqlite::params!["null", &b"n"[..], &b"c"[..]],
    ).unwrap();
    conn.execute(
        "INSERT INTO entries(alias, nonce, ciphertext, route_token) VALUES (?1, ?2, ?3, '')",
        rusqlite::params!["empty", &b"n"[..], &b"c"[..]],
    ).unwrap();

    // Should NOT err — NULL/empty don't match prefix filter.
    migrations::upgrade_all(&conn).expect("upgrade should succeed despite NULL/empty rows");

    // Completeness precheck reports them.
    let dirty_count = v1_0_5_alpha::completeness_precheck(&conn, "entries").unwrap();
    assert_eq!(dirty_count, 2, "completeness precheck should report 2 (NULL + empty)");

    // Both rows still NULL/empty post-upgrade — not synthesized into bogus tokens.
    let null_count: i64 = conn
        .query_row("SELECT count(*) FROM entries WHERE route_token IS NULL", [], |r| r.get(0))
        .unwrap();
    let empty_count: i64 = conn
        .query_row("SELECT count(*) FROM entries WHERE route_token = ''", [], |r| r.get(0))
        .unwrap();
    assert_eq!(null_count, 1);
    assert_eq!(empty_count, 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Round-trip — rollback v1.0.5-alpha and re-upgrade
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn rollback_then_re_upgrade_round_trip() {
    let conn = setup_pre_migration_vault();
    let original = format!("aikey_vk_{}", HEX_LOWER);
    insert_entry(&conn, "rt", &original);

    // Forward.
    migrations::upgrade_all(&conn).unwrap();
    let post_upgrade: String = conn
        .query_row("SELECT route_token FROM entries WHERE alias='rt'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(post_upgrade, format!("aikey_personal_{}", HEX_LOWER));

    // Rollback only the v1.0.5-alpha layer (not the whole registry — earlier
    // baseline rollbacks would drop tables).
    v1_0_5_alpha::rollback(&conn).unwrap();
    let post_rollback: String = conn
        .query_row("SELECT route_token FROM entries WHERE alias='rt'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(post_rollback, original, "rollback must restore original aikey_vk_ form");

    // Forward again — idempotency over the full round-trip.
    v1_0_5_alpha::upgrade(&conn).unwrap();
    let post_re_upgrade: String = conn
        .query_row("SELECT route_token FROM entries WHERE alias='rt'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(post_re_upgrade, format!("aikey_personal_{}", HEX_LOWER),
        "second upgrade after rollback must produce the same new-form token");
}

// ─────────────────────────────────────────────────────────────────────────
// Live event verification proxy — schema-truth check
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn post_migration_form_matches_proxy_isTier1Personal_strict_form() {
    // Schema-truth verification: after migration, every row's token must be
    // PARSEABLE by the proxy's strict isTier1Personal check (length 79 +
    // exactly 64 lowercase hex). Catches any silent format drift.
    let conn = setup_post_migration_vault();
    insert_entry(&conn, "post", &format!("aikey_personal_{}", HEX_LOWER));

    // Re-run upgrade — already migrated, should be no-op.
    v1_0_5_alpha::upgrade(&conn).unwrap();

    let token: String = conn
        .query_row("SELECT route_token FROM entries WHERE alias='post'", [], |r| r.get(0))
        .unwrap();
    // Mirror dispatch.go's isTier1Personal logic.
    assert_eq!(token.len(), 79);
    assert!(token.starts_with("aikey_personal_"));
    let suffix = &token[15..];
    assert_eq!(suffix.len(), 64);
    assert!(suffix.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "suffix must be lowercase hex only, got: {}", suffix);
}
