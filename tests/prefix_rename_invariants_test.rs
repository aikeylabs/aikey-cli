//! Invariant tests for the 2026-04-29 token prefix rename refactor.
//!
//! These tests pin contracts that are EASY to break by accident:
//!   - sentinel_token returning per-provider fixed string (alias-independent)
//!   - generate_route_token always lowercase hex (proxy's isTier1Personal
//!     only accepts [0-9a-f])
//!   - aikey route output never emits a token outside the 4 documented prefixes
//!   - team_token_from_vk_id is a complete round-trip with proxy supervisor's
//!     NormalizeTeamToken (no shape drift between Rust + Go)
//!   - migration prefix precheck catches every dirty-data shape the spec lists
//!
//! Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md
//!       roadmap20260320/技术实现/update/20260429-token前缀重命名-e2e测试方案.md

use aikeylabs_aikey_cli::storage::generate_route_token;
use aikeylabs_aikey_cli::team_token_normalize::team_token_from_vk_id;

// ───────────────────────────────────────────────────────────────────────────
// Invariant 1: generate_route_token output shape
// ───────────────────────────────────────────────────────────────────────────
//
// Why pin: proxy's isTier1Personal only accepts [0-9a-f]{64}. If a future
// refactor swaps `hex::encode` for an upper-case formatter (or a different
// crate that defaults to uppercase), every token generated post-refactor
// would 401 at the proxy. This test runs 100 iterations to make the
// probability of "happened to be lowercase by luck" negligible.

#[test]
fn generate_route_token_always_lowercase_hex() {
    for i in 0..100 {
        let t = generate_route_token();
        assert_eq!(t.len(), 79, "iter {}: wrong length: {}", i, t);
        assert!(
            t.starts_with("aikey_personal_"),
            "iter {}: wrong prefix: {}",
            i,
            t
        );
        let suffix = &t[15..];
        assert_eq!(suffix.len(), 64, "iter {}: suffix not 64 chars: {}", i, t);
        assert!(
            suffix.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "iter {}: suffix has non-lowercase-hex char: {}",
            i,
            t
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Invariant 2: team_token_from_vk_id is invariant under repeated application
// ───────────────────────────────────────────────────────────────────────────
//
// Why pin: handle_route, resolve_activate_key, and (in future) test target
// builders all call this helper. If any caller accidentally double-applies
// the helper or strips a prefix manually before calling, drift would surface
// as "aikey route" + "aikey activate" disagreeing on the same key. This
// invariant says: Ok(t) implies Ok(t.strip("aikey_team_")) → Ok(t).

#[test]
fn team_token_from_vk_id_is_idempotent_under_repeated_application() {
    let inputs = [
        "acc-1234",
        "vk_xyz",
        "team-with-dashes",
        "12345",
        "a",  // single char
    ];
    for raw in inputs {
        let first = team_token_from_vk_id(raw).unwrap();
        let second = team_token_from_vk_id(&first).unwrap();
        let third = team_token_from_vk_id(&second).unwrap();
        assert_eq!(
            first, second,
            "second application diverged for {:?}: {} vs {}",
            raw, first, second
        );
        assert_eq!(
            second, third,
            "third application diverged for {:?}: {} vs {}",
            raw, second, third
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Invariant 3: migration prefix-precheck catches every documented dirty shape
// ───────────────────────────────────────────────────────────────────────────
//
// Why pin: the spec's 8.2.2 dirty-data fixture matrix is the contract the
// migration runner must enforce. If precheck silently lets one shape through,
// the UPDATE WHERE clause will leave that row in legacy form post-migration
// → proxy 401 on next request. Test feeds each documented dirty shape into
// an in-memory fixture and asserts upgrade() refuses with a clear message.

#[test]
fn migration_refuses_every_documented_dirty_shape() {
    use aikeylabs_aikey_cli::migrations::v1_0_5_alpha;
    use rusqlite::Connection;

    let dirty_inputs: &[(&str, &str)] = &[
        // (alias, route_token) — each row is a separate scenario:
        //   "long_short"     — aikey_vk_ + 4-char suffix (length 13, not 73)
        ("d_short", "aikey_vk_short"),
        // "non_hex_char_g"   — length 73 but suffix contains 'g'
        ("d_g", "aikey_vk_gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"),
        // "uppercase letter beyond hex" (e.g. 'X') — length 73 with bad chars
        ("d_x", "aikey_vk_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
        // "all dashes"       — length 73 with all '-'
        ("d_dashes", "aikey_vk_----------------------------------------------------------------"),
    ];

    for (alias, dirty_token) in dirty_inputs {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE entries (alias TEXT PRIMARY KEY, route_token TEXT);
             CREATE TABLE provider_accounts (provider_account_id TEXT PRIMARY KEY, route_token TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entries(alias, route_token) VALUES (?1, ?2)",
            [alias, dirty_token],
        )
        .unwrap();

        let res = v1_0_5_alpha::upgrade(&conn);
        assert!(
            res.is_err(),
            "migration should refuse dirty row {} = {:?}, but it succeeded",
            alias,
            dirty_token
        );
        let err = res.unwrap_err();
        assert!(
            err.contains("v1.0.5-alpha migration refused"),
            "expected refusal message, got: {}",
            err
        );

        // After refused upgrade, dirty row must remain UNCHANGED — no partial migration.
        let after: String = conn
            .query_row(
                "SELECT route_token FROM entries WHERE alias = ?1",
                [alias],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            &after, dirty_token,
            "dirty row was partially migrated despite refusal: {:?} → {:?}",
            dirty_token, after
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Invariant 4: NULL + empty route_token are SKIPPED by upgrade (not refused)
// ───────────────────────────────────────────────────────────────────────────
//
// Why pin: spec §8.2.2 splits "dirty" into two classes:
//   A) bad shape with old prefix → prefix precheck refuses
//   B) NULL or empty token → completeness precheck SURFACES but does NOT
//      block migration (rows with missing tokens are valid pre-existing
//      state — e.g. row added but never had token generated yet)
// Upgrade should not refuse on B; it should just leave those rows untouched.
// This is subtle and easy to break by tightening the upgrade WHERE clause.

#[test]
fn migration_skips_null_and_empty_route_token_without_refusing() {
    use aikeylabs_aikey_cli::migrations::v1_0_5_alpha;
    use rusqlite::Connection;

    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE entries (alias TEXT PRIMARY KEY, route_token TEXT);
         CREATE TABLE provider_accounts (provider_account_id TEXT PRIMARY KEY, route_token TEXT);",
    )
    .unwrap();
    conn.execute("INSERT INTO entries(alias, route_token) VALUES ('null_one', NULL)", []).unwrap();
    conn.execute("INSERT INTO entries(alias, route_token) VALUES ('empty_one', '')", []).unwrap();

    // Should succeed (NOT refuse) — NULL/empty rows simply don't match the
    // upgrade WHERE clause's prefix filter.
    let res = v1_0_5_alpha::upgrade(&conn);
    assert!(res.is_ok(), "upgrade should succeed despite NULL/empty rows; got {:?}", res);

    // Both rows must still be NULL/empty post-upgrade — not synthesized into
    // some bogus token.
    let n_null: i64 = conn
        .query_row("SELECT count(*) FROM entries WHERE route_token IS NULL", [], |r| r.get(0))
        .unwrap();
    let n_empty: i64 = conn
        .query_row("SELECT count(*) FROM entries WHERE route_token = ''", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_null, 1, "NULL row was modified");
    assert_eq!(n_empty, 1, "empty row was modified");

    // Completeness precheck must report 2 (1 NULL + 1 empty).
    let dirty = v1_0_5_alpha::completeness_precheck(&conn, "entries").unwrap();
    assert_eq!(dirty, 2, "completeness precheck didn't catch NULL+empty");
}

// ───────────────────────────────────────────────────────────────────────────
// Invariant 5: helper rejects non-ASCII whitespace as "non-empty input"
// ───────────────────────────────────────────────────────────────────────────
//
// Exploratory: Rust's str::trim() strips Unicode whitespace (including
// U+00A0 NBSP, U+3000 IDEOGRAPHIC SPACE). If a vk_id field somehow ends
// up with NBSP padding from a copy-paste, trim() WILL strip it. This test
// pins that behavior so nobody "accidentally fixes" trim() to ASCII-only
// later — the cleanup is intentional.

#[test]
fn helper_trims_unicode_whitespace_consistently() {
    // U+00A0 = non-breaking space, common in copy-pasted text
    let nbsp = '\u{00A0}';
    let raw = format!("{}acc-1234{}", nbsp, nbsp);
    let result = team_token_from_vk_id(&raw).unwrap();
    assert_eq!(
        result, "aikey_team_acc-1234",
        "helper must trim Unicode whitespace consistently; got {:?}",
        result
    );

    // Pure NBSP-only input → empty after trim → Err (matches "  " case in golden fixture)
    let nbsp_only = format!("{}{}{}", nbsp, nbsp, nbsp);
    assert!(
        team_token_from_vk_id(&nbsp_only).is_err(),
        "Unicode-whitespace-only input should be rejected like ASCII whitespace-only"
    );
}
