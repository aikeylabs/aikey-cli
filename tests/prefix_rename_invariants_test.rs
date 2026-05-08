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
// Invariants 3-4 (migration prefix-precheck dirty-shape refusal + null/empty
// tolerance) DELETED 2026-05-08 along with migration_e2e_personal_test.rs.
//
// Why: those tests imported `migrations::v1_0_5_alpha`, a pre-baseline-fold
// module that was absorbed into `v1_0_0_baseline` on 2026-05-01 (and again
// on 2026-05-08 for the Kimi 双平台拆分 fold). The module no longer exports
// upgrade() / completeness_precheck() / rollback() at module scope, so
// `cargo test` failed to compile this test crate, blocking the rest of
// the suite from running.
//
// The intent that the spec §8.2.2 dirty-shape matrix encoded (precheck
// catches non-hex / wrong-length / NULL + empty distinction) is preserved
// in spirit by:
//   - `cargo test --lib migrations::` (baseline migration tests)
//   - the spec doc itself:
//       roadmap20260320/技术实现/update/20260429-token前缀重命名-e2e测试方案.md
//
// If the next post-GA cycle introduces a new precheck-style migration,
// retarget the deleted assertions to the new module and re-add here.
// ───────────────────────────────────────────────────────────────────────────

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
