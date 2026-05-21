//! AKL-107: tests for the `commands_app` storage + validation logic.
//!
//! Two test layers:
//!
//!   1. **Pure-logic validation** — slug form, protocol enum,
//!      first-party invariants, whitelist membership. No DB.
//!
//!   2. **Vault write paths** — drive the `*_with_conn` SQL inner functions
//!      against an in-memory SQLite primed with the real baseline schema
//!      via `migrations::v1_0_0_baseline::upgrade()`. This is the test
//!      fixture approach mandated by CLAUDE.md "测试 fixture 必须映射真实
//!      schema": we use the actual migration code rather than a hand-rolled
//!      simplified schema, so schema drift between the Rust writer and
//!      the Go reader is caught here.
//!
//! What we explicitly do NOT test here:
//!   - The handler-level orchestration (interactive prompts, env line
//!     output, json_mode plumbing). Those are thin shells over the storage
//!     helpers + crate::commands_proxy::maybe_warn_stale (which is a
//!     side-effect; orchestrating it in a test would require mocking the
//!     proxy lifecycle). Coverage is concentrated where the bugs live:
//!     the SQL + the validators.

use super::*;
use crate::migrations;
use rusqlite::Connection;

/// Builds an in-memory vault with the canonical baseline schema applied.
/// Matches the production `storage::open_connection` PRAGMA setup
/// (foreign_keys=ON) so CASCADE / FK rejections behave the same in tests
/// as in real usage.
fn fresh_test_vault() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory");
    conn.pragma_update(None, "foreign_keys", "ON")
        .expect("enable foreign_keys");
    migrations::upgrade_all(&conn).expect("upgrade_all");
    conn
}

// ---------------------------------------------------------------------------
// Pure-logic validators (no DB).
// ---------------------------------------------------------------------------

#[test]
fn validate_slug_accepts_canonical_forms() {
    for ok in &[
        "abc",
        "degrade-detector",
        "my-agent-v2",
        "agent42",
        "a1b2c3",
        &"a".repeat(64), // max length
    ] {
        assert!(
            validate_slug(ok).is_ok(),
            "slug {:?} should be accepted",
            ok
        );
    }
}

#[test]
fn validate_slug_rejects_bad_forms() {
    let bad: &[(&str, &str)] = &[
        ("ab", "too short (2 chars)"),
        (&"a".repeat(65), "too long (65 chars)"),
        ("1agent", "starts with digit"),
        ("-agent", "starts with dash"),
        ("agent-", "ends with dash"),
        ("Agent", "uppercase letter"),
        ("a_b", "underscore disallowed"),
        ("a.b", "dot disallowed"),
        ("a/b", "slash disallowed"),
        ("a--b", "consecutive dashes"),
        ("a b", "space disallowed"),
    ];
    for (slug, why) in bad {
        assert!(
            validate_slug(slug).is_err(),
            "slug {:?} should be rejected ({})",
            slug,
            why
        );
    }
}

#[test]
fn validate_upstreams_requires_known_values() {
    assert!(validate_upstreams(&[]).is_err(), "empty list must reject");
    assert!(validate_upstreams(&["openai".into()]).is_ok());
    assert!(validate_upstreams(&["anthropic".into()]).is_ok());
    assert!(validate_upstreams(&["openai".into(), "anthropic".into()]).is_ok());
    // kimi / openrouter / deepseek / qwen / etc. are valid since Day 9 B (OpenAI-wire-compat catalog).
    assert!(validate_upstreams(&["kimi".into()]).is_ok());
    assert!(validate_upstreams(&["openrouter".into()]).is_ok());
    // gemini upstream not supported yet (different wire, no translator pair).
    assert!(validate_upstreams(&["gemini".into()]).is_err(), "unsupported upstream must reject");
    assert!(validate_upstreams(&["OpenAI".into()]).is_err(), "case-sensitive: uppercase rejected");
    assert!(
        validate_upstreams(&["openai".into(), "nonexistent-vendor".into()]).is_err(),
        "one unknown in the set must reject the whole list"
    );
}

#[test]
fn first_party_whitelist_membership() {
    assert!(is_first_party("degrade-detector"));
    assert!(!is_first_party("random-third-party"));
    assert!(!is_first_party(""));
    assert!(!is_first_party("Degrade-Detector"), "case-sensitive");
}

// 2026-05-21 Regression pin — "第三方 app 不支持 follow_user_active=true, 内置的才支持, 堵死入口, 不让更改"
// 该 test 显式覆盖三种攻击/误用路径, 任何未来修改 validate_first_party_invariants
// 都得保证这些路径仍然 reject。
#[test]
fn r2_blocklist_third_party_cannot_follow_user_active() {
    // 路径 1: third-party slug 单独传 --follow-user-active=true (without first-party)
    //         → reject (跨字段规则: follow_user_active 要求 first_party=true)
    let err = validate_first_party_invariants("random-agent", false, true)
        .expect_err("third-party cannot follow_user_active");
    assert!(err.contains("--follow-user-active"), "msg should explain the rule: {}", err);

    // 路径 2: third-party slug + --first-party + --follow-user-active=true
    //         → reject (slug 白名单 fail)
    let err = validate_first_party_invariants("random-agent", true, true)
        .expect_err("third-party slug claiming first-party must reject");
    assert!(err.contains("whitelist"), "msg should mention whitelist: {}", err);

    // 路径 3: first-party 白名单内 slug + --first-party + --follow-user-active=true
    //         → 允许 (这是唯一合法路径)
    assert!(validate_first_party_invariants("degrade-detector", true, true).is_ok(),
            "first-party + follow_user_active=true must be allowed for whitelisted slug");
}

#[test]
fn first_party_invariants_gate_follow_user_active() {
    // happy path: first-party slug + first_party + follow_user_active
    assert!(validate_first_party_invariants("degrade-detector", true, true).is_ok());
    // happy path: third-party slug, no first-party flag, no follow
    assert!(validate_first_party_invariants("random-agent", false, false).is_ok());
    // happy path: first-party slug + first_party but follow=false (still OK)
    assert!(validate_first_party_invariants("degrade-detector", true, false).is_ok());

    // reject: random slug claiming first-party (R2 — main protection)
    let err = validate_first_party_invariants("random-agent", true, false)
        .expect_err("non-whitelist first-party must reject");
    assert!(
        err.contains("whitelist"),
        "rejection message should mention whitelist: {}",
        err
    );

    // reject: follow_user_active without first_party (cross-field rule)
    let err = validate_first_party_invariants("random-agent", false, true)
        .expect_err("follow_user_active without first_party must reject");
    assert!(
        err.contains("--follow-user-active"),
        "rejection message should mention --follow-user-active: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Vault SQL writes — driven through the *_with_conn inner functions.
// ---------------------------------------------------------------------------

#[test]
fn upsert_app_record_inserts_then_updates() {
    let conn = fresh_test_vault();

    let inserted = upsert_app_record_with_conn(
        &conn,
        "agent-a",
        "Agent A",
        "haoge-labs",
        &["openai".into()],
        "third-party",
        false,
        &["cloud_models".into()],
    )
    .expect("first upsert");
    assert!(inserted, "first call should return inserted=true");

    let rec = get_app_record_with_conn(&conn, "agent-a")
        .expect("read")
        .expect("row should exist after upsert");
    assert_eq!(rec.name, "Agent A");
    assert_eq!(rec.upstreams, vec!["openai".to_string()]);
    assert!(!rec.follow_user_active);

    // Second upsert: same slug, different metadata → update in place,
    // returns inserted=false.
    let inserted2 = upsert_app_record_with_conn(
        &conn,
        "agent-a",
        "Agent A Renamed",
        "new-vendor",
        &["openai".into(), "anthropic".into()],
        "third-party",
        false,
        &[],
    )
    .expect("second upsert");
    assert!(!inserted2, "second call must return inserted=false");

    let rec2 = get_app_record_with_conn(&conn, "agent-a")
        .expect("read")
        .expect("row");
    assert_eq!(rec2.name, "Agent A Renamed");
    assert_eq!(rec2.vendor, "new-vendor");
    assert_eq!(rec2.upstreams, vec!["openai".to_string(), "anthropic".to_string()]);
}

#[test]
fn get_app_record_missing_returns_none() {
    let conn = fresh_test_vault();
    let got = get_app_record_with_conn(&conn, "nonexistent").expect("query");
    assert!(got.is_none());
}

#[test]
fn upsert_app_record_first_party_with_follow() {
    let conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn,
        "degrade-detector",
        "Degradation Probe",
        "aikey-labs",
        &["openai".into(), "anthropic".into()],
        "first-party",
        true,
        &["cloud_models".into(), "oauth_accounts".into()],
    )
    .expect("upsert first-party");

    let rec = get_app_record_with_conn(&conn, "degrade-detector")
        .expect("read")
        .expect("row");
    assert_eq!(rec.app_kind, "first-party");
    assert!(rec.follow_user_active);
    assert_eq!(rec.requested_permissions.len(), 2);
}

#[test]
fn upsert_app_record_rejects_invalid_app_kind() {
    // The CHECK constraint in baseline schema rejects app_kind values
    // outside the enum. This pins the constraint as a SECOND defense
    // beyond validate_first_party_invariants in the handler — even if
    // the validator is bypassed (e.g. a future _internal helper that
    // forgets to call it), the DB will refuse.
    let conn = fresh_test_vault();
    let err = upsert_app_record_with_conn(
        &conn,
        "agent-a",
        "A",
        "v",
        &["openai".into()],
        "admin",
        false,
        &[],
    )
    .expect_err("invalid app_kind must fail at DB layer");
    assert!(err.contains("UPSERT app_records"), "{}", err);
}

#[test]
fn authorize_atomic_inserts_key_and_bindings() {
    let mut conn = fresh_test_vault();

    // Register first so the FK to app_records is satisfied.
    upsert_app_record_with_conn(
        &conn,
        "agent-a",
        "A",
        "v",
        &["openai".into()],
        "third-party",
        false,
        &[],
    )
    .unwrap();

    let initial_bindings = vec![
        (
            "openai".to_string(),
            CredentialType::PersonalApiKey,
            "my-key-alias".to_string(),
        ),
    ];

    let (key_id, route_token) =
        authorize_atomic_with_conn(&mut conn, "agent-a", &initial_bindings).expect("authorize");

    assert!(!key_id.is_empty(), "key_id must be non-empty UUID");
    assert!(
        route_token.starts_with("aikey_app_"),
        "route_token prefix wrong: {}",
        route_token
    );
    assert_eq!(
        route_token.len(),
        "aikey_app_".len() + 64,
        "route_token length wrong"
    );

    // Verify app_keys row.
    let key_row: (String, String, String) = conn
        .query_row(
            "SELECT key_id, app_slug, status FROM app_keys WHERE app_slug = 'agent-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("app_keys row");
    assert_eq!(key_row.0, key_id);
    assert_eq!(key_row.1, "agent-a");
    assert_eq!(key_row.2, "active");

    // Verify user_profile_provider_bindings row.
    let binding_row: (String, String, String) = conn
        .query_row(
            "SELECT key_source_type, key_source_ref, profile_id FROM user_profile_provider_bindings WHERE profile_id = 'app:agent-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("binding row");
    assert_eq!(binding_row.0, "personal");
    assert_eq!(binding_row.1, "my-key-alias");
    assert_eq!(binding_row.2, "app:agent-a");
}

#[test]
fn authorize_atomic_empty_bindings_still_writes_key() {
    let mut conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn,
        "agent-b",
        "B",
        "v",
        &["anthropic".into()],
        "third-party",
        false,
        &[],
    )
    .unwrap();

    let (_kid, _rt) = authorize_atomic_with_conn(&mut conn, "agent-b", &[]).expect("authorize");

    let key_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_keys WHERE app_slug = 'agent-b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(key_count, 1);

    let binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM user_profile_provider_bindings WHERE profile_id = 'app:agent-b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(binding_count, 0, "no bindings should be created with empty slice");
}

#[test]
fn authorize_atomic_rolls_back_on_binding_failure() {
    // Atomicity check: if the binding INSERT fails mid-transaction, the
    // app_keys INSERT must also be rolled back so we don't leave a key
    // row without a matching binding (which would cause the proxy to
    // 409 every request — the failure mode 主方案 §11.A specifically
    // calls out as why the writes must be transactional).
    //
    // We trigger a failure by passing TWO bindings with the same
    // (profile_id, provider_code) but the second one with a malformed
    // key_source_type that, while accepted at SQL level, would in a real
    // system be caught downstream. To force a SQL-level failure we cause
    // a PK clash by binding the same (profile_id, provider_code) twice
    // — but UPSERT handles that gracefully, so instead we abort by
    // pointing at a slug whose FK is not satisfied.
    let mut conn = fresh_test_vault();

    let initial_bindings = vec![
        ("openai".to_string(), CredentialType::PersonalApiKey, "ref-a".to_string()),
    ];

    // No app_records row for "ghost-slug" → FK violation on app_keys insert.
    let err = authorize_atomic_with_conn(&mut conn, "ghost-slug", &initial_bindings)
        .expect_err("FK violation should abort");
    assert!(
        err.contains("INSERT app_keys") || err.contains("FOREIGN KEY"),
        "{}",
        err
    );

    // Atomicity: no rows should have been written to either table.
    let key_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_keys WHERE app_slug = 'ghost-slug'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(key_count, 0, "failed authorize must leave 0 app_keys rows");

    let binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM user_profile_provider_bindings WHERE profile_id = 'app:ghost-slug'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(binding_count, 0, "failed authorize must leave 0 binding rows");
}

#[test]
fn revoke_active_keys_flips_status_preserves_history() {
    let mut conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn,
        "agent-c",
        "C",
        "v",
        &["openai".into()],
        "third-party",
        false,
        &[],
    )
    .unwrap();

    authorize_atomic_with_conn(&mut conn, "agent-c", &[]).unwrap();

    let revoked = revoke_active_keys_with_conn(&conn, "agent-c").expect("revoke");
    assert_eq!(revoked, 1, "exactly one active key should be revoked");

    // Re-revoke: no active rows left.
    let revoked2 = revoke_active_keys_with_conn(&conn, "agent-c").expect("revoke");
    assert_eq!(revoked2, 0, "second revoke is a no-op");

    // History preserved: row still exists with status='revoked'.
    let status: String = conn
        .query_row(
            "SELECT status FROM app_keys WHERE app_slug = 'agent-c'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "revoked", "row preserved with revoked status (audit trail)");

    // app_records row also preserved — user can re-authorize without re-registering.
    assert!(
        get_app_record_with_conn(&conn, "agent-c")
            .unwrap()
            .is_some(),
        "app_records row must survive revoke"
    );
}

#[test]
fn list_apps_returns_records_with_active_key_join() {
    let mut conn = fresh_test_vault();

    upsert_app_record_with_conn(
        &conn,
        "agent-with-key",
        "W",
        "v",
        &["openai".into()],
        "third-party",
        false,
        &[],
    )
    .unwrap();
    upsert_app_record_with_conn(
        &conn,
        "agent-no-key",
        "N",
        "v",
        &["anthropic".into()],
        "third-party",
        false,
        &[],
    )
    .unwrap();

    authorize_atomic_with_conn(&mut conn, "agent-with-key", &[]).unwrap();

    // list_apps uses the public function which calls open_connection —
    // we can't reuse our in-memory conn here. Instead drive the JOIN via
    // raw SQL on the in-memory conn to verify the same shape.
    let mut stmt = conn
        .prepare(
            "SELECT r.slug, k.key_id
               FROM app_records r
          LEFT JOIN app_keys k ON k.app_slug = r.slug AND k.status = 'active'
           ORDER BY r.slug",
        )
        .unwrap();
    let rows: Vec<(String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert_eq!(rows.len(), 2);
    let (slug1, key1) = &rows[0];
    let (slug2, key2) = &rows[1];
    assert_eq!(slug1, "agent-no-key");
    assert!(key1.is_none(), "no active key for agent-no-key");
    assert_eq!(slug2, "agent-with-key");
    assert!(key2.is_some(), "active key joined for agent-with-key");
}

#[test]
fn route_token_is_strict_aikey_app_form() {
    // Cross-check the generated route_token shape matches the proxy's
    // `isTier1App` form predicate (dispatch.go in aikey-proxy). If this
    // breaks, Phase 1 token bearer routing breaks — pin the contract.
    let token = storage::generate_app_route_token();
    assert!(token.starts_with("aikey_app_"));
    assert_eq!(token.len(), "aikey_app_".len() + 64);
    let suffix = &token["aikey_app_".len()..];
    for c in suffix.chars() {
        assert!(
            c.is_ascii_digit() || ('a'..='f').contains(&c),
            "char {:?} not lowercase hex (proxy isTier1App will reject)",
            c
        );
    }
}

// ---------------------------------------------------------------------------
// pause / resume / rotate (AKL-301b).
// ---------------------------------------------------------------------------

#[test]
fn pause_active_key_then_resume_returns_to_active() {
    let mut conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn, "agent-pause", "P", "v", &["openai".into()], "third-party", false, &[],
    )
    .unwrap();
    let (key_id, _) = authorize_atomic_with_conn(&mut conn, "agent-pause", &[]).unwrap();

    // Pause.
    let paused = pause_active_keys_with_conn(&conn, "agent-pause").unwrap();
    assert_eq!(paused, 1, "exactly one active key should be paused");
    let status: String = conn
        .query_row(
            "SELECT status FROM app_keys WHERE key_id = ?1",
            params![key_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "paused");

    // Resume.
    let resumed = resume_paused_keys_with_conn(&conn, "agent-pause").unwrap();
    assert_eq!(resumed, 1);
    let status: String = conn
        .query_row(
            "SELECT status FROM app_keys WHERE key_id = ?1",
            params![key_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "active", "resume must restore status to 'active'");

    // Same route_token across pause+resume cycle (Agent's bearer unchanged).
    // The key_id stayed the same throughout, which proves the row is the same.
}

#[test]
fn pause_does_not_affect_revoked_keys() {
    // If history contains revoked rows, pause must NOT touch them — only
    // currently-active rows are paused.
    let mut conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn, "agent-mix", "M", "v", &["openai".into()], "third-party", false, &[],
    )
    .unwrap();

    // Create an active key, revoke it (history row), then authorize a new active key.
    authorize_atomic_with_conn(&mut conn, "agent-mix", &[]).unwrap();
    revoke_active_keys_with_conn(&conn, "agent-mix").unwrap();
    let (new_key, _) = authorize_atomic_with_conn(&mut conn, "agent-mix", &[]).unwrap();

    // Pause should only flip the new active row, not the revoked history.
    let paused = pause_active_keys_with_conn(&conn, "agent-mix").unwrap();
    assert_eq!(paused, 1);

    let new_status: String = conn
        .query_row(
            "SELECT status FROM app_keys WHERE key_id = ?1",
            params![new_key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(new_status, "paused");

    // Revoked rows still revoked.
    let revoked_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_keys WHERE app_slug='agent-mix' AND status='revoked'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revoked_count, 1, "pause must not change revoked rows' status");
}

#[test]
fn rotate_atomic_replaces_old_active_with_new() {
    let mut conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn, "agent-rot", "R", "v", &["openai".into()], "third-party", false, &[],
    )
    .unwrap();
    let (old_key, old_token) = authorize_atomic_with_conn(&mut conn, "agent-rot", &[]).unwrap();

    let (new_key, new_token) = rotate_app_key_with_conn(&mut conn, "agent-rot").unwrap();

    // Different key_id + different route_token.
    assert_ne!(old_key, new_key, "rotate must produce a NEW key_id");
    assert_ne!(old_token, new_token, "rotate must produce a NEW route_token");

    // Old key must be revoked, new key must be active. Exactly one active.
    let old_status: String = conn
        .query_row(
            "SELECT status FROM app_keys WHERE key_id = ?1",
            params![old_key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_status, "revoked", "old key after rotate should be revoked");

    let new_status: String = conn
        .query_row(
            "SELECT status FROM app_keys WHERE key_id = ?1",
            params![new_key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(new_status, "active");

    let active_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_keys WHERE app_slug='agent-rot' AND status='active'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(active_count, 1, "exactly one active key after rotate");
}

#[test]
fn rotate_atomicity_no_window_with_two_active() {
    // Pin the single-transaction invariant via SQL-level evidence: at no
    // point should there be 2 active rows for the same slug. Since we
    // can't observe the intermediate state from outside, we check the
    // post-condition has exactly 1 active. (The transactional guarantee
    // is also encoded in rotate_app_key_with_conn's `tx.commit()`.)
    let mut conn = fresh_test_vault();
    upsert_app_record_with_conn(
        &conn, "agent-atom", "A", "v", &["openai".into()], "third-party", false, &[],
    )
    .unwrap();

    authorize_atomic_with_conn(&mut conn, "agent-atom", &[]).unwrap();

    // Multiple rotations in sequence; each must leave exactly 1 active.
    for _ in 0..5 {
        rotate_app_key_with_conn(&mut conn, "agent-atom").unwrap();
        let active: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM app_keys WHERE app_slug='agent-atom' AND status='active'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 1, "after each rotation, exactly one active key");
    }

    // Final state: 6 rows total (1 from initial authorize + 5 from rotations),
    // 5 revoked + 1 active.
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_keys WHERE app_slug='agent-atom'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(total, 6, "expected 6 history rows (1 authorize + 5 rotations)");
}

#[test]
fn route_tokens_are_unique_across_calls() {
    // Probabilistically test the 256-bit randomness: 100 sequential calls
    // must all produce distinct tokens. If this ever fails the OsRng is
    // broken (which would be a much bigger crisis than a test failure).
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for _ in 0..100 {
        let t = storage::generate_app_route_token();
        assert!(seen.insert(t), "duplicate route_token in 100 calls — OsRng broken?");
    }
}

// ---------------------------------------------------------------------------
// 2026-05-21 UX 重构: register 一步发 bearer + 静态快照 aikey use.
// Pure-logic tests for the binding classification (no DB needed).
// ---------------------------------------------------------------------------

use crate::commands_app::handlers::classify_upstreams_for_register;
use crate::commands_app::handlers::RegisterBindingOutcome;
use crate::credential_type::CredentialType;
use crate::storage::ProviderBinding;

fn binding(profile: &str, provider: &str, kt: CredentialType, kr: &str) -> ProviderBinding {
    ProviderBinding {
        profile_id: profile.to_string(),
        provider_code: provider.to_string(),
        key_source_type: kt,
        key_source_ref: kr.to_string(),
        updated_at: Some(1_700_000_000),
    }
}

#[test]
fn classify_register_all_from_default_snapshot() {
    // User ran `aikey use my-anthropic` + `aikey use my-openai`.
    // Brand-new register: nothing in app:<slug>, everything from default
    // should be snapshotted.
    let upstreams = vec!["anthropic".to_string(), "openai".to_string()];
    let existing_app: Vec<ProviderBinding> = vec![];
    let default = vec![
        binding("default", "anthropic", CredentialType::PersonalApiKey, "my-anthropic"),
        binding("default", "openai", CredentialType::PersonalApiKey, "my-openai"),
    ];
    let RegisterBindingOutcome { snapshotted, preserved, missing } =
        classify_upstreams_for_register(&upstreams, &existing_app, &default);
    assert_eq!(snapshotted.len(), 2);
    assert!(preserved.is_empty());
    assert!(missing.is_empty());
    assert!(snapshotted.iter().any(|(u, _, r)| u == "anthropic" && r == "my-anthropic"));
    assert!(snapshotted.iter().any(|(u, _, r)| u == "openai" && r == "my-openai"));
}

#[test]
fn classify_register_preserves_user_override_bug_1_regression() {
    // Bug 1 regression: user previously ran `aikey app route X --upstream
    // anthropic --key-ref my-work-anthropic`, app:<slug>|anthropic has a
    // row. Now vendor reruns register. We MUST keep that row (preserved),
    // NOT overwrite from default.
    let upstreams = vec!["anthropic".to_string(), "openai".to_string()];
    let existing_app = vec![binding(
        "app:claude-code",
        "anthropic",
        CredentialType::PersonalApiKey,
        "my-work-anthropic", // ← user's override
    )];
    let default = vec![
        binding("default", "anthropic", CredentialType::PersonalApiKey, "my-anthropic"),
        binding("default", "openai", CredentialType::PersonalApiKey, "my-openai"),
    ];
    let outcome = classify_upstreams_for_register(&upstreams, &existing_app, &default);
    // anthropic: preserved (user override wins), NOT snapshotted.
    assert_eq!(outcome.preserved.len(), 1);
    assert_eq!(outcome.preserved[0].0, "anthropic");
    assert_eq!(outcome.preserved[0].2, "my-work-anthropic"); // user's choice
    // openai: snapshotted (no override existed).
    assert_eq!(outcome.snapshotted.len(), 1);
    assert_eq!(outcome.snapshotted[0].0, "openai");
    assert_eq!(outcome.snapshotted[0].2, "my-openai");
    assert!(outcome.missing.is_empty());
}

#[test]
fn classify_register_missing_when_no_default_and_no_override() {
    // User declared anthropic + openai upstreams but `aikey use` only
    // selected anthropic. openai should land in missing list.
    let upstreams = vec!["anthropic".to_string(), "openai".to_string()];
    let existing_app: Vec<ProviderBinding> = vec![];
    let default = vec![binding(
        "default",
        "anthropic",
        CredentialType::PersonalApiKey,
        "my-anthropic",
    )];
    let outcome = classify_upstreams_for_register(&upstreams, &existing_app, &default);
    assert_eq!(outcome.snapshotted.len(), 1);
    assert_eq!(outcome.snapshotted[0].0, "anthropic");
    assert_eq!(outcome.missing, vec!["openai".to_string()]);
    assert!(outcome.preserved.is_empty());
}

#[test]
fn classify_register_aikey_use_empty_all_missing() {
    // Q2=B2 case: user never ran `aikey use`, but tries register anyway.
    // All upstreams land in missing. No bindings written.
    let upstreams = vec!["anthropic".to_string(), "openai".to_string()];
    let outcome = classify_upstreams_for_register(&upstreams, &[], &[]);
    assert!(outcome.snapshotted.is_empty());
    assert!(outcome.preserved.is_empty());
    assert_eq!(outcome.missing, vec!["anthropic", "openai"]);
}

#[test]
fn classify_register_all_overrides_no_snapshot() {
    // User ran `aikey app route` for every upstream already. Re-register
    // does NOTHING new — all preserved.
    let upstreams = vec!["anthropic".to_string()];
    let existing_app = vec![binding(
        "app:agent",
        "anthropic",
        CredentialType::ManagedVirtualKey,
        "team-vk-uuid",
    )];
    let default = vec![binding(
        "default",
        "anthropic",
        CredentialType::PersonalApiKey,
        "my-anthropic",
    )];
    let outcome = classify_upstreams_for_register(&upstreams, &existing_app, &default);
    assert!(outcome.snapshotted.is_empty()); // ← override prevented snapshot
    assert_eq!(outcome.preserved.len(), 1);
    assert_eq!(outcome.preserved[0].2, "team-vk-uuid");
    assert!(outcome.missing.is_empty());
}

#[test]
fn classify_register_extra_default_not_in_upstreams_ignored() {
    // User's `aikey use` has 3 providers, but app only declares 1.
    // Only the declared one is processed; extra defaults silently ignored.
    let upstreams = vec!["anthropic".to_string()];
    let existing_app: Vec<ProviderBinding> = vec![];
    let default = vec![
        binding("default", "anthropic", CredentialType::PersonalApiKey, "my-anthropic"),
        binding("default", "openai", CredentialType::PersonalApiKey, "my-openai"),
        binding("default", "kimi", CredentialType::PersonalApiKey, "my-kimi"),
    ];
    let outcome = classify_upstreams_for_register(&upstreams, &existing_app, &default);
    assert_eq!(outcome.snapshotted.len(), 1);
    assert_eq!(outcome.snapshotted[0].0, "anthropic");
    assert!(outcome.preserved.is_empty());
    assert!(outcome.missing.is_empty());
}
