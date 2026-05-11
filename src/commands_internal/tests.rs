//! commands_internal 单元测试（纯逻辑，不涉及真实 vault）

use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::decode_vault_key;

#[test]
fn envelope_parses_minimal() {
    let raw = r#"{
        "vault_key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "action": "verify"
    }"#;
    let env: StdinEnvelope = serde_json::from_str(raw).expect("parse ok");
    assert_eq!(env.action, "verify");
    assert_eq!(env.vault_key_hex.len(), 64);
    assert!(env.request_id.is_none());
}

#[test]
fn envelope_parses_with_request_id() {
    let raw = r#"{
        "vault_key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "action": "verify",
        "request_id": "req-123",
        "payload": {"foo": "bar"}
    }"#;
    let env: StdinEnvelope = serde_json::from_str(raw).expect("parse ok");
    assert_eq!(env.request_id.as_deref(), Some("req-123"));
    assert_eq!(env.payload["foo"], "bar");
}

#[test]
fn envelope_rejects_invalid_json() {
    let raw = "not json at all";
    let result: Result<StdinEnvelope, _> = serde_json::from_str(raw);
    assert!(result.is_err());
}

#[test]
fn envelope_rejects_missing_required_fields() {
    // 缺 vault_key_hex
    let raw = r#"{"action": "verify"}"#;
    let result: Result<StdinEnvelope, _> = serde_json::from_str(raw);
    assert!(result.is_err(), "should fail when vault_key_hex missing");

    // 缺 action
    let raw = r#"{"vault_key_hex": "abcd"}"#;
    let result: Result<StdinEnvelope, _> = serde_json::from_str(raw);
    assert!(result.is_err(), "should fail when action missing");
}

#[test]
fn decode_vault_key_accepts_64_hex() {
    let hex_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key = decode_vault_key(hex_str).expect("decode ok");
    assert_eq!(key.len(), 32);
    assert_eq!(key[0], 0x01);
    assert_eq!(key[31], 0xef);
}

#[test]
fn decode_vault_key_rejects_wrong_length() {
    // 太短
    let err = decode_vault_key("0123").expect_err("should fail short");
    assert_eq!(err.0, "I_VAULT_KEY_MALFORMED");

    // 64 chars 但非 hex
    let err = decode_vault_key("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        .expect_err("should fail non-hex");
    assert_eq!(err.0, "I_VAULT_KEY_MALFORMED");
}

#[test]
fn result_envelope_ok_serialization() {
    let env = ResultEnvelope::ok(Some("req-1".into()), serde_json::json!({"verified": true}));
    let s = serde_json::to_string(&env).unwrap();
    assert!(s.contains(r#""status":"ok""#));
    assert!(s.contains(r#""request_id":"req-1""#));
    assert!(s.contains(r#""verified":true"#));
    // ok 时不应有 error_code / error_message
    assert!(!s.contains("error_code"));
    assert!(!s.contains("error_message"));
}

#[test]
fn result_envelope_error_serialization() {
    let env = ResultEnvelope::error(None, "I_VAULT_KEY_INVALID", "bad key");
    let s = serde_json::to_string(&env).unwrap();
    assert!(s.contains(r#""status":"error""#));
    assert!(s.contains(r#""error_code":"I_VAULT_KEY_INVALID""#));
    assert!(s.contains(r#""error_message":"bad key""#));
    // error 时不应有 data
    assert!(!s.contains(r#""data":"#));
    // 无 request_id 时应省略该字段
    assert!(!s.contains("request_id"));
}

// ─── team_effective_status (regression: 2026-05-11) ─────────────────────
//
// Bugfix: workflow/CI/bugfix/
//   20260511-team-vault-effective-status-mismaps-synced-inactive.md
//
// The prior `local_state == "active"` check conflated "usable" with
// "currently routed", which made every claimed-but-not-routed team key
// (the common case after `aikey use` switches to a different key) render
// as INACTIVE on the vault page and hid the Use button — i.e. you could
// not re-select it because the UI lied about its state.
//
// These tests pin the truth table so the conflation cannot re-emerge.

use super::query::team_effective_status;

#[test]
fn team_effective_status_active_when_active_claimed_active() {
    assert_eq!(team_effective_status("active", "claimed", "active"), "active");
}

#[test]
fn team_effective_status_active_when_claimed_synced_inactive() {
    // The regression case: valid + claimed + not currently routed.
    // Must read as ACTIVE so the Use button is offered.
    assert_eq!(
        team_effective_status("active", "claimed", "synced_inactive"),
        "active",
    );
}

#[test]
fn team_effective_status_active_when_claimed_prompt_dismissed() {
    // User dismissed the auto-claim prompt; key is still valid + selectable.
    assert_eq!(
        team_effective_status("active", "claimed", "prompt_dismissed"),
        "active",
    );
}

#[test]
fn team_effective_status_inactive_when_local_state_stale() {
    // Server snapshot no longer includes this key — we don't know if it's
    // still valid, so don't offer it.
    assert_eq!(
        team_effective_status("active", "claimed", "stale"),
        "inactive",
    );
}

#[test]
fn team_effective_status_inactive_when_disabled_by_anything() {
    // Every `disabled_by_*` variant means the server told us this key is
    // unusable for a reason we can't override locally.
    for ls in [
        "disabled_by_key_status",
        "disabled_by_account_status",
        "disabled_by_account_scope",
        "disabled_by_seat_status",
    ] {
        assert_eq!(
            team_effective_status("active", "claimed", ls),
            "inactive",
            "local_state={} should map to inactive",
            ls,
        );
    }
}

#[test]
fn team_effective_status_inactive_when_key_status_not_active() {
    // Server-revoked / expired keys never usable regardless of local_state.
    assert_eq!(
        team_effective_status("revoked", "claimed", "active"),
        "inactive",
    );
    assert_eq!(
        team_effective_status("expired", "claimed", "active"),
        "inactive",
    );
}

#[test]
fn team_effective_status_inactive_when_share_pending() {
    // Not yet claimed → no `aikey_team_<vk_id>` binding the proxy will
    // accept, so unusable even though key_status=active.
    assert_eq!(
        team_effective_status("active", "pending_claim", "active"),
        "inactive",
    );
}

#[test]
fn team_effective_status_inactive_when_share_revoked() {
    assert_eq!(
        team_effective_status("active", "revoked", "active"),
        "inactive",
    );
}
