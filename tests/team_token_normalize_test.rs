//! Golden cases test for `team_token_from_vk_id` (Rust side).
//!
//! Loads `tests/fixtures/team_token_normalize.json` (shared with Go side at
//! `aikey-proxy/internal/supervisor/team_token_normalize_test.go`) and asserts
//! every case. Both implementations must produce identical results across the
//! same fixture — guards against long-term drift.
//!
//! Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §4.

use aikeylabs_aikey_cli::team_token_normalize::team_token_from_vk_id;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    input: String,
    expected_ok: Option<String>,
    expected_err: Option<String>,
}

const FIXTURE_JSON: &str = include_str!("fixtures/team_token_normalize.json");

#[test]
fn golden_cases_all_pass() {
    let fixture: Fixture = serde_json::from_str(FIXTURE_JSON)
        .expect("fixture JSON parse failed");
    assert!(!fixture.cases.is_empty(), "fixture must contain at least one case");

    let mut failed: Vec<String> = Vec::new();

    for case in &fixture.cases {
        let actual = team_token_from_vk_id(&case.input);
        match (&case.expected_ok, &case.expected_err, &actual) {
            (Some(expected), None, Ok(got)) if got == expected => {}
            (None, Some(expected), Err(got)) if &got.to_string() == expected => {}
            _ => {
                failed.push(format!(
                    "case '{}': input={:?}, expected_ok={:?}, expected_err={:?}, actual={:?}",
                    case.name, case.input, case.expected_ok, case.expected_err, actual
                ));
            }
        }
    }

    if !failed.is_empty() {
        panic!(
            "{} golden case(s) failed:\n{}",
            failed.len(),
            failed.join("\n")
        );
    }
}

#[test]
fn fixture_has_invariants() {
    // 防 fixture 被意外搞坏：每条 case 必须 expected_ok / expected_err 二选一。
    let fixture: Fixture = serde_json::from_str(FIXTURE_JSON).expect("fixture parse");
    for case in &fixture.cases {
        let has_ok = case.expected_ok.is_some();
        let has_err = case.expected_err.is_some();
        assert!(
            has_ok ^ has_err,
            "case '{}' must have exactly one of expected_ok / expected_err",
            case.name
        );
    }
}
