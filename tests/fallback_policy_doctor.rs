//! Fences for task 1b.10 of openspec change `aliyun-aigw-p0-upstream-fallback` —
//! `aikey doctor` must say WHERE each of the five upstream-fallback thresholds
//! came from, and how long ago the policy was last pulled.
//!
//! The value alone is not an answer. All five thresholds are org-configurable and
//! all five have a builtin default, so "5 minutes because the admin set it" and
//! "5 minutes because nobody ever touched it" render identically. The source
//! column is the entire diagnostic content of this check; these fences pin it,
//! plus the three states that are unreachable without a live proxy sitting in
//! each of them.

use aikeylabs_aikey_cli::commands_project::fallback_policy_report;
use serde_json::json;

fn status(synced: bool, rail: Option<serde_json::Value>, attempt_source: &str) -> serde_json::Value {
    let mut v = json!({
        "upstream_fallback": {
            "synced": synced,
            "version": 7,
            "last_success_at": 1_700_000_000i64,
            "thresholds": {
                "upstream_attempt_timeout_ms": {"value": 5000, "source": attempt_source},
                "chain_total_budget_ms": {"value": 180000, "source": "builtin"},
                "binding_cooldown_ms": {"value": 300000, "source": "builtin"},
                "idle_gap_ms": {"value": 300000, "source": "builtin"},
                "max_stickiness_ms": {"value": 1800000, "source": "builtin"}
            }
        }
    });
    if let Some(r) = rail {
        v["control_plane_sync"] = json!({ "fallback_policy": r });
    }
    v
}

/// The headline requirement: every row carries its source, and the summary says
/// how stale the policy is.
#[test]
fn every_row_carries_its_source_and_the_summary_carries_freshness() {
    let s = status(
        true,
        Some(json!({"state": "ok", "consecutive_failures": 0})),
        "org",
    );
    let r = fallback_policy_report(Some(&s), 1_700_000_008);

    assert!(r.ok, "a healthy rail with a synced policy must not be a failure");
    assert!(
        r.detail.contains("synced 8s ago (v7)"),
        "summary lost the freshness: {}. Without it an operator cannot tell a policy \
         pulled seconds ago from one pulled before the last config change",
        r.detail
    );
    assert!(
        r.detail.contains("builtin 4") && r.detail.contains("org 1"),
        "summary lost the source census: {}",
        r.detail
    );

    assert_eq!(r.rows.len(), 5, "all five thresholds must be listed");
    let attempt = r
        .rows
        .iter()
        .find(|(l, _)| l == "attempt timeout")
        .expect("attempt timeout row missing");
    assert!(
        attempt.1.contains("5000 ms") && attempt.1.contains("(org)"),
        "attempt timeout row = {:?}. Dropping `(org)` is the whole failure this check \
         exists to prevent: the admin's 5s and a builtin 5s would read identically",
        attempt.1
    );
    // Overall limit before per-attempt limit — the operator's first question is
    // "how long in total", so it is answered first.
    assert_eq!(r.rows[0].0, "chain budget");
    assert_eq!(r.rows[1].0, "attempt timeout");
}

/// 🔴 A poll failure is not an outage. The row must report the problem AND say the
/// data plane is still enforcing the last known values — otherwise an operator
/// reads "offline" and restarts things that are working.
#[test]
fn stale_rail_fails_the_check_but_says_the_data_plane_is_fine() {
    let s = status(
        true,
        Some(json!({"state": "stale", "consecutive_failures": 4})),
        "org",
    );
    let r = fallback_policy_report(Some(&s), 1_700_000_100);

    assert!(!r.ok, "a stale rail must surface as a failed check");
    let hint = r.hint.expect("a failing row must carry a hint");
    assert!(
        hint.contains("4 consecutive failures"),
        "hint should quote the failure count: {hint}"
    );
    assert!(
        hint.contains("NOT degraded"),
        "hint = {hint}\nIt must state that the data plane still enforces the last known \
         values (task 1b.4). Reporting only the failure invites a restart of a system \
         that is serving correctly."
    );
}

/// 🔴 The Personal shape: no control plane, so nothing to sync with. That is the
/// correct resting state, not a fault — and it is detected from the rail's ABSENCE,
/// never from an edition branch.
#[test]
fn never_synced_without_a_rail_is_not_a_failure() {
    let s = status(false, None, "builtin");
    let r = fallback_policy_report(Some(&s), 1_700_000_100);

    assert!(
        r.ok,
        "a host with no control plane was reported as broken. It has nothing to \
         sync with; every threshold resolves to its builtin default through the \
         same code path every other edition uses"
    );
    assert!(
        r.detail.contains("never synced") && r.detail.contains("rail not started"),
        "detail = {}, want it to state plainly that no policy was ever pulled",
        r.detail
    );
}

/// The opposite shape, which IS a fault: a rail is running, so the proxy is asking
/// — and it has never been answered. The thresholds in force are not the ones in
/// the console.
#[test]
fn never_synced_with_a_running_rail_is_a_failure() {
    let s = status(
        false,
        Some(json!({"state": "init", "consecutive_failures": 2})),
        "builtin",
    );
    let r = fallback_policy_report(Some(&s), 1_700_000_100);

    assert!(
        !r.ok,
        "the proxy is polling a control plane that has never answered, so the numbers \
         in force are not the ones the admin configured. Reporting that as healthy \
         hides exactly the case this check was added for"
    );
}

/// Absence must be reported as absence. Printing defaults for a build that does not
/// report the block would invent five numbers nothing is enforcing — the same
/// failure the source column exists to prevent, committed by the tool meant to
/// detect it.
#[test]
fn missing_block_is_reported_not_invented() {
    let r = fallback_policy_report(Some(&json!({"version": "x"})), 1_700_000_100);
    assert!(r.ok);
    assert!(r.rows.is_empty(), "no block means no numbers to show: {:?}", r.rows);
    assert!(r.detail.contains("not reported"), "detail = {}", r.detail);
}
