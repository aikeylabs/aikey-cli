//! Fences for bugfix 2026-07-28 — `aikey doctor` must not report an account it
//! never probed as a broken egress.
//!
//! Background: the proxy's `/admin/egress/selfcheck?dial=1` used to dial every
//! account SERIALLY, so its wall clock scaled with the account count and a
//! broken account (which burns the full dial timeout) made it worse. It now
//! bounds itself and reports accounts it could not reach in time as
//! `dialed=false, ok=false` + a reason.
//!
//! That new row shape is only safe if every CONSUMER distinguishes it from a
//! failed dial. In `aikey doctor` the verdict `ok_count == 0` would have turned
//! "we probed nothing" into "all egress paths are unreachable" plus a non-zero
//! exit code — telling the user to fix accounts that were never tested. These
//! fences pin the distinction at the verdict boundary.

use aikeylabs_aikey_cli::commands_proxy::{
    egress_all_probed_failed, egress_path_was_probed, EgressCheck,
};

fn row(label: &str, dialed: bool, ok: bool) -> EgressCheck {
    EgressCheck {
        label: label.to_string(),
        dialed,
        ok,
        engine: if ok { "mihomo".into() } else { String::new() },
        exit_ip: if ok {
            "69.5.53.60".into()
        } else {
            String::new()
        },
        latency_ms: if ok { 880 } else { 0 },
        reason: if !dialed && !ok {
            "not probed: the node's egress self-check budget (15s) was exhausted".into()
        } else if !ok {
            "egress unreachable via mihomo: rejected username/password".into()
        } else {
            String::new()
        },
    }
}

#[test]
fn budget_cutoff_row_is_not_a_probe() {
    assert!(
        !egress_path_was_probed(&row("cut-off@example.com", false, false)),
        "a dialed=false row is a budget cutoff, not a probe result"
    );
    assert!(egress_path_was_probed(&row("good@example.com", true, true)));
    assert!(
        egress_path_was_probed(&row("bad@example.com", true, false)),
        "a dialed-and-failed row IS a probe result and must keep counting as one"
    );
}

/// 🔴 THE fence. 能红: revert the verdict to `ok_count == 0` (drop the
/// non-empty-probed guard) and this fails.
#[test]
fn all_unprobed_is_not_a_failure_verdict() {
    let paths = vec![
        row("a@example.com", false, false),
        row("b@example.com", false, false),
    ];
    assert!(
        !egress_all_probed_failed(&paths),
        "nothing was probed, so `aikey doctor` must NOT claim all egress paths are unreachable \
         (that exits non-zero and sends the user to fix untested accounts)"
    );
}

#[test]
fn all_probed_and_failed_is_still_a_failure_verdict() {
    // The real staging shape before the egress fix: every account dialed, every
    // one rejected. This MUST stay a failure — the guard added for cutoffs must
    // not weaken the genuine all-broken signal (失败要显眼).
    let paths = vec![
        row("a@example.com", true, false),
        row("b@example.com", true, false),
    ];
    assert!(egress_all_probed_failed(&paths));
}

#[test]
fn one_healthy_account_clears_the_verdict() {
    let paths = vec![
        row("broken@example.com", true, false),
        row("healthy@example.com", true, true),
        row("cut-off@example.com", false, false),
    ];
    assert!(
        !egress_all_probed_failed(&paths),
        "at least one path exits fine, so this is not an all-failed node"
    );
}

/// A mix of failures and cutoffs with ZERO successes is still a genuine failure
/// verdict: the accounts we did test all failed. The cutoff rows neither create
/// nor suppress the verdict.
#[test]
fn cutoffs_do_not_suppress_a_real_failure_verdict() {
    let paths = vec![
        row("cut-off@example.com", false, false),
        row("broken@example.com", true, false),
    ];
    assert!(egress_all_probed_failed(&paths));
}

#[test]
fn empty_list_has_no_verdict() {
    assert!(
        !egress_all_probed_failed(&[]),
        "no per-account egress configured (the Personal case) is not a failure"
    );
}
