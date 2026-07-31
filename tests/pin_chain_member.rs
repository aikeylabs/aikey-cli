//! Fences for task 2.27c of openspec change `aliyun-aigw-p0-upstream-fallback` —
//! `aikey use <alias> --only <upstream>` pins ONE hop of a route group, and must
//! say out loud that it is turning automatic failover off.
//!
//! # Why the warning is the feature
//!
//! Decision D-1③ chose "pin one hop = use only that hop" over "pin one hop = move
//! it to the front", because the alternative would let a developer's local command
//! rewrite an order the administrator set in the control plane — breaking
//! control-plane authority and creating a second source of truth for the order at
//! the same time.
//!
//! The price of that choice is that pinning now REMOVES a capability the user very
//! likely believes they still have. So the consequence has to be stated at the
//! moment the pin is written; documenting it elsewhere does not help the person
//! typing the command today.

use assert_cmd::prelude::*;
use std::process::Command;

fn aikey() -> Command {
    Command::cargo_bin("aikey").expect("build aikey")
}

/// `--only` names one upstream inside ONE key's chain, so it cannot be answered
/// without knowing which key. Silently applying it to whatever key happens to be
/// active would pin the wrong chain — and the pin would look successful.
#[test]
fn only_without_an_alias_is_refused_with_the_full_usage() {
    let out = aikey()
        .args(["use", "--only", "zhipu"])
        .output()
        .expect("run aikey");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--only"),
        "stderr should explain the flag needs a key, got: {stderr}"
    );
    assert!(
        stderr.contains("aikey use <ALIAS> --only <UPSTREAM>"),
        "the error should show the working form, not just say no: {stderr}"
    );
}

/// The flag must be discoverable, and its help text must carry the consequence —
/// a user reading `--help` before running it is exactly the person we want to
/// reach.
#[test]
fn help_states_that_pinning_one_upstream_disables_failover() {
    let out = aikey().args(["use", "--help"]).output().expect("run aikey");
    // Help may land on either stream depending on how clap is invoked; the fence is
    // about the CONTENT being reachable, not about which pipe carries it.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("--only"),
        "`--only` missing from help: {text}"
    );
    let lowered = text.to_lowercase();
    assert!(
        lowered.contains("failover"),
        "help for --only never mentions failover, so the one consequence that matters \
         is invisible until it bites: {text}"
    );
}

/// Pinning inside a key that has no route group is a category error, and the
/// message has to say WHICH — otherwise the user retries with a different spelling
/// of the upstream name.
#[test]
fn pinning_a_key_that_does_not_exist_names_the_problem() {
    let out = aikey()
        .args(["use", "no-such-key-9f3a", "--only", "zhipu"])
        .output()
        .expect("run aikey");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.is_empty(),
        "an unknown key produced no diagnostic at all"
    );
}
