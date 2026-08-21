//! Fence for the `--json` stream contract (bugfix 2026-08-20
//! aikey-json-output-on-stderr): machine-readable JSON MUST land on STDOUT.
//!
//! WHY a real subprocess test and not a unit test: the defect was invisible at
//! the call sites (`json_output::success(...)` reads identically either way)
//! and only observable in how the PROCESS writes its streams. Two shipped
//! consumers were broken by it for months — ai-compliance-detector's
//! install_service.{sh,ps1} run `aikey app list --json 2>/dev/null | grep
//! <slug>` and always saw an empty stdout, so their "already registered" fast
//! path could never hit. This test reproduces exactly that shape: capture
//! stdout ONLY, and require parseable JSON in it.

use assert_cmd::cargo::cargo_bin;
use std::process::Command;

/// `--json` on a command that needs no vault: stdout carries the JSON,
/// stderr carries no JSON envelope of its own.
#[test]
fn json_mode_writes_payload_to_stdout_not_stderr() {
    // `aikey --json` with no subcommand takes the json_output::error path —
    // the same helper family every `--json` command exits through, and one
    // that needs neither a vault nor a running proxy.
    let out = Command::new(cargo_bin("aikey"))
        .arg("--json")
        .output()
        .expect("run aikey --json");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "--json payload must be parseable from STDOUT alone (a consumer that \
             discards stderr sees only this): {e}\nstdout={stdout}\nstderr={stderr}"
        )
    });
    assert_eq!(
        parsed.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "envelope shape changed: {parsed}"
    );

    // Anti-regression on the other half: the envelope must not ALSO be echoed
    // on stderr (double-emitting would break consumers that merge 2>&1 and
    // then parse, which is how the shipped SOP snippets read it).
    assert!(
        !stderr.contains("\"status\""),
        "the JSON envelope must not be duplicated on stderr; stderr={stderr}"
    );
}

/// The `_stderr` variants exist for `aikey run`, which hands stdout to the
/// child process. That distinction must stay real — it went inert once (both
/// families eprintln'd) and that is what produced the bug above.
#[test]
fn run_family_keeps_its_envelope_off_the_child_stdout_channel() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/json_output.rs"),
    )
    .expect("read json_output.rs");

    for helper in ["success_stderr", "error_stderr", "error_with_data_stderr"] {
        let body = src
            .split(&format!("pub fn {helper}"))
            .nth(1)
            .unwrap_or_else(|| panic!("{helper} not found — did the run-family helpers move?"));
        let body = body.split("\npub fn ").next().unwrap_or(body);
        assert!(
            body.contains("eprintln!"),
            "{helper} must write to stderr (aikey run gives stdout to the child)"
        );
        assert!(
            !body.contains("\n    println!"),
            "{helper} must NOT write to stdout"
        );
    }
}

/// One command, one envelope (bugfix 2026-08-20, second half): a FAILING
/// `--json` command must not print its own envelope AND then let the
/// top-level handler print a second one. Both now land on stdout, so a
/// consumer parsing stdout would hit "Extra data" and lose the real detail —
/// which is exactly how aikey-control's user-local service handler regressed
/// (its comment already records the same failure from the CombinedOutput era).
#[test]
fn failing_json_command_emits_exactly_one_envelope() {
    let out = Command::new(cargo_bin("aikey"))
        .args(["service", "status", "no-such-service", "--json"])
        .output()
        .expect("run aikey service status --json");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut de = serde_json::Deserializer::from_str(stdout.trim()).into_iter::<serde_json::Value>();
    let first = de
        .next()
        .unwrap_or_else(|| panic!("no JSON envelope on stdout; stdout={stdout}"))
        .unwrap_or_else(|e| panic!("first envelope unparseable: {e}\nstdout={stdout}"));
    assert_eq!(
        first.get("error").and_then(|v| v.as_str()),
        Some("UNKNOWN_SERVICE"),
        "wrong envelope: {first}"
    );
    assert!(
        de.next().is_none(),
        "a second envelope followed the first — consumers parsing stdout get \
         \"Extra data\" and lose the detail; stdout={stdout}"
    );
    assert!(
        !out.status.success(),
        "a failing command must exit non-zero"
    );
}
