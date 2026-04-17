//! Smoke tests for the status/introspection commands that every user touches:
//! `aikey status`, `aikey whoami`, `aikey doctor`, `aikey version`.
//!
//! Goal: catch regressions where one of these would panic, require a vault
//! that isn't there, or silently return nothing. We don't assert full output
//! formatting (that would be too brittle) — just key section anchors and
//! exit codes.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

/// Build a Command in a throwaway HOME with an empty vault path. No AK_TEST
/// secret is set — commands that only query state must work without one.
fn cmd_in_tmp(tag: &str) -> Command {
    let home = std::env::temp_dir().join(format!(
        "aikey-e2e-smoke-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("mkdir tmp");
    let vault = home.join(".aikey/data/vault.db");
    std::fs::create_dir_all(vault.parent().unwrap()).unwrap();

    let mut c = Command::new(bin_path());
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("AK_VAULT_PATH", &vault)
        .env("AK_TEST_PASSWORD", "smoke-pw")
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

// ── version ─────────────────────────────────────────────────────────────

#[test]
fn version_prints_semver_style_version() {
    let out = Command::new(bin_path())
        .arg("version")
        .output()
        .expect("run version");
    assert!(out.status.success(), "version exited non-zero: {:?}", out);
    // `aikey version` prints to stderr so a shell alias like
    // `aikey version | grep ...` doesn't silently pollute stdout consumers.
    let output = String::from_utf8_lossy(&out.stderr);
    assert!(output.contains("Version:"),
        "version output missing 'Version:' line:\n{}", output);
    assert!(
        output.split_whitespace().any(|tok| {
            let base = tok.split('-').next().unwrap_or("");
            base.split('.').count() >= 3
                && base.split('.').all(|p| p.chars().any(|c| c.is_ascii_digit()))
        }),
        "version output didn't contain a numeric semver:\n{}",
        output
    );
}

#[test]
fn version_json_has_expected_keys() {
    let out = Command::new(bin_path())
        .args(["version", "--json"])
        .output()
        .expect("run version --json");
    assert!(out.status.success());
    // `version --json` currently emits to stderr (matches the non-json form).
    // If that moves to stdout in the future, check both rather than hard-coding.
    let blob = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Strip any non-JSON preamble so the test tolerates future debug prints.
    let start = blob.find('{').expect("no `{` in version --json output");
    let end = blob.rfind('}').expect("no `}` in version --json output");
    let json_slice = &blob[start..=end];
    let v: serde_json::Value = serde_json::from_str(json_slice)
        .unwrap_or_else(|e| panic!("version --json not valid JSON: {}\n--- raw ---\n{}", e, blob));
    for key in &["version", "revision", "build_time"] {
        assert!(v.get(key).is_some(), "missing key '{}' in version JSON: {}", key, json_slice);
    }
}

// ── status ──────────────────────────────────────────────────────────────

#[test]
fn status_on_clean_env_shows_gateway_and_login_sections() {
    let out = cmd_in_tmp("status-clean").arg("status").output().expect("run status");
    // Exit code may be 0 or non-zero depending on health; we care about the
    // output shape being stable. At minimum the command must not panic.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(combined.contains("Gateway") || combined.contains("gateway"),
        "status output missing Gateway section:\n{}", combined);
    assert!(combined.contains("Login") || combined.contains("login"),
        "status output missing Login section:\n{}", combined);
}

// ── whoami ──────────────────────────────────────────────────────────────

#[test]
fn whoami_on_clean_env_reports_not_logged_in() {
    let out = cmd_in_tmp("whoami-clean").arg("whoami").output().expect("run whoami");
    // whoami on empty state should succeed and hint how to proceed.
    assert!(out.status.success(), "whoami should succeed on clean env, got:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(combined.contains("not logged in") || combined.contains("Account:"),
        "whoami output should show login status:\n{}", combined);
    assert!(combined.contains("aikey login"),
        "whoami should hint `aikey login`:\n{}", combined);
}

// ── doctor ──────────────────────────────────────────────────────────────

#[test]
fn doctor_runs_and_reports_check_lines() {
    let out = cmd_in_tmp("doctor").arg("doctor").output().expect("run doctor");
    // Doctor may exit non-zero when the environment is unhealthy (expected
    // on a clean tmpdir without a proxy). We only require that it runs to
    // completion and emits recognisable check output.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("cli version") || combined.contains("CLI"),
        "doctor output missing 'cli version' line:\n{}", combined
    );
    assert!(
        combined.contains("vault") || combined.contains("Vault"),
        "doctor output missing vault check:\n{}", combined
    );
    assert!(
        combined.contains("proxy") || combined.contains("Proxy"),
        "doctor output missing proxy check:\n{}", combined
    );
}

// ── help discovery: every top-level command has --help ──────────────────

#[test]
fn help_lists_core_user_commands() {
    let out = Command::new(bin_path())
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(out.status.success());
    // --help still embeds ANSI `[1m...[0m` bold tags around command names even
    // with NO_COLOR set. Strip ANSI escape sequences before substring matching.
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    let stripped = strip_ansi(&raw);
    for cmd in &["add", "list", "use", "route", "activate", "deactivate",
                 "doctor", "status", "whoami", "proxy", "run"] {
        // Commands appear in the form "  <cmd> " or "  <cmd>\n" in --help.
        let found = stripped.contains(&format!("  {} ", cmd))
            || stripped.contains(&format!("  {}\n", cmd));
        assert!(found,
            "--help missing documented command '{}':\n{}", cmd, stripped);
    }
}

/// Strip ANSI CSI escape sequences so `--help` command names match regardless
/// of `--color=always` or the binary's embedded bold tags.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            // CSI sequences end on an alpha (letter) terminator.
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        out.push(c);
    }
    out
}
