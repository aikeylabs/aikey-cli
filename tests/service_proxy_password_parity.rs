//! Fence: `aikey service {start,restart} proxy` must resolve the vault
//! master password the same way `aikey proxy start` does.
//!
//! ## Why this file exists
//!
//! There are two code paths that start the proxy, and they disagreed.
//!
//! `commands_proxy.rs` learned in 2026-06-11 (bug
//! `20260611-proxy-service-no-unattended-password`) that launchd/systemd run
//! it at login and on crash-restart with no terminal attached, so it tries the
//! session cache before giving up. `commands_service/commands.rs` never got
//! that treatment: it calls the interactive prompt helper unconditionally, so
//! with no TTY it fails every time — after first printing a password prompt
//! that nobody can answer.
//!
//! That divergence is invisible from a terminal (both work when you can type)
//! and total from anywhere else. The AiKey tray calls the second path, which
//! is why "restart proxy" from the tray could never succeed.
//!
//! ## What is fenced
//!
//! Not the exact wording — that would freeze the copy. What is fenced is the
//! observable contract a non-interactive caller depends on:
//!
//!   1. No path may print a password PROMPT when there is no terminal to
//!      answer it.
//!   2. When no password can be resolved, the error must say what to do about
//!      it, in the same terms both paths already use.
//!
//! ## Isolation
//!
//! Every case runs with `env_clear()`, a throwaway HOME, and stdin closed.
//! The session-cache backend picks "file" automatically when stdin is not a
//! TTY (`session::maybe_configure_backend`), so these tests can never read or
//! write the developer's real OS keychain.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

struct Sandbox {
    home: PathBuf,
    _dir: tempfile::TempDir,
}

fn sandbox() -> Sandbox {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().to_path_buf();
    // Bootstrap a vault so the commands under test get past "no vault" and
    // reach the password-resolution branch we actually care about.
    let status = Command::new(bin_path())
        .args(["add", "fence-probe", "--provider", "anthropic"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("AK_VAULT_PATH", home.join(".aikey/data/vault.db"))
        .env("AK_TEST_PASSWORD", "fence-pw")
        .env("AK_TEST_SECRET", "sk-fence-fake")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn aikey add");
    assert!(status.success(), "could not bootstrap the sandbox vault");
    Sandbox { home, _dir: dir }
}

/// Run a command with NO terminal and NO password available anywhere.
fn run_without_password(sb: &Sandbox, args: &[&str]) -> String {
    let out = Command::new(bin_path())
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &sb.home)
        .env("AK_VAULT_PATH", sb.home.join(".aikey/data/vault.db"))
        .env("NO_COLOR", "1")
        // Deliberately NOT set: AK_TEST_PASSWORD / AIKEY_MASTER_PASSWORD.
        // Setting either would make both paths succeed through the env branch
        // and hide the very divergence this file exists to catch.
        .stdin(Stdio::null())
        .output()
        .expect("spawn aikey");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The reference behaviour, already correct today. Kept as a control: without
/// it, a change that broke BOTH paths identically would still pass the parity
/// assertion below.
#[test]
fn proxy_start_reports_actionably_without_a_terminal() {
    let sb = sandbox();
    let out = run_without_password(&sb, &["proxy", "start"]);

    assert!(
        !out.contains("Enter Master Password"),
        "`aikey proxy start` printed a password prompt with no terminal attached:\n{out}"
    );
    assert!(
        out.contains("AIKEY_MASTER_PASSWORD") || out.contains("session cache"),
        "`aikey proxy start` must say how to supply a password:\n{out}"
    );
}

/// 🔴 The regression. Fails before the fix.
#[test]
fn service_start_proxy_does_not_prompt_without_a_terminal() {
    let sb = sandbox();
    let out = run_without_password(&sb, &["service", "start", "proxy"]);

    assert!(
        !out.contains("Enter Master Password"),
        "`aikey service start proxy` printed a password prompt with no terminal to answer it. \
         A non-interactive caller (the tray, launchd, a script) can only ever see this and fail:\n{out}"
    );
}

/// 🔴 The regression, restart variant — this is the one the tray calls.
#[test]
fn service_restart_proxy_does_not_prompt_without_a_terminal() {
    let sb = sandbox();
    let out = run_without_password(&sb, &["service", "restart", "proxy"]);

    assert!(
        !out.contains("Enter Master Password"),
        "`aikey service restart proxy` printed a password prompt with no terminal. \
         This is the exact call the AiKey tray makes when the user clicks Restart:\n{out}"
    );
}

/// Failing is fine; failing uselessly is not. Whatever the message ends up
/// being, it must tell a non-interactive caller how to proceed — the same
/// standard `aikey proxy start` already meets.
#[test]
fn service_restart_proxy_failure_is_actionable() {
    let sb = sandbox();
    let out = run_without_password(&sb, &["service", "restart", "proxy"]);

    assert!(
        out.contains("AIKEY_MASTER_PASSWORD") || out.contains("session cache"),
        "`aikey service restart proxy` must explain how to supply a password when it cannot \
         resolve one, instead of demanding a terminal that does not exist:\n{out}"
    );
}

/// Both paths answer the same question, so a caller must not have to know
/// which one it invoked. Compares behaviour class, not wording.
#[test]
fn both_paths_agree_on_the_no_password_outcome() {
    let sb = sandbox();
    let via_proxy = run_without_password(&sb, &["proxy", "start"]);
    let via_service = run_without_password(&sb, &["service", "restart", "proxy"]);

    let prompted = |s: &str| s.contains("Enter Master Password");
    assert_eq!(
        prompted(&via_proxy),
        prompted(&via_service),
        "the two proxy-start paths disagree about whether to prompt with no terminal.\n\
         `aikey proxy start`:\n{via_proxy}\n\
         `aikey service restart proxy`:\n{via_service}"
    );
}
