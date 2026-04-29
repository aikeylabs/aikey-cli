//! End-to-end: actually `eval $(aikey activate ...)` in a bash subshell and
//! verify the shell-level side effects — env vars set/restored, prompt var
//! saved, nested activate semantics. This exercises the final user-facing
//! contract that unit tests only approximate.
//!
//! Run with `--test-threads=1` is not required: each test uses its own tmpdir
//! for HOME and has no shared global state (unlike the in-process tests that
//! mutate `std::env::set_var`).

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

fn make_tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "aikey-e2e-activate-eval-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("mkdir tmp");
    p
}

/// Add a key directly via the CLI so the vault is in a known state, then
/// return the temp HOME path the test should operate against.
fn setup_vault_with_key(tag: &str, alias: &str, provider: &str) -> PathBuf {
    let home = make_tmpdir(tag);
    let bin = bin_path();
    let vault = home.join(".aikey/data/vault.db");
    std::fs::create_dir_all(vault.parent().unwrap()).unwrap();

    let status = Command::new(&bin)
        .args(["add", alias, "--provider", provider])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("AK_VAULT_PATH", &vault)
        .env("AK_TEST_PASSWORD", "e2e-pw")
        .env("AK_TEST_SECRET", "sk-e2e-fake")
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn aikey add");
    assert!(status.success(), "aikey add failed for {}/{}", alias, provider);
    home
}

/// Run `script` in bash with the test environment. The script can reference
/// `$AIKEY` (path to the binary) and `$HOME` is set to the test tmpdir.
fn run_bash(home: &PathBuf, script: &str) -> (String, String, i32) {
    let bin = bin_path();
    let out = Command::new("bash")
        .args(["-c", script])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AK_VAULT_PATH", home.join(".aikey/data/vault.db"))
        .env("AK_TEST_PASSWORD", "e2e-pw")
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1")
        .env("AIKEY", &bin)
        .output()
        .expect("spawn bash");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

// ── core round-trip: activate sets env vars, deactivate unsets ──────────

#[test]
fn activate_eval_injects_provider_env_vars() {
    let home = setup_vault_with_key("inject", "my-claude", "anthropic");
    let (stdout, _stderr, code) = run_bash(
        &home,
        r#"
            # No API key set initially.
            : ${ANTHROPIC_API_KEY:=}

            # Run activate and eval its stdout — the only user-facing contract.
            eval "$("$AIKEY" activate my-claude --shell bash 2>/dev/null)"

            echo "API_KEY=${ANTHROPIC_API_KEY}"
            echo "BASE_URL=${ANTHROPIC_BASE_URL}"
            echo "LABEL=${AIKEY_ACTIVE_LABEL}"
        "#,
    );
    assert_eq!(code, 0, "bash script failed: {}", _stderr);
    // 2026-04-29 prefix rename: personal route_token form is now a 79-char
    // string (15-char prefix + 64 lowercase hex).
    assert!(stdout.contains("API_KEY=aikey_personal_"),
        "ANTHROPIC_API_KEY not injected or wrong prefix:\n{}", stdout);
    assert!(stdout.contains("BASE_URL=http://127.0.0.1:"),
        "ANTHROPIC_BASE_URL not injected:\n{}", stdout);
    assert!(stdout.contains("LABEL=my-claude"),
        "AIKEY_ACTIVE_LABEL not set:\n{}", stdout);
}

#[test]
fn deactivate_restores_user_preexisting_env_var() {
    // Pre-existing env var should survive activate→deactivate round-trip
    // (M5 from the 2026-04-17 activate review).
    let home = setup_vault_with_key("restore", "my-claude", "anthropic");
    let (stdout, _stderr, code) = run_bash(
        &home,
        r#"
            export ANTHROPIC_API_KEY="sk-user-owned-value"

            eval "$("$AIKEY" activate my-claude --shell bash 2>/dev/null)"
            AFTER_ACTIVATE="${ANTHROPIC_API_KEY}"

            eval "$("$AIKEY" deactivate --shell bash 2>/dev/null)"
            AFTER_DEACTIVATE="${ANTHROPIC_API_KEY}"

            echo "AFTER_ACTIVATE=${AFTER_ACTIVATE}"
            echo "AFTER_DEACTIVATE=${AFTER_DEACTIVATE}"
        "#,
    );
    assert_eq!(code, 0, "bash failed: {}", _stderr);
    // Activate should have REPLACED the user's value with the vault token.
    assert!(stdout.contains("AFTER_ACTIVATE=aikey_personal_"),
        "activate should replace with vault token, got:\n{}", stdout);
    // Deactivate should have RESTORED the user's original value.
    assert!(stdout.contains("AFTER_DEACTIVATE=sk-user-owned-value"),
        "deactivate should restore user's pre-activate value, got:\n{}", stdout);
}

#[test]
fn nested_activate_preserves_original_prompt_across_switches() {
    // Two consecutive activate calls shouldn't pollute the original PS1 save —
    // the second activate must see _AIKEY_ORIG_PS1 still holding the user's
    // original prompt (idempotent save via `[ -z "$_AIKEY_ORIG_PS1" ]`).
    let home = setup_vault_with_key("nested", "claude-a", "anthropic");
    // Second key shares anthropic so the second activate is valid.
    let status = Command::new(bin_path())
        .args(["add", "claude-b", "--provider", "anthropic"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("AK_VAULT_PATH", home.join(".aikey/data/vault.db"))
        .env("AK_TEST_PASSWORD", "e2e-pw")
        .env("AK_TEST_SECRET", "sk-e2e-fake-2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "add claude-b failed");

    let (stdout, stderr, code) = run_bash(
        &home,
        r#"
            PS1="my-original-prompt> "
            ORIG_PS1="$PS1"

            eval "$("$AIKEY" activate claude-a --shell bash 2>/dev/null)"
            PS1_AFTER_FIRST="$PS1"

            eval "$("$AIKEY" activate claude-b --shell bash 2>/dev/null)"
            PS1_AFTER_SECOND="$PS1"

            eval "$("$AIKEY" deactivate --shell bash 2>/dev/null)"
            PS1_AFTER_DEACT="$PS1"

            echo "ORIG=${ORIG_PS1}"
            echo "FIRST=${PS1_AFTER_FIRST}"
            echo "SECOND=${PS1_AFTER_SECOND}"
            echo "DEACT=${PS1_AFTER_DEACT}"
        "#,
    );
    assert_eq!(code, 0, "bash failed: {}", stderr);
    // Both activates should embed their label + the ORIGINAL prompt (not nest).
    assert!(stdout.contains("FIRST=(claude-a) my-original-prompt> "),
        "first activate should show label+original:\n{}", stdout);
    assert!(stdout.contains("SECOND=(claude-b) my-original-prompt> "),
        "second activate should replace label but keep SAME original (not nest):\n{}", stdout);
    // Deactivate should restore the pristine PS1 (no `(label)` prefix).
    assert!(stdout.contains("DEACT=my-original-prompt> "),
        "deactivate should restore pristine PS1:\n{}", stdout);
}

// ── stdout discipline: eval safety ──────────────────────────────────────

#[test]
fn activate_stdout_has_no_ansi_when_via_wrapper() {
    // H1 regression: when --shell is passed (wrapper mode), stdout must be
    // pure shell code so eval doesn't choke on escape sequences.
    let home = setup_vault_with_key("ansi", "key", "anthropic");
    let out = Command::new(bin_path())
        .args(["activate", "key", "--shell", "bash"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("AK_VAULT_PATH", home.join(".aikey/data/vault.db"))
        .env("AK_TEST_PASSWORD", "e2e-pw")
        .stdin(Stdio::null())
        .output()
        .expect("spawn activate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains('\x1b'),
        "stdout must not contain ANSI escapes (breaks eval):\n{:?}", stdout);
}

// ── error path: bad alias via eval exits non-zero ───────────────────────

#[test]
fn activate_unknown_alias_returns_nonzero_and_no_exports() {
    let home = setup_vault_with_key("bad", "real-key", "anthropic");
    let (stdout, stderr, code) = run_bash(
        &home,
        r#"
            set -e
            if "$AIKEY" activate nonexistent-key --shell bash > /tmp/_act_out 2> /tmp/_act_err; then
                echo "UNEXPECTED_SUCCESS"
                exit 0
            else
                echo "EXIT_CODE=$?"
                echo "STDOUT_BYTES=$(wc -c < /tmp/_act_out)"
            fi
        "#,
    );
    // The script always exits 0; non-zero bash exit means something else broke.
    assert_eq!(code, 0, "wrapper script failed: {}", stderr);
    assert!(!stdout.contains("UNEXPECTED_SUCCESS"),
        "activate with unknown alias should fail:\n{}", stdout);
    // stdout of the real activate call should be empty (no partial shell code).
    // `wc -c` on macOS pads with leading spaces, so match the numeric tail.
    let bytes_line = stdout.lines()
        .find(|l| l.starts_with("STDOUT_BYTES="))
        .expect("STDOUT_BYTES line missing");
    let count: usize = bytes_line
        .trim_start_matches("STDOUT_BYTES=")
        .trim()
        .parse()
        .expect("STDOUT_BYTES not a number");
    assert_eq!(count, 0,
        "failed activate must produce no stdout bytes (else eval would run partial state), got {} bytes",
        count);
}
