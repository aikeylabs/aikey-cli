//! End-to-end tests for `aikey run` — the command users wrap their tools
//! with to pick up aikey-managed env vars.
//!
//! Replaces the three `test_json_run_*` tests that were deleted on 2026-04-17
//! for targeting a pre-Stage-2 contract (project-level `requiredVars` / env
//! mapping). The current contract resolves provider bindings → injects
//! `<PROVIDER>_API_KEY` + `<PROVIDER>_BASE_URL` env vars → spawns the child.
//!
//! ## Design notes
//!
//! - The local proxy auto-start is best-effort and fails in these tests
//!   (there's no `aikey-proxy.yaml` in the tmp HOME). That's fine: the child
//!   process still gets the env vars, we just don't exercise the HTTP path.
//! - `aikey run` without `--direct` injects SENTINEL tokens (e.g.
//!   `aikey_active_<provider>` post-2026-04-29 prefix rename) that the
//!   proxy resolves to real keys via tier-3 fallthrough.
//!   `--direct` bypasses the proxy and injects the real decrypted key.
//! - `--provider <code>` requires a project-level `aikey.config.json` with
//!   `providers.<code>.keyAlias` — that path has its own project-config
//!   tests in `project_command_test.rs` and isn't exercised here.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

struct Env {
    tmp: PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        if std::env::var("AIKEY_E2E_KEEP_TMPDIR").as_deref() != Ok("1") {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }
}

impl Env {
    fn new(tag: &str) -> Self {
        let tmp = std::env::temp_dir()
            .join(format!("aikey-e2e-run-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".aikey/data")).expect("mkdir");
        Self { tmp }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(bin_path());
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.tmp)
            .env("AK_VAULT_PATH", self.tmp.join(".aikey/data/vault.db"))
            .env("AK_TEST_PASSWORD", "run-pw")
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// Add a personal key for a given provider. Secret is a known test string
    /// so `--direct` tests can assert the real value survives.
    fn add_key(&self, alias: &str, provider: &str, secret: &str) {
        let out = self
            .cmd()
            .args(["add", alias, "--provider", provider])
            .env("AK_TEST_SECRET", secret)
            .output()
            .expect("spawn add");
        assert!(out.status.success(),
            "add {}/{} failed: {}", alias, provider,
            String::from_utf8_lossy(&out.stderr));
    }
}

/// Pull a specific `NAME=VALUE` line out of `env`/`printenv` child stdout.
fn env_value(stdout: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    stdout.lines()
        .find(|l| l.starts_with(&prefix))
        .map(|l| l[prefix.len()..].to_string())
}

// ── baseline: run -- env injects the expected vars ──────────────────────

#[test]
fn run_injects_provider_env_vars_from_binding() {
    let env = Env::new("basic");
    env.add_key("my-anthropic", "anthropic", "sk-ant-real-value");

    let out = env.cmd().args(["run", "--", "env"]).output().expect("spawn run env");
    assert!(out.status.success(),
        "aikey run -- env should succeed with one binding; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let api_key = env_value(&stdout, "ANTHROPIC_API_KEY")
        .expect("ANTHROPIC_API_KEY must be injected for a bound anthropic key");
    let base_url = env_value(&stdout, "ANTHROPIC_BASE_URL")
        .expect("ANTHROPIC_BASE_URL must be injected (non-openai providers keep their base URL)");

    // 2026-04-29 prefix rename: per-provider active sentinel (was
    // `aikey_personal_<alias>`, now `aikey_active_<provider>` — alias-
    // independent). Proxy's tier-3 fallthrough resolves via URL path.
    assert_eq!(api_key, "aikey_active_anthropic",
        "expected per-provider active sentinel token, got {}", api_key);
    assert_ne!(api_key, "sk-ant-real-value",
        "real secret must NOT leak into child process without --direct");

    // Base URL points at the local proxy.
    assert!(base_url.starts_with("http://127.0.0.1:"),
        "ANTHROPIC_BASE_URL should point at local proxy, got {}", base_url);
    assert!(base_url.ends_with("/anthropic"),
        "ANTHROPIC_BASE_URL path should be /anthropic, got {}", base_url);
}

#[test]
fn run_injects_openai_env_vars() {
    // NOTE: `profile_activation.rs:51-61` skips `OPENAI_BASE_URL` when it
    // writes to `~/.aikey/active.env` (the shell-hook path used by
    // `aikey use`), because Codex v0.118+ warns when both that env var AND
    // its own ~/.codex/config.toml set the base URL. `aikey run` uses a
    // different injection path that does NOT apply that skip — so under
    // `run` we still see OPENAI_BASE_URL. This test pins the current
    // behaviour so if the two code paths ever converge, the divergence is
    // visible rather than silent.
    let env = Env::new("openai");
    env.add_key("my-openai", "openai", "sk-openai-fake");

    let out = env.cmd().args(["run", "--", "env"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(env_value(&stdout, "OPENAI_API_KEY").is_some(),
        "OPENAI_API_KEY must be injected for a bound openai key");
    // Current `aikey run` behaviour: BASE_URL is injected. This contrasts
    // with `aikey use` → active.env, which omits it.
    assert!(env_value(&stdout, "OPENAI_BASE_URL").is_some(),
        "`aikey run` injects OPENAI_BASE_URL (unlike aikey use's active.env \
         which skips it for Codex compat); got:\n{}", stdout);
}

#[test]
fn run_multi_provider_injects_all_bound_keys() {
    let env = Env::new("multi");
    env.add_key("my-claude", "anthropic", "sk-ant");
    env.add_key("my-gpt", "openai", "sk-openai");

    let out = env.cmd().args(["run", "--", "env"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(env_value(&stdout, "ANTHROPIC_API_KEY").is_some(),
        "anthropic key missing from multi-provider run");
    assert!(env_value(&stdout, "OPENAI_API_KEY").is_some(),
        "openai key missing from multi-provider run");
}

// ── exit code propagation ──────────────────────────────────────────────

#[test]
fn run_propagates_child_exit_code() {
    let env = Env::new("exit");
    env.add_key("k", "anthropic", "sk");

    let out = env.cmd()
        .args(["run", "--", "sh", "-c", "exit 42"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(42),
        "aikey run must propagate the child's exit code, got {:?}", out.status);
}

#[test]
fn run_success_exit_code_is_zero() {
    let env = Env::new("exit-0");
    env.add_key("k", "anthropic", "sk");

    let out = env.cmd().args(["run", "--", "true"]).output().unwrap();
    assert!(out.status.success(), "aikey run -- true should exit 0");
}

// ── JSON mode ──────────────────────────────────────────────────────────

#[test]
fn run_json_success_reports_injected_count_and_exit_code() {
    let env = Env::new("json-ok");
    env.add_key("k", "anthropic", "sk");

    let out = env.cmd()
        .args(["run", "--json", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // `--json` is emitted on stderr (stdout is reserved for child output).
    let stderr = String::from_utf8_lossy(&out.stderr);
    let start = stderr.find('{').expect("run --json must contain JSON on stderr");
    let end = stderr.rfind('}').expect("run --json JSON unbalanced");
    let v: serde_json::Value = serde_json::from_str(&stderr[start..=end])
        .unwrap_or_else(|e| panic!("invalid JSON: {}\n--- stderr ---\n{}", e, stderr));

    assert_eq!(v["status"], "success");
    assert_eq!(v["exit_code"], 0);
    let injected = v["secrets_injected"].as_i64()
        .expect("secrets_injected must be an integer");
    // At minimum ANTHROPIC_API_KEY + ANTHROPIC_BASE_URL.
    assert!(injected >= 2,
        "should inject >= 2 env vars for one anthropic binding, got {}", injected);

    // NOTE on stdout routing under --json: `aikey run --json` captures the
    // child's stdout silently (the assumption is that scripts parsing the
    // JSON don't also care about the child's human output). We don't assert
    // on child stdout here because the current contract intentionally
    // suppresses it. If that changes, add the assertion back.
}

#[test]
fn run_json_failure_reports_nonzero_exit_code() {
    let env = Env::new("json-fail");
    env.add_key("k", "anthropic", "sk");

    let out = env.cmd()
        .args(["run", "--json", "--", "sh", "-c", "exit 7"])
        .output()
        .unwrap();
    // aikey's own exit status should mirror the child's.
    assert_eq!(out.status.code(), Some(7));

    let stderr = String::from_utf8_lossy(&out.stderr);
    let start = stderr.find('{').expect("JSON missing");
    let end = stderr.rfind('}').unwrap();
    let v: serde_json::Value = serde_json::from_str(&stderr[start..=end]).unwrap();

    assert_eq!(v["status"], "error");
    assert_eq!(v["exit_code"], 7);
}

// ── --direct: real secret injected ─────────────────────────────────────

#[test]
fn run_direct_injects_real_decrypted_secret() {
    // --direct bypasses the proxy sentinel and injects the real key. This
    // is the "escape hatch" path users take when they need to talk to the
    // real provider for verification (documented in `aikey run --help`).
    let env = Env::new("direct");
    env.add_key("my-claude", "anthropic", "sk-ant-real-value");

    let out = env.cmd()
        .args(["run", "--direct", "--", "env"])
        .output()
        .unwrap();
    assert!(out.status.success(),
        "aikey run --direct should succeed; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let api_key = env_value(&stdout, "ANTHROPIC_API_KEY")
        .expect("ANTHROPIC_API_KEY missing under --direct");
    assert_eq!(api_key, "sk-ant-real-value",
        "--direct must inject the REAL decrypted secret, not a sentinel; got {}",
        api_key);
    // The sentinel prefix MUST NOT appear under --direct.
    // Post-2026-04-29 prefix rename: sentinel is `aikey_active_<provider>`.
    assert!(!api_key.starts_with("aikey_active_"),
        "--direct must not leave a proxy sentinel in env: {}", api_key);
}

// ── error paths ────────────────────────────────────────────────────────

#[test]
fn run_on_empty_vault_falls_back_to_legacy_injection() {
    // A vault that exists but has no keys currently triggers a "legacy
    // active_key_config fallback" that injects sentinel tokens for all
    // known providers and still spawns the child. Document that behavior —
    // if we ever want to turn it into a hard error, this test will fail
    // and force a deliberate decision.
    let env = Env::new("empty-fallback");
    env.add_key("__boot__", "anthropic", "sk");
    env.cmd().args(["delete", "__boot__"]).output().unwrap();

    let out = env.cmd().args(["run", "--", "echo", "x"]).output().unwrap();
    assert!(out.status.success(),
        "aikey run on empty vault currently falls back to legacy injection \
         and still runs the child — if this changes to an error, update the \
         test comment and adjust the assertion.\nstderr: {}",
        String::from_utf8_lossy(&out.stderr));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("legacy") || stderr.contains("Injecting"),
        "fallback path should mention 'legacy' or 'Injecting', got:\n{}", stderr);

    // Child still produced its output on stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains('x'),
        "child stdout must still be forwarded, got: {:?}", stdout);
}

#[test]
fn run_injects_nothing_for_unknown_provider_filter() {
    // --provider <unknown-code> exercises a distinct error path that must
    // not fall through to a partial env injection.
    let env = Env::new("bad-provider");
    env.add_key("k", "anthropic", "sk");

    let out = env.cmd()
        .args(["run", "--provider", "totally-fake-provider", "--", "env"])
        .output()
        .unwrap();
    assert!(!out.status.success(),
        "run with unknown --provider should fail; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr));
}
