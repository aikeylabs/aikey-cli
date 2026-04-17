//! End-to-end test: `aikey route` and `aikey activate` must emit the same
//! `base_url` for the same key across all providers.
//!
//! This is the integration-level regression test for L5 (2026-04-17): before
//! the unification, `route` used `canonical_provider` and emitted `/kimi` for
//! Kimi keys while `activate` used `provider_proxy_prefix` and emitted
//! `/kimi/v1`. Users copying config from different commands hit different
//! upstream behavior. This test exercises both code paths through the binary
//! and compares their output strings.
//!
//! ## Test materials
//!
//! Everything happens in a per-test `tempdir` used as `$HOME`. The master
//! password and API key are deterministic test constants — no real credentials
//! are exercised by this test.
//!
//! Override knobs (optional, load from `tests/.env`):
//!   AIKEY_E2E_PASSWORD      — master password for the test vault (default: `e2e-test-pw`)
//!   AIKEY_E2E_API_KEY       — dummy provider API key to add (default: `sk-e2e-fake`)
//!   AIKEY_E2E_KEEP_TMPDIR   — set to `1` to keep the tmpdir after test (default: cleanup)
//!
//! See `tests/.env.example` for the template. Real `.env` is git-ignored.

use std::path::PathBuf;
use std::process::{Command, Stdio};

// ── .env loading (minimal, no crate dep) ────────────────────────────────

fn load_dotenv() {
    let candidates = [
        PathBuf::from("tests/.env"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/.env"),
    ];
    for p in &candidates {
        if let Ok(content) = std::fs::read_to_string(p) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim().trim_matches('"').trim_matches('\'');
                    if std::env::var(k).is_err() {
                        std::env::set_var(k, v);
                    }
                }
            }
            return;
        }
    }
}

fn test_password() -> String {
    std::env::var("AIKEY_E2E_PASSWORD").unwrap_or_else(|_| "e2e-test-pw".into())
}

fn test_api_key() -> String {
    std::env::var("AIKEY_E2E_API_KEY").unwrap_or_else(|_| "sk-e2e-fake".into())
}

fn keep_tmpdir() -> bool {
    matches!(std::env::var("AIKEY_E2E_KEEP_TMPDIR").as_deref(), Ok("1") | Ok("true"))
}

// ── env-isolated CLI harness ────────────────────────────────────────────

/// A self-contained aikey environment with its own HOME, vault path, and logs.
/// Drop this to clean up the tmpdir (unless `AIKEY_E2E_KEEP_TMPDIR=1`).
struct TestEnv {
    tmp: PathBuf,
    bin: PathBuf,
    password: String,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if keep_tmpdir() {
            eprintln!("[e2e] keeping tmpdir at: {}", self.tmp.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }
}

impl TestEnv {
    fn new(test_name: &str) -> Self {
        load_dotenv();
        let bin = PathBuf::from(env!("CARGO_BIN_EXE_aikey"));
        let tmp = std::env::temp_dir().join(format!(
            "aikey-e2e-{}-{}",
            test_name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create tmpdir");
        Self { tmp, bin, password: test_password() }
    }

    /// Build a Command with env isolation. Every call gets fresh env vars so
    /// tests don't leak state between invocations.
    fn cmd(&self) -> Command {
        let vault_path = self.tmp.join("vault.db");
        let mut c = Command::new(&self.bin);
        c.env_clear()
            // Minimal PATH so the binary can spawn subprocesses if needed.
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.tmp)
            .env("AK_VAULT_PATH", &vault_path)
            .env("AK_TEST_PASSWORD", &self.password)
            // Silence logs that would pollute stdout parsing.
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// Register a personal key with a single provider.
    fn add_key(&self, alias: &str, provider: &str) {
        let mut child = self.cmd()
            .args(["add", alias, "--provider", provider])
            .env("AK_TEST_SECRET", test_api_key())
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn aikey add");
        // aikey add may still read stdin for confirmation; close it immediately.
        drop(child.stdin.take());
        let out = child.wait_with_output().expect("wait aikey add");
        assert!(
            out.status.success(),
            "aikey add failed for alias={} provider={}\nstderr: {}\nstdout: {}",
            alias,
            provider,
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
    }

    /// Run `aikey route <alias>` and return stdout.
    fn run_route(&self, alias: &str) -> String {
        let out = self.cmd()
            .args(["route", alias])
            .output()
            .expect("run aikey route");
        assert!(
            out.status.success(),
            "aikey route {} failed\nstderr: {}",
            alias,
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Run `aikey activate <alias> --shell bash` and return stdout.
    fn run_activate(&self, alias: &str) -> String {
        let out = self.cmd()
            .args(["activate", alias, "--shell", "bash"])
            .output()
            .expect("run aikey activate");
        assert!(
            out.status.success(),
            "aikey activate {} failed\nstderr: {}",
            alias,
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

// ── output parsing ──────────────────────────────────────────────────────

/// Extract the base_url from `aikey route <alias>` output.
///
/// Format (verified 2026-04-17): label block has lines like
///   `    base_url   http://127.0.0.1:27200/anthropic`
/// with `base_url` as the first non-space token and the URL following after
/// one or more spaces. We accept either `base_url:` (legacy) or `base_url ` to
/// stay tolerant across minor UI revisions.
fn parse_route_base_url(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let rest = trimmed
            .strip_prefix("base_url:")
            .or_else(|| trimmed.strip_prefix("base_url "));
        if let Some(r) = rest {
            let url = r.trim();
            if url.starts_with("http://") || url.starts_with("https://") {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// Extract the `<PROVIDER>_BASE_URL` value from `aikey activate` bash output.
/// Looks for a line like: `export ANTHROPIC_BASE_URL='http://...'`
fn parse_activate_base_url(output: &str, provider_prefix: &str) -> Option<String> {
    let needle = format!("export {}_BASE_URL=", provider_prefix);
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&needle) {
            let value = &trimmed[needle.len()..];
            // Strip surrounding single quotes (shell-escaped).
            return Some(value.trim_matches('\'').to_string());
        }
    }
    None
}

// ── test cases ──────────────────────────────────────────────────────────

fn assert_base_urls_match(provider: &str, provider_env_prefix: &str) {
    let env = TestEnv::new(&format!("match-{}", provider));
    let alias = format!("e2e-{}", provider);
    env.add_key(&alias, provider);

    let route_out = env.run_route(&alias);
    let route_url = parse_route_base_url(&route_out)
        .unwrap_or_else(|| panic!("route output missing base_url\n--- stdout ---\n{}", route_out));

    let activate_out = env.run_activate(&alias);
    let activate_url = parse_activate_base_url(&activate_out, provider_env_prefix)
        .unwrap_or_else(|| panic!(
            "activate output missing {}_BASE_URL\n--- stdout ---\n{}",
            provider_env_prefix, activate_out
        ));

    assert_eq!(
        route_url, activate_url,
        "base_url mismatch for provider '{}':\n  route:    {}\n  activate: {}\n\
         If these differ, users copying config from different commands will hit different upstream paths.",
        provider, route_url, activate_url,
    );
}

#[test]
fn base_url_matches_anthropic() {
    assert_base_urls_match("anthropic", "ANTHROPIC");
}

#[test]
fn base_url_matches_openai() {
    assert_base_urls_match("openai", "OPENAI");
}

#[test]
fn base_url_matches_kimi() {
    // The original L5 bug: route emitted /kimi, activate emitted /kimi/v1.
    // After fix, both must emit /kimi/v1.
    let env = TestEnv::new("kimi-regression");
    env.add_key("e2e-kimi", "kimi");

    let route_out = env.run_route("e2e-kimi");
    let route_url = parse_route_base_url(&route_out)
        .expect("route output missing base_url");
    assert!(
        route_url.ends_with("/kimi/v1"),
        "route should emit /kimi/v1 (L5 fix), got: {}",
        route_url
    );

    let activate_out = env.run_activate("e2e-kimi");
    let activate_url = parse_activate_base_url(&activate_out, "KIMI")
        .expect("activate output missing KIMI_BASE_URL");
    assert_eq!(route_url, activate_url, "route and activate must agree for kimi");
}

#[test]
fn base_url_matches_deepseek() {
    assert_base_urls_match("deepseek", "DEEPSEEK");
}

/// Sanity: the `aikey activate` output for bash is pure shell code (H1 fix).
/// An ANSI escape code in stdout would break `eval $(aikey activate ...)`.
#[test]
fn activate_stdout_is_eval_safe() {
    let env = TestEnv::new("eval-safe");
    env.add_key("e2e-clean", "openai");
    let out = env.run_activate("e2e-clean");
    assert!(
        !out.contains('\x1b'),
        "activate stdout must not contain ANSI escape codes (breaks eval):\n{:?}",
        out
    );
    // Must contain the expected shell-statement anchors.
    assert!(out.contains("export OPENAI_API_KEY="),
        "missing OPENAI_API_KEY export:\n{}", out);
    assert!(out.contains("export OPENAI_BASE_URL="),
        "missing OPENAI_BASE_URL export:\n{}", out);
}

