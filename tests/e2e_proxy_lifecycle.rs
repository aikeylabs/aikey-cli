//! Lifecycle tests for `aikey proxy start/stop/status/restart`.
//!
//! These exercise the real `aikey-proxy` binary in the background against a
//! per-test port and a per-test HOME so they never clash with the user's
//! own running proxy.
//!
//! ## Required environment
//!
//! `AIKEY_PROXY_BIN` must point to an installed `aikey-proxy` binary. The
//! test auto-discovers it at `$HOME_REAL/.aikey/bin/aikey-proxy` (the default
//! installer path). If neither is reachable, every test in this file is
//! silently marked **skipped** — we don't fail CI just because nobody built
//! the proxy.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

/// Resolve the path to the `aikey-proxy` binary. Returns None if we can't
/// find it — callers should treat that as "skip".
fn proxy_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AIKEY_PROXY_BIN") {
        let path = PathBuf::from(p);
        if path.exists() { return Some(path); }
    }
    if let Ok(real_home) = std::env::var("HOME") {
        let candidate = PathBuf::from(real_home).join(".aikey/bin/aikey-proxy");
        if candidate.exists() { return Some(candidate); }
    }
    None
}

/// Pick a free localhost port by asking the OS for one, then closing it.
/// Caveat: TOCTOU — in rare races the port may be taken by the time proxy
/// starts. Re-running the test is the documented recovery.
fn pick_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Write a minimal proxy config that listens on `port`, points at `vault`,
/// and has a single virtual key referencing an empty alias. The config is
/// enough for `aikey proxy start` to launch; we don't care about routing
/// correctness here, only that start/stop/status work.
fn write_test_config(dir: &PathBuf, port: u16, vault: &PathBuf) -> PathBuf {
    let cfg_path = dir.join("aikey-proxy.yaml");
    let yaml = format!(
        r#"listen:
  host: "127.0.0.1"
  port: {port}

vault:
  path: "{vault_path}"

virtual_keys: []

providers:
  openai:
    protocol: "openai"
    timeout: 120s
"#,
        port = port,
        vault_path = vault.display(),
    );
    std::fs::write(&cfg_path, yaml).expect("write test config");
    cfg_path
}

struct Env {
    tmp: PathBuf,
    port: u16,
    proxy_bin: PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        // Best-effort stop (ignore errors — test may have already stopped).
        let _ = self.cmd().args(["proxy", "stop"]).output();
        if std::env::var("AIKEY_E2E_KEEP_TMPDIR").as_deref() != Ok("1") {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }
}

impl Env {
    /// Returns Some(Env) or None if prerequisites are missing (skip).
    fn try_new(tag: &str) -> Option<Self> {
        let proxy_bin = proxy_binary()?;
        let tmp = std::env::temp_dir()
            .join(format!("aikey-e2e-proxy-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".aikey/data")).expect("mkdir");
        std::fs::create_dir_all(tmp.join(".aikey/config")).expect("mkdir config");
        std::fs::create_dir_all(tmp.join(".aikey/logs")).expect("mkdir logs");

        let port = pick_free_port();
        let vault = tmp.join(".aikey/data/vault.db");

        // Bootstrap the vault first (proxy needs it to exist).
        let bootstrap = Command::new(bin_path())
            .args(["add", "__boot__", "--provider", "openai"])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &tmp)
            .env("AK_VAULT_PATH", &vault)
            .env("AK_TEST_PASSWORD", "proxy-pw")
            .env("AK_TEST_SECRET", "sk-boot")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("bootstrap vault");
        assert!(bootstrap.success(), "bootstrap add failed");

        // Write a proxy config in the well-known config dir.
        let cfg = tmp.join(".aikey/config/aikey-proxy.yaml");
        write_test_config(&tmp.join(".aikey/config"), port, &vault);
        assert!(cfg.exists());

        Some(Self { tmp, port, proxy_bin })
    }

    /// Build a Command isolated to this test's HOME + proxy binary + port.
    fn cmd(&self) -> Command {
        let mut c = Command::new(bin_path());
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.tmp)
            .env("AK_VAULT_PATH", self.tmp.join(".aikey/data/vault.db"))
            .env("AK_TEST_PASSWORD", "proxy-pw")
            .env("AIKEY_PROXY_BIN", &self.proxy_bin)
            .env("AIKEY_PROXY_PORT", self.port.to_string())
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// Wait up to `secs` seconds for proxy status to match `expect_running`.
    /// Returns true if the state was reached, false on timeout.
    fn wait_status(&self, expect_running: bool, secs: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            let out = self.cmd().args(["proxy", "status"]).output();
            if let Ok(o) = out {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr),
                );
                let running = text.contains("running") && !text.contains("not running");
                if running == expect_running {
                    return true;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        false
    }
}

/// Print a "skipped" marker and succeed. Cargo doesn't have a built-in
/// skip mechanism for integration tests; this is the idiomatic workaround.
fn skip_because_no_proxy_bin() {
    eprintln!("[skip] AIKEY_PROXY_BIN not set and ~/.aikey/bin/aikey-proxy not found — \
               skipping proxy lifecycle test (build/install aikey-proxy to enable)");
}

// ── tests ───────────────────────────────────────────────────────────────

#[test]
fn proxy_status_on_clean_env_reports_not_running() {
    let env = match Env::try_new("status-clean") {
        Some(e) => e,
        None => return skip_because_no_proxy_bin(),
    };

    let out = env.cmd().args(["proxy", "status"]).output().expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(combined.contains("not running")
            || combined.contains("stopped")
            || combined.contains("not reachable"),
        "proxy status on clean env should say 'not running', got:\n{}", combined);
}

#[test]
fn proxy_start_then_stop_round_trip() {
    let env = match Env::try_new("start-stop") {
        Some(e) => e,
        None => return skip_because_no_proxy_bin(),
    };

    let start = env.cmd().args(["proxy", "start"]).output().expect("spawn start");
    assert!(start.status.success(),
        "proxy start failed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr));

    assert!(env.wait_status(true, 10),
        "proxy status did not become 'running' within 10s after start");

    let stop = env.cmd().args(["proxy", "stop"]).output().expect("spawn stop");
    assert!(stop.status.success(),
        "proxy stop failed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr));

    assert!(env.wait_status(false, 5),
        "proxy status did not become 'not running' within 5s after stop");
}

#[test]
fn proxy_start_is_idempotent() {
    // Calling start twice in a row must not error out or spawn duplicates.
    let env = match Env::try_new("start-idem") {
        Some(e) => e,
        None => return skip_because_no_proxy_bin(),
    };

    let first = env.cmd().args(["proxy", "start"]).output().expect("start 1");
    assert!(first.status.success(), "first proxy start failed");
    assert!(env.wait_status(true, 10));

    let second = env.cmd().args(["proxy", "start"]).output().expect("start 2");
    // Second start should either succeed (no-op) or exit with an "already
    // running" message — both are acceptable. What's NOT acceptable is a
    // crash or a mismatched-port process.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    if !second.status.success() {
        assert!(combined.contains("already")
                || combined.contains("running")
                || combined.contains("exists"),
            "second start should be idempotent or report 'already running', got:\n{}",
            combined);
    }

    // Regardless, status must still report running.
    assert!(env.wait_status(true, 5), "proxy not running after second start");
}

#[test]
fn proxy_restart_leaves_proxy_running() {
    let env = match Env::try_new("restart") {
        Some(e) => e,
        None => return skip_because_no_proxy_bin(),
    };

    let start = env.cmd().args(["proxy", "start"]).output().unwrap();
    assert!(start.status.success());
    assert!(env.wait_status(true, 10));

    let restart = env.cmd().args(["proxy", "restart"]).output().unwrap();
    assert!(restart.status.success(),
        "proxy restart failed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&restart.stdout),
        String::from_utf8_lossy(&restart.stderr));

    // After restart the proxy must be reachable again.
    assert!(env.wait_status(true, 10),
        "proxy not running after restart");
}

/// Extract the PID from `aikey proxy status` output. Looks for a line like
/// `pid:     22085` (or similar) — matches the first run of digits after "pid".
fn pid_from_status(text: &str) -> Option<u32> {
    for line in text.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("pid") {
            continue;
        }
        if let Some(num) = line.split_whitespace()
            .find_map(|w| w.trim_matches(|c: char| !c.is_ascii_digit()).parse::<u32>().ok())
        {
            if num > 1 {
                return Some(num);
            }
        }
    }
    None
}

/// Regression test for 2026-04-05 bugfix
/// (workflow/CI/bugfix/20260405-proxy-down-no-warning-after-kill9.md):
/// after `kill -9` on the proxy, follow-up CLI commands must visibly warn
/// the user that the proxy is down, rather than silently proceeding.
///
/// Before fix: commands like `aikey list` ran to completion with no hint.
/// Fix: added post-op `warn_if_proxy_down()` health check that emits
/// "⚠  Proxy is not running. Start it with: aikey proxy start".
///
/// ## Why this test is tricky
///
/// `try_auto_start_from_env()` runs at the top of every dispatch and will
/// RE-SPAWN the proxy whenever `AK_TEST_PASSWORD` (or `AIKEY_MASTER_PASSWORD`)
/// is set — the moment we `kill -9`, the next CLI command would bring the
/// proxy back up before `warn_if_proxy_down` even runs, hiding the bug.
///
/// To reproduce the bug's actual condition (proxy dead + no auto-recovery),
/// the post-kill `aikey list` runs with `AIKEY_PROXY_BIN=/dev/null` so the
/// auto-start's binary lookup fails silently. Only then does `warn_if_proxy_down`
/// get its turn to fire.
#[test]
fn proxy_kill9_warns_on_next_cli_command() {
    let env = match Env::try_new("kill9-warn") {
        Some(e) => e,
        None => return skip_because_no_proxy_bin(),
    };

    // Start the proxy and confirm it's running.
    let start = env.cmd().args(["proxy", "start"]).output().unwrap();
    assert!(start.status.success(), "proxy start failed: {}",
        String::from_utf8_lossy(&start.stderr));
    assert!(env.wait_status(true, 10), "proxy never came up");

    // Pull the PID from `aikey proxy status` output.
    let status_out = env.cmd().args(["proxy", "status"]).output().unwrap();
    let status_text = format!(
        "{}{}",
        String::from_utf8_lossy(&status_out.stdout),
        String::from_utf8_lossy(&status_out.stderr),
    );
    let pid = pid_from_status(&status_text)
        .unwrap_or_else(|| panic!("couldn't parse PID from status:\n{}", status_text));

    // kill -9 the proxy. SIGKILL bypasses graceful shutdown, leaving the
    // pid file behind — exactly the condition the bugfix targets.
    let killed = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .expect("spawn kill");
    assert!(killed.success(), "kill -9 {} failed", pid);

    // Let the TCP listener fully release.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Run `aikey list` with AIKEY_PROXY_BIN=/dev/null so the auto-start in
    // `try_auto_start_from_env()` fails silently (it can't exec /dev/null).
    // Only then does `warn_if_proxy_down` run against a genuinely dead proxy.
    let list = env
        .cmd()
        .env("AIKEY_PROXY_BIN", "/dev/null")
        .arg("list")
        .output()
        .expect("spawn list");
    let stderr = String::from_utf8_lossy(&list.stderr);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&list.stdout),
        &stderr,
    );

    // Match both anchors: the fix adds BOTH "Proxy is not running" AND the
    // `aikey proxy start` hint. Requiring both prevents false positives from
    // unrelated stderr chatter.
    assert!(combined.contains("Proxy is not running")
            || combined.contains("proxy is not running"),
        "kill -9 of proxy MUST trigger 'Proxy is not running' warning on \
         the next CLI command (regression: 2026-04-05 bugfix).\n\
         combined output:\n{}", combined);
    assert!(combined.contains("aikey proxy start"),
        "warning should include the `aikey proxy start` hint so users know \
         how to recover.\ncombined output:\n{}", combined);
}
