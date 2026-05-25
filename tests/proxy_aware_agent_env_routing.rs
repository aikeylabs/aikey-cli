//! Fence: `build_proxy_aware_agent` must honor lowercase `https_proxy`
//! / `http_proxy` / `all_proxy` env vars, not only uppercase.
//!
//! Why this fence exists
//! ---------------------
//! Bugfix 20260525-aikey-cli-install-bypasses-proxy-aware-agent.md:
//! `aikey app install degrade-detector` failed with 30s TCP timeout on
//! Mac users running Clash / V2Ray (lowercase env exported by default).
//! Root cause: `install.rs` used `ureq::get()` directly — which reads
//! no env at all — instead of `build_proxy_aware_agent`. The proxy-
//! aware builder DID read lowercase env (it was added for the connectivity
//! suite earlier), but the install path bypassed it.
//!
//! This fence locks two contracts:
//!   F1: `build_proxy_aware_agent` reads lowercase env vars (so `install.rs`
//!       — which routes through it — gets the right proxy without
//!       requiring users to also export uppercase).
//!   F2: a request through the resulting agent actually reaches the
//!       configured proxy host (not direct).
//!
//! We don't validate uppercase env here because that path was always
//! covered by `std::env::var` defaults; the regression risk is on the
//! lowercase side specifically.
//!
//! Threading note: Rust's `std::env::set_var` is unsafe under concurrent
//! reads from other threads. Cargo's default `--test-threads=N` would
//! race this test with anything else also touching env. Mitigation: this
//! file uses a single `#[test]` that mutates env inside a `Mutex`-guarded
//! block and restores on drop. The Makefile `test-proxy-env-routing`
//! target additionally runs with `--test-threads=1` for full safety.

use std::io::Read;
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use aikeylabs_aikey_cli::connectivity::build_proxy_aware_agent;

// Single env mutation lock — prevents the (currently solo) tests in
// this file from racing each other if more get added.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard: set an env var on construct, restore prior value on drop.
struct EnvGuard {
    key: &'static str,
    prior: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prior = std::env::var(key).ok();
        // SAFETY: caller holds ENV_LOCK across the whole test, and Rust
        // edition 2024 wants set_var marked unsafe — but we're on
        // edition 2021 where it's still safe in single-threaded test
        // sections. If this crate upgrades to 2024, wrap in `unsafe {}`.
        std::env::set_var(key, value);
        Self { key, prior }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prior {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// Spawn a TCP listener on 127.0.0.1:0 (kernel-assigned port). Returns
/// the bound port + a join handle that resolves once one connection has
/// been accepted. The handle's value is `Some(first_line)` where
/// `first_line` is the first newline-delimited request line the listener
/// saw — enough to distinguish "ureq sent us a CONNECT" from "ureq sent
/// us a GET" from "nothing came in".
fn spawn_one_shot_listener() -> (u16, thread::JoinHandle<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        // Block up to the test's overall timeout for accept. ureq has a
        // 2s connect timeout below, so this races against that.
        listener.set_nonblocking(false).ok();
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).unwrap_or(0);
                let s = String::from_utf8_lossy(&buf[..n]).into_owned();
                Some(s.lines().next().unwrap_or("").to_string())
            }
            Err(_) => None,
        }
    });
    (port, handle)
}

#[test]
fn build_proxy_aware_agent_reads_lowercase_https_proxy_env() {
    let _lock = ENV_LOCK.lock().unwrap();

    // Ensure uppercase is empty so we're proving lowercase alone works.
    std::env::remove_var("HTTPS_PROXY");
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("ALL_PROXY");
    // Pre-clear lowercase too — the EnvGuard below will set just one.
    std::env::remove_var("http_proxy");
    std::env::remove_var("all_proxy");

    let (proxy_port, listener_handle) = spawn_one_shot_listener();
    let _guard = EnvGuard::set("https_proxy", &format!("http://127.0.0.1:{}", proxy_port));

    let agent = build_proxy_aware_agent(Duration::from_secs(2));
    // Fire a request to an HTTPS URL. ureq will issue HTTP CONNECT to
    // our listener (because https_proxy points there). The listener
    // will receive the CONNECT line, then close without replying — the
    // agent.call() will fail (which is fine), but the listener will
    // have captured proof that ureq DID try to use our proxy.
    let _ = agent.get("https://example.invalid/no-such-path").call();

    let first_line = listener_handle
        .join()
        .expect("listener thread panicked")
        .expect("listener never received a connection — agent bypassed the proxy");

    // The first line MUST start with "CONNECT" — that's the HTTPS-via-
    // proxy tunnel handshake. If we see "GET https://..." or anything
    // else, the agent went direct (regression!).
    assert!(
        first_line.starts_with("CONNECT "),
        "expected CONNECT line to mock proxy, got: {:?}",
        first_line
    );
    // Sanity: target host should appear in the CONNECT line
    assert!(
        first_line.contains("example.invalid"),
        "CONNECT line missing target host: {:?}",
        first_line
    );
}
