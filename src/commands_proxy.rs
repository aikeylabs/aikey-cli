//! Proxy lifecycle management commands: start, stop, status, restart, verify.
//!
//! `aikey proxy start` authenticates once with the vault master password,
//! then spawns `aikey-proxy` as a child process with the password injected
//! via `AIKEY_MASTER_PASSWORD` — no second prompt required.
//!
//! A lightweight `proxy_guard` is exported for use by other commands (e.g. `run`)
//! so the proxy is automatically started in the background when needed.

// TRANSITIONAL (Stages 1-2, remove in Stage 3 cut-over):
// `is_proxy_running` and `is_proxy_listening` are deprecated this file
// — their replacement (`proxy_state::proxy_state()`) lives alongside
// during Stages 1-2. The internal call sites here will be deleted /
// rewritten in Stage 3. Suppressing file-level so the build output
// during Stage 2 development isn't drowned in deprecation noise.
#![allow(deprecated)]

use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

// Fallback proxy listen address when the config cannot be parsed.
const PROXY_HEALTH_ADDR_DEFAULT: &str = "127.0.0.1:27200";
const PID_FILENAME: &str = "proxy.pid";
const DEFAULT_CONFIG_NAME: &str = "aikey-proxy.yaml";

// ---------------------------------------------------------------------------
// Layer 2 bridge — Stage 3 migration helpers
// ---------------------------------------------------------------------------

/// Canonical path for the proxy startup log. stderr from the spawned
/// proxy gets appended here so silent-failure modes (vault decrypt,
/// bind error, panicking goroutine) leave a forensic trail.
///
/// Bugfix record: 2026-04-28 — proxy auto-start silently failed when
/// user typed wrong vault password; vault decrypt error was lost
/// because stderr went to /dev/null.
fn startup_log_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".aikey").join("logs").join("aikey-proxy-startup.log"))
        .unwrap_or_else(|| PathBuf::from("/tmp/aikey-proxy-startup.log"))
}

/// Build a `StartOptions` struct from the existing CLI config-loading
/// flow. Bridges legacy `Option<&str>` config arg + proxy.env discovery
/// + binary lookup to the new Layer 2 surface.
///
/// Returns the loaded options + the proxy.env entries so the caller
/// can print the "proxy.env: N entries [...]" diagnostic before
/// invoking `start_proxy_*`.
fn build_start_options(
    config: Option<&str>,
    stderr_target: crate::proxy_lifecycle::StderrTarget,
) -> Result<(crate::proxy_lifecycle::StartOptions, Vec<String>), Box<dyn std::error::Error>> {
    let binary_path = find_proxy_binary()?;
    let config_path = resolve_config(config)?;
    let listen_addr = proxy_listen_addr(Some(&config_path));

    let (extra_env, env_keys) = match crate::proxy_env::read_proxy_env() {
        Ok(env_map) => {
            let keys: Vec<String> = env_map.keys().cloned().collect();
            let pairs: Vec<(String, String)> =
                env_map.into_iter().collect();
            (pairs, keys)
        }
        Err(e) => {
            return Err(format!(
                "Failed to parse ~/.aikey/proxy.env: {}\n\
                 Fix the file or remove it, then retry.",
                e
            )
            .into());
        }
    };

    let opts = crate::proxy_lifecycle::StartOptions {
        config_path,
        binary_path,
        listen_addr,
        healthy_deadline: crate::proxy_lifecycle::DEFAULT_HEALTHY_DEADLINE,
        stderr_target,
        extra_env,
    };
    Ok((opts, env_keys))
}

// ---------------------------------------------------------------------------
// Vault change-sequence state helpers
// ---------------------------------------------------------------------------

/// Whether the running proxy's vault snapshot is up-to-date.
#[derive(Debug, PartialEq)]
pub enum ProxyVaultState {
    /// Proxy has loaded the latest vault snapshot.
    Current,
    /// Vault has been written since the proxy last loaded it.
    Stale,
    /// Sequence numbers are unavailable (vault not initialised, proxy never
    /// recorded its loaded seq, etc.).
    Unknown,
}

/// Returns the vault snapshot state of the currently running proxy.
/// Does NOT check whether the proxy process is alive; call `is_proxy_running`
/// before this if you only want to inspect a live proxy.
pub fn proxy_vault_state() -> ProxyVaultState {
    let vault_seq = match crate::storage::get_vault_change_seq() {
        Ok(s) => s,
        Err(_) => return ProxyVaultState::Unknown,
    };
    let proxy_seq = match crate::storage::get_proxy_loaded_seq() {
        Ok(s) => s,
        Err(_) => return ProxyVaultState::Unknown,
    };
    if vault_seq > proxy_seq {
        ProxyVaultState::Stale
    } else {
        ProxyVaultState::Current
    }
}

/// Returns true if the proxy process is running.
///
/// Note: PID-only check (fast). For "actually serving requests" use
/// `is_proxy_listening()` instead — it adds a port probe to catch the
/// "PID alive but socket not bound" failure mode (e.g. proxy hung at
/// startup before bind, or PID recycle pointing to an unrelated process).
///
/// **Deprecated as of Round 5 (2026-04-28)**: this function returns
/// PID-only existence which is **not safe** to use as a kill gate —
/// PID recycling can make this return true for unrelated or
/// other-instance aikey-proxy processes. Use
/// [`crate::proxy_state::proxy_state`] instead, which combines
/// identity + ownership verification.
/// **Round 9 fix #1**: downgraded from `pub` to `pub(crate)` after all
/// external callers migrated to `proxy_is_running_managed` (Layer 1).
/// The remaining in-crate use (line 172, the deprecated `is_proxy_listening`
/// internal call) is itself slated for removal once `is_proxy_listening`
/// is dropped. Keeping the symbol behind the deprecation gate so any
/// future re-introduction is loud at compile time.
#[deprecated(
    since = "1.0.6",
    note = "Use proxy_state::proxy_state() — this PID-only check is unsafe \
            for kill decisions due to PID recycle (Round 5). \
            For boolean preflight, use commands_proxy::proxy_is_running_managed()."
)]
pub(crate) fn is_proxy_running() -> bool {
    read_pid().map_or(false, |pid| process_alive(pid))
}

/// Returns true if the proxy is BOTH (a) running per pidfile and
/// (b) actually listening on its configured port. Use this when the
/// answer needs to mean "the proxy can serve requests right now" — for
/// success reporting in `aikey proxy ensure-running`, for diagnostic
/// gates that need a hard truthful signal, etc.
///
/// `is_proxy_running()` alone is insufficient for those callers: a stale
/// pidfile (process died after `write_pid` but before `bind`) or PID
/// recycle (kernel reassigned the PID to an unrelated process) both
/// produce false positives. Adding a quick port probe closes both holes.
///
/// **Deprecated as of Round 5 (2026-04-28)**: PID + port-reachable is
/// still insufficient — port can be held by a *different* aikey-proxy
/// instance (PID recycle to another instance), in which case both
/// signals are true but the process is not ours. Use
/// [`crate::proxy_state::proxy_state`] which adds identity + ownership
/// (birth_token) verification.
/// **Round 9 fix #1**: downgraded from `pub` to `pub(crate)` after all
/// external callers migrated to `proxy_is_running_managed`.
#[deprecated(
    since = "1.0.6",
    note = "Use proxy_state::proxy_state() — PID + port still insufficient \
            for ownership; need identity + birth_token (Round 5). \
            For boolean preflight, use commands_proxy::proxy_is_running_managed()."
)]
#[allow(dead_code)]
pub(crate) fn is_proxy_listening() -> bool {
    #[allow(deprecated)]
    if !is_proxy_running() {
        return false;
    }
    let addr = proxy_listen_addr(None);
    port_reachable(&addr, Duration::from_millis(300))
}

/// Returns `true` iff the proxy is in `ProxyState::Running` —
/// identity + ownership + `/health` all verified. Other states
/// (Stopped, Crashed, Unresponsive, OrphanedPort) all return `false`.
///
/// **Round 9 review fix (MEDIUM, Finding 1)**: introduced as the
/// canonical `bool` wrapper around `proxy_state::proxy_state()` for
/// preflight callers (connectivity targets, `aikey run` dispatch,
/// command-entry guards). Use this in place of the deprecated
/// `is_proxy_running` / `is_proxy_listening` everywhere a simple
/// "can I route through proxy right now?" check is needed. PID recycle
/// to another aikey-proxy instance and OrphanedPort scenarios both
/// correctly return `false` via this helper, where the legacy probes
/// would have returned `true`.
pub fn proxy_is_running_managed() -> bool {
    use crate::proxy_state::{proxy_state, ProxyState};
    matches!(proxy_state(&proxy_listen_addr(None)), ProxyState::Running { .. })
}

/// Sends `POST /admin/reload` to the proxy if it is currently running.
///
/// Called by `aikey use` after updating the active key config so the proxy
/// picks up the new route without a full restart.  Errors are suppressed —
/// the proxy remains reachable even if the reload HTTP call fails.
pub fn try_reload_proxy() {
    // Round 9 fix #1: was is_proxy_running (PID-only); now Layer 1 so we
    // skip the reload POST when the proxy is OrphanedPort / Unresponsive
    // (the POST would fail anyway, but the diagnostic noise is cleaner now).
    if proxy_is_running_managed() {
        if let Err(e) = post_admin_reload() {
            let msg = e.to_string();
            // Why: after `aikey change-password`, the proxy process still has
            // the old AIKEY_MASTER_PASSWORD in its env; reload then fails with
            // "invalid master password" from aikey-proxy/vault.go and users
            // have no actionable hint. Detect that specific path and tell them
            // to restart the proxy so the new password is picked up.
            if msg.contains("invalid master password") {
                eprintln!("[aikey] proxy reload failed: vault password mismatch.");
                eprintln!("        The proxy is still holding the old AIKEY_MASTER_PASSWORD.");
                eprintln!("        Run `aikey proxy restart` to pick up the new password.");
            } else {
                eprintln!("[aikey] proxy reload hint failed (non-fatal): {}", msg);
            }
        }
    }
}

// `silently_start_proxy` was deleted in Stage 3 cut-over (2026-04-28).
// All call sites migrated to `crate::proxy_lifecycle::start_proxy`,
// which provides a single canonical spawn path with RAII cleanup,
// identity + ownership verification, and the lifecycle file lock.
// See lifecycle 方案 § Layer 2 — anything that needs to spawn proxy
// must go through Layer 2 now (no direct `Command::spawn` allowed).

/// Try to auto-start the proxy silently using `AIKEY_MASTER_PASSWORD` or
/// `AK_TEST_PASSWORD` environment variables.
///
/// Called at the top of every command dispatch so that the proxy is running
/// whenever a master password is pre-injected (e.g. CI / scripted sessions).
/// No-ops completely when neither env var is set — no prompt, no output.
///
/// Stage 3 migration: delegates to Layer 2 [`crate::proxy_lifecycle::start_proxy`]
/// for atomic spawn + identity / ownership tracking. Errors are silently
/// swallowed (function returns `()` not `Result`) — by design, this is a
/// best-effort hook called automatically; failure should never block
/// the actual command the user invoked.
pub fn try_auto_start_from_env() {
    use crate::proxy_lifecycle::StderrTarget;

    let pw = std::env::var("AIKEY_MASTER_PASSWORD")
        .or_else(|_| std::env::var("AK_TEST_PASSWORD"));
    let Ok(pw_val) = pw else { return };

    let stderr_target = StderrTarget::Log(startup_log_path());
    let Ok((opts, _)) = build_start_options(None, stderr_target) else { return };

    let _ = crate::proxy_lifecycle::start_proxy(&SecretString::new(pw_val), opts);
}

/// Ensure the proxy is running, prompting for the master password when needed.
///
/// Called by `aikey use` / `aikey key use` / wrapper hooks so that the
/// proxy is always started after activating a key. Priority chain:
///   1. Layer 1 says proxy is `Running` → no-op (idempotent fast-path)
///   2. `AIKEY_MASTER_PASSWORD` / `AK_TEST_PASSWORD` env var → silent start
///   3. Session-cache hit → silent start (verified via `list_secrets` first)
///   4. Interactive TTY → prompt + verify + start
///   5. Non-TTY without env var → print a hint but don't block
///
/// Stage 3 migration: delegates to Layer 2 [`crate::proxy_lifecycle::start_proxy`]
/// for the actual spawn. This shell handles the password resolution chain
/// + verifying password against the vault before spawning (avoids the
/// silent-vault-decrypt-failure pitfall — see commit history /
/// `bugfix/2026-04-28-*`).
pub fn ensure_proxy_for_use(password_stdin: bool) {
    use crate::proxy_lifecycle::{start_proxy, StartError, StderrTarget};

    // 0. Fast-path: ask Layer 1 if proxy is already running. This is
    // the safer-than-`is_proxy_running` check — Layer 1 verifies
    // identity + ownership, so a `Running` here is provably ours.
    let probe_listen = proxy_listen_addr(None);
    if matches!(
        crate::proxy_state::proxy_state(&probe_listen),
        crate::proxy_state::ProxyState::Running { .. }
    ) {
        return;
    }

    // 1. Resolve a candidate password.
    let stderr_target = StderrTarget::Log(startup_log_path());
    let env_pw = std::env::var("AIKEY_MASTER_PASSWORD")
        .or_else(|_| std::env::var("AK_TEST_PASSWORD"))
        .ok();

    let (pw, from_cache, prompted, env_path) = if let Some(env_val) = env_pw {
        // Env-var path: caller already injected the password; trust it.
        // No vault verification — env var has the same security model as
        // a flag, and the caller is responsible for getting it right.
        (SecretString::new(env_val), false, false, true)
    } else {
        // Interactive / cache path. Need to actually have a TTY (or
        // password-stdin mode) to ask for a fresh password.
        use std::io::IsTerminal;
        if !(io::stderr().is_terminal() || password_stdin) {
            eprintln!("[aikey] proxy not running — run `aikey proxy start` to enable routing");
            return;
        }
        eprintln!();
        eprintln!("Proxy not running — starting it now.");

        // Cache hit: silent.
        let mut from_cache = false;
        let mut prompted = false;
        let pw: SecretString = if let Some(cached) = (!password_stdin)
            .then(|| crate::session::try_get())
            .flatten()
        {
            crate::session::refresh();
            from_cache = true;
            cached
        } else if password_stdin {
            eprint!("\u{1F512} Enter Master Password: ");
            let _ = io::stderr().flush();
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            eprintln!("***");
            prompted = true;
            SecretString::new(line.trim().to_string())
        } else {
            prompted = true;
            match crate::prompt_hidden("\u{1F512} Enter Master Password: ") {
                Ok(p) => SecretString::new(p),
                Err(_) => {
                    eprintln!("  [aikey] Could not read password — run `aikey proxy start` manually.");
                    return;
                }
            }
        };

        // Verify password against the vault BEFORE spawning. Catches
        // wrong-password early instead of letting it manifest as a
        // silent vault-decrypt failure inside the child.
        if let Err(e) = crate::executor::list_secrets(&pw) {
            if from_cache {
                crate::session::invalidate();
            }
            eprintln!("  [aikey] vault password rejected: {}", e);
            eprintln!("  [aikey] retry with: aikey proxy start");
            return;
        }
        if prompted {
            crate::session::store(&pw);
        }
        (pw, from_cache, prompted, false)
    };
    let _ = (from_cache, prompted, env_path); // suppress unused warnings on cfg paths

    // 2. Build StartOptions + delegate to Layer 2.
    let (opts, _env_keys) = match build_start_options(None, stderr_target) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  [aikey] {}", e);
            return;
        }
    };

    match start_proxy(&pw, opts) {
        Ok(_) => {
            eprintln!("  [aikey] proxy started in background");
            if let Ok(seq) = crate::storage::get_vault_change_seq() {
                let _ = crate::storage::set_proxy_loaded_seq(seq);
            }
        }
        Err(StartError::OrphanedPort { port, owner_pid: _, reason: _ }) => {
            eprintln!(
                "  [aikey] port {port} is in use by another process — \
                 run `aikey proxy status` for details"
            );
        }
        Err(StartError::BinaryMissing(_)) => {
            eprintln!("  [aikey] proxy binary not found — reinstall with: aikey proxy install");
        }
        Err(StartError::ConfigMissing(_)) => {
            eprintln!("  [aikey] proxy config not found — run: aikey proxy start");
        }
        Err(e) => {
            eprintln!(
                "  [aikey] proxy failed to start: {e} — check ~/.aikey/logs/aikey-proxy-startup.log \
                 or run: aikey proxy start --foreground"
            );
        }
    }
}

/// Auto-restarts the proxy if it is running and its vault snapshot is stale.
/// Restart is needed (not just reload) because personal keys require a fresh
/// vault open with the master password to decrypt entries.
/// Call this after any vault-write operation (add, delete, update, etc.).
pub fn maybe_warn_stale() {
    // Round 9 fix #1: was is_proxy_running (PID-only); now Layer 1.
    // Stale-vault check only meaningful when the proxy is genuinely ours.
    if proxy_is_running_managed() && proxy_vault_state() == ProxyVaultState::Stale {
        if let Some(pw) = crate::session::try_get() {
            match handle_restart(None, &pw) {
                Ok(_) => eprintln!("  Proxy restarted with new keys."),
                Err(_) => eprintln!("  Run 'aikey proxy restart' to apply new keys."),
            }
        } else {
            eprintln!("  Run 'aikey proxy restart' to apply new keys.");
        }
    }
}

/// Sends `POST /admin/reload` to the running proxy and waits for the response.
/// Injects the current trace context via the W3C `traceparent` header so the
/// reload operation can be correlated with CLI log records by trace_id.
/// Returns Ok(()) when the proxy confirms a successful graceful reload.
pub fn post_admin_reload() -> Result<(), Box<dyn std::error::Error>> {
    // Why: use configured listen address instead of hardcoded default, so reload
    // works when the user/deployment overrides the proxy port in config YAML.
    let addr = proxy_listen_addr(None);
    let stream = TcpStream::connect(&addr)
        .map_err(|e| format!("cannot connect to proxy at {}: {}", addr, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Inject traceparent so the proxy's reload logs share the same trace_id.
    let traceparent_header = crate::observability::trace()
        .map(|tc| format!("traceparent: {}\r\n", tc.traceparent))
        .unwrap_or_default();

    let request = format!(
        "POST /admin/reload HTTP/1.0\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n{}\r\n",
        addr, traceparent_header
    );
    {
        let mut w = stream.try_clone()?;
        w.write_all(request.as_bytes())?;
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    // Read and check the HTTP status line.
    let status_line = lines
        .next()
        .ok_or("proxy closed connection without response")??;
    if !status_line.contains("200") {
        // Drain the rest of the body for the error message.
        let mut body = String::new();
        let mut in_body = false;
        for line in lines.flatten() {
            if in_body { body.push_str(&line); body.push('\n'); }
            else if line.is_empty() { in_body = true; }
        }
        return Err(format!("proxy reload failed: {} — {}", status_line.trim(), body.trim()).into());
    }
    Ok(())
}

/// Read the `listen.host:port` from the yaml config (best-effort, falls back to default).
fn proxy_listen_addr(config_path: Option<&std::path::Path>) -> String {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => match resolve_config(None) {
            Ok(p) => p,
            Err(_) => return PROXY_HEALTH_ADDR_DEFAULT.to_string(),
        },
    };
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return PROXY_HEALTH_ADDR_DEFAULT.to_string(),
    };
    // Minimal parse: look for `host:` and `port:` lines under `listen:`.
    let mut host = "127.0.0.1".to_string();
    let mut port = 27200u16;
    let mut in_listen = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "listen:" { in_listen = true; continue; }
        if in_listen {
            if trimmed.starts_with("host:") {
                host = trimmed.trim_start_matches("host:").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("port:") {
                if let Ok(p) = trimmed.trim_start_matches("port:").trim().parse::<u16>() {
                    port = p;
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(' ') {
                in_listen = false; // left the listen block
            }
        }
    }
    format!("{}:{}", host, port)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn handle_start(config: Option<&str>, detach: bool, password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    if detach {
        handle_start_background(config, password)
    } else {
        handle_start_foreground(config, password)
    }
}

/// Background start path — delegates to Layer 2 [`crate::proxy_lifecycle::start_proxy`]
/// which handles all the lifecycle invariants (lock, identity / ownership
/// verification, atomic sidecar+pidfile write, RAII cleanup, healthy-poll).
///
/// This shell is responsible for:
/// - building the [`StartOptions`] from the existing config-loading flow
/// - printing the user-facing diagnostics ("Starting...", "config:",
///   "binary:", "proxy.env: N entries")
/// - converting [`StartError`] variants to the legacy CLI error strings
///   so existing tests (`e2e_proxy_lifecycle.rs`) continue to pass
fn handle_start_background(
    config: Option<&str>,
    password: &SecretString,
) -> Result<(), Box<dyn std::error::Error>> {
    let stderr_target = crate::proxy_lifecycle::StderrTarget::Log(startup_log_path());
    let (opts, env_keys) = build_start_options(config, stderr_target)?;

    eprintln!("Starting aikey-proxy...");
    eprintln!("  config: {}", opts.config_path.display());
    eprintln!("  binary: {}", opts.binary_path.display());
    if !env_keys.is_empty() {
        eprintln!("  proxy.env: {} entries [{}]", env_keys.len(), env_keys.join(", "));
    }

    let listen_addr_for_msg = opts.listen_addr.clone();
    match crate::proxy_lifecycle::start_proxy(password, opts) {
        Ok(state) => {
            eprintln!(
                "\x1b[32m✓\x1b[0m aikey-proxy running (pid: {}, http://{})",
                state.pid, state.listen_addr
            );
            // Quick connectivity check for overseas providers after proxy starts.
            // Only warn when a provider is unreachable — no noise when all is fine.
            std::thread::spawn(|| {
                check_overseas_connectivity();
            });
            // Record vault snapshot seq so reload-vs-restart logic can detect
            // staleness later. (Sole writer per CLAUDE.md.)
            if let Ok(seq) = crate::storage::get_vault_change_seq() {
                let _ = crate::storage::set_proxy_loaded_seq(seq);
            }
            Ok(())
        }
        Err(crate::proxy_lifecycle::StartError::OrphanedPort { port, owner_pid: _, reason: _ }) => {
            // Preserve legacy error string so e2e tests match.
            Err(format!(
                "address {} is already in use by another process.\n  \
                 Stop the other listener or change listen.port in {}.\n  \
                 Check: {}",
                listen_addr_for_msg,
                resolve_config(config)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<config>".into()),
                crate::proxy_proc::port_inspect_command(port),
            )
            .into())
        }
        Err(crate::proxy_lifecycle::StartError::ChildDiedAtStartup { stderr_log }) => {
            let port: u16 = listen_addr_for_msg
                .rsplit(':')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(27200);
            Err(format!(
                "aikey-proxy exited shortly after starting.\n  \
                 Likely cause: address {} is already in use by another process, or the config is invalid.\n  \
                 Check:  {}\n  \
                 Logs:   {}",
                listen_addr_for_msg,
                crate::proxy_proc::port_inspect_command(port),
                stderr_log.display()
            )
            .into())
        }
        Err(e) => Err(format!("{e}").into()),
    }
}

/// Foreground start path. Behaves like `aikey proxy start` but inherits
/// stdout/stderr and blocks until the proxy exits.
///
/// **Round 7 review fix (HIGH, Finding 2)**: previously this path
/// wrote only the pidfile, so Layer 1 classified the running proxy as
/// `OrphanedPort + LegacyPidfileNoSidecar` and other shells could not
/// `aikey proxy stop / restart` it. Now it shares
/// `persist_ownership_files` with the detached path, so foreground
/// instances are first-class members of the lifecycle state machine.
///
/// **Round 9 review fix (MEDIUM, Finding 3)**: previously the foreground
/// path explicitly skipped Layer 2's lifecycle lock — meaning a
/// concurrent `aikey proxy stop / restart / start` from another shell
/// could race with foreground startup (e.g., another shell stop+start
/// could end up signalling our just-spawned PID before our
/// `persist_ownership_files` returns). The lock is now held across the
/// entire critical section: Layer-1 state check → spawn → persist
/// ownership files. After persist completes the lock is released and
/// the foreground proxy lives independently for its full session,
/// matching the detached-mode lock semantics (the lock serializes
/// lifecycle *transitions*, not the running-proxy lifetime).
///
/// Cleanup on exit removes BOTH pidfile and sidecar in reverse order.
/// Cleanup on Ctrl-C / panic is best-effort: we don't install a Drop
/// guard around `child.wait()` because the foreground proxy is
/// expected to outlive the CLI process for its full session — the
/// next `aikey proxy *` invocation will see `Crashed` if the user
/// SIGINTs the CLI but the proxy keeps running, or `Stopped` if
/// they're both gone.
fn handle_start_foreground(
    config: Option<&str>,
    password: &SecretString,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::proxy_lifecycle::{
        acquire_lifecycle_lock, best_effort_remove, meta_path as lifecycle_meta_path,
        persist_ownership_files, pid_path as lifecycle_pid_path,
    };
    use crate::proxy_state::{proxy_state, ProxyState};

    let config_path = resolve_config(config)?;
    let listen_addr = proxy_listen_addr(Some(&config_path));

    // **Round 9 fix #3**: acquire lifecycle lock for the spawn +
    // persist critical section. Released right after persist returns;
    // the foreground proxy then lives independently of the lock.
    let _lock = acquire_lifecycle_lock().map_err(|_| {
        "another aikey proxy command is in flight; retry shortly".to_string()
    })?;

    // Layer 1 is the source of truth for "is something already there?"
    // — it covers PID-recycle / OrphanedPort cases that the old
    // `read_pid + process_alive` could not.
    match proxy_state(&listen_addr) {
        ProxyState::Running { pid, listen_addr: addr, .. } => {
            eprintln!("proxy already running (pid: {pid})");
            eprintln!("listen: http://{addr}");
            return Ok(());
        }
        ProxyState::Unresponsive { pid, port } => {
            return Err(format!(
                "previous aikey-proxy (pid: {pid}) is unresponsive on port {port}.\n  \
                 Run `aikey proxy stop` (or restart) before starting a new instance.",
            )
            .into());
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            return Err(format!(
                "cannot start in foreground: port {port} is owned by something \
                 we cannot manage ({})",
                reason.hint(port, owner_pid)
            )
            .into());
        }
        ProxyState::Crashed { stale_pid: _ } => {
            // Crashed cleanup happens here while we hold the lock so
            // no other CLI can race in between cleanup and spawn.
            if let Ok(p) = lifecycle_pid_path() {
                best_effort_remove(&p);
            }
            if let Ok(p) = lifecycle_meta_path() {
                best_effort_remove(&p);
            }
        }
        ProxyState::Stopped => {}
    }

    let proxy_bin = find_proxy_binary()?;

    eprintln!("Starting aikey-proxy...");
    eprintln!("  config: {}", config_path.display());
    eprintln!("  binary: {}", proxy_bin.display());

    let mut cmd = Command::new(&proxy_bin);
    cmd.arg("--config").arg(&config_path);

    match crate::proxy_env::read_proxy_env() {
        Ok(env_map) if !env_map.is_empty() => {
            let keys: Vec<&str> = env_map.keys().map(|k| k.as_str()).collect();
            eprintln!("  proxy.env: {} entries [{}]", env_map.len(), keys.join(", "));
            for (k, v) in &env_map {
                cmd.env(k, v);
            }
        }
        Ok(_) => {}
        Err(e) => {
            return Err(format!(
                "Failed to parse ~/.aikey/proxy.env: {}\n\
                 Fix the file or remove it, then retry.",
                e
            ).into());
        }
    }

    cmd.env("AIKEY_MASTER_PASSWORD", password.expose_secret());

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let mut child = cmd.spawn()
        .map_err(|e| format!("failed to spawn aikey-proxy: {}", e))?;
    let pid = child.id();

    // Persist BOTH ownership anchor files so the proxy is recognized
    // by Layer 1 as `Running` (not `LegacyPidfileNoSidecar`).
    if let Err(e) = persist_ownership_files(pid, &proxy_bin, &config_path, &listen_addr) {
        // Spawn succeeded but we can't anchor ownership — the proxy
        // would otherwise be unmanageable from other shells. Kill the
        // child to avoid leaving an unowned instance.
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("failed to persist ownership files: {e}").into());
    }

    if let Ok(seq) = crate::storage::get_vault_change_seq() {
        let _ = crate::storage::set_proxy_loaded_seq(seq);
    }

    // Release the lifecycle lock now that ownership files are written.
    // The foreground proxy continues running independently; other
    // shells' `aikey proxy stop / restart / status` see it as a
    // first-class managed instance via the sidecar meta.
    drop(_lock);

    // **Round-15 install-script fix #1**: forward SIGTERM / SIGINT
    // from this CLI to the spawned proxy child. Critical for
    // service-managed deployments (systemd Type=simple, launchd):
    // the service manager signals US (the parent CLI), expecting
    // the whole service tree to shut down. Without forwarding, the
    // CLI would die from default SIGTERM handling and the proxy
    // would be orphaned (PPID=1) — service manager would then
    // restart, the new instance would see OrphanedPort, and the
    // service would fail to recover.
    //
    // ctrlc 3.x supports installing a single global handler. We
    // capture child PID into a local closure context. Any
    // subsequent installation (also rare in CLI-shell contexts)
    // overwrites the previous handler, which is acceptable here:
    // the foreground proxy mode is the ONE long-running CLI command
    // that needs signal forwarding, so first-installation-wins is
    // fine for our model.
    let child_pid_for_signal = pid;
    let _ = ctrlc::set_handler(move || {
        // Forward SIGTERM to the child. Best-effort: if the child is
        // already gone, libc::kill returns ESRCH which we silently
        // ignore. We do NOT exit the parent ourselves — child.wait()
        // will return naturally once the proxy completes shutdown,
        // and the cleanup path below runs as designed.
        unsafe {
            libc::kill(child_pid_for_signal as libc::pid_t, libc::SIGTERM);
        }
    });

    let status = child.wait()?;

    // Reverse order of write: pidfile first, sidecar second
    // (mirrors StartCleanupGuard's invariant — the read path's worst
    // intermediate state is "sidecar but no pidfile" = Stopped, which
    // is harmless. The opposite ("pidfile but no sidecar"
    // = LegacyPidfileNoSidecar) blocks subsequent management.)
    if let Ok(p) = lifecycle_pid_path() {
        best_effort_remove(&p);
    }
    if let Ok(p) = lifecycle_meta_path() {
        best_effort_remove(&p);
    }
    if !status.success() {
        return Err(format!("aikey-proxy exited with status: {}", status).into());
    }
    Ok(())
}

/// Stop the proxy synchronously, honoring the 30s graceful drain
/// contract aligned with `srv.Shutdown(30 * time.Second)` in the proxy
/// binary. Delegates to Layer 2 [`crate::proxy_lifecycle::stop_proxy`]
/// which handles the lifecycle lock, identity/ownership verification,
/// SIGTERM-then-SIGKILL escalation, and pidfile + sidecar cleanup.
pub fn handle_stop() -> Result<(), Box<dyn std::error::Error>> {
    use crate::proxy_lifecycle::{stop_proxy, StopError, DEFAULT_STOP_TIMEOUT};

    // Capture pre-stop state so we can still print "proxy not running"
    // for the no-pidfile case. (stop_proxy returns Ok silently for
    // already-stopped — we want a user-visible line.)
    let was_running_pid = read_pid().filter(|&pid| process_alive(pid));

    // Round-6 review fix #3: pass the configured listen_addr explicitly
    // so the stop loop probes the correct port even when the user has
    // customised it in `aikey-proxy.yaml`.
    let listen_addr = proxy_listen_addr(None);

    match stop_proxy(&listen_addr, DEFAULT_STOP_TIMEOUT, |s| eprintln!("{s}")) {
        Ok(()) => {
            match was_running_pid {
                Some(pid) => eprintln!("proxy stopped (pid: {})", pid),
                None => eprintln!("proxy not running"),
            }
            Ok(())
        }
        Err(StopError::NotOurs { port, owner_pid, reason }) => {
            // **Round 7 review fix (MEDIUM)**: previously this branch
            // returned Ok(()) so scripts that piped `stop && start`
            // wouldn't break — but that hid a critical truth from
            // automation: "stop succeeded" must mean "the proxy that
            // was there is gone". Returning Ok(()) when we provably
            // did NOT stop anything is dishonest and violates the
            // synchronous-stop contract introduced in Round 2.
            //
            // Now we return Err so the exit code is non-zero. Scripts
            // that want the old "noop = ok" behaviour can wrap with
            // `|| true` or check the specific error message. The error
            // is still actionable: it tells the user which PID owns
            // the port and why we wouldn't touch it.
            Err(format!(
                "{}",
                StopError::NotOurs { port, owner_pid, reason }
            )
            .into())
        }
        Err(e) => Err(format!("{e}").into()),
    }
}

pub fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    for line in status_rows() {
        println!("{}", line);
    }
    Ok(())
}

/// Returns the Gateway status as a list of display rows (no box frame).
/// Used by both `aikey proxy status` (plain) and `aikey status` (boxed overview).
///
/// **Round 7 review fix (MEDIUM, Findings 3 + 4)**: rewritten to use
/// Layer 1's `compute_proxy_state` as the single source of truth.
/// Previously this function:
/// 1. Used PID-only `process_alive` which could not distinguish a real
///    aikey-proxy from a PID-recycled unrelated process (Round 4 / 5
///    safety gap).
/// 2. Mutated disk in a read path (`fs::remove_file(pid_path)`) and
///    only cleaned the pidfile — leaving an orphan sidecar behind.
///    File cleanup is a Layer 2 responsibility; reads must be pure.
///
/// The new flow renders each `ProxyState` variant directly. Crashed
/// state's eventual cleanup happens on the next `start_proxy`, not in
/// `status` — keeping read and write paths cleanly separated.
pub fn status_rows() -> Vec<String> {
    use crate::proxy_state::{proxy_state, ProxyState};

    let mut rows: Vec<String> = Vec::new();
    let addr = proxy_listen_addr(None);
    match proxy_state(&addr) {
        ProxyState::Stopped => {
            rows.push("status:  stopped".to_string());
            rows.push("hint:    run `aikey proxy start` to start".to_string());
        }
        ProxyState::Crashed { stale_pid } => {
            rows.push(format!("status:  stopped (stale pid file, was: {stale_pid})"));
            rows.push("hint:    run `aikey proxy start` to clean up and restart".to_string());
        }
        ProxyState::Running { pid, listen_addr, .. } => {
            rows.push("status:  running (healthy)".to_string());
            rows.push(format!("pid:     {pid}"));
            rows.push(format!("listen:  http://{listen_addr}"));
            match proxy_vault_state() {
                ProxyVaultState::Current => rows.push("vault sync: current".to_string()),
                ProxyVaultState::Stale => {
                    rows.push("vault sync: stale".to_string());
                    rows.push("hint:    restart proxy to apply new keys: aikey proxy restart".to_string());
                }
                ProxyVaultState::Unknown => {}
            }
        }
        ProxyState::Unresponsive { pid, port } => {
            rows.push("status:  unresponsive (port bound, /health not responding)".to_string());
            rows.push(format!("pid:     {pid}"));
            rows.push(format!("listen:  http://127.0.0.1:{port}"));
            rows.push("hint:    could be initializing or hung — wait or `aikey proxy restart`".to_string());
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            rows.push("status:  orphaned (port held by something we cannot manage)".to_string());
            if let Some(owner) = owner_pid {
                rows.push(format!("owner:   pid {owner}"));
            }
            rows.push(format!("hint:    {}", reason.hint(port, owner_pid)));
        }
    }
    rows
}

/// Restart the proxy as a single atomic operation under one lifecycle
/// lock acquisition. Why hard restart instead of graceful reload:
/// restart must reload proxy.env (process environment variables),
/// which can only take effect via a new process. Graceful reload only
/// re-reads vault/YAML config within the existing process.
///
/// Delegates to Layer 2 [`crate::proxy_lifecycle::restart_proxy`] for
/// the actual stop+start under shared lock; this shell builds the
/// StartOptions and translates errors to legacy strings.
pub fn handle_restart(config: Option<&str>, password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    use crate::proxy_lifecycle::{restart_proxy, RestartError, StartError, StopError, StderrTarget, DEFAULT_STOP_TIMEOUT};

    let stderr_target = StderrTarget::Log(startup_log_path());
    let (opts, env_keys) = build_start_options(config, stderr_target)?;

    eprintln!("Restarting aikey-proxy...");
    eprintln!("  config: {}", opts.config_path.display());
    eprintln!("  binary: {}", opts.binary_path.display());
    if !env_keys.is_empty() {
        eprintln!("  proxy.env: {} entries [{}]", env_keys.len(), env_keys.join(", "));
    }

    match restart_proxy(password, opts, DEFAULT_STOP_TIMEOUT, |s| eprintln!("{s}")) {
        Ok(state) => {
            eprintln!(
                "\x1b[32m✓\x1b[0m aikey-proxy running (pid: {}, http://{})",
                state.pid, state.listen_addr
            );
            if let Ok(seq) = crate::storage::get_vault_change_seq() {
                let _ = crate::storage::set_proxy_loaded_seq(seq);
            }
            Ok(())
        }
        Err(RestartError::LockBusy) => Err("another aikey proxy command is in flight; retry shortly".into()),
        Err(RestartError::Stop(StopError::NotOurs { .. })) => {
            Err("cannot restart: existing port owner is not our managed proxy (see `aikey proxy status`)".into())
        }
        Err(RestartError::Stop(e)) => Err(format!("stop phase: {e}").into()),
        Err(RestartError::Start(StartError::OrphanedPort { port, .. })) => Err(format!(
            "address 127.0.0.1:{port} is in use by another process. \
             Stop the other listener or change listen.port; check with: {}",
            crate::proxy_proc::port_inspect_command(port),
        )
        .into()),
        Err(RestartError::Start(e)) => Err(format!("start phase: {e}").into()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `~/.aikey/run/proxy.pid`.
fn pid_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("cannot determine home directory")?;
    Ok(home.join(".aikey").join("run").join(PID_FILENAME))
}

fn read_pid() -> Option<u32> {
    let path = pid_path().ok()?;
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

// `write_pid` removed in Round 7 review fix #2 — all writes now go
// through `proxy_lifecycle::persist_ownership_files`, which atomically
// writes BOTH pidfile and sidecar meta in the correct order. Direct
// pidfile writes from outside Layer 2 are a layering violation that
// produces `LegacyPidfileNoSidecar` orphans.

/// Check whether a process with the given PID is alive.
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) returns 0 if the process exists.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        ret == 0
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 || h == INVALID_HANDLE_VALUE as isize {
            return false;
        }
        unsafe { CloseHandle(h) };
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Send SIGTERM / TerminateProcess to the given PID.
///
/// `#[allow(dead_code)]`: TRANSITIONAL Stage 3 — `handle_stop` migrated
/// to Layer 2 [`crate::proxy_lifecycle::stop_proxy`] which has its own
/// `kill_pid_signal` helper. This local fn remains as a transitional
/// utility and will be removed during the Stage 5 cleanup pass when
/// the deprecated `is_proxy_running` / `is_proxy_listening` are also
/// retired.
#[allow(dead_code)]
fn terminate_process(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if ret != 0 {
            return Err(format!("kill({}) failed: {}", pid, io::Error::last_os_error()).into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows_sys::Win32::Foundation::CloseHandle;
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if h == 0 {
            return Err(format!("OpenProcess({}) failed", pid).into());
        }
        unsafe { TerminateProcess(h, 1); CloseHandle(h); }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(format!("terminate_process not supported on this platform (pid: {})", pid).into())
    }
}

/// Non-blocking TCP connect to check if the proxy port is reachable.
fn port_reachable(addr: &str, timeout: Duration) -> bool {
    TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| PROXY_HEALTH_ADDR_DEFAULT.parse().unwrap()),
        timeout,
    ).is_ok()
}

/// Quick connectivity check for overseas AI providers.
/// Called in a background thread after proxy start. Only prints warnings
/// for providers that are unreachable — no output when all is fine.
fn check_overseas_connectivity() {
    const PROVIDERS: &[(&str, &str)] = &[
        ("OpenAI",    "api.openai.com:443"),
        ("Anthropic", "api.anthropic.com:443"),
    ];
    let timeout = Duration::from_secs(5);
    let mut unreachable = Vec::new();
    for &(name, addr) in PROVIDERS {
        if let Ok(sock_addr) = addr.to_socket_addrs().and_then(|mut it| {
            it.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no addr"))
        }) {
            if TcpStream::connect_timeout(&sock_addr, timeout).is_err() {
                unreachable.push(name);
            }
        } else {
            unreachable.push(name);
        }
    }
    if !unreachable.is_empty() {
        eprintln!();
        eprintln!("  \x1b[33m[warn]\x1b[0m  Cannot reach: {}",
            unreachable.join(", "));
        eprintln!("  \x1b[33m[warn]\x1b[0m  If you use these providers, configure HTTP_PROXY / HTTPS_PROXY");
        eprintln!("          and restart the proxy: aikey proxy restart");
    }
}

/// Locate the `aikey-proxy` binary using the following priority order:
/// 1. `AIKEY_PROXY_BIN` env var — explicit override for CI / custom installs
/// 2. Same directory as the running `aikey` binary — co-installed layout
/// 3. `~/.aikey/bin/aikey-proxy` — user-local install
/// 4. System `PATH` — standard install via `make install`
fn find_proxy_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let bin_name = if cfg!(windows) { "aikey-proxy.exe" } else { "aikey-proxy" };

    // 1. Explicit override via env var.
    if let Ok(val) = std::env::var("AIKEY_PROXY_BIN") {
        let p = PathBuf::from(val);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("AIKEY_PROXY_BIN is set but binary not found: {}", p.display()).into());
    }

    // 2. Same directory as the current `aikey` binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(bin_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // 3. ~/.aikey/bin/aikey-proxy
    if let Some(home) = dirs::home_dir() {
        let candidate = home.join(".aikey").join("bin").join(bin_name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 4. System PATH lookup.
    let which_cmd = if cfg!(windows) { "where" } else { "which" };
    if let Ok(out) = Command::new(which_cmd).arg(bin_name).output() {
        if out.status.success() {
            let path_str = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !path_str.is_empty() {
                return Ok(PathBuf::from(path_str));
            }
        }
    }

    Err("aikey-proxy not found. Searched: same dir as aikey, ~/.aikey/bin/, system PATH. \
         Run `make install` in the aikey-proxy project, or set AIKEY_PROXY_BIN.".into())
}

/// Verify current project / env / provider connectivity end-to-end.
///
/// Checks in order:
/// 1. Vault snapshot staleness (bail early if stale — results would be misleading)
/// 2. Vault is accessible (validated by caller before this function is called)
/// 3. Project config discovery
/// 4. Active logical environment
/// 5. Provider resolution from config
/// 6. Proxy health (auto-starts in background if not running)
pub fn handle_verify(password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    use crate::proxy_state::{proxy_state, ProxyState};

    // **Round 9 review fix (MEDIUM, Finding 2)**: was `is_proxy_running()`
    // (PID-only) + hardcoded PROXY_HEALTH_ADDR_DEFAULT port probe — which
    // diverged from the user's configured listen address AND could not
    // distinguish OrphanedPort / Unresponsive from "ours, healthy".
    // Migrated to Layer 1 `proxy_state(&listen_addr)` so verify shares
    // the same single-source-of-truth as `aikey proxy status`.
    let listen_addr = proxy_listen_addr(None);
    let initial_state = proxy_state(&listen_addr);

    // Step 1: bail early if the proxy is running on a stale vault snapshot.
    // (Stale check only meaningful when the proxy is actually ours.)
    if matches!(initial_state, ProxyState::Running { .. })
        && proxy_vault_state() == ProxyVaultState::Stale
    {
        eprintln!("proxy is using an outdated vault snapshot.");
        eprintln!("restart proxy to apply new keys: aikey proxy restart");
        eprintln!("Then re-run: aikey proxy verify");
        return Err("verify aborted: proxy vault snapshot is stale".into());
    }

    let mut failed = false;

    // Step 2: vault already validated by caller.
    println!("vault:    ok");

    // Step 2: project config.
    let config = crate::config::ProjectConfig::discover()
        .ok()
        .flatten()
        .map(|(_, cfg)| cfg);

    let project_name = config.as_ref()
        .map(|c| c.project.name.as_str())
        .unwrap_or("(no project config)");
    println!("project:  {}", project_name);

    // Step 3: current env.
    let current_env = crate::global_config::get_current_env()
        .ok()
        .flatten()
        .unwrap_or_else(|| "dev".to_string());
    println!("env:      {}", current_env);

    // Step 4: provider from config.
    let provider = config.as_ref().and_then(|cfg| {
        // Prefer envMappings for the active env, fall back to providers map.
        if let Some(env_map) = cfg.env_mappings.get(&current_env) {
            env_map.values().next().map(|m| m.provider.clone())
        } else {
            cfg.providers.keys().next().cloned()
        }
    });

    match &provider {
        Some(p) => println!("provider: {}", p),
        None => {
            println!("provider: (not configured)");
            println!("hint:     run `aikey project map` to configure a provider for this env");
        }
    }

    // Step 5: proxy health — auto-start if needed.
    // Use the SAME initial_state from Step 1 to avoid TOCTOU.
    match initial_state {
        ProxyState::Running { .. } => {
            println!("proxy:    running (healthy)");
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            // Don't auto-start — we'd OrphanedPort-error. Surface the
            // diagnostic so the user can resolve manually.
            println!("proxy:    orphaned (port {port} held by something we cannot manage)");
            println!("hint:     {}", reason.hint(port, owner_pid));
            failed = true;
        }
        ProxyState::Unresponsive { pid, port } => {
            println!("proxy:    unresponsive (pid {pid}, port {port})");
            println!("hint:     run `aikey proxy restart` to recover");
            failed = true;
        }
        ProxyState::Crashed { .. } | ProxyState::Stopped => {
            // Crashed cleans its stale files inside start_proxy_locked.
            eprintln!("proxy not running — attempting to start...");
            match handle_start(None, true, password) {
                Ok(_) => {
                    // Re-check via Layer 1 (avoid hardcoded probe).
                    std::thread::sleep(Duration::from_millis(300));
                    if matches!(proxy_state(&listen_addr), ProxyState::Running { .. }) {
                        println!("proxy:    running (healthy)");
                    } else {
                        println!("proxy:    unreachable after start attempt");
                        println!("hint:     run `aikey proxy status` to debug");
                        failed = true;
                    }
                }
                Err(e) => {
                    println!("proxy:    failed to start ({})", e);
                    println!("hint:     run `aikey proxy start` to troubleshoot");
                    failed = true;
                }
            }
        }
    }

    println!();
    if failed {
        println!("result:   failed");
        return Err("verification failed — check hints above".into());
    }

    println!("result:   ok");
    Ok(())
}

/// Lightweight proxy guard for use by `aikey run` and other commands.
///
/// Checks whether `aikey-proxy` is running and reachable. If not, silently
/// starts it in the background using the given master password. Returns `true`
/// if the proxy is (or becomes) reachable, `false` if startup failed.
///
/// Designed to be transparent to end users: no output on the happy path.
///
/// **Round 7 review fix (MEDIUM, Finding 3)**: was previously a
/// PID-only `process_alive + port_reachable` check that could not
/// distinguish a real aikey-proxy from a PID-recycled unrelated
/// process or a different aikey-proxy instance. Migrated to
/// `compute_proxy_state` so the guard's "is it ours?" decision uses
/// the same identity + ownership rules as `start_proxy` /
/// `stop_proxy`. OrphanedPort / Unresponsive states correctly route
/// to "do not auto-start; surface diagnostic" rather than silently
/// trying to re-spawn over a foreign owner.
pub fn proxy_guard(password: &SecretString) -> bool {
    use crate::proxy_state::{proxy_state, ProxyState};

    let health_addr = proxy_listen_addr(None);

    match proxy_state(&health_addr) {
        ProxyState::Running { .. } => {
            // Warn once if the proxy is serving from a stale vault snapshot.
            if proxy_vault_state() == ProxyVaultState::Stale {
                eprintln!("[aikey] proxy is using an outdated vault snapshot.");
                eprintln!("[aikey] restart proxy to apply new keys: aikey proxy restart");
            }
            return true;
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            // Layer 1 says the port is held by something we cannot
            // manage — auto-starting would either OrphanedPort-error
            // out or, worse, race with whoever owns it. Bail with a
            // clear diagnostic so the user can resolve manually.
            eprintln!("[aikey] cannot auto-start proxy: port {port} is owned by something \
                       we cannot manage ({})", reason.hint(port, owner_pid));
            eprintln!("[aikey] hint: run `aikey proxy status` for details");
            return false;
        }
        ProxyState::Unresponsive { pid, port } => {
            eprintln!("[aikey] previous aikey-proxy (pid: {pid}) is unresponsive on port {port}");
            eprintln!("[aikey] attempting restart (Layer 2 will SIGTERM/SIGKILL it first)...");
            // Fall through to the "start" path below, which will
            // route through start_proxy_locked → terminate_unresponsive
            // (Round 7 fix #1).
        }
        ProxyState::Crashed { .. } | ProxyState::Stopped => {
            // Need a (re)start.
        }
    }

    // Proxy not running (or stale state we should reset) — start silently in background.
    eprintln!("[aikey] proxy not running, starting in background...");
    match handle_start(None, true, password) {
        Ok(_) => {
            // Poll up to 5 s for the port to open (matches CI test timeout).
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let up = loop {
                if port_reachable(&health_addr, Duration::from_millis(300)) {
                    break true;
                }
                if std::time::Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(300));
            };
            if !up {
                eprintln!("[aikey] warning: proxy started but port {} unreachable", health_addr);
                eprintln!("[aikey] hint:    run `aikey proxy status` to debug");
            }
            up
        }
        Err(e) => {
            eprintln!("[aikey] warning: could not start proxy: {}", e);
            eprintln!("[aikey] hint:    run `aikey proxy start` to troubleshoot");
            false
        }
    }
}

/// Resolve the proxy config file path in priority order:
/// 1. Explicit `--config` argument
/// 2. `AIKEY_PROXY_CONFIG` environment variable
/// 3. Current working directory (`aikey-proxy.yaml`)
/// 4. `~/.aikey/config/aikey-proxy.yaml`
fn resolve_config(explicit: Option<&str>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()).into());
        }
        return Ok(path);
    }

    // AIKEY_PROXY_CONFIG env var.
    if let Ok(env_val) = std::env::var("AIKEY_PROXY_CONFIG") {
        let path = PathBuf::from(&env_val);
        if path.exists() {
            return Ok(path);
        }
        // Warn and fall back instead of failing hard, so the proxy can still start.
        // Stage 2.2 windows-compat: show the actual resolved path; if the home
        // resolver degrades, fall back to a Windows-friendly display string.
        let default_path = crate::commands_account::resolve_aikey_dir()
            .join("config")
            .join(DEFAULT_CONFIG_NAME)
            .display()
            .to_string();
        eprintln!("Warning: AIKEY_PROXY_CONFIG not found: {}", path.display());
        eprintln!("         Falling back to default: {}", default_path);
    }

    // Current working directory.
    let cwd_cfg = PathBuf::from(DEFAULT_CONFIG_NAME);
    if cwd_cfg.exists() {
        return Ok(cwd_cfg);
    }

    // ~/.aikey/config/aikey-proxy.yaml
    if let Some(home) = dirs::home_dir() {
        let home_cfg = home.join(".aikey").join("config").join(DEFAULT_CONFIG_NAME);
        if home_cfg.exists() {
            return Ok(home_cfg);
        }
    }

    Err("aikey-proxy.yaml not found. Searched: current directory, ~/.aikey/config/. \
         Use --config to specify explicitly.".into())
}

// ---------------------------------------------------------------------------
// Public diagnostic helpers (used by `aikey doctor`)
// ---------------------------------------------------------------------------

/// Returns the proxy listen address (e.g. `127.0.0.1:27200`).
pub fn doctor_proxy_addr() -> String {
    proxy_listen_addr(None)
}

/// Returns the proxy listen port from config, falling back to 27200.
pub fn proxy_port() -> u16 {
    let addr = proxy_listen_addr(None);
    addr.rsplit(':').next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(27200)
}

/// Lightweight post-operation check: prints a warning if the proxy is not
/// in `Running` state. Does NOT attempt to auto-start — just informs the user.
///
/// Intended to be called at the end of commands that depend on the proxy
/// (`list`, `use`, `run`, `exec`) so the user knows why requests may fail
/// after an unexpected proxy termination (e.g. `kill -9`).
///
/// **Round 10 review fix (MEDIUM, Finding 2)**: was `port_reachable()`
/// (port-open == healthy), which:
///   - missed `Unresponsive` (port bound but `/health` 503 — most often
///     when the proxy is mid-init or vault-decrypt has hung); and
///   - missed `OrphanedPort` (port held by an external program OR a
///     different aikey-proxy instance — `port_reachable` returns true
///     for both).
/// Now uses `proxy_state` directly so each non-Running variant gets a
/// distinct, actionable warning, matching the diagnostic vocabulary
/// `aikey proxy status` already uses.
pub fn warn_if_proxy_down() {
    use crate::proxy_state::{proxy_state, ProxyState};

    let addr = proxy_listen_addr(None);
    match proxy_state(&addr) {
        ProxyState::Running { .. } => {} // happy path: no warning
        ProxyState::Stopped | ProxyState::Crashed { .. } => {
            eprintln!();
            eprintln!("  \x1b[33m\u{26A0}\x1b[0m  Proxy is not running. Start it with: aikey proxy start");
        }
        ProxyState::Unresponsive { pid, port } => {
            eprintln!();
            eprintln!("  \x1b[33m\u{26A0}\x1b[0m  Proxy (pid {pid}) is unresponsive on port {port} \
                       (port bound, /health failing). Try: aikey proxy restart");
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            eprintln!();
            eprintln!("  \x1b[33m\u{26A0}\x1b[0m  Port {port} is held by something we cannot manage \
                       — {}", reason.hint(port, owner_pid));
            eprintln!("       Run `aikey proxy status` for details.");
        }
    }
}

/// Returns `(is_running, pid)` — Layer 1 wrapper for doctor / dashboard
/// callers that need a 2-tuple summary.
///
/// **Round 9 review fix (MEDIUM, Finding 2)**: was `read_pid +
/// process_alive + port_reachable`, which gave doctor a third
/// independent definition of "running" — diverging from `status_rows`
/// (already on `proxy_state`) and from Layer 2's `start_proxy` /
/// `stop_proxy` decisions. Migrated so doctor sees the same
/// identity + ownership-verified `Running` state as everyone else.
///
/// Mapping:
/// - `Running { pid, .. }` → `(true, Some(pid))` (the only "ours, healthy" case)
/// - `Unresponsive { pid, .. }` → `(false, Some(pid))` (port bound but /health bad)
/// - `Crashed { stale_pid }` → `(false, Some(stale_pid))` (pidfile points at dead pid)
/// - `OrphanedPort { owner_pid, .. }` → `(false, owner_pid)` (port held by foreign owner)
/// - `Stopped` → `(false, None)`
pub fn doctor_proxy_status() -> (bool, Option<u32>) {
    use crate::proxy_state::{proxy_state, ProxyState};
    let addr = proxy_listen_addr(None);
    match proxy_state(&addr) {
        ProxyState::Running { pid, .. } => (true, Some(pid)),
        ProxyState::Unresponsive { pid, .. } => (false, Some(pid)),
        ProxyState::Crashed { stale_pid } => (false, Some(stale_pid)),
        ProxyState::OrphanedPort { owner_pid, .. } => (false, owner_pid),
        ProxyState::Stopped => (false, None),
    }
}
