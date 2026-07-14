//! Local-server probe — shared discovery, health, and status helpers.
//!
//! Why this module exists:
//!   Three commands need to know "is aikey-local-server running, on what
//!   port, with what vault state?" — `aikey status`, `aikey doctor`,
//!   `aikey web` (plus `aikey import` as the original consumer). Before
//!   this extraction the helpers lived in `commands_import.rs` and
//!   `doctor` hard-coded port 8090 with a silent-skip on failure. That
//!   drift caused two real bugs: (1) `aikey web` would open a browser
//!   pointing at a dead URL when the service was down, (2) `aikey doctor`
//!   missed a stopped local-server entirely on non-default ports.
//!
//! Port discovery — single source of truth:
//!   `~/.aikey/config/control-trial.yaml`'s `listen:` field is the same
//!   file local-server reads at startup, so any user edit propagates here.
//!   A localhost `controlPanelUrl` in `config.json` is accepted as a
//!   fallback for users who deleted the yaml. Remote URLs are never
//!   accepted as a local port source — that would silently retarget local
//!   probes at a remote team server, a different feature.
//!
//! Edition awareness:
//!   - Personal / Trial: yaml exists → port → probe works.
//!   - Production: no local-server on the user's host, yaml absent →
//!     edition-aware error pointing at the remote Control Panel URL.

use std::fs;
use std::path::{Path, PathBuf};

// Surfaced as part of error messages so scripts can grep for it.
pub const ERR_I_CLI_NOT_AVAILABLE: &str = "I_CLI_NOT_AVAILABLE";

/// Candidate YAML config paths the local-server may be using.
///
/// Personal edition renders to `control.yaml` (post 2026-05-13 binary-
/// isolation refactor, commit a928cd4); Trial edition keeps the legacy
/// `control-trial.yaml`. The CLI doesn't know edition at probe time
/// (would require an install-state.json read every call), so we try
/// the new name first and fall back to the legacy name — whichever
/// exists is the active config.
///
/// Order matters:
/// - `control.yaml` first → Personal hosts return immediately (no
///   useless stat of legacy path)
/// - `control-trial.yaml` fallback → Trial hosts find their config;
///   also covers pre-rename Personal users who haven't run the new
///   installer yet (legacy file not yet mv'd)
///
/// Adding a new edition's config filename → add one entry here. Bugfix
/// 20260524-personal-install-console-failed-to-start.md captures the
/// scope-fidelity lesson: a928cd4 renamed the file but missed updating
/// hardcoded read paths; the list shape makes future renames a single-
/// point edit.
const YAML_CONFIG_REL_CANDIDATES: &[&str] = &[
    ".aikey/config/control.yaml",       // Personal (post 2026-05-13)
    ".aikey/config/control-trial.yaml", // Trial (legacy name preserved)
];
const JSON_CONFIG_REL: &str = ".aikey/config/config.json";

/// Canonical default listen port for Personal / Trial local-server when
/// no YAML config + no localhost-flavored JSON `controlPanelUrl` can be
/// resolved. Both installer scripts (`local-install.sh`,
/// `trial-install.sh`) render `listen: 127.0.0.1:8090` into the YAML and
/// the local-server binary itself defaults to 8090 internally, so falling
/// back here is just the CLI matching what the binary would already pick.
///
/// Only used by `read_local_server_port_or_default()` — the strict
/// variant `read_local_server_port()` still errors out for Bulk Import
/// flows that want "not installed" semantics. Bugfix
/// 20260524-aikey-service-restart-web-port-undiscoverable.md.
pub const DEFAULT_PERSONAL_TRIAL_LOCAL_SERVER_PORT: u16 = 8090;

/// Which local web service is installed on this host.
///
/// Personal = `aikey-local-server` (per-user, no privilege).
/// Trial    = `aikey-full-trial` (system-wide on Linux, user-scope on macOS).
///
/// Why an enum vs free strings: every service-control call site needs
/// to dispatch on edition (different launchctl labels, different
/// systemctl scopes, different binaries). Centralising the choice in
/// one detector keeps the three-platform × two-edition matrix tractable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    Personal,
    Trial,
}

impl Edition {
    /// Human label used in CLI messages.
    pub fn label(self) -> &'static str {
        match self {
            Edition::Personal => "aikey-local-server",
            Edition::Trial => "aikey-trial-server",
        }
    }
}

/// Inspect `~/.aikey/install-state.json` and return the edition.
/// `None` means neither local-server nor full-trial is installed
/// (CLI-only Personal, Production, or no install state at all).
pub fn detect_edition() -> Option<Edition> {
    let home = crate::commands_account::resolve_user_home();
    let path = home.join(".aikey/install-state.json");
    let raw = fs::read_to_string(&path).ok()?;
    // strip_bom: shipped PS 5.1 trial installers wrote this file WITH a BOM
    // (encoding sweep 2026-07-07 H1) and serde rejects it — without the strip
    // a whole trial install reads as "not installed" here.
    let parsed: serde_json::Value = serde_json::from_str(crate::strip_bom(&raw)).ok()?;
    let components = parsed.get("installed_components")?.as_array()?;
    // Why Trial wins over local-server when both appear: trial-server
    // is a superset bundle that includes local-server's user-side
    // routes; on a trial host the running listener is full-trial, so
    // service-control commands must target that label, not the
    // never-started local-server one.
    let has_trial = components.iter().any(|c| c.as_str() == Some("full-trial"));
    if has_trial {
        return Some(Edition::Trial);
    }
    let has_local = components
        .iter()
        .any(|c| c.as_str() == Some("local-server"));
    if has_local {
        return Some(Edition::Personal);
    }
    None
}

// ── Public API ──────────────────────────────────────────────────────────

/// Resolve local-server's listen port from the canonical config file,
/// falling back to a localhost `controlPanelUrl` in `config.json`.
///
/// **Strict variant** — returns an edition-aware error (with
/// `I_CLI_NOT_AVAILABLE` prefix + Bulk-Import-flavored install hint) when
/// neither source yields a local port. Right semantic for the Bulk
/// Import flow ("user genuinely has no local-server, tell them how to
/// install"). **Wrong** for service-lifecycle / status / browse flows
/// where the caller already knows local-server is installed and just
/// needs a port to probe — use `read_local_server_port_or_default()`
/// there. Bugfix
/// 20260524-aikey-service-restart-web-port-undiscoverable.md.
pub fn read_local_server_port() -> Result<u16, String> {
    // Stage 2.1 windows-compat: route through the single home-resolver so
    // sandbox tests (HOME-override) and Windows (USERPROFILE-only) take
    // the same code path the rest of the CLI uses.
    let home = crate::commands_account::resolve_user_home();

    // BR-rc.5-58 fix: try each candidate YAML path in order. Personal's
    // control.yaml first (new name from 2026-05-13 binary-isolation),
    // control-trial.yaml fallback (Trial + pre-rename Personal hosts).
    for rel in YAML_CONFIG_REL_CANDIDATES {
        if let Some(port) = read_yaml_listen_port(&home.join(rel))? {
            return Ok(port);
        }
    }
    if let Some(port) = read_localhost_port_from_config_json(&home.join(JSON_CONFIG_REL)) {
        return Ok(port);
    }
    let remote_hint = read_remote_control_url(&home.join(JSON_CONFIG_REL));
    Err(build_bulk_import_unavailable_error(remote_hint))
}

/// Resolve local-server's listen port like `read_local_server_port()`,
/// but on discovery failure return the canonical default
/// (`DEFAULT_PERSONAL_TRIAL_LOCAL_SERVER_PORT`) **iff** install-state
/// reports local-server / full-trial as installed. Returns an error
/// only when local-server isn't installed at all — in which case the
/// caller had no business asking for its port anyway.
///
/// Why this exists (split from the strict variant):
/// `aikey service restart web`, `aikey status`, and the browse preflight
/// all happen on hosts that just spawned the local-server binary; the
/// binary internally defaults to 8090 and runs fine without the YAML
/// even existing. Forcing the CLI to error when YAML is missing is a
/// false-negative (BR-rc.5-47) that misleads users into thinking the
/// service failed. Bulk Import keeps the strict variant because its
/// semantic IS "user must have a real local-server install".
pub fn read_local_server_port_or_default() -> Result<u16, String> {
    match read_local_server_port() {
        Ok(port) => Ok(port),
        Err(strict_err) => {
            if is_local_server_installed() {
                Ok(DEFAULT_PERSONAL_TRIAL_LOCAL_SERVER_PORT)
            } else {
                Err(strict_err)
            }
        }
    }
}

/// HTTP probe of `<base>/health`. Returns Ok(()) on 2xx, Err with an
/// actionable platform-specific start hint otherwise.
pub fn probe_health(base: &str) -> Result<(), String> {
    let url = format!("{}/health", base);
    match ureq_get_with_timeout(&url, 1) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "{} local-server not reachable at {} ({}). Start it with:\n    {}",
            ERR_I_CLI_NOT_AVAILABLE,
            base,
            e,
            start_command_hint()
        )),
    }
}

/// Probe `<base>/api/user/vault/status` and return whether the vault is
/// unlocked. Err on unreachable / non-2xx — callers that only want
/// reachability can treat any Ok as "running".
pub fn probe_vault_status(base: &str) -> Result<bool, String> {
    let url = format!("{}/api/user/vault/status", base);
    let body = ureq_get_with_timeout(&url, 1)?;
    Ok(body.contains(r#""unlocked":true"#))
}

/// Single canonical user-facing command to start/stop/restart the
/// local web service. Now that `aikey web {start|stop|restart}` is
/// the supported entry point, every hint points at it — there's no
/// need to leak the underlying launchctl / nohup details. Reason:
/// local-install.sh and trial-install.sh both spawn the service
/// directly with `nohup` (only `aikey-proxy` is registered with
/// launchd/systemd), so a launchctl hint would not even work.
pub fn start_command_hint() -> String {
    "aikey web start".to_string()
}

/// User-facing hint for a specific service action. Always routes
/// through `aikey web <action>` for the same reason as
/// `start_command_hint`. Edition is accepted so the caller can
/// surface "which service" in surrounding text, but the command
/// itself is edition-agnostic — the CLI auto-detects.
pub fn service_command_hint(_edition: Edition, action: &str) -> String {
    format!("aikey web {}", action)
}

fn web_service_binary(edition: Edition) -> &'static str {
    match edition {
        Edition::Personal => "aikey-local-server",
        Edition::Trial => "aikey-full-trial",
    }
}

/// Whether this edition is supposed to have a local-server running on
/// the user's host. Reads `~/.aikey/install-state.json`'s
/// `installed_components`. True for Personal (with console) and Trial;
/// false for Personal CLI-only and Production. Used by callers that
/// need to decide whether a missing local-server is "ok" (Production)
/// or "actionable warning" (Personal/Trial with service stopped).
pub fn is_local_server_installed() -> bool {
    let home = crate::commands_account::resolve_user_home();
    let path = home.join(".aikey/install-state.json");
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed
        .get("installed_components")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .any(|c| matches!(c.as_str(), Some("local-server") | Some("full-trial")))
        })
        .unwrap_or(false)
}

/// Block until local-server's vault-status endpoint responds on `port`,
/// or `wait_for` elapses. Polls every 200 ms. Returns Ok on the first
/// successful response, Err with the elapsed time on timeout.
pub fn wait_for_reachable(port: u16, wait_for: std::time::Duration) -> Result<(), String> {
    let base = format!("http://127.0.0.1:{}", port);
    let deadline = std::time::Instant::now() + wait_for;
    while std::time::Instant::now() < deadline {
        if probe_vault_status(&base).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!(
        "local-server did not respond on port {} within {:?}",
        port, wait_for
    ))
}

/// Fire the platform-native start command for the local web service
/// (launchd / systemd / direct spawn). Edition-aware — Personal targets
/// `aikey-local-server`, Trial targets `aikey-full-trial`. Returns Ok
/// if the command exited 0, Err with diagnostic otherwise. Does NOT
/// wait for the service to come up — callers should follow with
/// `wait_for_reachable`.
pub fn spawn_start_command() -> Result<(), String> {
    let edition = detect_edition().unwrap_or(Edition::Personal);
    run_service_action(edition, ServiceAction::Start)
}

/// Stop the local web service. Edition-aware. See `spawn_start_command`.
pub fn spawn_stop_command() -> Result<(), String> {
    let edition = detect_edition().ok_or_else(|| {
        "neither aikey-local-server nor aikey-trial-server is installed".to_string()
    })?;
    run_service_action(edition, ServiceAction::Stop)
}

/// Restart the local web service. Edition-aware. See `spawn_start_command`.
pub fn spawn_restart_command() -> Result<(), String> {
    let edition = detect_edition().ok_or_else(|| {
        "neither aikey-local-server nor aikey-trial-server is installed".to_string()
    })?;
    run_service_action(edition, ServiceAction::Restart)
}

#[derive(Debug, Clone, Copy)]
enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    fn verb(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

// Why direct process management instead of launchctl / systemctl:
//   local-install.sh and trial-install.sh both start the web service
//   via plain `nohup ${BIN}/aikey-{local-server,full-trial} --config
//   ${CONFIG}/control-trial.yaml`. Neither installer registers a
//   launchd plist or systemd unit for the web service itself (only
//   `aikey-proxy` is registered). So any launchctl/systemctl-based
//   restart command would target a label that doesn't exist on the
//   user's host. The original `spawn_start_command` had this bug
//   silently — the auto-start prompt in `aikey web` was a no-op for
//   every Personal install. Fixing it here also fixes that.

fn run_service_action(edition: Edition, action: ServiceAction) -> Result<(), String> {
    match action {
        ServiceAction::Start => start_service(edition),
        ServiceAction::Stop => stop_service(),
        ServiceAction::Restart => {
            // Best-effort stop — don't fail restart if the service
            // wasn't running (a common state right after install).
            let _ = stop_service();
            // Brief gap so the listener actually releases the port
            // before we try to bind on it again.
            std::thread::sleep(std::time::Duration::from_millis(300));
            start_service(edition)
        }
    }
}

fn start_service(edition: Edition) -> Result<(), String> {
    // Idempotent: if the service is already healthy on its configured
    // port, skip the spawn — re-spawning would race the existing
    // process for the port and leave one of them broken.
    if let Ok(port) = read_local_server_port() {
        let base = format!("http://127.0.0.1:{}", port);
        if probe_health(&base).is_ok() {
            return Ok(());
        }
    }

    let home = crate::commands_account::resolve_user_home();
    let bin_name = web_service_binary(edition);
    #[cfg(target_os = "windows")]
    let bin_file = format!("{}.exe", bin_name);
    #[cfg(not(target_os = "windows"))]
    let bin_file = bin_name.to_string();

    let bin = home.join(".aikey").join("bin").join(&bin_file);

    if !bin.exists() {
        return Err(format!(
            "binary not found: {} (run the {} installer to (re)install)",
            bin.display(),
            edition.label()
        ));
    }

    // BR-rc.5-58 fix (2026-05-24): no `--config` arg. The binary's
    // cmd/local/main.go (Personal) sets AIKEY_CONFIG_DEFAULT_NAME=
    // control.yaml in its own startup, and cmd/full/main.go (Trial)
    // leaves it unset so config.go DefaultConfigPath() falls back to
    // control-trial.yaml. Either way, NOT passing --config lets the
    // binary use its own edition-correct default — symmetric with the
    // installer fix in workflow/CD/installer/local-install.sh:1493
    // (also removed --config). Hardcoded `control-trial.yaml` was a
    // hangover from before 2026-05-13 binary-isolation refactor (commit
    // a928cd4 missed this read-side site). See bugfix
    // 20260524-personal-install-console-failed-to-start.md.
    spawn_detached(&bin)
}

fn stop_service() -> Result<(), String> {
    let port =
        read_local_server_port().map_err(|e| format!("cannot resolve service port: {}", e))?;
    let pid = match find_listening_pid(port) {
        Some(p) => p,
        None => return Ok(()), // already stopped
    };
    signal_terminate(pid)?;
    // Wait up to 5s for graceful exit; SIGKILL if still alive.
    for _ in 0..50 {
        if !pid_alive(pid) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    signal_kill(pid)?;
    Ok(())
}

#[cfg(unix)]
fn spawn_detached(bin: &Path) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    // No --config: binary uses env-driven DefaultConfigPath. See caller
    // start_service() docblock for full rationale (BR-rc.5-58).
    let mut cmd = Command::new(bin);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // setsid detaches the child from this process's session — without
    // it the spawned web service would die when the shell that ran
    // `aikey web start` exits. This matches what `nohup` gives us in
    // the installer's invocation.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn()
        .map_err(|e| format!("spawn {}: {}", bin.display(), e))?;
    Ok(())
}

#[cfg(windows)]
fn spawn_detached(bin: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    // CREATE_NO_WINDOW (0x08000000) | DETACHED_PROCESS (0x00000008) —
    // child survives parent exit and has no console window.
    // No --config: binary uses env-driven DefaultConfigPath (BR-rc.5-58).
    const DETACHED_NO_WINDOW: u32 = 0x0800_0008;
    Command::new(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("spawn {}: {}", bin.display(), e))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn spawn_detached(_bin: &Path) -> Result<(), String> {
    Err("service start not supported on this platform".to_string())
}

#[cfg(unix)]
fn signal_terminate(pid: u32) -> Result<(), String> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc != 0 {
        return Err(format!("kill(SIGTERM) for pid {} failed", pid));
    }
    Ok(())
}

#[cfg(unix)]
fn signal_kill(pid: u32) -> Result<(), String> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if rc != 0 {
        return Err(format!("kill(SIGKILL) for pid {} failed", pid));
    }
    Ok(())
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    // signal 0 = existence check, doesn't actually deliver a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(windows)]
fn signal_terminate(pid: u32) -> Result<(), String> {
    use std::process::Command;
    // Windows has no graceful-shutdown signal for arbitrary
    // processes; taskkill without /F sends WM_CLOSE which is the
    // closest equivalent. /F is reserved for the kill fallback.
    Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .status()
        .map_err(|e| format!("invoke taskkill: {}", e))
        .and_then(|s| {
            if s.success() {
                Ok(())
            } else {
                Err(format!("taskkill exit {}", s.code().unwrap_or(-1)))
            }
        })
}

#[cfg(windows)]
fn signal_kill(pid: u32) -> Result<(), String> {
    use std::process::Command;
    Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()
        .map_err(|e| format!("invoke taskkill: {}", e))
        .and_then(|s| {
            if s.success() {
                Ok(())
            } else {
                Err(format!("taskkill /F exit {}", s.code().unwrap_or(-1)))
            }
        })
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use std::process::Command;
    // tasklist filtering is the simplest existence check without
    // pulling in winapi crates.
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

fn find_listening_pid(port: u16) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::process::Command;
        // `lsof -ti :<port> -sTCP:LISTEN` returns just the PIDs of
        // listening sockets — same idiom the installer uses to find
        // the previous instance. We pick the first one because
        // there's at most one listener on a given port at a time.
        let out = Command::new("lsof")
            .args(["-ti", &format!(":{}", port), "-sTCP:LISTEN"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        s.lines().next()?.trim().parse::<u32>().ok()
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        // `netstat -ano` lines look like:
        //   "  TCP    127.0.0.1:8090   0.0.0.0:0    LISTENING    1234"
        let out = Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if !line.contains("LISTENING") {
                continue;
            }
            let needle = format!(":{} ", port);
            if !line.contains(&needle) {
                continue;
            }
            if let Some(pid_str) = line.split_whitespace().last() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
        None
    }
}

/// One-line summary used by `aikey status` — combines port discovery,
/// reachability, and vault state. Returns three distinct shapes:
///   - "local-server: running on port N (vault: locked|unlocked)"
///   - "local-server: NOT RUNNING on port N\n    Start:  <hint>"
///   - "local-server: NOT CONFIGURED — <discovery error>"
///
/// Compact one-line status for the `aikey service status` aggregate.
/// Returns `(running, "<detail>")`. Reuses the same port discovery +
/// `probe_vault_status` truth source as `local_server_status_line()` so the
/// aggregate stays consistent with `aikey web status`; only verbosity differs.
/// A host without local-server installed reports `(false, "not installed")`
/// rather than an error — "not installed" is a legitimate status.
pub fn status_summary() -> (bool, String) {
    if !is_local_server_installed() {
        return (false, "not installed".to_string());
    }
    match read_local_server_port_or_default() {
        Err(e) => (false, format!("not configured — {}", e)),
        Ok(port) => {
            let base = format!("http://127.0.0.1:{}", port);
            match probe_vault_status(&base) {
                Ok(unlocked) => (
                    true,
                    format!(
                        "running on http://127.0.0.1:{} (vault: {})",
                        port,
                        if unlocked { "unlocked" } else { "locked" }
                    ),
                ),
                Err(_) => (false, format!("not running (would use port {})", port)),
            }
        }
    }
}

// ── launchd supervision self-heal (§S5, 2026-07-04) ─────────────────────────
// Observed live (2026-07-04): `make restart-personal` left the launchd agent
// silently unloaded — 8090 dead, `launchctl print` "Could not find service",
// zero-byte logs — while the binary itself ran fine when started by hand. A
// status probe that already KNOWS the server is down can heal that state
// instead of only printing a hint (owner: recovery must be self-healing and
// idempotent, no manual steps).

/// Pure decision core (unit-tested): heal ONLY when the plist exists (the
/// installer wired supervision) AND launchd does NOT know the service. A
/// service launchd knows about but that is down is crashed/throttled — its
/// KeepAlive/ThrottleInterval owns the restart; fighting it would flap.
pub(crate) fn launchd_selfheal_applicable(
    plist_exists: bool,
    service_known_to_launchd: bool,
) -> bool {
    plist_exists && !service_known_to_launchd
}

/// macOS: try to re-bootstrap the local-server launchd agent when the probe
/// says it is down. Best-effort and idempotent (`launchctl bootstrap` of an
/// already-known service just fails → None). Returns the recovered status
/// line on success; None → caller prints the normal NOT RUNNING hint.
#[cfg(target_os = "macos")]
fn try_launchd_selfheal(base: &str, port: u16) -> Option<String> {
    use std::process::Command;
    let plist =
        dirs::home_dir()?.join("Library/LaunchAgents/com.aikeylabs.aikey-local-server.plist");
    let uid = String::from_utf8(Command::new("id").arg("-u").output().ok()?.stdout)
        .ok()?
        .trim()
        .to_string();
    let label = format!("gui/{}/com.aikeylabs.aikey-local-server", uid);
    let known = Command::new("launchctl")
        .args(["print", &label])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !launchd_selfheal_applicable(plist.exists(), known) {
        return None;
    }
    let ok = Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{}", uid), plist.to_str()?])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        return None;
    }
    // Give launchd a moment, then re-probe — only claim recovery on evidence.
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if let Ok(unlocked) = probe_vault_status(base) {
            return Some(format!(
                "local-server: recovered on port {} (vault: {}) — launchd agent was unloaded; re-bootstrapped automatically",
                port,
                if unlocked { "unlocked" } else { "locked" }
            ));
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn try_launchd_selfheal(_base: &str, _port: u16) -> Option<String> {
    None // supervision differs per platform; non-macOS keeps the manual hint
}

pub fn local_server_status_line() -> String {
    // `_or_default`: if the host has local-server installed but the YAML
    // hasn't been rendered, falling back to the canonical default port
    // gives the user accurate vault state instead of a Bulk-Import-
    // flavored "NOT CONFIGURED" error. Bugfix
    // 20260524-aikey-service-restart-web-port-undiscoverable.md.
    match read_local_server_port_or_default() {
        Err(e) => format!("local-server: NOT CONFIGURED — {}", e),
        Ok(port) => {
            let base = format!("http://127.0.0.1:{}", port);
            match probe_vault_status(&base) {
                Ok(unlocked) => format!(
                    "local-server: running on port {} (vault: {})",
                    port,
                    if unlocked { "unlocked" } else { "locked" }
                ),
                Err(_) => {
                    // §S5 self-heal: an unloaded launchd agent is recoverable
                    // right here — only fall back to the hint when it isn't.
                    if let Some(recovered) = try_launchd_selfheal(&base, port) {
                        return recovered;
                    }
                    let hint = start_command_hint();
                    format!(
                        "local-server: NOT RUNNING on port {}\n    Start:  {}",
                        port, hint
                    )
                }
            }
        }
    }
}

// ── Port discovery ──────────────────────────────────────────────────────

fn read_yaml_listen_port(path: &Path) -> Result<Option<u16>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    // Why serde_yaml over regex: the yaml has ~10 fields and users may
    // reformat / reorder freely; regex on "^listen:" is fragile to
    // indentation / multi-line shapes.
    let doc: serde_yaml::Value =
        serde_yaml::from_str(&raw).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let listen = doc
        .get("listen")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{} has no `listen:` field", path.display()))?;
    // Shape: "127.0.0.1:8090" — split on last ':' so IPv6-style hosts
    // like "[::1]:8090" are tolerated.
    let port_str = listen
        .rsplit_once(':')
        .map(|(_, p)| p)
        .ok_or_else(|| format!("listen `{}` is not host:port", listen))?;
    let port: u16 = port_str
        .parse()
        .map_err(|e| format!("listen port `{}` is not a u16: {}", port_str, e))?;
    Ok(Some(port))
}

fn read_localhost_port_from_config_json(path: &Path) -> Option<u16> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let url = parsed["controlPanelUrl"].as_str()?;
    localhost_port_of(url)
}

fn read_remote_control_url(path: &PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed["controlPanelUrl"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn localhost_port_of(url: &str) -> Option<u16> {
    let after_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let (host, port_str) = authority.rsplit_once(':')?;
    let is_localhost = host == "127.0.0.1" || host == "localhost" || host == "[::1]";
    if !is_localhost {
        return None;
    }
    port_str.parse::<u16>().ok()
}

/// Build the strict "no local-server here" error message — **specific to
/// the Bulk Import flow** ("user genuinely lacks a local-server install,
/// tell them how to install one or point at remote control panel").
///
/// **Do NOT call this from non-Bulk-Import paths.** The wording assumes
/// the user is trying to do Bulk Import; bubbling it from
/// service-lifecycle, status, or browse flows mis-attributes the failure
/// and steers users at the wrong fix (see BR-rc.5-47 root cause —
/// `aikey service restart web` got this error and the message said
/// "Local Bulk Import requires aikey-local-server..." which was nonsense
/// in that context). The name now encodes the constraint so a future
/// maintainer notices before adding a third caller.
///
/// If you need a port to probe but haven't actually verified local-server
/// is installed, use `read_local_server_port_or_default()` instead — it
/// falls back to the canonical default port without ever calling this.
fn build_bulk_import_unavailable_error(remote_hint: Option<String>) -> String {
    match remote_hint {
        Some(url)
            if !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") =>
        {
            format!(
                "{} Local Bulk Import is not available on this host \
                 (Personal/Trial editions only).\n\
                 For team-scope import, use the Control Panel:\n    {}\n\
                 Note: the remote page operates on the team vault, not your \
                 local CLI vault.",
                ERR_I_CLI_NOT_AVAILABLE, url
            )
        }
        _ => format!(
            "{} Local Bulk Import requires aikey-local-server, which is not \
             installed on this host.\n\
             Install (Personal): curl -fsSL .../local-install.sh | sh\n\
             Install (Trial):    curl -fsSL .../trial-install.sh | sh",
            ERR_I_CLI_NOT_AVAILABLE
        ),
    }
}

// ── Minimal blocking HTTP/1.0 client ────────────────────────────────────
//
// Why hand-rolled instead of reqwest/ureq: keeps the binary small (these
// probes are the only HTTP calls in this code path). Local-server is
// always on 127.0.0.1 — never use these helpers for arbitrary URLs.

fn ureq_get_with_timeout(url: &str, timeout_secs: u64) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let (host, port, path) = parse_local_url(url)?;
    if host != "127.0.0.1" && host != "localhost" {
        return Err(format!("refusing non-local URL: {}", url));
    }
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("bad addr: {}", e))?,
        Duration::from_secs(timeout_secs),
    )
    .map_err(|e| format!("connect: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    let status_ok = buf.starts_with("HTTP/1.0 2") || buf.starts_with("HTTP/1.1 2");
    if !status_ok {
        let status_line = buf.lines().next().unwrap_or("<empty>");
        return Err(format!("HTTP not OK: {}", status_line));
    }
    let body = buf.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok(body)
}

fn parse_local_url(url: &str) -> Result<(String, u16, String), String> {
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// supported: {}", url))?;
    let (host_port, path) = without_scheme
        .split_once('/')
        .map(|(h, p)| (h, format!("/{}", p)))
        .unwrap_or((without_scheme, "/".to_string()));
    let (host, port) = host_port
        .split_once(':')
        .ok_or_else(|| format!("URL missing port: {}", url))?;
    let port: u16 = port.parse().map_err(|e| format!("bad port: {}", e))?;
    Ok((host.to_string(), port, path))
}

// ── Tests ───────────────────────────────────────────────────────────────
//
// These mirror the safety-net suite that was authored against the old
// location in commands_import.rs. Keeping them here means future edits
// to this module are guarded at the place they need to be guarded.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // ── Pure helpers ─────────────────────────────────────────────────

    #[test]
    fn localhost_port_of_accepts_127() {
        assert_eq!(localhost_port_of("http://127.0.0.1:8090"), Some(8090));
        assert_eq!(localhost_port_of("http://127.0.0.1:8090/"), Some(8090));
        assert_eq!(localhost_port_of("http://127.0.0.1:8090/path"), Some(8090));
    }

    #[test]
    fn localhost_port_of_accepts_localhost_and_ipv6_loopback() {
        assert_eq!(localhost_port_of("http://localhost:9000"), Some(9000));
        assert_eq!(localhost_port_of("http://[::1]:9001"), Some(9001));
    }

    #[test]
    fn localhost_port_of_rejects_remote() {
        assert_eq!(localhost_port_of("https://control.example.com:443"), None);
        assert_eq!(localhost_port_of("http://10.0.0.1:8080"), None);
    }

    #[test]
    fn localhost_port_of_returns_none_without_port() {
        assert_eq!(localhost_port_of("http://127.0.0.1"), None);
        assert_eq!(localhost_port_of("http://localhost"), None);
    }

    #[test]
    fn parse_local_url_happy_path() {
        let (h, p, path) = parse_local_url("http://127.0.0.1:8090/health").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8090);
        assert_eq!(path, "/health");
    }

    #[test]
    fn parse_local_url_defaults_path_to_slash() {
        let (_, _, path) = parse_local_url("http://127.0.0.1:8090").unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_local_url_rejects_https() {
        assert!(parse_local_url("https://127.0.0.1:8090/").is_err());
    }

    #[test]
    fn parse_local_url_requires_port() {
        assert!(parse_local_url("http://127.0.0.1/health").is_err());
    }

    #[test]
    fn start_command_hint_is_nonempty_on_current_platform() {
        let hint = start_command_hint();
        assert!(
            !hint.trim().is_empty(),
            "start_command_hint must not be empty"
        );
    }

    #[test]
    fn build_bulk_import_unavailable_error_with_remote_url_mentions_it() {
        let err =
            build_bulk_import_unavailable_error(Some("https://control.example.com".to_string()));
        assert!(
            err.contains("https://control.example.com"),
            "remote hint should be embedded verbatim in error: {}",
            err
        );
        assert!(err.contains(ERR_I_CLI_NOT_AVAILABLE));
    }

    #[test]
    fn build_bulk_import_unavailable_error_treats_localhost_remote_as_no_remote() {
        let err = build_bulk_import_unavailable_error(Some("http://127.0.0.1:9999".to_string()));
        assert!(
            !err.contains("team vault"),
            "localhost-as-remote must not trigger production messaging: {}",
            err
        );
        assert!(err.contains("aikey-local-server"));
    }

    #[test]
    fn build_bulk_import_unavailable_error_without_remote_suggests_install() {
        let err = build_bulk_import_unavailable_error(None);
        assert!(err.contains("local-install.sh") || err.contains("trial-install.sh"));
    }

    // ── YAML / JSON file fixtures ────────────────────────────────────

    #[test]
    fn read_yaml_listen_port_absent_returns_ok_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.yaml");
        assert!(matches!(read_yaml_listen_port(&p), Ok(None)));
    }

    #[test]
    fn read_yaml_listen_port_extracts_port_from_listen() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "listen: 127.0.0.1:8090\nother: x\n").unwrap();
        assert_eq!(read_yaml_listen_port(&p).unwrap(), Some(8090));
    }

    #[test]
    fn read_yaml_listen_port_tolerates_ipv6_listen() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "listen: \"[::1]:8090\"\n").unwrap();
        assert_eq!(read_yaml_listen_port(&p).unwrap(), Some(8090));
    }

    #[test]
    fn read_yaml_listen_port_errors_when_field_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "other: x\n").unwrap();
        let err = read_yaml_listen_port(&p).unwrap_err();
        assert!(err.contains("listen"));
    }

    #[test]
    fn read_yaml_listen_port_errors_when_listen_shape_bad() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "listen: not-a-port\n").unwrap();
        let err = read_yaml_listen_port(&p).unwrap_err();
        assert!(err.contains("host:port") || err.contains("u16"));
    }

    // ── YAML_CONFIG_REL_CANDIDATES fence tests (BR-rc.5-58) ──────────
    //
    // Pin the candidate-list contract:
    //   1. `control.yaml` exists alone → port read from it (Personal)
    //   2. `control-trial.yaml` exists alone → fallback (Trial / pre-rename)
    //   3. Both exist → `control.yaml` wins (Personal post-renamed host
    //      where mv left both — defensive ordering)
    //   4. Neither exists → strict variant errors; _or_default falls back
    //      to 8090 when local-server is installed (covered by existing
    //      or_default_falls_back_to_8090_when_yaml_missing_but_installed)
    //
    // These tests would have caught BR-rc.5-58 had they existed pre-
    // 2026-05-13 rename — `control-trial.yaml`-only fixture passing while
    // a Personal-shaped host (control.yaml) silently returned no port.

    #[test]
    fn read_local_server_port_picks_control_yaml_personal_path() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_personal_yaml_under(tmp.path(), 8091);
        with_home(tmp.path(), || {
            assert_eq!(read_local_server_port().unwrap(), 8091);
        });
    }

    #[test]
    fn read_local_server_port_falls_back_to_control_trial_yaml() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        // Only the legacy / Trial name exists
        write_yaml_under(tmp.path(), 9092);
        with_home(tmp.path(), || {
            assert_eq!(read_local_server_port().unwrap(), 9092);
        });
    }

    #[test]
    fn read_local_server_port_prefers_control_yaml_when_both_present() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_personal_yaml_under(tmp.path(), 8093); // control.yaml
        write_yaml_under(tmp.path(), 7777); // control-trial.yaml (legacy)
        with_home(tmp.path(), || {
            // Personal (control.yaml) wins — first in CANDIDATES list.
            // Defensive against a host where mv migration was interrupted
            // and both files coexist; the new name should still be the
            // authoritative source.
            assert_eq!(read_local_server_port().unwrap(), 8093);
        });
    }

    #[test]
    fn yaml_config_rel_candidates_order_is_control_then_control_trial() {
        // Pin the order — `control.yaml` first (Personal post-rename),
        // `control-trial.yaml` fallback. Re-ordering would silently
        // change behavior for hosts where both files exist.
        assert_eq!(
            YAML_CONFIG_REL_CANDIDATES,
            &[
                ".aikey/config/control.yaml",
                ".aikey/config/control-trial.yaml"
            ]
        );
    }

    #[test]
    fn read_localhost_port_from_config_json_extracts_localhost() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("config.json");
        std::fs::write(&p, r#"{"controlPanelUrl":"http://127.0.0.1:8090"}"#).unwrap();
        assert_eq!(read_localhost_port_from_config_json(&p), Some(8090));
    }

    #[test]
    fn read_localhost_port_from_config_json_rejects_remote_url() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("config.json");
        std::fs::write(&p, r#"{"controlPanelUrl":"https://control.example.com"}"#).unwrap();
        assert_eq!(read_localhost_port_from_config_json(&p), None);
    }

    #[test]
    fn read_localhost_port_from_config_json_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            read_localhost_port_from_config_json(&tmp.path().join("nope.json")),
            None
        );
    }

    // ── Mock-server-backed tests ─────────────────────────────────────

    fn spawn_oneshot(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        port
    }

    fn pick_unused_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[test]
    fn probe_vault_status_detects_unlocked() {
        let port = spawn_oneshot(r#"{"unlocked":true}"#);
        let base = format!("http://127.0.0.1:{}", port);
        assert_eq!(probe_vault_status(&base), Ok(true));
    }

    #[test]
    fn probe_vault_status_detects_locked() {
        let port = spawn_oneshot(r#"{"unlocked":false}"#);
        let base = format!("http://127.0.0.1:{}", port);
        assert_eq!(probe_vault_status(&base), Ok(false));
    }

    #[test]
    fn probe_vault_status_errors_when_unreachable() {
        let port = pick_unused_port();
        let base = format!("http://127.0.0.1:{}", port);
        assert!(probe_vault_status(&base).is_err());
    }

    // ── Integration: local_server_status_line with HOME override ─────

    fn write_yaml_under(home: &std::path::Path, port: u16) {
        let cfg = home.join(".aikey/config");
        std::fs::create_dir_all(&cfg).unwrap();
        // Default to control-trial.yaml (legacy / Trial name) — existing
        // tests rely on this path. Personal-specific tests use the
        // dedicated `write_personal_yaml_under` helper below.
        std::fs::write(
            cfg.join("control-trial.yaml"),
            format!("listen: 127.0.0.1:{}\n", port),
        )
        .unwrap();
    }

    fn write_personal_yaml_under(home: &std::path::Path, port: u16) {
        let cfg = home.join(".aikey/config");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("control.yaml"),
            format!("listen: 127.0.0.1:{}\n", port),
        )
        .unwrap();
    }

    #[test]
    fn status_line_running_unlocked() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let port = spawn_oneshot(r#"{"unlocked":true}"#);
        let tmp = tempfile::tempdir().unwrap();
        write_yaml_under(tmp.path(), port);
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }

        assert!(line.contains(&format!("port {}", port)), "got: {}", line);
        assert!(line.contains("running"), "got: {}", line);
        assert!(line.contains("unlocked"), "got: {}", line);
    }

    #[test]
    fn status_line_running_locked() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let port = spawn_oneshot(r#"{"unlocked":false}"#);
        let tmp = tempfile::tempdir().unwrap();
        write_yaml_under(tmp.path(), port);
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }

        assert!(line.contains("running"), "got: {}", line);
        assert!(
            line.contains("locked") && !line.contains("unlocked"),
            "got: {}",
            line
        );
    }

    #[test]
    fn status_line_not_running_includes_start_hint() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let port = pick_unused_port();
        let tmp = tempfile::tempdir().unwrap();
        write_yaml_under(tmp.path(), port);
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }

        assert!(line.contains("NOT RUNNING"), "got: {}", line);
        assert!(line.contains("Start:"), "got: {}", line);
    }

    // ── wait_for_reachable ───────────────────────────────────────────

    #[test]
    fn wait_for_reachable_returns_ok_when_server_responds() {
        let port = spawn_oneshot(r#"{"unlocked":true}"#);
        let r = wait_for_reachable(port, std::time::Duration::from_secs(2));
        assert!(r.is_ok(), "expected Ok, got {:?}", r);
    }

    #[test]
    fn wait_for_reachable_times_out_when_no_server() {
        let port = pick_unused_port();
        // Short timeout so the test stays fast — covers the deadline path.
        let r = wait_for_reachable(port, std::time::Duration::from_millis(300));
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("did not respond"), "got: {}", msg);
        assert!(msg.contains(&port.to_string()), "got: {}", msg);
    }

    // ── is_local_server_installed ────────────────────────────────────

    fn write_install_state(home: &std::path::Path, body: &str) {
        let d = home.join(".aikey");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("install-state.json"), body).unwrap();
    }

    fn with_home<F: FnOnce()>(home: &std::path::Path, f: F) {
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", home);
        f();
        if let Some(h) = prev {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn is_local_server_installed_true_for_personal_with_console() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(
            tmp.path(),
            r#"{"installed_components":["aikey-cli","local-server"]}"#,
        );
        with_home(tmp.path(), || {
            assert!(is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_true_for_trial() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), r#"{"installed_components":["full-trial"]}"#);
        with_home(tmp.path(), || {
            assert!(is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_false_for_cli_only() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), r#"{"installed_components":["aikey-cli"]}"#);
        with_home(tmp.path(), || {
            assert!(!is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_false_when_state_missing() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_home(tmp.path(), || {
            assert!(!is_local_server_installed());
        });
    }

    // ── detect_edition ───────────────────────────────────────────────

    #[test]
    fn detect_edition_returns_personal_for_local_server_only() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(
            tmp.path(),
            r#"{"installed_components":["aikey-cli","local-server"]}"#,
        );
        with_home(tmp.path(), || {
            assert_eq!(detect_edition(), Some(Edition::Personal));
        });
    }

    #[test]
    fn detect_edition_returns_trial_for_full_trial() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), r#"{"installed_components":["full-trial"]}"#);
        with_home(tmp.path(), || {
            assert_eq!(detect_edition(), Some(Edition::Trial));
        });
    }

    #[test]
    fn detect_edition_tolerates_utf8_bom() {
        // Encoding sweep 2026-07-07 H1: shipped PS 5.1 trial installers
        // wrote install-state.json WITH a UTF-8 BOM (`Set-Content -Encoding
        // UTF8`), serde rejects BOM at byte 0, and the `.ok()?` swallowed
        // the error — a whole trial install read as "not installed".
        // Readers must tolerate BOM'd files forever (they're already on
        // customer machines).
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(
            tmp.path(),
            "\u{feff}{\"installed_components\":[\"full-trial\"]}",
        );
        with_home(tmp.path(), || {
            assert_eq!(detect_edition(), Some(Edition::Trial));
        });
    }

    #[test]
    fn detect_edition_prefers_trial_when_both_listed() {
        // If a host's install-state.json mentions both (unusual but
        // possible on a machine that ran both installers), the running
        // listener is full-trial, so service control must target Trial.
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(
            tmp.path(),
            r#"{"installed_components":["local-server","full-trial"]}"#,
        );
        with_home(tmp.path(), || {
            assert_eq!(detect_edition(), Some(Edition::Trial));
        });
    }

    #[test]
    fn detect_edition_none_for_cli_only() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), r#"{"installed_components":["aikey-cli"]}"#);
        with_home(tmp.path(), || {
            assert_eq!(detect_edition(), None);
        });
    }

    #[test]
    fn detect_edition_none_when_state_missing() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_home(tmp.path(), || {
            assert_eq!(detect_edition(), None);
        });
    }

    // ── read_local_server_port_or_default ────────────────────────────
    //
    // Pin the BR-rc.5-47 contract: when install-state says local-server
    // is present but YAML config is missing, fall back to 8090 silently
    // instead of bubbling a Bulk-Import-flavored "not installed" error.
    // If local-server isn't installed at all, the strict error is still
    // surfaced (Bulk-Import-flavored is correct in that case).

    #[test]
    fn or_default_returns_yaml_port_when_yaml_present() {
        // YAML present → strict and _or_default agree on the YAML port.
        // Default fallback is NOT consulted.
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(
            tmp.path(),
            r#"{"installed_components":["aikey-cli","local-server"]}"#,
        );
        write_yaml_under(tmp.path(), 9999);
        with_home(tmp.path(), || {
            assert_eq!(read_local_server_port_or_default().unwrap(), 9999);
        });
    }

    #[test]
    fn or_default_falls_back_to_8090_when_yaml_missing_but_installed() {
        // YAML absent + install-state says local-server installed → default.
        // This is the BR-rc.5-47 regression pin: must NOT propagate the
        // strict error (which would say "Local Bulk Import requires...").
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(
            tmp.path(),
            r#"{"installed_components":["aikey-cli","local-server"]}"#,
        );
        with_home(tmp.path(), || {
            assert_eq!(
                read_local_server_port_or_default().unwrap(),
                DEFAULT_PERSONAL_TRIAL_LOCAL_SERVER_PORT,
            );
        });
    }

    #[test]
    fn or_default_falls_back_to_8090_for_trial_too() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), r#"{"installed_components":["full-trial"]}"#);
        with_home(tmp.path(), || {
            assert_eq!(
                read_local_server_port_or_default().unwrap(),
                DEFAULT_PERSONAL_TRIAL_LOCAL_SERVER_PORT,
            );
        });
    }

    #[test]
    fn or_default_still_errors_when_local_server_not_installed() {
        // install-state has no local-server / no full-trial → fall back
        // should NOT kick in. The strict Bulk-Import wording is correct
        // semantically: the user has no local-server install.
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), r#"{"installed_components":["aikey-cli"]}"#);
        with_home(tmp.path(), || {
            let err = read_local_server_port_or_default().unwrap_err();
            assert!(
                err.contains(ERR_I_CLI_NOT_AVAILABLE),
                "fallback must NOT kick in when local-server not installed; got: {}",
                err
            );
        });
    }

    #[test]
    fn or_default_still_errors_when_install_state_missing() {
        // No install-state.json at all → treated as "not installed",
        // strict error surfaces. Important: an upgrade or fresh-clone
        // host without the state file shouldn't silently default to a
        // port that doesn't exist.
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_home(tmp.path(), || {
            let err = read_local_server_port_or_default().unwrap_err();
            assert!(
                err.contains(ERR_I_CLI_NOT_AVAILABLE),
                "missing install-state must NOT trigger default fallback; got: {}",
                err
            );
        });
    }

    // ── service_command_hint ─────────────────────────────────────────

    #[test]
    fn service_command_hint_points_at_aikey_web() {
        // Hints are intentionally edition-agnostic now — the CLI
        // auto-detects which edition is installed, so the user-facing
        // command is the same regardless. Surrounding text in error
        // messages still references the edition by name.
        for action in ["start", "stop", "restart"] {
            for ed in [Edition::Personal, Edition::Trial] {
                let h = service_command_hint(ed, action);
                assert_eq!(
                    h,
                    format!("aikey web {}", action),
                    "hint should be `aikey web {}`, got: {}",
                    action,
                    h
                );
            }
        }
    }

    #[test]
    fn start_command_hint_points_at_aikey_web_start() {
        assert_eq!(start_command_hint(), "aikey web start");
    }

    #[test]
    fn edition_label_is_user_facing() {
        assert_eq!(Edition::Personal.label(), "aikey-local-server");
        assert_eq!(Edition::Trial.label(), "aikey-trial-server");
    }

    #[test]
    fn is_local_server_installed_false_when_state_malformed() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), "not-json");
        with_home(tmp.path(), || {
            assert!(!is_local_server_installed());
        });
    }

    #[test]
    fn status_line_not_configured_when_no_yaml_no_config_json() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }

        assert!(line.contains("NOT CONFIGURED"), "got: {}", line);
    }
}

#[cfg(test)]
mod launchd_selfheal_tests {
    use super::launchd_selfheal_applicable;

    // §S5 decision core: heal ONLY the "installer wired supervision but launchd
    // lost the service" state. 能红: invert either condition and this fails.
    #[test]
    fn heals_only_when_plist_exists_and_service_unknown() {
        assert!(
            launchd_selfheal_applicable(true, false),
            "unloaded agent + plist → heal"
        );
        assert!(
            !launchd_selfheal_applicable(true, true),
            "launchd owns a crashed service (KeepAlive/Throttle) → do not fight it"
        );
        assert!(
            !launchd_selfheal_applicable(false, false),
            "no plist → nothing to bootstrap (not installed as agent)"
        );
        assert!(
            !launchd_selfheal_applicable(false, true),
            "inconsistent state → hands off"
        );
    }
}
