//! OS-service control core for the `aikey.trust-local` degrade-detector daemon
//! (launchctl on macOS, `systemctl --user` on Linux, `schtasks` per-user
//! ScheduledTask on Windows).
//!
//! Why this is its OWN lib module (2026-07-26, refactor): service control for
//! the other two managed daemons already lives in lib+bin modules —
//! `proxy_lifecycle`/`commands_proxy` for the proxy, `local_server_probe` for
//! the web local-server — so `commands_service` and any lib-side caller (e.g.
//! `aikey doctor`, which compiles in BOTH the lib and bin crates) can drive
//! them. trust-local was the odd one out: its control was inlined in the
//! bin-only `commands_service`, unreachable from the lib crate. Extracting it
//! here lets `commands_service::trust_local` (the CLI shell: install-guard +
//! emit) AND `commands_project::handle_doctor` (auto-repair) both call ONE
//! implementation — no parallel launchctl/systemctl/schtasks path.
//!
//! Layering: this module is the pure OS-process core (no stdout, no JSON). The
//! human/JSON output + the TRUST_LOCAL_NOT_INSTALLED CLI contract stay in
//! `commands_service::trust_local`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

/// launchd / systemd / ScheduledTask label.
pub const SERVICE_NAME: &str = "aikey.trust-local";

/// `~/.aikey/bin/trust-local` (Unix) or `%USERPROFILE%\.aikey\bin\trust-local.exe`
/// (Windows). Mirrors install_service.ps1's `$BinaryPath` resolution. Exposed so
/// the CLI shell can build its TRUST_LOCAL_NOT_INSTALLED message with the exact
/// path, matching the pre-refactor behavior.
pub fn bin_path() -> PathBuf {
    let home = if cfg!(windows) {
        std::env::var("USERPROFILE").unwrap_or_default()
    } else {
        std::env::var("HOME").unwrap_or_default()
    };
    let binary_name = if cfg!(windows) {
        "trust-local.exe"
    } else {
        "trust-local"
    };
    PathBuf::from(home)
        .join(".aikey")
        .join("bin")
        .join(binary_name)
}

/// True when the trust-local binary is present — same path truth source as
/// `status_summary` and the CLI install guard.
pub fn is_installed() -> bool {
    bin_path().exists()
}

/// Compact one-line status for the aggregate + the `status` verb. Read-only: a
/// single-shot healthz probe on :8801 (no 30s wait — that belongs to post-start).
/// "not installed" is a status, not an error.
pub fn status_summary() -> (bool, String) {
    if !bin_path().exists() {
        return (false, "not installed".to_string());
    }
    if healthz_once() {
        (true, "running on http://127.0.0.1:8801".to_string())
    } else {
        (false, "not running".to_string())
    }
}

/// Start (or restart — `launchctl kickstart -k` is kill-and-restart) the daemon,
/// then wait up to 30s for it to answer /healthz. Assumes the caller already
/// verified `is_installed()` (the CLI shell / doctor guard on it and print the
/// TRUST_LOCAL_NOT_INSTALLED contract). On an unsupported platform, errors.
pub fn start() -> Result<(), String> {
    platform_run("start").and_then(|()| probe_healthz())
}

/// Stop the daemon. No reachability probe — we trust the service manager to
/// deliver SIGTERM (matches the pre-refactor `dispatch` behavior).
pub fn stop() -> Result<(), String> {
    platform_run("stop")
}

/// Restart the daemon, then wait up to 30s for /healthz.
pub fn restart() -> Result<(), String> {
    platform_run("restart").and_then(|()| probe_healthz())
}

/// Single-shot healthz check (no retry loop). Distinct from `probe_healthz`,
/// which waits up to 30s for a service that was just asked to start.
fn healthz_once() -> bool {
    ureq::get("http://127.0.0.1:8801/healthz")
        .timeout(Duration::from_millis(500))
        .call()
        .map(|r| r.status() == 200)
        .unwrap_or(false)
}

/// The per-OS start/stop/restart dispatch. Moved verbatim from
/// `commands_service::trust_local::dispatch`'s platform match.
fn platform_run(verb: &str) -> Result<(), String> {
    match std::env::consts::OS {
        "macos" => match verb {
            "start" | "restart" => launchctl_kickstart(current_uid()),
            "stop" => launchctl_kill(current_uid()),
            _ => Err(format!("unknown verb '{}'", verb)),
        },
        "linux" => systemctl_user(verb),
        "windows" => match verb {
            "start" | "stop" => sc_action(verb),
            // Windows `sc.exe`/`schtasks` has no atomic restart; do stop +
            // wait-for-STOPPED + start. We can't just sleep a fixed interval
            // because the stop is async (returns immediately while the task
            // exits); starting before STOPPED can error "already running".
            "restart" => {
                let _ = sc_action("stop");
                // Poll for STOPPED state up to 10s. Match NSSM's stop timeout.
                let deadline = Instant::now() + Duration::from_secs(10);
                while Instant::now() < deadline {
                    if sc_is_stopped() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                sc_action("start")
            }
            _ => Err(format!("unknown verb '{}'", verb)),
        },
        other => Err(format!(
            "platform '{}' not supported (service control is macOS / Linux / Windows)",
            other
        )),
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid() is a documented thread-safe syscall.
    unsafe { libc::getuid() }
}

// Windows path is unreachable — `platform_run` returns "platform not supported"
// before this is called on anything other than macos/linux. The stub exists
// only so the windows-amd64 cross-compile target type-checks. BR-rc.5-50 —
// `libc::getuid` is Unix-only and broke the Windows build under the rc.5 hotfix.
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

fn launchctl_kickstart(uid: u32) -> Result<(), String> {
    // -k flag = kill running and start again; idempotent for both "start" and
    // "restart" semantics.
    let target = format!("gui/{}/{}", uid, SERVICE_NAME);
    run("launchctl", &["kickstart", "-k", &target])
}

fn launchctl_kill(uid: u32) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid, SERVICE_NAME);
    run("launchctl", &["kill", "TERM", &target])
}

fn systemctl_user(verb: &str) -> Result<(), String> {
    run("systemctl", &["--user", verb, SERVICE_NAME])
}

/// Windows: drive the trust-local per-user ScheduledTask via `schtasks`.
///
/// 2026-07-06: trust-local migrated from an NSSM-wrapped Windows service to a
/// per-user ScheduledTask (install_service.ps1). Root cause: nssm.exe is NOT
/// shipped in the offline package, so the sc.exe service never registered on
/// real end-user machines. The task is registered under SERVICE_NAME; `schtasks`
/// is Windows-bundled (no nssm dependency).
///   start -> /Run (launch the task's action now)
///   stop  -> /End (terminate the running task instance)
fn sc_action(verb: &str) -> Result<(), String> {
    let sw = match verb {
        "start" => "/Run",
        "stop" => "/End",
        other => return Err(format!("unknown service verb '{}'", other)),
    };
    run("schtasks", &[sw, "/TN", SERVICE_NAME])
}

/// Returns true when trust-local is NOT running. Used by the restart loop to
/// wait for an async `/End` to finish before re-firing `/Run`.
///
/// We probe the process image name via `tasklist` rather than parsing
/// `schtasks /Query` Status, because the Status strings are LOCALIZED and a
/// substring match would break off English hosts. The image name
/// `trust-local.exe` is not localized.
fn sc_is_stopped() -> bool {
    match std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq trust-local.exe", "/FO", "CSV", "/NH"])
        .output()
    {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            !s.contains("trust-local.exe")
        }
        Err(_) => false,
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{}: {}", cmd, e))?;
    if !output.status.success() {
        return Err(format!(
            "{} {}: {}",
            cmd,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Reachability deadline for the post-start healthz probe.
///
/// Why 30s: `launchctl kickstart` returns immediately while launchd brings
/// trust-local up asynchronously, and the daemon's cold start is dominated by
/// PyInstaller onefile self-extraction (~5.6s idle to ~20.3s under load, measured
/// 2026-06-08). The probe returns early on first healthz 200, so the typical
/// success path is far shorter than this ceiling. The web caller's context
/// timeout (service_handler.go) MUST stay above this.
const PROBE_DEADLINE_SECS: u64 = 30;

fn probe_healthz() -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(PROBE_DEADLINE_SECS);
    while Instant::now() < deadline {
        if ureq::get("http://127.0.0.1:8801/healthz")
            .timeout(Duration::from_millis(500))
            .call()
            .map(|r| r.status() == 200)
            .unwrap_or(false)
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "service did not become reachable on :8801 within {}s",
        PROBE_DEADLINE_SECS
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fence for the 2026-07-26 extraction (move from commands_service::trust_local).
    // These pin the observable contract of the moved core so a future edit can't
    // silently change it. The launchctl/systemctl/schtasks paths shell out and
    // aren't hermetically unit-testable; they were moved VERBATIM, and the live
    // `aikey service {status,start} trust-local` E2E covers them.

    #[test]
    fn service_name_is_stable() {
        // The launchd/systemd/schtasks label is a cross-component contract
        // (install_service.ps1, plists, the web trust-check banner). Pin it.
        assert_eq!(SERVICE_NAME, "aikey.trust-local");
    }

    #[test]
    fn status_summary_matches_installed_state() {
        // status_summary's first branch is driven purely by bin_path().exists(),
        // so it must agree with is_installed() on the not-installed verdict.
        let (running, detail) = status_summary();
        if !is_installed() {
            assert!(!running, "not-installed must report running=false");
            assert_eq!(detail, "not installed");
        }
    }

    #[test]
    fn bin_path_is_under_aikey_bin() {
        let p = bin_path();
        assert!(p.ends_with("trust-local") || p.ends_with("trust-local.exe"));
        assert!(p.to_string_lossy().contains(".aikey"));
    }
}
