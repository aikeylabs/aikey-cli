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

/// Stop the daemon, then verify on macOS that it actually stayed stopped.
///
/// Windows already verifies that the exact installed binary's process tree is
/// gone: Task Scheduler `/End` terminates only the hidden launcher on some
/// Win10 hosts and can orphan the PyInstaller parent/worker pair while
/// incorrectly reporting success. macOS had no such check and needs one for a
/// different reason — see `verify_launchd_stopped`.
///
/// Linux is unverified by design: `systemctl --user stop` is synchronous and
/// systemd never restarts a unit that was stopped on purpose, so there is no
/// respawn to catch.
pub fn stop() -> Result<(), String> {
    platform_run("stop")?;
    #[cfg(target_os = "macos")]
    verify_launchd_stopped(current_uid())?;
    Ok(())
}

/// Poll launchd until the job reports no pid — i.e. it is really down.
///
/// Why this check exists: macOS "stop" used to be `launchctl kill TERM`, which
/// signals the process but leaves the job loaded, so `KeepAlive=<true/>` had
/// launchd respawn it seconds later while we printed "stop succeeded" over the
/// top of that (measured 2026-08-14: fresh pid ~10s later, serving again at
/// t+20s, `runs` 40 -> 41). `launchctl_bootout` fixes the behaviour; this check
/// is the fence that proves it, and it also catches any future path that
/// reintroduces a signal-based stop.
///
/// Why we ask launchd and NOT /healthz: a healthz probe cannot tell "stopped"
/// from "restarting". The PyInstaller binary needs ~20s to self-extract before
/// it binds, so a respawn is invisible to any healthz poll shorter than that —
/// during the diagnosis a 15s healthz-style window reported a clean stop for a
/// service that was already coming back up. launchd's own job state is the only
/// ruler that distinguishes the two.
///
/// Bugfix: workflow/CI/bugfix/20260814-trust-local-stop-does-not-stop-macos.md
#[cfg(target_os = "macos")]
fn verify_launchd_stopped(uid: u32) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid, SERVICE_NAME);
    let deadline = Instant::now() + Duration::from_secs(STOP_VERIFY_SECS);
    let mut last_pid = None;
    while Instant::now() < deadline {
        match launchd_job_pid(&target) {
            Some(pid) => last_pid = Some(pid),
            // No pid line (or the job isn't loaded at all) = really stopped.
            None => return Ok(()),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "trust-local is still running {}s after stop (launchd pid {}). The job \
         is still loaded in launchd, which restarts it because the LaunchAgent \
         sets KeepAlive. To stop it right now: launchctl bootout {}",
        STOP_VERIFY_SECS,
        last_pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".into()),
        target,
    ))
}

/// Ask launchd for the job's current pid. `None` = not running (no pid line, or
/// the job is not loaded, or launchctl failed — all of which mean "not up").
#[cfg(target_os = "macos")]
fn launchd_job_pid(target: &str) -> Option<u32> {
    let output = std::process::Command::new("launchctl")
        .args(["print", target])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_launchd_pid(&String::from_utf8_lossy(&output.stdout))
}

/// Extract the top-level `pid = N` from `launchctl print` output.
///
/// Split out from the shell-out so the fence can exercise the parse against
/// real captured output — the launchctl invocation itself is not hermetic.
/// Only the job's own `pid =` key is a pid; the same dump also contains keys
/// like `original pid`, `state = running`, and per-endpoint sub-dicts, so we
/// match the exact key rather than the first number we see.
#[cfg(target_os = "macos")]
fn parse_launchd_pid(printed: &str) -> Option<u32> {
    printed.lines().find_map(|line| {
        let trimmed = line.trim();
        let value = trimmed.strip_prefix("pid =")?;
        value.trim().parse::<u32>().ok()
    })
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
            "stop" => launchctl_bootout(current_uid()),
            _ => Err(format!("unknown verb '{}'", verb)),
        },
        "linux" => systemctl_user(verb),
        "windows" => match verb {
            "start" => sc_action(verb),
            "stop" => windows_stop(),
            // Windows `sc.exe`/`schtasks` has no atomic restart; do stop +
            // wait-for-STOPPED + start. We can't just sleep a fixed interval
            // because the stop is async (returns immediately while the task
            // exits); starting before STOPPED can error "already running".
            "restart" => {
                windows_stop()?;
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
pub(crate) fn current_uid() -> u32 {
    // SAFETY: getuid() is a documented thread-safe syscall.
    unsafe { libc::getuid() }
}

// Windows path is unreachable — `platform_run` returns "platform not supported"
// before this is called on anything other than macos/linux. The stub exists
// only so the windows-amd64 cross-compile target type-checks. BR-rc.5-50 —
// `libc::getuid` is Unix-only and broke the Windows build under the rc.5 hotfix.
#[cfg(not(unix))]
pub(crate) fn current_uid() -> u32 {
    0
}

/// `~/Library/LaunchAgents/aikey.trust-local.plist` — the same path
/// install_service.sh writes. Needed because a `stop` now unloads the job, so
/// `start` may have to bootstrap it back in before kickstart can find it.
fn launchd_plist_path() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", SERVICE_NAME))
}

fn launchctl_kickstart(uid: u32) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid, SERVICE_NAME);
    // `stop` boots the job out of the domain, so on the next start there may be
    // nothing for kickstart to kick. Bootstrap it back in first; an "already
    // loaded" error is the normal case (service was never stopped) and is not
    // a failure — kickstart below is what actually (re)starts it either way.
    let domain = format!("gui/{}", uid);
    let plist = launchd_plist_path();
    if plist.exists() {
        let _ = run(
            "launchctl",
            &["bootstrap", &domain, &plist.to_string_lossy()],
        );
    }
    // -k flag = kill running and start again; idempotent for both "start" and
    // "restart" semantics.
    run("launchctl", &["kickstart", "-k", &target])
}

/// Stop by UNLOADING the job, not by signalling it.
///
/// Why not `launchctl kill TERM` (what this did until 2026-08-14): the plist
/// carries `KeepAlive=<true/>`, so signalling the process just makes launchd
/// start it again — measured: "stop succeeded", then a fresh pid ~10s later and
/// the service serving again at t+20s (`runs` 40 -> 41). Weakening the plist to
/// `{SuccessfulExit: false}` does NOT fix it either: trust-local is a
/// PyInstaller onefile, so launchd tracks the bootloader parent, and a
/// signalled parent dies BY SIGNAL rather than exiting 0 — still an
/// unsuccessful exit, still respawned (verified, `runs` 1 -> 2 -> 3).
///
/// `bootout` removes the job from the domain, so there is nothing left to
/// respawn. `start` bootstraps it back in. Unconditional KeepAlive is then
/// exactly right for every case that ISN'T a deliberate stop — a crash still
/// self-heals, which the private-deployment brief requires.
///
/// Bugfix: workflow/CI/bugfix/20260814-trust-local-stop-does-not-stop-macos.md
fn launchctl_bootout(uid: u32) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid, SERVICE_NAME);
    match run("launchctl", &["bootout", &target]) {
        Ok(()) => Ok(()),
        // "Could not find specified service" = already unloaded. Stop is
        // idempotent: the post-condition the caller asked for already holds.
        Err(e)
            if e.contains("Could not find specified service") || e.contains("No such process") =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsProcess {
    pid: u32,
    parent_pid: u32,
}

/// Return only roots from a set of matching processes. `taskkill /T` on each
/// root then terminates its full descendant tree without issuing redundant
/// kills for the PyInstaller worker child.
fn process_tree_roots(processes: &[WindowsProcess]) -> Vec<u32> {
    processes
        .iter()
        .filter(|process| {
            !processes
                .iter()
                .any(|candidate| candidate.pid == process.parent_pid)
        })
        .map(|process| process.pid)
        .collect()
}

#[cfg(windows)]
fn normalize_windows_path(path: &std::path::Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_start_matches(r"\\?\")
        .to_lowercase()
}

/// Enumerate only processes whose OS-reported executable path exactly matches
/// this user's installed trust-local.exe. Matching by image name alone would
/// kill detector processes belonging to another Windows account or sandbox.
#[cfg(windows)]
fn windows_trust_local_processes() -> Result<Vec<WindowsProcess>, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let expected = std::fs::canonicalize(bin_path()).unwrap_or_else(|_| bin_path());
    let expected = normalize_windows_path(&expected);
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateToolhelp32Snapshot: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut matches = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let pid = entry.th32ProcessID;
        if pid != 0 {
            if let Some(actual) = crate::proxy_proc::process_identity(pid) {
                if normalize_windows_path(&actual) == expected {
                    matches.push(WindowsProcess {
                        pid,
                        parent_pid: entry.th32ParentProcessID,
                    });
                }
            }
        }
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    Ok(matches)
}

/// Task Scheduler can report `/End` success after terminating only the hidden
/// PowerShell launcher. Kill the exact installed binary's remaining roots with
/// `/T`, then poll the process table and fail if anything survives.
#[cfg(windows)]
fn windows_stop() -> Result<(), String> {
    // Always attempt /End first so the registered task no longer supervises or
    // respawns the daemon. A Ready task may return a non-zero result while an
    // orphan is still alive; final process state, not that localized message,
    // is the authoritative stop result.
    let scheduler_result = sc_action("stop");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let survivors = windows_trust_local_processes()?;
        if survivors.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let pids = survivors
                .iter()
                .map(|process| process.pid.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let scheduler_detail = scheduler_result
                .err()
                .map(|detail| format!("; schtasks: {detail}"))
                .unwrap_or_default();
            return Err(format!(
                "trust-local process tree still running after stop (PID(s): {pids}){scheduler_detail}"
            ));
        }
        // Re-enumerate and retry each pass. A parent can exit between the
        // snapshot and taskkill, orphaning its child under a new parent; the
        // next pass then treats that survivor as a root instead of waiting the
        // full timeout without another termination attempt.
        for pid in process_tree_roots(&survivors) {
            let pid_arg = pid.to_string();
            let _ = run("taskkill", &["/PID", &pid_arg, "/T", "/F"]);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(not(windows))]
fn windows_stop() -> Result<(), String> {
    Err("Windows trust-local stop requested on a non-Windows build".to_string())
}

pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
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

/// How long `stop` waits for launchd to report the job down.
///
/// Why 12s: the measured respawn appeared ~10s after the kill (launchd's own
/// throttle floor), so the window has to clear that or the check would pass on
/// the very gap it exists to catch. It is NOT sized against the ~20s binary
/// boot time — we watch launchd's job state, which flips as soon as the job is
/// spawned, long before the process finishes unpacking and binds :8801.
#[cfg(target_os = "macos")]
const STOP_VERIFY_SECS: u64 = 12;

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

    /// Fence for the macOS stop-verification parse.
    ///
    /// Why it matters: if `parse_launchd_pid` ever returns None for a job that
    /// IS running, `stop` goes back to reporting success over a live respawn —
    /// the exact 2026-08-14 bug. The samples below are real `launchctl print`
    /// output captured from a running aikey.trust-local, trimmed to the shapes
    /// that matter (tab indentation preserved).
    #[cfg(target_os = "macos")]
    #[test]
    fn parse_launchd_pid_reads_the_job_pid_not_a_neighbouring_key() {
        let running = "\tstate = running\n\truns = 43\n\tpid = 65264\n\t\tstate = active\n";
        assert_eq!(parse_launchd_pid(running), Some(65264));

        // A stopped job still prints its dump — with no pid line. Reading this
        // as "running" would make every stop fail; reading a *running* job as
        // stopped is the dangerous direction, covered above.
        let stopped = "\tstate = not running\n\truns = 43\n\tlast exit code = 0\n";
        assert_eq!(parse_launchd_pid(stopped), None);

        // Keys that merely CONTAIN a number must not be mistaken for the pid.
        let decoys = "\toriginal pid = 999\n\tstate = not running\n\truns = 43\n";
        assert_eq!(parse_launchd_pid(decoys), None);
    }

    #[test]
    fn process_tree_roots_avoid_redundant_child_kills() {
        let processes = [
            WindowsProcess {
                pid: 100,
                parent_pid: 50,
            },
            WindowsProcess {
                pid: 101,
                parent_pid: 100,
            },
            WindowsProcess {
                pid: 200,
                parent_pid: 75,
            },
        ];
        assert_eq!(process_tree_roots(&processes), vec![100, 200]);
    }
}
