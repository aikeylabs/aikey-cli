//! local-server start-failure diagnosis — turn a silent timeout into an
//! ordered, self-serviceable cause list.
//!
//! Why this module exists (bugfix 2026-07-29): a Win10 user ran `ak web`,
//! watched "Starting local-server…" wait 25 seconds, and got NOTHING — no
//! cause, no next step. The machine's actual problem (a broken DACL on
//! `~/.aikey/data\` from an older install → SQLITE_CANTOPEN(14) the instant
//! the server opened control.db) was knowable at that moment from local
//! evidence alone; the CLI simply never looked. Worse, the installer's own
//! failure text blamed ports/AV, sending the user in the wrong direction.
//!
//! Design:
//!   - `Probes` is a plain snapshot of local evidence, collected by
//!     `collect_start_failure_probes` (the only OS-touching part).
//!   - `diagnose` is a PURE function over that snapshot — a table of
//!     candidate causes ordered by decisiveness, fully unit-testable with no
//!     real service, registry, or filesystem.
//!   - Every `Finding` is three-part: conclusion / evidence / paste-ready fix
//!     commands. The evidence is printed so the user can re-check the
//!     reasoning themselves instead of trusting the CLI's verdict.
//!   - `diagnose` NEVER returns empty: if nothing matches, the fallback
//!     finding hands the user the foreground command that reproduces the
//!     failure with the error visible — the self-service path of last resort.
//!
//! Ordering rationale (most decisive first, not most common first): a probe
//! that PROVES impossibility (data dir unwritable, binary missing) beats a
//! statistical guess, so the user's first read is the most trustworthy line.

use std::path::PathBuf;

use crate::local_server_probe::Edition;

/// One diagnosed candidate cause.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Conclusion — what is wrong, one line.
    pub cause: String,
    /// Evidence — why we think so; verifiable by the user.
    pub evidence: String,
    /// Paste-ready fix commands / steps, in order.
    pub fix: Vec<String>,
}

/// Snapshot of local evidence relevant to "the web service did not come up".
/// Collected once, then judged purely. All fields are plain data so tests can
/// fabricate any machine state.
#[derive(Debug, Default, Clone)]
pub struct Probes {
    /// The service binary's expected path and whether it exists.
    pub binary_path: String,
    pub binary_exists: bool,
    /// Supervisor registration (ScheduledTask / launchd plist / systemd unit).
    pub supervisor_kind: String,
    pub supervisor_unit: String,
    pub supervisor_registered: bool,
    /// Short raw status from the supervisor when registered (schtasks verbose
    /// fields / `launchctl print` excerpt / `systemctl status` head).
    pub supervisor_status: Option<String>,
    /// The port the service should listen on, and who (if anyone) holds it.
    pub port: u16,
    pub port_holder: Option<PortHolder>,
    /// Expected config file (first existing candidate, or first expected path).
    pub config_path: String,
    pub config_exists: bool,
    /// Result of a REAL write probe in the data dir (None = probe not run).
    /// false is the SQLITE_CANTOPEN precursor: no SQLite DB there can open.
    pub data_dir: String,
    pub data_dir_writable: Option<bool>,
    /// Log tails, each (path, non-empty tail). Order matters and is fixed by
    /// the collector: control.log (the server's OWN structured log) FIRST —
    /// live forensics 2026-07-29 found the real error there while both svc
    /// stdout/stderr redirect files were empty.
    pub control_log_tail: Option<(String, String)>,
    pub svc_err_log_tail: Option<(String, String)>,
    pub cli_fallback_log_tail: Option<(String, String)>,
    /// The installer command for this edition/platform (re-run hint).
    pub installer_hint: String,
    /// Foreground reproduction command (last-resort self-service).
    pub foreground_hint: String,
}

/// Who is listening on the expected port.
#[derive(Debug, Clone)]
pub struct PortHolder {
    pub pid: u32,
    pub name: String,
    /// True when the listener IS our web service binary (then the port is not
    /// a conflict — the service is up or wedged, a different diagnosis).
    pub is_our_service: bool,
}

/// Pure candidate-cause table over a `Probes` snapshot. See module docs for
/// the ordering rationale. C-numbers refer to the design table in
/// workflow/CI/bugfix/20260729-ak-web-autostart-bypasses-supervisor-and-discards-stderr.md.
pub fn diagnose(p: &Probes) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    // C7 — data dir unwritable (the 2026-07-29 Win10 root cause). Most
    // decisive: with this true the service dies on control.db no matter what
    // else is right, so it MUST outrank every other line.
    if p.data_dir_writable == Some(false) {
        out.push(Finding {
            cause: format!(
                "data directory ACL is broken — {} is not writable by you, so the service \
                 dies opening its SQLite database (SQLITE_CANTOPEN, error 14) immediately \
                 after start",
                p.data_dir
            ),
            evidence: format!(
                "a real write probe (creating a temp file in {}) just failed; this is the \
                 same check the installer's data_acl gate performs",
                p.data_dir
            ),
            fix: vec![
                "This needs an ELEVATED (Administrator) shell — an orphaned/empty DACL cannot \
                 be repaired unprivileged. That is the only step requiring elevation."
                    .to_string(),
                format!("takeown /F \"{}\" /R /D Y", p.data_dir),
                format!(
                    "icacls \"{}\" /grant:r \"%USERNAME%:(OI)(CI)F\" \"SYSTEM:(OI)(CI)F\" \
                     \"Administrators:(OI)(CI)F\" /T /C",
                    parent_of(&p.data_dir)
                ),
                format!(
                    "then re-run the installer (idempotent): {}",
                    p.installer_hint
                ),
            ],
        });
    }

    // C2 — binary missing: nothing can start.
    if !p.binary_exists {
        out.push(Finding {
            cause: "the web service binary is not installed (or the install was interrupted)"
                .to_string(),
            evidence: format!("{} does not exist", p.binary_path),
            fix: vec![format!("re-run the installer: {}", p.installer_hint)],
        });
    }

    // C6 — config missing: the service exits before listening.
    if p.binary_exists && !p.config_exists {
        out.push(Finding {
            cause: "the service config file was never rendered — startup fails before \
                    the port is bound"
                .to_string(),
            evidence: format!("expected config not found: {}", p.config_path),
            fix: vec![format!(
                "re-run the installer (it renders the config): {}",
                p.installer_hint
            )],
        });
    }

    // C3 — port conflict: only when the holder is NOT our own service.
    if let Some(h) = &p.port_holder {
        if !h.is_our_service {
            out.push(Finding {
                cause: format!(
                    "port {} is already taken by another program — the service can start \
                     but can never bind its listener",
                    p.port
                ),
                evidence: format!("PID {} ({}) is listening on {}", h.pid, h.name, p.port),
                fix: vec![format!(
                    "either stop that program (PID {}), or change the service port in {} \
                         (listen:) and retry",
                    h.pid, p.config_path
                )],
            });
        }
    }

    // C1 — supervisor not registered: the installer's registration step never
    // completed on this machine (half-finished install).
    if p.binary_exists && !p.supervisor_registered {
        out.push(Finding {
            cause: format!(
                "no {} named '{}' is registered — the installer's service-registration step \
                 did not complete on this machine, so nothing supervises the service \
                 (no auto-start at boot, no restart on crash)",
                p.supervisor_kind, p.supervisor_unit
            ),
            evidence: format!(
                "queried the {} registry for '{}': not found, while the binary itself is \
                 present at {}",
                p.supervisor_kind, p.supervisor_unit, p.binary_path
            ),
            fix: vec![format!(
                "re-run the installer (idempotent — it re-registers the {}): {}",
                p.supervisor_kind, p.installer_hint
            )],
        });
    }

    // C4 — registered but not running / crashed: relay the supervisor's own
    // status so the user sees what the OS saw.
    if p.supervisor_registered {
        if let Some(status) = &p.supervisor_status {
            if !status.trim().is_empty() {
                out.push(Finding {
                    cause: format!(
                        "the {} '{}' is registered but the service is not staying up — \
                         it is starting and then dying",
                        p.supervisor_kind, p.supervisor_unit
                    ),
                    evidence: format!("supervisor status:\n{}", indent(status)),
                    fix: vec![
                        "read the log tails below — the service's own log names the real \
                         error in almost every observed case"
                            .to_string(),
                    ],
                });
            }
        }
    }

    // C5 — log tails, fixed order: control.log FIRST (the server's own
    // structured log is where Go services actually write their dying words;
    // the svc stdout/stderr redirects are often empty — proven live
    // 2026-07-29), then the supervisor's stderr redirect, then the CLI
    // fallback-spawn log.
    for tail in [
        &p.control_log_tail,
        &p.svc_err_log_tail,
        &p.cli_fallback_log_tail,
    ]
    .into_iter()
    .flatten()
    {
        let (path, content) = tail;
        if !content.trim().is_empty() {
            out.push(Finding {
                cause: format!("recent errors in {}", path),
                evidence: indent(content),
                fix: vec![
                    "the lines above are the service's own words — fix what they name, \
                     or share them when asking for help"
                        .to_string(),
                ],
            });
        }
    }

    // Last resort — NEVER return empty (an empty diagnosis is the silent 25s
    // all over again). Hand over the foreground command that reproduces the
    // failure with the error on screen.
    if out.is_empty() {
        out.push(Finding {
            cause: "no local evidence pinpointed the failure automatically".to_string(),
            evidence: format!(
                "binary present: {}; {} '{}' registered: {}; port {} holder: {}; config \
                 present: {}; no non-empty log tails",
                p.binary_exists,
                p.supervisor_kind,
                p.supervisor_unit,
                p.supervisor_registered,
                p.port,
                p.port_holder
                    .as_ref()
                    .map(|h| format!("PID {} ({})", h.pid, h.name))
                    .unwrap_or_else(|| "none".to_string()),
                p.config_exists,
            ),
            fix: vec![
                format!(
                    "run the service in the FOREGROUND so its error prints directly to \
                     your terminal: {}",
                    p.foreground_hint
                ),
                "then share that output when asking for help".to_string(),
            ],
        });
    }

    out
}

/// Render findings in the house error style (cf. augment_hook_update_error):
/// conclusion first, then evidence, then paste-ready fix steps.
pub fn render_findings(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("Possible causes (most likely first):\n");
    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!("\n{}. {}\n", i + 1, f.cause));
        out.push_str(&format!("   Evidence: {}\n", f.evidence.trim_start()));
        if !f.fix.is_empty() {
            out.push_str("   To fix:\n");
            for (j, step) in f.fix.iter().enumerate() {
                out.push_str(&format!("     {}. {}\n", j + 1, step));
            }
        }
    }
    out
}

/// Collect a real `Probes` snapshot for this host. The only OS-touching part;
/// everything downstream is pure. Best-effort throughout — a probe that
/// cannot run records its neutral value rather than failing the diagnosis.
pub fn collect_start_failure_probes(edition: Edition, port: u16) -> Probes {
    use crate::local_server_probe as probe;

    let home = crate::commands_account::resolve_user_home();
    let aikey = home.join(".aikey");

    let bin_name = match edition {
        Edition::Personal => "aikey-local-server",
        Edition::Trial => "aikey-full-trial",
    };
    let bin_file = if cfg!(windows) {
        format!("{}.exe", bin_name)
    } else {
        bin_name.to_string()
    };
    let binary_path = aikey.join("bin").join(&bin_file);

    let id = probe::service_identity(edition);
    let registered = probe::supervisor_registered(&id);

    // Config: first existing candidate wins; otherwise report the
    // edition-preferred expected path.
    let candidates = [
        aikey.join("config").join("control.yaml"),
        aikey.join("config").join("control-trial.yaml"),
    ];
    let existing = candidates.iter().find(|p| p.exists());
    let (config_path, config_exists) = match existing {
        Some(p) => (p.display().to_string(), true),
        None => (candidates[0].display().to_string(), false),
    };

    // Real write probe in data\ — the same evidence the installer's data_acl
    // gate uses; a false here IS the SQLITE_CANTOPEN precursor.
    let data_dir = aikey.join("data");
    let data_dir_writable = {
        let probe_file = data_dir.join(format!(".acl-probe-cli-{}.tmp", std::process::id()));
        match std::fs::write(&probe_file, b"ok") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe_file);
                Some(true)
            }
            Err(_) => Some(false),
        }
    };

    let port_holder = probe::find_listening_pid(port).map(|pid| {
        let name = process_name(pid).unwrap_or_else(|| "unknown".to_string());
        let is_our_service = name.contains("local-server") || name.contains("full-trial");
        PortHolder {
            pid,
            name,
            is_our_service,
        }
    });

    let logs = aikey.join("logs");
    let tail = |p: PathBuf| -> Option<(String, String)> {
        let content = std::fs::read_to_string(&p).ok()?;
        let tail: Vec<&str> = content.lines().rev().take(15).collect();
        let joined = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
        (!joined.trim().is_empty()).then(|| (p.display().to_string(), joined))
    };

    let foreground = foreground_hint(&binary_path.display().to_string(), &config_path);
    Probes {
        binary_path: binary_path.display().to_string(),
        binary_exists: binary_path.exists(),
        supervisor_kind: supervisor_kind_label().to_string(),
        supervisor_unit: id.unit.clone(),
        supervisor_registered: registered,
        supervisor_status: registered
            .then(|| supervisor_status_excerpt(&id.unit))
            .flatten(),
        port,
        port_holder,
        config_path,
        config_exists,
        data_dir: data_dir.display().to_string(),
        data_dir_writable,
        control_log_tail: tail(logs.join("control.log")),
        svc_err_log_tail: id.err_log.clone().and_then(tail),
        cli_fallback_log_tail: tail(probe::cli_fallback_err_log()),
        installer_hint: installer_hint(edition),
        foreground_hint: foreground,
    }
}

fn supervisor_kind_label() -> &'static str {
    match std::env::consts::OS {
        "windows" => "Scheduled Task",
        "macos" => "launchd agent",
        _ => "systemd unit",
    }
}

/// A short excerpt of the supervisor's own view of the service — enough for
/// C4's evidence without dumping pages.
fn supervisor_status_excerpt(unit: &str) -> Option<String> {
    use std::process::Command;
    let out = match std::env::consts::OS {
        "windows" => Command::new("schtasks")
            .args(["/Query", "/TN", unit, "/V", "/FO", "LIST"])
            .output()
            .ok()?,
        "macos" => {
            let uid = crate::trust_local_service::current_uid().to_string();
            Command::new("launchctl")
                .args(["print", &format!("gui/{}/{}", uid, unit)])
                .output()
                .ok()?
        }
        _ => Command::new("systemctl")
            .args(["status", "--no-pager", "-n", "0", unit])
            .output()
            .ok()?,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let interesting: Vec<&str> = text
        .lines()
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            // The fields that actually explain "why is it not up".
            [
                "status",
                "last result",
                "last run",
                "state",
                "exit",
                "active",
                "pid",
            ]
            .iter()
            .any(|k| l.contains(k))
        })
        .take(6)
        .collect();
    let s = interesting.join("\n");
    (!s.trim().is_empty()).then_some(s)
}

fn process_name(pid: u32) -> Option<String> {
    use std::process::Command;
    if cfg!(windows) {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        line.split(',')
            .next()
            .map(|s| s.trim_matches('"').to_string())
    } else {
        let out = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
}

fn installer_hint(edition: Edition) -> String {
    let (sh, ps1) = match edition {
        Edition::Personal => ("local-install.sh", "local-install.ps1"),
        Edition::Trial => ("trial-install.sh", "trial-install.ps1"),
    };
    if cfg!(windows) {
        format!("powershell -ExecutionPolicy Bypass -File .\\{}", ps1)
    } else {
        format!("./{}", sh)
    }
}

fn foreground_hint(binary: &str, config: &str) -> String {
    if cfg!(windows) {
        format!("& \"{}\" serve --config \"{}\"", binary, config)
    } else {
        format!("\"{}\" serve", binary)
    }
}

fn parent_of(dir: &str) -> String {
    std::path::Path::new(dir)
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| dir.to_string())
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("     | {}", l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A healthy-looking machine where only ONE aspect is broken per test.
    fn base_probes() -> Probes {
        Probes {
            binary_path: "/home/u/.aikey/bin/aikey-local-server".into(),
            binary_exists: true,
            supervisor_kind: "Scheduled Task".into(),
            supervisor_unit: "AikeyLocalServer".into(),
            supervisor_registered: true,
            supervisor_status: None,
            port: 8090,
            port_holder: None,
            config_path: "/home/u/.aikey/config/control.yaml".into(),
            config_exists: true,
            data_dir: "C:\\Users\\u\\.aikey\\data".into(),
            data_dir_writable: Some(true),
            control_log_tail: None,
            svc_err_log_tail: None,
            cli_fallback_log_tail: None,
            installer_hint: "powershell -ExecutionPolicy Bypass -File .\\local-install.ps1".into(),
            foreground_hint: "& aikey-local-server.exe serve".into(),
        }
    }

    /// 🔴 The 2026-07-29 Win10 field failure. A broken data-dir ACL must be
    /// diagnosed BY NAME with the elevated repair (takeown + icacls) — never
    /// lumped into "unknown".
    ///
    /// 能红: drop the C7 branch from `diagnose` → the ACL cause disappears and
    /// only the fallback finding remains.
    #[test]
    fn diagnose_detects_broken_data_acl() {
        let mut p = base_probes();
        p.data_dir_writable = Some(false);
        let f = diagnose(&p);
        assert!(
            f[0].cause.contains("ACL") && f[0].cause.contains("SQLITE_CANTOPEN"),
            "broken data dir must be the FIRST finding and name the mechanism, got: {}",
            f[0].cause
        );
        let fixes = f[0].fix.join("\n");
        assert!(
            fixes.contains("takeown") && fixes.contains("icacls"),
            "fix must carry the paste-ready elevated repair, got:\n{}",
            fixes
        );
        assert!(
            fixes.to_lowercase().contains("administrator"),
            "fix must say WHY elevation is needed (orphaned DACL), got:\n{}",
            fixes
        );
    }

    /// The half-installed machine (registration step skipped/failed): binary
    /// present, supervisor missing → C1 first, pointing at the installer.
    ///
    /// 能红: drop the C1 branch → only the fallback remains.
    #[test]
    fn diagnose_reports_unregistered_supervisor_first() {
        let mut p = base_probes();
        p.supervisor_registered = false;
        let f = diagnose(&p);
        assert!(
            f[0].cause.contains("not complete") || f[0].cause.contains("registration"),
            "unregistered supervisor must be finding #1, got: {}",
            f[0].cause
        );
        assert!(
            f[0].fix.join(" ").contains("local-install.ps1"),
            "fix must hand over the exact installer re-run command"
        );
    }

    /// 🔴 Anti-silence: the diagnosis must NEVER be empty — an empty answer is
    /// the 25s-of-nothing this module exists to kill. The fallback must hand
    /// over the foreground reproduction command.
    ///
    /// 能红: remove the `if out.is_empty()` fallback block.
    #[test]
    fn diagnose_never_returns_empty() {
        let f = diagnose(&base_probes());
        assert!(!f.is_empty(), "diagnosis must never be empty");
        assert!(
            f.last().unwrap().fix.join(" ").contains("serve"),
            "the last-resort fix must include the foreground reproduction command"
        );
    }

    /// C5 ordering: control.log (the server's OWN log) must be surfaced before
    /// the supervisor's stderr redirect — live forensics found the real error
    /// in control.log while both svc redirects were EMPTY files.
    ///
    /// 能红: swap the tail order in `diagnose`'s C5 array.
    #[test]
    fn diagnose_reads_control_log_before_svc_redirects() {
        let mut p = base_probes();
        p.control_log_tail = Some((
            "logs/control.log".into(),
            r#"{"msg":"open database","error":"probe journal_mode: unable to open database file (14)"}"#.into(),
        ));
        p.svc_err_log_tail = Some(("logs/local-server-svc.err.log".into(), "older noise".into()));
        let f = diagnose(&p);
        let idx_control = f
            .iter()
            .position(|x| x.cause.contains("control.log"))
            .expect("control.log tail must be surfaced");
        let idx_svc = f
            .iter()
            .position(|x| x.cause.contains("svc.err.log"))
            .expect("svc err tail must be surfaced");
        assert!(
            idx_control < idx_svc,
            "control.log must come before the svc stderr redirect"
        );
        assert!(
            f[idx_control]
                .evidence
                .contains("unable to open database file (14)"),
            "the actual error line must be shown verbatim"
        );
    }

    /// C5 presence: any non-empty tail must be surfaced even when another
    /// cause already matched — the log is the only line that can name the true
    /// error, so it must never be crowded out.
    ///
    /// 能红: gate the C5 loop behind `out.is_empty()`.
    #[test]
    fn diagnose_surfaces_log_tail_when_present() {
        let mut p = base_probes();
        p.supervisor_registered = false; // C1 matches…
        p.control_log_tail = Some(("logs/control.log".into(), "fatal: something real".into()));
        let f = diagnose(&p);
        assert!(
            f.iter().any(|x| x.cause.contains("control.log")),
            "log tail must be surfaced alongside other findings"
        );
    }

    /// A port held by OUR OWN service is not a conflict finding — that state
    /// means "already running / wedged", and calling it a conflict would tell
    /// the user to kill their own healthy service.
    #[test]
    fn own_service_on_port_is_not_a_conflict() {
        let mut p = base_probes();
        p.port_holder = Some(PortHolder {
            pid: 4242,
            name: "aikey-local-server".into(),
            is_our_service: true,
        });
        let f = diagnose(&p);
        assert!(
            !f.iter().any(|x| x.cause.contains("already taken")),
            "own service on the port must not be reported as a conflict"
        );
    }

    /// Foreign holder IS a conflict, with PID + name in the evidence.
    #[test]
    fn foreign_port_holder_is_a_conflict_with_pid() {
        let mut p = base_probes();
        p.port_holder = Some(PortHolder {
            pid: 999,
            name: "python.exe".into(),
            is_our_service: false,
        });
        let f = diagnose(&p);
        let conflict = f
            .iter()
            .find(|x| x.cause.contains("already taken"))
            .expect("foreign port holder must be diagnosed");
        assert!(
            conflict.evidence.contains("999") && conflict.evidence.contains("python.exe"),
            "evidence must name PID and process"
        );
    }

    /// Render shape: numbered findings, Evidence + To fix sections — the
    /// three-part contract that makes the output self-serviceable.
    #[test]
    fn render_carries_evidence_and_fix() {
        let mut p = base_probes();
        p.data_dir_writable = Some(false);
        let s = render_findings(&diagnose(&p));
        assert!(s.contains("Possible causes"));
        assert!(s.contains("Evidence:"));
        assert!(s.contains("To fix:"));
        assert!(s.contains("takeown"));
    }
}
