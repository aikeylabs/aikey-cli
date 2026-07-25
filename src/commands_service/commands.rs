//! `aikey service` command dispatch.

use crate::cli::ServiceAction;

/// Short name → (display label, launchd label) lookup. The closed
/// whitelist is the security boundary for the web equivalent endpoint
/// `/api/internal/services/<name>/<action>` — both share this table.
const SUPPORTED_SERVICES: &[(&str, &str)] = &[
    (
        "trust-local",
        "AiKey trust-local (degrade-detector observer + scoring)",
    ),
    ("web", "AiKey local-server (Personal Web Console on :8090)"),
    (
        "proxy",
        "AiKey local proxy (:27200, BYOK routing + observer host)",
    ),
];

/// Entry point — invoked from main.rs Commands::Service { action } arm.
///
/// `name` is optional; without it we print the supported list. With it
/// we dispatch by name. Errors are bubbled as Box<dyn Error> so
/// existing main.rs error handling formats them.
pub(crate) fn handle_service(
    action: &ServiceAction,
    json: bool,
    password_stdin: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (verb, name) = match action {
        ServiceAction::Start { name } => ("start", name),
        ServiceAction::Stop { name } => ("stop", name),
        ServiceAction::Restart { name } => ("restart", name),
        ServiceAction::Status { name } => ("status", name),
    };

    let Some(name) = name.as_deref() else {
        // No name given. For the read-only `status` verb this means "show
        // every service at once" (the aggregate dashboard). For the
        // mutating verbs there's no safe all-services default, so we print
        // the supported list instead (users usually land here by tab-
        // completing and forgetting the name).
        if verb == "status" {
            return status_all(json);
        }
        print_supported(json);
        return Ok(());
    };

    // `all` is an explicit meta-target, NOT a whitelisted service. It fans out
    // to every installed service: for read-only `status` it's an alias of the
    // bare-`status` aggregate; for mutating verbs it runs the best-effort
    // orchestrator. Handled BEFORE is_supported() on purpose — `all` is
    // deliberately kept out of SUPPORTED_SERVICES so the web
    // `/api/internal/services/<name>/<action>` endpoint (which shares that
    // table as its security boundary) can only ever target one concrete
    // service per call, never a fan-out.
    if name == "all" {
        return if verb == "status" {
            status_all(json)
        } else {
            run_all(verb, json, password_stdin)
        };
    }

    if !is_supported(name) {
        let msg = format!(
            "unknown service '{}'. Supported: {}",
            name,
            SUPPORTED_SERVICES
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", "),
        );
        if json {
            println!(
                "{}",
                serde_json::json!({"ok": false, "error": "UNKNOWN_SERVICE", "detail": msg})
            );
        } else {
            eprintln!("{}", msg);
        }
        return Err(msg.into());
    }

    match name {
        "trust-local" => trust_local::dispatch(verb, json),
        "web" => web::dispatch(verb, json),
        "proxy" => proxy::dispatch(verb, json, password_stdin),
        _ => unreachable!("guarded by is_supported() above"),
    }
}

fn is_supported(name: &str) -> bool {
    SUPPORTED_SERVICES.iter().any(|(n, _)| *n == name)
}

fn print_supported(json: bool) {
    if json {
        let payload: Vec<_> = SUPPORTED_SERVICES
            .iter()
            .map(|(name, label)| serde_json::json!({"name": name, "description": label}))
            .collect();
        println!("{}", serde_json::json!({"supported_services": payload}));
    } else {
        println!("Supported services:");
        for (name, label) in SUPPORTED_SERVICES {
            println!("  {:<14}  {}", name, label);
        }
        println!("  {:<14}  {}", "all", "every installed service above (fan-out)");
        println!();
        println!("Usage: aikey service <start|stop|restart|status> <name|all>");
    }
}

/// `aikey service status` (no name) — one-line status for every registered
/// service. Each row delegates to that service's own compact probe
/// (`status_summary`), so this aggregate is a pure view: it never owns a
/// second copy of any service's health logic and can't drift from the
/// per-service `status` commands.
fn status_all(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let rows: Vec<(&str, bool, String)> = vec![
        {
            let (r, d) = crate::local_server_probe::status_summary();
            ("web", r, d)
        },
        {
            let (r, d) = crate::commands_proxy::status_summary();
            ("proxy", r, d)
        },
        {
            let (r, d) = trust_local::status_summary();
            ("trust-local", r, d)
        },
    ];

    if json {
        let payload: Vec<_> = rows
            .iter()
            .map(|(name, running, detail)| {
                serde_json::json!({"name": name, "running": running, "detail": detail})
            })
            .collect();
        println!("{}", serde_json::json!({"services": payload}));
    } else {
        for (name, running, detail) in &rows {
            // Aligned two-column table: fixed-width name, state glyph, detail.
            let glyph = if *running {
                crate::symbols::RADIO_ON.s()
            } else {
                crate::symbols::RADIO_OFF.s()
            };
            println!("{glyph} {name:<12}  {detail}");
        }
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────
// `all` meta-target orchestrator
// ───────────────────────────────────────────────────────────────────

/// Outcome plan for one service leg of `aikey service <verb> all`. Kept as a
/// pure function so the orchestration policy (skip vs act) is unit-testable
/// without spawning real services — the actual spawn is delegated to the
/// already-tested per-service dispatchers.
#[derive(Debug, PartialEq, Eq)]
enum LegPlan {
    /// Don't touch this service; the reason is shown to the user.
    Skip(&'static str),
    /// Perform the verb via the canonical per-service dispatcher.
    Act,
}

/// Decide what `all` does for one service given its installed/running state.
/// Idempotent by design:
///   - not installed       → skip on every verb (an edition without this service)
///   - start + running     → skip: avoids re-prompting the proxy vault password
///                           and avoids bouncing trust-local, whose `start` is a
///                           kill-restart (`launchctl kickstart -k`)
///   - stop  + not running  → skip
///   - restart / start-when-stopped / stop-when-running → act
fn plan_leg(verb: &str, installed: bool, running: bool) -> LegPlan {
    if !installed {
        return LegPlan::Skip("not installed");
    }
    match verb {
        "start" if running => LegPlan::Skip("already running"),
        "stop" if !running => LegPlan::Skip("already stopped"),
        _ => LegPlan::Act,
    }
}

/// `aikey service <start|stop|restart> all` — best-effort orchestrator over
/// every INSTALLED whitelist service (proxy + web + trust-local).
///
/// It owns no per-service lifecycle logic: each acting leg calls the same
/// canonical dispatcher as `aikey service <verb> <name>`, so `all` can never
/// drift from the single-service commands. It only adds orchestration:
///   - ordering: proxy (main data-path link) comes up first; teardown reverses
///     so the observer/console stop before the proxy,
///   - idempotent + not-installed skips (see `plan_leg`),
///   - best-effort execution: one service failing does NOT abort the others,
///   - a loud aggregate: a non-zero exit when ANY installed service failed.
///
/// Output: each acting leg prints its own native line(s) (identical to the
/// single-service command); this function adds a skip line per skipped service
/// and a final summary. In `--json` mode the stream is newline-delimited JSON
/// (the underlying command's object per acting leg + a skip object per skipped
/// service + a final summary object) — this mirrors how json-ness already
/// varies across the per-service mutating commands, rather than inventing a
/// single-object shape that would require silencing them.
fn run_all(
    verb: &str,
    json: bool,
    password_stdin: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // proxy first (main link), then console, then observer. Teardown reverses.
    let mut order = vec!["proxy", "web", "trust-local"];
    if verb == "stop" {
        order.reverse();
    }

    let (mut acted, mut skipped, mut failed) = (0u32, 0u32, 0u32);

    for svc in order {
        let (installed, running) = leg_state(svc);
        match plan_leg(verb, installed, running) {
            LegPlan::Skip(reason) => {
                skipped += 1;
                emit_skip(svc, verb, reason, json);
            }
            LegPlan::Act => {
                let res = match svc {
                    "proxy" => proxy::dispatch(verb, json, password_stdin),
                    "web" => web::dispatch(verb, json),
                    "trust-local" => trust_local::dispatch(verb, json),
                    _ => unreachable!("order slice only holds whitelist names"),
                };
                match res {
                    Ok(()) => acted += 1,
                    Err(e) => {
                        failed += 1;
                        // The dispatcher already surfaced its own error in its
                        // mode; add a service-attributed line so the aggregate
                        // reads clearly even when several legs run.
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "name": svc, "action": verb,
                                    "result": "failed", "detail": e.to_string(),
                                })
                            );
                        } else {
                            eprintln!("{} {}: {}", crate::symbols::CROSS.s(), svc, e);
                        }
                    }
                }
            }
        }
    }

    emit_summary(verb, acted, skipped, failed, json);

    if failed > 0 {
        // Non-zero exit — failures must be loud (project principle).
        return Err(format!("service {verb} all: {failed} service(s) failed").into());
    }
    Ok(())
}

/// (installed, running) for one whitelist service, via that service's existing
/// read-only probe — never spawns, never prompts.
fn leg_state(svc: &str) -> (bool, bool) {
    match svc {
        // proxy is edition-agnostic — always "installed".
        "proxy" => (true, crate::commands_proxy::status_summary().0),
        "web" => {
            let installed = crate::local_server_probe::is_local_server_installed();
            (
                installed,
                installed && crate::local_server_probe::status_summary().0,
            )
        }
        "trust-local" => {
            let installed = trust_local::is_installed();
            (installed, installed && trust_local::status_summary().0)
        }
        _ => (false, false),
    }
}

fn emit_skip(svc: &str, verb: &str, reason: &str, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "name": svc, "action": verb, "result": "skipped", "reason": reason,
            })
        );
    } else {
        println!("- {svc}: skipped ({reason})");
    }
}

fn emit_summary(verb: &str, acted: u32, skipped: u32, failed: u32, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": failed == 0,
                "action": format!("{verb} all"),
                "acted": acted, "skipped": skipped, "failed": failed,
                "summary": true,
            })
        );
    } else {
        println!();
        println!("Summary: {acted} acted, {skipped} skipped, {failed} failed");
    }
}

// ───────────────────────────────────────────────────────────────────
// per-service drivers
// ───────────────────────────────────────────────────────────────────

mod trust_local {
    //! launchctl / systemctl --user driver for `aikey.trust-local`.
    //! Mirrors the helpers I drafted earlier in commands_trust/commands.rs
    //! but lives here as the canonical owner — commands_trust no longer
    //! exposes service control.

    use std::time::{Duration, Instant};

    const SERVICE_NAME: &str = "aikey.trust-local";

    /// Compact one-line status for the aggregate + the `status` verb.
    /// Read-only: a single-shot healthz probe on :8801 (no 30s wait — that
    /// belongs to post-start). "not installed" is a status, not an error.
    pub(super) fn status_summary() -> (bool, String) {
        if !aikey_home_bin_path().exists() {
            return (false, "not installed".to_string());
        }
        if healthz_once() {
            (true, "running on http://127.0.0.1:8801".to_string())
        } else {
            (false, "not running".to_string())
        }
    }

    /// True when the trust-local binary is present — same path truth source as
    /// `status_summary` and the `dispatch` install guard. Lets the `all`
    /// orchestrator skip trust-local on hosts that never installed the
    /// degrade-detector, instead of surfacing a hard TRUST_LOCAL_NOT_INSTALLED
    /// error for the whole `all` run.
    pub(super) fn is_installed() -> bool {
        aikey_home_bin_path().exists()
    }

    /// Single-shot healthz check (no retry loop). Distinct from
    /// `probe_healthz`, which waits up to 30s for a service that was just
    /// asked to start.
    fn healthz_once() -> bool {
        ureq::get("http://127.0.0.1:8801/healthz")
            .timeout(Duration::from_millis(500))
            .call()
            .map(|r| r.status() == 200)
            .unwrap_or(false)
    }

    fn status_detail(json: bool) -> Result<(), Box<dyn std::error::Error>> {
        // `installed` is an explicit field (not inferred from `detail`) so
        // consumers — notably the web trust-check banner via the console —
        // can distinguish "not installed" from "installed but stopped"
        // without string-matching the human detail. Same binary-path truth
        // source as status_summary(). Bugfix:
        // 20260703-trust-check-web-offline-vs-notinstalled-proactive.md.
        let installed = aikey_home_bin_path().exists();
        let (running, detail) = status_summary();
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "service": SERVICE_NAME,
                    "installed": installed,
                    "running": running,
                    "detail": detail,
                })
            );
        } else if running {
            println!("{}: {}", SERVICE_NAME, detail);
        } else {
            println!("{}: {}", SERVICE_NAME, detail);
            if detail == "not installed" {
                println!("    Install: aikey app install degrade-detector");
            } else {
                println!("    Start:   aikey service start trust-local");
            }
        }
        Ok(())
    }

    pub(super) fn dispatch(verb: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        // Read-only status short-circuits before the install check: on a
        // host without trust-local, "not installed" is the answer we want to
        // print, not a hard error like the mutating verbs raise.
        if verb == "status" {
            return status_detail(json);
        }
        // Refuse if trust-local binary isn't installed. Since rc.5 it's
        // installed by default — if it's missing the user either ran
        // `--no-degrade-detector` at install time or `aikey app
        // uninstall degrade-detector` later. Either way the simplest
        // path back is `aikey app install`, not the curl-pipe.
        //
        // Path resolution is cross-platform:
        //   Unix:    $HOME/.aikey/bin/trust-local
        //   Windows: %USERPROFILE%\.aikey\bin\trust-local.exe
        let trust_local_bin = aikey_home_bin_path();
        if !trust_local_bin.exists() {
            let msg = format!(
                "trust-local binary not found at {}. Install via: \
                 aikey app install degrade-detector",
                trust_local_bin.display()
            );
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "error": "TRUST_LOCAL_NOT_INSTALLED", "detail": msg})
                );
            } else {
                eprintln!("{}", msg);
            }
            return Err(msg.into());
        }

        let result = match std::env::consts::OS {
            "macos" => match verb {
                "start" | "restart" => launchctl_kickstart(current_uid()),
                "stop" => launchctl_kill(current_uid()),
                _ => return Err(format!("unknown verb '{}'", verb).into()),
            },
            "linux" => systemctl_user(verb),
            "windows" => match verb {
                "start" | "stop" => sc_action(verb),
                // Windows `sc.exe` has no atomic restart; do stop + wait-for-STOPPED
                // + start. We can't just sleep a fixed interval because `sc.exe stop`
                // is async (returns STOP_PENDING immediately while the service exits);
                // starting before STOPPED → `sc.exe start` returns "1056: service is
                // already running" / "1056: service has been marked for deletion".
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
                _ => return Err(format!("unknown verb '{}'", verb).into()),
            },
            other => {
                return Err(format!(
                    "platform '{}' not supported (service control is macOS / Linux / Windows)",
                    other
                )
                .into())
            }
        };

        // Reachability probe after start/restart. Stop has no probe —
        // we trust the service manager to deliver SIGTERM.
        let final_state = match (&result, verb) {
            (Ok(()), "start") | (Ok(()), "restart") => probe_healthz(),
            _ => result.clone(),
        };

        emit(verb, &final_state, json);
        final_state.map_err(|e| e.into())
    }

    #[cfg(unix)]
    fn current_uid() -> u32 {
        // SAFETY: getuid() is a documented thread-safe syscall.
        unsafe { libc::getuid() }
    }

    // Windows path is unreachable — `dispatch` returns "platform '{}' not
    // supported" before this is called on anything other than macos/linux.
    // The stub exists only so the windows-amd64 cross-compile target type-
    // checks. BR-rc.5-50 — `libc::getuid` is Unix-only and broke Windows
    // build under the rc.5 hotfix re-release.
    #[cfg(not(unix))]
    fn current_uid() -> u32 {
        0
    }

    fn launchctl_kickstart(uid: u32) -> Result<(), String> {
        // -k flag = kill running and start again; idempotent for
        // both "start" and "restart" semantics.
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
    /// 2026-07-06: trust-local migrated from an NSSM-wrapped Windows service to
    /// a per-user ScheduledTask (install_service.ps1), matching the aikey-proxy
    /// + console migration in local-install.ps1. Root cause: nssm.exe is NOT
    /// shipped in the offline package (only on the build box), so the sc.exe
    /// service never registered on real end-user machines and this command
    /// errored with "sc.exe start aikey.trust-local: <service not found>".
    /// The task is registered under the same identifier as SERVICE_NAME.
    /// `schtasks` is Windows-bundled (no nssm dependency).
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

    /// Returns true when trust-local is NOT running. Used by the restart loop
    /// to wait for an async `/End` to finish before re-firing `/Run`.
    ///
    /// We probe the process image name via `tasklist` rather than parsing
    /// `schtasks /Query` Status, because the Status strings ("Running" /
    /// "Ready" / …) are LOCALIZED (e.g. "正在运行" / "就绪" on zh-CN Windows) and
    /// a substring match would break off English hosts. The image name
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

    /// `~/.aikey/bin/trust-local` (Unix) or `%USERPROFILE%\.aikey\bin\trust-local.exe`
    /// (Windows). Mirrors install_service.ps1's `$BinaryPath` resolution.
    fn aikey_home_bin_path() -> std::path::PathBuf {
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
        std::path::PathBuf::from(home)
            .join(".aikey")
            .join("bin")
            .join(binary_name)
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
    /// Why 30s: `launchctl kickstart` returns immediately while launchd
    /// brings trust-local up asynchronously, and the trust-local binary's
    /// cold start is dominated by PyInstaller **onefile self-extraction**
    /// (the 23MB single file re-unpacks its bundled Python runtime + numpy
    /// + deps to a temp dir on every launch) plus the cold-interpreter
    /// import tax (fastapi/starlette/sqlalchemy/pydantic/numpy). That cost
    /// is IO-bound and balloons under machine load: measured 2026-06-08 it
    /// ranged ~5.6s idle to ~20.3s under load (load avg ~4). The original
    /// 5s window lost that race on nearly every restart and reported a
    /// false "did not become reachable" failure even though launchd had
    /// successfully started the service (user saw "无法启动" then a refresh
    /// showed it online). 30s gives ~1.5x headroom over the worst observed
    /// 20.3s. The probe returns early on first healthz 200, so the typical
    /// success path is far shorter than this ceiling — only a genuine
    /// failure blocks the full 30s. The web caller's context timeout
    /// (service_handler.go) MUST stay above this.
    ///
    /// Root-cause lever (deferred, separate decision): switching the
    /// PyInstaller build to `onedir` extracts once at install time and
    /// would cut cold start to ~3s and remove the load-driven variance,
    /// making this timeout far less load-bearing.
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

    fn emit(verb: &str, result: &Result<(), String>, json: bool) {
        if json {
            let (ok, detail) = match result {
                Ok(()) => (true, String::new()),
                Err(e) => (false, e.clone()),
            };
            println!(
                "{}",
                serde_json::json!({
                    "ok": ok,
                    "action": verb,
                    "service": SERVICE_NAME,
                    "detail": detail,
                })
            );
        } else {
            match result {
                Ok(()) => println!("{}: {} succeeded", SERVICE_NAME, verb),
                Err(e) => eprintln!("{}: {} — {}", SERVICE_NAME, verb, e),
            }
        }
    }
}

mod web {
    //! Forwarder to commands_account::handle_web_service, which is
    //! the existing edition-aware (Personal / Trial) local-server
    //! service controller. We pass through verb + json_mode and
    //! don't replicate any logic.

    pub(super) fn dispatch(verb: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        // status is read-only and lives in its own handler; the mutating
        // verbs go through the existing lifecycle controller. Both spellings
        // (`aikey web status` and `aikey service status web`) land here.
        if verb == "status" {
            return crate::commands_account::handle_web_status(json);
        }
        crate::commands_account::handle_web_service(verb, json)
    }
}

mod proxy {
    //! Forwarder to existing commands_proxy::handle_* for proxy
    //! lifecycle. Stage 1 of the unification (per
    //! roadmap20260320/.../降智检测-M5-kickoff.md §11) — interface
    //! is unified, internal mechanism (PID-file vs launchd) stays
    //! unchanged.
    //!
    //! Stage 2 (deferred): move proxy under launchd too. Blocker:
    //! master password input under launchd needs a keychain / cached-
    //! token design, ~1-2 day spike. Not in this follow-up's scope.

    pub(super) fn dispatch(
        verb: &str,
        json: bool,
        password_stdin: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match verb {
            "status" => {
                // Read-only: no vault password. Human path delegates to the
                // exact same `handle_status()` as `aikey proxy status` (byte-
                // identical output); JSON path reuses `status_summary()`,
                // which derives from the same proxy_state() truth source.
                if json {
                    let (running, detail) = crate::commands_proxy::status_summary();
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": true,
                            "service": "proxy",
                            "running": running,
                            "detail": detail,
                        })
                    );
                } else {
                    crate::commands_proxy::handle_status()?;
                }
                Ok(())
            }
            "start" => {
                // prompt_vault_password lives in main.rs as a thin
                // wrapper around executor::prompt_password; we
                // reuse it via crate visibility.
                let password = crate::prompt_vault_password(password_stdin, false)?;
                crate::executor::list_secrets(&password)
                    .map_err(|e| format!("vault authentication failed: {}", e))?;
                crate::commands_proxy::handle_start(None, true /*detach*/, &password)?;
                Ok(())
            }
            "stop" => {
                crate::commands_proxy::handle_stop()?;
                Ok(())
            }
            "restart" => {
                let password = crate::prompt_vault_password(password_stdin, false)?;
                crate::executor::list_secrets(&password)
                    .map_err(|e| format!("vault authentication failed: {}", e))?;
                crate::commands_proxy::handle_restart(None, &password)?;
                Ok(())
            }
            other => Err(format!("unknown verb '{}'", other).into()),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// fence tests
//
// These pin the whitelist contract — both the CLI dispatcher above
// AND the upcoming /api/internal/services/<name>/<action> endpoint
// will consult the same SUPPORTED_SERVICES table. A test that catches
// "someone removes 'web' from the whitelist by mistake" is more
// useful than a test that mocks every platform command.
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_contains_expected_services() {
        // Pin the exact 3 supported services. New additions go through
        // a SPEC update + explicit test edit so we don't silently grow
        // the surface area an attacker (or buggy caller) can reach.
        let names: Vec<&str> = SUPPORTED_SERVICES.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["trust-local", "web", "proxy"]);
    }

    #[test]
    fn is_supported_known_names() {
        assert!(is_supported("trust-local"));
        assert!(is_supported("web"));
        assert!(is_supported("proxy"));
    }

    // `all` is a meta-target handled BEFORE is_supported() in handle_service.
    // It must NOT leak into the whitelist, or the web
    // /api/internal/services/<name>/<action> endpoint (which shares
    // SUPPORTED_SERVICES) could be driven with name="all" and fan out — the
    // exact single-concrete-service boundary that table exists to enforce.
    #[test]
    fn all_is_not_a_whitelisted_service() {
        assert!(!is_supported("all"));
    }

    // Orchestration policy for `service <verb> all` — pure decision table, no
    // service spawned. Pins the idempotent + not-installed skip semantics.
    #[test]
    fn plan_leg_skips_not_installed_on_every_verb() {
        for verb in ["start", "stop", "restart"] {
            assert_eq!(
                plan_leg(verb, false, false),
                LegPlan::Skip("not installed"),
                "verb {verb}: not-installed must skip regardless of running flag"
            );
            assert_eq!(
                plan_leg(verb, false, true),
                LegPlan::Skip("not installed"),
            );
        }
    }

    #[test]
    fn plan_leg_start_is_idempotent() {
        // running → skip (don't re-prompt proxy password / bounce trust-local)
        assert_eq!(plan_leg("start", true, true), LegPlan::Skip("already running"));
        // stopped → act
        assert_eq!(plan_leg("start", true, false), LegPlan::Act);
    }

    #[test]
    fn plan_leg_stop_is_idempotent() {
        // not running → skip
        assert_eq!(plan_leg("stop", true, false), LegPlan::Skip("already stopped"));
        // running → act
        assert_eq!(plan_leg("stop", true, true), LegPlan::Act);
    }

    #[test]
    fn plan_leg_restart_always_acts_when_installed() {
        assert_eq!(plan_leg("restart", true, true), LegPlan::Act);
        assert_eq!(plan_leg("restart", true, false), LegPlan::Act);
    }

    #[test]
    fn is_supported_rejects_unknown() {
        assert!(!is_supported(""));
        assert!(!is_supported("foo"));
        // launchd-style labels are NOT accepted directly — we accept
        // short names and map to labels internally. This pin prevents
        // a future maintainer from "helpfully" letting users type the
        // full label, which would loosen the security boundary.
        assert!(!is_supported("aikey.trust-local"));
        // Case-sensitive: 'TrustLocal' != 'trust-local'.
        assert!(!is_supported("TrustLocal"));
        // Whitespace not stripped — caller's responsibility to trim.
        assert!(!is_supported(" web"));
        assert!(!is_supported("web "));
    }

    // ── status verb ────────────────────────────────────────────────

    #[test]
    fn status_summary_shape_per_service() {
        // Each service's compact probe returns (bool, non-empty detail).
        // We can't assert the running state (depends on the host), but the
        // contract that the aggregate relies on is: always a printable
        // detail line, never an empty string or a panic.
        for (_, detail) in [
            crate::local_server_probe::status_summary(),
            crate::commands_proxy::status_summary(),
            trust_local::status_summary(),
        ] {
            assert!(!detail.is_empty(), "status detail must be non-empty");
        }
    }

    #[test]
    fn trust_local_status_summary_not_installed_is_status_not_error() {
        // The whole point of status short-circuiting the install check:
        // on a host without the binary, "not installed" is a legitimate
        // (running=false) status, never an Err. This test only holds when
        // trust-local isn't installed on the test host; when it is, the
        // detail is a running/not-running line — either way non-empty and
        // no panic. (Kept assertion loose so it passes on both kinds of
        // host / CI.)
        let (running, detail) = trust_local::status_summary();
        if !running {
            assert!(
                detail == "not installed" || detail == "not running",
                "unexpected trust-local down-detail: {detail}"
            );
        }
    }
}
