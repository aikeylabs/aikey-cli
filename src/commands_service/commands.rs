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
    };

    let Some(name) = name.as_deref() else {
        // Bare `aikey service start` (no name) — print the list and
        // exit non-error. Users typically reach this by tab-completing
        // and forgetting to pass a name.
        print_supported(json);
        return Ok(());
    };

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
        println!();
        println!("Usage: aikey service <start|stop|restart> <name>");
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

    pub(super) fn dispatch(verb: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
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

    /// Windows: drive the NSSM-wrapped service via Windows SCM.
    ///
    /// install_service.ps1 registers the service via `nssm install`, which
    /// produces a real Windows service that responds to `sc.exe` SCM calls.
    /// We use `sc.exe` (Windows-bundled) rather than `nssm.exe` directly to
    /// avoid hard-depending on NSSM being on PATH from this CLI's perspective
    /// (nssm is installed to System32 by setup-aliyun-win-build.ps1, but if
    /// an end-user installed trust-local via the published install_service.ps1
    /// it lands wherever the script placed it).
    fn sc_action(verb: &str) -> Result<(), String> {
        run("sc.exe", &[verb, SERVICE_NAME])
    }

    /// Returns true when `sc.exe query <SERVICE_NAME>` reports `STATE :
    /// 1  STOPPED`. Used by the restart loop to wait for an async `sc.exe
    /// stop` to actually finish before re-firing `sc.exe start` (otherwise
    /// start races stop and returns 1056 / 1062).
    fn sc_is_stopped() -> bool {
        match std::process::Command::new("sc.exe")
            .args(["query", SERVICE_NAME])
            .output()
        {
            Ok(out) => {
                let s = String::from_utf8_lossy(&out.stdout);
                s.contains("STOPPED")
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

    fn probe_healthz() -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
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
        Err("service did not become reachable on :8801 within 5s".to_string())
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
        _json: bool,
        password_stdin: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match verb {
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
}
