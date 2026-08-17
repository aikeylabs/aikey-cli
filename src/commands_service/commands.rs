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
        println!(
            "  {:<14}  {}",
            "all", "every installed service above (fan-out)"
        );
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
            let (r, d) = crate::trust_local_service::status_summary();
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
        // 🔴 schema_version is a wire contract, not decoration.
        //
        // This JSON is consumed across a release boundary: the AiKey tray ships
        // as an independent package, so "old tray + new CLI" is a NORMAL state,
        // not an error case. Without a version the tray has no way to tell
        // "this CLI predates the field I need" from "the field is legitimately
        // absent", and the failure mode is silent — an empty menu, not an error.
        //
        // Rules for changing it (mirrors the project's wire-contract governance):
        //   - Adding an optional field: DO NOT bump. Consumers must ignore
        //     unknown fields, so additive changes stay compatible in both
        //     directions and either side can upgrade first.
        //   - Removing/renaming a field, or changing its type or meaning:
        //     bump. That is the only change a consumer cannot absorb.
        //   - Never use exact equality as a consumer-side gate; compare
        //     against a minimum. Exact-match gating turns every release into
        //     a fleet-wide breakage.
        println!(
            "{}",
            serde_json::json!({"schema_version": 1, "services": payload})
        );
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
fn run_all(verb: &str, json: bool, password_stdin: bool) -> Result<(), Box<dyn std::error::Error>> {
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
            let installed = crate::trust_local_service::is_installed();
            (
                installed,
                installed && crate::trust_local_service::status_summary().0,
            )
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
    //! CLI shell for `aikey.trust-local` service control: the read-only status
    //! detail, the TRUST_LOCAL_NOT_INSTALLED install-guard contract, and the
    //! human/JSON emit. The OS-process core (launchctl/systemctl/schtasks +
    //! healthz probe) moved to the lib+bin module `crate::trust_local_service`
    //! (2026-07-26) so lib-side callers — notably `aikey doctor` (auto-repair) —
    //! drive the SAME one implementation, no parallel launchctl path.

    use crate::trust_local_service as core;

    fn status_detail(json: bool) -> Result<(), Box<dyn std::error::Error>> {
        // `installed` is an explicit field (not inferred from `detail`) so
        // consumers — notably the web trust-check banner via the console — can
        // distinguish "not installed" from "installed but stopped" without
        // string-matching the human detail. Bugfix:
        // 20260703-trust-check-web-offline-vs-notinstalled-proactive.md.
        let installed = core::is_installed();
        let (running, detail) = core::status_summary();
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "service": core::SERVICE_NAME,
                    "installed": installed,
                    "running": running,
                    "detail": detail,
                })
            );
        } else if running {
            println!("{}: {}", core::SERVICE_NAME, detail);
        } else {
            println!("{}: {}", core::SERVICE_NAME, detail);
            if detail == "not installed" {
                println!("    Install: aikey app install degrade-detector");
            } else {
                println!("    Start:   aikey service start trust-local");
            }
        }
        Ok(())
    }

    pub(super) fn dispatch(verb: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        // Read-only status short-circuits before the install check: on a host
        // without trust-local, "not installed" is the answer we want to print,
        // not a hard error like the mutating verbs raise.
        if verb == "status" {
            return status_detail(json);
        }
        // Install guard — the TRUST_LOCAL_NOT_INSTALLED CLI contract lives here
        // (shell), not in the core. Since rc.5 the detector installs by default;
        // a missing binary means the user opted out at install or ran
        // `aikey app uninstall degrade-detector`. Path is cross-platform
        // (core::bin_path): $HOME/.aikey/bin/trust-local, Windows .exe.
        let bin = core::bin_path();
        if !bin.exists() {
            let msg = format!(
                "trust-local binary not found at {}. Install via: \
                 aikey app install degrade-detector",
                bin.display()
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

        let result = match verb {
            "start" => core::start(),
            "stop" => core::stop(),
            "restart" => core::restart(),
            other => return Err(format!("unknown verb '{}'", other).into()),
        };
        emit(verb, &result, json);
        result.map_err(|e| e.into())
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
                    "service": core::SERVICE_NAME,
                    "detail": detail,
                })
            );
        } else {
            match result {
                Ok(()) => println!("{}: {} succeeded", core::SERVICE_NAME, verb),
                Err(e) => eprintln!("{}: {} — {}", core::SERVICE_NAME, verb, e),
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
                // Reuse the ONE password-resolution core (commands_proxy::
                // resolve_verified_vault_password). Calling prompt_vault_password
                // here was the bug: it only knows env / stdin / interactive TTY,
                // so every non-interactive caller — the AiKey tray, launchd, a
                // script — got a password prompt it could not answer, and only
                // then an error. The core consults the session cache first,
                // exactly as `aikey proxy start` has since 2026-06-11.
                //
                // It also verifies before we spawn, so the explicit
                // list_secrets check that used to live here is now redundant.
                let (password, _origin) =
                    crate::commands_proxy::resolve_verified_vault_password(password_stdin)?;
                crate::commands_proxy::handle_start(None, true /*detach*/, &password)?;
                Ok(())
            }
            "stop" => {
                crate::commands_proxy::handle_stop()?;
                Ok(())
            }
            "restart" => {
                // Reuse the ONE password-resolution core (commands_proxy::
                // resolve_verified_vault_password). Calling prompt_vault_password
                // here was the bug: it only knows env / stdin / interactive TTY,
                // so every non-interactive caller — the AiKey tray, launchd, a
                // script — got a password prompt it could not answer, and only
                // then an error. The core consults the session cache first,
                // exactly as `aikey proxy start` has since 2026-06-11.
                //
                // It also verifies before we spawn, so the explicit
                // list_secrets check that used to live here is now redundant.
                let (password, _origin) =
                    crate::commands_proxy::resolve_verified_vault_password(password_stdin)?;
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
            assert_eq!(plan_leg(verb, false, true), LegPlan::Skip("not installed"),);
        }
    }

    #[test]
    fn plan_leg_start_is_idempotent() {
        // running → skip (don't re-prompt proxy password / bounce trust-local)
        assert_eq!(
            plan_leg("start", true, true),
            LegPlan::Skip("already running")
        );
        // stopped → act
        assert_eq!(plan_leg("start", true, false), LegPlan::Act);
    }

    #[test]
    fn plan_leg_stop_is_idempotent() {
        // not running → skip
        assert_eq!(
            plan_leg("stop", true, false),
            LegPlan::Skip("already stopped")
        );
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
            crate::trust_local_service::status_summary(),
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
        let (running, detail) = crate::trust_local_service::status_summary();
        if !running {
            assert!(
                detail == "not installed" || detail == "not running",
                "unexpected trust-local down-detail: {detail}"
            );
        }
    }
}
