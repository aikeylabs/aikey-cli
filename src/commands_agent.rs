//! `aikey agent` — manage this host as a龙虾/OpenClaw digital employee.
//!
//! Phase 3 (this file) implements `aikey agent register`: a one-shot,
//! unattended-friendly self-enrollment. The host presents an org join token to
//! the Control plane, which creates the service account + digital-employee seat
//! (NO virtual key yet — the admin assigns one later) and returns a long-lived
//! daemon refresh_token. We persist that credential in the local vault via the
//! same `save_oauth_session` path `aikey login` uses, so the (forthcoming)
//! `aikey agent start` daemon can refresh a JWT and pull the assigned VK.
//!
//! Onboarding flow (revised 2026-06-08, see roadmap update
//! 20260608-龙虾数字员工接入-daemon实施方案与R1R2拍板.md): self-register first,
//! admin assigns VK after. The join token is org-level and reusable.

use crate::commands_account::{
    openclaw_hook, persist_control_url_sidecar, run_full_snapshot_sync_for_agent,
    set_de_collector_base,
};
use crate::platform_client::PlatformClient;
use crate::storage;
use secrecy::SecretString;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Minimum sync interval — guards against a hot loop hammering Control.
const MIN_INTERVAL_SECS: u64 = 5;
/// Default sync interval.
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 30;

/// `aikey agent register --join-token <t> [--control-url <u>] [--name <n>]`.
pub(crate) fn register(
    join_token: &str,
    url: Option<&str>,
    name: Option<&str>,
) -> Result<(), String> {
    let join_token = join_token.trim();
    if join_token.is_empty() {
        return Err("missing --join-token (copy it from the admin console)".to_string());
    }

    // Resolve the Control URL: explicit flag wins, else reuse what this host
    // already has saved (re-register / re-run), else ask the operator.
    let control_url = match url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => storage::get_platform_account()
            .ok()
            .flatten()
            .map(|a| a.control_url)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                "missing --control-url (e.g. --control-url http://<host>:3000)".to_string()
            })?,
    };

    // Ensure the local vault exists + is initialized before we persist the
    // daemon credential. On a fresh host the master password comes from
    // AIKEY_MASTER_PASSWORD (the install script generates one) — same model the
    // `aikey agent start` daemon and the cluster daemon use, so the vault can be
    // managed unattended.
    ensure_vault_initialized()?;

    let host_info = host_identifier();
    let display_name = name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| host_info.clone());

    // 1) Self-register against Control (join token is the credential).
    let res = PlatformClient::register_digital_employee(
        &control_url,
        join_token,
        &host_info,
        &display_name,
    )?;

    // 2) Exchange the daemon refresh_token for an initial access token — this
    //    both validates the credential end-to-end and gives us a complete
    //    session to persist (mirrors `aikey login`).
    let refreshed = PlatformClient::do_refresh_token(&control_url, &res.refresh_token)?;
    let expires_at = now_epoch() + refreshed.expires_in;
    // The daemon credential rotates on refresh; persist the latest refresh_token.
    let refresh_token = if refreshed.refresh_token.is_empty() {
        res.refresh_token.clone()
    } else {
        refreshed.refresh_token.clone()
    };

    // 3) Persist the session in the vault (same store as `aikey login`). The
    //    seat has no real email — use the server's synthetic placeholder so
    //    `whoami`-style views render consistently.
    let email = format!("bot+{}@openclaw.local", res.seat_id);
    storage::save_oauth_session(
        &res.account_id,
        &email,
        &refreshed.access_token,
        &refresh_token,
        expires_at,
        &control_url,
    )?;

    // Wire the local proxy to the master the SAME way `aikey login` does — write
    // the control URL to config.json (proxy compliance-policy poll), install-
    // state.json, and user-yaml collector_url (usage reporting). save_oauth_session
    // above only wrote the vault; without this the unattended daemon's proxy never
    // learns the master URL → compliance detector never spawns + usage reporting
    // falls back to the Personal localhost default (regression 2026-06-08 form②).
    persist_control_url_sidecar(&control_url, true);
    // A DE has no Personal local-server, so its proxy's BASE collector_url
    // (default 127.0.0.1:8090) is a dead address — point it at the master so
    // team-key usage events upload instead of bouncing (regression finding #2).
    set_de_collector_base(&control_url);

    println!(
        "\u{2713} Registered as digital employee: {}",
        res.display_name
    );
    println!("  org_id  : {}", res.org_id);
    println!("  seat_id : {}", res.seat_id);
    println!("  control : {}", control_url);
    println!();
    println!("  No virtual key is assigned yet — an admin assigns one in the console.");
    println!("  The daemon will pick it up automatically once assigned.");
    Ok(())
}

/// Initialize the local vault if it doesn't exist yet (fresh daemon host),
/// using `AIKEY_MASTER_PASSWORD`. Idempotent: a no-op if already initialized.
/// Reuses `commands_init::core::initialize` (the same core `aikey init` and the
/// cluster daemon's `_internal init` use) — no parallel bootstrap logic.
fn ensure_vault_initialized() -> Result<(), String> {
    if storage::get_salt().is_ok() {
        return Ok(());
    }
    let pw = master_password_from_env()?;
    crate::commands_init::core::initialize(&pw).map_err(|e| format!("initialize vault: {e}"))
}

/// Read the daemon's vault master password from `AIKEY_MASTER_PASSWORD` (the
/// install script generates one; same env the cluster daemon + proxy use). The
/// digital-employee daemon is unattended, so there is no interactive prompt.
fn master_password_from_env() -> Result<SecretString, String> {
    let pw = std::env::var("AIKEY_MASTER_PASSWORD").map_err(|_| {
        "AIKEY_MASTER_PASSWORD is unset — set it (the install script generates one) so the \
         digital-employee vault can be managed unattended"
            .to_string()
    })?;
    if pw.trim().is_empty() {
        return Err("AIKEY_MASTER_PASSWORD is empty".to_string());
    }
    Ok(SecretString::new(pw))
}

/// Best-effort stable host identifier for the console (hostname). Falls back to
/// env vars then a constant — never fails registration over a missing hostname.
fn host_identifier() -> String {
    if let Ok(out) = Command::new("hostname").output() {
        if out.status.success() {
            let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !h.is_empty() {
                return h;
            }
        }
    }
    for v in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(h) = std::env::var(v) {
            if !h.trim().is_empty() {
                return h.trim().to_string();
            }
        }
    }
    "unknown-host".to_string()
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `aikey agent start [--interval N]` — the unattended sync daemon.
///
/// This is a FOREGROUND loop, run by the host's service manager
/// (systemd/launchd) — same model as the cluster daemon — so it owns no
/// pidfile/ownership of its own; the service manager handles lifecycle + restart
/// + SIGTERM. Each cycle:
///   1. `run_snapshot_sync()` refreshes the JWT (from the stored daemon
///      refresh_token) and pulls the managed-keys snapshot into the local vault
///      VK cache — exactly what the proxy reads. No master password needed for
///      team VKs (metadata only).
///   2. Once the admin has assigned a VK, configure OpenClaw to route through the
///      local proxy with that VK (quietly; only rewrites when the VK changes).
///
/// Never exits on transient errors — it logs and retries so a flaky network or a
/// not-yet-assigned VK doesn't take the daemon down.
pub(crate) fn start(interval_secs: u64) -> Result<(), String> {
    let acc = storage::get_platform_account()
        .ok()
        .flatten()
        .ok_or("not registered — run `aikey agent register --join-token <token>` first")?;
    let interval = Duration::from_secs(interval_secs.max(MIN_INTERVAL_SECS));
    println!(
        "aikey agent daemon started (account {}, control {}, sync every {}s)",
        acc.account_id,
        acc.control_url,
        interval.as_secs()
    );

    // The full sync (claim assigned VK + download provider key material so the
    // proxy can actually forward) needs the vault key, derived from the master
    // password. Same env the daemon already relies on (see register/bootstrap).
    let password = master_password_from_env()?;

    let mut last_token: Option<String> = None;
    let mut announced_waiting = false;
    // Whether OpenClaw currently carries our `aikey` provider. Seeded from the
    // actual OpenClaw config so revoke-cleanup is restart-safe (a daemon restart
    // after a revoke still cleans the stale key) without re-cleaning every cycle.
    let mut configured = openclaw_hook::is_provider_present().unwrap_or(false);
    loop {
        // 1) FULL snapshot sync: refreshes JWT, claims any newly-assigned VK, and
        //    downloads + encrypts its provider key material into the vault cache —
        //    metadata-only sync is NOT enough for the proxy to forward a team VK.
        //    Agent variant: opens the cluster gate so a form-② DE on a CLUSTER
        //    org still pulls its own seat's key material (control plane enforces
        //    seat-scoped delivery). Plain sync would skip the download on
        //    clusters → ciphertext NULL → empty DE-proxy registry → 401s. Bug:
        //    20260611-form2-de-proxy-token-registry-mismatch.
        match run_full_snapshot_sync_for_agent(&password) {
            Ok(0) => {} // nothing new
            Ok(n) => println!("[agent] synced {n} key(s) into vault"),
            Err(e) => eprintln!("[agent] snapshot sync failed (retrying): {e}"),
        }

        // 2) Configure OpenClaw once a VK is assigned + whenever it changes.
        match openclaw_hook::configure_quiet(None) {
            Ok(Some(token)) => {
                if last_token.as_deref() != Some(token.as_str()) {
                    println!("[agent] OpenClaw configured with assigned virtual key");
                    last_token = Some(token);
                    // The OpenClaw Gateway loads config at start and does NOT
                    // hot-reload the file ("Restart the gateway to apply"), so a
                    // running Gateway won't pick up the new/rotated VK until
                    // restarted. Do it here, but only when the VK actually changed
                    // (not every cycle) and only if a Gateway is up — the headless
                    // `openclaw agent --local` path reads config fresh and needs no
                    // restart. Best-effort: never fail the daemon over this.
                    match openclaw_hook::restart_gateway_if_running() {
                        Ok(true) => {
                            println!("[agent] restarted OpenClaw Gateway to apply the new key")
                        }
                        Ok(false) => {} // no Gateway running → --local reads fresh
                        Err(e) => eprintln!(
                            "[agent] OpenClaw Gateway restart failed (apply manually): {e}"
                        ),
                    }
                }
                announced_waiting = false;
                configured = true;
            }
            Ok(None) => {
                // No active VK (never assigned, or admin revoked it). If OpenClaw
                // was previously wired, clear the now-dead key so 龙虾 fails fast
                // instead of spinning on a revoked bearer. Runs once on the
                // configured→revoked transition (no restart loop). WHY no
                // placeholder: pending-vs-revoked lives on the server/console,
                // not in OpenClaw config (no source-of-truth split).
                if configured {
                    match openclaw_hook::deconfigure_quiet() {
                        Ok(()) => {
                            println!(
                                "[agent] no active virtual key — cleared OpenClaw config (revoked?)"
                            );
                            let _ = openclaw_hook::restart_gateway_if_running();
                        }
                        Err(e) => eprintln!("[agent] OpenClaw cleanup failed (retrying): {e}"),
                    }
                    configured = false;
                    last_token = None;
                }
                if !announced_waiting {
                    println!("[agent] waiting for an admin to assign a virtual key…");
                    announced_waiting = true;
                }
            }
            Err(e) => eprintln!("[agent] OpenClaw config failed (retrying): {e}"),
        }

        std::thread::sleep(interval);
    }
}

/// `aikey agent status` — show enrollment + sync state for this host.
pub(crate) fn status() -> Result<(), String> {
    match storage::get_platform_account().ok().flatten() {
        None => {
            println!("\u{2717} Not registered. Run `aikey agent register --join-token <token>`.");
            return Ok(());
        }
        Some(acc) => {
            println!("\u{2713} Registered digital employee");
            println!("  account : {}", acc.account_id);
            println!("  control : {}", acc.control_url);
        }
    }
    let vk_count = storage::list_virtual_key_cache_readonly()
        .map(|v| v.iter().filter(|k| k.key_status == "active").count())
        .unwrap_or(0);
    if vk_count == 0 {
        println!("  virtual key : none assigned yet (ask an admin to assign one)");
    } else {
        println!("  virtual key : {vk_count} active in cache");
    }
    // Reuse the OpenClaw wiring status.
    let _ = openclaw_hook::status();
    Ok(())
}
