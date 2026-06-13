//! `aikey hook install openclaw` — wire OpenClaw (龙虾 digital employee) into
//! AiKey so its LLM calls go through the local aikey proxy with a team virtual
//! key.
//!
//! ## Why this is a separate "hook" path (not the codex/kimi shell hook)
//! codex/kimi rely on an interactive shell + precmd hook + `active.env` that
//! re-points an env var per session. OpenClaw is an *unattended* agent with no
//! interactive shell, so that mechanism never fires. Instead we write a static
//! provider entry into OpenClaw's own config (`~/.openclaw/openclaw.json`)
//! pointing at the proxy's `/anthropic` prefix, with the team VK as a static
//! bearer. This mirrors the 2026-06-03 spike and the龙虾 digital-employee
//! design (`roadmap.../阶段4-增值版/20260603-龙虾数字员工接入-ER图与业务流.md`).
//!
//! ## Reuse, not reimplement (internal-command-reuses-public-core)
//! The team-VK bearer + proxy base_url are derived with the SAME primitives as
//! `aikey route` — `commands_proxy::proxy_port()`,
//! `storage::list_virtual_key_cache_readonly()` / `list_provider_bindings_readonly()`,
//! `team_token_normalize::team_token_from_vk_id()` — so there is no second copy
//! of the token logic. We merge into OpenClaw config via its own non-interactive
//! `openclaw config patch --stdin` API (JSON5-aware, recursive merge, `null`
//! deletes) rather than hand-editing JSON5, so a user's comments/structure are
//! never corrupted.
//!
//! Note: `aikey agent enroll/start` (unattended VK enrollment + sync daemon) is
//! the eventual fully-automated form; this hook is the manual-config equivalent
//! a node/operator runs once after `aikey use`.

use crate::{commands_proxy, credential_type, storage, team_token_normalize};
use std::io::Write;
use std::process::{Command, Stdio};

/// Default provider id written under `models.providers.<id>` in openclaw.json
/// when AiKey OWNS the provider entry (greenfield: we created the OpenClaw
/// install, so a dedicated `aikey` provider is ours to add/remove).
const DEFAULT_PROVIDER_ID: &str = "aikey";
/// api enum OpenClaw expects for Anthropic-native `/v1/messages` upstreams.
const OPENCLAW_API: &str = "anthropic-messages";
/// Default model id surfaced to OpenClaw (verified via aicoding/Anthropic).
const DEFAULT_MODEL: &str = "claude-sonnet-4-5";

/// Which provider id the daemon writes under. Brownfield (the customer already
/// runs OpenClaw) sets `AIKEY_OPENCLAW_PROVIDER_ID` to THEIR existing provider's
/// id so we *repoint* it instead of adding a parallel `aikey` provider the
/// customer would have to switch to. Greenfield leaves it unset → `aikey`.
/// Why env (not a const): the installer knows the deployment shape (brownfield
/// vs greenfield) and the de-agent unit carries it; the pure patch builders stay
/// env-free and unit-testable by taking provider_id as an argument.
fn provider_id() -> String {
    std::env::var("AIKEY_OPENCLAW_PROVIDER_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_PROVIDER_ID.to_string())
}

/// Repoint mode (brownfield): the target provider is the CUSTOMER's, pre-existing
/// one. We must (a) patch ONLY baseUrl/apiKey/api so their models[] list survives,
/// and (b) never DELETE the provider on revoke (that would wipe the customer's
/// config) — we blank the key instead, and the original is restored from the
/// installer's whole-file backup on uninstall. Gated explicitly (not derived from
/// provider_id != "aikey") so the two concerns stay independent.
fn is_repoint_mode() -> bool {
    std::env::var("AIKEY_OPENCLAW_REPOINT").map(|v| v == "1").unwrap_or(false)
}

/// Dot-path of the active provider entry (`models.providers.<id>`), for
/// `openclaw config get/unset/set`. Tracks `provider_id()`.
fn provider_dot_path() -> String {
    format!("models.providers.{}", provider_id())
}

// ── route resolution (reuses `aikey route` primitives) ──────────────────────

/// Resolve the team VK bearer + proxy `/anthropic` base_url that OpenClaw
/// should use. Prefers the `aikey use`-active team VK; otherwise the first
/// server-active team VK that supports anthropic. Read-only (no vault unlock).
pub(crate) fn resolve_anthropic_team_route() -> Result<(String, String), String> {
    let proxy_port = commands_proxy::proxy_port();
    let base_url = format!("http://127.0.0.1:{proxy_port}/anthropic");

    // Which team VK did `aikey use` select? Prefer it when multiple exist.
    let active_team: std::collections::HashSet<String> =
        storage::list_provider_bindings_readonly("default")
            .unwrap_or_default()
            .iter()
            .filter(|b| {
                matches!(
                    b.key_source_type,
                    credential_type::CredentialType::ManagedVirtualKey
                )
            })
            .map(|b| b.key_source_ref.clone())
            .collect();

    let supports_anthropic = |provider_code: &str, supported: &[String]| -> bool {
        provider_code == "anthropic" || supported.iter().any(|p| p == "anthropic")
    };

    let vks =
        storage::list_virtual_key_cache_readonly().map_err(|e| format!("read team keys: {e}"))?;

    let mut fallback: Option<String> = None;
    let mut chosen: Option<String> = None;
    for vk in &vks {
        if vk.key_status != "active" {
            continue;
        }
        if !supports_anthropic(&vk.provider_code, &vk.supported_providers) {
            continue;
        }
        if active_team.contains(&vk.virtual_key_id) {
            chosen = Some(vk.virtual_key_id.clone());
            break;
        }
        if fallback.is_none() {
            fallback = Some(vk.virtual_key_id.clone());
        }
    }

    let vk_id = chosen.or(fallback).ok_or_else(|| {
        "no active team virtual key supporting anthropic found — run `aikey login` then \
         `aikey use <key>` to activate a team key first"
            .to_string()
    })?;
    let token = team_token_normalize::team_token_from_vk_id(&vk_id)
        .map_err(|e| format!("team token: {e}"))?;
    Ok((token, base_url))
}

// ── openclaw config patch payloads (pure, unit-tested) ──────────────────────

/// Build the JSON patch that registers a FULL `<provider_id>` provider in
/// openclaw.json (greenfield: AiKey owns the entry, so it carries our model
/// list too). The recursive `config patch` merge creates the provider if absent.
pub(crate) fn build_install_patch(
    provider_id: &str,
    token: &str,
    base_url: &str,
    model: &str,
) -> serde_json::Value {
    serde_json::json!({
        "models": {
            "providers": {
                provider_id: {
                    "baseUrl": base_url,
                    "api": OPENCLAW_API,
                    "apiKey": token,
                    "models": [
                        {
                            "id": model,
                            "name": format!("{model} (via AiKey)"),
                            "contextWindow": 200000,
                            "maxTokens": 8192
                        }
                    ]
                }
            }
        }
    })
}

/// Build the NARROW repoint patch for brownfield: overwrite ONLY the customer's
/// existing provider baseUrl/apiKey/api so their request flow goes through the
/// local aikey proxy. Deliberately omits `models[]` — `config patch` merges
/// recursively, so leaving models out preserves whatever model list the customer
/// already configured (sending an array would replace theirs). `api` is set to
/// anthropic-messages because the proxy speaks that on `/anthropic`; a non-
/// Anthropic target provider must be chosen correctly by the operator
/// (`--openclaw-provider`).
pub(crate) fn build_repoint_patch(
    provider_id: &str,
    token: &str,
    base_url: &str,
) -> serde_json::Value {
    serde_json::json!({
        "models": {
            "providers": {
                provider_id: {
                    "baseUrl": base_url,
                    "api": OPENCLAW_API,
                    "apiKey": token
                }
            }
        }
    })
}

// ── openclaw CLI plumbing ───────────────────────────────────────────────────

fn openclaw_bin() -> Result<String, String> {
    // Honor AIKEY_OPENCLAW_BIN override (tests / non-standard installs), else
    // rely on PATH resolution by Command.
    Ok(std::env::var("AIKEY_OPENCLAW_BIN").unwrap_or_else(|_| "openclaw".to_string()))
}

/// Restart the OpenClaw Gateway IFF one is currently running, so a newly
/// assigned/rotated team VK takes effect. The Gateway loads config at start and
/// does NOT hot-reload the file (it prints "Restart the gateway to apply"), so
/// without this a Gateway-mode digital employee never picks up its key. Returns
/// Ok(true) when a Gateway was up and a restart was issued, Ok(false) when none
/// is running — the headless `openclaw agent --local` path reads config fresh,
/// so there is nothing to restart. Liveness probe: `openclaw health` only
/// succeeds against a running Gateway.
pub(crate) fn restart_gateway_if_running() -> Result<bool, String> {
    // Brownfield fail-safe: the customer OWNS their gateway (their unit, their
    // launch args). `AIKEY_DE_MANAGE_GATEWAY=0` (set by the brownfield installer)
    // means "never touch their gateway" — the customer restarts it once after the
    // first VK lands (a documented one-time step). Default unset/"1" preserves the
    // greenfield behavior where AiKey owns the gateway and applies key changes.
    if std::env::var("AIKEY_DE_MANAGE_GATEWAY").map(|v| v == "0").unwrap_or(false) {
        return Ok(false);
    }
    let bin = openclaw_bin()?;
    let up = Command::new(&bin)
        .args(["health"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !up {
        return Ok(false);
    }
    let out = Command::new(&bin)
        .args(["gateway", "restart"])
        .output()
        .map_err(|e| format!("openclaw gateway restart: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(true)
}

/// Pipe a JSON patch into `openclaw config patch --stdin`.
fn openclaw_config_patch(patch: &serde_json::Value) -> Result<(), String> {
    let bin = openclaw_bin()?;
    let mut child = Command::new(&bin)
        .args(["config", "patch", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!("OpenClaw CLI not runnable ('{bin}'): {e}. Install OpenClaw (npm i -g openclaw) and retry.")
        })?;
    child
        .stdin
        .take()
        .ok_or("failed to open openclaw stdin")?
        .write_all(patch.to_string().as_bytes())
        .map_err(|e| format!("write openclaw patch: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("openclaw config patch: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "openclaw config patch failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

// ── public actions (called from `aikey hook {install,uninstall,status} openclaw`) ──

/// `aikey hook install openclaw` — point OpenClaw at the aikey proxy.
pub(crate) fn install(model: Option<&str>) -> Result<(), String> {
    let (token, base_url) = resolve_anthropic_team_route()?;
    let model = model.unwrap_or(DEFAULT_MODEL);
    let pid = provider_id();
    if is_repoint_mode() {
        openclaw_config_patch(&build_repoint_patch(&pid, &token, &base_url))?;
        println!("\u{2713} OpenClaw provider '{pid}' repointed through AiKey.");
        println!("  baseUrl  : {base_url}");
        println!("  (real provider key stays in the vault; OpenClaw only holds the team VK)");
    } else {
        openclaw_config_patch(&build_install_patch(&pid, &token, &base_url, model))?;
        println!("\u{2713} OpenClaw configured to route through AiKey.");
        println!("  provider : {pid}");
        println!("  baseUrl  : {base_url}");
        println!("  model    : {pid}/{model}");
        println!("  (real provider key stays in the vault; OpenClaw only holds the team VK)");
        println!();
        println!("  Try it:");
        println!(
            "    openclaw agent --local --session-key s1 --model {pid}/{model} --message \"hi\""
        );
    }
    println!("  If the OpenClaw gateway is already running, reload it to apply.");
    Ok(())
}

/// Daemon-friendly variant of `install`: configure OpenClaw for the currently
/// assigned team VK WITHOUT the interactive banner, used by `aikey agent start`.
///
/// Returns `Ok(Some(bearer))` with the configured team VK bearer (so the daemon
/// can detect changes and avoid rewriting/reloading every cycle), or `Ok(None)`
/// when no VK is assigned yet (the admin hasn't assigned one — the daemon waits
/// and retries). Real failures (vault read, openclaw patch) propagate as `Err`.
pub(crate) fn configure_quiet(model: Option<&str>) -> Result<Option<String>, String> {
    let (token, base_url) = match resolve_anthropic_team_route() {
        Ok(v) => v,
        // The only "not an error, just not ready" case: no assigned team VK yet.
        Err(e) if e.contains("no active team virtual key") => return Ok(None),
        Err(e) => return Err(e),
    };
    let pid = provider_id();
    if is_repoint_mode() {
        // Brownfield: narrow patch (no models[]) so the customer's model list
        // survives — we only swap their provider's baseUrl/apiKey to our proxy.
        openclaw_config_patch(&build_repoint_patch(&pid, &token, &base_url))?;
    } else {
        let model = model.unwrap_or(DEFAULT_MODEL);
        openclaw_config_patch(&build_install_patch(&pid, &token, &base_url, model))?;
    }
    Ok(Some(token))
}

/// `aikey hook uninstall openclaw` — remove the aikey provider from OpenClaw.
pub(crate) fn uninstall() -> Result<(), String> {
    let bin = openclaw_bin()?;
    let pid = provider_id();
    let dot_path = provider_dot_path();
    // Repoint mode: the provider is the customer's — don't delete it, just blank
    // the apiKey (the original is restored from the installer's whole-file backup).
    if is_repoint_mode() {
        let out = Command::new(&bin)
            .args(["config", "set", &format!("{dot_path}.apiKey"), ""])
            .output()
            .map_err(|e| format!("OpenClaw CLI not runnable ('{bin}'): {e}"))?;
        if out.status.success() {
            println!("\u{2713} Cleared the AiKey key from OpenClaw provider '{pid}' (provider kept; restore the original baseUrl from the installer backup).");
            return Ok(());
        }
        return Err(format!(
            "openclaw config set apiKey='' failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let out = Command::new(&bin)
        .args(["config", "unset", &dot_path])
        .output()
        .map_err(|e| format!("OpenClaw CLI not runnable ('{bin}'): {e}"))?;
    if out.status.success() {
        println!("\u{2713} Removed the '{pid}' provider from OpenClaw config.");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // OpenClaw has its own config-shrink safety guard ("size-drop") that
    // rejects writes which remove a large chunk — e.g. deleting the ONLY
    // provider. That's OpenClaw protecting its config, not an aikey failure;
    // degrade to a clear manual-removal hint instead of crashing.
    if stderr.contains("size-drop") || stderr.contains("rejected") {
        println!(
            "\u{26a0} OpenClaw declined to auto-remove the provider (its config-shrink safety guard)."
        );
        println!(
            "  Remove it manually: edit ~/.openclaw/openclaw.json and delete the \"{pid}\" entry under models.providers."
        );
        return Ok(());
    }
    Err(format!("openclaw config unset failed: {}", stderr.trim()))
}

/// Is the `aikey` provider currently present in OpenClaw config? Best-effort via
/// `openclaw config get`. Used by the agent daemon to seed its in-memory
/// "configured" flag at startup so revoke-cleanup is restart-safe (survives a
/// daemon restart) without re-running cleanup every cycle.
pub(crate) fn is_provider_present() -> Result<bool, String> {
    let bin = openclaw_bin()?;
    let out = Command::new(&bin)
        .args(["config", "get", &provider_dot_path()])
        .output()
        .map_err(|e| format!("openclaw config get: {e}"))?;
    if !out.status.success() {
        return Ok(false);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let s = s.trim();
    Ok(!s.is_empty() && s != "null" && s != "undefined" && s != "{}")
}

/// Remove the `aikey` provider (or, if OpenClaw's config-shrink guard rejects
/// removing the only provider, blank its apiKey) when the digital employee has
/// NO active VK — e.g. the admin revoked it. This stops 龙虾 from spinning on a
/// dead/revoked bearer (it fails fast on "no/empty model key" instead of a
/// confusing "token not found" every call).
///
/// Why no placeholder/sentinel key: the REASON there's no key (pending vs
/// revoked) is owned by the server/console (seat + VK status). The local
/// OpenClaw config only mirrors the usable route — encoding state here would
/// split the source of truth. So we just clear the dead key, nothing more.
///
/// Caller gates this behind an in-memory "was configured" flag, so it runs once
/// on the configured→revoked transition (no restart loop).
pub(crate) fn deconfigure_quiet() -> Result<(), String> {
    let bin = openclaw_bin()?;
    let dot_path = provider_dot_path();
    // Brownfield repoint mode: the provider is the CUSTOMER's — deleting it would
    // wipe their config. Only blank the (now revoked) apiKey so 龙虾 fails closed;
    // the original baseUrl/key is restored from the installer's whole-file backup
    // on uninstall. Never unset.
    if is_repoint_mode() {
        let out = Command::new(&bin)
            .args(["config", "set", &format!("{dot_path}.apiKey"), ""])
            .output()
            .map_err(|e| format!("openclaw config set: {e}"))?;
        return if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "openclaw config set apiKey='' failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        };
    }
    let out = Command::new(&bin)
        .args(["config", "unset", &dot_path])
        .output()
        .map_err(|e| format!("openclaw config unset: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // OpenClaw won't remove the only provider (size-drop guard). Fall back to
    // blanking the dead key so 龙虾 stops sending the revoked bearer.
    if stderr.contains("size-drop") || stderr.contains("rejected") {
        let _ = Command::new(&bin)
            .args(["config", "set", &format!("{dot_path}.apiKey"), ""])
            .output();
        return Ok(());
    }
    Err(format!("openclaw config unset failed: {}", stderr.trim()))
}

/// `aikey hook status openclaw` — show whether OpenClaw is wired to AiKey.
pub(crate) fn status() -> Result<(), String> {
    let bin = openclaw_bin()?;
    let pid = provider_id();
    let out = Command::new(&bin)
        .args(["config", "get", &provider_dot_path()])
        .output()
        .map_err(|e| format!("OpenClaw CLI not runnable ('{bin}'): {e}"))?;
    let body = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && body.contains("baseUrl") {
        println!("\u{2713} OpenClaw is wired to AiKey (provider '{pid}').");
        // Show the base_url line if present (apiKey is redacted by OpenClaw).
        for line in body.lines() {
            if line.contains("baseUrl") {
                println!("  {}", line.trim());
            }
        }
    } else {
        println!(
            "\u{2717} OpenClaw is not wired to AiKey. Run `aikey hook install openclaw` first."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_patch_shape_is_anthropic_messages_provider() {
        let p = build_install_patch(
            "aikey",
            "aikey_team_abc",
            "http://127.0.0.1:27200/anthropic",
            "claude-sonnet-4-5",
        );
        let prov = &p["models"]["providers"]["aikey"];
        assert_eq!(prov["api"], "anthropic-messages");
        assert_eq!(prov["apiKey"], "aikey_team_abc");
        assert_eq!(prov["baseUrl"], "http://127.0.0.1:27200/anthropic");
        assert_eq!(prov["models"][0]["id"], "claude-sonnet-4-5");
        // contextWindow/maxTokens present so OpenClaw accepts the model entry.
        assert!(prov["models"][0]["contextWindow"].is_number());
        assert!(prov["models"][0]["maxTokens"].is_number());
    }

    #[test]
    fn install_patch_honors_custom_provider_id() {
        // Greenfield can still be told a non-default id; the patch nests under it.
        let p = build_install_patch("myprov", "tok", "http://x/anthropic", "m");
        assert!(p["models"]["providers"]["myprov"].is_object());
        assert!(p["models"]["providers"]["aikey"].is_null());
    }

    #[test]
    fn repoint_patch_omits_models_to_preserve_customer_list() {
        // Brownfield repoint: ONLY baseUrl/apiKey/api under the CUSTOMER's
        // provider id, NO models[] (sending one would replace their list).
        let p = build_repoint_patch("anthropic", "aikey_team_xyz", "http://127.0.0.1:27200/anthropic");
        let prov = &p["models"]["providers"]["anthropic"];
        assert_eq!(prov["api"], "anthropic-messages");
        assert_eq!(prov["apiKey"], "aikey_team_xyz");
        assert_eq!(prov["baseUrl"], "http://127.0.0.1:27200/anthropic");
        // The crux: no models key → customer's existing model list is untouched.
        assert!(prov["models"].is_null());
    }

    #[test]
    fn repoint_patch_is_deterministic() {
        let a = build_repoint_patch("p", "t", "u").to_string();
        let b = build_repoint_patch("p", "t", "u").to_string();
        assert_eq!(a, b);
    }

    #[test]
    fn provider_resolution_defaults_when_env_absent() {
        // No env set in the test process → greenfield defaults. (The env-set
        // brownfield branch is exercised by the installer dry-run + staging E2E,
        // not by mutating process-global env in a parallel unit test.)
        assert_eq!(provider_id(), "aikey");
        assert_eq!(provider_dot_path(), "models.providers.aikey");
        assert!(!is_repoint_mode());
    }
}
