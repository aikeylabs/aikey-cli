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

/// Provider id written under `models.providers.<id>` in openclaw.json.
const PROVIDER_ID: &str = "aikey";
/// api enum OpenClaw expects for Anthropic-native `/v1/messages` upstreams.
const OPENCLAW_API: &str = "anthropic-messages";
/// Default model id surfaced to OpenClaw (verified via aicoding/Anthropic).
const DEFAULT_MODEL: &str = "claude-sonnet-4-5";

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
    let token =
        team_token_normalize::team_token_from_vk_id(&vk_id).map_err(|e| format!("team token: {e}"))?;
    Ok((token, base_url))
}

// ── openclaw config patch payloads (pure, unit-tested) ──────────────────────

/// Build the JSON patch that registers the `aikey` provider in openclaw.json.
pub(crate) fn build_install_patch(
    token: &str,
    base_url: &str,
    model: &str,
) -> serde_json::Value {
    serde_json::json!({
        "models": {
            "providers": {
                PROVIDER_ID: {
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

/// Dot-path of the provider entry, used by `openclaw config unset`.
/// (We remove via `config unset` rather than a `null` patch because OpenClaw's
/// patch path has a size-drop safety guard that rejects large shrinks — e.g.
/// removing the only provider — whereas `unset` is the sanctioned delete.)
const PROVIDER_DOT_PATH: &str = "models.providers.aikey";

// ── openclaw CLI plumbing ───────────────────────────────────────────────────

fn openclaw_bin() -> Result<String, String> {
    // Honor AIKEY_OPENCLAW_BIN override (tests / non-standard installs), else
    // rely on PATH resolution by Command.
    Ok(std::env::var("AIKEY_OPENCLAW_BIN").unwrap_or_else(|_| "openclaw".to_string()))
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
    openclaw_config_patch(&build_install_patch(&token, &base_url, model))?;
    println!("\u{2713} OpenClaw configured to route through AiKey.");
    println!("  provider : {PROVIDER_ID}");
    println!("  baseUrl  : {base_url}");
    println!("  model    : {PROVIDER_ID}/{model}");
    println!("  (real provider key stays in the vault; OpenClaw only holds the team VK)");
    println!();
    println!("  Try it:");
    println!(
        "    openclaw agent --local --session-key s1 --model {PROVIDER_ID}/{model} --message \"hi\""
    );
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
    let model = model.unwrap_or(DEFAULT_MODEL);
    openclaw_config_patch(&build_install_patch(&token, &base_url, model))?;
    Ok(Some(token))
}

/// `aikey hook uninstall openclaw` — remove the aikey provider from OpenClaw.
pub(crate) fn uninstall() -> Result<(), String> {
    let bin = openclaw_bin()?;
    let out = Command::new(&bin)
        .args(["config", "unset", PROVIDER_DOT_PATH])
        .output()
        .map_err(|e| format!("OpenClaw CLI not runnable ('{bin}'): {e}"))?;
    if out.status.success() {
        println!("\u{2713} Removed the '{PROVIDER_ID}' provider from OpenClaw config.");
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
            "  Remove it manually: edit ~/.openclaw/openclaw.json and delete the \"{PROVIDER_ID}\" entry under models.providers."
        );
        return Ok(());
    }
    Err(format!("openclaw config unset failed: {}", stderr.trim()))
}

/// `aikey hook status openclaw` — show whether OpenClaw is wired to AiKey.
pub(crate) fn status() -> Result<(), String> {
    let bin = openclaw_bin()?;
    let out = Command::new(&bin)
        .args(["config", "get", "models.providers.aikey"])
        .output()
        .map_err(|e| format!("OpenClaw CLI not runnable ('{bin}'): {e}"))?;
    let body = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && body.contains("baseUrl") {
        println!("\u{2713} OpenClaw is wired to AiKey (provider '{PROVIDER_ID}').");
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
        let p = build_install_patch("aikey_team_abc", "http://127.0.0.1:27200/anthropic", "claude-sonnet-4-5");
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
    fn uninstall_targets_provider_dot_path() {
        // uninstall removes via `openclaw config unset <dot-path>` (not a null
        // patch — that trips OpenClaw's size-drop guard). Lock the path.
        assert_eq!(PROVIDER_DOT_PATH, "models.providers.aikey");
    }

    #[test]
    fn install_patch_is_deterministic() {
        // Same inputs → byte-identical patch (idempotent re-runs).
        let a = build_install_patch("t", "u", "m").to_string();
        let b = build_install_patch("t", "u", "m").to_string();
        assert_eq!(a, b);
    }
}
