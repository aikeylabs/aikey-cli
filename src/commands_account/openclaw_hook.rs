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
/// Max OUTPUT tokens written into a model entry. WHY this MUST be set (2026-06-16,
/// browser-chat bug): the gateway-served chat path (the OpenClaw web UI / `openclaw
/// agent`) requires a POSITIVE maxTokens on the resolved model — unlike `infer` /
/// `openclaw agent --local`, which inject a per-request default and so silently mask a
/// missing value. A model entry WITHOUT maxTokens makes the digital employee's chat
/// throw `requires a positive maxTokens value for <provider>/<model>` BEFORE producing
/// any content. Reproduced + verified in a clean-room VM (openclaw 2026.6.5): the SAME
/// model with vs without maxTokens flips the gateway agent between a real LLM request
/// and that error. 8192 is the Anthropic Messages default output cap.
const MODEL_MAX_OUTPUT_TOKENS: u32 = 8192;
/// Context window written alongside maxTokens in a model entry.
const MODEL_CONTEXT_WINDOW: u32 = 200_000;

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
    std::env::var("AIKEY_OPENCLAW_REPOINT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// True when AiKey OWNS this node's OpenClaw gateway — greenfield, or brownfield with
/// `gateway_port` (the AiKey-managed digital-employee lobster). Mirrors the gate in
/// `restart_gateway_if_running`: only `AIKEY_DE_MANAGE_GATEWAY=0` (a real customer
/// running their OWN OpenClaw) opts out. WHY it also governs the model definition: when
/// AiKey manages the gateway it owns the chat model end-to-end, so the brownfield
/// repoint must write that model WITH maxTokens (see `build_repoint_patch`). A real
/// customer keeps their own model list untouched.
fn de_manages_gateway() -> bool {
    std::env::var("AIKEY_DE_MANAGE_GATEWAY")
        .map(|v| v != "0")
        .unwrap_or(true)
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

/// One `models.providers.<id>.models[]` entry. Centralized so greenfield install and
/// AiKey-managed brownfield repoint write an IDENTICAL spec — crucially both carry
/// `maxTokens` (see `MODEL_MAX_OUTPUT_TOKENS`), without which the gateway chat fails.
fn model_entry(model: &str) -> serde_json::Value {
    serde_json::json!({
        "id": model,
        "name": format!("{model} (via AiKey)"),
        "contextWindow": MODEL_CONTEXT_WINDOW,
        "maxTokens": MODEL_MAX_OUTPUT_TOKENS
    })
}

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
                    "models": [model_entry(model)]
                }
            }
        }
    })
}

/// Build the repoint patch for brownfield: overwrite the customer's existing provider
/// baseUrl/apiKey/api so their request flow goes through the local aikey proxy. `api`
/// is set to anthropic-messages because the proxy speaks that on `/anthropic`; a non-
/// Anthropic target provider must be chosen correctly by the operator
/// (`--openclaw-provider`).
///
/// `managed_model` decides whether we also write `models[]`:
/// - `Some(model)` (AiKey OWNS the gateway — the digital-employee lobster): write the
///   chat model WITH maxTokens. WHY (2026-06-16 root cause): the gateway chat path
///   requires a positive maxTokens on the resolved model; this patch historically
///   omitted `models[]`, leaving the spec to the box's pre-existing OpenClaw config,
///   which need not carry maxTokens → the chat threw `requires a positive maxTokens
///   value`. Since we own this OpenClaw, defining the one model we route is correct.
/// - `None` (real customer running their OWN OpenClaw, `AIKEY_DE_MANAGE_GATEWAY=0`):
///   omit `models[]` — `config patch` merges recursively, so leaving models out
///   preserves whatever model list the customer already configured.
pub(crate) fn build_repoint_patch(
    provider_id: &str,
    token: &str,
    base_url: &str,
    managed_model: Option<&str>,
) -> serde_json::Value {
    let mut provider = serde_json::json!({
        "baseUrl": base_url,
        "api": OPENCLAW_API,
        "apiKey": token
    });
    if let Some(model) = managed_model {
        provider["models"] = serde_json::json!([model_entry(model)]);
    }
    serde_json::json!({ "models": { "providers": { provider_id: provider } } })
}

/// Build the patch that makes `<provider_id>/<model>` openclaw's DEFAULT chat
/// model (`agents.defaults.model.primary` — the field openclaw onboarding sets).
/// WHY (2026-06-15 root cause): writing only `models.providers` left the default
/// model UNSET, so openclaw fell back to a session/built-in default pointing at a
/// DIFFERENT, un-maintained provider → the digital employee's chat hit a dead
/// route ("Route token not found in registry"). The caller applies this ONLY when
/// no default is set yet (see `openclaw_default_model_set`), so a user/operator
/// who pinned their own default in production is never overridden.
pub(crate) fn build_default_model_patch(provider_id: &str, model: &str) -> serde_json::Value {
    let model_ref = format!("{provider_id}/{model}");
    let mut models = serde_json::Map::new();
    // The entry stays EMPTY on purpose — it only REGISTERS the model as an allowed
    // agent default. Do NOT put `maxTokens` here: OpenClaw's config schema REJECTS it
    // ("Unrecognized key: maxTokens" on `config patch`). maxTokens lives on the
    // PROVIDER model entry (`model_entry`), which greenfield install and AiKey-managed
    // brownfield repoint both now write. Clean-room verified (openclaw 2026.6.5): an
    // empty agent entry + a provider model carrying maxTokens → the gateway chat works.
    models.insert(model_ref.clone(), serde_json::json!({}));
    serde_json::json!({
        "agents": {
            "defaults": {
                "model": { "primary": model_ref },
                "models": models
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

/// True when openclaw has a default chat model pinned (`agents.defaults.model.primary`)
/// to a provider that STILL EXISTS. The daemon checks this to AVOID overriding a default
/// the user/operator set in their own (production) OpenClaw — we only set ours when none
/// is pinned.
///
/// WHY also require the provider to exist (2026-06-15): a green→brownfield transition
/// leaves a DANGLING default. Greenfield onboarding pins `aikey/<model>` and creates the
/// `aikey` provider; teardown then `unset`s the `aikey` PROVIDER but NOT
/// `agents.defaults.model.primary`; the brownfield re-attach repoints a DIFFERENT
/// provider (e.g. `anthropic`). The stale `aikey/...` default now points at a provider
/// that is gone, so the chat fails with `No API key found for provider "aikey"`. Treating
/// a pin-to-a-removed-provider as UNSET lets us re-point the chat at the active provider.
/// A pin to a provider that IS present (a genuine user default) is still respected.
fn openclaw_default_model_set() -> bool {
    let bin = match openclaw_bin() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let primary = match Command::new(&bin)
        .args(["config", "get", "agents.defaults.model.primary"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .trim()
            .trim_matches('"')
            .to_string(),
        _ => return false,
    };
    if primary.is_empty() || primary == "null" || primary == "undefined" {
        return false; // nothing pinned → we set ours
    }
    // The model ref is "<provider>/<model>"; honor the pin only when <provider> is still
    // a configured provider — otherwise it is a stale/dangling default (treat as unset).
    let provider = match primary.split('/').next() {
        Some(p) if !p.is_empty() => p,
        _ => return false,
    };
    match Command::new(&bin)
        .args(["config", "get", &format!("models.providers.{provider}")])
        .output()
    {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            let t = s.trim();
            // present = non-empty object/value; absent prints "null"/empty.
            !t.is_empty() && t != "null" && t != "undefined" && t != "{}"
        }
        _ => false, // provider not found → stale pin → treat as unset
    }
}

/// Restart the OpenClaw Gateway IFF one is currently running, so a newly
/// assigned/rotated team VK takes effect. The Gateway loads config at start and
/// does NOT hot-reload the file (it prints "Restart the gateway to apply"), so
/// without this a Gateway-mode digital employee never picks up its key. Returns
/// Ok(true) when a Gateway was up and a restart was issued, Ok(false) when none
/// is running — the headless `openclaw agent --local` path reads config fresh,
/// so there is nothing to restart. Greenfield (AiKey owns the gateway unit) goes
/// through systemd via AIKEY_DE_GATEWAY_UNIT; brownfield `--manage-gateway` uses
/// the `openclaw health` liveness probe + `openclaw gateway restart`.
pub(crate) fn restart_gateway_if_running() -> Result<bool, String> {
    // Brownfield fail-safe: the customer OWNS their gateway (their unit, their
    // launch args). `AIKEY_DE_MANAGE_GATEWAY=0` (set by the brownfield installer)
    // means "never touch their gateway" — the customer restarts it once after the
    // first VK lands (a documented one-time step). Default unset/"1" preserves the
    // greenfield behavior where AiKey owns the gateway and applies key changes.
    if std::env::var("AIKEY_DE_MANAGE_GATEWAY")
        .map(|v| v == "0")
        .unwrap_or(false)
    {
        return Ok(false);
    }
    // Greenfield: AiKey owns the gateway as a systemd unit (AIKEY_DE_GATEWAY_UNIT,
    // set by the greenfield installer). Restart via systemd — it needs no gateway
    // auth and reliably reloads the patched config. WHY not the `openclaw health` +
    // `openclaw gateway restart` path below: the greenfield gateway runs with
    // `--auth password`, so a tokenless `openclaw health` exits non-zero here
    // ("reachable, but no token for health RPCs"), making the probe below falsely
    // report "no gateway" and skip the restart — the live gateway then keeps its
    // pre-VK config and a newly assigned/rotated key never reaches the chat UI.
    if let Ok(unit) = std::env::var("AIKEY_DE_GATEWAY_UNIT") {
        if !unit.is_empty() {
            let out = Command::new("systemctl")
                .args(["restart", &unit])
                .output()
                .map_err(|e| format!("systemctl restart {unit}: {e}"))?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
            // VERIFY the gateway actually came back up — don't fire-and-forget.
            // `systemctl restart` reports success once the unit is *started*, but the
            // process can still crash-loop or fail to bind. Probe the listen port (set
            // by the installer as AIKEY_DE_GATEWAY_PORT) so a dead gateway surfaces
            // loudly (the daemon loop prints this Err as a WARN) instead of the silent
            // "restarted OK" that hid the original chat-delivery gap.
            if let Ok(port) = std::env::var("AIKEY_DE_GATEWAY_PORT") {
                if let Ok(p) = port.parse::<u16>() {
                    if !gateway_port_listening(p) {
                        return Err(format!(
                            "gateway unit '{unit}' restarted but :{p} is not listening \
                             after retries — check `journalctl -u {unit}`"
                        ));
                    }
                }
            }
            return Ok(true);
        }
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

/// Probe whether the chat gateway accepts TCP on `127.0.0.1:port`, retrying so a
/// just-restarted gateway has time to bind. Used to VERIFY (not fire-and-forget) that a
/// gateway restart actually brought the listen port back up.
///
/// Window = ~60s: the OpenClaw gateway is NOT instant — it loads config, starts channels
/// + sidecars, and pre-warms provider auth before binding. Warmup is NOT bounded by the
/// earlier ~10-13s observation: under event-loop pressure the provider-auth pre-warm alone
/// took ~14s and "ready" landed at ~18s from start, and the restart→bind gap exceeded the
/// old 20s window → a bogus "restart failed (apply manually)" WARN on a gateway that was
/// in fact coming up fine (staging lobster, 2026-06-17). 60s comfortably covers a cold +
/// blocked-event-loop warmup. Each refused connect returns immediately, so the loop is
/// paced by the 1s sleep (~60 tries ≈ 60s wall). Over-waiting is cheap (only runs on a
/// restart, best-effort); under-waiting cries wolf — bias to the longer window.
fn gateway_port_listening(port: u16) -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    for attempt in 0..60 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok() {
            return true;
        }
        if attempt < 59 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    false
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
        let managed_model = de_manages_gateway().then_some(model);
        openclaw_config_patch(&build_repoint_patch(&pid, &token, &base_url, managed_model))?;
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
    // Set our provider as OpenClaw's default chat model — but only if none is
    // pinned, so a production default is never overridden (2026-06-15).
    if !openclaw_default_model_set() {
        openclaw_config_patch(&build_default_model_patch(&pid, model))?;
        println!("  default model : {pid}/{model} (none was pinned)");
    } else {
        println!("  default model : left as-is (you have one pinned)");
    }
    println!("  If the OpenClaw gateway is already running, reload it to apply.");
    Ok(())
}

/// Daemon-friendly variant of `install`: configure OpenClaw for the currently
/// assigned team VK WITHOUT the interactive banner, used by `aikey agent start`.
///
/// Returns `Ok(Some((bearer, default_model_set)))`: the configured team VK bearer
/// (so the daemon can detect VK changes and avoid reloading every cycle), plus a
/// flag that is `true` only on the cycle where we FIRST set OpenClaw's default
/// chat model (so the daemon knows to restart the gateway even when the VK didn't
/// change — e.g. a redeploy). `Ok(None)` when no VK is assigned yet (daemon waits
/// and retries). Real failures (vault read, openclaw patch) propagate as `Err`.
pub(crate) fn configure_quiet(model: Option<&str>) -> Result<Option<(String, bool)>, String> {
    let (token, base_url) = match resolve_anthropic_team_route() {
        Ok(v) => v,
        // The only "not an error, just not ready" case: no assigned team VK yet.
        Err(e) if e.contains("no active team virtual key") => return Ok(None),
        Err(e) => return Err(e),
    };
    let pid = provider_id();
    let model = model.unwrap_or(DEFAULT_MODEL);
    if is_repoint_mode() {
        // Brownfield: when AiKey owns the gateway (digital-employee lobster) write the
        // chat model WITH maxTokens — else the gateway chat throws "requires a positive
        // maxTokens value". For a real customer (hands-off, AIKEY_DE_MANAGE_GATEWAY=0)
        // keep models[] out so their existing model list survives.
        let managed_model = de_manages_gateway().then_some(model);
        openclaw_config_patch(&build_repoint_patch(&pid, &token, &base_url, managed_model))?;
    } else {
        openclaw_config_patch(&build_install_patch(&pid, &token, &base_url, model))?;
    }
    // Make our provider OpenClaw's DEFAULT chat model so the digital employee's
    // chat actually routes through AiKey — but ONLY when no default is pinned, so a
    // user/operator's production default is never overridden. WHY (2026-06-15 root
    // cause): without a default set, OpenClaw fell back to a stale/other provider
    // (dead VK) → "Route token not found in registry".
    let mut default_model_set = false;
    if !openclaw_default_model_set() {
        openclaw_config_patch(&build_default_model_patch(&pid, model))?;
        default_model_set = true;
    }
    Ok(Some((token, default_model_set)))
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
    fn default_model_patch_sets_agents_defaults_primary() {
        // The default-model patch must write agents.defaults.model.primary (the
        // field OpenClaw resolves its default chat model from) + register it in
        // agents.defaults.models, so the digital employee's chat routes through us.
        let p = build_default_model_patch("aikey", "claude-sonnet-4-5");
        assert_eq!(
            p["agents"]["defaults"]["model"]["primary"],
            "aikey/claude-sonnet-4-5"
        );
        assert!(p["agents"]["defaults"]["models"]["aikey/claude-sonnet-4-5"].is_object());
        // It must NOT touch models.providers (that's the separate provider patch).
        assert!(p["models"].is_null());
    }

    #[test]
    fn install_patch_honors_custom_provider_id() {
        // Greenfield can still be told a non-default id; the patch nests under it.
        let p = build_install_patch("myprov", "tok", "http://x/anthropic", "m");
        assert!(p["models"]["providers"]["myprov"].is_object());
        assert!(p["models"]["providers"]["aikey"].is_null());
    }

    #[test]
    fn repoint_patch_handsoff_omits_models_to_preserve_customer_list() {
        // Real customer (managed_model = None): ONLY baseUrl/apiKey/api under the
        // CUSTOMER's provider id, NO models[] (sending one would replace their list).
        let p = build_repoint_patch(
            "anthropic",
            "aikey_team_xyz",
            "http://127.0.0.1:27200/anthropic",
            None,
        );
        let prov = &p["models"]["providers"]["anthropic"];
        assert_eq!(prov["api"], "anthropic-messages");
        assert_eq!(prov["apiKey"], "aikey_team_xyz");
        assert_eq!(prov["baseUrl"], "http://127.0.0.1:27200/anthropic");
        // The crux: no models key → customer's existing model list is untouched.
        assert!(prov["models"].is_null());
    }

    #[test]
    fn repoint_patch_managed_writes_model_with_max_tokens() {
        // AiKey-managed lobster (managed_model = Some): the repoint MUST define the
        // chat model WITH maxTokens, else the gateway chat throws
        // "requires a positive maxTokens value". Regression guard for 2026-06-16.
        let p = build_repoint_patch(
            "anthropic",
            "aikey_team_xyz",
            "http://127.0.0.1:27200/anthropic",
            Some("claude-sonnet-4-5"),
        );
        let prov = &p["models"]["providers"]["anthropic"];
        assert_eq!(prov["models"][0]["id"], "claude-sonnet-4-5");
        assert_eq!(prov["models"][0]["maxTokens"], 8192);
        assert!(prov["models"][0]["contextWindow"].is_number());
    }

    #[test]
    fn repoint_patch_is_deterministic() {
        let a = build_repoint_patch("p", "t", "u", None).to_string();
        let b = build_repoint_patch("p", "t", "u", None).to_string();
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
