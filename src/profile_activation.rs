//! Multi-provider profile activation engine (v1.0.2).
//!
//! Implements the "implicit default profile" model where each provider has
//! exactly one Primary key.  This module is the single source of truth for:
//!
//! - Assigning / removing provider primaries
//! - Refreshing `~/.aikey/active.env` from the current binding set
//! - Reconciling bindings after key sync or key removal
//!
//! It intentionally does **not** perform interactive I/O — that stays in
//! `commands_account.rs`.  Functions here return results; callers decide
//! how to present them.

use crate::commands_account::{provider_env_vars_pub, provider_extra_env_vars_pub, provider_proxy_prefix_pub};
use crate::commands_proxy;
use crate::credential_type;
use crate::storage::{self, ProviderBinding};

/// Default profile id used throughout v1.0.2 (implicit unique profile).
pub const DEFAULT_PROFILE: &str = "default";

// ============================================================================
// refresh_implicit_profile_activation
// ============================================================================

/// Reads all provider bindings for the default profile, rewrites
/// `~/.aikey/active.env`, bumps the vault change-seq and nudges the
/// proxy to reload.
///
/// This is the **single write-path** for `active.env` in the new model.
/// All other functions that mutate bindings should call this afterwards.
pub fn refresh_implicit_profile_activation() -> Result<RefreshResult, String> {
    let bindings = storage::list_provider_bindings(DEFAULT_PROFILE)?;
    let proxy_port = commands_proxy::proxy_port();

    // Build env lines.
    let mut env_lines: Vec<String> = vec![
        "# aikey active key — auto-generated, do not edit manually".to_string(),
    ];
    let mut activated_providers: Vec<String> = Vec::new();

    for b in &bindings {
        if let Some((api_key_var, base_url_var)) = provider_env_vars_pub(&b.provider_code) {
            let token = sentinel_token(b.key_source_type.as_str(), &b.key_source_ref);
            let base_url = format!(
                "http://127.0.0.1:{}/{}",
                proxy_port,
                provider_proxy_prefix_pub(&b.provider_code)
            );
            env_lines.push(format!("export {}=\"{}\"", api_key_var, token));
            // Why: Codex v0.118+ warns when OPENAI_BASE_URL env var is set,
            // because it now reads openai_base_url from ~/.codex/config.toml.
            // We inject that config via configure_codex_cli(), so skip the
            // env var to avoid the deprecation warning.
            let skip_base_url = matches!(
                b.provider_code.to_lowercase().as_str(),
                "openai" | "gpt" | "chatgpt"
            );
            if !skip_base_url {
                env_lines.push(format!("export {}=\"{}\"", base_url_var, base_url));
            }
            // Provider-specific extras (e.g. KIMI_MODEL_NAME for the
            // minimal-scaffold Kimi config — see commands_account docstring).
            for (extra_var, extra_val) in provider_extra_env_vars_pub(&b.provider_code) {
                env_lines.push(format!("export {}=\"{}\"", extra_var, extra_val));
            }
            activated_providers.push(b.provider_code.clone());
        }
    }

    // Ensure localhost traffic to the local proxy is never hijacked by the
    // user's HTTP proxy (http_proxy / all_proxy).  We append 127.0.0.1 and
    // localhost to the existing no_proxy — the user's proxy for external
    // sites remains fully intact.
    //
    // Why idempotent guard: active.env is sourced on every prompt (precmd).
    // Without the guard, `no_proxy` would accumulate duplicates indefinitely.
    // The case/esac check ensures 127.0.0.1 is added exactly once.
    if !activated_providers.is_empty() {
        env_lines.push(
            "case \",$no_proxy,\" in *,127.0.0.1,*) ;; *) export no_proxy=\"127.0.0.1,localhost,${no_proxy:-}\" ;; esac".to_string()
        );
        env_lines.push(
            "case \",$NO_PROXY,\" in *,127.0.0.1,*) ;; *) export NO_PROXY=\"127.0.0.1,localhost,${NO_PROXY:-}\" ;; esac".to_string()
        );
    }

    // Active key mapping: provider=display_name pairs for preexec display.
    // Allows the shell hook to print which key/account is active for each CLI tool.
    // Covers all credential types: personal API key (alias), team key (alias), OAuth (email).
    let mut active_pairs: Vec<String> = Vec::new();
    for b in &bindings {
        let display = match b.key_source_type {
            credential_type::CredentialType::PersonalOAuthAccount => {
                if let Ok(Some(acct)) = storage::get_provider_account(&b.key_source_ref) {
                    acct.display_identity.as_deref()
                        .filter(|s| !s.is_empty())
                        .or_else(|| acct.external_id.as_deref().filter(|s| !s.is_empty()))
                        .unwrap_or(&b.key_source_ref)
                        .to_string()
                } else {
                    b.key_source_ref.clone()
                }
            }
            credential_type::CredentialType::ManagedVirtualKey => {
                // Team key: try to resolve local alias, fallback to virtual_key_id
                storage::get_virtual_key_cache(&b.key_source_ref)
                    .ok().flatten()
                    .map(|e| e.local_alias.unwrap_or(e.alias))
                    .unwrap_or_else(|| b.key_source_ref.clone())
            }
            _ => b.key_source_ref.clone(), // Personal API key: alias is the ref
        };
        active_pairs.push(format!("{}={}", b.provider_code, display));
    }
    if !active_pairs.is_empty() {
        env_lines.push(format!("export AIKEY_ACTIVE_KEYS=\"{}\"", active_pairs.join(",")));
    } else {
        env_lines.push("unset AIKEY_ACTIVE_KEYS 2>/dev/null".to_string());
    }

    // Write active.env
    write_active_env_file(&env_lines)?;

    // Backward compat: also write active_key_config for any remaining consumers
    // of the legacy single-key model. executor::run_with_active_key() now reads
    // provider bindings directly, but this shim is kept for pre-migration vault
    // callers and external tooling that may read active_key_config.
    // TODO: remove once all consumers are migrated to provider bindings.
    sync_active_key_config_from_bindings(&bindings)?;

    // Bump change-seq so the proxy knows the vault state changed.
    let _ = storage::bump_vault_change_seq();
    commands_proxy::try_reload_proxy();

    Ok(RefreshResult {
        activated_providers,
        bindings,
    })
}

/// Result of a profile activation refresh.
#[derive(Debug)]
pub struct RefreshResult {
    /// Providers that were written to `active.env`.
    pub activated_providers: Vec<String>,
    /// The full binding set used.
    pub bindings: Vec<ProviderBinding>,
}

// ============================================================================
// auto_assign_primaries_for_key
// ============================================================================

/// After a key is added (personal or team), check each of its providers.
/// If the provider has no current binding, assign this key as the Primary.
///
/// Returns the list of providers where this key became the new Primary.
pub fn auto_assign_primaries_for_key(
    key_source_type: &str,
    key_source_ref: &str,
    providers: &[String],
) -> Result<Vec<String>, String> {
    let mut newly_assigned: Vec<String> = Vec::new();

    for provider in providers {
        let existing = storage::get_provider_binding(DEFAULT_PROFILE, provider)?;
        if existing.is_none() {
            storage::set_provider_binding(
                DEFAULT_PROFILE,
                provider,
                key_source_type,
                key_source_ref,
            )?;
            newly_assigned.push(provider.clone());
        }
    }

    Ok(newly_assigned)
}

// ============================================================================
// reconcile_provider_primaries_after_team_key_sync
// ============================================================================

/// After team key sync, for each synced key's supported providers, if the
/// provider has no current Primary, assign the team key.
///
/// This is a thin wrapper around `auto_assign_primaries_for_key` operating
/// on a batch of team keys.
pub fn reconcile_provider_primaries_after_team_key_sync(
    synced_keys: &[(String, Vec<String>)], // (virtual_key_id, supported_providers)
) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut results: Vec<(String, Vec<String>)> = Vec::new();

    for (vk_id, providers) in synced_keys {
        let assigned = auto_assign_primaries_for_key("team", vk_id, providers)?;
        if !assigned.is_empty() {
            results.push((vk_id.clone(), assigned));
        }
    }

    Ok(results)
}

// ============================================================================
// reconcile_provider_primary_after_key_removal
// ============================================================================

/// When a key is deleted/revoked, remove its bindings and attempt to fill the
/// gap with another available key for each affected provider.
///
/// Returns the list of providers that were affected and how they were resolved.
pub fn reconcile_provider_primary_after_key_removal(
    key_source_type: &str,
    key_source_ref: &str,
) -> Result<Vec<ReconcileAction>, String> {
    // Remove all bindings referencing this key.
    let affected_providers =
        storage::remove_bindings_by_key_source(DEFAULT_PROFILE, key_source_type, key_source_ref)?;

    let mut actions: Vec<ReconcileAction> = Vec::new();

    for provider in &affected_providers {
        // Try to find a replacement candidate.
        let replacement = find_replacement_candidate(provider, key_source_type, key_source_ref)?;
        match replacement {
            Some((src_type, src_ref)) => {
                storage::set_provider_binding(
                    DEFAULT_PROFILE,
                    provider,
                    &src_type,
                    &src_ref,
                )?;
                actions.push(ReconcileAction {
                    provider_code: provider.clone(),
                    outcome: ReconcileOutcome::Replaced {
                        new_source_type: src_type,
                        new_source_ref: src_ref,
                    },
                });
            }
            None => {
                actions.push(ReconcileAction {
                    provider_code: provider.clone(),
                    outcome: ReconcileOutcome::Cleared,
                });
            }
        }
    }

    Ok(actions)
}

/// Outcome of reconciling a single provider after its Primary was removed.
#[derive(Debug, Clone)]
pub enum ReconcileOutcome {
    /// Another key was promoted to Primary.
    Replaced {
        new_source_type: String,
        new_source_ref: String,
    },
    /// No replacement found; provider has no Primary.
    Cleared,
}

/// A reconcile action for a single provider.
#[derive(Debug, Clone)]
pub struct ReconcileAction {
    pub provider_code: String,
    pub outcome: ReconcileOutcome,
}

// ============================================================================
// Helpers
// ============================================================================

/// Syncs the legacy `active_key_config` from the current provider bindings.
///
/// Picks the first binding as the "representative" active key (for backward
/// compat with `aikey run` and other commands that still read the single-key
/// config). All bound providers are listed in `providers`.
fn sync_active_key_config_from_bindings(bindings: &[ProviderBinding]) -> Result<(), String> {
    if bindings.is_empty() {
        // Clear legacy config.
        let _ = storage::set_active_key_config(&storage::ActiveKeyConfig {
            key_type: crate::credential_type::CredentialType::PersonalApiKey, // default when clearing
            key_ref: String::new(),
            providers: vec![],
        });
        return Ok(());
    }

    // Use the first binding as the representative key.
    let first = &bindings[0];
    let all_providers: Vec<String> = bindings.iter().map(|b| b.provider_code.clone()).collect();

    storage::set_active_key_config(&storage::ActiveKeyConfig {
        key_type: first.key_source_type.clone(),
        key_ref: first.key_source_ref.clone(),
        providers: all_providers,
    })?;
    Ok(())
}

/// Builds the sentinel token that the proxy expects in env vars.
fn sentinel_token(key_source_type: &str, key_source_ref: &str) -> String {
    if key_source_type == "team" {
        format!("aikey_vk_{}", key_source_ref)
    } else {
        format!("aikey_personal_{}", key_source_ref)
    }
}

/// Writes the env lines to `~/.aikey/active.env`.
fn write_active_env_file(lines: &[String]) -> Result<(), String> {
    // Use resolve_aikey_dir for consistent HOME → USERPROFILE → "." fallback.
    let aikey_dir = crate::commands_account::resolve_aikey_dir();
    std::fs::create_dir_all(&aikey_dir)
        .map_err(|e| format!("Failed to create ~/.aikey: {}", e))?;
    let env_path = aikey_dir.join("active.env");

    let content = lines.join("\n") + "\n";

    // v3 architecture: active.env contains only env vars (no source statements).
    // Wrapper functions live in ~/.aikey/hook.{zsh,bash}, loaded once from shell rc.

    std::fs::write(&env_path, content)
        .map_err(|e| format!("Failed to write active.env: {}", e))?;

    // Also write active.env.flat (plain KEY=VALUE, no shell syntax) for Windows.
    // PowerShell/cmd deactivate reads this file instead of parsing sh-style active.env.
    let flat_path = aikey_dir.join("active.env.flat");
    let flat_lines: Vec<String> = lines.iter()
        .filter_map(|line| {
            // Extract KEY="VALUE" from `export KEY="VALUE"` lines.
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("export ") {
                if let Some(eq) = rest.find('=') {
                    let key = &rest[..eq];
                    let val = rest[eq + 1..].trim_matches('"');
                    // Skip shell-expansion lines (${...}) — not valid for flat file.
                    if !val.contains("${") {
                        return Some(format!("{}={}", key, val));
                    }
                }
            }
            None
        })
        .collect();
    if !flat_lines.is_empty() {
        let _ = std::fs::write(&flat_path, flat_lines.join("\n") + "\n");
    }

    Ok(())
}

/// Searches for a replacement key that supports the given provider.
/// Returns the first usable candidate as `(key_source_type, key_source_ref)`.
///
/// Strategy: oldest personal key first, then oldest team key.
/// The removed key (`excluded_type`/`excluded_ref`) is skipped.
fn find_replacement_candidate(
    provider_code: &str,
    excluded_type: &str,
    excluded_ref: &str,
) -> Result<Option<(String, String)>, String> {
    // Search personal keys, sorted by created_at (oldest first) for
    // deterministic "earliest added" backfill order.
    let mut entries = storage::list_entries_with_metadata()
        .unwrap_or_default();
    entries.sort_by_key(|e| e.created_at.unwrap_or(i64::MAX));
    for entry in &entries {
        if entry.alias == excluded_ref && excluded_type == "personal" {
            continue;
        }
        let providers = resolve_providers_for_entry(entry);
        if providers.iter().any(|p| p == provider_code) {
            return Ok(Some(("personal".to_string(), entry.alias.clone())));
        }
    }

    // Search team keys.
    let vk_entries = storage::list_virtual_key_cache().unwrap_or_default();
    for vk in &vk_entries {
        if vk.virtual_key_id == excluded_ref && excluded_type == "team" {
            continue;
        }
        // Only consider usable team keys.
        if vk.local_state != "active" && vk.local_state != "synced_inactive" {
            continue;
        }
        if vk.key_status != "active" {
            continue;
        }
        let providers = if !vk.supported_providers.is_empty() {
            &vk.supported_providers
        } else if !vk.provider_code.is_empty() {
            // Borrow a temporary vec — just check inline.
            if vk.provider_code == provider_code {
                return Ok(Some(("team".to_string(), vk.virtual_key_id.clone())));
            }
            continue;
        } else {
            continue;
        };
        if providers.iter().any(|p| p == provider_code) {
            return Ok(Some(("team".to_string(), vk.virtual_key_id.clone())));
        }
    }

    Ok(None)
}

/// Resolve providers for a personal key entry using the same priority as
/// `storage::resolve_supported_providers`, but without an extra DB call
/// (we already have the metadata in memory).
fn resolve_providers_for_entry(entry: &storage::SecretMetadata) -> Vec<String> {
    if let Some(ref sp) = entry.supported_providers {
        if !sp.is_empty() {
            return sp.clone();
        }
    }
    if let Some(ref code) = entry.provider_code {
        if !code.is_empty() {
            return vec![code.clone()];
        }
    }
    vec![]
}
