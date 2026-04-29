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

    // Bump change-seq up front so the value embedded in active.env is the
    // value the proxy will see for this state. Why bump-before-write: a
    // crashed process between write and bump would leave active.env with a
    // seq newer than the on-disk counter, breaking precmd's diff for any
    // shell that already saw that seq. Bump-first means a crash leaves the
    // counter ahead of the file at worst — shells re-source on next prompt.
    let _ = storage::bump_vault_change_seq();
    let active_seq = storage::get_vault_change_seq().unwrap_or(0);

    // Build env lines. AIKEY_ACTIVE_SEQ goes near the top so the precmd
    // hook's `grep -m1` can short-circuit cheaply.
    let mut env_lines: Vec<String> = vec![
        "# aikey active key — auto-generated, do not edit manually".to_string(),
        format!("export AIKEY_ACTIVE_SEQ=\"{}\"", active_seq),
    ];
    let mut activated_providers: Vec<String> = Vec::new();

    for b in &bindings {
        if let Some((api_key_var, base_url_var)) = provider_env_vars_pub(&b.provider_code) {
            let token = sentinel_token(&b.provider_code);
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

    // change_seq already bumped at the top of this function so the value
    // is reflected in active.env. Just nudge the proxy now.
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
/// Returns the list of providers where this key became the new Primary
/// (reported in their canonical form — claude → anthropic, codex → openai —
/// matching what actually got written to the bindings table).
///
/// # Canonical normalization
/// As of 2026-04-24 (per CLAUDE.md §"`_internal` 隐藏命令必须复用公开命令的
/// 非交互 core"), every binding write must go through
/// `commands_account::write_bindings_canonical` — otherwise the bindings
/// table can drift into a state with both raw (e.g. "codex") and canonical
/// (e.g. "openai") rows for the same routing target, which the vault UI
/// would correctly show as "two in_use in one family". Callers can pass
/// raw OAuth-vocabulary provider codes ("claude" / "codex") here; the
/// helper normalizes + cleans stale alias rows on write.
pub fn auto_assign_primaries_for_key(
    key_source_type: &str,
    key_source_ref: &str,
    providers: &[String],
) -> Result<Vec<String>, String> {
    let mut newly_assigned: Vec<String> = Vec::new();

    for raw in providers {
        let canonical = crate::commands_account::oauth_provider_to_canonical(
            &raw.to_lowercase()
        ).to_string();
        let existing = storage::get_provider_binding(DEFAULT_PROFILE, &canonical)?;
        if existing.is_none() {
            // Funnels through the shared canonical-write helper so any
            // stale non-canonical alias row (e.g. a prior "codex" row from
            // a pre-fix CLI) is cleaned up as a side effect.
            crate::commands_account::write_bindings_canonical(
                &[canonical.clone()],
                key_source_type,
                key_source_ref,
            )?;
            newly_assigned.push(canonical);
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
                // Canonical-write (2026-04-24 rule) — replacement bindings
                // go through the same helper as every other write path so
                // stale alias rows self-heal.
                crate::commands_account::write_bindings_canonical(
                    &[provider.clone()],
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

/// Builds the sentinel token that the proxy expects in env vars for the
/// "follow active binding" routing semantic.
///
/// The token is per-provider (e.g. `aikey_active_anthropic`) — independent of
/// which credential is currently bound. The proxy's tier-3 fallthrough uses
/// the URL path's canonical provider code to look up the active binding from
/// the vault DB on every request, so the suffix here is purely informational
/// and never read by the proxy. This means `aikey use` switching credentials
/// (personal / OAuth / team) for the same provider does NOT need to rewrite
/// active.env — the sentinel string stays the same; only the binding table
/// changes. Eliminates a class of "shell didn't re-source after `aikey use`"
/// bugs.
///
/// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md
fn sentinel_token(canonical_provider: &str) -> String {
    format!("aikey_active_{}", canonical_provider)
}

/// Writes the env lines to `~/.aikey/active.env` atomically.
///
/// Why atomic: a shell hook may be `source`-ing this file at the moment we
/// rewrite it. Plain `std::fs::write` truncates first, opening a window
/// where the shell reads a partial file → "command not found" / parse
/// errors. Same for `active.env.flat` (Windows). We write to a temp file in
/// the same directory then `rename`, which POSIX guarantees atomic on the
/// same filesystem (and Win32 ReplaceFile semantics on Windows for stable
/// readers — best-effort there).
fn write_active_env_file(lines: &[String]) -> Result<(), String> {
    // Use resolve_aikey_dir for consistent HOME → USERPROFILE → "." fallback.
    let aikey_dir = crate::commands_account::resolve_aikey_dir();
    std::fs::create_dir_all(&aikey_dir)
        .map_err(|e| format!("Failed to create ~/.aikey: {}", e))?;
    let env_path = aikey_dir.join("active.env");

    let content = lines.join("\n") + "\n";

    // v3 architecture: active.env contains only env vars (no source statements).
    // Wrapper functions live in ~/.aikey/hook.{zsh,bash}, loaded once from shell rc.

    atomic_write(&env_path, content.as_bytes())
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
        // Reviewer round-3 fix: don't swallow .flat write errors. A failed
        // .flat write means PowerShell / cmd `aikey deactivate` will read
        // stale globals — the operation looks successful from the POSIX
        // shell's POV but Windows users see ghost env. Surfacing as a
        // warning (not a hard error) preserves the existing contract that
        // `refresh_implicit_profile_activation` succeeds when the primary
        // active.env write succeeds, while still giving operators a signal
        // to chase the underlying disk / perms issue.
        if let Err(e) = atomic_write(&flat_path, (flat_lines.join("\n") + "\n").as_bytes()) {
            eprintln!(
                "\x1b[33m[aikey] warn: failed to update {}: {} \
                 (Windows deactivate may restore stale env)\x1b[0m",
                flat_path.display(),
                e,
            );
        }
    }

    Ok(())
}

/// Atomic file replace via temp+rename. Caller-provided directory must exist.
/// On error the temp file is best-effort cleaned up.
fn atomic_write(target: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent dir")
    })?;
    let file_name = target.file_name().and_then(|s| s.to_str()).unwrap_or("active");
    // Per-pid suffix avoids collisions if two `aikey` processes refresh
    // concurrently. Last writer wins on rename — that's the seq's job to
    // record the order, the file content is a snapshot either way.
    let temp_path = parent.join(format!("{}.tmp.{}", file_name, std::process::id()));
    match std::fs::write(&temp_path, content) {
        Ok(()) => match std::fs::rename(&temp_path, target) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&temp_path);
                Err(e)
            }
        },
        Err(e) => {
            let _ = std::fs::remove_file(&temp_path);
            Err(e)
        }
    }
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
    // Canonicalize the target on entry, then canonicalize each candidate's
    // provider on comparison. Why both sides: bindings rows go through
    // `write_bindings_canonical`, but personal entries / VK cache rows from
    // earlier code paths or server payloads can still hold raw OAuth /
    // broker vocabulary (`claude` / `codex` / `moonshot`). A naïve `==`
    // would silently miss a perfectly valid replacement and the user
    // would see "no candidate" despite having one — same family as the
    // 2026-04-25 activate canonicalization bug.
    let target = crate::commands_account::oauth_provider_to_canonical(provider_code);

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
        if providers.iter().any(|p|
            crate::commands_account::oauth_provider_to_canonical(p) == target
        ) {
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
            if crate::commands_account::oauth_provider_to_canonical(&vk.provider_code) == target {
                return Ok(Some(("team".to_string(), vk.virtual_key_id.clone())));
            }
            continue;
        } else {
            continue;
        };
        if providers.iter().any(|p|
            crate::commands_account::oauth_provider_to_canonical(p) == target
        ) {
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

#[cfg(test)]
mod atomic_write_tests {
    use super::atomic_write;

    // Stage 4 (active-state cross-shell sync, 2026-04-27):
    // active.env is now written via temp+rename so a shell that's mid-source
    // never reads a partially-written file. These tests pin the contract.

    #[test]
    fn atomic_write_creates_target_with_content() {
        let dir = std::env::temp_dir().join(format!(
            "aikey-atomic-test-create-{}", std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env");
        atomic_write(&target, b"hello\n").expect("write");
        assert_eq!(std::fs::read(&target).unwrap(), b"hello\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_replaces_existing_content() {
        let dir = std::env::temp_dir().join(format!(
            "aikey-atomic-test-replace-{}", std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env");
        std::fs::write(&target, b"old content\n").unwrap();
        atomic_write(&target, b"new content\n").expect("replace");
        assert_eq!(std::fs::read(&target).unwrap(), b"new content\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_does_not_leave_temp_file_on_success() {
        // The whole point of temp+rename: post-rename, the .tmp.<pid> file
        // must not exist. Otherwise drift detection / cleanup logic that
        // greps the directory could trip over stale temps.
        let dir = std::env::temp_dir().join(format!(
            "aikey-atomic-test-cleanup-{}", std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env");
        atomic_write(&target, b"x\n").expect("write");
        let entries: Vec<String> = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !entries.iter().any(|n| n.contains(".tmp.")),
            "temp file was not cleaned up after rename, dir contents: {:?}",
            entries,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
