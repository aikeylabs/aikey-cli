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

use std::collections::HashSet;

use crate::commands_account::{provider_env_vars_pub, provider_extra_env_vars_pub};
use crate::commands_proxy;
use crate::credential_type;
use crate::storage::{self, ProviderBinding};
use colored::Colorize;

/// Shell variables emitted by short-lived, pre-four-axis projections. They
/// are deliberately kept outside the provider registry: registering them
/// would reintroduce Mock Provider as a client route. New active.env files
/// must unset them so re-sourcing also cleans already-running shells.
const LEGACY_PROJECTION_ENV_VARS: &[&str] = &[
    "AIKEY_MOCK_PROVIDER_TOKEN",
    "AIKEY_MOCK_PROVIDER_BASE_URL",
    "AIKEY_ACTIVE_CLIENT_ROUTES",
];

/// Default profile id used throughout v1.0.2 (implicit unique profile).
pub const DEFAULT_PROFILE: &str = "default";

/// Render the value stored beside a client route in `AIKEY_ACTIVE_KEYS`.
///
/// This is deliberately shared with lifecycle audit: the generated env file
/// and its verifier must resolve OAuth identities and Team-key aliases with
/// the same rule, otherwise every healthy non-personal binding looks stale.
pub(crate) fn active_binding_display(binding: &ProviderBinding) -> String {
    match binding.key_source_type {
        credential_type::CredentialType::PersonalOAuthAccount => {
            if let Ok(Some(account)) = storage::get_provider_account(&binding.key_source_ref) {
                account
                    .display_identity
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .or_else(|| account.external_id.as_deref().filter(|s| !s.is_empty()))
                    .unwrap_or(&binding.key_source_ref)
                    .to_string()
            } else {
                binding.key_source_ref.clone()
            }
        }
        credential_type::CredentialType::ManagedVirtualKey => {
            storage::get_virtual_key_cache(&binding.key_source_ref)
                .ok()
                .flatten()
                .map(|entry| entry.local_alias.unwrap_or(entry.alias))
                .unwrap_or_else(|| binding.key_source_ref.clone())
        }
        credential_type::CredentialType::PersonalApiKey => binding.key_source_ref.clone(),
    }
}

/// For every env var registered in `provider_registry::entries()` that was
/// NOT in `emitted_export_vars`, append an `unset VAR 2>/dev/null` line to
/// `env_lines`.
///
/// Why: `source FILE.env` only runs the file's `export` statements; it does
/// NOT auto-unset vars that the file no longer mentions. So a shell that
/// already sourced an older active.env (with KIMI_API_KEY=...) and then
/// re-sources a newer one (no KIMI_*) keeps the stale `KIMI_API_KEY` until
/// the user opens a new terminal. This helper makes the active.env file
/// itself emit explicit `unset` for everything inactive, so re-sourcing is
/// idempotent — every shell ends up with exactly the active set, no more.
///
/// Why registry-driven (not a hardcoded provider list): single source of
/// truth. Adding a provider to `data/provider_registry.yaml` automatically
/// extends the unset coverage. kimi vs moonshot are intentionally distinct
/// entries with distinct env vars (KIMI_* vs MOONSHOT_*); both get covered
/// without dedup logic.
fn append_unset_lines_for_inactive_providers(
    env_lines: &mut Vec<String>,
    emitted_export_vars: &HashSet<String>,
) {
    // Track vars already given an `unset` line so we don't duplicate when
    // multiple registry entries reference the same env var (e.g. kimi +
    // moonshot share KIMI_MODEL_NAME via extras when they map the same
    // protocol family). HashSet::insert returns true the first time only,
    // doubling as the "should we emit?" gate.
    let mut already_unset: HashSet<&'static str> = HashSet::new();
    let emit =
        |env_lines: &mut Vec<String>, var: &'static str, already: &mut HashSet<&'static str>| {
            if !emitted_export_vars.contains(var) && already.insert(var) {
                env_lines.push(format!("unset {} 2>/dev/null", var));
            }
        };
    for entry in crate::provider_registry::entries() {
        let (api_key_var, base_url_var) = entry.env_vars;
        if !api_key_var.is_empty() {
            emit(env_lines, api_key_var, &mut already_unset);
        }
        if !base_url_var.is_empty() {
            emit(env_lines, base_url_var, &mut already_unset);
        }
        for (extra_var, _) in entry.extra_env_vars {
            emit(env_lines, extra_var, &mut already_unset);
        }
    }
}

fn append_unset_lines_for_legacy_projections(env_lines: &mut Vec<String>) {
    env_lines.extend(
        LEGACY_PROJECTION_ENV_VARS
            .iter()
            .map(|var| format!("unset {} 2>/dev/null", var)),
    );
}

/// Insert or replace one generated export while keeping active.env and its
/// shell-free `.flat` mirror byte-for-byte consistent.
fn upsert_active_export(
    env_lines: &mut Vec<String>,
    flat_pairs: &mut Vec<(String, String)>,
    emitted_export_vars: &mut HashSet<String>,
    var: &str,
    value: &str,
) {
    let rendered = crate::shell_quote::active_env_export_line(var, value);
    if emitted_export_vars.insert(var.to_string()) {
        env_lines.push(rendered);
        flat_pairs.push((var.to_string(), value.to_string()));
        return;
    }

    let prefix = format!("export {}=", var);
    if let Some(line) = env_lines.iter_mut().find(|line| line.starts_with(&prefix)) {
        *line = rendered;
    }
    if let Some((_, existing)) = flat_pairs.iter_mut().find(|(key, _)| key == var) {
        *existing = value.to_string();
    }
}

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
    //
    // SEQ stays DOUBLE-quoted on purpose: hook.zsh / hook.bash detect it with
    // `grep -oE 'AIKEY_ACTIVE_SEQ="[0-9]+"'` (literal double quotes). The value
    // is a CLI-generated integer, so it needs no shell-escaping anyway. Every
    // OTHER export value below is single-quoted via `sh_single_quote` because it
    // can carry untrusted data (server-synced alias, cluster token / node URL).
    let mut env_lines: Vec<String> = vec![
        "# aikey active key — auto-generated, do not edit manually".to_string(),
        crate::shell_quote::active_env_export_line("AIKEY_ACTIVE_SEQ", &active_seq.to_string()),
    ];
    // Structured (key, raw-value) pairs that mirror the real `export` lines.
    // active.env.flat is rendered from THIS (plain KEY=VALUE), never by
    // reverse-parsing the sh lines — see write_active_env_file. Shell-only
    // lines (no_proxy case/esac, unset) are deliberately absent from flat.
    let mut flat_pairs: Vec<(String, String)> =
        vec![("AIKEY_ACTIVE_SEQ".to_string(), active_seq.to_string())];
    let mut activated_providers: Vec<String> = Vec::new();
    // Track every env var name we `export` below so we can decide which
    // registry-known vars need an `unset` line at the end (see comment
    // before the unset loop for rationale).
    let mut emitted_export_vars: HashSet<String> = HashSet::new();
    let mut anthropic_approval_tokens: Vec<String> = Vec::new();

    // 2026-05-08 Kimi family corrupt-state pre-scan(详见 update/20260508-Kimi-family
    // 互斥-active-env统一KIMI写入.md 决策 #4):
    // family 互斥(set_provider_binding)在写入层保证最多 1 个 active binding,
    // 但运行时仍可能因 (a) 手工改 vault (b) migration race (c) future bug 出现
    // 同 family 多 active binding 的 corrupt state。此时**绝不 silently 选第一个写**
    // (该选 binding 顺序 ORDER BY provider_code 不稳定,且 binding 顺序的语义不
    // 等价于"用户最近选的"),改为:
    //   ① 输出 WARN 到 stderr + telemetry
    //   ② 跳过所有 Kimi family 的 KIMI_* / MODEL_* exports
    //   ③ 仍正常写非 Kimi family 的其它 provider exports(让用户能继续用 Claude/OpenAI)
    //   ④ 不整体 panic / abort active.env(不阻断其它 family 的 prompt activation)
    let kimi_family_active: Vec<&str> = bindings
        .iter()
        .filter(|b| storage::KIMI_FAMILY_CODES.contains(&b.provider_code.as_str()))
        .map(|b| b.provider_code.as_str())
        .collect();
    let kimi_family_corrupt = kimi_family_active.len() > 1;
    if kimi_family_corrupt {
        eprintln!(
            "  [aikey] WARN: corrupt state detected — {} active Kimi family bindings ({:?}). \
             Skipping KIMI_* exports until repaired. Run `aikey use <key> --provider <kimi_code|moonshot>` \
             to fix. Other providers (Claude / OpenAI / etc.) unaffected.",
            kimi_family_active.len(),
            kimi_family_active
        );
    }

    for b in &bindings {
        // family corrupt state 跳过整个 Kimi family
        if kimi_family_corrupt && storage::KIMI_FAMILY_CODES.contains(&b.provider_code.as_str()) {
            continue;
        }

        if let Some((api_key_var, base_url_var)) = provider_env_vars_pub(&b.client_route) {
            let Some(proxy_path) = crate::provider_registry::proxy_path_for_binding(
                &b.provider_code,
                &b.protocol_type,
            ) else {
                eprintln!(
                    "  [aikey] WARN: skipping invalid active binding provider={} protocol={} route={}",
                    b.provider_code, b.protocol_type, b.client_route
                );
                continue;
            };
            // Canonicalize before deriving the sentinel. See
            // sentinel_token's doc-comment + spec §6.1 in
            // 20260429-token前缀按角色重命名.md: `<provider>` MUST be a
            // canonical code (lowercase ASCII, no underscore/dot
            // suffix). Without canonicalization, OAuth-derived bindings
            // whose provider_code is e.g. "claude.ai" would produce
            // `aikey_active_claude.ai`, breaking the namespace-isolation
            // invariant in §3 and the proxy `aikey_*` tier switch.
            let canonical_route = crate::commands_account::oauth_provider_to_canonical(
                &b.client_route.to_lowercase(),
            );
            // §5.5 PER-PROVIDER routing (this IS the single write-path for
            // `aikey use`): a direct-bind managed VK whose user is on a cluster
            // → the central node + that VK's real token; every other binding
            // (personal/native/OAuth, Team OAuth account-pool VK, or a direct-bind
            // VK in a non-cluster deployment) → local proxy + sentinel. Mixed
            // local-key + cluster-VK bindings coexist per provider.
            let (token, base_url) =
                match crate::commands_account::cluster_route(&b.key_source_type, &b.key_source_ref)
                {
                    Some((node, vk_token)) => (vk_token, format!("http://{}/{}", node, proxy_path)),
                    None => (
                        sentinel_token(canonical_route),
                        format!("http://127.0.0.1:{}/{}", proxy_port, proxy_path),
                    ),
                };
            // 2026-05-08 Kimi 双平台拆分 review self-review fix: 如果同一个 env
            // var 名已经被前一个 binding 写过 (典型场景:vault 同时有 'kimi'
            // (deprecated alias) + 'kimi_code',两者 env_vars 都是 KIMI_API_KEY
            // / KIMI_BASE_URL),不要重复 push,否则 active.env 里同一变量出现
            // 2-3 次 (shell 中后写覆盖前写,值正确但噪声很大,影响 prompt 速度
            // + bug-trace 噪声)。emitted_export_vars HashSet 已经在跟踪此信息,
            // 这里复用它做幂等门控。
            if !emitted_export_vars.contains(api_key_var) {
                upsert_active_export(
                    &mut env_lines,
                    &mut flat_pairs,
                    &mut emitted_export_vars,
                    api_key_var,
                    &token,
                );
            }
            // Why: Codex v0.118+ warns when OPENAI_BASE_URL env var is set,
            // because it now reads openai_base_url from ~/.codex/config.toml.
            // We inject that config via configure_codex_cli(), so skip the
            // env var to avoid the deprecation warning.
            let skip_base_url = matches!(
                b.client_route.to_lowercase().as_str(),
                "openai" | "gpt" | "chatgpt"
            );
            if !skip_base_url && !emitted_export_vars.contains(base_url_var) {
                upsert_active_export(
                    &mut env_lines,
                    &mut flat_pairs,
                    &mut emitted_export_vars,
                    base_url_var,
                    &base_url,
                );
            }
            // Provider-specific extras (e.g. KIMI_MODEL_NAME for the
            // minimal-scaffold Kimi config — see commands_account docstring).
            // 同样对 extras 做幂等去重 (kimi_code / moonshot 都把 KIMI_MODEL_NAME
            // 作为 extra,不去重则重复出现)。
            for (extra_var, extra_val) in provider_extra_env_vars_pub(&b.provider_code) {
                if !emitted_export_vars.contains(extra_var) {
                    upsert_active_export(
                        &mut env_lines,
                        &mut flat_pairs,
                        &mut emitted_export_vars,
                        extra_var,
                        extra_val,
                    );
                }
            }
            if b.client_route == "anthropic" && !anthropic_approval_tokens.contains(&token) {
                anthropic_approval_tokens.push(token);
            }
            activated_providers.push(b.client_route.clone());
        }
    }

    // Emit `unset` lines for every registry-known env var that we did NOT
    // export this round. See helper docstring for rationale.
    append_unset_lines_for_inactive_providers(&mut env_lines, &emitted_export_vars);

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
        let display = active_binding_display(b);
        active_pairs.push(format!("{}={}", b.client_route, display));
    }
    if !active_pairs.is_empty() {
        // PRIMARY injection surface: active_pairs embed the display alias of
        // each binding, which for a managed (team/cluster) key is synced down
        // from the server and NOT under CLI control. Single-quote the whole
        // value so any `$(...)` / backtick / `${...}` is inert when sourced.
        let joined = active_pairs.join(",");
        env_lines.push(crate::shell_quote::active_env_export_line(
            "AIKEY_ACTIVE_KEYS",
            &joined,
        ));
        flat_pairs.push(("AIKEY_ACTIVE_KEYS".to_string(), joined));
    } else {
        env_lines.push("unset AIKEY_ACTIVE_KEYS 2>/dev/null".to_string());
    }

    // Remove all short-lived provider-keyed projections if an older
    // active.env introduced them. The binding row is the complete route truth.
    append_unset_lines_for_legacy_projections(&mut env_lines);

    // Write active.env
    write_active_env_file(&env_lines, &flat_pairs)?;

    // Sync the anthropic sentinel token's last-20 chars into ~/.claude.json's
    // `customApiKeyResponses.approved` array. Without this, claude code v2.1.x
    // interactive mode rejects the env-injected ANTHROPIC_API_KEY and falls
    // through to the OAuth login URL even though the key is valid (see
    // bugfix doc 2026-04-29-claude-interactive-ignores-anthropic-api-key.md
    // and design doc 20260429-claude-customApiKeyResponses-approval-pre-write.md).
    //
    // Soft-fail: ~/.claude.json is a tertiary writeback (active.env is the
    // primary contract; .claude.json is a workaround for an upstream bug
    // Anthropic marked closed-not-planned). A failure here just degrades to
    // the original symptom — equivalent to current state — so we warn and
    // continue rather than aborting the whole activation.
    if let Err(e) = write_claude_json_approvals(&anthropic_approval_tokens) {
        eprintln!(
            "{}",
            format!(
                "[aikey] warn: could not pre-approve ANTHROPIC_API_KEY in \
             ~/.claude.json: {} \
                 (claude may still ask to /login on first run)",
                e,
            )
            .yellow()
        );
    }

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
    audit: Option<&crate::audit::VerifiedVaultKey>,
) -> Result<Vec<String>, String> {
    // 2026-05-08 Kimi family fill-empty-only(详见 update/20260508-Kimi-family
    // 互斥-active-env统一KIMI写入.md 决策 #2.1):family 内已有任何 primary
    // (kimi_code / moonshot / legacy kimi)→ 新 key 不抢占任何 family 成员,
    // 只入 vault.entries 备用;family 完全空才允许 auto-primary。
    // 真正的 active 切换只发生在 `aikey use`(Switched lifecycle event)。
    // Why: `aikey add` / team sync / reconcile 都是"保存 / 同步",不应该悄悄
    // 切换用户当前正在使用的上游。
    let kimi_family_has_primary = storage::KIMI_FAMILY_CODES.iter().any(|c| {
        storage::get_provider_binding(DEFAULT_PROFILE, c)
            .map(|o| o.is_some())
            .unwrap_or(false)
    });

    // Material guard (2026-07-06): a team VK whose key material is NOT reachable
    // (no local ciphertext, not a claimed cluster central key, not a group VK)
    // must never be auto-promoted to Primary. A Primary binding's semantic is
    // "the proxy can serve requests with it" — binding an unreachable key gives
    // 503 NO_ACTIVE_KEY at request time while the picker hides the key and the
    // web vault still shows it as IN USE (the 2026-07-06 display-split incident).
    // Better to leave the slot EMPTY (fail-visible, next reachable key or an
    // explicit `aikey use` fills it) than to bind an unusable key. Explicit user
    // switches are NOT gated here — `use`/web set-route have their own guard
    // with a hard error (I_KEY_NOT_DELIVERED); automatic fills skip silently
    // except for the WARN below. Same predicate as the picker / web set-route
    // (`key_material_reachable`) so the three paths cannot diverge.
    if key_source_type == "team" {
        let on_cluster = crate::commands_account::read_cluster_node().is_some();
        let reachable = storage::get_virtual_key_cache(key_source_ref)
            .ok()
            .flatten()
            .map(|e| e.key_material_reachable(on_cluster))
            .unwrap_or(false);
        if !reachable {
            let msg = format!(
                "auto-assign skipped: team key {} has no reachable key material (run `aikey key sync`)",
                key_source_ref
            );
            crate::observability::log_warn_event(
                crate::observability::EVENT_CLI_BINDING_AUTO_ASSIGN_SKIPPED,
                &msg,
                Some(crate::observability::ERRCODE_BINDING_MATERIAL_UNREACHABLE),
            );
            eprintln!("[aikey] warning: {}", msg);
            return Ok(Vec::new());
        }
    }

    let mut newly_assigned: Vec<String> = Vec::new();

    for raw in providers {
        let canonical =
            crate::commands_account::oauth_provider_to_canonical(&raw.to_lowercase()).to_string();

        // Kimi family fill-empty-only: family 已有 primary 就跳过。
        if storage::KIMI_FAMILY_CODES.contains(&canonical.as_str()) && kimi_family_has_primary {
            continue;
        }

        // Fill empty CLIENT ROUTES atomically. Provider is the upstream
        // supplier, not the user's selection slot: `mock + anthropic` must
        // respect an existing official-Anthropic primary, and vice versa.
        let written_routes = crate::commands_account::write_unbound_bindings_canonical(
            &[canonical.clone()],
            key_source_type,
            key_source_ref,
            audit,
        )?;
        if !written_routes.is_empty() {
            // Traceability (2026-07-06): automatic binding writes bypass the
            // user-facing audit chain, so they MUST leave a structured event —
            // this write was previously invisible in every log store.
            crate::observability::log_event(
                crate::observability::EVENT_CLI_BINDING_AUTO_ASSIGNED,
                &format!(
                    "auto-assigned {} ({}) as primary for {} via provider {}",
                    key_source_ref,
                    key_source_type,
                    written_routes.join(","),
                    canonical
                ),
            );
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
    audit: Option<&crate::audit::VerifiedVaultKey>,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut results: Vec<(String, Vec<String>)> = Vec::new();

    for (vk_id, providers) in synced_keys {
        let assigned = auto_assign_primaries_for_key("team", vk_id, providers, audit)?;
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
    audit: Option<&crate::audit::VerifiedVaultKey>,
) -> Result<Vec<ReconcileAction>, String> {
    // Remove all bindings referencing this key.
    let affected_bindings =
        storage::remove_bindings_by_key_source(DEFAULT_PROFILE, key_source_type, key_source_ref)?;

    let mut actions: Vec<ReconcileAction> = Vec::new();

    for removed in &affected_bindings {
        // Replacement compatibility is defined by the client route. Requiring
        // the same supplier would incorrectly exclude Mock+Anthropic from an
        // Anthropic slot (and official Anthropic from the inverse case).
        let replacement =
            find_replacement_candidate(&removed.client_route, key_source_type, key_source_ref)?;
        match replacement {
            Some(candidate) => {
                storage::set_client_route_binding(
                    DEFAULT_PROFILE,
                    &removed.client_route,
                    &candidate.provider_code,
                    &candidate.protocol_type,
                    &candidate.source_type,
                    &candidate.source_ref,
                )?;
                if let Some(vk) = audit {
                    if let Err(err) = crate::audit::log_audit_event_from_vault_key(
                        vk.as_bytes(),
                        crate::audit::AuditOperation::Bind,
                        Some(&format!(
                            "{}:{}:{}:{}:{}",
                            removed.client_route,
                            candidate.provider_code,
                            candidate.protocol_type,
                            candidate.source_type,
                            candidate.source_ref
                        )),
                        true,
                    ) {
                        eprintln!("[aikey] warning: bind audit row not written: {}", err);
                    }
                }
                // Traceability (2026-07-06): automatic binding writes must
                // leave a structured event (see auto_assign counterpart).
                crate::observability::log_event(
                    crate::observability::EVENT_CLI_BINDING_RECONCILED,
                    &format!(
                        "reconcile promoted {} ({}) as primary for {} via provider {} after removal of {} ({})",
                        candidate.source_ref,
                        candidate.source_type,
                        removed.client_route,
                        candidate.provider_code,
                        key_source_ref,
                        key_source_type
                    ),
                );
                actions.push(ReconcileAction {
                    provider_code: removed.client_route.clone(),
                    outcome: ReconcileOutcome::Replaced {
                        new_source_type: candidate.source_type,
                        new_source_ref: candidate.source_ref,
                    },
                });
            }
            None => {
                actions.push(ReconcileAction {
                    provider_code: removed.client_route.clone(),
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
    // 🔴 SUPPLIER axis, not the client route (bugfix 2026-08-20). The proxy
    // matches this list against the provider code it derives from the request
    // path, so a route name here only matched by accident of the registry
    // alias `kimi → kimi_code`. A moonshot key bound to the kimi route wrote
    // "kimi", canonicalised to "kimi_code", and every `/moonshot/v1` request
    // came back NO_ACTIVE_KEY while `/kimi/v1` on the SAME key worked.
    let all_providers: Vec<String> = bindings.iter().map(|b| b.provider_code.clone()).collect();

    storage::set_active_key_config(&storage::ActiveKeyConfig {
        key_type: first.key_source_type.clone(),
        key_ref: first.key_source_ref.clone(),
        providers: all_providers,
    })?;
    Ok(())
}

/// Resolve the effective wire protocol for one active Provider binding.
///
/// Team VKs carry an explicit protocol in the local binding-granular cache.
/// Personal/OAuth entries are resolved from their stored endpoint through the
/// canonical fingerprint. The stored protocol is authoritative; the fallback
/// exists only for pre-two-axis rows.
pub fn resolve_binding_protocol(binding: &ProviderBinding) -> String {
    if !binding.protocol_type.is_empty() {
        return binding.protocol_type.clone();
    }
    use crate::credential_type::CredentialType;
    let classifier = crate::commands_internal::parse::provider_fingerprint::instance();
    let via_base_url = |base_url: &str, fallback: &str| -> Option<String> {
        classifier
            .route_for_base_url(base_url)
            .map(|route| route.protocol.clone())
            .filter(|protocol| !protocol.is_empty())
            .or_else(|| (!fallback.is_empty()).then(|| fallback.to_string()))
    };

    let resolved = match binding.key_source_type {
        CredentialType::ManagedVirtualKey => {
            storage::list_virtual_key_cache_bindings(&binding.key_source_ref)
                .ok()
                .and_then(|rows| {
                    let mut candidates = rows
                        .into_iter()
                        .filter(|vk| {
                            binding.provider_code.is_empty()
                                || vk
                                    .provider_code
                                    .eq_ignore_ascii_case(&binding.provider_code)
                                || (vk.provider_code.is_empty()
                                    && vk.supported_providers.iter().any(|provider| {
                                        provider.eq_ignore_ascii_case(&binding.provider_code)
                                    }))
                        })
                        .filter_map(|vk| via_base_url(&vk.base_url, &vk.protocol_type));
                    let first = candidates.next()?;
                    candidates
                        .all(|protocol| protocol == first)
                        .then_some(first)
                })
        }
        _ => storage::get_entry_base_url(&binding.key_source_ref)
            .ok()
            .flatten()
            .and_then(|url| via_base_url(&url, "")),
    };

    resolved.unwrap_or_else(|| {
        let protocols = classifier.protocols_for_provider(&binding.provider_code);
        if protocols.len() == 1 {
            protocols[0].clone()
        } else {
            "unknown".to_string()
        }
    })
}

/// Builds the sentinel token that the proxy expects in env vars for the
/// "follow active binding" routing semantic.
///
/// The token is per-client-route (e.g. `aikey_active_anthropic`) — independent of
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
fn sentinel_token(client_route: &str) -> String {
    format!("aikey_active_{}", client_route)
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
fn write_active_env_file(lines: &[String], flat_pairs: &[(String, String)]) -> Result<(), String> {
    // Use resolve_aikey_dir for consistent HOME → USERPROFILE → "." fallback.
    let aikey_dir = crate::commands_account::resolve_aikey_dir();
    write_active_env_file_at(&aikey_dir, lines, flat_pairs)
}

/// Testable core: write active.env / active.env.flat into an explicit dir so
/// tests don't need to override HOME (which would race with parallel cargo
/// test threads — same pattern as apply_claude_json_approvals_at).
fn write_active_env_file_at(
    aikey_dir: &std::path::Path,
    lines: &[String],
    flat_pairs: &[(String, String)],
) -> Result<(), String> {
    std::fs::create_dir_all(aikey_dir).map_err(|e| format!("Failed to create ~/.aikey: {}", e))?;
    // Re-assert owner-only on the directory. Vault init already hardens it to
    // 0700, but this write path can also create ~/.aikey before vault init in
    // some orderings; don't depend on that implicit invariant. Best-effort
    // (a hardening failure must not block activation) — see the file-level
    // hardening below for why these files must not be world-readable.
    let _ = crate::storage_acl::enforce_owner_only_dir(aikey_dir);
    let env_path = aikey_dir.join("active.env");

    let content = lines.join("\n") + "\n";

    // v3 architecture: active.env contains only env vars (no source statements).
    // Wrapper functions live in ~/.aikey/hook.{zsh,bash}, loaded once from shell rc.

    atomic_write(&env_path, content.as_bytes())
        .map_err(|e| format!("Failed to write active.env: {}", e))?;
    // active.env may carry a cluster node's real token (cluster routing); harden
    // to 0600 / owner-only ACL. Mirrors session.rs / synapse.rs / WAL.
    let _ = crate::storage_acl::enforce_owner_only_file(&env_path);

    // Also write active.env.flat (plain KEY=VALUE, no shell syntax) for Windows.
    // PowerShell/cmd deactivate reads this file instead of parsing sh-style active.env.
    //
    // Rendered from the structured (key, raw-value) pairs — NOT by reverse-
    // parsing the sh `export` lines. Reverse-parsing was both fragile and unsafe:
    // once sh values are single-quoted for injection-safety, stripping `"` would
    // produce wrong values, and a value with embedded `=` / quotes could not be
    // recovered. The structured source is authoritative; shell-only lines
    // (no_proxy case/esac, unset) have no flat representation by construction.
    let flat_path = aikey_dir.join("active.env.flat");
    let flat_lines: Vec<String> = flat_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
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
                "{}",
                format!(
                    "[aikey] warn: failed to update {}: {} \
                     (Windows deactivate may restore stale env)",
                    flat_path.display(),
                    e,
                )
                .yellow()
            );
        } else {
            // Same owner-only hardening as active.env (carries the same values).
            let _ = crate::storage_acl::enforce_owner_only_file(&flat_path);
        }
    }

    Ok(())
}

/// Sync `~/.claude.json`'s `customApiKeyResponses.approved` array with the
/// last-20 chars of every aikey-managed Anthropic sentinel token currently
/// in `active.env`.
///
/// Why this exists: claude code v2.1.x interactive mode requires the
/// ANTHROPIC_API_KEY in env to be pre-approved (entry in this array)
/// before it will use it; otherwise it falls through to a fresh OAuth
/// login flow even though the key is valid. Anthropic closed the
/// upstream issues (#27900 / #9699 / #25069) as "not planned", so we
/// pre-approve at activation time. Mac users historically don't see the
/// bug only because they completed an interactive approval at some point;
/// this writeback makes the experience uniform across Mac / Windows /
/// Linux without depending on user history.
///
/// Why merge-safe (read-modify-write, never overwrite): `~/.claude.json`
/// is also written by claude code itself (themes, recent sessions, MCP
/// servers, etc). A naive overwrite would destroy unrelated user state.
///
/// Why goes through `atomic_write` (5×retry budget): on Windows, claude
/// code may have an open handle on `~/.claude.json` while we try to
/// rewrite — same sharing-violation class as the
/// 2026-04-29-aikey-hook-update-eacces-and-sudo-silent-failure bug.
fn write_claude_json_approvals(tokens: &[String]) -> Result<(), String> {
    // Approve the token Claude will actually receive from the anthropic client
    // route, independent of which Provider implements that binding.
    let mut tails: Vec<String> = Vec::new();
    for token in tokens {
        let tail = last_n_chars(token, 20);
        if !tails.contains(&tail) {
            tails.push(tail);
        }
    }
    if tails.is_empty() {
        // No anthropic binding → nothing to approve. Don't read or write
        // ~/.claude.json — preserves mtime, avoids touching unrelated state.
        return Ok(());
    }

    let claude_json_path = crate::commands_account::resolve_user_home().join(".claude.json");
    apply_claude_json_approvals_at(&claude_json_path, &tails)
}

/// Take the last `n` characters of a UTF-8 string. Char-aware (not byte-aware)
/// to match how claude code's JS implementation slices `string.slice(-20)`.
/// For ASCII-only sentinel tokens (current schema), char count == byte count,
/// but kept char-aware in case future provider sentinels grow non-ASCII.
fn last_n_chars(s: &str, n: usize) -> String {
    let total = s.chars().count();
    let skip = total.saturating_sub(n);
    s.chars().skip(skip).collect()
}

/// Testable core: take an explicit path so tests don't need to override HOME
/// (which would race with parallel cargo test threads).
fn apply_claude_json_approvals_at(
    claude_json_path: &std::path::Path,
    tails: &[String],
) -> Result<(), String> {
    use serde_json::Value;

    if tails.is_empty() {
        return Ok(());
    }

    // Read existing config; treat missing as empty object. Treat malformed
    // JSON as a soft skip — overwriting could destroy user state in a way
    // we cannot recover; degrading to "this approval did not stick" is
    // strictly better than that.
    let mut config: Value = match std::fs::read_to_string(claude_json_path) {
        Ok(s) if !s.trim().is_empty() => match serde_json::from_str::<Value>(&s) {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "{}",
                    format!(
                        "[aikey] warn: {} is not valid JSON; skipping \
                         customApiKeyResponses update (will retry on next aikey use)",
                        claude_json_path.display(),
                    )
                    .yellow()
                );
                return Ok(());
            }
        },
        _ => Value::Object(serde_json::Map::new()),
    };
    if !config.is_object() {
        // Top-level is something other than an object (array, string, ...).
        // Same conservative posture as malformed JSON: don't clobber.
        eprintln!(
            "{}",
            format!(
                "[aikey] warn: {} top-level is not a JSON object; \
                 skipping customApiKeyResponses update",
                claude_json_path.display(),
            )
            .yellow()
        );
        return Ok(());
    }

    // Ensure customApiKeyResponses sub-object exists with an "approved" array
    // and a "rejected" array. Use entry().or_insert_with() so existing
    // user/claude-code state under either field is preserved.
    let cfg_obj = config.as_object_mut().expect("checked is_object above");
    let cak = cfg_obj
        .entry("customApiKeyResponses".to_string())
        .or_insert_with(|| {
            serde_json::json!({
                "approved": [],
                "rejected": [],
            })
        });
    if !cak.is_object() {
        // Existing field is the wrong shape — replace with a fresh object.
        // This is the one place we overwrite, justified because the field
        // we own is unusable in its current form.
        *cak = serde_json::json!({"approved": [], "rejected": []});
    }
    let cak_obj = cak.as_object_mut().expect("just-ensured object");

    let approved = cak_obj
        .entry("approved".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !approved.is_array() {
        *approved = Value::Array(Vec::new());
    }
    let approved_arr = approved.as_array_mut().expect("just-ensured array");

    // Idempotent append. If every tail is already present, do not write
    // (preserves mtime, avoids invalidating any reader's cache).
    let mut changed = false;
    for tail in tails {
        let v = Value::String(tail.clone());
        if !approved_arr.iter().any(|existing| existing == &v) {
            approved_arr.push(v);
            changed = true;
        }
    }
    if !changed {
        return Ok(());
    }

    let serialized = serde_json::to_vec_pretty(&config)
        .map_err(|e| format!("serialize ~/.claude.json: {}", e))?;

    // Ensure parent dir exists (~/.claude/ is created by `claude` itself,
    // but if the user has not run claude at all yet it may be absent).
    if let Some(parent) = claude_json_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create_dir_all {}: {}", parent.display(), e))?;
    }

    atomic_write(claude_json_path, &serialized)
        .map_err(|e| format!("atomic_write ~/.claude.json: {}", e))?;
    Ok(())
}

/// Atomic file replace via temp+rename. Caller-provided directory must exist.
/// On error the temp file is best-effort cleaned up.
///
/// `pub(crate)` so other modules that write into `~/.aikey/` (notably
/// `commands_account::shell_integration::write_hook_file`) can share the
/// Windows transient-rename retry budget — without it, EACCES from a
/// concurrent file-open in another shell would surface as an unrecoverable
/// hard error on the very first attempt. See bugfix doc
/// `2026-04-29-aikey-hook-update-eacces-and-sudo-silent-failure.md`.
pub(crate) fn atomic_write(target: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent dir")
    })?;
    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("active");
    // Per-pid suffix avoids collisions if two `aikey` processes refresh
    // concurrently. Last writer wins on rename — that's the seq's job to
    // record the order, the file content is a snapshot either way.
    let temp_path = parent.join(format!("{}.tmp.{}", file_name, std::process::id()));
    if let Err(e) = std::fs::write(&temp_path, content) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    // On Windows, MoveFileEx (which std::fs::rename compiles to) can fail
    // with ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32) when
    // another process holds the target open without FILE_SHARE_DELETE.
    // Known transient holders we cannot eliminate from the writer side:
    //   1. Antivirus / Windows Defender on-access scan after temp write.
    //   2. Windows Search indexer briefly opening the file.
    //   3. Other shells whose hooks were authored before the 2026-04-29
    //      hook.ps1 ReadAllLines fix and still leak StreamReader handles.
    //
    // Retry budget: 5 attempts over ~310ms total. Bounded so a genuinely
    // persistent failure (revoked ACL, disk full mid-rename) returns
    // promptly. Non-transient errors fail-fast on the first attempt.
    // POSIX rename(2) is atomic and never returns EACCES for "another
    // process has it open" — `is_transient_rename_error` returns false
    // off-Windows, collapsing this to a single attempt.
    let backoffs_ms = [0u64, 10, 30, 70, 150];
    let mut last_err: std::io::Error =
        std::io::Error::new(std::io::ErrorKind::Other, "rename retry budget exhausted");
    for &delay_ms in &backoffs_ms {
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        match std::fs::rename(&temp_path, target) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if !is_transient_rename_error(&e) {
                    let _ = std::fs::remove_file(&temp_path);
                    return Err(e);
                }
                last_err = e;
            }
        }
    }
    let _ = std::fs::remove_file(&temp_path);
    Err(last_err)
}

/// Returns true when the rename error is the kind that's typically
/// transient on Windows — another process has the target open briefly
/// without FILE_SHARE_DELETE — and a backoff retry is worth the wait.
///
/// On POSIX this always returns false: rename(2) is atomic and the
/// "target held open" condition does not surface as EACCES, so
/// `atomic_write` collapses to a single attempt off-Windows.
/// Public to crate so call sites that re-do their own retry loop (or
/// classify the error in user-facing text) can reuse the canonical list
/// of "OS errors that mean another process briefly held the target".
#[cfg(windows)]
pub(crate) fn is_transient_rename_error(e: &std::io::Error) -> bool {
    // ERROR_ACCESS_DENIED       = 5
    // ERROR_SHARING_VIOLATION   = 32
    matches!(e.raw_os_error(), Some(5) | Some(32))
}

#[cfg(not(windows))]
pub(crate) fn is_transient_rename_error(_: &std::io::Error) -> bool {
    false
}

/// True iff the current process is running with Administrator-elevated
/// token on Windows. False everywhere else.
///
/// Why we care: on Windows, the native `sudo` shim defaults to
/// `forceNewWindow` mode which spawns the elevated process in a separate
/// console that closes immediately on exit — so any error our binary
/// prints is invisible to the caller. If the user runs `sudo aikey hook
/// update` and it fails (e.g., because another non-elevated PowerShell
/// session is holding hook.ps1 open), the error window flashes and the
/// user sees nothing. We use this helper at command entry to print an
/// upfront warning explaining that elevation cannot fix the actual
/// failure mode (sharing-violation by an unrelated user-mode process is
/// orthogonal to elevation), redirecting them to the right action:
/// close the other shells, then re-run unelevated.
///
/// Implementation: opens the current process token with TOKEN_QUERY,
/// queries TokenElevation. Returns false on any error path so the
/// non-elevated default never blocks legitimate use. Closes the handle
/// on every exit.
///
/// Cost: one syscall pair per call. We call this once per `aikey hook
/// update` invocation.
#[cfg(windows)]
pub(crate) fn is_running_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY:
    //   - GetCurrentProcess returns a pseudo-handle that does not need closing.
    //   - We zero TOKEN_ELEVATION before passing a pointer to it.
    //   - On non-zero return from OpenProcessToken we always CloseHandle.
    //   - On any failure path (Open*, GetTokenInformation) we return false.
    // windows-sys 0.52: HANDLE is `isize` (a numeric handle), not `*mut c_void`.
    // The "null" sentinel for a not-yet-acquired handle is therefore 0_isize,
    // not std::ptr::null_mut().
    unsafe {
        let mut token_handle: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut return_length: u32 = 0;
        let ok = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );
        CloseHandle(token_handle);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub(crate) fn is_running_elevated() -> bool {
    false
}

/// Searches for a replacement key that supports the given provider.
/// Returns the first usable candidate as `(key_source_type, key_source_ref)`.
///
/// Strategy: oldest personal key first, then oldest team key.
/// The removed key (`excluded_type`/`excluded_ref`) is skipped.
struct ReplacementCandidate {
    source_type: String,
    source_ref: String,
    provider_code: String,
    protocol_type: String,
}

fn find_replacement_candidate(
    client_route: &str,
    excluded_type: &str,
    excluded_ref: &str,
) -> Result<Option<ReplacementCandidate>, String> {
    // Search personal keys, sorted by created_at (oldest first) for
    // deterministic "earliest added" backfill order.
    let mut entries = storage::list_entries_with_metadata().unwrap_or_default();
    entries.sort_by_key(|e| e.created_at.unwrap_or(i64::MAX));
    for entry in &entries {
        if entry.alias == excluded_ref && excluded_type == "personal" {
            continue;
        }
        if let Ok((provider_code, protocol_type)) =
            crate::commands_account::binding_spec_for_client_route(
                client_route,
                "personal",
                &entry.alias,
            )
        {
            return Ok(Some(ReplacementCandidate {
                source_type: "personal".to_string(),
                source_ref: entry.alias.clone(),
                provider_code,
                protocol_type,
            }));
        }
    }

    // Search team keys.
    let vk_entries = storage::list_virtual_key_cache().unwrap_or_default();
    // Material guard (2026-07-06): same predicate as the picker / web set-route /
    // auto_assign — a replacement Primary must be servable by the proxy NOW.
    // Promoting a material-unreachable VK here recreates the display-split
    // incident (web "IN USE" vs picker hides it vs proxy 503).
    let on_cluster = crate::commands_account::read_cluster_node().is_some();
    for vk in &vk_entries {
        if vk.virtual_key_id == excluded_ref && excluded_type == "team" {
            continue;
        }
        // Only consider usable team keys. Same three conditions as before,
        // now expressed by the shared `is_servable` (2026-08-31): keeping them
        // inline here is how a fourth, wrong copy got written elsewhere.
        if !vk.is_servable(on_cluster) {
            continue;
        }
        if let Ok((provider_code, protocol_type)) =
            crate::commands_account::binding_spec_for_client_route(
                client_route,
                "team",
                &vk.virtual_key_id,
            )
        {
            return Ok(Some(ReplacementCandidate {
                source_type: "team".to_string(),
                source_ref: vk.virtual_key_id.clone(),
                provider_code,
                protocol_type,
            }));
        }
    }

    Ok(None)
}

// ============================================================================
// reconcile_baseurl_port — port-drift self-healing guard
// ============================================================================

/// What `reconcile_baseurl_port` did — surfaced for seams' logging and tests.
#[derive(Debug, PartialEq, Eq)]
pub enum PortReconcileOutcome {
    /// No live proxy (runtime.json absent / pid dead) — nothing to compare
    /// against; intent-level ports (yaml/env) are deliberately NOT used so a
    /// stopped proxy never triggers speculative config rewrites.
    NoLiveProxy,
    /// No downstream surface carries a local (127.0.0.1) baseurl — either no
    /// bindings yet or all routes point at cluster nodes. Nothing to heal.
    NoSentinel,
    /// Downstream configs already point at the live proxy's actual port.
    InSync { port: u16 },
    /// Drift detected and the full rewrite funnel ran (active.env + seq bump
    /// + codex/kimi/statusline/Desktop via the third-party funnel).
    Healed { from: u16, to: u16 },
    /// Guard could not complete (vault DB unreadable, write failure, …).
    /// Callers must treat this as advisory — never block the main flow.
    Failed(String),
}

/// Idempotent reconcile: live proxy actual port vs the baseurl port already
/// written into downstream configs; rewrite everything through the existing
/// activation funnel when they disagree.
///
/// Why (20260728-端口漂移baseurl自愈回写): port drift (27200 busy → bind
/// 27201..+10) updates `proxy-runtime.json`, and every *runtime* CLI port
/// lookup follows it — but configs already ON DISK (active.env, codex toml,
/// Desktop profile) kept the old port with no write-back mechanism, so
/// claude/codex silently hit a dead port while `aikey doctor` stayed green
/// (real incident: bugfix 2026-07-17 agent-daemon port-drift pollution).
/// This guard is mounted on consumption paths (`ensure_proxy_for_use`) and
/// start paths (foreground service start), per the "event-driven writes need
/// an idempotent reconcile read" invariant: launchd can start a drifted proxy
/// with no CLI in the loop, so a pure event hook would miss it.
///
/// Staleness is judged across ALL local surfaces (`written_local_baseurl_ports`),
/// not just active.env: openai routes deliberately skip the OPENAI_BASE_URL
/// env export (Codex v0.118+ reads `~/.codex/config.toml` instead), so an
/// openai-only user's ONLY port-carrying surface is the codex toml.
/// Cluster-node URLs (non-127.0.0.1) are never compared — drift must not
/// rewrite cluster direct-bind routes.
pub fn reconcile_baseurl_port() -> PortReconcileOutcome {
    // 1. Live actual port only (pid-verified runtime.json).
    let Some(actual_addr) = commands_proxy::read_runtime_actual_addr() else {
        return PortReconcileOutcome::NoLiveProxy;
    };
    let Some(actual_port) = actual_addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
    else {
        return PortReconcileOutcome::Failed(format!(
            "runtime actual_addr has no parsable port: {actual_addr}"
        ));
    };

    // 2. Ports already written to downstream surfaces; any local mismatch
    // triggers the full funnel rewrite (all surfaces re-anchor together).
    let surfaces = written_local_baseurl_ports();
    let Some(written_port) = surfaces
        .iter()
        .find_map(|(_, p)| p.filter(|p| *p != actual_port))
    else {
        return if surfaces.iter().any(|(_, p)| p.is_some()) {
            PortReconcileOutcome::InSync { port: actual_port }
        } else {
            PortReconcileOutcome::NoSentinel
        };
    };

    // 3. Drift → rewrite through the single existing funnel (never a
    // parallel write path). refresh bumps AIKEY_ACTIVE_SEQ, so already-open
    // terminals re-source active.env at their next prompt via the hook.
    eprintln!(
        "[aikey] proxy port changed ({} -> {}) — refreshing baseurl configs \
         (active.env / codex / desktop); open terminals update at next prompt",
        written_port, actual_port
    );
    match refresh_implicit_profile_activation() {
        Ok(refresh) => {
            let active_providers: Vec<String> = refresh
                .bindings
                .iter()
                .map(|b| b.client_route.clone())
                .collect();
            // interactive=false: heal only what is already ours — a drift
            // reconcile must never pop the Desktop takeover consent prompt
            // mid `claude` launch (see apply_third_party_cli_configs_with).
            let _ = crate::commands_account::apply_third_party_cli_configs_with(
                &active_providers,
                actual_port,
                false,
            );
            PortReconcileOutcome::Healed {
                from: written_port,
                to: actual_port,
            }
        }
        Err(e) => {
            // Advisory by design: a failed heal must not block the launch
            // that triggered it (main-flow robustness > side repair).
            eprintln!("[aikey] warning: baseurl refresh failed: {e}");
            PortReconcileOutcome::Failed(e)
        }
    }
}

/// `(surface label, locally-written port)` for every downstream config that
/// can carry a local-proxy baseurl. `None` = surface absent / not ours /
/// pointing at a non-loopback (cluster) host — healthy, never stale.
///
/// Shared by the reconcile guard above and `aikey doctor`'s `baseurl sync`
/// row so both apply identical staleness rules (single source of truth).
pub(crate) fn written_local_baseurl_ports() -> [(&'static str, Option<u16>); 3] {
    let active_env_port =
        std::fs::read_to_string(crate::commands_account::resolve_aikey_dir().join("active.env"))
            .ok()
            .and_then(|t| parse_local_baseurl_port(&t));
    [
        ("active.env", active_env_port),
        ("codex", crate::commands_account::codex_local_baseurl_port()),
        (
            "desktop",
            crate::commands_account::claude_desktop::profile_local_baseurl_port(),
        ),
    ]
}

/// Pure core: first local-proxy port written in an active.env body.
///
/// Only generated `export *_BASE_URL='http://127.0.0.1:<port>/...'` lines
/// count; `unset` lines and cluster-node URLs (non-loopback hosts) are
/// skipped. Separated from IO for direct unit testing.
pub(crate) fn parse_local_baseurl_port(active_env: &str) -> Option<u16> {
    for line in active_env.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("export ") else {
            continue;
        };
        let Some((var, value)) = rest.split_once('=') else {
            continue;
        };
        if !var.ends_with("_BASE_URL") {
            continue;
        }
        if let Some(p) = local_url_port(value) {
            return Some(p);
        }
    }
    None
}

/// Port of a loopback (`127.0.0.1`) URL embedded anywhere in `text`;
/// None for non-local hosts. Shared by the active.env sentinel parse and
/// the doctor's codex/Desktop stale-port checks so all surfaces apply the
/// same "local URLs only — never compare cluster routes" rule.
pub(crate) fn local_url_port(text: &str) -> Option<u16> {
    let idx = text.find("://127.0.0.1:")?;
    let digits: String = text[idx + "://127.0.0.1:".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u16>().ok()
}

#[cfg(test)]
mod reconcile_baseurl_tests {
    //! Pins the sentinel-parse contract of the drift self-heal guard
    //! (20260728-端口漂移baseurl自愈回写): local base_url wins, cluster
    //! URLs and unset lines never do. The IO/funnel halves are covered by
    //! the e2e case (占用 27200 → drift → assert rewrite).

    use super::parse_local_baseurl_port;

    #[test]
    fn picks_first_local_baseurl_port() {
        let env = "# aikey active key — auto-generated\n\
                   export AIKEY_ACTIVE_SEQ=\"42\"\n\
                   export ANTHROPIC_BASE_URL='http://127.0.0.1:27201/anthropic'\n\
                   export OPENAI_BASE_URL='http://127.0.0.1:27201/openai'\n";
        assert_eq!(parse_local_baseurl_port(env), Some(27201));
    }

    #[test]
    fn skips_cluster_urls_and_unset_lines() {
        let env = "unset KIMI_BASE_URL 2>/dev/null\n\
                   export OPENAI_BASE_URL='http://10.1.2.3:8080/openai'\n";
        assert_eq!(parse_local_baseurl_port(env), None);
    }

    #[test]
    fn cluster_route_then_local_route_uses_local() {
        // Mixed set: openai direct-bound to a cluster node, anthropic on the
        // local proxy — the local line is the sentinel.
        let env = "export OPENAI_BASE_URL='http://10.1.2.3:8080/openai'\n\
                   export ANTHROPIC_BASE_URL='http://127.0.0.1:27203/anthropic'\n";
        assert_eq!(parse_local_baseurl_port(env), Some(27203));
    }

    #[test]
    fn no_baseurl_lines_yields_none() {
        let env =
            "export AIKEY_ACTIVE_SEQ=\"7\"\nexport ANTHROPIC_API_KEY='aikey_active_anthropic'\n";
        assert_eq!(parse_local_baseurl_port(env), None);
    }
}

#[cfg(test)]
mod unset_inactive_tests {
    //! Regression coverage for the source-only-export gap (2026-05-07):
    //! before this fix, deleting a provider from active bindings left the
    //! shell with stale per-provider env vars (KIMI_API_KEY etc.) until a
    //! new terminal was opened. The unset-line emitter makes active.env
    //! self-cleaning under `source`.
    //!
    //! Tests target the pure helper `append_unset_lines_for_inactive_providers`
    //! so they run without a real vault DB.
    use super::*;

    #[test]
    fn legacy_mock_projection_is_explicitly_unset() {
        let mut lines = Vec::new();
        append_unset_lines_for_legacy_projections(&mut lines);
        let blob = lines.join("\n");
        for var in LEGACY_PROJECTION_ENV_VARS {
            assert!(
                blob.contains(&format!("unset {} 2>/dev/null", var)),
                "expected legacy projection {var} to be unset, got:\n{blob}"
            );
        }
    }

    #[test]
    fn unset_emitted_for_kimi_when_only_anthropic_active() {
        let mut lines: Vec<String> = Vec::new();
        let mut exported = HashSet::new();
        // Simulate "anthropic active": only ANTHROPIC_* exported.
        exported.insert("ANTHROPIC_API_KEY".to_string());
        exported.insert("ANTHROPIC_BASE_URL".to_string());

        append_unset_lines_for_inactive_providers(&mut lines, &exported);
        let blob = lines.join("\n");

        // Each registry-known non-anthropic api_key var must have an unset line.
        // 2026-05-08 Kimi family 互斥落地: moonshot 改写 KIMI_* (与 kimi_code 一致),
        // MOONSHOT_API_KEY/MOONSHOT_BASE_URL 不再出现在 registry env_api_key/env_base_url
        // 字段里,故从此处 assertion 移除 — registry-driven unset 自然不会包含它们。
        for var in ["KIMI_API_KEY", "KIMI_BASE_URL", "OPENAI_API_KEY"] {
            assert!(
                blob.contains(&format!("unset {} 2>/dev/null", var)),
                "expected `unset {}` line, got:\n{}",
                var,
                blob,
            );
        }

        // Active ones must NOT be unset.
        assert!(
            !blob.contains("unset ANTHROPIC_API_KEY"),
            "ANTHROPIC_API_KEY was exported, should not be unset"
        );
        assert!(
            !blob.contains("unset ANTHROPIC_BASE_URL"),
            "ANTHROPIC_BASE_URL was exported, should not be unset"
        );
    }

    #[test]
    fn unset_emitted_for_anthropic_when_only_kimi_active() {
        let mut lines: Vec<String> = Vec::new();
        let mut exported = HashSet::new();
        exported.insert("KIMI_API_KEY".to_string());
        exported.insert("KIMI_BASE_URL".to_string());
        exported.insert("KIMI_MODEL_NAME".to_string());

        append_unset_lines_for_inactive_providers(&mut lines, &exported);
        let blob = lines.join("\n");

        for var in ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "OPENAI_API_KEY"] {
            assert!(
                blob.contains(&format!("unset {} 2>/dev/null", var)),
                "expected `unset {}`, got:\n{}",
                var,
                blob,
            );
        }

        // Kimi extras that we exported should NOT be unset.
        assert!(!blob.contains("unset KIMI_API_KEY"));
        assert!(!blob.contains("unset KIMI_MODEL_NAME"));
    }

    #[test]
    fn unset_emitted_for_all_when_no_provider_active() {
        let mut lines: Vec<String> = Vec::new();
        let exported = HashSet::new(); // nothing exported

        append_unset_lines_for_inactive_providers(&mut lines, &exported);
        let blob = lines.join("\n");

        // Sanity: every registry entry's api_key_var must show up.
        for entry in crate::provider_registry::entries() {
            let (api_key_var, _) = entry.env_vars;
            if api_key_var.is_empty() {
                continue;
            }
            assert!(
                blob.contains(&format!("unset {} 2>/dev/null", api_key_var)),
                "missing `unset {}` for empty-active state, got:\n{}",
                api_key_var,
                blob,
            );
        }
    }

    #[test]
    fn no_unset_when_all_active() {
        // Synthetic: every registry api_key + base_url is in the exported set.
        let mut lines: Vec<String> = Vec::new();
        let mut exported = HashSet::new();
        for entry in crate::provider_registry::entries() {
            let (api, base) = entry.env_vars;
            if !api.is_empty() {
                exported.insert(api.to_string());
            }
            if !base.is_empty() {
                exported.insert(base.to_string());
            }
            for (extra_var, _) in entry.extra_env_vars {
                exported.insert(extra_var.to_string());
            }
        }
        append_unset_lines_for_inactive_providers(&mut lines, &exported);
        assert!(
            lines.is_empty(),
            "no unsets expected when everything is active, got:\n{}",
            lines.join("\n")
        );
    }
}

#[cfg(test)]
mod atomic_write_tests {
    use super::atomic_write;

    // Stage 4 (active-state cross-shell sync, 2026-04-27):
    // active.env is now written via temp+rename so a shell that's mid-source
    // never reads a partially-written file. These tests pin the contract.

    #[test]
    fn atomic_write_creates_target_with_content() {
        let dir =
            std::env::temp_dir().join(format!("aikey-atomic-test-create-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env");
        atomic_write(&target, b"hello\n").expect("write");
        assert_eq!(std::fs::read(&target).unwrap(), b"hello\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_replaces_existing_content() {
        let dir =
            std::env::temp_dir().join(format!("aikey-atomic-test-replace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env");
        std::fs::write(&target, b"old content\n").unwrap();
        atomic_write(&target, b"new content\n").expect("replace");
        assert_eq!(std::fs::read(&target).unwrap(), b"new content\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 2026-04-29 active.env.flat rename access-denied on Windows ──────────

    /// Pin the predicate that decides which rename errors trigger retry.
    /// On Windows, ERROR_ACCESS_DENIED (5) and ERROR_SHARING_VIOLATION (32)
    /// surface when another process holds the target file open without
    /// FILE_SHARE_DELETE — typical of antivirus / Search indexer / a leaked
    /// PowerShell StreamReader handle. Other errors must fail-fast (we don't
    /// want to wait 310ms for a permission-denied that won't ever clear).
    #[cfg(windows)]
    #[test]
    fn is_transient_rename_error_classifies_windows_sharing_codes() {
        let access_denied = std::io::Error::from_raw_os_error(5);
        let sharing_violation = std::io::Error::from_raw_os_error(32);
        let path_not_found = std::io::Error::from_raw_os_error(3);
        let disk_full = std::io::Error::from_raw_os_error(112);
        assert!(is_transient_rename_error(&access_denied));
        assert!(is_transient_rename_error(&sharing_violation));
        assert!(!is_transient_rename_error(&path_not_found));
        assert!(!is_transient_rename_error(&disk_full));
    }

    /// The full-stack regression: simulate the 2026-04-29 cascade where the
    /// PowerShell hook leaked a StreamReader handle on `active.env.flat`,
    /// then the next `aikey use` failed to atomic-rename over it. The hook
    /// is fixed in templates/hook.ps1 (ReadAllLines), but defense-in-depth
    /// retry in atomic_write must still let the writer succeed when an
    /// uncontrolled holder (antivirus, Search indexer) briefly grabs the
    /// file.
    ///
    /// Test setup: open the target with FILE_SHARE_READ | FILE_SHARE_WRITE
    /// (no FILE_SHARE_DELETE) — the same restrictive sharing PowerShell's
    /// StreamReader uses — then drop the handle after 50ms. atomic_write
    /// has a 310ms retry budget, so it must recover.
    #[cfg(windows)]
    #[test]
    fn atomic_write_retries_through_transient_sharing_violation() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir =
            std::env::temp_dir().join(format!("aikey-atomic-test-retry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env.flat");
        std::fs::write(&target, b"AIKEY_ACTIVE_SEQ=1\nold=value\n").unwrap();

        // FILE_SHARE_READ (1) | FILE_SHARE_WRITE (2) — NO FILE_SHARE_DELETE (4).
        // Mirrors the share mode PowerShell's [System.IO.File]::ReadLines
        // uses, which is the real-world holder we saw in the field.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001 | 0x0000_0002)
            .open(&target)
            .expect("open holder");

        let release_after = std::time::Duration::from_millis(50);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(release_after);
            drop(holder);
        });

        let result = atomic_write(&target, b"AIKEY_ACTIVE_SEQ=2\nnew=value\n");
        releaser.join().unwrap();

        assert!(
            result.is_ok(),
            "atomic_write must succeed after the transient holder releases; got {:?}",
            result,
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "AIKEY_ACTIVE_SEQ=2\nnew=value\n",
            "post-retry content must reflect the new write",
        );

        // Cleanup must still run — assert no stale .tmp.<pid> debris from
        // the failed attempts before the holder released.
        let stale_tmps: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            stale_tmps.is_empty(),
            "stale temp file left after successful retry: {:?}",
            stale_tmps.iter().map(|e| e.file_name()).collect::<Vec<_>>(),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bugfix 2026-04-29-aikey-hook-update-eacces-and-sudo-silent-failure:
    /// `is_running_elevated` must NOT panic in the test process and must
    /// return a boolean. We don't assert the value because cargo test can
    /// run from elevated or unelevated parents; the contract is "doesn't
    /// crash, returns a stable bool".
    #[test]
    fn is_running_elevated_is_callable_from_tests() {
        let _ = super::is_running_elevated();
    }

    /// Off-Windows the helper must always return false — no syscall path
    /// to take, and callers rely on this to short-circuit Windows-only
    /// warnings (the elevated-warning at the top of `aikey hook update`).
    #[cfg(not(windows))]
    #[test]
    fn is_running_elevated_is_false_off_windows() {
        assert!(
            !super::is_running_elevated(),
            "non-Windows builds must always report false"
        );
    }

    #[test]
    fn atomic_write_does_not_leave_temp_file_on_success() {
        // The whole point of temp+rename: post-rename, the .tmp.<pid> file
        // must not exist. Otherwise drift detection / cleanup logic that
        // greps the directory could trip over stale temps.
        let dir =
            std::env::temp_dir().join(format!("aikey-atomic-test-cleanup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("active.env");
        atomic_write(&target, b"x\n").expect("write");
        let entries: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
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

#[cfg(test)]
mod claude_json_tests {
    //! Bugfix 2026-04-29-claude-interactive-ignores-anthropic-api-key:
    //! claude code v2.1.x interactive mode rejects ANTHROPIC_API_KEY env
    //! unless `~/.claude.json`'s `customApiKeyResponses.approved` array
    //! already contains the key's last 20 chars. We pre-approve at every
    //! `aikey use` to make the experience uniform across platforms.
    //!
    //! These tests pin the contract on the testable core
    //! `apply_claude_json_approvals_at(&path, &tails)` which takes an
    //! explicit path so we don't override $HOME (which would race with
    //! parallel cargo test threads).
    use super::{apply_claude_json_approvals_at, last_n_chars};
    use serde_json::Value;

    fn fresh_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aikey-claude-json-{}-{}-{}",
            label,
            std::process::id(),
            rand::random::<u64>(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_json(path: &std::path::Path) -> Value {
        let s = std::fs::read_to_string(path).expect("read claude.json");
        serde_json::from_str(&s).expect("parse claude.json")
    }

    fn approved_array(v: &Value) -> Vec<String> {
        v.pointer("/customApiKeyResponses/approved")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn last_n_chars_handles_short_strings() {
        // String shorter than n → return whole string (saturating_sub avoids
        // panic on underflow). Important: claude code's slice(-20) on a
        // 5-char string returns the whole 5-char string, not "" or panic.
        assert_eq!(last_n_chars("abc", 20), "abc");
        assert_eq!(last_n_chars("", 20), "");
        // Exactly n chars → whole string.
        // Fixture is content-irrelevant; we test length math, not token shape —
        // intentionally non-aikey-prefixed to keep prefix-rename-gate clean.
        assert_eq!(
            last_n_chars("abcdefghij0123456789", 20),
            "abcdefghij0123456789"
        );
        // Longer than n → last n.
        let s = "this_is_a_long_fixture_string_more_than_twenty_chars";
        assert_eq!(last_n_chars(s, 20).chars().count(), 20);
        assert!(s.ends_with(&last_n_chars(s, 20)));
    }

    #[test]
    fn creates_when_missing() {
        let dir = fresh_dir("create");
        let path = dir.join(".claude.json");
        assert!(!path.exists(), "precondition: file does not exist");

        apply_claude_json_approvals_at(&path, &["tail-twenty-chars-aaa".to_string()])
            .expect("write");

        let v = read_json(&path);
        assert_eq!(
            approved_array(&v),
            vec!["tail-twenty-chars-aaa".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preserves_unrelated_fields() {
        // Critical: ~/.claude.json is also written by claude code itself.
        // Naive overwrite would destroy themePreference / recentChats / etc.
        let dir = fresh_dir("preserve");
        let path = dir.join(".claude.json");
        let existing = serde_json::json!({
            "themePreference": "dark",
            "userInfo": { "uuid": "abc-123" },
            "mcpServers": { "github": {"command": "gh-mcp"} },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&existing).unwrap()).unwrap();

        apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()])
            .expect("write");

        let v = read_json(&path);
        assert_eq!(v["themePreference"], "dark");
        assert_eq!(v["userInfo"]["uuid"], "abc-123");
        assert_eq!(v["mcpServers"]["github"]["command"], "gh-mcp");
        assert_eq!(approved_array(&v), vec!["xxxxxxxxxxxxxxxxxxx1".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idempotent_no_write_when_already_approved() {
        // When every tail is already in the array, we must NOT write —
        // preserving the file's mtime is important because claude code
        // itself watches this file for self-changes.
        let dir = fresh_dir("idempotent");
        let path = dir.join(".claude.json");
        let initial = serde_json::json!({
            "customApiKeyResponses": {
                "approved": ["xxxxxxxxxxxxxxxxxxx1"],
                "rejected": [],
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&initial).unwrap()).unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Sleep just enough that any rewrite would be observable.
        std::thread::sleep(std::time::Duration::from_millis(20));

        apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()])
            .expect("noop write");

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "idempotent path must not touch the file (rewrite invalidates claude code's cache)",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appends_without_replacing_other_tails() {
        // User's ~/.claude.json may already have approvals for non-aikey
        // keys (e.g. user manually approved an Anthropic console key once).
        // Those entries must survive.
        let dir = fresh_dir("append");
        let path = dir.join(".claude.json");
        let initial = serde_json::json!({
            "customApiKeyResponses": {
                "approved": ["existing-tail-1234567"],
                "rejected": [],
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&initial).unwrap()).unwrap();

        apply_claude_json_approvals_at(&path, &["new-tail-aaaaaaaaaaa".to_string()])
            .expect("append write");

        let v = read_json(&path);
        let approved = approved_array(&v);
        assert!(
            approved.contains(&"existing-tail-1234567".to_string()),
            "existing tail must be preserved, got {:?}",
            approved
        );
        assert!(
            approved.contains(&"new-tail-aaaaaaaaaaa".to_string()),
            "new tail must be appended, got {:?}",
            approved
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_malformed_silently() {
        // Invalid JSON → don't crash, don't overwrite (overwriting could
        // destroy unrelated user state if we misclassified valid JSON as
        // invalid for any reason — much safer to skip).
        let dir = fresh_dir("malformed");
        let path = dir.join(".claude.json");
        std::fs::write(&path, b"{not valid json at all").unwrap();
        let original = std::fs::read(&path).unwrap();

        apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()])
            .expect("must not propagate parse error");

        // File content must be byte-identical.
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "malformed file must not be overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_when_top_level_not_object() {
        // Defensive: handle the (extremely unlikely) case that ~/.claude.json
        // has been replaced with an array or scalar by some other tool.
        // Don't overwrite — same rationale as malformed.
        let dir = fresh_dir("toplevel-array");
        let path = dir.join(".claude.json");
        std::fs::write(&path, b"[]").unwrap();
        let original = std::fs::read(&path).unwrap();

        apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()])
            .expect("must not propagate");

        assert_eq!(std::fs::read(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_tails_is_noop() {
        // No anthropic binding in the activation set → no write at all.
        // This is the kimi-only / openai-only path: we must not even read
        // ~/.claude.json (let alone write to it) when there's nothing for
        // claude code to approve.
        let dir = fresh_dir("empty-tails");
        let path = dir.join(".claude.json");
        // Path explicitly does NOT exist. If function reads/writes anyway
        // the assertion below would fail.

        apply_claude_json_approvals_at(&path, &[]).expect("noop");

        assert!(!path.exists(), "empty-tails must not create the file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replaces_wrong_shape_custom_api_key_responses() {
        // If `customApiKeyResponses` exists but is the wrong type (string,
        // array, ...), we replace it with a fresh object. Only acceptable
        // overwrite path because the existing field is unusable. Note: we
        // are NOT touching other top-level fields, just this one field.
        let dir = fresh_dir("wrong-shape");
        let path = dir.join(".claude.json");
        let initial = serde_json::json!({
            "themePreference": "dark",
            "customApiKeyResponses": "this is the wrong type",
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&initial).unwrap()).unwrap();

        apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()])
            .expect("write");

        let v = read_json(&path);
        assert_eq!(v["themePreference"], "dark", "unrelated field preserved");
        assert_eq!(approved_array(&v), vec!["xxxxxxxxxxxxxxxxxxx1".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creates_parent_dir_if_missing() {
        // ~/.claude.json's parent (the user's home dir) always exists, but
        // make sure we don't crash if the parent is missing — this also
        // catches the case where a sandboxed test passes a deeper path.
        let dir = fresh_dir("nested-parent");
        let nested = dir.join("nonexistent-subdir");
        let path = nested.join(".claude.json");
        assert!(!nested.exists());

        apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()])
            .expect("must create parent dir");

        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bugfix 2026-04-29-aikey-hook-update-eacces-and-sudo-silent-failure
    /// applies here too: claude code may have ~/.claude.json open without
    /// FILE_SHARE_DELETE while we try to atomic-rename. atomic_write's
    /// 5×retry budget must let us ride past that. Mirrors the existing
    /// `atomic_write_retries_through_transient_sharing_violation` test
    /// but exercised through the claude.json writer to prevent a future
    /// regression that bypasses atomic_write here.
    #[cfg(windows)]
    #[test]
    fn recovers_from_transient_sharing_violation() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = fresh_dir("sharing-violation");
        let path = dir.join(".claude.json");
        std::fs::write(&path, b"{}").unwrap();

        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001 | 0x0000_0002) // SHARE_READ | SHARE_WRITE
            .open(&path)
            .expect("open holder");

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(holder);
        });

        let result = apply_claude_json_approvals_at(&path, &["xxxxxxxxxxxxxxxxxxx1".to_string()]);
        releaser.join().unwrap();

        result.expect("write_claude_json_approvals must ride past transient hold");
        let v = read_json(&path);
        assert_eq!(approved_array(&v), vec!["xxxxxxxxxxxxxxxxxxx1".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod active_env_render_tests {
    //! Fence tests for the #1 (active.env shell injection) fix. They pin the
    //! contract on the testable core `write_active_env_file_at(&dir, ...)` so we
    //! exercise the REAL writer (sh single-quoting + structured flat rendering +
    //! owner-only hardening) without overriding $HOME.
    //!
    //! Why this matters (Why): active.env is `source`-d by the zsh/bash prompt
    //! hook on every prompt. A managed-key display alias is synced from the
    //! server and not CLI-controlled; an unescaped `$(...)` in it would execute.
    use super::write_active_env_file_at;
    use crate::shell_quote::active_env_export_line;

    fn fresh_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aikey-active-env-{}-{}-{}",
            label,
            std::process::id(),
            rand::random::<u64>(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn malicious_alias_is_inert_in_sh_and_raw_in_flat() {
        let dir = fresh_dir("inject");
        let payload = "anthropic=$(touch /tmp/aikey_pwn)`id`";
        // Build the env_lines exactly as refresh_implicit_profile_activation does
        // for the AIKEY_ACTIVE_KEYS display line.
        let env_lines = vec![
            active_env_export_line("AIKEY_ACTIVE_SEQ", "7"),
            active_env_export_line("AIKEY_ACTIVE_KEYS", payload),
        ];
        let flat_pairs = vec![
            ("AIKEY_ACTIVE_SEQ".to_string(), "7".to_string()),
            ("AIKEY_ACTIVE_KEYS".to_string(), payload.to_string()),
        ];
        write_active_env_file_at(&dir, &env_lines, &flat_pairs).expect("write");

        let sh = std::fs::read_to_string(dir.join("active.env")).unwrap();
        // The payload must be fully wrapped in single quotes → inert when sourced.
        assert!(
            sh.contains("export AIKEY_ACTIVE_KEYS='anthropic=$(touch /tmp/aikey_pwn)`id`'"),
            "AIKEY_ACTIVE_KEYS must be single-quoted (inert). Got:\n{sh}"
        );
        // No bare command-substitution outside single quotes.
        assert!(
            !sh.contains("=\"anthropic=$("),
            "value must not be double-quoted (would expand $()):\n{sh}"
        );

        // flat carries the RAW value (it is parsed as KEY=VALUE, never eval'd).
        let flat = std::fs::read_to_string(dir.join("active.env.flat")).unwrap();
        assert!(
            flat.contains(&format!("AIKEY_ACTIVE_KEYS={payload}")),
            "flat must carry the raw value with no quote munging. Got:\n{flat}"
        );
        // Exactly the two structured pairs → no reverse-parse artifacts / forged lines.
        let flat_kv: Vec<&str> = flat.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            flat_kv.len(),
            2,
            "flat must have exactly the structured pairs:\n{flat}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seq_line_stays_double_quoted_for_hook_grep() {
        let dir = fresh_dir("seq");
        let env_lines = vec![active_env_export_line("AIKEY_ACTIVE_SEQ", "123")];
        let flat_pairs = vec![("AIKEY_ACTIVE_SEQ".to_string(), "123".to_string())];
        write_active_env_file_at(&dir, &env_lines, &flat_pairs).expect("write");
        let sh = std::fs::read_to_string(dir.join("active.env")).unwrap();
        // hook.zsh/bash grep `AIKEY_ACTIVE_SEQ="[0-9]+"` — must remain double-quoted.
        assert!(
            sh.contains("export AIKEY_ACTIVE_SEQ=\"123\""),
            "SEQ must stay double-quoted for the precmd grep fast-path:\n{sh}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn active_env_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("perm");
        let env_lines = vec![active_env_export_line(
            "ANTHROPIC_API_KEY",
            "aikey_active_anthropic",
        )];
        let flat_pairs = vec![(
            "ANTHROPIC_API_KEY".to_string(),
            "aikey_active_anthropic".to_string(),
        )];
        write_active_env_file_at(&dir, &env_lines, &flat_pairs).expect("write");
        for name in ["active.env", "active.env.flat"] {
            let mode = std::fs::metadata(dir.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name} must be 0600, got {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod default_profile_fence {
    /// 🔴 Every production read of the binding table must go through
    /// DEFAULT_PROFILE, not the literal "default".
    ///
    /// The constant existed while three production call sites wrote the string
    /// themselves. That is not a style issue: the vault page and the desktop
    /// tray read the SAME table through different call paths, so a change to
    /// the default profile would have moved one and left the other behind —
    /// two surfaces quietly showing different bindings, with nothing failing.
    ///
    /// Test files are exempt: a test that pins the literal is asserting what
    /// the default IS, which is the opposite of drifting from it.
    #[test]
    fn production_code_does_not_hardcode_the_default_profile() {
        let roots = [
            "src/commands_internal",
            "src/commands_account",
            "src/commands_proxy.rs",
        ];
        let mut offenders = Vec::new();
        for root in roots {
            collect(std::path::Path::new(root), &mut offenders);
        }
        assert!(
            offenders.is_empty(),
            "these production sites read the binding table with the literal \"default\" \
             instead of profile_activation::DEFAULT_PROFILE: {offenders:?}"
        );
    }

    fn collect(p: &std::path::Path, out: &mut Vec<String>) {
        if p.is_dir() {
            let Ok(entries) = std::fs::read_dir(p) else {
                return;
            };
            for e in entries.flatten() {
                collect(&e.path(), out);
            }
            return;
        }
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            return;
        }
        let Ok(src) = std::fs::read_to_string(p) else {
            return;
        };
        // Strip test modules: their literals are assertions, not drift.
        let scanned = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src[..],
        };
        for (n, line) in scanned.lines().enumerate() {
            if line.contains("list_provider_bindings") && line.contains("\"default\"") {
                out.push(format!("{}:{}", p.display(), n + 1));
            }
        }
    }
}

#[cfg(test)]
mod active_key_axis_tests {
    use super::*;

    /// 🔴 `active_key_providers` is the SUPPLIER axis, not the client route
    /// (bugfix 2026-08-20 NO_ACTIVE_KEY-for-moonshot).
    ///
    /// The two axes are different vocabularies: a `kimi` ROUTE can be served
    /// by the `kimi_code` or the `moonshot` SUPPLIER. Writing the route name
    /// into a field the proxy matches against supplier codes worked only
    /// because the registry aliases `kimi → kimi_code`, so the route name
    /// happened to canonicalise to a real supplier. Bind a moonshot key and
    /// the disguise fails: `/moonshot/v1` gets NO_ACTIVE_KEY while
    /// `/kimi/v1` still works, on the same key.
    ///
    /// Structural because the value only reaches the proxy through SQLite;
    /// this pins the FIELD, which is where the bug lived.
    #[test]
    fn active_providers_are_written_from_the_supplier_axis() {
        // Scan the ASSIGNMENT LINE only — prose in this file (and in the fix's
        // own comment) mentions both axis names, and a whole-file scan matches
        // itself. Same self-reference trap as the usage-scope fence.
        let src = include_str!("profile_activation.rs");
        let line = src
            .lines()
            .find(|l| l.contains("let all_providers: Vec<String>"))
            .expect("the all_providers assignment is gone — re-point this fence");
        let marker = format!("b.{}_code.clone()", "provider");
        assert!(
            line.contains(marker.as_str()),
            "sync_active_key_config_from_bindings must collect provider_code \
             (the SUPPLIER axis). Collecting client_route re-introduces \
             NO_ACTIVE_KEY for every supplier whose name differs from its \
             route (moonshot under the kimi route, first reported 2026-08-20)."
        );
        let wrong = format!("b.{}_route.clone()", "client");
        assert!(
            !line.contains(wrong.as_str()),
            "the client_route axis is being written into active_key_providers again"
        );
    }
}
