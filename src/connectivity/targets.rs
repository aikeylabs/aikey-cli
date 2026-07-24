//! Target resolvers — convert `(binding | alias | new-key)` into `Vec<TestTarget>`.
//!
//! Every target this module produces goes through one of the three factories
//! (`personal_target` / `team_target` / `oauth_target`) defined in the parent
//! module, which keeps the `TestTarget.provider_code` canonicalization
//! invariant honest in one place.

// **Round 9 review fix (MEDIUM, Finding 1)**: migrated all
// `is_proxy_running()` calls to `proxy_is_running_managed()`, which
// wraps Layer 1's `compute_proxy_state` for identity + ownership +
// /health verification. Previously preflight here would treat any
// PID-alive process as "ours" — including PID-recycled foreign
// processes — and let target construction proceed against a proxy
// we don't manage. The probe time cost of `compute_proxy_state` (~10ms
// from /health) is acceptable for the safety upgrade.

use crate::storage;

use super::{
    oauth_target, personal_target, personal_target_direct, provider_defaults, team_target,
    team_target_cluster, BuildTargetError, TestTarget,
};

/// A direct-bind Team VK needs locally delivered ciphertext. A Team OAuth
/// group VK never has VK-level ciphertext: the local proxy resolves its
/// current account from group-runtime and injects that account's credential.
/// Keep every connectivity resolver on this one predicate.
fn team_key_missing_required_local_material(is_group_vk: bool, has_ciphertext: bool) -> bool {
    !is_group_vk && !has_ciphertext
}

/// Build a TestTarget for a single provider binding.
///
/// `_password_unused` is kept in the signature as `Option<&SecretString>` so
/// external callers still pass through their existing handle but it is
/// **no longer read**. Plan D (2026-04-22) moved personal-key decryption
/// to the proxy side via the probe sentinel (post-2026-04-29 prefix rename:
/// `aikey_probe_*`), so CLI-side password access is no longer required for
/// any probe path. Removing
/// the parameter entirely would be a breaking API change for no gain —
/// callers are free to stop passing a password whenever convenient.
pub fn target_from_binding(
    binding: &crate::storage::ProviderBinding,
    _password_unused: Option<&secrecy::SecretString>,
    proxy_port: u16,
) -> Result<TestTarget, BuildTargetError> {
    use crate::credential_type::CredentialType;

    let label_suffix = match binding.key_source_type {
        CredentialType::PersonalApiKey => "",
        CredentialType::ManagedVirtualKey => " (team)",
        CredentialType::PersonalOAuthAccount => " (oauth)",
    };
    let row_label = format!("{}{}", binding.provider_code, label_suffix);
    if crate::provider_registry::proxy_path_for_binding(
        &binding.provider_code,
        &binding.protocol_type,
    )
    .is_none()
    {
        return Err(BuildTargetError::Unknown {
            label: row_label,
            detail: format!(
                "invalid provider/protocol binding: provider={} protocol={}",
                binding.provider_code, binding.protocol_type
            ),
        });
    }

    match binding.key_source_type {
        // ── Personal API key: route via proxy with the alias sentinel. ────
        // Post-2026-04-22 (plan D) this path matches team/OAuth: CLI never
        // touches the plaintext. Proxy decrypts on its side.
        CredentialType::PersonalApiKey => {
            if !crate::commands_proxy::proxy_is_running_managed() {
                return Err(BuildTargetError::ProxyNotRunning { label: row_label });
            }
            Ok(personal_target(
                &binding.key_source_ref,
                &binding.provider_code,
                &binding.protocol_type,
                proxy_port,
            ))
        }

        // ── Team virtual key: route through the local proxy. ───────────────
        CredentialType::ManagedVirtualKey => {
            if !crate::commands_proxy::proxy_is_running_managed() {
                return Err(BuildTargetError::ProxyNotRunning { label: row_label });
            }
            // Direct-bind Team VKs need local ciphertext. Group VKs do not:
            // their per-account credential arrives through group-runtime and
            // is resolved by the local proxy at request time.
            let vk = storage::get_virtual_key_cache(&binding.key_source_ref)
                .ok()
                .flatten();
            if let Some(ref v) = vk {
                if team_key_missing_required_local_material(
                    v.oauth_group_id.is_some(),
                    v.provider_key_ciphertext.is_some(),
                ) {
                    let display = v.local_alias.clone().unwrap_or_else(|| v.alias.clone());
                    return Err(BuildTargetError::TeamKeyNotDelivered {
                        virtual_key_id: binding.key_source_ref.clone(),
                        display,
                    });
                }
            }
            Ok(team_target(
                &binding.key_source_ref,
                &binding.provider_code,
                &binding.protocol_type,
                proxy_port,
            ))
        }

        // ── OAuth account: route through the local proxy. ──────────────────
        CredentialType::PersonalOAuthAccount => {
            if !crate::commands_proxy::proxy_is_running_managed() {
                return Err(BuildTargetError::ProxyNotRunning { label: row_label });
            }
            // Surface OAuth accounts in reauth/subscription_required early.
            // The probe would fail anyway; this tells the user *what to fix*.
            if let Ok(accounts) = storage::list_provider_accounts_readonly() {
                if let Some(acct) = accounts
                    .iter()
                    .find(|a| a.provider_account_id == binding.key_source_ref)
                {
                    if !matches!(acct.status.as_str(), "active" | "idle") {
                        // Surface the user-facing label (local_alias if
                        // renamed, else email) — `effective_label` falls
                        // through to provider_account_id only when both are
                        // empty, matching the pre-v1.0.1-alpha.1 fallback.
                        return Err(BuildTargetError::OAuthUnhealthy {
                            account: acct.effective_label().to_string(),
                            status: acct.status.clone(),
                        });
                    }
                }
            }
            // Bindings store canonical provider_code already, so the factory's
            // broker-to-canonical normalization is idempotent here — kept in
            // the call path for uniformity (one construction chokepoint).
            Ok(oauth_target(
                &binding.key_source_ref,
                &binding.provider_code,
                &binding.protocol_type,
                proxy_port,
            ))
        }
    }
}

/// Canonical target list for all active provider bindings (doctor + test).
///
/// Returns two lists in lockstep: successful targets ready for the suite,
/// and build errors suitable for the "cannot test" block beneath the table.
/// Callers may mutate either list freely (e.g. add extra targets, drop rows).
pub fn targets_from_active_bindings(
    _password_unused: Option<&secrecy::SecretString>,
    proxy_port: u16,
) -> (Vec<TestTarget>, Vec<BuildTargetError>) {
    let bindings = storage::list_provider_bindings(crate::profile_activation::DEFAULT_PROFILE)
        .unwrap_or_default();

    let mut targets = Vec::with_capacity(bindings.len());
    let mut errors = Vec::new();
    for b in &bindings {
        match target_from_binding(b, None, proxy_port) {
            Ok(t) => targets.push(t),
            Err(e) => errors.push(e),
        }
    }
    (targets, errors)
}

/// Resolve `alias` to a TestTarget by scanning personal → team → OAuth.
///
/// Priority is fixed and documented: personal entry wins over team key,
/// team wins over OAuth account. On a personal hit, expands across the
/// provider list (N targets) so `aikey test <alias>` covers all providers
/// the key is bound to; team and OAuth resolve to exactly one target since
/// their provider is inherent to the credential.
///
/// Returns an empty Vec when the alias doesn't match anything in any
/// source — callers should report "not found" rather than "error".
///
/// `provider_override` lets `aikey test <alias> --provider X` force a
/// specific provider (only meaningful for PersonalApi multi-provider keys).
pub fn targets_from_alias(
    alias: &str,
    provider_override: Option<&str>,
    _password_unused: Option<&secrecy::SecretString>,
    proxy_port: u16,
) -> Vec<TestTarget> {
    use crate::credential_type::CredentialType;

    // ── 1. Personal vault entry (highest priority). ──────────────────────
    if storage::entry_exists(alias).unwrap_or(false) {
        // Plan D (2026-04-22): no decryption here — proxy does it server-
        // side via the probe sentinel (post-2026-04-29 prefix rename:
        // `aikey_probe_<alias>`). We just need the provider list (metadata,
        // unencrypted) and the proxy running.
        if !crate::commands_proxy::proxy_is_running_managed() {
            return Vec::new();
        }

        let meta = storage::list_entries_with_metadata()
            .unwrap_or_default()
            .into_iter()
            .find(|m| m.alias == alias);

        let providers: Vec<String> = if let Some(p) = provider_override {
            vec![p.to_lowercase()]
        } else if let Some(ref m) = meta {
            if let Some(ref sp) = m.supported_providers {
                if !sp.is_empty() {
                    sp.clone()
                } else if let Some(ref code) = m.provider_code {
                    vec![code.clone()]
                } else {
                    // Unknown provider + no explicit list: fall back to the
                    // well-known set so the user can see which upstreams the
                    // key reaches.
                    provider_defaults()
                        .iter()
                        .map(|(c, _)| c.to_string())
                        .collect()
                }
            } else if let Some(ref code) = m.provider_code {
                vec![code.clone()]
            } else {
                provider_defaults()
                    .iter()
                    .map(|(c, _)| c.to_string())
                    .collect()
            }
        } else {
            provider_defaults()
                .iter()
                .map(|(c, _)| c.to_string())
                .collect()
        };

        return providers
            .into_iter()
            .map(|code| personal_target(alias, &code, "", proxy_port))
            .collect();
    }

    // ── 2. Team virtual key (by ID, local_alias, or server alias). ───────
    let team_entry = storage::get_virtual_key_cache(alias)
        .ok()
        .flatten()
        .or_else(|| {
            storage::get_virtual_key_cache_by_alias(alias)
                .ok()
                .flatten()
        });
    if let Some(vk) = team_entry {
        if !crate::commands_proxy::proxy_is_running_managed() {
            return Vec::new();
        }
        // Team keys have a single authoritative provider; honour the override
        // only when the user supplied one (keeps probe URL consistent). GROUP
        // VKs (oauth_group_id set) carry an EMPTY VK-level provider_code BY DESIGN
        // (provider lives per-account in group_accounts) — fall back to the VK's
        // supported_providers (synced from the group's account set) so the probe
        // URL gets the right /<prefix>. Same root cause as the proxy-side
        // 2026-06-25-group-vk-empty-provider-code-502 fix, applied here on the
        // CLI probe side.
        let provider = provider_override
            .map(|p| p.to_lowercase())
            .unwrap_or_else(|| {
                if !vk.provider_code.is_empty() {
                    vk.provider_code.clone()
                } else {
                    vk.supported_providers.first().cloned().unwrap_or_default()
                }
            });
        // Cluster form-① direct-bind VK: the provider key material stays central
        // on the hub-resolved node, so this VK's local cache entry has
        // provider_key_ciphertext = None BY DESIGN. Probe the SAME way a real
        // call routes (cluster_route → node authority + real VK token) instead
        // of demanding local ciphertext. Without this the cluster VK fell
        // through to the is_none() guard below → empty targets →
        // I_CREDENTIAL_NOT_FOUND → HTTP 404 in the Web "Test Connection",
        // which was misleading (the VK exists; only LOCAL material is absent).
        // Precondition: a prior `aikey use` persisted the resolved node
        // (read_cluster_node); without it cluster_route is None and we keep the
        // original local-material path. Bug:
        // workflow/CI/bugfix/20260611-cluster-form1-connectivity-test-404.md
        if let Some((node, token)) = crate::commands_account::cluster_route(
            &crate::credential_type::CredentialType::ManagedVirtualKey,
            &vk.virtual_key_id,
        ) {
            return vec![team_target_cluster(
                &node,
                &token,
                &vk.virtual_key_id,
                &provider,
                &vk.protocol_type,
            )];
        }
        // GROUP VKs have NO local key material (provider_key_ciphertext = None)
        // BY DESIGN — the per-account credential is pulled by the proxy via
        // channel ③ (group-runtime) and injected at route time, never stored
        // locally. So the ciphertext guard (which means "direct-bind VK not yet
        // delivered → unprobeable") must NOT apply to group VKs: probe them
        // through the proxy with the aikey_team_<vk_id> bearer exactly like a
        // real group request (the proxy resolves the account + injects its key).
        if team_key_missing_required_local_material(
            vk.oauth_group_id.is_some(),
            vk.provider_key_ciphertext.is_some(),
        ) {
            // Non-cluster, direct-bind team VK with no local material (never
            // delivered) — genuinely unprobeable. Caller surfaces
            // I_CREDENTIAL_NOT_FOUND.
            return Vec::new();
        }
        return vec![team_target(
            &vk.virtual_key_id,
            &provider,
            &vk.protocol_type,
            proxy_port,
        )];
    }

    // ── 3. OAuth account (by ID, local_alias, or display_identity / email). ────
    // v1.0.1-alpha.1: also match local_alias so a renamed OAuth account
    // resolves correctly here. Mirror with `commands_account::resolve_oauth_account`.
    if let Ok(accounts) = storage::list_provider_accounts_readonly() {
        let hit = accounts.iter().find(|a| {
            a.provider_account_id.eq_ignore_ascii_case(alias)
                || a.local_alias
                    .as_deref()
                    .map(|d| d.eq_ignore_ascii_case(alias))
                    .unwrap_or(false)
                || a.display_identity
                    .as_deref()
                    .map(|d| d.eq_ignore_ascii_case(alias))
                    .unwrap_or(false)
        });
        if let Some(acct) = hit {
            // CredentialType::PersonalOAuthAccount is the only kind we
            // route through here; other types would be data corruption.
            debug_assert_eq!(acct.credential_type, CredentialType::PersonalOAuthAccount);
            if !crate::commands_proxy::proxy_is_running_managed() {
                return Vec::new();
            }
            if !matches!(acct.status.as_str(), "active" | "idle") {
                return Vec::new();
            }
            // `oauth_target` handles broker→canonical normalization internally
            // — we just pass the raw string (override or account field) and
            // trust the factory. Single chokepoint for the mapping means the
            // 2026-04-21 "claude vs anthropic" divergence can't recur from
            // a new resolver forgetting to call `oauth_provider_to_canonical`.
            let raw_provider = provider_override
                .map(|p| p.to_lowercase())
                .unwrap_or_else(|| acct.provider.clone());
            return vec![oauth_target(
                &acct.provider_account_id,
                &raw_provider,
                &acct.protocol_type,
                proxy_port,
            )];
        }
    }

    Vec::new()
}

/// Enumerate every credential in the vault (personal entries + team keys +
/// OAuth accounts) and build TestTargets for the connectivity suite.
///
/// 2026-05-09: backs `aikey test --all`. Different from
/// `targets_from_active_bindings` (which only tests the **Primary** for each
/// provider): this iterates every stored key regardless of activation state,
/// so the user can audit dormant / multi-provider / aggregator keys without
/// repeatedly running `aikey test <alias>` per row.
///
/// Each personal entry expands across its supported_providers list (so a
/// multi-protocol aggregator key like 0011 produces one row per protocol).
/// Team keys and OAuth accounts each produce exactly one row (their provider
/// is inherent to the credential).
///
/// Returns the same (targets, build_errors) shape as
/// `targets_from_active_bindings` so the suite runner doesn't care which
/// builder produced its inputs.
pub fn targets_from_all_keys(proxy_port: u16) -> (Vec<TestTarget>, Vec<BuildTargetError>) {
    let mut targets = Vec::new();
    let errors: Vec<BuildTargetError> = Vec::new();

    // ── 1. Personal entries ──────────────────────────────────────────────
    // Use _readonly variant: enumeration shouldn't bump vault_change_seq or
    // contend with concurrent CLI writes. proxy_is_running gate matches
    // the `targets_from_alias` precondition (probe path needs proxy up).
    let proxy_up = crate::commands_proxy::proxy_is_running_managed();
    if proxy_up {
        if let Ok(metas) = storage::list_entries_with_metadata_readonly() {
            for m in metas {
                let providers: Vec<String> = if let Some(ref sp) = m.supported_providers {
                    if !sp.is_empty() {
                        sp.clone()
                    } else if let Some(ref code) = m.provider_code {
                        vec![code.clone()]
                    } else {
                        // No provider info — skip (vs. fan out across all
                        // defaults like the alias-resolver does). For --all
                        // we want signal not noise; an unbound key has
                        // nothing to test against.
                        continue;
                    }
                } else if let Some(ref code) = m.provider_code {
                    vec![code.clone()]
                } else {
                    continue;
                };
                for code in providers {
                    targets.push(personal_target(&m.alias, &code, "", proxy_port));
                }
            }
        }
    }

    // ── 2. Team virtual keys ─────────────────────────────────────────────
    if proxy_up {
        if let Ok(team_entries) = storage::list_virtual_key_cache_readonly() {
            for vk in team_entries {
                // Skip direct-bind keys without ciphertext (server hasn't
                // delivered the real key yet) — probe can't decrypt nothing.
                // GROUP VKs (oauth_group_id set) have NO local ciphertext BY
                // DESIGN (material via proxy channel ③), so don't skip them.
                if team_key_missing_required_local_material(
                    vk.oauth_group_id.is_some(),
                    vk.provider_key_ciphertext.is_some(),
                ) {
                    continue;
                }
                // Skip stale / disabled rows (matches the runtime route
                // gate in vault.GetActiveManagedKeys).
                if vk.local_state == "stale" || vk.local_state.starts_with("disabled_by_") {
                    continue;
                }
                if vk.key_status != "active" {
                    continue;
                }
                // Friendly Key column: local_alias (renamed) → server alias
                // (canonical, e.g. `key-335923591-0011-1`). vk_id tail is
                // useless to humans — never surface it as the display label
                // when a real alias is available.
                // Group VKs carry an empty VK-level provider_code; use the
                // synced supported_providers as the probe URL prefix source
                // (proxy resolves the real per-account provider at route time).
                let provider = if !vk.provider_code.is_empty() {
                    vk.provider_code.clone()
                } else {
                    vk.supported_providers.first().cloned().unwrap_or_default()
                };
                let mut t =
                    team_target(&vk.virtual_key_id, &provider, &vk.protocol_type, proxy_port);
                t.display_alias = vk.local_alias.clone().unwrap_or_else(|| vk.alias.clone());
                targets.push(t);
            }
        }
    }

    // ── 3. OAuth accounts ────────────────────────────────────────────────
    if proxy_up {
        if let Ok(accounts) = storage::list_provider_accounts_readonly() {
            for acct in accounts {
                if !matches!(acct.status.as_str(), "active" | "idle") {
                    continue;
                }
                if !matches!(
                    acct.credential_type,
                    crate::credential_type::CredentialType::PersonalOAuthAccount
                ) {
                    continue;
                }
                let mut t = oauth_target(
                    &acct.provider_account_id,
                    &acct.provider,
                    &acct.protocol_type,
                    proxy_port,
                );
                // Friendly Key column: effective_label = local_alias → display_identity
                // → account_id. Falls back to source_ref via TestTarget::key_display
                // when it's empty (rare; only if all three are missing).
                t.display_alias = acct.effective_label().to_string();
                targets.push(t);
            }
        }
    }

    (targets, errors)
}

#[cfg(test)]
mod group_vk_material_tests {
    use super::team_key_missing_required_local_material;

    #[test]
    fn group_vk_without_ciphertext_is_probeable_via_group_runtime() {
        assert!(!team_key_missing_required_local_material(true, false));
    }

    #[test]
    fn direct_bind_vk_without_ciphertext_still_requires_delivery() {
        assert!(team_key_missing_required_local_material(false, false));
        assert!(!team_key_missing_required_local_material(false, true));
    }
}

/// Build targets for the `aikey add` post-entry probe: one plaintext key
/// tested against each of the user-selected providers.
///
/// `base_url_override` is the user-typed custom URL (empty = use defaults).
/// When set, every target uses that URL; the probe treats it as the provider's
/// upstream (PersonalApi → direct hit).
pub fn targets_from_new_personal_key(
    alias: &str,
    plaintext: &str,
    providers: &[String],
    base_url_override: Option<&str>,
) -> Vec<TestTarget> {
    providers
        .iter()
        .map(|code| personal_target_direct(alias, plaintext, code, base_url_override))
        .collect()
}
