//! Target resolvers — convert `(binding | alias | new-key)` into `Vec<TestTarget>`.
//!
//! Every target this module produces goes through one of the three factories
//! (`personal_target` / `team_target` / `oauth_target`) defined in the parent
//! module, which keeps the `TestTarget.provider_code` canonicalization
//! invariant honest in one place.

use crate::storage;

use super::{
    BuildTargetError, TestTarget,
    personal_target, personal_target_direct, team_target, oauth_target,
    PROVIDER_DEFAULTS,
};

/// Build a TestTarget for a single provider binding.
///
/// `_password_unused` is kept in the signature as `Option<&SecretString>` so
/// external callers still pass through their existing handle but it is
/// **no longer read**. Plan D (2026-04-22) moved personal-key decryption
/// to the proxy side via the aikey_personal_alias_ sentinel, so CLI-side
/// password access is no longer required for any probe path. Removing
/// the parameter entirely would be a breaking API change for no gain —
/// callers are free to stop passing a password whenever convenient.
pub fn target_from_binding(
    binding: &crate::storage::ProviderBinding,
    _password_unused: Option<&secrecy::SecretString>,
    proxy_port: u16,
) -> Result<TestTarget, BuildTargetError> {
    use crate::credential_type::CredentialType;

    let label_suffix = match binding.key_source_type {
        CredentialType::PersonalApiKey        => "",
        CredentialType::ManagedVirtualKey     => " (team)",
        CredentialType::PersonalOAuthAccount  => " (oauth)",
    };
    let row_label = format!("{}{}", binding.provider_code, label_suffix);

    match binding.key_source_type {
        // ── Personal API key: route via proxy with the alias sentinel. ────
        // Post-2026-04-22 (plan D) this path matches team/OAuth: CLI never
        // touches the plaintext. Proxy decrypts on its side.
        CredentialType::PersonalApiKey => {
            if !crate::commands_proxy::is_proxy_running() {
                return Err(BuildTargetError::ProxyNotRunning { label: row_label });
            }
            Ok(personal_target(
                &binding.key_source_ref,
                &binding.provider_code,
                proxy_port,
            ))
        }

        // ── Team virtual key: route through the local proxy. ───────────────
        CredentialType::ManagedVirtualKey => {
            if !crate::commands_proxy::is_proxy_running() {
                return Err(BuildTargetError::ProxyNotRunning { label: row_label });
            }
            // Sanity: team VK needs its ciphertext delivered for the proxy to
            // forward it. Without that, proxy responds 503; we can surface
            // that upfront as a clearer "run sync".
            let vk = storage::get_virtual_key_cache(&binding.key_source_ref)
                .ok()
                .flatten();
            if let Some(ref v) = vk {
                if v.provider_key_ciphertext.is_none() {
                    let display = v.local_alias.clone().unwrap_or_else(|| v.alias.clone());
                    return Err(BuildTargetError::TeamKeyNotDelivered {
                        virtual_key_id: binding.key_source_ref.clone(),
                        display,
                    });
                }
            }
            Ok(team_target(&binding.key_source_ref, &binding.provider_code, proxy_port))
        }

        // ── OAuth account: route through the local proxy. ──────────────────
        CredentialType::PersonalOAuthAccount => {
            if !crate::commands_proxy::is_proxy_running() {
                return Err(BuildTargetError::ProxyNotRunning { label: row_label });
            }
            // Surface OAuth accounts in reauth/subscription_required early.
            // The probe would fail anyway; this tells the user *what to fix*.
            if let Ok(accounts) = storage::list_provider_accounts_readonly() {
                if let Some(acct) = accounts.iter()
                    .find(|a| a.provider_account_id == binding.key_source_ref)
                {
                    if !matches!(acct.status.as_str(), "active" | "idle") {
                        return Err(BuildTargetError::OAuthUnhealthy {
                            account: acct.display_identity.clone()
                                .unwrap_or_else(|| binding.key_source_ref.clone()),
                            status: acct.status.clone(),
                        });
                    }
                }
            }
            // Bindings store canonical provider_code already, so the factory's
            // broker-to-canonical normalization is idempotent here — kept in
            // the call path for uniformity (one construction chokepoint).
            Ok(oauth_target(&binding.key_source_ref, &binding.provider_code, proxy_port))
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
    let mut errors  = Vec::new();
    for b in &bindings {
        match target_from_binding(b, None, proxy_port) {
            Ok(t)  => targets.push(t),
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
        // side via the aikey_personal_alias_ sentinel. We just need the
        // provider list (metadata, unencrypted) and the proxy running.
        if !crate::commands_proxy::is_proxy_running() {
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
                if !sp.is_empty() { sp.clone() }
                else if let Some(ref code) = m.provider_code { vec![code.clone()] }
                else {
                    // Unknown provider + no explicit list: fall back to the
                    // well-known set so the user can see which upstreams the
                    // key reaches.
                    PROVIDER_DEFAULTS.iter().map(|(c, _)| c.to_string()).collect()
                }
            } else if let Some(ref code) = m.provider_code {
                vec![code.clone()]
            } else {
                PROVIDER_DEFAULTS.iter().map(|(c, _)| c.to_string()).collect()
            }
        } else {
            PROVIDER_DEFAULTS.iter().map(|(c, _)| c.to_string()).collect()
        };

        return providers.into_iter().map(|code| {
            personal_target(alias, &code, proxy_port)
        }).collect();
    }

    // ── 2. Team virtual key (by ID, local_alias, or server alias). ───────
    let team_entry = storage::get_virtual_key_cache(alias).ok().flatten()
        .or_else(|| storage::get_virtual_key_cache_by_alias(alias).ok().flatten());
    if let Some(vk) = team_entry {
        if !crate::commands_proxy::is_proxy_running() {
            return Vec::new();
        }
        if vk.provider_key_ciphertext.is_none() {
            return Vec::new();
        }
        // Team keys have a single authoritative provider; honour the override
        // only when the user supplied one (keeps probe URL consistent).
        let provider = provider_override
            .map(|p| p.to_lowercase())
            .unwrap_or_else(|| vk.provider_code.clone());
        return vec![team_target(&vk.virtual_key_id, &provider, proxy_port)];
    }

    // ── 3. OAuth account (by ID or display_identity / email). ────────────
    if let Ok(accounts) = storage::list_provider_accounts_readonly() {
        let hit = accounts.iter().find(|a| {
            a.provider_account_id.eq_ignore_ascii_case(alias)
                || a.display_identity.as_deref()
                    .map(|d| d.eq_ignore_ascii_case(alias))
                    .unwrap_or(false)
        });
        if let Some(acct) = hit {
            // CredentialType::PersonalOAuthAccount is the only kind we
            // route through here; other types would be data corruption.
            debug_assert_eq!(acct.credential_type, CredentialType::PersonalOAuthAccount);
            if !crate::commands_proxy::is_proxy_running() {
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
            return vec![oauth_target(&acct.provider_account_id, &raw_provider, proxy_port)];
        }
    }

    Vec::new()
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
    providers.iter()
        .map(|code| personal_target_direct(alias, plaintext, code, base_url_override))
        .collect()
}

