//! Tests for `build_run_env` — the per-provider binding env injection logic
//! introduced when `run_with_active_key` was migrated from the legacy
//! single-key `active_key_config` model to `user_profile_provider_bindings`.

use aikeylabs_aikey_cli::credential_type::CredentialType;
use aikeylabs_aikey_cli::executor::build_run_env;
use aikeylabs_aikey_cli::storage::{ActiveKeyConfig, ProviderBinding};

/// Helper: build a ProviderBinding from string-form `src_type` for readability.
/// Accepts legacy string labels ("personal", "team", "oauth") and maps them to
/// the current `CredentialType` enum. Unknown strings return None so the test
/// author notices typos instead of getting a surprising default.
fn src_type_from_str(s: &str) -> Option<CredentialType> {
    match s {
        "personal" => Some(CredentialType::PersonalApiKey),
        "team"     => Some(CredentialType::ManagedVirtualKey),
        "oauth"    => Some(CredentialType::PersonalOAuthAccount),
        _          => None,
    }
}

fn make_binding(provider: &str, src_type: &str, src_ref: &str) -> ProviderBinding {
    ProviderBinding {
        profile_id: "default".to_string(),
        provider_code: provider.to_string(),
        key_source_type: src_type_from_str(src_type)
            .unwrap_or_else(|| panic!("unknown src_type '{}' in test fixture", src_type)),
        key_source_ref: src_ref.to_string(),
        updated_at: Some(1000),
    }
}

// ============================================================================
// Single provider binding injection
// ============================================================================

#[test]
fn single_personal_binding_injects_correct_env() {
    let bindings = vec![make_binding("anthropic", "personal", "my-claude-key")];
    let (env, providers, used_legacy) = build_run_env(&bindings, None, 27200).unwrap();

    assert!(!used_legacy);
    assert_eq!(providers, vec!["anthropic"]);
    assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "aikey_active_anthropic");
    assert_eq!(env.get("ANTHROPIC_BASE_URL").unwrap(), "http://127.0.0.1:27200/anthropic");
    // Should only have 2 env vars (API_KEY + BASE_URL) for one provider.
    assert_eq!(env.len(), 2);
}

#[test]
fn single_team_binding_injects_vk_token() {
    let bindings = vec![make_binding("openai", "team", "vk-abc-123")];
    let (env, providers, _) = build_run_env(&bindings, None, 27200).unwrap();

    assert_eq!(providers, vec!["openai"]);
    assert_eq!(env.get("OPENAI_API_KEY").unwrap(), "aikey_active_openai");
    assert_eq!(env.get("OPENAI_BASE_URL").unwrap(), "http://127.0.0.1:27200/openai");
}

// ============================================================================
// Multi-provider with mixed key sources
// ============================================================================

#[test]
fn multi_provider_mixed_sources() {
    let bindings = vec![
        make_binding("anthropic", "team", "vk-team-1"),
        make_binding("openai", "personal", "my-openai"),
        make_binding("google", "personal", "my-gemini"),
    ];
    let (env, providers, used_legacy) = build_run_env(&bindings, None, 27200).unwrap();

    assert!(!used_legacy);
    assert_eq!(providers.len(), 3);

    // Anthropic: team key
    assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "aikey_active_anthropic");
    assert_eq!(env.get("ANTHROPIC_BASE_URL").unwrap(), "http://127.0.0.1:27200/anthropic");

    // OpenAI: personal key
    assert_eq!(env.get("OPENAI_API_KEY").unwrap(), "aikey_active_openai");
    assert_eq!(env.get("OPENAI_BASE_URL").unwrap(), "http://127.0.0.1:27200/openai");

    // Google: personal key
    assert_eq!(env.get("GOOGLE_API_KEY").unwrap(), "aikey_active_google");
    assert_eq!(env.get("GOOGLE_BASE_URL").unwrap(), "http://127.0.0.1:27200/google");

    // 3 providers * 2 vars each = 6
    assert_eq!(env.len(), 6);
}

// ============================================================================
// No bindings — error when no legacy config either
// ============================================================================

#[test]
fn no_bindings_no_legacy_returns_empty() {
    let (env, providers, used_legacy) = build_run_env(&[], None, 27200).unwrap();
    assert!(providers.is_empty());
    assert!(env.is_empty());
    assert!(!used_legacy);
}

// ============================================================================
// Legacy fallback: single key for all providers
// ============================================================================

#[test]
fn legacy_fallback_team_key() {
    let legacy = ActiveKeyConfig {
        key_type: CredentialType::ManagedVirtualKey,
        key_ref: "vk-legacy-1".to_string(),
        providers: vec!["anthropic".to_string(), "openai".to_string()],
    };
    let (env, providers, used_legacy) = build_run_env(&[], Some(&legacy), 27200).unwrap();

    assert!(used_legacy);
    assert_eq!(providers, vec!["anthropic", "openai"]);
    // Both providers get the same team token (legacy single-key behavior).
    assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "aikey_active_anthropic");
    assert_eq!(env.get("OPENAI_API_KEY").unwrap(), "aikey_active_anthropic");
}

#[test]
fn legacy_fallback_personal_key() {
    let legacy = ActiveKeyConfig {
        key_type: CredentialType::PersonalApiKey,
        key_ref: "my-old-key".to_string(),
        providers: vec!["anthropic".to_string()],
    };
    let (env, providers, used_legacy) = build_run_env(&[], Some(&legacy), 27200).unwrap();

    assert!(used_legacy);
    assert_eq!(providers, vec!["anthropic"]);
    assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "aikey_active_anthropic");
}

#[test]
fn legacy_fallback_empty_providers_injects_all_defaults() {
    let legacy = ActiveKeyConfig {
        key_type: CredentialType::PersonalApiKey,
        key_ref: "catch-all".to_string(),
        providers: vec![],
    };
    let (_, providers, used_legacy) = build_run_env(&[], Some(&legacy), 27200).unwrap();

    assert!(used_legacy);
    // Empty providers in legacy mode falls back to all known providers.
    assert!(providers.contains(&"anthropic".to_string()));
    assert!(providers.contains(&"openai".to_string()));
    assert!(providers.contains(&"google".to_string()));
    assert!(providers.contains(&"deepseek".to_string()));
    assert!(providers.contains(&"kimi".to_string()));
}

// ============================================================================
// Bindings take priority over legacy config
// ============================================================================

#[test]
fn bindings_override_legacy_config() {
    let bindings = vec![make_binding("anthropic", "personal", "new-key")];
    let legacy = ActiveKeyConfig {
        key_type: CredentialType::ManagedVirtualKey,
        key_ref: "old-vk".to_string(),
        providers: vec!["anthropic".to_string(), "openai".to_string()],
    };
    let (env, providers, used_legacy) = build_run_env(&bindings, Some(&legacy), 27200).unwrap();

    // New model wins — legacy is ignored.
    assert!(!used_legacy);
    assert_eq!(providers, vec!["anthropic"]);
    assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "aikey_active_anthropic");
    // OpenAI should NOT be injected (only anthropic has a binding).
    assert!(env.get("OPENAI_API_KEY").is_none());
}

// ============================================================================
// (Removed) unknown_key_source_type_returns_error
//
// The original test passed a free-form string "magic" to exercise the error
// path. After the 2026-04 storage migration `key_source_type` became a typed
// CredentialType enum, so unknown values can no longer be constructed at the
// type level. This branch is now a compile-time guarantee, so no runtime test
// is needed. Retained as a comment for archaeologists.
// ============================================================================

// ============================================================================
// Unknown provider code is skipped (no env var mapping)
// ============================================================================

#[test]
fn unknown_provider_skipped_gracefully() {
    let bindings = vec![
        make_binding("anthropic", "personal", "key-a"),
        make_binding("unknown_provider_xyz", "personal", "key-b"),
    ];
    let (env, providers, _) = build_run_env(&bindings, None, 27200).unwrap();

    // Only anthropic should be injected; unknown provider silently skipped.
    assert_eq!(providers, vec!["anthropic"]);
    assert_eq!(env.len(), 2);
}

// ============================================================================
// Custom proxy port is respected
// ============================================================================

#[test]
fn custom_proxy_port_in_base_url() {
    let bindings = vec![make_binding("openai", "personal", "k1")];
    let (env, _, _) = build_run_env(&bindings, None, 31337).unwrap();

    assert_eq!(env.get("OPENAI_BASE_URL").unwrap(), "http://127.0.0.1:31337/openai");
}
