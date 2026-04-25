//! Tests for v1.0.2 profile activation engine (Phase 2 core functions).
//!
//! Covers: auto_assign_primaries_for_key, reconcile after sync,
//! reconcile after key removal, and refresh_implicit_profile_activation.
//!
//! ## Running
//!
//! Must run with `--test-threads=1` because `setup()` mutates global env vars
//! (`AK_VAULT_PATH`, `HOME`). Parallel test execution races on these vars.
//!
//! ```
//! cargo test --test profile_activation_test -- --test-threads=1
//! ```

use aikeylabs_aikey_cli::credential_type::CredentialType;
use aikeylabs_aikey_cli::profile_activation::{self, DEFAULT_PROFILE, ReconcileOutcome};
use aikeylabs_aikey_cli::storage;
use secrecy::SecretString;
use tempfile::TempDir;

/// Sets up an isolated vault and returns the temp dir guard.
fn setup() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("vault.db");
    std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap());
    // Also point HOME to tempdir so active.env writes there.
    std::env::set_var("HOME", dir.path().to_str().unwrap());

    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let pw = SecretString::new("test_password_123".to_string());
    storage::initialize_vault(&salt, &pw).expect("init vault");
    dir
}

// ============================================================================
// auto_assign_primaries_for_key
// ============================================================================

#[test]
fn auto_assign_fills_empty_providers() {
    let _dir = setup();

    // Add a key supporting two providers.
    let assigned = profile_activation::auto_assign_primaries_for_key(
        "personal",
        "my-claude",
        &["anthropic".into(), "openai".into()],
    )
    .unwrap();

    assert_eq!(assigned, vec!["anthropic", "openai"]);

    // Verify bindings were created.
    let b = storage::get_provider_binding(DEFAULT_PROFILE, "anthropic")
        .unwrap()
        .unwrap();
    assert_eq!(b.key_source_ref, "my-claude");
    assert_eq!(b.key_source_type, CredentialType::PersonalApiKey);
}

#[test]
fn auto_assign_does_not_overwrite_existing_primary() {
    let _dir = setup();

    // Pre-populate anthropic with an existing primary.
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "old-key")
        .unwrap();

    // Now add a new key that also supports anthropic + openai.
    let assigned = profile_activation::auto_assign_primaries_for_key(
        "personal",
        "new-key",
        &["anthropic".into(), "openai".into()],
    )
    .unwrap();

    // Only openai should have been assigned (anthropic was already taken).
    assert_eq!(assigned, vec!["openai"]);

    // anthropic still points to old-key.
    let b = storage::get_provider_binding(DEFAULT_PROFILE, "anthropic")
        .unwrap()
        .unwrap();
    assert_eq!(b.key_source_ref, "old-key");
}

#[test]
fn auto_assign_team_key() {
    let _dir = setup();

    let assigned = profile_activation::auto_assign_primaries_for_key(
        "team",
        "vk_abc",
        &["google".into()],
    )
    .unwrap();

    assert_eq!(assigned, vec!["google"]);

    let b = storage::get_provider_binding(DEFAULT_PROFILE, "google")
        .unwrap()
        .unwrap();
    assert_eq!(b.key_source_type, CredentialType::ManagedVirtualKey);
    assert_eq!(b.key_source_ref, "vk_abc");
}

// ============================================================================
// reconcile_provider_primaries_after_team_key_sync
// ============================================================================

#[test]
fn team_sync_reconcile_fills_gaps() {
    let _dir = setup();

    // anthropic already has a primary.
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "my-claude")
        .unwrap();

    // Sync brings in a team key that supports anthropic + openai.
    let synced = vec![
        ("vk_team_1".to_string(), vec!["anthropic".to_string(), "openai".to_string()]),
    ];
    let results =
        profile_activation::reconcile_provider_primaries_after_team_key_sync(&synced).unwrap();

    // Only openai should be assigned to the team key.
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "vk_team_1");
    assert_eq!(results[0].1, vec!["openai"]);

    // anthropic unchanged.
    let b = storage::get_provider_binding(DEFAULT_PROFILE, "anthropic")
        .unwrap()
        .unwrap();
    assert_eq!(b.key_source_ref, "my-claude");
}

#[test]
fn team_sync_reconcile_no_op_when_all_taken() {
    let _dir = setup();

    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "a").unwrap();
    storage::set_provider_binding(DEFAULT_PROFILE, "openai", "personal", "b").unwrap();

    let synced = vec![
        ("vk_x".to_string(), vec!["anthropic".to_string(), "openai".to_string()]),
    ];
    let results =
        profile_activation::reconcile_provider_primaries_after_team_key_sync(&synced).unwrap();

    assert!(results.is_empty());
}

// ============================================================================
// reconcile_provider_primary_after_key_removal
// ============================================================================

#[test]
fn removal_clears_binding_when_no_replacement() {
    let _dir = setup();

    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "only-key")
        .unwrap();

    // The only personal key — no replacement available.
    // (We don't add any entries to the entries table, so find_replacement will find nothing.)
    let actions = profile_activation::reconcile_provider_primary_after_key_removal(
        "personal",
        "only-key",
    )
    .unwrap();

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].provider_code, "anthropic");
    assert!(matches!(actions[0].outcome, ReconcileOutcome::Cleared));

    // Binding should be gone.
    assert!(storage::get_provider_binding(DEFAULT_PROFILE, "anthropic")
        .unwrap()
        .is_none());
}

#[test]
fn removal_promotes_replacement_personal_key() {
    let _dir = setup();

    // Two personal keys supporting anthropic.
    storage::store_entry("key-a", &[0u8; 12], &[1u8; 32]).unwrap();
    storage::set_entry_supported_providers("key-a", &["anthropic".into()]).unwrap();

    storage::store_entry("key-b", &[0u8; 12], &[1u8; 32]).unwrap();
    storage::set_entry_supported_providers("key-b", &["anthropic".into()]).unwrap();

    // key-a is the current primary.
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "key-a")
        .unwrap();

    // Remove key-a.
    let actions = profile_activation::reconcile_provider_primary_after_key_removal(
        "personal",
        "key-a",
    )
    .unwrap();

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].provider_code, "anthropic");
    match &actions[0].outcome {
        ReconcileOutcome::Replaced { new_source_type, new_source_ref } => {
            assert_eq!(new_source_type, "personal");
            assert_eq!(new_source_ref, "key-b");
        }
        other => panic!("Expected Replaced, got {:?}", other),
    }

    // Binding should now point to key-b.
    let b = storage::get_provider_binding(DEFAULT_PROFILE, "anthropic")
        .unwrap()
        .unwrap();
    assert_eq!(b.key_source_ref, "key-b");
}

#[test]
fn removal_of_multi_provider_key_reconciles_each_provider() {
    let _dir = setup();

    // gateway key bound to two providers.
    storage::set_provider_binding(DEFAULT_PROFILE, "openai", "personal", "gateway").unwrap();
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "gateway").unwrap();

    // A backup key exists for openai only.
    storage::store_entry("backup-openai", &[0u8; 12], &[1u8; 32]).unwrap();
    storage::set_entry_supported_providers("backup-openai", &["openai".into()]).unwrap();

    let actions = profile_activation::reconcile_provider_primary_after_key_removal(
        "personal",
        "gateway",
    )
    .unwrap();

    assert_eq!(actions.len(), 2);

    // openai should be replaced with backup-openai.
    let openai_action = actions.iter().find(|a| a.provider_code == "openai").unwrap();
    match &openai_action.outcome {
        ReconcileOutcome::Replaced { new_source_ref, .. } => {
            assert_eq!(new_source_ref, "backup-openai");
        }
        other => panic!("Expected Replaced for openai, got {:?}", other),
    }

    // anthropic has no replacement — cleared.
    let anthropic_action = actions.iter().find(|a| a.provider_code == "anthropic").unwrap();
    assert!(matches!(anthropic_action.outcome, ReconcileOutcome::Cleared));
}

// Canonicalization regression (bugfix 2026-04-25, audit follow-up):
// When a personal/team key's supported_providers list still carries the raw
// OAuth vocabulary (`claude` / `codex` / `moonshot`) but the binding being
// reconciled keys on the canonical (`anthropic` / `openai` / `kimi`),
// find_replacement_candidate must canonicalize both sides before comparing —
// otherwise a perfectly valid replacement is silently skipped.
#[test]
fn replacement_search_finds_personal_entry_with_raw_oauth_provider_code() {
    let _dir = setup();

    // Two keys: the primary (anthropic, canonical) and a backup whose
    // supported_providers row still says raw "claude" (older add path
    // before write_bindings_canonical). Both should be eligible.
    storage::store_entry("primary", &[0u8; 12], &[1u8; 32]).unwrap();
    storage::set_entry_supported_providers("primary", &["anthropic".into()]).unwrap();

    storage::store_entry("legacy-claude", &[0u8; 12], &[1u8; 32]).unwrap();
    storage::set_entry_supported_providers("legacy-claude", &["claude".into()]).unwrap();

    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "primary")
        .unwrap();

    let actions = profile_activation::reconcile_provider_primary_after_key_removal(
        "personal",
        "primary",
    )
    .unwrap();

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].provider_code, "anthropic");
    match &actions[0].outcome {
        ReconcileOutcome::Replaced { new_source_type, new_source_ref } => {
            assert_eq!(new_source_type, "personal");
            assert_eq!(new_source_ref, "legacy-claude",
                "raw `claude` provider on the candidate must be canonicalized to \
                 `anthropic` for the match — otherwise the replacement is silently \
                 missed (same family as the 2026-04-25 activate bug)");
        }
        other => panic!("Expected Replaced, got {:?}", other),
    }
}

// ============================================================================
// refresh_implicit_profile_activation
// ============================================================================

#[test]
fn refresh_writes_active_env_for_all_bindings() {
    let _dir = setup();

    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "my-claude")
        .unwrap();
    storage::set_provider_binding(DEFAULT_PROFILE, "openai", "team", "vk_openai")
        .unwrap();

    let result = profile_activation::refresh_implicit_profile_activation().unwrap();

    assert_eq!(result.activated_providers.len(), 2);
    assert!(result.activated_providers.contains(&"anthropic".to_string()));
    assert!(result.activated_providers.contains(&"openai".to_string()));

    // Read the active.env file.
    let home = std::env::var("HOME").unwrap();
    let env_path = std::path::PathBuf::from(&home).join(".aikey/active.env");
    let contents = std::fs::read_to_string(&env_path).expect("active.env should exist");

    assert!(contents.contains("ANTHROPIC_API_KEY=\"aikey_personal_my-claude\""));
    assert!(contents.contains("OPENAI_API_KEY=\"aikey_vk_vk_openai\""));
    assert!(contents.contains("ANTHROPIC_BASE_URL="));
    // OPENAI_BASE_URL is deliberately NOT written: Codex v0.118+ warns when it's
    // set, because Codex now reads `openai_base_url` from ~/.codex/config.toml
    // (which aikey injects via configure_codex_cli). See profile_activation.rs
    // line 51-61 for the skip_base_url rationale.
    assert!(!contents.contains("OPENAI_BASE_URL="),
        "OPENAI_BASE_URL should be omitted to avoid Codex deprecation warning, got:\n{}",
        contents);
}

#[test]
fn refresh_writes_empty_env_when_no_bindings() {
    let _dir = setup();

    let result = profile_activation::refresh_implicit_profile_activation().unwrap();
    assert!(result.activated_providers.is_empty());

    let home = std::env::var("HOME").unwrap();
    let env_path = std::path::PathBuf::from(&home).join(".aikey/active.env");
    let contents = std::fs::read_to_string(&env_path).expect("active.env should exist");

    // Should only contain the header comment.
    assert!(contents.contains("auto-generated"));
    assert!(!contents.contains("API_KEY"));
}
