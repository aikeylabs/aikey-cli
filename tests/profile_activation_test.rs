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

    // 2026-04-29 prefix rename: sentinel is per-provider, alias-independent.
    // Old: per-credential-type sentinel embedded the alias / vk_id.
    // New: ANTHROPIC_API_KEY=aikey_active_anthropic (same string regardless of bound alias).
    // Alias info still surfaces via the separate AIKEY_ACTIVE_KEYS=anthropic=my-claude,...
    assert!(contents.contains("ANTHROPIC_API_KEY=\"aikey_active_anthropic\""));
    assert!(contents.contains("OPENAI_API_KEY=\"aikey_active_openai\""));
    assert!(contents.contains("anthropic=my-claude"),
        "AIKEY_ACTIVE_KEYS must surface the bound personal alias for anthropic");
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

// ============================================================================
// Stage 1+2 contract: AIKEY_ACTIVE_SEQ + active.env.flat (reviewer round-7)
// ============================================================================
//
// Cross-shell sync depends on three contracts. The original "writes
// API_KEY / BASE_URL" tests above don't pin them, so a future refactor
// could quietly drop:
//   1. AIKEY_ACTIVE_SEQ near the top of active.env (precmd's grep target)
//   2. seq monotonically advancing across refresh calls (atomic write
//      guarantee from the design doc's "seq 契约")
//   3. active.env.flat sibling file with PowerShell/cmd-friendly KEY=VALUE
//      (Windows deactivate path)
// These three tests pin each one.

#[test]
fn refresh_writes_aikey_active_seq_near_top() {
    let _dir = setup();
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "my-claude")
        .unwrap();
    profile_activation::refresh_implicit_profile_activation().unwrap();

    let home = std::env::var("HOME").unwrap();
    let env_path = std::path::PathBuf::from(&home).join(".aikey/active.env");
    let contents = std::fs::read_to_string(&env_path).expect("active.env should exist");

    // Format: `export AIKEY_ACTIVE_SEQ="<digits>"`. The hook precmd does
    // `grep -m1 -oE 'AIKEY_ACTIVE_SEQ="[0-9]+"' ... | grep -oE '[0-9]+'`,
    // so this exact shape matters — pin both the export prefix and the
    // quoted-digits payload.
    let line = contents.lines()
        .find(|l| l.starts_with("export AIKEY_ACTIVE_SEQ="))
        .expect("active.env must contain export AIKEY_ACTIVE_SEQ= line");
    assert!(
        line.contains("AIKEY_ACTIVE_SEQ=\""),
        "seq value must be double-quoted (precmd grep depends on this), got: {}",
        line
    );
    let value = line
        .trim_start_matches("export AIKEY_ACTIVE_SEQ=\"")
        .trim_end_matches('"');
    assert!(
        !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()),
        "AIKEY_ACTIVE_SEQ value must be a non-empty digit run, got: {:?}",
        value
    );

    // Position: precmd uses `grep -m1` so the seq line must appear early.
    // We're stricter than the smoke (top 5 lines) — pin to top 3.
    let head: Vec<&str> = contents.lines().take(3).collect();
    assert!(
        head.iter().any(|l| l.starts_with("export AIKEY_ACTIVE_SEQ=")),
        "AIKEY_ACTIVE_SEQ must appear in the first 3 lines, got:\n{}",
        head.join("\n")
    );
}

#[test]
fn refresh_seq_advances_monotonically() {
    let _dir = setup();
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "k1")
        .unwrap();

    let read_seq = || -> u64 {
        let home = std::env::var("HOME").unwrap();
        let env_path = std::path::PathBuf::from(&home).join(".aikey/active.env");
        let contents = std::fs::read_to_string(&env_path).unwrap();
        let line = contents.lines()
            .find(|l| l.starts_with("export AIKEY_ACTIVE_SEQ="))
            .expect("seq line must exist");
        let v = line.trim_start_matches("export AIKEY_ACTIVE_SEQ=\"").trim_end_matches('"');
        v.parse().expect("seq must parse as u64")
    };

    profile_activation::refresh_implicit_profile_activation().unwrap();
    let s1 = read_seq();
    profile_activation::refresh_implicit_profile_activation().unwrap();
    let s2 = read_seq();
    profile_activation::refresh_implicit_profile_activation().unwrap();
    let s3 = read_seq();

    // Strictly monotonic across consecutive refreshes — the precmd uses
    // this to detect "binding changed since I last sourced". Equality
    // would let a refresh go undetected and break cross-shell sync.
    assert!(s2 > s1, "seq must advance: s1={} s2={}", s1, s2);
    assert!(s3 > s2, "seq must advance: s2={} s3={}", s2, s3);
}

#[test]
fn refresh_writes_active_env_flat_for_windows() {
    let _dir = setup();
    storage::set_provider_binding(DEFAULT_PROFILE, "anthropic", "personal", "my-claude")
        .unwrap();
    profile_activation::refresh_implicit_profile_activation().unwrap();

    let home = std::env::var("HOME").unwrap();
    let flat_path = std::path::PathBuf::from(&home).join(".aikey/active.env.flat");
    let flat = std::fs::read_to_string(&flat_path)
        .expect("active.env.flat should exist when there are bindings");

    // Plain KEY=VALUE — no shell `export`, no shell expansion. PowerShell
    // / cmd parse it as `[Environment]::SetEnvironmentVariable($1, $2)`,
    // so any `${...}` literal would land as broken text in user env.
    for line in flat.lines() {
        if line.is_empty() { continue; }
        assert!(!line.starts_with("export "),
            "flat must not contain shell `export` prefix, got: {}", line);
        assert!(!line.contains("${"),
            "flat must not contain shell expansion ${{...}}, got: {}", line);
        // Each non-empty line is KEY=VALUE; nothing else.
        assert!(line.contains('='),
            "flat line must be KEY=VALUE, got: {}", line);
    }

    // Same payload as active.env but in flat form — the seq must be there
    // too so a Windows precmd-equivalent (when added) can use it.
    assert!(flat.contains("AIKEY_ACTIVE_SEQ="),
        "flat must carry AIKEY_ACTIVE_SEQ for Windows precmd parity, got:\n{}",
        flat);
    assert!(flat.contains("ANTHROPIC_API_KEY=aikey_active_anthropic"),
        "flat must carry the same env vars as active.env (no quoting), got:\n{}",
        flat);
}

#[test]
fn refresh_no_bindings_writes_flat_with_only_seq() {
    // Stage 1 contract: AIKEY_ACTIVE_SEQ is unconditionally written to
    // env_lines, which means .flat is always non-empty even when no
    // bindings exist (it carries just the seq). This is a behaviour
    // change from pre-Stage-1, where empty env_lines meant no .flat.
    //
    // Pin the new behaviour:
    //   - .flat exists
    //   - it has AIKEY_ACTIVE_SEQ=...
    //   - it does NOT have any *_API_KEY (no provider envs to clear)
    //
    // Why we keep .flat in the no-bindings case: a future Windows
    // precmd-equivalent will also want to detect "binary upgraded but
    // no key configured" via the seq line. Dropping .flat here would
    // make that scenario invisible to Windows shells.
    let _dir = setup();

    profile_activation::refresh_implicit_profile_activation().unwrap();

    let home = std::env::var("HOME").unwrap();
    let flat_path = std::path::PathBuf::from(&home).join(".aikey/active.env.flat");
    assert!(flat_path.exists(),
        "no bindings should still write .flat (carrying AIKEY_ACTIVE_SEQ)");

    let flat = std::fs::read_to_string(&flat_path).unwrap();
    assert!(flat.contains("AIKEY_ACTIVE_SEQ="),
        ".flat with no bindings should still carry the seq, got:\n{}", flat);
    assert!(!flat.contains("API_KEY"),
        ".flat with no bindings must not contain provider env, got:\n{}", flat);
}
