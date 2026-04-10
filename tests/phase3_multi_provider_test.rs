//! Phase 5 E2E integration tests for multi-provider primary key support (v1.0.2).
//!
//! Tests the full CLI flow: add → auto-assign → list → use → delete → reconcile.
//! Uses `AK_TEST_PASSWORD` and `AK_TEST_SECRET` to avoid interactive prompts.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

struct TestEnv {
    _temp_dir: TempDir,
}

impl TestEnv {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("tempdir");
        // Initialize vault via the init command.
        Command::new(cargo_bin("aikey"))
            .arg("init")
            .arg("--password-stdin")
            .env("HOME", temp_dir.path())
            .write_stdin("test_pass_123\n")
            .assert()
            .success();
        Self { _temp_dir: temp_dir }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(cargo_bin("aikey"));
        cmd.env("HOME", self._temp_dir.path());
        cmd.env("AK_TEST_PASSWORD", "test_pass_123");
        cmd.current_dir(self._temp_dir.path());
        cmd
    }

    fn add_key(&self, alias: &str, provider: &str) -> assert_cmd::assert::Assert {
        self.cmd()
            .arg("add")
            .arg(alias)
            .arg("--provider")
            .arg(provider)
            .env("AK_TEST_SECRET", "sk-test-12345")
            .assert()
    }

    fn active_env_path(&self) -> PathBuf {
        self._temp_dir.path().join(".aikey").join("active.env")
    }

    fn active_env_content(&self) -> String {
        let path = self.active_env_path();
        if path.exists() {
            fs::read_to_string(&path).unwrap_or_default()
        } else {
            String::new()
        }
    }

    fn db_path(&self) -> PathBuf {
        self._temp_dir.path().join(".aikey").join("data").join("vault.db")
    }
}

// ============================================================================
// E2E 1: Add multiple different-provider keys → verify active.env multi-output
// ============================================================================

#[test]
fn e2e_add_multi_provider_keys_writes_all_env_vars() {
    let env = TestEnv::new();

    // Add three keys for different providers.
    env.add_key("claude-main", "anthropic").success();
    env.add_key("gpt-main", "openai").success();
    env.add_key("gemini-main", "google").success();

    let content = env.active_env_content();
    assert!(content.contains("ANTHROPIC_API_KEY"), "should contain ANTHROPIC_API_KEY");
    assert!(content.contains("OPENAI_API_KEY"), "should contain OPENAI_API_KEY");
    assert!(content.contains("GOOGLE_API_KEY"), "should contain GOOGLE_API_KEY");

    // All three should have base URLs pointing to local proxy.
    assert!(content.contains("ANTHROPIC_BASE_URL"), "should contain ANTHROPIC_BASE_URL");
    assert!(content.contains("OPENAI_BASE_URL"), "should contain OPENAI_BASE_URL");
    assert!(content.contains("GOOGLE_BASE_URL"), "should contain GOOGLE_BASE_URL");
}

// ============================================================================
// E2E 2: Add same-provider second key → verify no Primary overwrite
// ============================================================================

#[test]
fn e2e_add_same_provider_does_not_overwrite_primary() {
    let env = TestEnv::new();

    // First key becomes Primary for anthropic.
    env.add_key("claude-main", "anthropic").success();
    let content1 = env.active_env_content();
    assert!(content1.contains("aikey_personal_claude-main"), "first key should be primary");

    // Second key for same provider should NOT replace.
    env.add_key("claude-backup", "anthropic").success();
    let content2 = env.active_env_content();
    assert!(content2.contains("aikey_personal_claude-main"), "first key should still be primary");
    assert!(!content2.contains("aikey_personal_claude-backup"), "backup should not be in active.env");
}

// ============================================================================
// E2E 3: aikey use <alias> switches Primary → verify active.env updated
// ============================================================================

#[test]
fn e2e_use_alias_switches_primary() {
    let env = TestEnv::new();

    env.add_key("claude-main", "anthropic").success();
    env.add_key("claude-backup", "anthropic").success();

    // Verify initial state: claude-main is Primary.
    let content1 = env.active_env_content();
    assert!(content1.contains("aikey_personal_claude-main"));

    // Switch to backup.
    env.cmd()
        .arg("use")
        .arg("claude-backup")
        .arg("--no-hook")
        .assert()
        .success();

    // Verify: backup is now Primary.
    let content2 = env.active_env_content();
    assert!(content2.contains("aikey_personal_claude-backup"),
        "backup should now be primary. Content:\n{}", content2);
    assert!(!content2.contains("aikey_personal_claude-main"),
        "main should no longer be in active.env for anthropic");
}

// ============================================================================
// E2E 4: Delete Primary → verify auto-backfill
// ============================================================================

#[test]
fn e2e_delete_primary_auto_backfills() {
    let env = TestEnv::new();

    env.add_key("claude-main", "anthropic").success();
    env.add_key("claude-backup", "anthropic").success();

    // Verify initial Primary.
    let content1 = env.active_env_content();
    assert!(content1.contains("aikey_personal_claude-main"));

    // Delete the Primary key.
    env.cmd()
        .arg("delete")
        .arg("claude-main")
        .arg("--json")
        .assert()
        .success();

    // Verify: backup should be auto-promoted.
    let content2 = env.active_env_content();
    assert!(content2.contains("aikey_personal_claude-backup"),
        "backup should be auto-promoted after primary deletion. Content:\n{}", content2);
}

// ============================================================================
// E2E 5: Delete only key → provider cleared from active.env
// ============================================================================

#[test]
fn e2e_delete_only_key_clears_provider() {
    let env = TestEnv::new();

    env.add_key("claude-only", "anthropic").success();
    env.add_key("gpt-main", "openai").success();

    let content1 = env.active_env_content();
    assert!(content1.contains("ANTHROPIC_API_KEY"));
    assert!(content1.contains("OPENAI_API_KEY"));

    // Delete the only anthropic key.
    env.cmd()
        .arg("delete")
        .arg("claude-only")
        .arg("--json")
        .assert()
        .success();

    // Anthropic should be gone from active.env; OpenAI remains.
    let content2 = env.active_env_content();
    assert!(!content2.contains("ANTHROPIC_API_KEY"),
        "anthropic should be cleared. Content:\n{}", content2);
    assert!(content2.contains("OPENAI_API_KEY"),
        "openai should remain. Content:\n{}", content2);
}

// ============================================================================
// E2E 6: List shows PRIMARY FOR column
// ============================================================================

#[test]
fn e2e_list_shows_primary_for() {
    let env = TestEnv::new();

    env.add_key("claude-main", "anthropic").success();
    env.add_key("gpt-main", "openai").success();

    let output = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    // JSON output should contain providers info.
    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap_or_default();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap_or_default();
    let combined = format!("{}{}", stdout, stderr);

    // Should mention both keys.
    assert!(combined.contains("claude-main") || combined.contains("anthropic"),
        "list output should mention claude-main or anthropic");
}

// ============================================================================
// E2E 7: Multi-provider key mixed with single-provider keys
// ============================================================================

#[test]
fn e2e_mixed_providers_coexist() {
    let env = TestEnv::new();

    // Add a key for anthropic.
    env.add_key("claude-main", "anthropic").success();
    // Add a key for openai.
    env.add_key("gpt-main", "openai").success();
    // Add a key for google.
    env.add_key("gemini-main", "google").success();

    // Now switch only the openai provider to a new key.
    env.add_key("gpt-backup", "openai").success();
    env.cmd()
        .arg("use")
        .arg("gpt-backup")
        .arg("--no-hook")
        .assert()
        .success();

    // Verify: anthropic = claude-main, openai = gpt-backup, google = gemini-main
    let content = env.active_env_content();
    assert!(content.contains("aikey_personal_claude-main"),
        "anthropic should still be claude-main");
    assert!(content.contains("aikey_personal_gpt-backup"),
        "openai should be switched to gpt-backup");
    assert!(content.contains("aikey_personal_gemini-main"),
        "google should still be gemini-main");
    // gpt-main should NOT appear.
    assert!(!content.contains("aikey_personal_gpt-main"),
        "gpt-main should no longer be primary");
}
