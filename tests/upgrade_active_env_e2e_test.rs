//! L6 Upgrade E2E (合约 A + 合约 B) for active.env auto-migration after the
//! 2026-04-29 token-prefix rename refactor.
//!
//! Two contracts the spec pins:
//!
//!   合约 A — Installer hook contract:
//!     `aikey _refresh-active-env --if-legacy` (callable by install/upgrade
//!     scripts). Idempotent on already-migrated input. No vault password
//!     required (binding table is unencrypted).
//!
//!   合约 B — CLI safety net contract:
//!     Every `aikey <subcmd>` invocation lightweight-detects legacy form
//!     and auto-rewrites. Covers the case where the installer hook
//!     didn't run (manual binary swap, machine-to-machine ~/.aikey/ copy).
//!
//! These are unit-level integration tests for the *contract surface* —
//! they don't spin up a real install/upgrade flow but they do verify the
//! exact behavior installer scripts and main.rs dispatch depend on.
//!
//! Spec: roadmap20260320/技术实现/update/20260429-token前缀重命名-e2e测试方案.md §9
//!       roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §modify §5

use aikeylabs_aikey_cli::active_env_migration::{self, RefreshOutcome};
use aikeylabs_aikey_cli::storage;
use secrecy::SecretString;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

/// HOME env-var override locking. Several tests mutate HOME to point at a
/// per-test tmpdir; without serialization parallel tests would clobber
/// each other.
static HOME_LOCK: Mutex<()> = Mutex::new(());

/// Set HOME to a fresh tmpdir for the duration of the test guard. Cleans
/// the tmpdir + restores HOME on drop.
struct ScopedHome {
    _guard: std::sync::MutexGuard<'static, ()>,
    prev: Option<String>,
    dir: PathBuf,
}

impl ScopedHome {
    fn new() -> Self {
        let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("HOME").ok();
        let dir = std::env::temp_dir().join(format!(
            "aikey-stage8-l6-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".aikey")).expect("create .aikey");
        std::env::set_var("HOME", &dir);
        ScopedHome { _guard: guard, prev, dir }
    }

    fn aikey_dir(&self) -> PathBuf {
        self.dir.join(".aikey")
    }

    fn active_env_path(&self) -> PathBuf {
        self.aikey_dir().join("active.env")
    }

    fn write_active_env(&self, contents: &str) {
        fs::write(self.active_env_path(), contents).expect("write active.env");
    }

    fn read_active_env(&self) -> String {
        fs::read_to_string(self.active_env_path()).unwrap_or_default()
    }
}

impl Drop for ScopedHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
        if let Some(prev) = &self.prev {
            std::env::set_var("HOME", prev);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

const LEGACY_TEAM: &str = r#"export ANTHROPIC_AUTH_TOKEN="aikey_vk_my-team-key"
export ANTHROPIC_BASE_URL="http://127.0.0.1:27200/anthropic"
export AIKEY_ACTIVE_KEYS="anthropic=my-team-key"
"#;

const LEGACY_PERSONAL_ALIAS: &str = r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_my-claude-account"
export AIKEY_ACTIVE_KEYS="anthropic=my-claude-account"
"#;

const NEW_FORMAT: &str = r#"# aikey active key — auto-generated, do not edit manually
export AIKEY_ACTIVE_SEQ="42"
export ANTHROPIC_AUTH_TOKEN="aikey_active_anthropic"
export AIKEY_ACTIVE_KEYS="anthropic=my-claude-account"
"#;

// ─────────────────────────────────────────────────────────────────────────
// 合约 A — Installer hook surface
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn contract_a_no_legacy_form_is_no_op() {
    // Calling `_refresh-active-env --if-legacy` on already-migrated state
    // must be a no-op. Idempotency requirement — installer scripts call
    // this on every upgrade/reinstall, so it must be safe to call repeatedly.
    let h = ScopedHome::new();
    h.write_active_env(NEW_FORMAT);

    let outcome = active_env_migration::refresh_active_env(true)
        .expect("refresh should succeed on no-legacy input");

    assert!(matches!(outcome, RefreshOutcome::NoLegacyDetected),
        "expected NoLegacyDetected, got {:?}", outcome);

    // active.env unchanged.
    assert_eq!(h.read_active_env(), NEW_FORMAT,
        "no-op refresh must not modify the file");
}

#[test]
fn contract_a_no_vault_yields_no_bindings_to_follow() {
    // Legacy form present + no vault.db (fresh install, never ran
    // `aikey add`/`aikey login`). Per spec failure策略 "provider 推不出 → no-op",
    // this is NOT an error — the user just has nothing to migrate to.
    // installer hook reports NoBindingsToFollow + the next `aikey use` will
    // overwrite cleanly.
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_TEAM);

    let outcome = active_env_migration::refresh_active_env(true)
        .expect("refresh should succeed (not error) when no vault is present");

    assert!(matches!(outcome, RefreshOutcome::NoBindingsToFollow),
        "expected NoBindingsToFollow when vault.db absent, got {:?}", outcome);

    // active.env still in legacy form (we didn't touch it because there's
    // nothing to follow). User's next `aikey use <key>` will overwrite.
    assert!(h.read_active_env().contains("aikey_vk_"),
        "active.env should remain in legacy form when migration is no-op");
}

#[test]
fn contract_a_detects_legacy_aikey_vk() {
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_TEAM);

    assert!(active_env_migration::active_env_has_legacy_form(),
        "must detect 'aikey_vk_' as legacy form");

    let _ = h;  // hold the guard
}

#[test]
fn contract_a_detects_legacy_personal_alias() {
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_PERSONAL_ALIAS);

    assert!(active_env_migration::active_env_has_legacy_form(),
        "must detect 'aikey_personal_<non-hex>' (legacy sentinel form) as legacy");

    let _ = h;
}

#[test]
fn contract_a_passes_new_active_sentinel() {
    let h = ScopedHome::new();
    h.write_active_env(NEW_FORMAT);

    assert!(!active_env_migration::active_env_has_legacy_form(),
        "must NOT classify the new aikey_active_<provider> form as legacy");

    let _ = h;
}

#[test]
fn contract_a_creates_backup_before_modification() {
    // When refresh actually rewrites (legacy detected + vault present),
    // it MUST first backup the current file to active.env.bak.<unix_ts>.
    // Test the backup_active_env helper directly since the full refresh
    // requires a working vault.
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_TEAM);

    let backup = active_env_migration::backup_active_env()
        .expect("backup should succeed on a writable dir");
    let path = backup.expect("backup must return a path when source file existed");
    assert!(path.exists(), "backup file {} must exist", path.display());

    // Backup contents match original.
    let backed_up = fs::read_to_string(&path).expect("read backup");
    assert_eq!(backed_up, LEGACY_TEAM, "backup must be byte-identical to original");

    let _ = h;
}

#[test]
fn contract_a_backup_no_op_when_source_missing() {
    // No active.env present → backup returns Ok(None), not an error.
    // This shape lets refresh_active_env handle "first ever install"
    // gracefully (refresh writes a fresh file with no prior to back up).
    let h = ScopedHome::new();
    // Don't write active.env.

    let outcome = active_env_migration::backup_active_env();
    match outcome {
        Ok(None) => {}  // expected
        other => panic!("expected Ok(None), got {:?}", other),
    }

    let _ = h;
}

#[test]
fn contract_a_backup_prunes_to_keep_3() {
    // Only the latest 3 backups should be retained — installer scripts
    // run repeatedly on every upgrade, so unbounded growth would fill the
    // user's disk over time. Spec failure策略 §5 caps at 3.
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_TEAM);

    // Create 5 backups in sequence (each one reads the current file +
    // writes a uniquely-named backup; the helper's prune step trims the
    // older ones at each call).
    for _ in 0..5 {
        active_env_migration::backup_active_env().expect("backup");
        // Sleep 1s to ensure distinct filenames (timestamp-based).
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let backup_count = fs::read_dir(h.aikey_dir())
        .expect("read aikey dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("active.env.bak."))
        .count();

    assert!(backup_count <= 3,
        "expected at most 3 backups after 5 iterations, found {}", backup_count);
    assert!(backup_count >= 1,
        "expected at least 1 backup, found {}", backup_count);
}

// ─────────────────────────────────────────────────────────────────────────
// 合约 B — CLI safety net contract surface (logic-level)
// ─────────────────────────────────────────────────────────────────────────
//
// The full main.rs safety-net path requires running the binary with a
// fresh HOME, which is what `e2e_smoke_tests` covers via assert_cmd. Here
// we test the LOGIC: every aikey_*-prefixed legacy form active.env must
// be detected by `active_env_has_legacy_form` so the safety net trigger
// fires at dispatch start.

#[test]
fn contract_b_safety_net_fires_for_aikey_vk() {
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_TEAM);

    // The safety net at main.rs line ~635 calls `active_env_has_legacy_form()`
    // and conditionally triggers refresh. This test pins the trigger condition.
    assert!(active_env_migration::active_env_has_legacy_form(),
        "safety net must fire on aikey_vk_ legacy form");

    let _ = h;
}

#[test]
fn contract_b_safety_net_fires_for_personal_alias() {
    let h = ScopedHome::new();
    h.write_active_env(LEGACY_PERSONAL_ALIAS);

    assert!(active_env_migration::active_env_has_legacy_form(),
        "safety net must fire on aikey_personal_<non-hex> legacy sentinel form");

    let _ = h;
}

#[test]
fn contract_b_safety_net_silent_on_already_new_format() {
    let h = ScopedHome::new();
    h.write_active_env(NEW_FORMAT);

    // The safety net branch at main.rs is skipped when this returns false —
    // pin "no spurious migration warning on every command".
    assert!(!active_env_migration::active_env_has_legacy_form(),
        "safety net must NOT fire on the new format");

    let _ = h;
}

#[test]
fn contract_b_safety_net_silent_when_active_env_absent() {
    let h = ScopedHome::new();
    // Don't write active.env — fresh install before any `aikey use`.

    assert!(!active_env_migration::active_env_has_legacy_form(),
        "safety net must NOT fire when active.env doesn't exist (fresh install)");

    let _ = h;
}

// ─────────────────────────────────────────────────────────────────────────
// Mixed-content edge cases — exploratory
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn safety_net_detects_legacy_in_mixed_active_env() {
    // Even if active.env happens to contain SOME new-form lines, a single
    // legacy line means safety net must fire (otherwise the legacy line
    // would silently fail at the proxy on every request from that shell).
    let h = ScopedHome::new();
    let mixed = format!("{}\n{}", LEGACY_TEAM, NEW_FORMAT);
    h.write_active_env(&mixed);

    assert!(active_env_migration::active_env_has_legacy_form(),
        "any single legacy line in active.env must trigger safety net");

    let _ = h;
}

// ─────────────────────────────────────────────────────────────────────────
// Path-resolution regression — AK_VAULT_PATH override must be honored
// (third-party review #4 finding [中], 2026-04-29)
// ─────────────────────────────────────────────────────────────────────────
//
// Why: the original `refresh_active_env` hard-coded the vault check to
// `~/.aikey/data/vault.db`, ignoring `AK_VAULT_PATH` / `AK_STORAGE_PATH`.
// In CI sandboxes, custom-deployment, or migration test setups the vault
// can live elsewhere — under the bug the "is vault present?" guard would
// return `NoBindingsToFollow` and silently skip the rewrite even though
// a perfectly valid vault existed at the override path. Legacy
// `aikey_vk_*` / `aikey_personal_<alias>` bearers would stay in
// active.env and fail at proxy 401 on every command in that env.
//
// This test reproduces that bug-case: HOME=tmpdir1 (active.env home),
// AK_VAULT_PATH=tmpdir2/custom_vault.db (vault home, fully separate from
// HOME). With the fix routing through `storage::get_vault_path()`, the
// guard sees the vault and proceeds to the actual refresh path; without
// the fix it returns NoBindingsToFollow.

#[test]
fn ak_vault_path_override_is_honored_during_refresh() {
    // Acquire HOME_LOCK so we don't race with other env-mutating tests.
    let home = ScopedHome::new();

    // Build a separate tmpdir for the vault, NOT under HOME/.aikey/data.
    let vault_dir = std::env::temp_dir().join(format!(
        "aikey-stage8-vault-override-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let _ = fs::remove_dir_all(&vault_dir);
    fs::create_dir_all(&vault_dir).expect("create vault dir");
    let custom_vault_path = vault_dir.join("custom-vault.db");

    // Snapshot prior AK_VAULT_PATH so we can restore on cleanup.
    let prev_ak_vault_path = std::env::var("AK_VAULT_PATH").ok();
    std::env::set_var("AK_VAULT_PATH", &custom_vault_path);

    // Create a real, openable vault at the override path. Empty/zero-byte
    // file would also exercise the path-resolution guard, but using a real
    // vault makes the assertion stronger: refresh must reach the
    // post-guard logic rather than just returning NoBindingsToFollow.
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let pw = SecretString::new("test_password_AK_VAULT_PATH".to_string());
    storage::initialize_vault(&salt, &pw).expect("init vault at AK_VAULT_PATH");

    // Confirm vault file is at the override location, and NOT at the
    // hard-coded HOME/.aikey/data/vault.db path that the buggy code probed.
    assert!(custom_vault_path.exists(),
        "vault must exist at AK_VAULT_PATH override");
    assert!(!home.aikey_dir().join("data/vault.db").exists(),
        "no vault should exist at the hard-coded HOME path; \
         test invariant is that AK_VAULT_PATH is the only vault location");

    // Stage legacy form in active.env so refresh has something to migrate.
    home.write_active_env(LEGACY_TEAM);

    // Pre-fix behavior: refresh_active_env probes
    // `resolve_aikey_dir().join("data/vault.db")`, finds nothing, returns
    // NoBindingsToFollow. Post-fix: it routes through
    // `storage::get_vault_path()` which honors AK_VAULT_PATH, finds the
    // vault at custom_vault_path, and proceeds.
    let outcome = active_env_migration::refresh_active_env(true);

    // Restore env BEFORE asserting so a panic doesn't leak the override
    // into subsequent tests in the same binary (HOME_LOCK serialization
    // already protects HOME, but AK_VAULT_PATH needs its own restore).
    match prev_ak_vault_path {
        Some(prev) => std::env::set_var("AK_VAULT_PATH", prev),
        None => std::env::remove_var("AK_VAULT_PATH"),
    }
    let _ = fs::remove_dir_all(&vault_dir);

    // The bug regression: outcome must NOT be NoBindingsToFollow when a
    // vault exists at AK_VAULT_PATH. It can be Err (downstream binding
    // read fails because there are no bindings yet) or Refreshed; either
    // proves the path-resolution guard saw the vault.
    let outcome = outcome.unwrap_or_else(|e| {
        // An Err result here is actually fine for the regression — it
        // means refresh proceeded past the no-vault guard and tripped on
        // some downstream step (e.g., binding lookup hit a known nonempty
        // vault that has zero bindings, or env didn't expose one of the
        // vault helpers). What we're pinning is *not* NoBindingsToFollow.
        panic!("refresh_active_env returned Err (acceptable for this regression test if it means the vault was opened, but not the path we want to assert): {}", e)
    });
    assert!(!matches!(outcome, RefreshOutcome::NoBindingsToFollow),
        "refresh must NOT return NoBindingsToFollow when a valid vault exists \
         at AK_VAULT_PATH override (got {:?}); this is the third-party review #4 \
         [中] finding regression — `refresh_active_env` ignored AK_VAULT_PATH \
         and probed the hard-coded home path instead", outcome);
}

#[test]
fn safety_net_distinguishes_uppercase_hex_as_legacy() {
    // `aikey_personal_<64-uppercase-hex>`: not a legitimate new form
    // (proxy's isTier1Personal rejects uppercase). Treat as legacy to
    // force regeneration in lowercase.
    let h = ScopedHome::new();
    let upper_hex = "ABCDEF0123456789".repeat(4);  // 64 chars, mixed (uppercase + digits)
    let env = format!(r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_{}""#, upper_hex);
    h.write_active_env(&env);

    assert!(active_env_migration::active_env_has_legacy_form(),
        "uppercase hex personal bearer must be classified as legacy");

    let _ = h;
}

#[test]
fn safety_net_passes_strict_64hex_bearer_as_new_form() {
    // The legitimate new bearer form `aikey_personal_<64-lowercase-hex>` is
    // valid and must NOT trigger migration.
    let h = ScopedHome::new();
    let lower_hex = "0123456789abcdef".repeat(4);  // 64 lowercase hex
    let env = format!(r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_{}""#, lower_hex);
    h.write_active_env(&env);

    assert!(!active_env_migration::active_env_has_legacy_form(),
        "strict 64-hex personal bearer is the legitimate new form, not legacy");

    let _ = h;
}
