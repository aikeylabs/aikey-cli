//! Security/data-safety regression tests — pin fixes that MUST NOT regress.
//!
//! Each test references the bugfix record it guards so future engineers can
//! trace intent back to the original incident.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

// ── test harness ────────────────────────────────────────────────────────

struct Env {
    tmp: PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        if std::env::var("AIKEY_E2E_KEEP_TMPDIR").as_deref() != Ok("1") {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }
}

impl Env {
    fn new(tag: &str) -> Self {
        let tmp = std::env::temp_dir()
            .join(format!("aikey-e2e-sec-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".aikey/data")).expect("mkdir");
        Self { tmp }
    }

    fn vault_path(&self) -> PathBuf {
        self.tmp.join(".aikey/data/vault.db")
    }

    /// Build a command preloaded with HOME + vault path + the given password.
    fn cmd_with_password(&self, password: &str) -> Command {
        let mut c = Command::new(bin_path());
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.tmp)
            .env("AK_VAULT_PATH", self.vault_path())
            .env("AK_TEST_PASSWORD", password)
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    fn add_key(&self, password: &str, alias: &str, provider: &str, secret: &str) {
        let out = self
            .cmd_with_password(password)
            .args(["add", alias, "--provider", provider])
            .env("AK_TEST_SECRET", secret)
            .output()
            .expect("spawn add");
        assert!(out.status.success(),
            "add {} failed: {}", alias, String::from_utf8_lossy(&out.stderr));
    }

    /// Open the SQLite file with rusqlite directly so tests can simulate the
    /// "password_hash missing" condition exercised by the 2026-04-11 bug.
    fn open_db_direct(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.vault_path()).expect("open vault.db")
    }
}

// ── 2026-04-11: vault password bypass when password_hash missing ────────
// Ref: workflow/CI/bugfix/20260411-vault-password-bypass-on-missing-hash.md
//
// Before the fix: vaults without `password_hash` in `config` accepted ANY
// password and silently stored the wrong key as the new hash, encrypting
// subsequent entries against a bogus key.

#[test]
fn wrong_password_rejected_when_password_hash_missing() {
    let env = Env::new("pwbypass-wrong");

    // 1. Create a vault the normal way (seeds password_hash).
    env.add_key("correct-password", "k1", "openai", "sk-real");

    // 2. Simulate a pre-fix vault: drop the password_hash record. The vault
    // still has entries, so verify() MUST reject a wrong password by trying
    // to decrypt an existing entry — NOT accept anything as the new hash.
    {
        let conn = env.open_db_direct();
        let deleted = conn
            .execute("DELETE FROM config WHERE key = 'password_hash'", [])
            .expect("delete hash");
        assert!(deleted > 0, "password_hash row should have existed");
    }

    // 3. Try to add another key with a WRONG password. Must fail.
    let out = env
        .cmd_with_password("wrong-password")
        .args(["add", "k2", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-also-real")
        .output()
        .expect("spawn add");
    assert!(!out.status.success(),
        "wrong password MUST be rejected when password_hash missing — the 2026-04-11 \
         bug allowed ANY password and silently stored it as the new hash.\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Invalid master password")
            || stderr.contains("invalid")
            || stderr.contains("corrupted"),
        "rejection message should mention password validity, got:\n{}",
        stderr
    );
}

#[test]
fn correct_password_still_works_when_password_hash_missing() {
    let env = Env::new("pwbypass-right");
    env.add_key("correct-pw", "k1", "openai", "sk-1");

    // Simulate the missing-hash condition.
    env.open_db_direct()
        .execute("DELETE FROM config WHERE key = 'password_hash'", [])
        .expect("delete hash");

    // Correct password must still work — the fix should verify by decrypting
    // an existing entry, not lock the user out.
    let out = env
        .cmd_with_password("correct-pw")
        .args(["add", "k2", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-2")
        .output()
        .expect("spawn add");
    assert!(out.status.success(),
        "correct password MUST still work even with password_hash missing.\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
}

// ── aikey db upgrade/rollback smoke ─────────────────────────────────────
// db is hidden from --help because it's an internal escape hatch. These
// tests just ensure the sub-commands are reachable and don't panic on a
// normal vault.

#[test]
fn db_help_lists_upgrade_and_rollback() {
    let out = Command::new(bin_path())
        .args(["db", "--help"])
        .output()
        .expect("spawn db --help");
    assert!(out.status.success());
    // `db` is an internal escape-hatch subcommand (hidden from top-level --help)
    // so its own --help goes to stderr. Accept either channel to stay tolerant.
    let h = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(h.contains("upgrade"),
        "db --help should list `upgrade`:\n{}", h);
    assert!(h.contains("rollback"),
        "db --help should list `rollback`:\n{}", h);
}

#[test]
fn db_upgrade_is_idempotent_on_current_vault() {
    let env = Env::new("db-upgrade");
    // Bootstrap a vault — migrations run automatically here.
    env.add_key("pw", "k1", "openai", "sk-1");

    // Running `db upgrade` a second time must be a safe no-op (= exit 0 with
    // "nothing to do" semantics). If this panics or reports schema changes
    // on an already-current vault, something is wrong with the migration
    // registration.
    let out = env
        .cmd_with_password("pw")
        .args(["db", "upgrade"])
        .output()
        .expect("spawn db upgrade");
    assert!(out.status.success(),
        "`db upgrade` on current vault should succeed (idempotent), got:\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
}

#[test]
fn db_upgrade_then_add_leaves_vault_usable() {
    // Defence against "upgrade corrupts schema" regressions: after an
    // explicit upgrade pass the vault must still accept writes normally.
    let env = Env::new("db-then-add");
    env.add_key("pw", "k1", "openai", "sk-1");

    let upgrade = env
        .cmd_with_password("pw")
        .args(["db", "upgrade"])
        .output()
        .unwrap();
    assert!(upgrade.status.success());

    // A follow-up add against the upgraded vault must succeed.
    let add = env
        .cmd_with_password("pw")
        .args(["add", "k2", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-2")
        .output()
        .unwrap();
    assert!(add.status.success(),
        "add after `db upgrade` must work.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr));

    // And list must show both keys.
    let list = env
        .cmd_with_password("pw")
        .arg("list")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("k1") && stdout.contains("k2"),
        "list should show both keys after upgrade:\n{}", stdout);
}
