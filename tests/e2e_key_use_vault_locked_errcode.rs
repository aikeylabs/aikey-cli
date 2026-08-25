//! Regression: `aikey key use` on an undelivered team key, with no TTY and no
//! cached master password, must fail with the machine-readable code
//! `VAULT_LOCKED_NO_CACHED_PASSWORD` — not a bare sentence.
//!
//! Why this matters: the tray panel spawns exactly this invocation (no TTY)
//! when the user clicks a team-key radio in the route list. The panel's only
//! recovery path — its in-panel master-password unlock form — triggers on the
//! ERROR CODE in the CLI's output (fallback/page.html, act()). Before the fix
//! the refusal was a raw string ("Set AK_TEST_PASSWORD or run from an
//! interactive terminal"), so a GUI user hit a dead end on winpc2 (2026-08-25).
//!
//! Bugfix: workflow/CI/bugfix/2026-08-25-tray-team-key-switch-locked-vault-dead-end.md

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

/// Self-contained CLI environment; dropping cleans up.
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
        let tmp =
            std::env::temp_dir().join(format!("aikey-e2e-uselock-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".aikey/data")).expect("mkdir");
        Self { tmp }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(bin_path());
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.tmp)
            .env("AK_VAULT_PATH", self.tmp.join(".aikey/data/vault.db"))
            .env("AK_TEST_PASSWORD", "e2e-pw")
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    fn add_key(&self, alias: &str, provider: &str) {
        let out = self
            .cmd()
            .args(["add", alias, "--provider", provider])
            .env("AK_TEST_SECRET", "sk-e2e-fake")
            .output()
            .expect("spawn add");
        assert!(
            out.status.success(),
            "add {}/{} failed: {}",
            alias,
            provider,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A team key synced to this device (metadata present) whose key material has
/// NOT been delivered (`provider_key_ciphertext` NULL, `share_status`
/// pending_claim per column default). This is the state a freshly-assigned
/// team key is in until the first password-bearing sync.
fn insert_undelivered_team_key(vault_db: &std::path::Path, virtual_key_id: &str, alias: &str) {
    let conn = rusqlite::Connection::open(vault_db).expect("open vault.db");
    conn.execute(
        "INSERT INTO managed_virtual_keys_cache (
            virtual_key_id, org_id, seat_id, alias,
            provider_code, base_url,
            credential_id, credential_revision, virtual_key_revision,
            local_state
         ) VALUES (?1, 'test-org', 'test-seat', ?2,
            'openai', 'https://api.openai.com',
            'cred-1', '1', '1',
            'synced_inactive')",
        rusqlite::params![virtual_key_id, alias],
    )
    .expect("insert team key fixture");
}

#[test]
fn key_use_without_password_carries_vault_locked_code() {
    let env = Env::new("errcode");
    // `add` initialises the vault (master password from AK_TEST_PASSWORD).
    env.add_key("bootstrap-personal", "openai");
    let vault = env.tmp.join(".aikey/data/vault.db");

    insert_undelivered_team_key(&vault, "vk-pending-errcode", "team-pending");

    // The tray's exact spawn shape: no TTY (stdin is null), and no password
    // source — AK_TEST_PASSWORD removed, no session file, no keychain meta in
    // this fresh HOME.
    let out = env
        .cmd()
        .args(["key", "use", "team-pending"])
        .env_remove("AK_TEST_PASSWORD")
        .output()
        .expect("spawn key use");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    assert!(
        !out.status.success(),
        "key use must refuse without a master password.\n--- combined ---\n{}",
        combined
    );
    // The load-bearing property: the CODE, not the sentence — and on the
    // REFUSAL LINE itself. aikey-tray's panel (act() in fallback/page.html)
    // and servicebridge.IsVaultLocked match on this literal to offer the
    // in-panel unlock form. `combined` is not enough: when the local proxy
    // happens to be down, an unrelated unattended-proxy-start warning earlier
    // in the output also carries the code (observed while writing this test),
    // and on the real tray machine the proxy IS running, so that bypass line
    // is absent and the refusal must carry the code by itself.
    let refusal = combined
        .lines()
        .find(|l| l.contains("Error"))
        .unwrap_or_else(|| panic!("no Error line in output:\n{}", combined));
    assert!(
        refusal.contains("VAULT_LOCKED_NO_CACHED_PASSWORD"),
        "the refusal line must carry ERRCODE_VAULT_LOCKED_NO_CACHED_PASSWORD so \
         the tray can open its unlock form.\n--- refusal ---\n{}\n--- combined ---\n{}",
        refusal,
        combined
    );
    // The remedy must not advertise the test-only env var to end users.
    assert!(
        !combined.contains("AK_TEST_PASSWORD"),
        "test-only env var leaked into user-facing guidance.\n--- combined ---\n{}",
        combined
    );
}
