//! Output-format pins for `aikey route` — complements
//! `e2e_route_activate_consistency` which only checks URL equality.
//!
//! These tests lock in the contracts that users actually copy from the
//! quickstart docs. Breaking them means the docs need updating too.

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
        let tmp = std::env::temp_dir()
            .join(format!("aikey-e2e-route-{}-{}", tag, std::process::id()));
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
        assert!(out.status.success(),
            "add {}/{} failed: {}", alias, provider,
            String::from_utf8_lossy(&out.stderr));
    }
}

/// Strip ANSI CSI escape sequences so substring matching is stable across
/// terminal settings.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut escape = false;
    for c in s.chars() {
        if escape {
            if c.is_ascii_alphabetic() { escape = false; }
            continue;
        }
        if c == '\x1b' { escape = true; continue; }
        out.push(c);
    }
    out
}

// ── table view: columns + sections + separators ─────────────────────────

#[test]
fn route_table_has_expected_columns() {
    let env = Env::new("cols");
    env.add_key("my-openai", "openai");
    let out = env.cmd().arg("route").output().expect("spawn");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));

    // Header row is on stderr (table is informational).
    for col in &["PROVIDER", "LABEL", "API_KEY", "BASE URL"] {
        assert!(stderr.contains(col),
            "route header missing '{}' column:\n{}", col, stderr);
    }
    // A row should contain the alias + a truncated token + the base_url.
    assert!(stderr.contains("my-openai"),
        "route row missing alias:\n{}", stderr);
    // 2026-04-29 prefix rename: route_token form is now aikey_personal_<64-hex>.
    assert!(stderr.contains("aikey_personal_"),
        "route row missing token prefix:\n{}", stderr);
    assert!(stderr.contains("http://127.0.0.1:") && stderr.contains("/openai"),
        "route row missing proxy base URL:\n{}", stderr);
}

#[test]
fn route_default_truncates_token_but_full_flag_shows_it_all() {
    let env = Env::new("trunc");
    env.add_key("tr-key", "anthropic");

    let default_out = env.cmd().arg("route").output().unwrap();
    let default_err = strip_ansi(&String::from_utf8_lossy(&default_out.stderr));
    // Truncation uses "..." inside the displayed token.
    assert!(default_err.contains("..."),
        "default route should truncate tokens:\n{}", default_err);

    let full_out = env.cmd().args(["route", "--full"]).output().unwrap();
    let full_err = strip_ansi(&String::from_utf8_lossy(&full_out.stderr));
    // --full must emit at least one 64-hex char token in full (no ellipsis in the token).
    let full_token_present = full_err.split_whitespace().any(|w| {
        w.strip_prefix("aikey_personal_")
            .map(|tail| tail.len() >= 64 && tail.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
    });
    assert!(full_token_present,
        "--full should print the entire 64-hex-char token:\n{}", full_err);
}

#[test]
fn route_shows_active_marker_for_selected_key() {
    let env = Env::new("active");
    env.add_key("only-key", "openai");
    // First add creates a binding automatically (Primary for openai).
    // The active marker `●` should appear on that row.
    let out = env.cmd().arg("route").output().unwrap();
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(stderr.contains('\u{25cf}'),
        "route should show `●` (active marker) for the key made Primary on add:\n{}", stderr);
    // The legend should explain what `●` means.
    assert!(stderr.contains("active") || stderr.contains("Active"),
        "route footer should explain the active marker:\n{}", stderr);
}

#[test]
fn route_empty_vault_prints_friendly_hint() {
    let env = Env::new("empty");
    // Still need to bootstrap the vault (otherwise route prompts for password).
    env.add_key("boot", "openai");
    env.cmd().args(["delete", "boot"]).output().unwrap();

    let out = env.cmd().arg("route").output().expect("spawn");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    // Must not crash; should hint how to add a key.
    assert!(out.status.success(),
        "route on empty vault should exit 0, got: {}\nstderr: {}",
        out.status, stderr);
    assert!(stderr.contains("aikey add") || stderr.contains("aikey auth login"),
        "empty-vault route should guide the user:\n{}", stderr);
}

// ── JSON mode ───────────────────────────────────────────────────────────

#[test]
fn route_json_mode_emits_parseable_json_with_schema() {
    let env = Env::new("json");
    env.add_key("json-key", "anthropic");

    let out = env.cmd().args(["route", "--json"]).output().unwrap();
    assert!(out.status.success(), "route --json should exit 0");

    // `json_output::success` writes to stderr (so stdout stays clean for
    // pipe-chained tools). Parse whichever channel carries JSON.
    let blob = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let start = blob.find('{').expect("route --json has no JSON object");
    let end = blob.rfind('}').expect("route --json has unbalanced braces");
    let v: serde_json::Value = serde_json::from_str(&blob[start..=end])
        .unwrap_or_else(|e| panic!("route --json invalid JSON: {}\n--- raw ---\n{}", e, blob));

    assert_eq!(v["status"], "success");
    let routes = v["routes"].as_array().expect("routes must be array");
    assert_eq!(routes.len(), 1, "expected 1 route, got {}", routes.len());
    let r = &routes[0];
    for key in &["label", "provider", "type", "api_key", "base_url", "active"] {
        assert!(r.get(key).is_some(), "route JSON entry missing '{}' field:\n{}", key, r);
    }
    assert_eq!(r["label"], "json-key");
    assert_eq!(r["provider"], "anthropic");
    assert!(r["api_key"].as_str().unwrap().starts_with("aikey_personal_"),
        "api_key should use aikey_personal_ prefix: {}", r["api_key"]);
}

// ── single-label copy-paste view ────────────────────────────────────────

#[test]
fn route_single_label_emits_copy_paste_block_on_stdout() {
    let env = Env::new("single");
    env.add_key("cp-key", "openai");

    let out = env.cmd().args(["route", "cp-key"]).output().unwrap();
    assert!(out.status.success());
    // H1 regression: the copy-paste block must be on STDOUT so
    // `aikey route cp-key | pbcopy` (documented in quickstart) works.
    let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(stdout.contains("base_url"),
        "single-label route should print 'base_url' on stdout:\n{}", stdout);
    assert!(stdout.contains("api_key"),
        "single-label route should print 'api_key' on stdout:\n{}", stdout);
    assert!(stdout.contains("aikey_personal_"),
        "single-label route should print the token on stdout:\n{}", stdout);
    assert!(stdout.contains("http://127.0.0.1:"),
        "single-label route should print the base URL on stdout:\n{}", stdout);
}

// ── synced_inactive filter behaviour ────────────────────────────────────
//
// Context: 2026-04-16 pre-release audit
// (workflow/CI/bugfix/20260416-pre-release-audit-4-fixes.md, Bug 4)
// flagged a divergence where `aikey route` HID keys with
// `local_state=synced_inactive` while `aikey activate` ACCEPTED them,
// confusing users.
//
// The bugfix tightened `activate` to reject synced_inactive keys. AFTER
// that, the `route` command was independently revised to show them again
// — matching `aikey list`, per the comment at main.rs::handle_route
// ("so aikey route mirrors aikey list"). So the current state is:
//
//   aikey list       → shows synced_inactive  (status column explains it)
//   aikey route      → shows synced_inactive  (current design, post-revision)
//   aikey activate   → REJECTS synced_inactive with "Run aikey key sync"
//
// That's still a minor inconsistency (route invites copy-pasting a token
// the proxy won't register until sync), but it's the documented current
// behavior. These tests pin BOTH directions so any future change forces
// a deliberate update on both sides.
//
// We fabricate the synced_inactive state by INSERT-ing directly into
// `managed_virtual_keys_cache` — there's no CLI path to that state
// (the sync pipeline produces it from server responses).

fn insert_team_key(vault_db: &std::path::Path, virtual_key_id: &str, alias: &str, local_state: &str) {
    let conn = rusqlite::Connection::open(vault_db).expect("open vault.db");
    conn.execute(
        "INSERT INTO managed_virtual_keys_cache (
            virtual_key_id, org_id, seat_id, alias,
            provider_code, base_url,
            credential_id, credential_revision, virtual_key_revision,
            local_state
         ) VALUES (?1, 'test-org', 'test-seat', ?2,
            'anthropic', 'https://api.anthropic.com',
            'cred-1', '1', '1',
            ?3)",
        rusqlite::params![virtual_key_id, alias, local_state],
    )
    .expect("insert team key fixture");
}

#[test]
fn route_shows_synced_inactive_team_keys() {
    // `aikey route` mirrors `aikey list`: a team key that has been synced
    // to this device (metadata present) but not yet delivered (key material
    // absent) is still visible so the user knows it exists. The `●` active
    // marker separately signals which keys the proxy is actually serving.
    let env = Env::new("synced-inactive-shown");
    env.add_key("bootstrap-personal", "openai");
    let vault = env.tmp.join(".aikey/data/vault.db");

    insert_team_key(&vault, "synced_inactive_xyz", "team-not-yet-delivered",
                    "synced_inactive");

    let out = env.cmd().arg("route").output().expect("spawn route");
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    ));

    assert!(combined.contains("team-not-yet-delivered"),
        "aikey route should show synced_inactive team keys (mirrors aikey list).\n\
         --- combined ---\n{}", combined);
}

#[test]
fn activate_rejects_synced_inactive_team_key() {
    // Regression test for 2026-04-16 Bug 4: `aikey activate` MUST reject
    // keys with `local_state=synced_inactive` and point users at
    // `aikey key sync`. Before the fix, activate silently accepted them
    // and produced a token that 401ed at the proxy.
    let env = Env::new("synced-inactive-reject");
    env.add_key("bootstrap-personal", "openai");
    let vault = env.tmp.join(".aikey/data/vault.db");

    insert_team_key(&vault, "synced_inactive_reject_abc",
                    "stale-team-key", "synced_inactive");

    let out = env.cmd()
        .args(["activate", "stale-team-key", "--shell", "bash"])
        .output()
        .expect("spawn activate");
    assert!(!out.status.success(),
        "activate of synced_inactive key MUST fail (regression: \
         2026-04-16 Bug 4). stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not available")
            || stderr.contains("synced_inactive")
            || stderr.contains("not ready"),
        "activate error should explain the state, got:\n{}", stderr);
    assert!(stderr.contains("aikey key sync"),
        "activate error MUST point users at `aikey key sync` to recover, got:\n{}",
        stderr);
}

#[test]
fn route_shows_team_keys_with_active_state() {
    // Complement: team keys with local_state=active MUST appear in route
    // — otherwise the filter is too aggressive and hides usable keys.
    let env = Env::new("active-shown");
    env.add_key("bootstrap-personal", "openai");
    let vault = env.tmp.join(".aikey/data/vault.db");

    insert_team_key(&vault, "active_abc", "team-delivered", "active");

    let out = env.cmd().arg("route").output().expect("spawn route");
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));

    assert!(stderr.contains("team-delivered"),
        "route MUST show team keys with local_state=active:\n{}", stderr);
}

#[test]
fn route_unknown_label_errors_with_guidance() {
    let env = Env::new("unknown");
    env.add_key("real-key", "openai");

    let out = env.cmd().args(["route", "nonexistent"]).output().unwrap();
    assert!(!out.status.success(),
        "unknown label should exit non-zero, got: {}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not found") || stderr.contains("Not found"),
        "unknown label error should say 'not found':\n{}", stderr);
    assert!(stderr.contains("aikey route"),
        "error should hint running `aikey route` to list available routes:\n{}", stderr);
}
