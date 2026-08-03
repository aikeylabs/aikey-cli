//! Live end-to-end proof for `aikey use` two-axis summary + the
//! "Select provider(s)" mislabel fix (P1f.11, model-mapping-egress).
//!
//! Why this exists: the two-axis summary + mislabel fix shipped in
//! e9fa37f were verified only by unit/lib tests. This test drives the REAL
//! compiled `aikey` binary against a REAL seeded vault.db (team VK cache row
//! written through the same `storage::upsert_virtual_key_cache` the member-rail
//! sync uses) so the rendered output is captured end-to-end — no live platform
//! backend required (P7 infra is blocked).
//!
//! Run:  cargo test --test e2e_use_two_axis_live -- --nocapture

use aikeylabs_aikey_cli::{crypto, storage};
use secrecy::SecretString;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const PW: &str = "e2e-two-axis-pw";

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

/// Base env every invocation of the real binary shares: isolated HOME + vault.
fn base_cmd(home: &PathBuf, vault: &PathBuf) -> Command {
    let mut c = Command::new(bin());
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AK_VAULT_PATH", vault)
        .env("AK_TEST_PASSWORD", PW)
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1");
    c
}

/// Build a full team-VK cache row (P1e re-grained: one row per binding).
#[allow(clippy::too_many_arguments)]
fn vk_row(
    id: &str,
    alias: &str,
    provider: &str,
    protocol: &str,
    base_url: &str,
    supported: &[&str],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> storage::VirtualKeyCacheEntry {
    storage::VirtualKeyCacheEntry {
        binding_id: String::new(),
        virtual_key_id: id.to_string(),
        org_id: "org-e2e".to_string(),
        seat_id: "seat-e2e".to_string(),
        alias: alias.to_string(),
        provider_code: provider.to_string(),
        protocol_type: protocol.to_string(),
        base_url: base_url.to_string(),
        credential_id: format!("cred-{id}"),
        credential_revision: "1".to_string(),
        virtual_key_revision: "1".to_string(),
        key_status: "active".to_string(),
        share_status: "accepted".to_string(),
        local_state: "active".to_string(),
        expires_at: None,
        provider_key_nonce: Some(nonce),
        provider_key_ciphertext: Some(ciphertext),
        synced_at: 1,
        local_alias: None,
        supported_providers: supported.iter().map(|s| s.to_string()).collect(),
        provider_base_urls: {
            let mut m = HashMap::new();
            for s in supported {
                m.insert(s.to_string(), base_url.to_string());
            }
            m
        },
        // P0a task 1.2b: the chain columns. A legacy fixture is priority 1 /
        // primary / no group — the pre-upgrade single-shot shape, which is what
        // these tests are asserting about.
        priority: 1,
        fallback_role: "primary".to_string(),
        route_group_id: String::new(),
        route_group_name: String::new(),
        owner_account_id: None,
        owner_email: None,
        extra: None,
        oauth_group_id: None,
        group_accounts: None,
        routing_config: None,
        group_alias: None,
        group_runtime: None,
    }
}

#[test]
fn use_two_axis_summary_and_mislabel_prompt() {
    let tmp = std::env::temp_dir().join(format!("aikey-two-axis-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let vault = tmp.join("vault.db");

    // ── 1. Initialise the vault by running the real binary once ──────────────
    let out = base_cmd(&tmp, &vault)
        .args(["add", "bootstrap", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-ant-bootstrap-e2e")
        .stdin(Stdio::null())
        .output()
        .expect("run aikey add");
    assert!(
        out.status.success(),
        "bootstrap add failed\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ── 2. Seed team-VK cache rows through the same lib API the sync uses ─────
    // Point THIS process at the same vault so storage helpers hit it.
    std::env::set_var("AK_VAULT_PATH", &vault);
    let salt = storage::get_salt().expect("salt");
    let (m, t, p) = storage::get_kdf_params().expect("kdf");
    let key = crypto::derive_key_with_params(&SecretString::new(PW.to_string()), &salt, m, t, p)
        .expect("derive");
    let mut vault_key = [0u8; 32];
    vault_key.copy_from_slice(key.as_slice());
    storage::verify_vault_key(&vault_key).expect("vault key verifies");

    let enc = |plain: &str| crypto::encrypt(&vault_key, plain.as_bytes()).expect("encrypt");

    // (a) single-provider GLM-via-anthropic VK → drives the two-axis summary.
    let (n1, c1) = enc("glm-real-key-material");
    storage::upsert_virtual_key_cache(&vk_row(
        "vk-glm-anthropic",
        "glm-team",
        "zhipu",
        "anthropic",
        "https://open.bigmodel.cn/api/anthropic",
        &["zhipu"],
        n1,
        c1,
    ))
    .expect("seed glm vk");

    // (b) multi-provider VK → drives the interactive "Select provider(s)" prompt.
    let (n2, c2) = enc("multi-key-material");
    storage::upsert_virtual_key_cache(&vk_row(
        "vk-multi",
        "multi-team",
        "zhipu",
        "anthropic",
        "https://open.bigmodel.cn/api/anthropic",
        &["zhipu", "moonshot"],
        n2,
        c2,
    ))
    .expect("seed multi vk");

    // (c) Team OAuth group VK backed by Mock Provider. It intentionally has no
    // direct ciphertext: the member proxy consumes per-account group_runtime.
    let (n3, c3) = enc("unused-group-placeholder");
    let mut group = vk_row(
        "vk-mock-group",
        "mock-group",
        "mock",
        "anthropic",
        "http://127.0.0.1:3000/mock-provider/anthropic",
        &["mock"],
        n3,
        c3,
    );
    group.provider_key_nonce = None;
    group.provider_key_ciphertext = None;
    group.oauth_group_id = Some("group-e2e".to_string());
    storage::upsert_virtual_key_cache(&group).expect("seed mock group vk");

    // ── 3. Live run A: `aikey use glm-team` → two-axis summary box ────────────
    let a = base_cmd(&tmp, &vault)
        .args(["use", "glm-team", "--no-hook"])
        .stdin(Stdio::null())
        .output()
        .expect("run aikey use glm-team");
    let a_out = format!(
        "{}{}",
        String::from_utf8_lossy(&a.stdout),
        String::from_utf8_lossy(&a.stderr)
    );
    println!("\n================ LIVE A: `aikey use glm-team` ================\n{a_out}");

    // ── 4. Live run B: `aikey use multi-team` under a PTY → prompt text ───────
    // `script -q /dev/null <cmd>` gives the child a real TTY so the interactive
    // multi-provider branch (and its prompt) is reached; feed "1" on stdin.
    let mut b = Command::new("script")
        .args(["-q", "/dev/null"])
        .arg(bin())
        .args(["use", "multi-team", "--no-hook"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &tmp)
        .env("AK_VAULT_PATH", &vault)
        .env("AK_TEST_PASSWORD", PW)
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn script pty");
    b.stdin.as_mut().unwrap().write_all(b"1\n").unwrap();
    let b_out_raw = b.wait_with_output().expect("wait pty");
    let b_out = format!(
        "{}{}",
        String::from_utf8_lossy(&b_out_raw.stdout),
        String::from_utf8_lossy(&b_out_raw.stderr)
    );
    println!("\n================ LIVE B: `aikey use multi-team` (PTY) ================\n{b_out}");

    // ── 5. Live run C: cluster sidecar must NOT divert member group VK ──────
    let aikey_dir = tmp.join(".aikey");
    std::fs::create_dir_all(&aikey_dir).unwrap();
    std::fs::write(
        aikey_dir.join("active-cluster.json"),
        r#"{"authority":"127.0.0.1:19088"}"#,
    )
    .unwrap();
    let c = base_cmd(&tmp, &vault)
        .args(["use", "mock-group", "--no-hook"])
        .stdin(Stdio::null())
        .output()
        .expect("run aikey use mock-group");
    let c_out = format!(
        "{}{}",
        String::from_utf8_lossy(&c.stdout),
        String::from_utf8_lossy(&c.stderr)
    );
    println!("\n================ LIVE C: member OAuth group with cluster sidecar ================\n{c_out}");

    // ── 6. Assertions ────────────────────────────────────────────────────────
    // Two-axis summary: PROTOCOL + PROVIDER header, anthropic protocol, zhipu(GLM).
    assert!(a.status.success(), "aikey use glm-team failed:\n{a_out}");
    assert!(
        a_out.contains("PROTOCOL") && a_out.contains("PROVIDER"),
        "summary missing two-axis header:\n{a_out}"
    );
    assert!(
        a_out.contains("anthropic"),
        "summary missing anthropic protocol axis:\n{a_out}"
    );
    assert!(
        a_out.contains("zhipu(GLM)") || a_out.contains("zhipu"),
        "summary missing zhipu provider axis:\n{a_out}"
    );

    // Mislabel fix: prompt says "provider(s)", never the old "protocol(s)".
    assert!(
        b_out.contains("Select provider(s) to set as Primary"),
        "mislabel fix not observed (expected 'Select provider(s)'):\n{b_out}"
    );
    assert!(
        !b_out.contains("Select protocol(s) to set as Primary"),
        "old mislabel 'Select protocol(s)' still present:\n{b_out}"
    );

    assert!(c.status.success(), "aikey use mock-group failed:\n{c_out}");
    assert!(
        !c_out.contains("cluster node (key stays central)"),
        "member OAuth group VK was misclassified as ingress/central:\n{c_out}"
    );
    assert!(
        c_out.contains("Primary for anthropic")
            && c_out.contains("anthropic")
            && c_out.contains("mock"),
        "group activation must show Client Route=anthropic and Provider=mock:\n{c_out}"
    );
    let active_env = std::fs::read_to_string(aikey_dir.join("active.env")).expect("active.env");
    assert!(
        active_env.contains("ANTHROPIC_API_KEY='aikey_active_anthropic'")
            && active_env.contains("ANTHROPIC_BASE_URL='http://127.0.0.1:27200/anthropic'"),
        "member OAuth group must stay on local proxy:\n{active_env}"
    );
    assert!(
        !active_env.contains("export AIKEY_MOCK_PROVIDER_")
            && !active_env.contains("http://127.0.0.1:19088/anthropic"),
        "member active.env leaked Mock/ingress route:\n{active_env}"
    );

    println!("\n✓ two-axis summary + member/Agent route boundary verified live\n");
    let _ = std::fs::remove_dir_all(&tmp);
}
