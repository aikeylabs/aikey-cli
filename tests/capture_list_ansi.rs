//! Capture the REAL ANSI-colored output of `aikey list` from the compiled
//! binary against a real seeded vault, and write the raw bytes to the path in
//! $SCREENSHOT_ANSI_OUT. This is a capture harness (not an assertion test) —
//! it only runs when SCREENSHOT_ANSI_OUT is set, so the normal suite skips it.
//!
//! Run:
//!   SCREENSHOT_ANSI_OUT=/abs/out.ansi cargo test --test capture_list_ansi -- --nocapture

use aikeylabs_aikey_cli::{crypto, storage};
use secrecy::SecretString;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const PW: &str = "e2e-capture-pw";

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aikey"))
}

fn base_cmd(home: &PathBuf, vault: &PathBuf) -> Command {
    let mut c = Command::new(bin());
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("AK_VAULT_PATH", vault)
        .env("AK_TEST_PASSWORD", PW)
        .env("RUST_LOG", "off");
    c
}

#[allow(clippy::too_many_arguments)]
fn vk_row(
    id: &str,
    alias: &str,
    provider: &str,
    protocol: &str,
    base_url: &str,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> storage::VirtualKeyCacheEntry {
    storage::VirtualKeyCacheEntry {
        virtual_key_id: id.to_string(),
        org_id: "org-e2e".to_string(),
        seat_id: "seat-e2e".to_string(),
        alias: alias.to_string(),
        provider_code: provider.to_string(),
        protocol_type: protocol.to_string(),
        base_url: base_url.to_string(),
        credential_id: format!("cred-{id}-{provider}-{protocol}"),
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
        supported_providers: vec![provider.to_string()],
        provider_base_urls: {
            let mut m = HashMap::new();
            m.insert(provider.to_string(), base_url.to_string());
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
fn capture_real_list_ansi() {
    let out_path = match std::env::var("SCREENSHOT_ANSI_OUT") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!("SCREENSHOT_ANSI_OUT not set — skipping capture harness");
            return;
        }
    };

    let tmp = std::env::temp_dir().join(format!("aikey-capture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let vault = tmp.join("vault.db");

    // Init vault via the real binary.
    let out = base_cmd(&tmp, &vault)
        .args(["add", "my-claude", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-ant-bootstrap")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("aikey add");
    assert!(
        out.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Seed team VKs through the real sync write path.
    std::env::set_var("AK_VAULT_PATH", &vault);
    let salt = storage::get_salt().unwrap();
    let (m, t, p) = storage::get_kdf_params().unwrap();
    let key =
        crypto::derive_key_with_params(&SecretString::new(PW.to_string()), &salt, m, t, p).unwrap();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(key.as_slice());
    let enc = |s: &str| crypto::encrypt(&vk, s.as_bytes()).unwrap();

    let (n, c) = enc("glm-single");
    storage::upsert_virtual_key_cache(&vk_row(
        "vk-solo",
        "glm-team",
        "zhipu",
        "anthropic",
        "https://open.bigmodel.cn/api/anthropic",
        n,
        c,
    ))
    .unwrap();

    let bindings = [
        (
            "zhipu",
            "anthropic",
            "https://open.bigmodel.cn/api/anthropic",
        ),
        (
            "zhipu",
            "openai_compatible",
            "https://open.bigmodel.cn/api/paas/v4",
        ),
        (
            "moonshot",
            "openai_compatible",
            "https://api.moonshot.cn/v1",
        ),
        (
            "qwen",
            "openai_compatible",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        ),
        (
            "doubao",
            "openai_compatible",
            "https://ark.cn-beijing.volces.com/api/v3",
        ),
    ];
    for (prov, proto, url) in bindings {
        let (n, c) = enc(&format!("mat-{prov}-{proto}"));
        storage::upsert_virtual_key_cache(&vk_row(
            "vk-multi",
            "everything-team",
            prov,
            proto,
            url,
            n,
            c,
        ))
        .unwrap();
    }

    // Run `aikey list` with COLOR FORCED (real ANSI, though stdout is piped).
    let out = base_cmd(&tmp, &vault)
        .arg("list")
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .output()
        .expect("aikey list");

    let mut bytes = out.stdout.clone();
    bytes.extend_from_slice(&out.stderr);
    std::fs::write(&out_path, &bytes).expect("write ANSI capture");
    println!("wrote {} bytes of real ANSI to {out_path}", bytes.len());
    assert!(out.status.success(), "aikey list failed");

    let _ = std::fs::remove_dir_all(&tmp);
}
