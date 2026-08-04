//! Live end-to-end proof for `aikey use` under ROUTE GROUPS (openspec change
//! `aliyun-aigw-p0-upstream-fallback`, tasks 4.37 / 4.38 / 4.39 and decision
//! D-1③ / F-16④).
//!
//! Drives the REAL compiled `aikey` binary against a REAL seeded vault holding a
//! two-hop chain, so what this prints is what a developer actually sees.
//!
//! The three behaviours it proves are the ones a unit test cannot:
//!
//!   1. `aikey use <key>` pins the GROUP — failover stays on. 🔴 The literal
//!      reading of the pin table's three-state row ("no scope column, so treat
//!      it as one hop") would silently disable failover for every developer who
//!      has ever run `aikey use`, which is nearly all of them.
//!   2. `aikey use <key> --only <upstream>` pins ONE hop and SAYS SO at the
//!      moment it happens. A pin that quietly removes failover is the trap the
//!      decision exists to close, so the warning is part of the contract, not
//!      cosmetics.
//!   3. `--group <name>` alone resolves only when unambiguous. A group is an
//!      org-level TEMPLATE, so two of your keys can share it — and those are
//!      different credentials billed to different owners. Guessing would charge
//!      somebody else, so it fails loudly and lists the candidates.
//!
//! Run:  cargo test --test e2e_use_route_group_live -- --nocapture

use aikeylabs_aikey_cli::{crypto, storage};
use secrecy::SecretString;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const PW: &str = "e2e-route-group-pw";

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
        .env("AIKEY_NO_HOOK", "1")
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1");
    // Windows: storage_acl::enforce_owner_only reads USERNAME to grant the
    // current user before stripping ACL inheritance. Under env_clear() an
    // absent USERNAME locks the non-elevated caller out of the vault file, so
    // forward it (and USERDOMAIN) the same way PATH is forwarded.
    if let Ok(u) = std::env::var("USERNAME") {
        c.env("USERNAME", u);
    }
    if let Ok(d) = std::env::var("USERDOMAIN") {
        c.env("USERDOMAIN", d);
    }
    c
}

/// One hop of a chain: a binding-grained cache row carrying its group + priority.
#[allow(clippy::too_many_arguments)]
fn hop(
    vk_id: &str,
    alias: &str,
    provider: &str,
    base_url: &str,
    priority: i64,
    role: &str,
    group_id: &str,
    group_name: &str,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> storage::VirtualKeyCacheEntry {
    storage::VirtualKeyCacheEntry {
        virtual_key_id: vk_id.to_string(),
        org_id: "org-rg".to_string(),
        seat_id: "seat-rg".to_string(),
        alias: alias.to_string(),
        provider_code: provider.to_string(),
        protocol_type: "anthropic".to_string(),
        base_url: base_url.to_string(),
        // 🔴 Kept as ONE line on purpose (2026-08-04). Two commits fixed the same
        // E0063 here independently — 17ea1f8 with `String::new()`, 91b98bd with
        // this — and the merge that brought both together produced E0062
        // (`binding_id` specified more than once), which stopped the ENTIRE
        // `aikey-cli` test suite from compiling on develop-v1.0.5.
        //
        // A distinct id per hop is the right one here: this fixture stands in for
        // a delivered route-group chain, where every hop has a real binding id.
        // `String::new()` is the sentinel for "vault written before the column
        // existed" (see VirtualKeyCacheEntry::binding_id) — correct for a legacy
        // row, wrong for a wire this test says the server just sent.
        binding_id: format!("bind-{vk_id}-{provider}"),
        credential_id: format!("cred-{vk_id}-{provider}"),
        credential_revision: "1".to_string(),
        virtual_key_revision: "1".to_string(),
        key_status: "active".to_string(),
        share_status: "accepted".to_string(),
        local_state: "active".to_string(),
        expires_at: None,
        provider_key_nonce: Some(nonce),
        provider_key_ciphertext: Some(ciphertext),
        synced_at: 1,
        local_alias: Some(alias.to_string()),
        supported_providers: vec!["anthropic".to_string()],
        provider_base_urls: {
            let mut m = HashMap::new();
            m.insert("anthropic".to_string(), base_url.to_string());
            m
        },
        priority,
        fallback_role: role.to_string(),
        route_group_id: group_id.to_string(),
        route_group_name: group_name.to_string(),
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
fn use_under_route_groups_pins_group_by_default_and_says_so_when_it_does_not() {
    let tmp = std::env::temp_dir().join(format!("aikey-rg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let vault = tmp.join("vault.db");

    // ── Initialise the vault through the real binary ────────────────────────
    let out = base_cmd(&tmp, &vault)
        .args(["add", "bootstrap", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-ant-bootstrap-rg")
        .stdin(Stdio::null())
        .output()
        .expect("run aikey add");
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ── Seed a two-hop chain on ONE key, plus a second key sharing the same
    //    org-level template (that is what makes `--group` ambiguous) ─────────
    // Point THIS process at the same vault so the storage helpers hit it.
    std::env::set_var("AK_VAULT_PATH", &vault);
    let salt = storage::get_salt().expect("salt");
    let (m, t, p_) = storage::get_kdf_params().expect("kdf");
    let key = crypto::derive_key_with_params(&SecretString::new(PW.to_string()), &salt, m, t, p_)
        .expect("derive");
    let mut vault_key = [0u8; 32];
    vault_key.copy_from_slice(key.as_slice());
    storage::verify_vault_key(&vault_key).expect("vault key verifies");
    let enc = |plain: &str| crypto::encrypt(&vault_key, plain.as_bytes()).expect("encrypt");

    let (n1, c1) = enc("sk-ant-primary");
    storage::upsert_virtual_key_cache(&hop(
        "vk-eng",
        "eng-key",
        "anthropic",
        "https://api.anthropic.com",
        1,
        "primary",
        "rg-main",
        "main-chain",
        n1,
        c1,
    ))
    .expect("seed eng primary");

    let (n2, c2) = enc("sk-glm-fallback");
    storage::upsert_virtual_key_cache(&hop(
        "vk-eng",
        "eng-key",
        "zhipu",
        "https://open.bigmodel.cn/api/anthropic",
        2,
        "fallback",
        "rg-main",
        "main-chain",
        n2,
        c2,
    ))
    .expect("seed eng fallback");

    // A DIFFERENT key built from the SAME template — different credentials,
    // different quota, billed to a different owner.
    let (n3, c3) = enc("sk-ant-data-team");
    storage::upsert_virtual_key_cache(&hop(
        "vk-data",
        "data-key",
        "anthropic",
        "https://api.anthropic.com",
        1,
        "primary",
        "rg-main",
        "main-chain",
        n3,
        c3,
    ))
    .expect("seed data primary");

    let run = |args: &[&str]| -> (String, bool) {
        let o = base_cmd(&tmp, &vault)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run aikey");
        (
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            o.status.success(),
        )
    };

    // ── 1. Default: pin the GROUP, failover stays on ────────────────────────
    let (grp, ok) = run(&["use", "eng-key"]);
    println!("================ LIVE 1: `aikey use eng-key` (default = pin the GROUP) ================\n{grp}");
    assert!(ok, "use eng-key failed:\n{grp}");
    assert!(
        !grp.to_lowercase().contains("will not automatically switch")
            && !grp.contains("没有故障转移"),
        "the DEFAULT pin claimed failover was off — it pins the group, so the \
         administrator's fallback order still applies:\n{grp}"
    );

    // ── 2. `--only`: pin ONE hop, and say the consequence out loud ──────────
    let (only, ok) = run(&["use", "eng-key", "--only", "zhipu"]);
    println!("================ LIVE 2: `aikey use eng-key --only zhipu` (pin ONE hop) ================\n{only}");
    assert!(ok, "use --only failed:\n{only}");
    let warned = only.to_lowercase().contains("not")
        && (only.to_lowercase().contains("failover")
            || only.to_lowercase().contains("switch")
            || only.contains("故障转移"));
    assert!(
        warned,
        "`--only` pinned one upstream WITHOUT telling the user failover is now off.\n\
         🔴 A pin that silently removes a capability is exactly the trap D-1③/F-16④ \
         exists to close — the warning is part of the contract, not decoration.\n{only}"
    );

    // ── 3. `--group` alone is ambiguous across two keys → loud failure ──────
    let (amb, ok) = run(&["use", "--group", "main-chain"]);
    println!("================ LIVE 3: `aikey use --group main-chain` (shared by 2 keys) ================\n{amb}");
    assert!(
        !ok,
        "an ambiguous --group SUCCEEDED. Those are different keys with different \
         credentials billed to different owners, so picking one quietly charges \
         somebody else:\n{amb}"
    );
    assert!(
        amb.contains("eng-key") && amb.contains("data-key"),
        "the ambiguity error did not list BOTH candidate keys, so the user cannot \
         tell which one they meant:\n{amb}"
    );

    // ── 4. (key, group) two coordinates always resolve ──────────────────────
    let (pair, ok) = run(&["use", "--key", "eng-key", "--group", "main-chain"]);
    println!("================ LIVE 4: `aikey use --key eng-key --group main-chain` ================\n{pair}");
    assert!(ok, "the two-coordinate form must always resolve:\n{pair}");

    println!("✓ route-group `aikey use` semantics verified live against the real binary");
}
