//! End-to-end proof that a cluster snapshot removes a binding row it superseded.
//!
//! This is the 2026-08-03 staging outage, reproduced through the REAL binary's
//! `_internal vault-op` / `cluster_apply_snapshot` path — the SOLE writer of a
//! worker node's `managed_virtual_keys_cache`.
//!
//! The failure it pins: an OAuth pool VK is delivered with an empty
//! `provider_code` while its provider is unresolved, and with the real one after.
//! Since P1e the cache is keyed `(virtual_key_id, protocol_type, provider_code)`,
//! so the second delivery INSERTS a row beside the first instead of replacing it.
//! The old stale-sweep is VK-grain — the VK is still in the snapshot, so it was
//! never looked at again — and the proxy then read the pair as TWO chain entries
//! at the defaulted priority 1 and answered every pool call with 409
//! PROVIDER_ROUTE_AMBIGUOUS. Both staging workers carried one such pair per pool.
//!
//! 🔴 Why an e2e test and not a unit test: the sweep lives inside
//! `apply_cluster_snapshot`, which is `pub(crate)` and takes a decrypted vault
//! key. The bug survived precisely because nothing exercised this path with a
//! real vault — which is what this does.
//!
//! Run:  cargo test --test e2e_cluster_apply_superseded_binding -- --nocapture

use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const PW: &str = "e2e-cluster-superseded-pw";
const ORG: &str = "org-cluster-e2e";
const VK: &str = "vk-pool-e2e";
const GID: &str = "grp-pool-e2e";

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
    c
}

/// One delivery of the pool VK, carrying `provider_code` on its group bundle.
fn snapshot(provider_code: &str) -> serde_json::Value {
    json!({
        "action": "cluster_apply_snapshot",
        "request_id": "e2e-superseded",
        // Required by the envelope, but unused here: resolve_cluster_vault_key
        // PREFERS payload.master_password so `aikey` owns the Argon2id
        // derivation (the daemon never re-implements crypto).
        "vault_key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "payload": {
            "org_id": ORG,
            "master_password": PW,
            "virtual_keys": [{
                "virtual_key_id": VK,
                "owner_account_id": "acct-e2e",
                "seat_id": "seat-e2e",
                "alias": "agent-pool-e2e-anthropic",
                "key_status": "active",
                "virtual_key_revision": "r1",
                "protocol_type": "anthropic",
                "oauth_group_id": GID,
                "slots": []
            }],
            "oauth_group_runtime": {
                "groups": [{
                    "oauth_group_id": GID,
                    "provider_code": provider_code,
                    "routing_config": "{}",
                    "accounts": []
                }]
            }
        }
    })
}

fn apply(home: &PathBuf, vault: &PathBuf, provider_code: &str) -> String {
    let mut child = base_cmd(home, vault)
        .args(["_internal", "vault-op", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aikey _internal vault-op");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(snapshot(provider_code).to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    String::from_utf8_lossy(&out.stdout).to_string()
        + &String::from_utf8_lossy(&out.stderr)
}

/// Counts cache rows for the pool VK, and how many carry an empty provider_code.
fn rows(vault: &PathBuf) -> (usize, usize) {
    let conn = rusqlite::Connection::open(vault).expect("open vault");
    let total: usize = conn
        .query_row(
            "SELECT count(*) FROM managed_virtual_keys_cache WHERE virtual_key_id = ?1",
            [VK],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let empty: usize = conn
        .query_row(
            "SELECT count(*) FROM managed_virtual_keys_cache \
             WHERE virtual_key_id = ?1 AND ifnull(provider_code,'') = ''",
            [VK],
            |r| r.get(0),
        )
        .unwrap_or(0);
    (total, empty)
}

#[test]
fn a_pool_whose_provider_code_resolves_does_not_leave_a_second_row_behind() {
    let tmp = std::env::temp_dir().join(format!("aikey-cluster-sup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let vault = tmp.join("vault.db");

    // Initialise a real vault through the real binary.
    let out = base_cmd(&tmp, &vault)
        .args(["add", "bootstrap", "--provider", "anthropic"])
        .env("AK_TEST_SECRET", "sk-ant-bootstrap-cluster")
        .stdin(Stdio::null())
        .output()
        .expect("run aikey add");
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Delivery 1: the pool's provider has not resolved yet — empty provider_code.
    let first = apply(&tmp, &vault, "");
    let (total, empty) = rows(&vault);
    assert_eq!(
        (total, empty),
        (1, 1),
        "first apply should leave exactly one row, with the empty provider_code \
         the snapshot carried. Got total={total} empty={empty}. Output: {first}"
    );

    // Delivery 2: same VK, provider now resolved. Under the P1e key this is a
    // DIFFERENT row, which is how the duplicate was born on staging.
    let second = apply(&tmp, &vault, "anthropic");
    let (total, empty) = rows(&vault);

    assert_eq!(
        empty, 0,
        "the superseded empty-provider row survived the second delivery.\n\
         That row is not a key that went away — it is a duplicate identity of the \n\
         key that is right here, and the proxy reads the pair as two chain entries \n\
         at the defaulted priority 1: 409 PROVIDER_ROUTE_AMBIGUOUS on every pool \n\
         call, on a configuration nobody got wrong. Output: {second}"
    );
    assert_eq!(
        total, 1,
        "expected exactly one row for the pool VK after re-delivery, got {total}"
    );
}
