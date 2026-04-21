//! `aikey _internal *` stdin-json IPC 集成测试
//!
//! 验证 Go local-server ↔ Rust cli 的协议契约：
//! - `--stdin-json` 从 stdin 读 JSON envelope
//! - stdout 输出 JSON envelope
//! - 非 0 exit 只在进程崩溃时；其它情况 exit 0 + error envelope
//! - vault_key_hex 必须 64 chars / 有效 hex

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// 与 integration_test.rs 同款 TestEnv 简化版（仅 _internal 用）
struct InternalTestEnv {
    _temp_dir: TempDir,
    vault_path: PathBuf,
    password: String,
}

impl InternalTestEnv {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("temp dir");
        let vault_path = temp_dir.path().join(".aikey");
        Self {
            _temp_dir: temp_dir,
            vault_path,
            password: "integration_test_pw_123".to_string(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(cargo_bin("aikey"));
        cmd.env("HOME", self._temp_dir.path());
        cmd.env("AK_TEST_PASSWORD", &self.password);
        cmd.current_dir(self._temp_dir.path());
        cmd
    }

    /// 用 `aikey add` lazy-init 一份真实 vault
    fn init_vault(&self) {
        let data_dir = self.vault_path.join("data");
        fs::create_dir_all(&data_dir).expect("mk data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.vault_path, fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }
        self.cmd()
            .arg("add")
            .arg("_ipc_bootstrap_")
            .args(["--provider", "openai"])
            .env("AK_TEST_SECRET", "bootstrap")
            .assert()
            .success();
    }

    /// 从 bootstrap 过的 vault 派生 key hex
    fn vault_key_hex(&self) -> String {
        use argon2::{Algorithm, Argon2, Params, Version};
        use rusqlite::Connection;

        let db = self.vault_path.join("data").join("vault.db");
        let conn = Connection::open(&db).expect("open vault");
        let salt: Vec<u8> = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'master_salt' OR key = 'salt' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("read salt");

        let params = Params::new(65536, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(self.password.as_bytes(), &salt, &mut key)
            .expect("derive");
        hex::encode(key)
    }
}

fn parse_stdout_json(raw: &[u8]) -> Value {
    let s = String::from_utf8_lossy(raw);
    serde_json::from_str::<Value>(s.trim())
        .unwrap_or_else(|e| panic!("stdout not JSON: {} \n raw: {}", e, s))
}

// ========== Phase A 4 个场景 ==========

#[test]
fn verify_succeeds_with_correct_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    let req = serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "verify",
        "request_id": "test-1",
    });
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(req.to_string())
        .assert()
        .success()
        .get_output()
        .clone();

    let v = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "ok", "full response: {}", v);
    assert_eq!(v["request_id"], "test-1");
    assert_eq!(v["data"]["verified"], true);
}

#[test]
fn verify_fails_with_wrong_key() {
    let env = InternalTestEnv::new();
    env.init_vault();

    let wrong_key = "0".repeat(64);
    let req = serde_json::json!({
        "vault_key_hex": wrong_key,
        "action": "verify",
        "request_id": "test-2",
    });
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(req.to_string())
        .assert()
        .success()  // 协议约定：exit 0 + error envelope
        .get_output()
        .clone();

    let v = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_INVALID");
    assert_eq!(v["request_id"], "test-2");
}

#[test]
fn invalid_json_stdin_returns_error_envelope() {
    let env = InternalTestEnv::new();
    env.init_vault();

    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin("this is not json at all")
        .assert()
        .success()
        .get_output()
        .clone();

    let v = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_STDIN_INVALID_JSON");
}

#[test]
fn missing_action_field_returns_error() {
    let env = InternalTestEnv::new();
    env.init_vault();

    // 缺 `action` 字段
    let req = serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "request_id": "test-missing-action"
    });
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(req.to_string())
        .assert()
        .success()
        .get_output()
        .clone();

    let v = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_STDIN_INVALID_JSON");
}

#[test]
fn malformed_vault_key_returns_error() {
    let env = InternalTestEnv::new();
    env.init_vault();

    // vault_key_hex 长度不对
    let req = serde_json::json!({
        "vault_key_hex": "short",
        "action": "verify",
    });
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(req.to_string())
        .assert()
        .success()
        .get_output()
        .clone();

    let v = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_MALFORMED");
}

#[test]
fn unknown_vault_op_action_returns_error() {
    let env = InternalTestEnv::new();
    env.init_vault();

    let req = serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "fake_action_that_does_not_exist",
    });
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(req.to_string())
        .assert()
        .success()
        .get_output()
        .clone();

    let v = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_UNKNOWN_ACTION");
}

#[test]
fn internal_subcommand_hidden_from_help() {
    // aikey --help 不应暴露 _internal（hide = true）
    let env = InternalTestEnv::new();
    let out = env
        .cmd()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .clone();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("_internal"), "_internal should be hidden from --help");
}

// ========== Phase B: add / batch_import / update_secret / delete ==========

/// 用 _internal vault-op 跑一个 action，返回 stdout JSON
fn run_vault_op(env: &InternalTestEnv, payload: Value) -> Value {
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(payload.to_string())
        .assert()
        .success()
        .get_output()
        .clone();
    parse_stdout_json(&out.stdout)
}

/// 统计 vault entries 数量（用 sqlite 直连，避开 cli 命令污染 audit）
fn count_entries(env: &InternalTestEnv) -> i64 {
    use rusqlite::Connection;
    let db = env.vault_path.join("data").join("vault.db");
    let conn = Connection::open(&db).expect("open");
    conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
        .expect("count")
}

#[test]
fn add_creates_new_credential() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let before = count_entries(&env);

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "add",
        "request_id": "add-1",
        "payload": {
            "alias": "claude-test",
            "secret_plaintext": "sk-ant-api03-test",
            "provider": "anthropic",
        }
    }));
    assert_eq!(v["status"], "ok", "response: {}", v);
    assert_eq!(v["data"]["action_taken"], "inserted");
    assert_eq!(v["data"]["alias"], "claude-test");
    assert_eq!(v["data"]["provider"], "anthropic");
    assert_eq!(count_entries(&env), before + 1);
}

#[test]
fn add_rejects_duplicate_by_default() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    // 第一次 ok
    let v1 = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "add",
        "payload": {"alias": "dup", "secret_plaintext": "first"}
    }));
    assert_eq!(v1["status"], "ok");

    // 第二次冲突
    let v2 = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "add",
        "payload": {"alias": "dup", "secret_plaintext": "second"}
    }));
    assert_eq!(v2["status"], "error");
    assert_eq!(v2["error_code"], "I_CREDENTIAL_CONFLICT");
}

#[test]
fn add_with_on_conflict_replace_overwrites() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    // 第一次
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "replace-me", "secret_plaintext": "v1"}
    }));
    let before = count_entries(&env);
    // 第二次 on_conflict=replace
    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "add",
        "payload": {"alias": "replace-me", "secret_plaintext": "v2", "on_conflict": "replace"}
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["action_taken"], "replaced");
    // 数量不变（更新不是插入）
    assert_eq!(count_entries(&env), before);
}

#[test]
fn batch_import_inserts_multiple() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let before = count_entries(&env);

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "batch_import",
        "payload": {
            "items": [
                {"alias": "batch-1", "secret_plaintext": "s1", "provider": "anthropic"},
                {"alias": "batch-2", "secret_plaintext": "s2", "provider": "openai"},
                {"alias": "batch-3", "secret_plaintext": "s3"},
            ]
        }
    }));
    assert_eq!(v["status"], "ok", "{}", v);
    assert_eq!(v["data"]["total"], 3);
    assert_eq!(v["data"]["inserted"], 3);
    assert_eq!(v["data"]["replaced"], 0);
    assert_eq!(count_entries(&env), before + 3);
}

#[test]
fn batch_import_error_on_conflict_aborts() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    // 先种一个
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "batch-seed", "secret_plaintext": "seed"}
    }));
    let before = count_entries(&env);

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "batch_import",
        "payload": {
            "items": [
                {"alias": "batch-new-1", "secret_plaintext": "x"},
                {"alias": "batch-seed", "secret_plaintext": "conflict"},  // 冲突
            ]
            // on_conflict 默认 "error"
        }
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_CONFLICT");
    // 冲突预检在写任何之前做 → entries 数应不变（batch 是原子的）
    assert_eq!(count_entries(&env), before);
}

#[test]
fn batch_import_skip_on_conflict() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "skip-seed", "secret_plaintext": "seed"}
    }));
    let before = count_entries(&env);

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "batch_import",
        "payload": {
            "items": [
                {"alias": "skip-new", "secret_plaintext": "x"},
                {"alias": "skip-seed", "secret_plaintext": "conflict"},
            ],
            "on_conflict": "skip",
        }
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["inserted"], 1);
    assert_eq!(v["data"]["skipped"], 1);
    assert_eq!(count_entries(&env), before + 1);
}

#[test]
fn update_secret_requires_existing_alias() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    // 不存在 → I_CREDENTIAL_NOT_FOUND
    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "update_secret",
        "payload": {"alias": "does-not-exist", "new_secret_plaintext": "x"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_NOT_FOUND");

    // 创建 → update → ok
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "upd-target", "secret_plaintext": "v1"}
    }));
    let v2 = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "update_secret",
        "payload": {"alias": "upd-target", "new_secret_plaintext": "v2"}
    }));
    assert_eq!(v2["status"], "ok");
    assert_eq!(v2["data"]["action_taken"], "updated");
}

#[test]
fn delete_removes_credential() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "del-me", "secret_plaintext": "x"}
    }));
    let before = count_entries(&env);

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "delete",
        "payload": {"alias": "del-me"}
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["action_taken"], "deleted");
    assert_eq!(count_entries(&env), before - 1);
}

#[test]
fn delete_nonexistent_returns_not_found() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "delete",
        "payload": {"alias": "never-existed"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_NOT_FOUND");
}

// ========== Phase C: query actions ==========

/// 跑一个 query action
fn run_query(env: &InternalTestEnv, payload: Value) -> Value {
    let out = env
        .cmd()
        .args(["_internal", "query", "--stdin-json"])
        .write_stdin(payload.to_string())
        .assert()
        .success()
        .get_output()
        .clone();
    parse_stdout_json(&out.stdout)
}

/// 种几条典型 entry 供 query 测试使用
fn seed_credentials(env: &InternalTestEnv, key_hex: &str) {
    let out = env
        .cmd()
        .args(["_internal", "vault-op", "--stdin-json"])
        .write_stdin(serde_json::json!({
            "vault_key_hex": key_hex,
            "action": "batch_import",
            "payload": {
                "items": [
                    {"alias": "q-claude", "secret_plaintext": "sk-ant-api03-SECRET-A", "provider": "anthropic"},
                    {"alias": "q-openai", "secret_plaintext": "sk-proj-SECRET-B", "provider": "openai"},
                    {"alias": "q-kimi", "secret_plaintext": "sk-kimi-SECRET-C"},
                ]
            }
        }).to_string())
        .assert()
        .success()
        .get_output()
        .clone();
    let v: Value = parse_stdout_json(&out.stdout);
    assert_eq!(v["status"], "ok", "seed failed: {}", v);
}

#[test]
fn query_list_returns_all_aliases() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "list",
        "request_id": "list-1",
    }));
    assert_eq!(v["status"], "ok");
    let aliases = v["data"]["aliases"].as_array().expect("aliases array");
    // init_vault 种了 _ipc_bootstrap_，加上 3 个 seed → 至少 4 条
    assert!(aliases.len() >= 4);
    let names: Vec<&str> = aliases.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(names.contains(&"q-claude"));
    assert!(names.contains(&"q-openai"));
    assert!(names.contains(&"q-kimi"));
}

#[test]
fn query_list_rejects_wrong_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "list",
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_INVALID");
}

#[test]
fn query_list_with_metadata_includes_provider() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "list_with_metadata",
    }));
    assert_eq!(v["status"], "ok");
    let entries = v["data"]["entries"].as_array().expect("entries array");
    let claude = entries.iter().find(|e| e["alias"] == "q-claude").expect("q-claude present");
    assert_eq!(claude["provider_code"], "anthropic");
    // list_with_metadata 必须**不**含 secret_plaintext
    assert!(claude.get("secret_plaintext").is_none());
}

#[test]
fn query_get_metadata_only_by_default() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "get",
        "payload": {"alias": "q-claude"},
        // 无 include_secret → 默认 false
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["alias"], "q-claude");
    assert_eq!(v["data"]["provider_code"], "anthropic");
    assert!(v["data"].get("secret_plaintext").is_none(), "默认不返回 plaintext");
}

#[test]
fn query_get_with_include_secret_true_decrypts() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "get",
        "payload": {"alias": "q-claude", "include_secret": true},
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["secret_plaintext"], "sk-ant-api03-SECRET-A");
    assert_eq!(v["data"]["provider_code"], "anthropic");
}

#[test]
fn query_get_returns_not_found_for_missing_alias() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "get",
        "payload": {"alias": "never-existed"},
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_NOT_FOUND");
}

#[test]
fn query_check_alias_exists_does_not_need_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    // 用 wrong key 也能 check_alias_exists（该 action 只查 alias 本身，不涉及解密）
    let v1 = run_query(&env, serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "check_alias_exists",
        "payload": {"alias": "q-claude"},
    }));
    assert_eq!(v1["status"], "ok");
    assert_eq!(v1["data"]["exists"], true);

    let v2 = run_query(&env, serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "check_alias_exists",
        "payload": {"alias": "never-existed"},
    }));
    assert_eq!(v2["status"], "ok");
    assert_eq!(v2["data"]["exists"], false);
}

#[test]
fn query_unknown_action_returns_error() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "not_a_real_query_action",
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_UNKNOWN_ACTION");
}

// ========== Phase D: update-alias ==========

fn run_update_alias(env: &InternalTestEnv, payload: Value) -> Value {
    let out = env
        .cmd()
        .args(["_internal", "update-alias", "--stdin-json"])
        .write_stdin(payload.to_string())
        .assert()
        .success()
        .get_output()
        .clone();
    parse_stdout_json(&out.stdout)
}

/// 从 vault 读单条 entry 的几个 metadata 字段（用 sqlite 直读，不依赖 _internal query）
fn read_entry_meta(env: &InternalTestEnv, alias: &str) -> Value {
    use rusqlite::Connection;
    let db = env.vault_path.join("data").join("vault.db");
    let conn = Connection::open(&db).expect("open");
    let row: (Option<String>, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT provider_code, base_url, supported_providers, metadata FROM entries WHERE alias = ?",
            [alias],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("row");
    serde_json::json!({
        "provider_code": row.0,
        "base_url": row.1,
        "supported_providers": row.2,
        "metadata": row.3,
    })
}

#[test]
fn rename_alias_updates_primary_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "rename_alias",
        "payload": {"old_alias": "q-claude", "new_alias": "q-claude-renamed"}
    }));
    assert_eq!(v["status"], "ok", "{}", v);
    assert_eq!(v["data"]["action_taken"], "renamed");

    // 老名不存在、新名存在
    let v1 = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "check_alias_exists",
        "payload": {"alias": "q-claude"}
    }));
    assert_eq!(v1["data"]["exists"], false);
    let v2 = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "check_alias_exists",
        "payload": {"alias": "q-claude-renamed"}
    }));
    assert_eq!(v2["data"]["exists"], true);
}

#[test]
fn rename_alias_rejects_conflict() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    // q-claude 和 q-openai 都已存在
    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "rename_alias",
        "payload": {"old_alias": "q-claude", "new_alias": "q-openai"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_CONFLICT");
}

#[test]
fn rename_alias_not_found() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "rename_alias",
        "payload": {"old_alias": "nope", "new_alias": "x"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_NOT_FOUND");
}

#[test]
fn rename_alias_rejects_identical_names() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);
    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "rename_alias",
        "payload": {"old_alias": "q-claude", "new_alias": "q-claude"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_STDIN_INVALID_JSON");
}

#[test]
fn set_provider_updates_field() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    // q-kimi 原本无 provider
    let meta0 = read_entry_meta(&env, "q-kimi");
    assert!(meta0["provider_code"].is_null());

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "set_provider",
        "payload": {"alias": "q-kimi", "provider": "moonshot"}
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["provider_code"], "moonshot");

    let meta1 = read_entry_meta(&env, "q-kimi");
    assert_eq!(meta1["provider_code"], "moonshot");
}

#[test]
fn set_provider_null_clears() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "set_provider",
        "payload": {"alias": "q-claude", "provider": null}
    }));
    assert_eq!(v["status"], "ok");
    let meta = read_entry_meta(&env, "q-claude");
    assert!(meta["provider_code"].is_null());
}

#[test]
fn set_base_url_updates_field() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "set_base_url",
        "payload": {"alias": "q-openai", "base_url": "https://api.internal.corp/v1"}
    }));
    assert_eq!(v["status"], "ok");
    let meta = read_entry_meta(&env, "q-openai");
    assert_eq!(meta["base_url"], "https://api.internal.corp/v1");
}

#[test]
fn set_supported_providers_json_array() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "set_supported_providers",
        "payload": {"alias": "q-claude", "providers": ["anthropic", "openai-compat"]}
    }));
    assert_eq!(v["status"], "ok");
    let meta = read_entry_meta(&env, "q-claude");
    // 存储为 JSON string
    let stored: String = meta["supported_providers"].as_str().unwrap().to_string();
    let parsed: Vec<String> = serde_json::from_str(&stored).unwrap();
    assert_eq!(parsed, vec!["anthropic", "openai-compat"]);
}

#[test]
fn set_metadata_roundtrip() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "set_metadata",
        "payload": {
            "alias": "q-kimi",
            "metadata": {"tag": "prod", "note": "月底到期", "enabled": true}
        }
    }));
    assert_eq!(v["status"], "ok");
    let meta = read_entry_meta(&env, "q-kimi");
    let stored: String = meta["metadata"].as_str().unwrap().to_string();
    let parsed: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(parsed["tag"], "prod");
    assert_eq!(parsed["note"], "月底到期");
    assert_eq!(parsed["enabled"], true);
}

#[test]
fn set_metadata_null_clears() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);

    // 先设置
    run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "set_metadata",
        "payload": {"alias": "q-kimi", "metadata": {"tag": "x"}}
    }));
    // 再清空
    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "set_metadata",
        "payload": {"alias": "q-kimi", "metadata": null}
    }));
    assert_eq!(v["status"], "ok");
    let meta = read_entry_meta(&env, "q-kimi");
    assert!(meta["metadata"].is_null());
}

#[test]
fn update_alias_rejects_wrong_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);
    let before = read_entry_meta(&env, "q-claude");

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "set_provider",
        "payload": {"alias": "q-claude", "provider": "malicious"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_INVALID");

    // 未被修改
    let after = read_entry_meta(&env, "q-claude");
    assert_eq!(before, after);
}

#[test]
fn update_alias_unknown_action() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "fake",
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_UNKNOWN_ACTION");
}

// ========== Phase E: parse (Stage 2 skeleton) ==========

fn run_parse(env: &InternalTestEnv, payload: Value) -> Value {
    let out = env
        .cmd()
        .args(["_internal", "parse", "--stdin-json"])
        .write_stdin(payload.to_string())
        .assert()
        .success()
        .get_output()
        .clone();
    parse_stdout_json(&out.stdout)
}

#[test]
fn parse_extracts_email_url_and_secret_from_simple_text() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    let text = "alice@example.com\nhttps://api.claude.ai/v1\nsk-ant-api03-abcdef123456SECRET";
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "parse",
        "request_id": "parse-1",
        "payload": {"text": text}
    }));
    assert_eq!(v["status"], "ok", "{}", v);
    let cands = v["data"]["candidates"].as_array().expect("candidates");
    // 应含 1 email + 1 url + 1 secret
    assert!(cands.iter().any(|c| c["kind"] == "email" && c["value"] == "alice@example.com"));
    assert!(cands.iter().any(|c| c["kind"] == "url" && c["value"].as_str().unwrap().starts_with("https://")));
    assert!(cands.iter().any(|c| c["kind"] == "secret_like" && c["value"].as_str().unwrap().starts_with("sk-ant-api03-")));
    // Stage 2 所有 rule 命中都是 confirmed tier
    for c in cands {
        assert_eq!(c["tier"], "confirmed");
    }
}

#[test]
fn parse_returns_stable_source_hash() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    let text = "some arbitrary text";
    let v1 = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": text}
    }));
    let v2 = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": text}
    }));
    // 幂等：同 text → 同 source_hash
    assert_eq!(v1["data"]["source_hash"], v2["data"]["source_hash"]);
    let h = v1["data"]["source_hash"].as_str().unwrap();
    assert!(h.starts_with("sha256:"));
    assert_eq!(h.len(), "sha256:".len() + 64, "sha256 hex is 64 chars");
}

#[test]
fn parse_dedups_cross_pattern_matches() {
    // sk-ant-* 同时能被 sk-ant 和 sk- 两条 regex 匹配；dedup 后只出现 1 次
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let text = "key sk-ant-api03-ABCDEFGHIJ1234567890xyz";
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": text}
    }));
    let cands = v["data"]["candidates"].as_array().unwrap();
    let secret_count = cands.iter().filter(|c| c["kind"] == "secret_like").count();
    assert_eq!(secret_count, 1, "should dedup, got: {:?}", cands);
}

#[test]
fn parse_returns_layer_versions_and_warnings() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": "bob@foo.com"}
    }));
    // Stage 3 Phase 2：rules = 2.0-full（4 层规则齐活）；crf / fingerprint 仍 disabled
    let warnings = v["data"]["warnings"].as_array().unwrap();
    let warn_strs: Vec<&str> = warnings.iter().filter_map(|w| w.as_str()).collect();
    // 任一 stage-* 标签即可（Phase 2/3/4 会演进）
    assert!(
        warn_strs.iter().any(|w| w.starts_with("stage-")),
        "expected a stage-* warning; got: {:?}", warn_strs
    );
    // rules 应从 1.0-lite 升到 2.0-full（Phase 2 落地）
    let rules_ver = v["data"]["layer_versions"]["rules"].as_str().unwrap();
    assert!(
        rules_ver == "2.0-full" || rules_ver == "1.0-lite",
        "rules version {} unexpected (should be 2.0-full or legacy 1.0-lite)", rules_ver
    );
    // CRF / Fingerprint 版本字段允许 Stage 3 各 Phase 演进；仅验证格式合法
    let crf_ver = v["data"]["layer_versions"]["crf"].as_str().unwrap();
    assert!(
        crf_ver == "1.0" || crf_ver == "disabled",
        "crf version {} unexpected", crf_ver
    );
    let fp_ver = v["data"]["layer_versions"]["fingerprint"].as_str().unwrap();
    assert!(
        fp_ver == "1.0" || fp_ver == "disabled",
        "fingerprint version {} unexpected", fp_ver
    );
}

#[test]
fn parse_fills_orphans_from_every_candidate_stage2() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let text = "c@d.io\nhttps://x.y\nsk-ant-api03-abcdefghij1234567890";
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": text}
    }));
    let cands = v["data"]["candidates"].as_array().unwrap();
    let orphans = v["data"]["orphans"].as_array().unwrap();
    // Stage 2: 所有候选都是 orphan，无 grouping
    assert_eq!(cands.len(), orphans.len());
}

#[test]
fn parse_rejects_empty_text() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": ""}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_STDIN_INVALID_JSON");
}

#[test]
fn parse_does_not_require_valid_vault_key() {
    // parse 不读 vault → 错的 key 也能 parse；但 key 格式必须合法
    let env = InternalTestEnv::new();
    env.init_vault();
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "parse",
        "payload": {"text": "alice@x.com"}
    }));
    // parse 不校验 key 是否匹配 vault → ok
    assert_eq!(v["status"], "ok", "parse should succeed with any well-formed key: {}", v);
}

#[test]
fn parse_requires_wellformed_vault_key() {
    // 但 key 必须格式合法（协议一致性）
    let env = InternalTestEnv::new();
    env.init_vault();
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": "short",
        "action": "parse",
        "payload": {"text": "x"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_MALFORMED");
}

#[test]
fn parse_respects_max_candidates_cap() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    // 构造 20 个 email
    let text = (1..=20).map(|i| format!("user{}@domain.com", i)).collect::<Vec<_>>().join("\n");
    let v = run_parse(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "parse",
        "payload": {"text": text, "max_candidates": 5}
    }));
    let cands = v["data"]["candidates"].as_array().unwrap();
    assert!(cands.len() <= 5, "cap should be enforced, got {}", cands.len());
}

// ========== Phase F: audit + import_jobs wiring ==========

/// 统计 audit_log / import_jobs / import_items 表行数（sqlite 直读）
fn count_table(env: &InternalTestEnv, table: &str) -> i64 {
    use rusqlite::Connection;
    let db = env.vault_path.join("data").join("vault.db");
    let conn = Connection::open(&db).expect("open");
    conn.query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |r| r.get(0))
        .unwrap_or(0)
}

fn read_import_job(env: &InternalTestEnv, job_id: &str) -> Option<Value> {
    use rusqlite::Connection;
    let db = env.vault_path.join("data").join("vault.db");
    let conn = Connection::open(&db).ok()?;
    conn.query_row(
        "SELECT job_id, source_type, source_hash, total_items, inserted_count, replaced_count, \
         skipped_count, status FROM import_jobs WHERE job_id = ?",
        [job_id],
        |r| {
            Ok(serde_json::json!({
                "job_id": r.get::<_, String>(0)?,
                "source_type": r.get::<_, Option<String>>(1)?,
                "source_hash": r.get::<_, Option<String>>(2)?,
                "total_items": r.get::<_, i64>(3)?,
                "inserted_count": r.get::<_, i64>(4)?,
                "replaced_count": r.get::<_, i64>(5)?,
                "skipped_count": r.get::<_, i64>(6)?,
                "status": r.get::<_, String>(7)?,
            }))
        },
    ).ok()
}

#[test]
fn migrations_create_import_tables() {
    let env = InternalTestEnv::new();
    env.init_vault();
    // migration v1.0.5-alpha 应该在 init_vault 的第一次 add 就跑完
    assert_eq!(count_table(&env, "import_jobs"), 0, "table exists and empty");
    assert_eq!(count_table(&env, "import_items"), 0);
}

#[test]
fn add_writes_audit_log() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let before = count_table(&env, "audit_log");

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "add",
        "payload": {"alias": "audit-test-1", "secret_plaintext": "secret"}
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["audit_logged"], true);
    // audit_log 应该多了一行
    assert!(count_table(&env, "audit_log") > before);
}

#[test]
fn delete_writes_audit_log() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "audit-del", "secret_plaintext": "x"}
    }));
    let before = count_table(&env, "audit_log");
    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "delete",
        "payload": {"alias": "audit-del"}
    }));
    assert_eq!(v["data"]["audit_logged"], true);
    assert!(count_table(&env, "audit_log") > before);
}

#[test]
fn update_secret_writes_audit_log() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "add",
        "payload": {"alias": "audit-upd", "secret_plaintext": "v1"}
    }));
    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "update_secret",
        "payload": {"alias": "audit-upd", "new_secret_plaintext": "v2"}
    }));
    assert_eq!(v["data"]["audit_logged"], true);
}

#[test]
fn update_alias_actions_write_audit() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    seed_credentials(&env, &key_hex);
    let before = count_table(&env, "audit_log");

    let v = run_update_alias(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "set_provider",
        "payload": {"alias": "q-kimi", "provider": "moonshot"}
    }));
    assert_eq!(v["data"]["audit_logged"], true);
    assert!(count_table(&env, "audit_log") > before);
}

#[test]
fn batch_import_with_job_id_writes_import_tables() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let jid = "job-test-aaa";
    assert!(read_import_job(&env, jid).is_none(), "job shouldn't exist yet");

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex,
        "action": "batch_import",
        "payload": {
            "job_id": jid,
            "source_type": "paste",
            "source_hash": "sha256:fake",
            "items": [
                {"alias": "imp-1", "secret_plaintext": "x1", "provider": "anthropic"},
                {"alias": "imp-2", "secret_plaintext": "x2"},
            ]
        }
    }));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["data"]["job_id"], jid);
    assert_eq!(v["data"]["audit_logged"], true);

    let job = read_import_job(&env, jid).expect("job row should exist");
    assert_eq!(job["status"], "completed");
    assert_eq!(job["total_items"], 2);
    assert_eq!(job["inserted_count"], 2);
    assert_eq!(job["replaced_count"], 0);
    assert_eq!(job["source_type"], "paste");
    assert_eq!(job["source_hash"], "sha256:fake");
    // import_items 应该有 2 行与该 job 关联
    use rusqlite::Connection;
    let db = env.vault_path.join("data").join("vault.db");
    let conn = Connection::open(&db).unwrap();
    let items_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM import_items WHERE job_id = ?",
        [jid], |r| r.get(0),
    ).unwrap();
    assert_eq!(items_count, 2);
}

#[test]
fn batch_import_duplicate_job_id_rejected() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let jid = "job-dup";
    // 第一次 ok
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "batch_import",
        "payload": {"job_id": jid, "items": [{"alias":"a","secret_plaintext":"x"}]}
    }));
    // 第二次同 job_id → 冲突
    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "batch_import",
        "payload": {"job_id": jid, "items": [{"alias":"b","secret_plaintext":"y"}]}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_CONFLICT");
}

#[test]
fn batch_import_without_job_id_skips_import_tables() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let jobs_before = count_table(&env, "import_jobs");
    let items_before = count_table(&env, "import_items");

    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "batch_import",
        "payload": {
            "items": [{"alias": "no-job-1", "secret_plaintext": "x"}]
        }
    }));
    assert_eq!(v["status"], "ok");
    // 未传 job_id → import_jobs/items 不变
    assert_eq!(count_table(&env, "import_jobs"), jobs_before);
    assert_eq!(count_table(&env, "import_items"), items_before);
}

// ========== Phase G: list_import_jobs / get_import_job_items query actions ==========

#[test]
fn list_import_jobs_returns_recent_first() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();

    // 种 3 个 job
    for i in 1..=3 {
        run_vault_op(&env, serde_json::json!({
            "vault_key_hex": key_hex, "action": "batch_import",
            "payload": {
                "job_id": format!("job-list-{}", i),
                "items": [{"alias": format!("la-{}", i), "secret_plaintext": "x"}]
            }
        }));
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "list_import_jobs",
    }));
    assert_eq!(v["status"], "ok", "{}", v);
    let jobs = v["data"]["jobs"].as_array().unwrap();
    assert!(jobs.len() >= 3, "should have at least 3 jobs, got {}", jobs.len());

    // 最近创建的应该在最前（DESC）
    let ts_first = jobs[0]["created_at"].as_i64().unwrap();
    let ts_last = jobs[jobs.len() - 1]["created_at"].as_i64().unwrap();
    assert!(ts_first >= ts_last, "created_at DESC: first {} < last {}", ts_first, ts_last);
}

#[test]
fn list_import_jobs_respects_limit() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    for i in 1..=4 {
        run_vault_op(&env, serde_json::json!({
            "vault_key_hex": key_hex, "action": "batch_import",
            "payload": {
                "job_id": format!("job-lim-{}", i),
                "items": [{"alias": format!("lim-{}", i), "secret_plaintext": "x"}]
            }
        }));
    }
    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "list_import_jobs",
        "payload": {"limit": 2}
    }));
    let jobs = v["data"]["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
}

#[test]
fn list_import_jobs_filters_by_status() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "batch_import",
        "payload": {
            "job_id": "job-st-1",
            "items": [{"alias": "st-1", "secret_plaintext": "x"}]
        }
    }));
    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "list_import_jobs",
        "payload": {"status": "completed"}
    }));
    let jobs = v["data"]["jobs"].as_array().unwrap();
    assert!(!jobs.is_empty());
    for j in jobs {
        assert_eq!(j["status"], "completed");
    }
    // 不存在的 status → 空
    let v2 = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "list_import_jobs",
        "payload": {"status": "aborted"}
    }));
    assert_eq!(v2["data"]["count"], 0);
}

#[test]
fn get_import_job_items_returns_item_details() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let jid = "job-items-test";
    run_vault_op(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "batch_import",
        "payload": {
            "job_id": jid,
            "items": [
                {"alias": "item-1", "secret_plaintext": "a", "provider": "anthropic"},
                {"alias": "item-2", "secret_plaintext": "b"},
                {"alias": "item-3", "secret_plaintext": "c", "provider": "openai"},
            ]
        }
    }));

    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "get_import_job_items",
        "payload": {"job_id": jid}
    }));
    assert_eq!(v["status"], "ok", "{}", v);
    assert_eq!(v["data"]["count"], 3);
    let items = v["data"]["items"].as_array().unwrap();
    let aliases: Vec<&str> = items.iter().map(|i| i["alias"].as_str().unwrap()).collect();
    assert!(aliases.contains(&"item-1"));
    assert!(aliases.contains(&"item-2"));
    assert!(aliases.contains(&"item-3"));
    // 验证 action + provider_code 字段
    let i1 = items.iter().find(|i| i["alias"] == "item-1").unwrap();
    assert_eq!(i1["action"], "inserted");
    assert_eq!(i1["provider_code"], "anthropic");
}

#[test]
fn get_import_job_items_not_found() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let key_hex = env.vault_key_hex();
    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": key_hex, "action": "get_import_job_items",
        "payload": {"job_id": "does-not-exist"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_CREDENTIAL_NOT_FOUND");
}

#[test]
fn list_import_jobs_rejects_wrong_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let v = run_query(&env, serde_json::json!({
        "vault_key_hex": "0".repeat(64),
        "action": "list_import_jobs",
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_INVALID");
}

#[test]
fn mutating_actions_reject_wrong_key() {
    let env = InternalTestEnv::new();
    env.init_vault();
    let wrong_key = "f".repeat(64);
    let before = count_entries(&env);

    // add 应在写之前 reject
    let v = run_vault_op(&env, serde_json::json!({
        "vault_key_hex": wrong_key,
        "action": "add",
        "payload": {"alias": "should-not-land", "secret_plaintext": "x"}
    }));
    assert_eq!(v["status"], "error");
    assert_eq!(v["error_code"], "I_VAULT_KEY_INVALID");
    assert_eq!(count_entries(&env), before, "wrong key must not write");
}
