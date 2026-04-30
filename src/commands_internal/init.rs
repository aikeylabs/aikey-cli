//! `_internal init` action — vault first-time setup driven by Web UI.
//!
//! Unlike vault-op, this action precedes vault existence: there is no
//! vault_key to derive yet. Hence the dedicated handler with its own
//! envelope shape that omits `vault_key_hex`.
//!
//! Per 20260430-个人vault-Web首次设置-方案A.md: aikey-local-server's
//! POST /api/user/vault/init invokes this subprocess with stdin JSON
//! `{password, request_id?}`, and the same business logic core that
//! `aikey init` (CLI shell) uses runs end-to-end. No prompts, no TTY.

use std::io::{self, Read, Write};

use secrecy::SecretString;
use serde::Deserialize;

use crate::commands_init::core as init_core;
use super::internal_log;
use super::protocol::ResultEnvelope;

#[derive(Debug, Deserialize)]
struct InitEnvelope {
    password: String,
    #[serde(default)]
    request_id: Option<String>,
}

const ACTION: &str = "init";

/// Entry point — reads its own envelope so it doesn't trip on the
/// vault-op envelope's `vault_key_hex` requirement.
pub fn handle() {
    let started = std::time::Instant::now();

    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        emit_error(
            None,
            "I_STDIN_READ_FAILED",
            format!("failed to read stdin: {}", e),
            started,
        );
        return;
    }
    if buf.trim().is_empty() {
        emit_error(
            None,
            "I_STDIN_INVALID_JSON",
            "stdin is empty (expected JSON envelope)".to_string(),
            started,
        );
        return;
    }

    let env: InitEnvelope = match serde_json::from_str(&buf) {
        Ok(e) => e,
        Err(e) => {
            emit_error(
                None,
                "I_STDIN_INVALID_JSON",
                format!("stdin is not valid JSON: {}", e),
                started,
            );
            return;
        }
    };

    let req_id = env.request_id.clone();

    if env.password.is_empty() {
        emit_error(
            req_id,
            "I_PASSWORD_REQUIRED",
            "password must be non-empty".to_string(),
            started,
        );
        return;
    }

    let password = SecretString::from(env.password);

    match init_core::initialize(&password) {
        Ok(()) => {
            let result = ResultEnvelope::ok(
                req_id.clone(),
                serde_json::json!({"message": "vault initialized"}),
            );
            internal_log::log_dispatch_success(
                ACTION,
                req_id.as_deref(),
                result.data.as_ref().unwrap_or(&serde_json::Value::Null),
                started.elapsed().as_millis(),
            );
            emit(&result);
        }
        Err(msg) => {
            // storage::initialize_vault returns this exact error string when
            // the vault is already initialized — map to a stable error code
            // so the web layer can render "already initialized, refresh
            // status" without parsing the human message.
            let code = if msg.contains("Vault already initialized") {
                "I_VAULT_ALREADY_INITIALIZED"
            } else {
                "I_VAULT_INIT_FAILED"
            };
            emit_error(req_id, code, msg, started);
        }
    }
}

fn emit(result: &ResultEnvelope) {
    let out = serde_json::to_string(result).unwrap_or_else(|_| {
        r#"{"status":"error","error_code":"I_INTERNAL","error_message":"failed to serialize"}"#
            .to_string()
    });
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{}", out);
    let _ = stdout.flush();
}

fn emit_error(
    req_id: Option<String>,
    code: &'static str,
    message: String,
    started: std::time::Instant,
) {
    let env = ResultEnvelope::error(req_id.clone(), code, message.clone());
    internal_log::log_dispatch_error(
        ACTION,
        req_id.as_deref(),
        code,
        &message,
        started.elapsed().as_millis(),
    );
    emit(&env);
}
