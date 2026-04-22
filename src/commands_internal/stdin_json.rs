//! stdin-json IPC 工具：读 stdin → 解析 JSON → emit stdout JSON
//!
//! 2026-04-22 L2 observability: every `emit` / `emit_error` also writes a
//! structured outcome line to `~/.aikey/logs/aikey-cli/internal.jsonl`.
//! The dispatch context (action name, request_id, dispatch_start_at) is
//! set by `commands_internal::dispatch` right after envelope parse so
//! `emit` can stamp duration + action onto the outcome event without
//! threading extra params through every action handler.

use std::io::{self, Read, Write};
use std::sync::Mutex;
use std::time::Instant;

use super::internal_log;
use super::protocol::{ResultEnvelope, StdinEnvelope};

/// Per-process dispatch context set by `commands_internal::dispatch`. The
/// `_internal` CLI runs exactly one subcommand per process, so a single
/// global slot is safe — no concurrency. Kept under a `Mutex` purely to
/// satisfy `Sync` without unsafe.
struct DispatchCtx {
    action: &'static str,
    request_id: Option<String>,
    started_at: Instant,
}
static DISPATCH_CTX: Mutex<Option<DispatchCtx>> = Mutex::new(None);

/// Called by `commands_internal::dispatch` once the envelope has parsed
/// successfully. Records the action name + request_id + start time so
/// `emit` / `emit_error` can emit the outcome log line.
pub fn set_dispatch_context(action: &'static str, request_id: Option<String>) {
    if let Ok(mut g) = DISPATCH_CTX.lock() {
        *g = Some(DispatchCtx {
            action,
            request_id,
            started_at: Instant::now(),
        });
    }
}

fn take_dispatch_context() -> Option<(&'static str, Option<String>, u128)> {
    let mut g = DISPATCH_CTX.lock().ok()?;
    let ctx = g.take()?;
    Some((ctx.action, ctx.request_id, ctx.started_at.elapsed().as_millis()))
}

/// 从 stdin 读全部字节并解析为 `StdinEnvelope`
///
/// 失败（非法 JSON / 缺字段 / stdin 读失败）直接返回 Err(error_code, message)，
/// 调用方应立刻 `emit_error` 并退出。
pub fn read_envelope() -> Result<StdinEnvelope, (&'static str, String)> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| ("I_STDIN_READ_FAILED", format!("failed to read stdin: {}", e)))?;

    if buf.trim().is_empty() {
        return Err((
            "I_STDIN_INVALID_JSON",
            "stdin is empty (expected JSON envelope)".to_string(),
        ));
    }

    let env: StdinEnvelope = serde_json::from_str(&buf)
        .map_err(|e| ("I_STDIN_INVALID_JSON", format!("stdin is not valid JSON: {}", e)))?;

    // vault_key_hex 必须 64 chars（32 bytes）
    if env.vault_key_hex.len() != 64 {
        return Err((
            "I_VAULT_KEY_MALFORMED",
            format!(
                "vault_key_hex must be 64 hex characters (got {})",
                env.vault_key_hex.len()
            ),
        ));
    }

    Ok(env)
}

/// 把 ResultEnvelope 序列化并写到 stdout，刷新并换行
pub fn emit(env: &ResultEnvelope) {
    // Log the outcome BEFORE writing to stdout. That way if stdout is
    // closed (Go parent crashed) we still have the observation.
    //
    // `take_dispatch_context` returns None for the "context never set"
    // path — e.g. envelope parse failed before dispatch could mark
    // start. In that case we skip the structured outcome log; the
    // error-path log from `emit_error` on the read-fail branch already
    // covers it.
    if let Some((action, req_id, duration_ms)) = take_dispatch_context() {
        match env.status {
            "ok" => {
                let data = env.data.clone().unwrap_or(serde_json::Value::Null);
                internal_log::log_dispatch_success(action, req_id.as_deref(), &data, duration_ms);
            }
            _ => {
                let code = env.error_code.unwrap_or("I_UNKNOWN");
                let msg = env.error_message.clone().unwrap_or_default();
                internal_log::log_dispatch_error(action, req_id.as_deref(), code, &msg, duration_ms);
            }
        }
    }

    let out = serde_json::to_string(env).unwrap_or_else(|_| {
        // Fallback: 即使序列化失败也要给 caller 一个合法 JSON
        r#"{"status":"error","error_code":"I_INTERNAL","error_message":"failed to serialize result"}"#
            .to_string()
    });
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{}", out);
    let _ = stdout.flush();
}

/// 便捷方法：直接 emit error 并返回
pub fn emit_error(request_id: Option<String>, code: &'static str, message: impl Into<String>) {
    emit(&ResultEnvelope::error(request_id, code, message));
}

/// 把 `vault_key_hex` 解码为 32 字节 key
pub fn decode_vault_key(hex_str: &str) -> Result<[u8; 32], (&'static str, String)> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ("I_VAULT_KEY_MALFORMED", format!("vault_key_hex decode failed: {}", e)))?;
    if bytes.len() != 32 {
        return Err((
            "I_VAULT_KEY_MALFORMED",
            format!("vault_key_hex decoded to {} bytes, expected 32", bytes.len()),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
