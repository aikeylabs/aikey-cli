//! stdin-json IPC 工具：读 stdin → 解析 JSON → emit stdout JSON

use std::io::{self, Read, Write};

use super::protocol::{ResultEnvelope, StdinEnvelope};

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
