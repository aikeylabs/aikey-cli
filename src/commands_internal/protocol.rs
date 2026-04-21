//! `aikey _internal *` stdin-json IPC 协议
//!
//! 所有 `_internal` 子命令遵循统一信封：
//!
//! stdin:
//! ```json
//! {
//!   "vault_key_hex": "64 char hex (Argon2id 派生 key 的 hex 编码)",
//!   "action": "verify|add|batch_import|update_secret|delete|query|update_alias|parse",
//!   "request_id": "uuid-v4（可选，echo 回 stdout 便于追踪）",
//!   "payload": { /* action-specific */ }
//! }
//! ```
//!
//! stdout（成功和失败都用同一信封）：
//! ```json
//! {
//!   "request_id": "...",
//!   "status": "ok|error",
//!   "error_code": "I_* (仅 error 时)",
//!   "error_message": "human readable (仅 error 时)",
//!   "data": { /* action-specific (仅 ok 时) */ }
//! }
//! ```
//!
//! Why 统一信封：Go local-server spawn subprocess 时可以泛化解析（不用按 action 写 N 份解析代码），
//! 错误处理路径也一致。对比 exit code + stderr 的 ad-hoc 协议，stdin-json 更易测、更可演进。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// stdin 信封：Go local-server → Rust cli subprocess
#[derive(Debug, Clone, Deserialize)]
pub struct StdinEnvelope {
    /// 32 字节 Argon2id 派生 key 的 hex 编码（64 chars）
    pub vault_key_hex: String,

    /// action 名称（以 action 区分具体操作）
    pub action: String,

    /// 可选 request_id，echo 回 stdout 便于 Go 侧追踪
    #[serde(default)]
    pub request_id: Option<String>,

    /// action-specific payload（Phase B-E 对应 action 会用到；Phase A verify 不用）
    #[serde(default)]
    #[allow(dead_code)]
    pub payload: Value,
}

/// stdout 信封：Rust cli → Go local-server
#[derive(Debug, Clone, Serialize)]
pub struct ResultEnvelope {
    /// echo 回 stdin.request_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// "ok" | "error"
    pub status: &'static str,

    /// 成功时的数据（action-specific）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,

    /// 失败时的错误码（I_* 前缀）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,

    /// 失败时的人读消息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl ResultEnvelope {
    pub fn ok(request_id: Option<String>, data: Value) -> Self {
        Self {
            request_id,
            status: "ok",
            data: Some(data),
            error_code: None,
            error_message: None,
        }
    }

    #[allow(dead_code)]  // Phase B-E vault-op actions 会用到
    pub fn ok_empty(request_id: Option<String>) -> Self {
        Self {
            request_id,
            status: "ok",
            data: Some(serde_json::json!({})),
            error_code: None,
            error_message: None,
        }
    }

    pub fn error(request_id: Option<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            request_id,
            status: "error",
            data: None,
            error_code: Some(code),
            error_message: Some(message.into()),
        }
    }
}
