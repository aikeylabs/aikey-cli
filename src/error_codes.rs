//! Unified error model for CLI
//! Provides structured error codes and messages for consistent error handling

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    // External/stable codes (guaranteed in CLI responses)
    AliasExists,
    AliasNotFound,
    VaultLocked,
    NoActiveProfile,
    InvalidInput,
    UnknownError,
    UnsupportedProtocol,
    InternalError,

    // Internal codes
    Unauthorized,
    Forbidden,
    IoError,
    Timeout,
    VaultNotInitialized,
    ProfileNotFound,

    // ===== `_internal` IPC 错误码（I_ 前缀）=====
    // 用于 `aikey _internal *` 子命令组的 stdin-json 协议。
    // 这些错误码通过 stdout JSON 返回给 Go local-server（不是 exit code）。
    // 新增时：同步更新 as_str() / code() 映射 + docs/VAULT_SPEC.md 错误码表。
    InternalStdinInvalidJson,       // I_STDIN_INVALID_JSON
    InternalStdinReadFailed,        // I_STDIN_READ_FAILED
    InternalVaultKeyMalformed,      // I_VAULT_KEY_MALFORMED（hex 长度/格式错）
    InternalVaultKeyInvalid,        // I_VAULT_KEY_INVALID（key 不匹配 vault）
    InternalVaultNotInitialized,    // I_VAULT_NOT_INITIALIZED
    InternalVaultOpenFailed,        // I_VAULT_OPEN_FAILED
    InternalUnknownAction,          // I_UNKNOWN_ACTION（envelope.action 不认识）
    InternalNotImplemented,         // I_NOT_IMPLEMENTED（Phase 占位）
    InternalCredentialNotFound,     // I_CREDENTIAL_NOT_FOUND
    InternalCredentialConflict,     // I_CREDENTIAL_CONFLICT（add 时 alias 已存在）
    InternalParseFailed,            // I_PARSE_FAILED（解析引擎三层流水失败）
    InternalIo,                     // I_INTERNAL（serialize/io 等意外内部错误）
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::AliasExists => "ALIAS_EXISTS",
            ErrorCode::AliasNotFound => "ALIAS_NOT_FOUND",
            ErrorCode::VaultLocked => "VAULT_LOCKED",
            ErrorCode::NoActiveProfile => "NO_ACTIVE_PROFILE",
            ErrorCode::InvalidInput => "INVALID_INPUT",
            ErrorCode::UnknownError => "UNKNOWN_ERROR",
            ErrorCode::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
            ErrorCode::InternalError => "INTERNAL_ERROR",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::Forbidden => "FORBIDDEN",
            ErrorCode::IoError => "IO_ERROR",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::VaultNotInitialized => "VAULT_NOT_INITIALIZED",
            ErrorCode::ProfileNotFound => "PROFILE_NOT_FOUND",
            // _internal IPC 错误码
            ErrorCode::InternalStdinInvalidJson => "I_STDIN_INVALID_JSON",
            ErrorCode::InternalStdinReadFailed => "I_STDIN_READ_FAILED",
            ErrorCode::InternalVaultKeyMalformed => "I_VAULT_KEY_MALFORMED",
            ErrorCode::InternalVaultKeyInvalid => "I_VAULT_KEY_INVALID",
            ErrorCode::InternalVaultNotInitialized => "I_VAULT_NOT_INITIALIZED",
            ErrorCode::InternalVaultOpenFailed => "I_VAULT_OPEN_FAILED",
            ErrorCode::InternalUnknownAction => "I_UNKNOWN_ACTION",
            ErrorCode::InternalNotImplemented => "I_NOT_IMPLEMENTED",
            ErrorCode::InternalCredentialNotFound => "I_CREDENTIAL_NOT_FOUND",
            ErrorCode::InternalCredentialConflict => "I_CREDENTIAL_CONFLICT",
            ErrorCode::InternalParseFailed => "I_PARSE_FAILED",
            ErrorCode::InternalIo => "I_INTERNAL",
        }
    }

    pub fn code(&self) -> i32 {
        match self {
            ErrorCode::AliasExists => 1001,
            ErrorCode::AliasNotFound => 1002,
            ErrorCode::VaultLocked => 1003,
            ErrorCode::NoActiveProfile => 1004,
            ErrorCode::InvalidInput => 1005,
            ErrorCode::UnknownError => 1006,
            ErrorCode::UnsupportedProtocol => -32001,
            ErrorCode::InternalError => -32603,
            ErrorCode::Unauthorized => -32002,
            ErrorCode::Forbidden => -32003,
            ErrorCode::IoError => -32004,
            ErrorCode::Timeout => -32005,
            ErrorCode::VaultNotInitialized => -32006,
            ErrorCode::ProfileNotFound => -32007,
            // _internal IPC: 负数区间（与其他 internal 保持一致）
            ErrorCode::InternalStdinInvalidJson => -32101,
            ErrorCode::InternalStdinReadFailed => -32102,
            ErrorCode::InternalVaultKeyMalformed => -32103,
            ErrorCode::InternalVaultKeyInvalid => -32104,
            ErrorCode::InternalVaultNotInitialized => -32105,
            ErrorCode::InternalVaultOpenFailed => -32106,
            ErrorCode::InternalUnknownAction => -32107,
            ErrorCode::InternalNotImplemented => -32108,
            ErrorCode::InternalCredentialNotFound => -32109,
            ErrorCode::InternalCredentialConflict => -32110,
            ErrorCode::InternalParseFailed => -32111,
            ErrorCode::InternalIo => -32199,
        }
    }

    /// Map internal error messages to error codes
    pub fn from_error_message(msg: &str) -> Self {
        if msg.contains("already exists") || msg.contains("duplicate") {
            ErrorCode::AliasExists
        } else if msg.contains("not found") || msg.contains("does not exist") {
            ErrorCode::AliasNotFound
        } else if msg.contains("password") || msg.contains("authentication") || msg.contains("locked") {
            ErrorCode::VaultLocked
        } else if msg.contains("profile") {
            ErrorCode::NoActiveProfile
        } else if msg.contains("invalid") {
            ErrorCode::InvalidInput
        } else {
            ErrorCode::UnknownError
        }
    }
}

/// Centralized user-facing message templates.
/// Use these constants instead of hardcoding strings at call sites.
pub mod msgs {
    pub const NO_CONFIG_FOUND: &str =
        "No aikey.config.json found. Run 'aikey project init' to create one.";
    pub const NO_CONFIG_FOUND_HINT: &str =
        "No aikey.config.json found. Run 'aikey project init' to create one, or use --provider to specify a provider directly.";
    pub const NO_CONFIG_FOUND_DIR: &str =
        "No aikey.config.json found in current directory or parent directories";
    pub const NO_PROJECT_CONFIG: &str =
        "No project configuration found. Run 'aikey project init' first.";
    pub const INVALID_PASSWORD: &str = "Invalid master password or corrupted vault.";
    pub const INVALID_PASSWORD_SHORT: &str = "Invalid master password.";
}

/// Unified error type for CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn alias_exists(name: &str) -> Self {
        Self::new(ErrorCode::AliasExists, format!("Secret already exists: {}", name))
    }

    pub fn alias_not_found(name: &str) -> Self {
        Self::new(ErrorCode::AliasNotFound, format!("Secret not found: {}", name))
    }

    pub fn vault_locked() -> Self {
        Self::new(ErrorCode::VaultLocked, "Vault is locked or password is incorrect")
    }

    pub fn no_active_profile() -> Self {
        Self::new(ErrorCode::NoActiveProfile, "No active profile is configured")
    }

    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, msg)
    }

    pub fn unknown_error(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnknownError, msg)
    }

    pub fn vault_not_initialized() -> Self {
        Self::new(ErrorCode::VaultNotInitialized, "Vault not initialized. Run any aikey command to initialize it automatically.")
    }

    pub fn profile_not_found(name: &str) -> Self {
        Self::new(ErrorCode::ProfileNotFound, format!("Profile not found: {}", name))
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, msg)
    }
}
