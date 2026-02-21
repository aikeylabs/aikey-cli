/// Standard error codes for Platform API (v0.2)
/// These codes provide a stable interface for IDE and tool integrations

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Secret with the given name already exists
    AliasExists,
    /// Secret with the given name does not exist
    AliasNotFound,
    /// Vault is locked or password is incorrect
    VaultLocked,
    /// No active profile is configured
    NoActiveProfile,
    /// Invalid input provided
    InvalidInput,
    /// Unknown or unclassified error
    UnknownError,
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
