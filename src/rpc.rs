/// JSON-RPC 2.0 protocol implementation
/// Defines request/response structures, error model, and method constants

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    pub params: RequestParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// Request parameters with protocol version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(flatten)]
    pub data: serde_json::Value,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub jsonrpc: String,
    pub result: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub jsonrpc: String,
    pub error: RpcError,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// RPC method names
pub mod methods {
    pub const SYSTEM_PING: &str = "system.ping";
    pub const SYSTEM_STATUS: &str = "system.status";

    pub const AUTH_UNLOCK: &str = "auth.unlock";
    pub const AUTH_LOCK: &str = "auth.lock";
    pub const AUTH_SESSION_STATUS: &str = "auth.session.status";

    pub const PROFILE_LIST: &str = "profile.list";
    pub const PROFILE_CURRENT: &str = "profile.current";
    pub const PROFILE_USE: &str = "profile.use";
    pub const PROFILE_CREATE: &str = "profile.create";
    pub const PROFILE_DELETE: &str = "profile.delete";

    pub const SECRET_LIST: &str = "secret.list";
    pub const SECRET_GET: &str = "secret.get";
    pub const SECRET_UPSERT: &str = "secret.upsert";
    pub const SECRET_DELETE: &str = "secret.delete";

    pub const BINDING_LIST: &str = "binding.list";
    pub const BINDING_SET: &str = "binding.set";
    pub const BINDING_DELETE: &str = "binding.delete";

    pub const ENV_RESOLVE: &str = "env.resolve";
}

/// RPC error codes
pub mod error_codes {
    // Standard errors (external)
    pub const UNSUPPORTED_PROTOCOL: i32 = -32001;
    pub const INTERNAL_ERROR: i32 = -32603;

    // Daemon-level errors (internal)
    pub const UNAUTHORIZED: i32 = -32002;
    pub const FORBIDDEN: i32 = -32003;
    pub const IO_ERROR: i32 = -32004;
    pub const TIMEOUT: i32 = -32005;
    pub const VAULT_NOT_INITIALIZED: i32 = -32006;
    pub const PROFILE_NOT_FOUND: i32 = -32007;

    // Legacy CLI error codes (mapped to RPC)
    pub const ALIAS_EXISTS: i32 = 1001;
    pub const ALIAS_NOT_FOUND: i32 = 1002;
    pub const VAULT_LOCKED: i32 = 1003;
    pub const NO_ACTIVE_PROFILE: i32 = 1004;
    pub const INVALID_INPUT: i32 = 1005;
    pub const UNKNOWN_ERROR: i32 = 1006;
}

/// Current protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

impl Request {
    pub fn new(method: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params: RequestParams {
                protocol_version: PROTOCOL_VERSION.to_string(),
                data,
            },
            id: None,
        }
    }

    pub fn with_id(mut self, id: serde_json::Value) -> Self {
        self.id = Some(id);
        self
    }

    /// Check if protocol version is supported
    pub fn is_protocol_supported(&self) -> bool {
        // For now, only support exact version match
        self.params.protocol_version == PROTOCOL_VERSION
    }
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn unsupported_protocol() -> Self {
        Self::new(error_codes::UNSUPPORTED_PROTOCOL, "Unsupported protocol version")
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(error_codes::INTERNAL_ERROR, msg)
    }

    pub fn vault_not_initialized() -> Self {
        Self::new(error_codes::VAULT_NOT_INITIALIZED, "Vault not initialized")
    }

    pub fn profile_not_found(name: &str) -> Self {
        Self::new(error_codes::PROFILE_NOT_FOUND, format!("Profile not found: {}", name))
    }

    pub fn alias_exists(name: &str) -> Self {
        Self::new(error_codes::ALIAS_EXISTS, format!("Secret already exists: {}", name))
    }

    pub fn alias_not_found(name: &str) -> Self {
        Self::new(error_codes::ALIAS_NOT_FOUND, format!("Secret not found: {}", name))
    }

    pub fn no_active_profile() -> Self {
        Self::new(error_codes::NO_ACTIVE_PROFILE, "No active profile configured")
    }

    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_INPUT, msg)
    }
}

impl SuccessResponse {
    pub fn new(result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result,
            id: None,
        }
    }

    pub fn with_id(mut self, id: serde_json::Value) -> Self {
        self.id = Some(id);
        self
    }
}

impl ErrorResponse {
    pub fn new(error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            error,
            id: None,
        }
    }

    pub fn with_id(mut self, id: serde_json::Value) -> Self {
        self.id = Some(id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_check() {
        let req = Request::new("system.ping", serde_json::json!({}));
        assert!(req.is_protocol_supported());
    }

    #[test]
    fn test_unsupported_protocol() {
        let mut req = Request::new("system.ping", serde_json::json!({}));
        req.params.protocol_version = "2.0.0".to_string();
        assert!(!req.is_protocol_supported());
    }

    #[test]
    fn test_error_serialization() {
        let err = RpcError::unsupported_protocol();
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("Unsupported protocol version"));
    }
}
