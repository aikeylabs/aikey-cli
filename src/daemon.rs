//! Daemon server implementation for AiKey
//!
//! Provides a JSON-RPC 2.0 server that handles requests from CLI clients
//! and other applications. Supports Unix sockets on Unix systems and TCP on all platforms.

use crate::rpc::{Request, Response, SuccessResponse, ErrorResponse, RpcError, methods};
use crate::rpc::error_codes;
use crate::executor;
use crate::core;
use crate::storage;
use secrecy::{SecretString, ExposeSecret};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::fs;

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// TCP port for the daemon (default: 9999)
    pub port: u16,
    /// Unix socket path (Unix only)
    pub socket_path: Option<PathBuf>,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Whether to use Unix socket (if available)
    pub use_unix_socket: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            port: 9999,
            socket_path: Self::default_socket_path(),
            max_connections: 100,
            use_unix_socket: cfg!(unix),
        }
    }
}

impl DaemonConfig {
    /// Get default Unix socket path
    #[cfg(unix)]
    fn default_socket_path() -> Option<PathBuf> {
        // Explicit override
        if let Ok(path) = std::env::var("AIKEYD_SOCKET_PATH") {
            return Some(PathBuf::from(path));
        }

        // Derive from test/storage overrides to isolate per-vault daemon during tests
        if let Ok(test_path) = std::env::var("AK_VAULT_PATH").or_else(|_| std::env::var("AK_STORAGE_PATH")) {
            let path = PathBuf::from(test_path);
            if path.extension().and_then(|e| e.to_str()) == Some("db") {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("aikeyd");
                if let Some(parent) = path.parent() {
                    return Some(parent.join(format!("aikeyd-{}.sock", stem)));
                }
            } else {
                return Some(path.join("aikeyd.sock"));
            }
        }

        // Fall back to ~/.aikey/aikeyd.sock
        if let Some(home) = dirs::home_dir() {
            return Some(home.join(".aikey").join("aikeyd.sock"));
        }

        dirs::runtime_dir().map(|dir| dir.join("aikeyd.sock"))
    }

    #[cfg(not(unix))]
    fn default_socket_path() -> Option<PathBuf> {
        None
    }
}

/// Daemon server state
pub struct DaemonServer {
    config: DaemonConfig,
    vault_password: Arc<Mutex<Option<String>>>,
}

impl DaemonServer {
    /// Create a new daemon server
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            vault_password: Arc::new(Mutex::new(None)),
        }
    }

    /// Set the vault password for this session
    pub fn set_password(&self, password: String) -> Result<(), String> {
        let mut pwd = self.vault_password.lock()
            .map_err(|e| format!("Failed to acquire password lock: {}", e))?;
        *pwd = Some(password);
        Ok(())
    }

    /// Start the daemon server
    pub fn start(&self) -> Result<(), String> {
        #[cfg(unix)]
        if self.config.use_unix_socket {
            if let Some(socket_path) = &self.config.socket_path {
                return self.start_unix_socket(socket_path);
            }
        }

        self.start_tcp()
    }

    /// Start TCP server
    fn start_tcp(&self) -> Result<(), String> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.config.port))
            .map_err(|e| format!("Failed to bind to port {}: {}", self.config.port, e))?;

        eprintln!("AiKey daemon listening on 127.0.0.1:{}", self.config.port);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let vault_pwd = Arc::clone(&self.vault_password);
                    thread::spawn(move || {
                        if let Err(e) = handle_tcp_client(stream, vault_pwd) {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Start Unix socket server
    #[cfg(unix)]
    fn start_unix_socket(&self, socket_path: &PathBuf) -> Result<(), String> {
        // Check if daemon is already running
        if socket_path.exists() {
            // Try to connect to see if it's actually running
            match UnixStream::connect(socket_path) {
                Ok(_) => {
                    return Err(format!("AiKey daemon is already running at {:?}", socket_path));
                }
                Err(_) => {
                    // Socket exists but daemon isn't running, remove stale socket
                    fs::remove_file(socket_path)
                        .map_err(|e| format!("Failed to remove stale socket: {}", e))?;
                }
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create socket directory: {}", e))?;
        }

        let listener = UnixListener::bind(socket_path)
            .map_err(|e| format!("Failed to bind Unix socket at {:?}: {}", socket_path, e))?;

        // Set restrictive permissions (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(socket_path, perms)
                .map_err(|e| format!("Failed to set socket permissions: {}", e))?;
        }

        eprintln!("AiKey daemon listening on Unix socket: {:?}", socket_path);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let vault_pwd = Arc::clone(&self.vault_password);
                    thread::spawn(move || {
                        if let Err(e) = handle_unix_client(stream, vault_pwd) {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// Handle a single TCP client connection
fn handle_tcp_client(mut stream: TcpStream, vault_password: Arc<Mutex<Option<String>>>) -> Result<(), String> {
    let mut buffer = vec![0; 8192];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                let request_data = &buffer[..n];
                let response = process_request(request_data, &vault_password)?;

                stream.write_all(response.as_bytes())
                    .map_err(|e| format!("Failed to write response: {}", e))?;

                // Close connection after a single request to unblock client reads
                break;
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single Unix socket client connection
#[cfg(unix)]
fn handle_unix_client(mut stream: UnixStream, vault_password: Arc<Mutex<Option<String>>>) -> Result<(), String> {
    let mut buffer = vec![0; 8192];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                let request_data = &buffer[..n];
                let response = process_request(request_data, &vault_password)?;

                stream.write_all(response.as_bytes())
                    .map_err(|e| format!("Failed to write response: {}", e))?;

                // Close connection after a single request to unblock client reads
                break;
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn unauthorized_error() -> RpcError {
    RpcError::new(error_codes::UNAUTHORIZED, "Unauthorized: vault password not set")
}

fn internal_error(msg: impl Into<String>) -> RpcError {
    RpcError::new(error_codes::INTERNAL_ERROR, msg)
}

/// Process a JSON-RPC request
fn process_request(data: &[u8], vault_password: &Arc<Mutex<Option<String>>>) -> Result<String, String> {
    let request_str = String::from_utf8(data.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in request: {}", e))?;

    let request: Request = serde_json::from_str(&request_str)
        .map_err(|e| format!("Invalid JSON-RPC request: {}", e))?;

    // Check protocol version
    if !request.is_protocol_supported() {
        let err = RpcError::unsupported_protocol();
        let resp = ErrorResponse::new(err).with_id(request.id.unwrap_or(Value::Null));
        return serde_json::to_string(&Response::Error(resp))
            .map_err(|e| format!("Failed to serialize response: {}", e));
    }

    let response = match request.method.as_str() {
        // System methods
        methods::SYSTEM_PING => handle_system_ping(&request),
        methods::SYSTEM_STATUS => handle_system_status(&request, &vault_password),

        // Auth methods (allow setting/clearing vault password)
        methods::AUTH_UNLOCK => handle_auth_unlock(&request, &vault_password),
        methods::AUTH_LOCK => handle_auth_lock(&request, &vault_password),
        methods::AUTH_SESSION_STATUS => handle_auth_session_status(&request, &vault_password),

        // Profile methods
        methods::PROFILE_LIST => handle_profile_list(&request),
        methods::PROFILE_CURRENT => handle_profile_current(&request),
        methods::PROFILE_USE => handle_profile_use(&request),
        methods::PROFILE_CREATE => handle_profile_create(&request),
        methods::PROFILE_DELETE => handle_profile_delete(&request),

        // Secret methods
        methods::SECRET_GET => handle_get_secret(&request, vault_password),
        methods::SECRET_LIST => handle_list_secrets(&request, vault_password),
        methods::SECRET_UPSERT => handle_upsert_secret(&request, vault_password),
        methods::SECRET_DELETE => handle_delete_secret(&request, vault_password),

        // Binding methods
        methods::BINDING_LIST => handle_list_bindings(&request, vault_password),
        methods::BINDING_SET => handle_set_binding(&request, vault_password),
        methods::BINDING_DELETE => handle_delete_binding(&request, vault_password),

        // Environment methods
        methods::ENV_RESOLVE => handle_resolve_env(&request, vault_password),

        _ => Err(RpcError::new(-32601, "Method not found")),
    };

    let json_response = match response {
        Ok(result) => {
            let mut resp = SuccessResponse::new(result);
            if let Some(id) = request.id {
                resp = resp.with_id(id);
            }
            Response::Success(resp)
        }
        Err(err) => {
            let mut resp = ErrorResponse::new(err);
            if let Some(id) = request.id {
                resp = resp.with_id(id);
            }
            Response::Error(resp)
        }
    };

    serde_json::to_string(&json_response)
        .map_err(|e| format!("Failed to serialize response: {}", e))
}

/// Handle system.ping RPC method
fn handle_system_ping(_request: &Request) -> Result<Value, RpcError> {
    Ok(json!({
        "status": "ok"
    }))
}

/// Handle system.status RPC method
fn handle_system_status(_request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;
    let session_status = if pwd.is_some() { "unlocked" } else { "locked" };

    Ok(json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "session": session_status
    }))
}

/// Handle auth.unlock RPC method (set vault password for session)
fn handle_auth_unlock(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;
    let password = params.get("password")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'password' parameter"))?;

    let mut pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;
    *pwd = Some(password.to_string());

    Ok(json!({
        "status": "unlocked"
    }))
}

/// Handle auth.lock RPC method (clear vault password)
fn handle_auth_lock(_request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let mut pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;
    *pwd = None;

    Ok(json!({
        "status": "locked"
    }))
}

/// Handle auth.session.status RPC method
fn handle_auth_session_status(_request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;
    let status = if pwd.is_some() { "unlocked" } else { "locked" };

    Ok(json!({
        "status": status
    }))
}

/// Handle profile.list RPC method
fn handle_profile_list(_request: &Request) -> Result<Value, RpcError> {
    let profiles = storage::get_all_profiles()
        .map_err(|e| internal_error(format!("Failed to list profiles: {}", e)))?;

    Ok(json!({
        "profiles": profiles
    }))
}

/// Handle profile.current RPC method
fn handle_profile_current(_request: &Request) -> Result<Value, RpcError> {
    let profile = storage::get_active_profile()
        .map_err(|e| internal_error(format!("Failed to get current profile: {}", e)))?;

    match profile {
        Some(p) => Ok(json!({
            "name": p.name
        })),
        None => Err(RpcError::no_active_profile()),
    }
}

/// Handle profile.use RPC method
fn handle_profile_use(request: &Request) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let name = params.get("name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'name' parameter"))?;

    let profile = storage::set_active_profile(name)
        .map_err(|e| internal_error(format!("Failed to set active profile: {}", e)))?;

    Ok(json!({
        "name": profile.name
    }))
}

/// Handle profile.create RPC method
fn handle_profile_create(request: &Request) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let name = params.get("name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'name' parameter"))?;

    let profile = storage::create_profile(name)
        .map_err(|e| internal_error(format!("Failed to create profile: {}", e)))?;

    Ok(json!({
        "profile": profile.name
    }))
}

/// Handle profile.delete RPC method
fn handle_profile_delete(request: &Request) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let name = params.get("name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'name' parameter"))?;

    storage::delete_profile(name)
        .map_err(|e| internal_error(format!("Failed to delete profile: {}", e)))?;

    Ok(json!({
        "profile": name,
        "status": "deleted"
    }))
}


fn handle_get_secret(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let alias = params.get("alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'alias' parameter"))?;

    // Browser policy: require explicit userGesture when surface == "browser"
    let surface = params.get("surface").and_then(|v| v.as_str()).unwrap_or("");
    if surface == "browser" {
        let user_gesture = params
            .get("context")
            .and_then(|v| v.get("userGesture"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !user_gesture {
            return Err(RpcError::new(error_codes::FORBIDDEN, "Browser secret.get requires userGesture"));
        }
    }

    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| unauthorized_error())?;

    let password = SecretString::new(password_str.clone());
    let secret_value = executor::get_secret(alias, &password)
        .map_err(|e| {
            if e.contains("not found") {
                RpcError::alias_not_found(alias)
            } else {
                internal_error(format!("Failed to get secret: {}", e))
            }
        })?;

    Ok(json!({
        "alias": alias,
        "value": secret_value.as_str()
    }))
}

/// Handle list_secrets RPC method
fn handle_list_secrets(_request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| unauthorized_error())?;

    let password = SecretString::new(password_str.clone());
    let secrets = executor::list_secrets_with_metadata(&password)
        .map_err(|e| internal_error(format!("Failed to list secrets: {}", e)))?;

    Ok(json!({
        "secrets": secrets.iter().map(|s| json!({
            "alias": s.alias,
            "created_at": s.created_at
        })).collect::<Vec<_>>()
    }))
}

/// Handle add_secret RPC method
fn handle_add_secret(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let alias = params.get("alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'alias' parameter"))?;

    let value = params.get("value")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'value' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| unauthorized_error())?;

    let password = SecretString::new(password_str.clone());
    executor::add_secret(alias, value, &password)
        .map_err(|e| {
            if e.contains("already exists") {
                RpcError::alias_exists(alias)
            } else {
                internal_error(format!("Failed to add secret: {}", e))
            }
        })?;

    Ok(json!({
        "alias": alias,
        "status": "created"
    }))
}

/// Handle upsert_secret RPC method
fn handle_upsert_secret(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let alias = params.get("alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'alias' parameter"))?;

    let value = params.get("value")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'value' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| unauthorized_error())?;

    let password = SecretString::new(password_str.clone());
    let exists = storage::entry_exists(alias)
        .map_err(|e| internal_error(format!("Failed to check secret existence: {}", e)))?;

    if exists {
        executor::update_secret(alias, value, &password)
            .map_err(|e| internal_error(format!("Failed to update secret: {}", e)))?;
        Ok(json!({
            "alias": alias,
            "status": "updated"
        }))
    } else {
        executor::add_secret(alias, value, &password)
            .map_err(|e| internal_error(format!("Failed to add secret: {}", e)))?;
        Ok(json!({
            "alias": alias,
            "status": "created"
        }))
    }
}

/// Handle delete_secret RPC method
fn handle_delete_secret(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let alias = params.get("alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'alias' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| internal_error("Failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| unauthorized_error())?;

    let password = SecretString::new(password_str.clone());
    executor::delete_secret(alias, &password)
        .map_err(|e| {
            if e.contains("not found") {
                RpcError::alias_not_found(alias)
            } else {
                internal_error(format!("Failed to delete secret: {}", e))
            }
        })?;

    Ok(json!({
        "alias": alias,
        "status": "deleted"
    }))
}

/// Handle list_bindings RPC method
fn handle_list_bindings(request: &Request, _vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'profile_name' parameter"))?;

    let conn = storage::open_connection()
        .map_err(|e| RpcError::internal_error(format!("Failed to get database connection: {}", e)))?;

    let bindings = core::Core::list_profile_bindings(&conn, profile_name)
        .map_err(|e| RpcError::internal_error(format!("Failed to list bindings: {}", e)))?;

    let bindings_json: Vec<Value> = bindings
        .into_iter()
        .map(|(domain, alias)| json!({ "domain": domain, "alias": alias }))
        .collect();

    Ok(json!({
        "profile_name": profile_name,
        "bindings": bindings_json
    }))
}

/// Handle set_binding RPC method
fn handle_set_binding(request: &Request, _vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'profile_name' parameter"))?;

    let secret_alias = params.get("secret_alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'secret_alias' parameter"))?;

    let domain = params.get("domain")
        .and_then(|v: &Value| v.as_str())
        .unwrap_or("default");

    let conn = storage::open_connection()
        .map_err(|e| RpcError::internal_error(format!("Failed to get database connection: {}", e)))?;

    // Ensure secret exists
    storage::get_entry(secret_alias)
        .map_err(|_| RpcError::alias_not_found(secret_alias))?;

    core::Core::bind_secret_to_profile(&conn, profile_name, domain, secret_alias)
        .map_err(|e| RpcError::internal_error(format!("Failed to set binding: {}", e)))?;

    Ok(json!({
        "profile_name": profile_name,
        "domain": domain,
        "secret_alias": secret_alias,
        "status": "bound"
    }))
}

/// Handle delete_binding RPC method
fn handle_delete_binding(request: &Request, _vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'profile_name' parameter"))?;

    let secret_alias = params.get("secret_alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'secret_alias' parameter"))?;

    let domain = params.get("domain")
        .and_then(|v: &Value| v.as_str())
        .unwrap_or("default");

    let conn = storage::open_connection()
        .map_err(|e| RpcError::internal_error(format!("Failed to get database connection: {}", e)))?;

    core::Core::unbind_secret_from_profile(&conn, profile_name, domain, secret_alias)
        .map_err(|e| RpcError::internal_error(format!("Failed to delete binding: {}", e)))?;

    Ok(json!({
        "profile_name": profile_name,
        "domain": domain,
        "secret_alias": secret_alias,
        "status": "unbound"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_db_path(prefix: &str) -> PathBuf {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        env::temp_dir().join(format!("{}_{}.db", prefix, ts))
    }

    #[test]
    fn test_auth_unlock_lock_status() {
        let vault_password = Arc::new(Mutex::new(None));

        let status_locked = handle_auth_session_status(&Request::new(methods::AUTH_SESSION_STATUS, json!({})), &vault_password).unwrap();
        assert_eq!(status_locked.get("status").and_then(|v| v.as_str()), Some("locked"));

        let unlock_req = Request::new(methods::AUTH_UNLOCK, json!({"password": "testpwd"}));
        handle_auth_unlock(&unlock_req, &vault_password).unwrap();

        let status_unlocked = handle_auth_session_status(&Request::new(methods::AUTH_SESSION_STATUS, json!({})), &vault_password).unwrap();
        assert_eq!(status_unlocked.get("status").and_then(|v| v.as_str()), Some("unlocked"));

        let lock_req = Request::new(methods::AUTH_LOCK, json!({}));
        handle_auth_lock(&lock_req, &vault_password).unwrap();

        let status_locked_again = handle_auth_session_status(&Request::new(methods::AUTH_SESSION_STATUS, json!({})), &vault_password).unwrap();
        assert_eq!(status_locked_again.get("status").and_then(|v| v.as_str()), Some("locked"));
    }

    #[test]
    fn test_binding_set_list_delete_roundtrip() {
        let db_path = unique_db_path("aikeyd-binding-test");
        env::set_var("AK_VAULT_PATH", &db_path);

        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let password = SecretString::new("testpassword".to_string());
        storage::initialize_vault(&salt, &password).unwrap();
        storage::create_profile("default").unwrap();
        storage::set_active_profile("default").unwrap();
        executor::add_secret("api_key", "value", &password).unwrap();

        let vault_password = Arc::new(Mutex::new(Some(password.expose_secret().to_string())));

        let set_req = Request::new(methods::BINDING_SET, json!({"profile_name": "default", "secret_alias": "api_key"}));
        handle_set_binding(&set_req, &vault_password).unwrap();

        let list_req = Request::new(methods::BINDING_LIST, json!({"profile_name": "default"}));
        let list_resp = handle_list_bindings(&list_req, &vault_password).unwrap();
        let bindings = list_resp.get("bindings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        assert!(bindings.iter().any(|v| {
            v.get("alias").and_then(|a| a.as_str()) == Some("api_key")
                && v.get("domain").and_then(|d| d.as_str()) == Some("default")
        }));

        let del_req = Request::new(methods::BINDING_DELETE, json!({"profile_name": "default", "secret_alias": "api_key"}));
        handle_delete_binding(&del_req, &vault_password).unwrap();

        let list_resp_after = handle_list_bindings(&list_req, &vault_password).unwrap();
        let bindings_after = list_resp_after.get("bindings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        assert!(bindings_after.iter().all(|v| v.get("alias").and_then(|a| a.as_str()) != Some("api_key")));

        let _ = std::fs::remove_file(&db_path);
    }
}

/// Handle resolve_env RPC method
fn handle_resolve_env(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str());

    let project_path = params.get("project_path")
        .and_then(|v: &Value| v.as_str());
    let config_path = params.get("config_path")
        .and_then(|v: &Value| v.as_str());
    let include_values = params.get("include_values")
        .and_then(|v: &Value| v.as_bool())
        .unwrap_or(true);

    // Get database connection
    let conn = storage::open_connection()
        .map_err(|e| internal_error(format!("Failed to get database connection: {}", e)))?;

    let config = if let Some(path) = config_path {
        let path = std::path::Path::new(path);
        if path.is_dir() {
            crate::config::ProjectConfig::discover_from(path)
                .map_err(|e| RpcError::new(-32603, format!("Failed to resolve environment: {}", e)))?
        } else {
            crate::config::ProjectConfig::load(path)
                .map(|config| Some((path.to_path_buf(), config)))
                .map_err(|e| RpcError::new(-32603, format!("Failed to resolve environment: {}", e)))?
        }
    } else if let Some(path) = project_path {
        crate::config::ProjectConfig::discover_from(std::path::Path::new(path))
            .map_err(|e| RpcError::new(-32603, format!("Failed to resolve environment: {}", e)))?
    } else {
        crate::config::ProjectConfig::discover()
            .map_err(|e| RpcError::new(-32603, format!("Failed to resolve environment: {}", e)))?
    };

    let (_config_path, config) = config
        .ok_or_else(|| RpcError::new(-32603, "Failed to resolve environment: No project configuration found. Run 'aikey project init' first."))?;

    let context = if include_values {
        let pwd = vault_password.lock()
            .map_err(|_| internal_error("Failed to acquire password lock"))?;
        let password_str = pwd.as_ref()
            .ok_or_else(|| unauthorized_error())?;
        let password = SecretString::new(password_str.clone());

        if let Some(profile) = profile_name {
            core::Core::resolve_environment_for_profile_with_config(&conn, profile, &password, &config)
        } else {
            core::Core::resolve_environment_with_config(&conn, &password, &config)
        }
    } else if let Some(profile) = profile_name {
        core::Core::resolve_environment_metadata_for_profile_with_config(&conn, profile, &config)
    } else {
        core::Core::resolve_environment_metadata_with_config(&conn, &config)
    }
    .map_err(|e| RpcError::new(-32603, format!("Failed to resolve environment: {}", e)))?;

    let (satisfied, total) = context.satisfaction_status();
    let resolved_vars: Vec<Value> = context.resolved_vars.iter().map(|v| {
        json!({
            "name": v.name,
            "value": if include_values { v.value.clone() } else { None },
            "source": format!("{:?}", v.source)
        })
    }).collect();
    let resolved = context.resolved_vars.iter().map(|v| {
        let value = if include_values { v.value.as_deref().unwrap_or("") } else { "" };
        format!("{}={}", v.name, value)
    }).collect::<Vec<_>>().join("\n");

    Ok(json!({
        "profile_name": context.profile_name,
        "resolved": resolved,
        "resolved_vars": resolved_vars,
        "satisfied": satisfied,
        "total": total,
        "is_complete": context.is_complete()
    }))
}

/// Start the daemon server with the given configuration
pub fn start_daemon(port: u16, use_unix_socket: bool, password: &SecretString, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = DaemonConfig::default();
    config.port = port;
    config.use_unix_socket = use_unix_socket;

    let server = DaemonServer::new(config);
    server.set_password(password.expose_secret().to_string())?;

    if !json_mode {
        eprintln!("Starting AiKey daemon...");
    }

    server.start()?;
    Ok(())
}

