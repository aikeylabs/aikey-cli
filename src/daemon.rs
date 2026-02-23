//! Daemon server implementation for AiKey
//!
//! Provides a JSON-RPC 2.0 server that handles requests from CLI clients
//! and other applications. Supports Unix sockets on Unix systems and TCP on all platforms.

use crate::rpc::{Request, Response, SuccessResponse, ErrorResponse, RpcError, methods};
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
        // Remove existing socket if it exists
        if socket_path.exists() {
            fs::remove_file(socket_path)
                .map_err(|e| format!("Failed to remove existing socket: {}", e))?;
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
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Process a JSON-RPC request
fn process_request(data: &[u8], vault_password: &Arc<Mutex<Option<String>>>) -> Result<String, String> {
    let request_str = String::from_utf8(data.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in request: {}", e))?;

    let request: Request = serde_json::from_str(&request_str)
        .map_err(|e| format!("Invalid JSON-RPC request: {}", e))?;

    let response = match request.method.as_str() {
        methods::SECRET_GET => handle_get_secret(&request, vault_password),
        methods::SECRET_LIST => handle_list_secrets(&request, vault_password),
        methods::SECRET_UPSERT => handle_add_secret(&request, vault_password),
        methods::SECRET_DELETE => handle_delete_secret(&request, vault_password),
        methods::BINDING_LIST => handle_list_bindings(&request, vault_password),
        methods::BINDING_SET => handle_set_binding(&request, vault_password),
        methods::BINDING_DELETE => handle_delete_binding(&request, vault_password),
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

/// Handle get_secret RPC method
fn handle_get_secret(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let alias = params.get("alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'alias' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    let password = SecretString::new(password_str.clone());
    let secret_value = executor::get_secret(alias, &password)
        .map_err(|e| RpcError::new(-32603, format!("Failed to get secret: {}", e)))?;

    Ok(json!({
        "alias": alias,
        "value": secret_value.as_str()
    }))
}

/// Handle list_secrets RPC method
fn handle_list_secrets(_request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    let password = SecretString::new(password_str.clone());
    let secrets = executor::list_secrets_with_metadata(&password)
        .map_err(|e| RpcError::new(-32603, format!("Failed to list secrets: {}", e)))?;

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
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    let password = SecretString::new(password_str.clone());
    executor::add_secret(alias, value, &password)
        .map_err(|e| RpcError::new(-32603, format!("Failed to add secret: {}", e)))?;

    Ok(json!({
        "alias": alias,
        "status": "created"
    }))
}

/// Handle delete_secret RPC method
fn handle_delete_secret(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let alias = params.get("alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'alias' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    let password = SecretString::new(password_str.clone());
    executor::delete_secret(alias, &password)
        .map_err(|e| RpcError::new(-32603, format!("Failed to delete secret: {}", e)))?;

    Ok(json!({
        "alias": alias,
        "status": "deleted"
    }))
}

/// Handle list_bindings RPC method
fn handle_list_bindings(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'profile_name' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let _password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    // Get database connection
    let conn = storage::open_connection()
        .map_err(|e| RpcError::new(-32603, format!("Failed to get database connection: {}", e)))?;

    let bindings = core::Core::list_profile_bindings(&conn, profile_name)
        .map_err(|e| RpcError::new(-32603, format!("Failed to list bindings: {}", e)))?;

    Ok(json!({
        "profile_name": profile_name,
        "bindings": bindings
    }))
}

/// Handle set_binding RPC method
fn handle_set_binding(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'profile_name' parameter"))?;

    let secret_alias = params.get("secret_alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'secret_alias' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let _password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    // Get database connection
    let conn = storage::open_connection()
        .map_err(|e| RpcError::new(-32603, format!("Failed to get database connection: {}", e)))?;

    core::Core::bind_secret_to_profile(&conn, profile_name, secret_alias)
        .map_err(|e| RpcError::new(-32603, format!("Failed to set binding: {}", e)))?;

    Ok(json!({
        "profile_name": profile_name,
        "secret_alias": secret_alias,
        "status": "bound"
    }))
}

/// Handle delete_binding RPC method
fn handle_delete_binding(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'profile_name' parameter"))?;

    let secret_alias = params.get("secret_alias")
        .and_then(|v: &Value| v.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing or invalid 'secret_alias' parameter"))?;

    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let _password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    // Get database connection
    let conn = storage::open_connection()
        .map_err(|e| RpcError::new(-32603, format!("Failed to get database connection: {}", e)))?;

    core::Core::unbind_secret_from_profile(&conn, profile_name, secret_alias)
        .map_err(|e| RpcError::new(-32603, format!("Failed to delete binding: {}", e)))?;

    Ok(json!({
        "profile_name": profile_name,
        "secret_alias": secret_alias,
        "status": "unbound"
    }))
}

/// Handle resolve_env RPC method
fn handle_resolve_env(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
    let params = &request.params.data;

    let profile_name = params.get("profile_name")
        .and_then(|v: &Value| v.as_str());

    let pwd = vault_password.lock()
        .map_err(|_| RpcError::new(-32603, "Internal error: failed to acquire password lock"))?;

    let password_str = pwd.as_ref()
        .ok_or_else(|| RpcError::new(-32002, "Unauthorized: vault password not set"))?;

    let password = SecretString::new(password_str.clone());

    // Get database connection
    let conn = storage::open_connection()
        .map_err(|e| RpcError::new(-32603, format!("Failed to get database connection: {}", e)))?;

    let context = if let Some(profile) = profile_name {
        core::Core::resolve_environment_for_profile(&conn, profile, &password)
    } else {
        core::Core::resolve_environment(&conn, &password)
    }
    .map_err(|e| RpcError::new(-32603, format!("Failed to resolve environment: {}", e)))?;

    let (satisfied, total) = context.satisfaction_status();
    let resolved_vars: Vec<Value> = context.resolved_vars.iter().map(|v| {
        json!({
            "name": v.name,
            "value": v.value,
            "source": format!("{:?}", v.source)
        })
    }).collect();

    Ok(json!({
        "profile_name": context.profile_name,
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

