//! Daemon server implementation for AiKey
//!
//! Provides a JSON-RPC 2.0 server that handles requests from CLI clients
//! and other applications. Supports Unix sockets on Unix systems and TCP on all platforms.

use crate::rpc::{Request, Response, SuccessResponse, ErrorResponse, RpcError, methods};
use crate::executor;
use secrecy::SecretString;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// TCP port for the daemon (default: 9999)
    pub port: u16,
    /// Unix socket path (Unix only)
    pub socket_path: Option<PathBuf>,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            port: 9999,
            socket_path: None,
            max_connections: 100,
        }
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
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.config.port))
            .map_err(|e| format!("Failed to bind to port {}: {}", self.config.port, e))?;

        eprintln!("AiKey daemon listening on 127.0.0.1:{}", self.config.port);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let vault_pwd = Arc::clone(&self.vault_password);
                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream, vault_pwd) {
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

/// Handle a single client connection
fn handle_client(mut stream: TcpStream, vault_password: Arc<Mutex<Option<String>>>) -> Result<(), String> {
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
fn handle_list_secrets(request: &Request, vault_password: &Arc<Mutex<Option<String>>>) -> Result<Value, RpcError> {
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
