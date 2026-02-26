//! Daemon client for connecting to AiKey daemon
//! 
//! Provides connection management, auto-start logic, retry/timeout handling,
//! and typed wrappers for RPC methods. Note: secret-related operations require
//! calling `auth.unlock` first to set the session vault password.

use crate::rpc::{Request, Response, methods};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

pub struct RpcClientError {
    pub code: Option<i32>,
    pub message: String,
}

impl std::fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = self.code {
            write!(f, "[code {}] {}", code, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::fmt::Debug for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClientError")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for RpcClientError {}

#[cfg(unix)]
use std::os::unix::net::UnixStream;

/// Daemon client configuration
#[derive(Debug, Clone)]
pub struct DaemonClientConfig {
    /// TCP port (default: 9999)
    pub port: u16,
    /// Unix socket path
    pub socket_path: Option<PathBuf>,
    /// Use Unix socket if available
    pub prefer_unix_socket: bool,
    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Number of retry attempts
    pub max_retries: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
}

impl Default for DaemonClientConfig {
    fn default() -> Self {
        Self {
            port: 9999,
            socket_path: Self::default_socket_path(),
            prefer_unix_socket: cfg!(unix),
            connect_timeout_ms: 5000,
            max_retries: 3,
            retry_delay_ms: 500,
        }
    }
}

impl DaemonClientConfig {
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

/// Daemon client with auto-start capability
pub struct DaemonClient {
    config: DaemonClientConfig,
}

impl DaemonClient {
    /// Create a new daemon client
    pub fn new(config: DaemonClientConfig) -> Self {
        Self { config }
    }

    /// Create a client with default configuration
    pub fn new_default() -> Self {
        Self::new(DaemonClientConfig::default())
    }

    /// Send a request to the daemon with auto-start and retry logic
    pub fn send_request(&self, request: &Request) -> Result<Response, String> {
        let request_json = serde_json::to_string(request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        // Try to send with retries
        for attempt in 0..=self.config.max_retries {
            match self.send_request_internal(&request_json) {
                Ok(response_str) => {
                    return serde_json::from_str(&response_str)
                        .map_err(|e| format!("Failed to parse response: {}", e));
                }
                Err(e) => {
                    if attempt == 0 {
                        // First attempt failed, try auto-start
                        if let Err(start_err) = self.ensure_daemon_running() {
                            eprintln!("Warning: Failed to start daemon: {}", start_err);
                        } else {
                            // Daemon started, wait a bit before retrying
                            thread::sleep(Duration::from_millis(self.config.retry_delay_ms));
                            continue;
                        }
                    }

                    if attempt < self.config.max_retries {
                        thread::sleep(Duration::from_millis(self.config.retry_delay_ms));
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err("Failed to connect to daemon after retries".to_string())
    }

    /// Send a request to the daemon without attempting auto-start (used by native host)
    pub fn send_request_no_autostart(&self, request: &Request) -> Result<Response, String> {
        let request_json = serde_json::to_string(request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        for attempt in 0..=self.config.max_retries {
            match self.send_request_internal(&request_json) {
                Ok(response_str) => {
                    return serde_json::from_str(&response_str)
                        .map_err(|e| format!("Failed to parse response: {}", e));
                }
                Err(e) => {
                    if attempt < self.config.max_retries {
                        thread::sleep(Duration::from_millis(self.config.retry_delay_ms));
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err("Failed to connect to daemon after retries".to_string())
    }

    /// Internal request sending without auto-start
    fn send_request_internal(&self, request_json: &str) -> Result<String, String> {
        if self.config.prefer_unix_socket {
            #[cfg(unix)]
            if let Some(socket_path) = &self.config.socket_path {
                return self.send_via_unix_socket(request_json, socket_path);
            }
        }

        self.send_via_tcp(request_json)
    }

    /// Ensure daemon is running, starting it if necessary
    fn ensure_daemon_running(&self) -> Result<(), String> {
        // Check if daemon is already running
        if self.is_daemon_running() {
            return Ok(());
        }

        // Try to start the daemon
        self.start_daemon()?;

        // Wait for daemon to be ready
        self.wait_for_daemon_ready()
    }

    /// Check if daemon is currently running
    fn is_daemon_running(&self) -> bool {
        if self.config.prefer_unix_socket {
            #[cfg(unix)]
            if let Some(socket_path) = &self.config.socket_path {
                return socket_path.exists() && UnixStream::connect(socket_path).is_ok();
            }
        }

        TcpStream::connect(format!("127.0.0.1:{}", self.config.port)).is_ok()
    }

    /// Start the daemon process
    fn start_daemon(&self) -> Result<(), String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable: {}", e))?;

        let mut cmd = Command::new(exe);
        cmd.arg("daemon").arg("start");

        // Ensure the daemon uses the same socket path as this client (even if env is not set)
        if let Some(socket_path) = &self.config.socket_path {
            cmd.env("AIKEYD_SOCKET_PATH", socket_path);
            cmd.arg("--unix-socket");
        }

        // IMPORTANT: detach stdio so the background daemon doesn't keep parent pipes open
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn daemon process: {}", e))?;

        Ok(())
    }

    /// Wait for daemon to be ready (up to connect_timeout_ms)
    fn wait_for_daemon_ready(&self) -> Result<(), String> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(self.config.connect_timeout_ms);

        loop {
            if self.is_daemon_running() {
                return Ok(());
            }

            if start.elapsed() > timeout {
                return Err("Daemon failed to start within timeout".to_string());
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Send request via TCP
    fn send_via_tcp(&self, request_json: &str) -> Result<String, String> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", self.config.port))
            .map_err(|e| format!("Failed to connect to daemon on port {}: {}", self.config.port, e))?;

        stream.write_all(request_json.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        Ok(response)
    }

    /// Send request via Unix socket
    #[cfg(unix)]
    fn send_via_unix_socket(&self, request_json: &str, socket_path: &PathBuf) -> Result<String, String> {
        let mut stream = UnixStream::connect(socket_path)
            .map_err(|e| format!("Failed to connect to Unix socket at {:?}: {}", socket_path, e))?;

        stream.write_all(request_json.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        Ok(response)
    }

    // ===== Typed RPC Method Wrappers =====

    /// Get current profile
    pub fn get_current_profile(&self) -> Result<String, RpcClientError> {
        let request = Request::new(methods::PROFILE_CURRENT, serde_json::json!({}));
        let response = self.send_request(&request)
            .map_err(|e| RpcClientError { code: None, message: e })?;

        match response {
            Response::Success(resp) => {
                resp.result.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| RpcClientError { code: None, message: "Invalid response format".to_string() })
            }
            Response::Error(err) => Err(RpcClientError { code: Some(err.error.code), message: err.error.message }),
        }
    }

    /// List all profiles
    pub fn list_profiles(&self) -> Result<Vec<String>, String> {
        let request = Request::new(methods::PROFILE_LIST, serde_json::json!({}));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("profiles")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Switch to a different profile
    pub fn use_profile(&self, name: &str) -> Result<String, String> {
        let request = Request::new(methods::PROFILE_USE, serde_json::json!({ "name": name }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Create a new profile
    pub fn create_profile(&self, name: &str) -> Result<String, String> {
        let request = Request::new(methods::PROFILE_CREATE, serde_json::json!({ "name": name }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Delete a profile
    pub fn delete_profile(&self, name: &str) -> Result<(), String> {
        let request = Request::new(methods::PROFILE_DELETE, serde_json::json!({ "name": name }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// List all secrets
    pub fn list_secrets(&self) -> Result<Vec<String>, String> {
        let request = Request::new(methods::SECRET_LIST, serde_json::json!({}));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("secrets")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| {
                                if let Some(alias) = v.get("alias").and_then(|x| x.as_str()) {
                                    Some(alias.to_string())
                                } else {
                                    v.as_str().map(|s| s.to_string())
                                }
                            })
                            .collect()
                    })
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// List all secrets with metadata
    pub fn list_secrets_with_metadata(&self) -> Result<Vec<crate::storage::SecretMetadata>, String> {
        let request = Request::new(methods::SECRET_LIST, serde_json::json!({}));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("secrets")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| serde_json::from_value::<crate::storage::SecretMetadata>(v.clone()).ok())
                            .collect()
                    })
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Get a secret value
    pub fn get_secret(&self, name: &str) -> Result<String, String> {
        let request = Request::new(methods::SECRET_GET, serde_json::json!({ "alias": name }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Upsert a secret value
    pub fn upsert_secret(&self, name: &str, value: &str) -> Result<(), String> {
        let request = Request::new(methods::SECRET_UPSERT, serde_json::json!({ "alias": name, "value": value }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Delete a secret value
    pub fn delete_secret(&self, name: &str) -> Result<(), String> {
        let request = Request::new(methods::SECRET_DELETE, serde_json::json!({ "alias": name }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Resolve environment variables
    pub fn resolve_env(&self, template: &str, project_path: Option<&str>, config_path: Option<&str>, include_values: bool) -> Result<String, String> {
        let mut params = serde_json::json!({ "template": template, "include_values": include_values });
        if let Some(path) = project_path {
            params["project_path"] = serde_json::Value::String(path.to_string());
        }
        if let Some(path) = config_path {
            params["config_path"] = serde_json::Value::String(path.to_string());
        }
        let request = Request::new(methods::ENV_RESOLVE, params);
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("resolved")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Resolve environment variables and return structured details
    pub fn resolve_env_details(&self, template: &str, project_path: Option<&str>, config_path: Option<&str>, include_values: bool) -> Result<serde_json::Value, String> {
        let mut params = serde_json::json!({ "template": template, "include_values": include_values });
        if let Some(path) = project_path {
            params["project_path"] = serde_json::Value::String(path.to_string());
        }
        if let Some(path) = config_path {
            params["config_path"] = serde_json::Value::String(path.to_string());
        }
        let request = Request::new(methods::ENV_RESOLVE, params);
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => Ok(resp.result),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// List bindings for a profile
    pub fn list_bindings(&self, profile_name: &str) -> Result<Vec<(String, String)>, String> {
        let request = Request::new(methods::BINDING_LIST, serde_json::json!({ "profile_name": profile_name }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => {
                resp.result.get("bindings")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| {
                                let domain = v.get("domain").and_then(|d| d.as_str());
                                let alias = v.get("alias").and_then(|a| a.as_str());
                                match (domain, alias) {
                                    (Some(d), Some(a)) => Some((d.to_string(), a.to_string())),
                                    _ => None,
                                }
                            })
                            .collect()
                    })
                    .ok_or_else(|| "Invalid response format".to_string())
            }
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Set a binding for a profile
    pub fn set_binding(&self, profile_name: &str, domain: &str, secret_alias: &str) -> Result<(), String> {
        let request = Request::new(methods::BINDING_SET, serde_json::json!({ "profile_name": profile_name, "domain": domain, "secret_alias": secret_alias }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Delete a binding for a profile
    pub fn delete_binding(&self, profile_name: &str, domain: &str, secret_alias: &str) -> Result<(), String> {
        let request = Request::new(methods::BINDING_DELETE, serde_json::json!({ "profile_name": profile_name, "domain": domain, "secret_alias": secret_alias }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Get daemon status
    pub fn get_status(&self) -> Result<serde_json::Value, String> {
        let request = Request::new(methods::SYSTEM_STATUS, serde_json::json!({}));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(resp) => Ok(resp.result),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Unlock daemon session by setting vault password
    pub fn unlock(&self, password: &str) -> Result<(), String> {
        let request = Request::new(methods::AUTH_UNLOCK, serde_json::json!({ "password": password }));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }

    /// Ping the daemon
    pub fn ping(&self) -> Result<(), String> {
        let request = Request::new(methods::SYSTEM_PING, serde_json::json!({}));
        let response = self.send_request(&request)?;

        match response {
            Response::Success(_) => Ok(()),
            Response::Error(err) => Err(format!("RPC error: {}", err.error.message)),
        }
    }
}

/// Check daemon status
pub fn check_daemon_status() -> Result<serde_json::Value, String> {
    let client = DaemonClient::new_default();
    client.ping()?;
    client.get_status()
}
