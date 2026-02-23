//! Daemon client for connecting to AiKey daemon
//!
//! Supports both TCP and Unix socket connections

use crate::rpc::{Request, Response};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

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
}

impl Default for DaemonClientConfig {
    fn default() -> Self {
        Self {
            port: 9999,
            socket_path: Self::default_socket_path(),
            prefer_unix_socket: cfg!(unix),
        }
    }
}

impl DaemonClientConfig {
    #[cfg(unix)]
    fn default_socket_path() -> Option<PathBuf> {
        dirs::runtime_dir().map(|dir| dir.join("aikeyd.sock"))
    }

    #[cfg(not(unix))]
    fn default_socket_path() -> Option<PathBuf> {
        None
    }
}

/// Daemon client
pub struct DaemonClient {
    config: DaemonClientConfig,
}

impl DaemonClient {
    /// Create a new daemon client
    pub fn new(config: DaemonClientConfig) -> Self {
        Self { config }
    }

    /// Send a request to the daemon and get response
    pub fn send_request(&self, request: &Request) -> Result<Response, String> {
        let request_json = serde_json::to_string(request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        let response_str = if self.config.prefer_unix_socket {
            #[cfg(unix)]
            if let Some(socket_path) = &self.config.socket_path {
                self.send_via_unix_socket(&request_json, socket_path)?
            } else {
                self.send_via_tcp(&request_json)?
            }

            #[cfg(not(unix))]
            self.send_via_tcp(&request_json)?
        } else {
            self.send_via_tcp(&request_json)?
        };

        serde_json::from_str(&response_str)
            .map_err(|e| format!("Failed to parse response: {}", e))
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
}
