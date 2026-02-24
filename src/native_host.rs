use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use aikeylabs_aikey_cli::daemon_client::DaemonClient;
use aikeylabs_aikey_cli::error_codes::ErrorCode;
use aikeylabs_aikey_cli::rpc::{self, Request, RequestParams, Response};
use clap::Parser;
use serde::{Deserialize, Serialize};

const BROWSER_PROTOCOL_VERSION: &str = "0.2";

#[derive(Parser, Debug)]
#[command(author, version, about = "AiKey Native Messaging Host (bridge to aikeyd)")]
struct Args {
    /// Optional input file (defaults to stdin)
    #[arg(long)]
    input: Option<PathBuf>,

    /// Treat input as raw JSON (no Chrome Native Messaging length prefix)
    #[arg(long, default_value_t = false)]
    raw_json: bool,

    /// Process a single message and exit (defaults to true when --input is provided)
    #[arg(long, default_value_t = false)]
    once: bool,
}

#[derive(Debug, Deserialize)]
struct HostMessage {
    #[serde(rename = "protocolVersion")]
    protocol_version: Option<String>,
    #[serde(default)]
    surface: Option<String>,
    #[serde(default)]
    context: Option<serde_json::Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: serde_json::Value,
    #[serde(default)]
    id: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct HostSuccess {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    result: serde_json::Value,
}

#[derive(Serialize)]
struct HostErrorResponse {
    ok: bool,
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let input: Box<dyn Read> = if let Some(path) = &args.input {
        Box::new(File::open(path)?)
    } else {
        Box::new(io::stdin())
    };

    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(io::stdout());

    if args.raw_json {
        let mut raw = String::new();
        reader.read_to_string(&mut raw)?;
        if raw.trim().is_empty() {
            return Ok(());
        }
        let response = process_json_bytes(raw.as_bytes());
        write_native_message(&mut writer, &response)?;
        writer.flush()?;
        return Ok(());
    }

    let single_shot = args.once || args.input.is_some();
    loop {
        match read_native_message(&mut reader)? {
            Some(bytes) => {
                let response = process_json_bytes(&bytes);
                write_native_message(&mut writer, &response)?;
                writer.flush()?;
                if single_shot {
                    break;
                }
            }
            None => break,
        }
    }

    Ok(())
}

fn process_json_bytes(bytes: &[u8]) -> serde_json::Value {
    let parsed: HostMessage = match serde_json::from_slice(bytes) {
        Ok(msg) => msg,
        Err(e) => {
            return error_value(
                ErrorCode::InvalidInput,
                format!("Invalid JSON: {}", e),
                None,
                None,
            )
        }
    };

    let id = parsed.id.clone();
    let protocol = parsed.protocol_version.as_deref().unwrap_or("");
    if !is_supported_protocol(protocol) {
        return error_value(
            ErrorCode::UnsupportedProtocol,
            format!("Unsupported protocolVersion: {}", protocol),
            id,
            None,
        );
    }

    let surface = parsed.surface.as_deref().unwrap_or("");
    if surface != "browser" {
        return error_value(
            ErrorCode::InvalidInput,
            "surface must be \"browser\"",
            id,
            None,
        );
    }

    let method = match parsed.method {
        Some(m) if !m.trim().is_empty() => m,
        _ => {
            return error_value(
                ErrorCode::InvalidInput,
                "Missing method",
                id,
                None,
            )
        }
    };

    let mut params = if parsed.params.is_null() {
        serde_json::json!({})
    } else {
        parsed.params
    };

    // Attach surface/context for policy enforcement in daemon
    if let Some(surface_val) = parsed.surface {
        params["surface"] = serde_json::Value::String(surface_val);
    }
    if let Some(context_val) = parsed.context {
        params["context"] = context_val;
    }

    let rpc_request = Request {
        jsonrpc: "2.0".to_string(),
        method,
        params: RequestParams {
            protocol_version: rpc::PROTOCOL_VERSION.to_string(),
            data: params,
        },
        id: None,
    };

    let client = DaemonClient::default();
    match client.send_request_no_autostart(&rpc_request) {
        Ok(Response::Success(resp)) => success_value(resp.result, id),
        Ok(Response::Error(err)) => {
            let code = map_rpc_error_code(err.error.code);
            error_value(code, err.error.message, id, err.error.data)
        }
        Err(e) => error_value(ErrorCode::IoError, e, id, None),
    }
}

fn is_supported_protocol(version: &str) -> bool {
    version == BROWSER_PROTOCOL_VERSION || version == rpc::PROTOCOL_VERSION
}

fn success_value(result: serde_json::Value, id: Option<serde_json::Value>) -> serde_json::Value {
    let mut success = serde_json::to_value(HostSuccess {
        ok: true,
        id: None,
        result,
    })
    .unwrap_or_else(|_| serde_json::json!({ "ok": true, "result": serde_json::Value::Null }));

    if let Some(id_val) = id {
        if let Some(obj) = success.as_object_mut() {
            obj.insert("id".to_string(), id_val);
        }
    }

    success
}

fn error_value(
    code: ErrorCode,
    message: impl Into<String>,
    id: Option<serde_json::Value>,
    details: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut value = serde_json::to_value(HostErrorResponse {
        ok: false,
        code: code.as_str().to_string(),
        message: message.into(),
        details: None,
        id: None,
    })
    .unwrap_or_else(|_| serde_json::json!({ "ok": false, "code": code.as_str(), "message": "Unknown error" }));

    if let Some(obj) = value.as_object_mut() {
        if let Some(details_val) = details {
            obj.insert("details".to_string(), details_val);
        }
        if let Some(id_val) = id {
            obj.insert("id".to_string(), id_val);
        }
    }

    value
}

fn map_rpc_error_code(code: i32) -> ErrorCode {
    match code {
        rpc::error_codes::ALIAS_EXISTS => ErrorCode::AliasExists,
        rpc::error_codes::ALIAS_NOT_FOUND => ErrorCode::AliasNotFound,
        rpc::error_codes::VAULT_LOCKED => ErrorCode::VaultLocked,
        rpc::error_codes::NO_ACTIVE_PROFILE => ErrorCode::NoActiveProfile,
        rpc::error_codes::INVALID_INPUT => ErrorCode::InvalidInput,
        rpc::error_codes::UNSUPPORTED_PROTOCOL => ErrorCode::UnsupportedProtocol,
        rpc::error_codes::INTERNAL_ERROR => ErrorCode::InternalError,
        rpc::error_codes::UNAUTHORIZED => ErrorCode::Unauthorized,
        rpc::error_codes::FORBIDDEN => ErrorCode::Forbidden,
        rpc::error_codes::IO_ERROR => ErrorCode::IoError,
        rpc::error_codes::TIMEOUT => ErrorCode::Timeout,
        rpc::error_codes::VAULT_NOT_INITIALIZED => ErrorCode::VaultNotInitialized,
        rpc::error_codes::PROFILE_NOT_FOUND => ErrorCode::ProfileNotFound,
        _ => ErrorCode::InternalError,
    }
}

fn read_native_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buffer = vec![0u8; len];
            reader.read_exact(&mut buffer)?;
            Ok(Some(buffer))
        }
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_native_message(writer: &mut impl Write, message: &serde_json::Value) -> io::Result<()> {
    let payload = serde_json::to_vec(message).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    Ok(())
}
