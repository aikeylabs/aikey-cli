//! Local structured logging and lightweight trace context for aikey-cli.
//!
//! # Design
//! - TraceContext holds W3C-compatible IDs (trace_id, span_id, command_id).
//! - A process-global JSONL logger writes to `~/.aikey/logs/aikey-cli/current.jsonl`.
//! - The logger is synchronous (CLI commands are short-lived, no async overhead needed).
//! - Each log record follows the same field schema as aikey-proxy for cross-process
//!   correlation by trace_id.
//!
//! # Security
//! No secrets, vault passwords, or provider keys are ever passed to these functions.
//! Callers are responsible for sanitising values before logging.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Trace context ─────────────────────────────────────────────────────────────

/// Lightweight W3C-compatible trace context created once per CLI invocation.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// 128-bit random trace ID (32 hex chars). Shared across cli→proxy calls.
    pub trace_id: String,
    /// 64-bit random span ID for the root command span (16 hex chars).
    pub span_id: String,
    /// Stable ID for this CLI command execution.
    pub command_id: String,
    /// W3C traceparent header value: `00-{trace_id}-{span_id}-01`.
    pub traceparent: String,
}

impl TraceContext {
    /// Creates a new root TraceContext with randomly generated IDs.
    pub fn new() -> Self {
        let trace_id = random_hex(16);
        let span_id = random_hex(8);
        let command_id = random_hex(8);
        let traceparent = format!("00-{}-{}-01", trace_id, span_id);
        Self {
            trace_id,
            span_id,
            command_id,
            traceparent,
        }
    }
}

/// Generates `n` cryptographically random bytes as lowercase hex.
fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ── Process-global trace context ─────────────────────────────────────────────

static TRACE_CTX: OnceLock<TraceContext> = OnceLock::new();

/// Initialises the global trace context for this process.
/// Must be called once at the start of `main()` before any commands run.
pub fn init_trace() -> &'static TraceContext {
    TRACE_CTX.get_or_init(TraceContext::new)
}

/// Returns the global trace context, or a zero-value placeholder if
/// `init_trace()` has not been called.
pub fn trace() -> Option<&'static TraceContext> {
    TRACE_CTX.get()
}

// ── JSONL logger ──────────────────────────────────────────────────────────────

/// Log severity levels matching the proxy schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Level::Debug => write!(f, "DEBUG"),
            Level::Info => write!(f, "INFO"),
            Level::Warn => write!(f, "WARN"),
            Level::Error => write!(f, "ERROR"),
        }
    }
}

/// A structured log record written as a single JSONL line.
///
/// Fields match the schema defined in the technical spec so that log records
/// from both aikey-cli and aikey-proxy can be correlated by trace_id.
#[derive(Serialize)]
struct LogRecord<'a> {
    ts: String,
    level: &'a str,
    #[serde(rename = "service.name")]
    service_name: &'static str,
    #[serde(rename = "process.pid")]
    process_pid: u32,
    message: &'a str,
    #[serde(rename = "event.name", skip_serializing_if = "Option::is_none")]
    event_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    traceparent: Option<&'a str>,
    #[serde(rename = "error.code", skip_serializing_if = "Option::is_none")]
    error_code: Option<&'a str>,
    #[serde(rename = "error.message", skip_serializing_if = "Option::is_none")]
    error_message: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    extra: BTreeMap<&'a str, Value>,
}

// Process-global log file handle (lazy init).
static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

fn log_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aikey")
        .join("logs")
        .join("aikey-cli")
}

fn ensure_log_file() -> Option<&'static Mutex<std::fs::File>> {
    LOG_FILE.get_or_init(|| {
        let dir = log_dir();
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("current.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|_| {
                // If we can't open the log file, open /dev/null as a sink.
                OpenOptions::new()
                    .write(true)
                    .open(if cfg!(unix) { "/dev/null" } else { "NUL" })
                    .expect("cannot open null device")
            });
        Mutex::new(file)
    })
    .into()
}

/// Writes one structured JSON line to `~/.aikey/logs/aikey-cli/current.jsonl`.
///
/// Silently ignores write errors to avoid interfering with CLI output.
pub fn write_log(
    level: Level,
    message: &str,
    event_name: Option<&str>,
    error_code: Option<&str>,
    error_message: Option<&str>,
    extra: BTreeMap<&str, Value>,
) {
    let ts = iso8601_now();
    let level_str = level.to_string();
    let pid = std::process::id();

    let (trace_id, span_id, command_id, traceparent) = if let Some(tc) = trace() {
        (
            Some(tc.trace_id.as_str()),
            Some(tc.span_id.as_str()),
            Some(tc.command_id.as_str()),
            Some(tc.traceparent.as_str()),
        )
    } else {
        (None, None, None, None)
    };

    let record = LogRecord {
        ts: ts.clone(),
        level: &level_str,
        service_name: "aikey-cli",
        process_pid: pid,
        message,
        event_name,
        trace_id,
        span_id,
        command_id,
        traceparent,
        error_code,
        error_message,
        extra,
    };

    if let Ok(mut line) = serde_json::to_string(&record) {
        line.push('\n');
        if let Some(mutex) = ensure_log_file() {
            if let Ok(mut f) = mutex.lock() {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

/// Convenience macro-like function: log at INFO with an event name.
pub fn log_event(event_name: &str, message: &str) {
    write_log(Level::Info, message, Some(event_name), None, None, BTreeMap::new());
}

/// Convenience function: log a command failure with error context.
pub fn log_error_event(event_name: &str, message: &str, error_code: Option<&str>, error_msg: Option<&str>) {
    write_log(Level::Error, message, Some(event_name), error_code, error_msg, BTreeMap::new());
}

// ── Event name constants ──────────────────────────────────────────────────────

pub const EVENT_CLI_COMMAND_STARTED: &str = "cli.command.started";
pub const EVENT_CLI_COMMAND_COMPLETED: &str = "cli.command.completed";
pub const EVENT_CLI_COMMAND_FAILED: &str = "cli.command.failed";
pub const EVENT_CLI_PROXY_REQUEST_STARTED: &str = "cli.proxy.request.started";
pub const EVENT_CLI_PROXY_REQUEST_COMPLETED: &str = "cli.proxy.request.completed";
pub const EVENT_CLI_PROXY_REQUEST_FAILED: &str = "cli.proxy.request.failed";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns the current time as an ISO 8601 string (RFC 3339 format).
fn iso8601_now() -> String {
    // Use SystemTime → seconds + nanos for a portable implementation without
    // pulling in a full datetime crate.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();

    // Simple UTC formatter (no DST, no time-zone offset).
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Gregorian calendar from Unix epoch (1970-01-01).
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        year, month, day, h, m, s, nanos
    )
}

/// Converts days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // 400-year Gregorian cycle = 146097 days.
    let era = days / 146097;
    days %= 146097;
    let yoe = (days - days / 1460 + days / 36524 - days / 146096) / 365;
    let y = yoe + era * 400;
    let doy = days - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
