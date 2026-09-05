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
//! No secrets, master passwords, or provider keys are ever passed to these functions.
//! Callers are responsible for sanitising values before logging.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

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
    LOG_FILE
        .get_or_init(|| {
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
    write_log(
        Level::Info,
        message,
        Some(event_name),
        None,
        None,
        BTreeMap::new(),
    );
}

/// Convenience function: log a command failure with error context.
pub fn log_error_event(
    event_name: &str,
    message: &str,
    error_code: Option<&str>,
    error_msg: Option<&str>,
) {
    write_log(
        Level::Error,
        message,
        Some(event_name),
        error_code,
        error_msg,
        BTreeMap::new(),
    );
}

// ── Event name constants ──────────────────────────────────────────────────────

pub const EVENT_CLI_COMMAND_STARTED: &str = "cli.command.started";
pub const EVENT_CLI_COMMAND_COMPLETED: &str = "cli.command.completed";
pub const EVENT_CLI_COMMAND_FAILED: &str = "cli.command.failed";
pub const EVENT_CLI_PROXY_REQUEST_STARTED: &str = "cli.proxy.request.started";
pub const EVENT_CLI_PROXY_REQUEST_COMPLETED: &str = "cli.proxy.request.completed";
pub const EVENT_CLI_PROXY_REQUEST_FAILED: &str = "cli.proxy.request.failed";

// Usage-receipt pipeline degradation signals. These fire when a third-party CLI
// (kimi / claude) upgrade changes a contract we depend on (Stop-hook payload
// shape, session-dir derivation), so a break becomes visible in the log instead
// of a silent `return Ok(())`. See workflow/versions/compatible/ for the full
// coupling inventory. Paired with the `receipt-health-<tool>.json` heartbeat so
// the state is externally readable (health-signal-surface principle).
pub const EVENT_RECEIPT_KIMI_PAYLOAD_UNRECOGNIZED: &str = "cli.receipt.kimi_payload_unrecognized";
pub const EVENT_RECEIPT_KIMI_SESSION_DIR_MISSING: &str = "cli.receipt.kimi_session_dir_missing";
pub const EVENT_RECEIPT_CLAUDE_PAYLOAD_UNRECOGNIZED: &str =
    "cli.receipt.claude_payload_unrecognized";

// Binding auto-write visibility (2026-07-06 incident): an automatic post-sync
// reconcile bound a material-unreachable team VK as a provider Primary with no
// trace in audit_log or the internal log — root-causing required timestamp
// cross-referencing across three stores. Every non-user-initiated binding write
// now emits an event, and the material guard's skip decision logs at WARN.
// audit_log is deliberately NOT used here: its rows are HMAC-signed with a
// vault_key-derived audit_key, and most automatic binding paths have no key
// context (unsigned rows would trip verify_audit_log as tampering).
// See roadmap20260320/技术实现/update/20260706-绑定材料守卫与Web解锁态全量sync.md.
pub const EVENT_CLI_BINDING_AUTO_ASSIGNED: &str = "cli.binding.auto_assigned";
pub const EVENT_CLI_BINDING_RECONCILED: &str = "cli.binding.reconciled";
pub const EVENT_CLI_BINDING_AUTO_ASSIGN_SKIPPED: &str =
    "cli.binding.auto_assign_skipped_unreachable";

// Third-party config guard (2026-09-05): a refused or failed write/remove on
// a codex/kimi/claude/Desktop config file. Before this the whole injection
// funnel was invisible to current.jsonl — the winpc2 dead-end (five `aikey use`
// runs against an unparseable ~/.codex/config.toml) left no trace except
// stderr. Carries tool/path/state/line/col/backup in `extra` and the
// ReasonCode as error.code.
// spec: R-third-party-config-guard-1.S2 坏文件不阻塞 KEY 激活（但必须留痕）
pub const EVENT_CLI_TP_CONFIG_REFUSED: &str = "cli.third_party_config.refused";

// Web-driven first-run vault setup (_internal init). The session cache is
// best-effort — a keychain can decline — and a silent decline would leave the
// proxy asking for a password the user believes they already configured.
pub const EVENT_CLI_VAULT_SESSION_CACHE_SKIPPED: &str = "cli.vault.session_cache_skipped";

// UPPER_SNAKE error codes (logging-conventions.md).
pub const ERRCODE_SESSION_BACKEND_UNKNOWN: &str = "SESSION_BACKEND_UNKNOWN";
pub const ERRCODE_BINDING_MATERIAL_UNREACHABLE: &str = "BINDING_MATERIAL_UNREACHABLE";
pub const ERRCODE_KIMI_STOP_PAYLOAD_UNRECOGNIZED: &str = "KIMI_STOP_PAYLOAD_UNRECOGNIZED";
pub const ERRCODE_KIMI_SESSION_DIR_MISSING: &str = "KIMI_SESSION_DIR_MISSING";
pub const ERRCODE_CLAUDE_STATUSLINE_PAYLOAD_UNRECOGNIZED: &str =
    "CLAUDE_STATUSLINE_PAYLOAD_UNRECOGNIZED";

/// An unattended `aikey proxy start` found no master password on this machine:
/// no env var, no OS keychain entry, no session file.
///
/// Why it needs a CODE and not just a sentence (2026-08-22): the desktop app
/// reaches this state legitimately — `uninstall.sh --keep-data` keeps the vault
/// but drops the keychain AND the `.session_*` files, so the very next install
/// has credentials it cannot open. The tray has to tell THIS failure apart from
/// every other start failure in order to offer the one thing that fixes it
/// (unlock once in the console). Matching on the message text would break the
/// moment anyone rewords it; the code is the contract.
///
/// Consumer: aikey-tray `servicebridge.IsVaultLocked`, fenced against this
/// constant so the two cannot drift.
pub const ERRCODE_VAULT_LOCKED_NO_CACHED_PASSWORD: &str = "VAULT_LOCKED_NO_CACHED_PASSWORD";

/// Convenience: log a WARN with an event name + optional error code. Used by
/// degrade-to-default code paths that must not stay silent (logging-conventions:
/// "解析失败、字段缺失、shape 不匹配回落默认值必须配 WARN 日志").
pub fn log_warn_event(event_name: &str, message: &str, error_code: Option<&str>) {
    write_log(
        Level::Warn,
        message,
        Some(event_name),
        error_code,
        None,
        BTreeMap::new(),
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns the current time as an ISO 8601 string (RFC 3339 format).
///
/// 🔴 Delegates to `commands_internal::internal_log::iso_now` (2026-09-05).
/// This file used to carry its own civil-from-days conversion that omitted the
/// 719468-day shift from the Unix epoch to the civil era, so EVERY line in
/// current.jsonl was stamped year 0056 — the log could not be searched by
/// time at all (the 2026-09-04 winpc2 forensics had to key on event names).
/// One correct implementation, fenced by `log_timestamp_year_is_current`.
fn iso8601_now() -> String {
    crate::commands_internal::internal_log::iso_now()
}

#[cfg(test)]
mod timestamp_fence {
    /// 能红: put the old `days_to_ymd` back (no +719468) and the year reads 0056.
    #[test]
    fn log_timestamp_year_is_current() {
        let ts = super::iso8601_now();
        let year: i32 = ts[..4].parse().expect("ISO-8601 year prefix");
        assert!(
            (2026..=2100).contains(&year),
            "current.jsonl ts year is {year}: {ts}"
        );
        assert!(ts.ends_with('Z') && ts.contains('T'), "{ts}");
    }
}
