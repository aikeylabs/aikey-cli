//! Proxy lifecycle state-transition event stream (Layer 4).
//!
//! Every `start_proxy` / `stop_proxy` / `restart_proxy` invocation
//! appends one JSON-line to `~/.aikey/logs/proxy-state-events.jsonl`
//! recording: timestamp, transition (from→to), duration, pid (if
//! known), port, trigger (which CLI fn called), reason on failure.
//!
//! Why JSON-Lines: trivial to append, one-line-per-event makes
//! `tail -f` and `grep` work without parsing context, and `jq` can
//! pretty-print individual events when needed.
//!
//! # Pairing with proxy startup log
//!
//! - This file (`proxy-state-events.jsonl`): **CLI writes** —
//!   "what we asked the proxy to do".
//! - `aikey-proxy-startup.log` (also under `~/.aikey/logs/`):
//!   **proxy writes** — "what proxy actually saw at startup".
//! - Proxy's own runtime log (separate): "what proxy is doing right now".
//!
//! Cross-reference all three by timestamp when troubleshooting
//! lifecycle issues.
//!
//! # Rotation
//!
//! Keep ≤5 MB per file, rotate to `.1` at threshold (one rotation
//! generation kept). Total disk footprint ≤10 MB. Rotate is
//! best-effort — if it fails the next event still gets appended,
//! just on a longer file.
//!
//! # Failure handling
//!
//! All operations are best-effort: a write failure logs nothing
//! (we already log enough elsewhere). Lifecycle code MUST NOT
//! depend on event-stream success.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Maximum size of `proxy-state-events.jsonl` before rotation kicks in.
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Filename under `~/.aikey/logs/`.
const EVENTS_FILENAME: &str = "proxy-state-events.jsonl";

/// One JSONL line written per lifecycle transition. Field naming
/// follows the [observability](workflow/CI/IDE/claude/principles)
/// conventions used by aikey-proxy's structured logs so a unified
/// JSON parser can ingest both streams.
#[derive(Debug, Serialize)]
pub struct TransitionEvent<'a> {
    /// RFC3339-ish UTC timestamp.
    pub ts: String,
    /// Always "proxy.state.transition" or
    /// "proxy.state.transition_failed".
    pub event: &'a str,
    /// State name we transitioned from (e.g., "Stopped").
    pub from: &'a str,
    /// State name we transitioned to. Same enum as `from` for success;
    /// for failures this is `to_attempted` semantically (what we tried).
    pub to: &'a str,
    /// Which Layer 2 / Layer 3 fn triggered the transition (e.g.,
    /// "handle_start_background", "ensure_proxy_for_use").
    pub trigger: &'a str,
    /// Wall time elapsed during the transition (ms).
    pub duration_ms: u128,
    /// PID of the involved proxy process, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Listen port, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Reason text on failure / non-success transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Resolve the events log path. Returns None if home dir unavailable
/// (best-effort; events are dropped silently in that case).
fn events_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let dir = home.join(".aikey").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join(EVENTS_FILENAME))
}

/// Append a transition event to the log. Best-effort — failures are
/// silently swallowed so lifecycle code is never blocked by logging.
///
/// Triggers a rotation when the file exceeds [`MAX_LOG_BYTES`].
pub fn record(event: &TransitionEvent<'_>) {
    let Some(path) = events_path() else { return };

    // Best-effort rotation BEFORE write. Avoids unbounded growth.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() >= MAX_LOG_BYTES {
            let backup = path.with_extension("jsonl.1");
            // overwrite previous .1 if any
            let _ = std::fs::rename(&path, &backup);
        }
    }

    let mut f = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let line = match serde_json::to_string(event) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = writeln!(f, "{line}");
}

/// Convenience: produce the RFC3339-ish timestamp used by all events.
/// Mirrors `proxy_lifecycle::chrono_now_rfc3339` (kept duplicate to
/// avoid the cross-module dep — both implementations are tiny).
pub fn now_ts() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let day_secs = secs % 86_400;
    let h = day_secs / 3_600;
    let m = (day_secs % 3_600) / 60;
    let s = day_secs % 60;
    let days = secs / 86_400;
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as u32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: serialization produces a single JSON line with no
    /// embedded newlines (jsonl format requires this — readers split
    /// on \n).
    #[test]
    fn event_serializes_to_single_line() {
        let e = TransitionEvent {
            ts: now_ts(),
            event: "proxy.state.transition",
            from: "Stopped",
            to: "Running",
            trigger: "handle_start_background",
            duration_ms: 487,
            pid: Some(12345),
            port: Some(27200),
            reason: None,
        };
        let s = serde_json::to_string(&e).expect("serialize");
        assert!(!s.contains('\n'), "must be single line for JSONL");
        // Must include the renamed `event` field, not the type's
        // automatic name.
        assert!(s.contains(r#""event":"proxy.state.transition""#));
        // Must NOT include `pid`/`port` fields when None — verified
        // via serde skip_serializing_if. Pinned because adding a
        // null-valued pid clutters the field index for grepping.
        let e2 = TransitionEvent {
            ts: now_ts(),
            event: "proxy.state.transition_failed",
            from: "Stopped",
            to: "Running",
            trigger: "ensure_proxy_for_use",
            duration_ms: 4012,
            pid: None,
            port: None,
            reason: Some("vault password rejected".into()),
        };
        let s2 = serde_json::to_string(&e2).unwrap();
        assert!(!s2.contains(r#""pid":"#));
        assert!(!s2.contains(r#""port":"#));
        assert!(s2.contains(r#""reason":"vault password rejected""#));
    }

    /// `now_ts()` produces a 20-char RFC3339-ish UTC stamp. Pinned
    /// because the manual civil-from-days arithmetic is the kind of
    /// code that fails silently when wrong.
    #[test]
    fn now_ts_format_is_well_formed() {
        let s = now_ts();
        assert_eq!(s.len(), 20, "unexpected length: {s:?}");
        assert!(s.ends_with('Z'));
    }
}
