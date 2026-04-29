//! Dedicated log for hidden `_internal *` IPC subcommands.
//!
//! Why a separate file (L2 of the 2026-04-22 hidden-command observability
//! decision, see `workflow/CI/research/2026-04-22-stage-4-6-self-review.md`):
//!
//!   - `_internal *` runs far more often than user-typed commands
//!     (every Web UI parse/confirm is 1-2 subprocess spawns). Mixing its
//!     detailed trace into `current.jsonl` would drown the commands that
//!     humans care about when debugging.
//!   - IPC payloads carry the most sensitive envelope fields in the
//!     system (`vault_key_hex`, potential `secret_plaintext` in parse
//!     output, `oauth_identity`). Separating them lets us set `0600` on
//!     the file and apply a stricter retention.
//!   - Operators usually want ONE file to grep when an import job
//!     misbehaves — having IPC trace in a distinct place ("oh this one")
//!     saves mental context switching.
//!
//! Redaction rules (STRICT — there is no knob to relax these):
//!   - NEVER logged: `vault_key_hex`, `password`, `secret_plaintext`,
//!     `bearer`, `api_key`, `Authorization`, `oauth_identity`'s real
//!     email (hashed only).
//!   - Logged: action name, a non-reversible fingerprint of the payload
//!     (SHA256[:16]), payload byte length, candidate / orphan counts,
//!     duration, error code + message, request_id echo.
//!
//! File management:
//!   - Path:        ~/.aikey/logs/aikey-cli/internal.jsonl
//!   - Permissions: 0600 (user-read/write only, tighter than current.jsonl's 0644)
//!   - Rotation:    5 MB per file × 3 files ≈ 15 MB max on disk
//!   - Format:      one JSON object per line, `{ts,pid,event,action,...}`
//!
//! The writer is intentionally synchronous-direct (no async channel) —
//! throughput here is well under 100 events/s even in busy Web UI flows,
//! and avoiding the async writer + its tokio-ish lifecycle keeps the
//! blast radius of a logging bug small.

use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use serde_json::{json, Value};

use super::protocol::StdinEnvelope;

const ROTATE_AT_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
const KEEP_ROTATIONS: usize = 3;

/// Mutex-guarded rotating writer. Lazily opens on first call; cheap after.
static WRITER: Mutex<Option<Writer>> = Mutex::new(None);

struct Writer {
    path: PathBuf,
    bytes_written: u64,
}

impl Writer {
    fn new() -> Option<Self> {
        // Stage 2.1 windows-compat: route through `resolve_aikey_dir()` so
        // internal-log writes follow the same HOME / USERPROFILE chain as
        // vault paths. `Some(...)` unconditionally now — the `"."` fallback
        // in `resolve_user_home` keeps degraded environments writing to
        // cwd rather than silently dropping logs.
        let dir = crate::commands_account::resolve_aikey_dir()
            .join("logs").join("aikey-cli");
        // create_dir_all is idempotent and safe across concurrent processes.
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("internal.jsonl");
        let bytes_written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Some(Self { path, bytes_written })
    }

    fn rotate_if_needed(&mut self) {
        if self.bytes_written < ROTATE_AT_BYTES {
            return;
        }
        // Shift: .2 → drop; .1 → .2; current → .1.
        for i in (1..KEEP_ROTATIONS).rev() {
            let from = self.path.with_extension(format!("jsonl.{}", i));
            let to   = self.path.with_extension(format!("jsonl.{}", i + 1));
            let _ = std::fs::rename(&from, &to);
        }
        let first_rotation = self.path.with_extension("jsonl.1");
        let _ = std::fs::rename(&self.path, &first_rotation);
        self.bytes_written = 0;
    }

    fn append(&mut self, line: &str) {
        self.rotate_if_needed();
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        { opts.mode(0o600); }  // tighter than current.jsonl (0644) — payloads are sensitive
        let mut file = match opts.open(&self.path) {
            Ok(f) => f,
            Err(_) => return, // logging failures never propagate to the caller
        };
        let bytes = line.as_bytes();
        if file.write_all(bytes).is_err() { return; }
        if file.write_all(b"\n").is_err() { return; }
        self.bytes_written += (bytes.len() + 1) as u64;
    }
}

fn with_writer<F>(f: F)
where
    F: FnOnce(&mut Writer),
{
    let mut guard = match WRITER.lock() {
        Ok(g) => g,
        Err(_) => return, // poisoned; silently drop
    };
    if guard.is_none() {
        *guard = Writer::new();
    }
    if let Some(w) = guard.as_mut() {
        f(w);
    }
}

fn iso_now() -> String {
    // Produce a stable ISO-8601 UTC timestamp without pulling in chrono.
    // Matches current.jsonl format closely enough for grep/jq.
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let nanos = d.subsec_nanos();
    let days = (secs / 86400) as i64;
    let mut rem = (secs % 86400) as i64;
    let hour = rem / 3600; rem -= hour * 3600;
    let min = rem / 60;    rem -= min * 60;
    let sec = rem;
    // Calendar from epoch — naive but fine for log sort order.
    let (y, mo, da) = epoch_days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            y, mo, da, hour, min, sec, nanos)
}

fn epoch_days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    // Civil-from-days algorithm (Howard Hinnant, public domain).
    days += 719468;
    let era = if days >= 0 { days / 146097 } else { (days - 146096) / 146097 };
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy + 2) / 153;
    let d = doy - (153*mp + 2)/5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_final = if m <= 2 { y + 1 } else { y };
    (y_final as i32, m as u32, d as u32)
}

/// SHA256 of `s`, hex-encoded, truncated to 16 chars. Used for payload
/// fingerprints where the operator needs to tell two requests apart but
/// we must not store the raw text.
fn fingerprint(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let full = hex::encode(h.finalize());
    full[..16].to_string()
}

/// Sanitise the envelope payload by walking it recursively and replacing
/// any field whose key looks like a secret with the literal string
/// `"<redacted>"`. Preserves structural shape so operators can still
/// recognise the action's payload schema.
fn redact_payload(v: &Value) -> Value {
    fn looks_sensitive(key: &str) -> bool {
        let k = key.to_ascii_lowercase();
        // Order roughly by how badly each leaks if missed.
        [
            "password",
            "master_password",
            "vault_key",
            "vault_key_hex",
            "secret",             // covers secret_plaintext, secret_value
            "plaintext",
            "bearer",
            "api_key",
            "authorization",
            "token",
            "oauth_identity",     // email
            "display_identity",
            "email",
            "refresh_token",
            "access_token",
            // 2026-04-22: user-pasted content fields. The `parse` action's
            // primary input is `text`, which is EXACTLY "raw user paste"
            // and routinely contains API keys / passwords — we must not
            // log those. Operators still see `source_hash`, `length`, and
            // the parse output (candidates/drafts counts) for debugging.
            // `input` / `body` / `raw` are also common names for the same
            // kind of payload across IPC action schemas.
            "text",
            "input",
            "body",
            "raw",
        ].iter().any(|needle| k.contains(needle))
    }
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                if looks_sensitive(k) {
                    out.insert(k.clone(), Value::String("<redacted>".to_string()));
                } else {
                    out.insert(k.clone(), redact_payload(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact_payload).collect()),
        _ => v.clone(),
    }
}

/// Log "dispatch start" — called from commands_internal::dispatch after
/// the envelope has been parsed. Captures: action name, request_id,
/// payload fingerprint, payload byte length, and a redacted shape view.
pub fn log_dispatch_start(action_name: &str, env: &StdinEnvelope) {
    let payload_raw = serde_json::to_string(&env.payload).unwrap_or_default();
    let entry = json!({
        "ts":         iso_now(),
        "pid":        std::process::id(),
        "event":      "cli._internal.dispatch.start",
        "action":     action_name,
        "env_action": env.action,
        "request_id": env.request_id,
        "payload_fp":    fingerprint(&payload_raw),
        "payload_bytes": payload_raw.len(),
        "payload_shape": redact_payload(&env.payload),
    });
    with_writer(|w| w.append(&entry.to_string()));
}

/// Log a successful dispatch outcome. Called from
/// `stdin_json::emit` right before the ok envelope is printed to stdout.
pub fn log_dispatch_success(action_name: &str, request_id: Option<&str>, data: &Value, duration_ms: u128) {
    let data_raw = serde_json::to_string(data).unwrap_or_default();
    let entry = json!({
        "ts":         iso_now(),
        "pid":        std::process::id(),
        "event":      "cli._internal.dispatch.ok",
        "action":     action_name,
        "request_id": request_id,
        "duration_ms": duration_ms,
        "data_fp":     fingerprint(&data_raw),
        "data_bytes":  data_raw.len(),
        "data_shape":  redact_payload(data),
    });
    with_writer(|w| w.append(&entry.to_string()));
}

/// Log an error-path dispatch outcome.
pub fn log_dispatch_error(
    action_name: &str,
    request_id: Option<&str>,
    code: &str,
    message: &str,
    duration_ms: u128,
) {
    let entry = json!({
        "ts":         iso_now(),
        "pid":        std::process::id(),
        "event":      "cli._internal.dispatch.err",
        "action":     action_name,
        "request_id": request_id,
        "duration_ms": duration_ms,
        "error_code": code,
        "error_message": message,
    });
    with_writer(|w| w.append(&entry.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strips_known_sensitive_fields() {
        let v = json!({
            "alias": "my-kimi",
            "secret_plaintext": "sk-REAL",
            "bearer": "<test-bearer-placeholder>",
            "nested": {
                "password": "hunter2",
                "safe": "keep-me",
                "API_KEY": "leak!",
            },
            "list": [ { "token": "t" }, { "alias": "b" } ],
        });
        let r = redact_payload(&v);
        assert_eq!(r["alias"], "my-kimi");
        assert_eq!(r["secret_plaintext"], "<redacted>");
        assert_eq!(r["bearer"], "<redacted>");
        assert_eq!(r["nested"]["password"], "<redacted>");
        assert_eq!(r["nested"]["safe"], "keep-me");
        assert_eq!(r["nested"]["API_KEY"], "<redacted>");
        assert_eq!(r["list"][0]["token"], "<redacted>");
        assert_eq!(r["list"][1]["alias"], "b");
    }

    #[test]
    fn fingerprint_is_stable_and_truncated() {
        let a = fingerprint("hello world");
        let b = fingerprint("hello world");
        assert_eq!(a, b, "same input → same fingerprint");
        assert_eq!(a.len(), 16, "fingerprint must be 16 hex chars");
        let c = fingerprint("hello worlX");
        assert_ne!(a, c, "one-byte diff → different fingerprint");
    }

    #[test]
    fn redact_catches_case_variants_of_password() {
        let cases = ["password", "PASSWORD", "Password", "oldPassword", "master_password"];
        for k in cases {
            let v = json!({ k: "secret" });
            let r = redact_payload(&v);
            assert_eq!(r[k], "<redacted>", "key={} should redact", k);
        }
    }

    #[test]
    fn redact_parse_payload_strips_user_pasted_text() {
        // Regression: `parse` action's payload.text is raw user paste,
        // which commonly contains API keys. We must not log it verbatim.
        let parse_payload = json!({
            "text": "OPENAI_API_KEY=sk-reallybad-abcdef123",
            "source_type": "paste",
        });
        let r = redact_payload(&parse_payload);
        assert_eq!(r["text"], "<redacted>",
            "parse.payload.text must be redacted — it is raw user paste and routinely contains secrets");
        assert_eq!(r["source_type"], "paste",
            "non-sensitive metadata must survive redaction");
    }
}
