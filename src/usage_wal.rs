//! Shared read path for the aikey-proxy usage WAL.
//!
//! aikey-proxy appends one JSON object per request to
//! `~/.aikey/data/usage-wal/usage-YYYYMMDD-HH.jsonl` (hourly rotation).
//! Both `aikey statusline` (single-row probe) and `aikey watch` (full
//! aggregator) read this log — putting the parser in one place keeps
//! them honest about the schema.
//!
//! The proxy's schema is larger than what UI consumers need. We only
//! deserialize the subset of fields that drive the receipt / aggregator
//! and tolerate unknown fields so the proxy can grow the schema without
//! breaking older CLI builds.
//!
//! ## event_time wire format
//!
//! Post proxy v1.0.3-alpha (bugfix 20260424) the proxy writes
//! `event_time` as **int64 Unix epoch milliseconds** (UTC). Previous
//! builds wrote an RFC3339 string. This module tolerates **both** so
//! statusline doesn't break during a mixed-version window — hourly
//! WAL files written by an older proxy may still be on disk and
//! readable for up to 24h after upgrade before hourly rotation ages
//! them out.

use serde::{Deserialize, Deserializer};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One usage event, projected from the WAL's `event_json` envelope.
///
/// Fields mirror `aikey-proxy/internal/events/reportable.go::ReportableEvent`
/// — keep these two in sync whenever the proxy adds a new field the UI
/// wants to show.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageEvent {
    #[serde(default)]
    pub event_id: String,
    /// Unix epoch **milliseconds** (UTC). 0 = unknown / absent.
    ///
    /// Deserializer accepts both a JSON number (the current proxy wire
    /// format) and a JSON string in RFC3339 or numeric-string form
    /// (pre-v1.0.3-alpha WAL files still on disk during a mixed-version
    /// window). See `deserialize_event_time_ms` for the tolerance rules.
    #[serde(default, deserialize_with = "deserialize_event_time_ms")]
    pub event_time: i64,

    /// Newest (v5) anchor fields. omitempty on the proxy side, so absent
    /// on events written by pre-v5 binaries.
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub key_label: Option<String>,
    #[serde(default)]
    pub completion: Option<String>,

    #[serde(default)]
    pub virtual_key_id: String,
    #[serde(default)]
    pub provider_code: String,
    #[serde(default)]
    pub route_source: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub oauth_identity: Option<String>,

    /// Numeric fields are `Option<i64>` because the proxy sends them as
    /// `omitempty` — absent means "unknown" rather than zero.
    #[serde(default)]
    pub input_tokens: Option<i64>,
    #[serde(default)]
    pub output_tokens: Option<i64>,
    #[serde(default)]
    pub total_tokens: Option<i64>,

    /// Cache breakdown — Anthropic prompt caching splits `input_tokens` into
    /// fresh + read-from-cache + written-to-cache, reported via these two
    /// optional fields. `input_tokens` already includes both, so consumers
    /// that don't care about the breakdown can keep ignoring these. Absent
    /// for providers that don't expose caching (Kimi / generic OpenAI).
    #[serde(default)]
    pub cache_read_input_tokens: Option<i64>,
    #[serde(default)]
    pub cache_creation_input_tokens: Option<i64>,

    /// Raw provider-specific termination reason. Pass-through from proxy,
    /// not normalized. Values depend on provider: Anthropic emits
    /// "end_turn"/"tool_use"/"max_tokens"/"stop_sequence"; OpenAI family
    /// emits "stop"/"tool_calls"/"length"/"content_filter". Empty string
    /// when the upstream response did not include it (error path, or the
    /// stream ended before the usage/finish frame arrived).
    #[serde(default)]
    pub stop_reason: Option<String>,

    #[serde(default)]
    pub request_status: String,
    #[serde(default)]
    pub http_status_code: Option<i32>,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl UsageEvent {
    /// Returns seconds since the unix epoch for `event_time`, or None
    /// when the field is absent / zero. Kept lazy so hot-path callers
    /// (statusline) don't pay the divide unless they actually need it.
    pub fn finished_at_unix(&self) -> Option<i64> {
        if self.event_time <= 0 {
            None
        } else {
            Some(self.event_time / 1000)
        }
    }

    /// Age compared to `now`; None when the timestamp can't be parsed.
    pub fn age(&self, now: SystemTime) -> Option<Duration> {
        let ev_secs = self.finished_at_unix()?;
        let now_secs = now.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
        let delta = now_secs.saturating_sub(ev_secs);
        if delta < 0 { return None; }
        Some(Duration::from_secs(delta as u64))
    }
}

/// Accept JSON number (millis) or string (numeric or RFC3339) for
/// `event_time`. All outputs are normalised to epoch millis.
///
/// Why tolerant: proxy writes int64 after v1.0.3-alpha, but a just-
/// upgraded machine may still have hourly WAL files on disk that were
/// written by the previous build with RFC3339 strings — the statusline
/// must keep working against them until natural rotation ages them
/// out (~24h).
fn deserialize_event_time_ms<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Int(i64),
        Str(String),
        Null,
    }
    match Raw::deserialize(d)? {
        Raw::Int(n) => Ok(n),
        Raw::Null => Ok(0),
        Raw::Str(s) => {
            if s.is_empty() {
                return Ok(0);
            }
            // Numeric string (e.g. "1777041000000") — proxy never emits
            // this but keep the path for hand-crafted fixtures.
            if let Ok(n) = s.parse::<i64>() {
                return Ok(n);
            }
            // RFC3339 legacy path.
            if let Some(secs) = parse_rfc3339_secs(&s) {
                return Ok(secs.saturating_mul(1000));
            }
            Err(D::Error::custom(format!(
                "event_time: unrecognised format {s:?} — expected int64 millis or RFC3339"
            )))
        }
    }
}

/// WAL envelope — `{"wal_seq":..,"written_at":..,"event_json":{...}}`.
///
/// `wal_seq` lives at the envelope level (alongside `event_json`), matching
/// proxy's Go `WALEntry { WALSeq, WrittenAt, EventJSON }`. It's writer-
/// lifetime monotonic (atomic.Int64 in proxy), resets on proxy restart.
/// Paired with the WAL file name it gives `(file, seq)` tuple — the
/// watermark key used by `aikey statusline render kimi` to bound each
/// Kimi turn.
///
/// We DO NOT add `wal_seq` to `UsageEvent` — that struct mirrors proxy's
/// `ReportableEvent` (the payload), not the envelope. Mixing layers would
/// confuse future schema migrations.
#[derive(Debug, Deserialize)]
struct WalEntry {
    #[serde(default)]
    wal_seq: u64,
    event_json: UsageEvent,
}

/// A matched WAL entry with its physical location (file + envelope seq).
///
/// The tuple `(wal_file_name, wal_seq)` is strictly monotonic within a
/// single proxy lifetime: `wal_seq` increments across hourly file rotation,
/// and file names sort lexicographically in time order. Use it for
/// watermark comparisons where `event.event_time`'s second-level parser
/// would collide on same-second events.
///
/// Caveat: proxy restart resets `wal_seq` (in-memory counter) — see the
/// "Proxy 重启 edge case" section in the Kimi receipt design doc for
/// the self-healing behavior. Consumers that need strict monotonicity
/// across restarts should also compare file names, not just seq.
#[derive(Debug, Clone)]
pub struct WalHit {
    pub event: UsageEvent,
    pub wal_file_name: String,
    pub wal_seq: u64,
}

/// Options controlling the backward scan budget.
///
/// The scan trades off between "always find my session's event" and "keep
/// statusline fast even under heavy load". `max_age` prunes by time first
/// (`Some(d)` = stop reading events older than this cutoff; `None` = no age
/// bound, rely on `max_lines` only). `max_lines` is the hard cap on total
/// lines parsed so a single pathological file can't block us.
///
/// When `max_age` is `None`, scans are bounded ONLY by `max_lines` — used
/// by `render_kimi` once a watermark exists, since the watermark tuple is
/// the semantic lower bound and an arbitrarily long Kimi turn (e.g. 30 min
/// of tool calls) must not drop early events.
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub max_age: Option<Duration>,
    pub max_lines: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            // 5 minutes — generous enough to survive noisy mixed-session
            // machines (see §5.1 of design doc). Used as the first-turn
            // fallback when no watermark exists yet.
            max_age: Some(Duration::from_secs(300)),
            max_lines: 500,
        }
    }
}

/// Compute the "events older than this are dropped" cutoff (unix seconds).
/// `None` → sentinel `i64::MIN` so the comparison `ts < cutoff` is never
/// true; the scan is then bounded purely by `max_lines`. Factored out so
/// both `scan_wal_backward` and `collect_wal_backward` share the semantics.
fn compute_cutoff(max_age: Option<Duration>) -> i64 {
    let Some(max_age) = max_age else { return i64::MIN; };
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 - max_age.as_secs() as i64)
        .unwrap_or(0)
}

/// Default WAL directory (`~/.aikey/data/usage-wal`). Kept here so CLI
/// commands don't each reinvent the path.
pub fn default_wal_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".aikey").join("data").join("usage-wal"))
}

/// Scan WAL files newest-first, invoking `match_fn` on each entry.  Returns
/// the first Some(T) result or None when the budget is exhausted.
///
/// Design rationale (§5.1 of the receipt plan):
///   - fixed "tail N" breaks on high-traffic machines where N gets filled
///     by other sessions before our target is reached
///   - scanning until a match or a time/line budget is exhausted keeps the
///     cost bounded while respecting the actual workload
///   - reads per file are bounded by the file size, and only the latest
///     hour usually has significant size; older hours are short-circuited
///     by the age budget before we even open them
pub fn scan_wal_backward<T, F>(
    dir: &Path,
    mut match_fn: F,
    opts: ScanOptions,
) -> io::Result<Option<T>>
where
    F: FnMut(&UsageEvent) -> Option<T>,
{
    let cutoff_secs = compute_cutoff(opts.max_age);

    let mut files = match list_wal_files(dir) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // File names are `usage-YYYYMMDD-HH.jsonl`; lexical sort descending = time-descending.
    files.sort_by(|a, b| b.cmp(a));

    let mut lines_scanned = 0usize;
    for path in files {
        // Short-circuit: if this file's latest-possible timestamp is older
        // than the cutoff, everything inside is older still — skip the open.
        // (Disabled for simplicity: we rely on the per-entry age check
        // below, which is accurate. The file-level skip is a future optimization.)
        let scanned = scan_file_backward(&path, cutoff_secs, opts.max_lines - lines_scanned, &mut match_fn)?;
        lines_scanned += scanned.lines;
        if let Some(found) = scanned.found {
            return Ok(Some(found));
        }
        if scanned.hit_cutoff || lines_scanned >= opts.max_lines {
            break;
        }
    }
    Ok(None)
}

struct FileScanResult<T> {
    found: Option<T>,
    lines: usize,
    hit_cutoff: bool,
}

/// Scan a single JSONL file newest-first. Reads in chunks from the end so
/// we don't load the whole file even when the proxy has been running all day.
fn scan_file_backward<T, F>(
    path: &Path,
    cutoff_secs: i64,
    max_lines: usize,
    match_fn: &mut F,
) -> io::Result<FileScanResult<T>>
where
    F: FnMut(&UsageEvent) -> Option<T>,
{
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(FileScanResult { found: None, lines: 0, hit_cutoff: false });
        }
        Err(e) => return Err(e),
    };
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(FileScanResult { found: None, lines: 0, hit_cutoff: false });
    }

    const CHUNK: usize = 8 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK * 2);
    let mut pos = size;
    let mut remainder: Vec<u8> = Vec::new();  // bytes from previous chunk that
                                              // belonged to a line not yet terminated
    let mut lines_scanned = 0usize;
    let mut hit_cutoff = false;

    while pos > 0 && lines_scanned < max_lines {
        let read_size = CHUNK.min(pos as usize);
        pos -= read_size as u64;
        buf.resize(read_size, 0);
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut buf)?;

        // Splice this chunk in front of the remainder from last iteration
        // so any line that crosses the chunk boundary is reconstituted.
        let mut combined = Vec::with_capacity(buf.len() + remainder.len());
        combined.extend_from_slice(&buf);
        combined.extend_from_slice(&remainder);
        remainder.clear();

        // Split into lines, processing newest (end) first.
        let mut line_end = combined.len();
        let mut i = combined.len();
        while i > 0 {
            i -= 1;
            if combined[i] == b'\n' {
                let line = &combined[i + 1..line_end];
                line_end = i;
                if line.is_empty() { continue; }
                if let Some(res) = process_line(line, cutoff_secs, match_fn, &mut lines_scanned, &mut hit_cutoff) {
                    return Ok(FileScanResult { found: Some(res), lines: lines_scanned, hit_cutoff });
                }
                if hit_cutoff || lines_scanned >= max_lines {
                    return Ok(FileScanResult { found: None, lines: lines_scanned, hit_cutoff });
                }
            }
        }
        // Whatever's left before the first newline in this chunk is a
        // partial line; stash it and prepend on next iteration.
        if line_end > 0 {
            remainder = combined[..line_end].to_vec();
        }
    }

    // When we reach the start of the file, the leftover remainder IS the
    // first line and may still be unprocessed.
    if !remainder.is_empty() && lines_scanned < max_lines {
        if let Some(res) = process_line(&remainder, cutoff_secs, match_fn, &mut lines_scanned, &mut hit_cutoff) {
            return Ok(FileScanResult { found: Some(res), lines: lines_scanned, hit_cutoff });
        }
    }

    Ok(FileScanResult { found: None, lines: lines_scanned, hit_cutoff })
}

fn process_line<T, F>(
    line: &[u8],
    cutoff_secs: i64,
    match_fn: &mut F,
    lines_scanned: &mut usize,
    hit_cutoff: &mut bool,
) -> Option<T>
where
    F: FnMut(&UsageEvent) -> Option<T>,
{
    *lines_scanned += 1;
    let Ok(entry) = serde_json::from_slice::<WalEntry>(line) else {
        return None;  // bad line → skip
    };
    let ev = &entry.event_json;
    if let Some(ts) = ev.finished_at_unix() {
        if ts < cutoff_secs {
            *hit_cutoff = true;
            return None;
        }
    }
    match_fn(ev)
}

// ---------------------------------------------------------------------------
// collect_wal_backward — multi-hit counterpart to scan_wal_backward.
// ---------------------------------------------------------------------------
//
// Use case: Kimi receipt aggregation needs to fold ALL matching events in a
// window (one turn = N HTTP requests = N WAL events), not just the latest
// one. scan_wal_backward returns on first match; collect_wal_backward keeps
// walking newest-first and accumulates hits until the budget is exhausted.
//
// Returns `Vec<WalHit>` in newest-first order: `Vec[0]` is the most recent
// matching event. Callers that want the "turn's final event" for fields
// like model/event_time/stop_reason should index `Vec[0]` — NOT "last"
// (which is the oldest).
//
// Each `WalHit` carries the event plus its physical location in the WAL
// (`wal_file_name` + `wal_seq` from the envelope). The `(file, seq)` tuple
// is the strictly-monotonic watermark key the Kimi render handler uses to
// bound turns without depending on event_time's second-level precision.

/// Collect all matching WAL events within the scan window.
///
/// `match_fn` receives a `&WalHit` (event + location) and returns true to
/// include. Budget-bounded by `opts` (`max_lines` / `max_age`); stops early
/// when either exhausts. Results are in newest-first order.
pub fn collect_wal_backward<F>(
    dir: &Path,
    mut match_fn: F,
    opts: ScanOptions,
) -> io::Result<Vec<WalHit>>
where
    F: FnMut(&WalHit) -> bool,
{
    let cutoff_secs = compute_cutoff(opts.max_age);

    let mut files = match list_wal_files(dir) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    files.sort_by(|a, b| b.cmp(a)); // newest file first

    let mut out: Vec<WalHit> = Vec::new();
    let mut lines_scanned = 0usize;
    for path in files {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let (hit_cutoff, scanned_lines) = collect_file_backward(
            &path,
            &file_name,
            cutoff_secs,
            opts.max_lines.saturating_sub(lines_scanned),
            &mut match_fn,
            &mut out,
        )?;
        lines_scanned += scanned_lines;
        if hit_cutoff || lines_scanned >= opts.max_lines {
            break;
        }
    }
    Ok(out)
}

/// Scan a single WAL file newest-first, appending matching entries to `out`.
/// Returns `(hit_cutoff, lines_scanned)`. Shares chunked backward-read
/// plumbing with scan_file_backward but accumulates instead of returning.
fn collect_file_backward<F>(
    path: &Path,
    file_name: &str,
    cutoff_secs: i64,
    max_lines: usize,
    match_fn: &mut F,
    out: &mut Vec<WalHit>,
) -> io::Result<(bool, usize)>
where
    F: FnMut(&WalHit) -> bool,
{
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((false, 0)),
        Err(e) => return Err(e),
    };
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok((false, 0));
    }

    const CHUNK: usize = 8 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK * 2);
    let mut pos = size;
    let mut remainder: Vec<u8> = Vec::new();
    let mut lines_scanned = 0usize;
    let mut hit_cutoff = false;

    while pos > 0 && lines_scanned < max_lines {
        let read_size = CHUNK.min(pos as usize);
        pos -= read_size as u64;
        buf.resize(read_size, 0);
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut buf)?;

        let mut combined = Vec::with_capacity(buf.len() + remainder.len());
        combined.extend_from_slice(&buf);
        combined.extend_from_slice(&remainder);
        remainder.clear();

        let mut line_end = combined.len();
        let mut i = combined.len();
        while i > 0 {
            i -= 1;
            if combined[i] == b'\n' {
                let line = &combined[i + 1..line_end];
                line_end = i;
                if line.is_empty() { continue; }
                process_line_collect(line, file_name, cutoff_secs, match_fn, &mut lines_scanned, &mut hit_cutoff, out);
                if hit_cutoff || lines_scanned >= max_lines {
                    return Ok((hit_cutoff, lines_scanned));
                }
            }
        }
        if line_end > 0 {
            remainder = combined[..line_end].to_vec();
        }
    }

    if !remainder.is_empty() && lines_scanned < max_lines {
        process_line_collect(&remainder, file_name, cutoff_secs, match_fn, &mut lines_scanned, &mut hit_cutoff, out);
    }

    Ok((hit_cutoff, lines_scanned))
}

fn process_line_collect<F>(
    line: &[u8],
    file_name: &str,
    cutoff_secs: i64,
    match_fn: &mut F,
    lines_scanned: &mut usize,
    hit_cutoff: &mut bool,
    out: &mut Vec<WalHit>,
) where
    F: FnMut(&WalHit) -> bool,
{
    *lines_scanned += 1;
    let Ok(entry) = serde_json::from_slice::<WalEntry>(line) else { return; };
    if let Some(ts) = entry.event_json.finished_at_unix() {
        if ts < cutoff_secs {
            *hit_cutoff = true;
            return;
        }
    }
    let hit = WalHit {
        event: entry.event_json,
        wal_file_name: file_name.to_string(),
        wal_seq: entry.wal_seq,
    };
    if match_fn(&hit) {
        out.push(hit);
    }
}

/// Enumerate all `usage-*.jsonl` files under `dir`. Order is unspecified;
/// callers sort as they need.
fn list_wal_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name.starts_with("usage-") && name.ends_with(".jsonl") {
            out.push(path);
        }
    }
    Ok(out)
}

/// Best-effort RFC3339 → unix seconds parser. Returns None on any format
/// we don't recognize (the WAL should always emit RFC3339 with offset, but
/// being defensive keeps a rogue line from aborting the whole scan).
fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    // Accept the common patterns the proxy emits:
    //   2026-04-13T11:54:40.122225+08:00
    //   2026-04-17T15:23:45.123Z
    //   2026-04-17T15:23:45Z
    // We don't need millisecond precision — statusline filtering is at
    // second granularity, so a lightweight parser avoids pulling chrono in.
    let bytes = s.as_bytes();
    if bytes.len() < 19 { return None; }
    let (y, mo, d, h, mi, sec) = (
        std::str::from_utf8(&bytes[0..4]).ok()?.parse::<i32>().ok()?,
        std::str::from_utf8(&bytes[5..7]).ok()?.parse::<u32>().ok()?,
        std::str::from_utf8(&bytes[8..10]).ok()?.parse::<u32>().ok()?,
        std::str::from_utf8(&bytes[11..13]).ok()?.parse::<u32>().ok()?,
        std::str::from_utf8(&bytes[14..16]).ok()?.parse::<u32>().ok()?,
        std::str::from_utf8(&bytes[17..19]).ok()?.parse::<u32>().ok()?,
    );
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    // Find timezone: skip optional fractional seconds (.123456).
    let mut idx = 19;
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    let tz_offset_secs = if idx < bytes.len() {
        match bytes[idx] {
            b'Z' | b'z' => 0,
            b'+' | b'-' => {
                if bytes.len() < idx + 6 || bytes[idx + 3] != b':' {
                    return None;
                }
                let hh = std::str::from_utf8(&bytes[idx + 1..idx + 3]).ok()?.parse::<i64>().ok()?;
                let mm = std::str::from_utf8(&bytes[idx + 4..idx + 6]).ok()?.parse::<i64>().ok()?;
                let signed = (hh * 3600 + mm * 60) * if bytes[idx] == b'+' { 1 } else { -1 };
                signed
            }
            _ => return None,
        }
    } else {
        0
    };

    // Gregorian days-from-epoch, naive but correct for the range we care about.
    let days = days_from_civil(y, mo, d)?;
    let utc_secs = days * 86400 + h as i64 * 3600 + mi as i64 * 60 + sec as i64 - tz_offset_secs;
    Some(utc_secs)
}

/// Howard Hinnant's days_from_civil algorithm: converts a proleptic
/// Gregorian calendar date to number of days since 1970-01-01.  Copied
/// here to avoid a chrono dependency just for one parse helper.
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || d == 0 || d > 31 { return None; }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as i64;
    let mu = m as i64;
    let doy = (153 * (if mu > 2 { mu - 3 } else { mu + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era as i64 * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_utc_with_fractional() {
        let ts = parse_rfc3339_secs("2026-04-17T15:23:45.123Z").unwrap();
        // 2026-04-17 15:23:45 UTC
        assert_eq!(ts, 1776439425);
    }

    #[test]
    fn parse_positive_offset() {
        let ts = parse_rfc3339_secs("2026-04-13T11:54:40.122225+08:00").unwrap();
        // 2026-04-13 11:54:40 +08:00 = 2026-04-13 03:54:40 UTC
        assert_eq!(ts, 1776052480);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_rfc3339_secs("not a timestamp").is_none());
        assert!(parse_rfc3339_secs("2026-04-17").is_none());
    }

    #[test]
    fn usage_event_deserializes_omitempty_fields() {
        let raw = br#"{"event_id":"abc","event_time":"2026-04-17T15:23:45Z","virtual_key_id":"personal:kimi-local","provider_code":"kimi","route_source":"personal","input_tokens":10,"output_tokens":20,"total_tokens":30,"request_status":"success","http_status_code":200}"#;
        let ev: UsageEvent = serde_json::from_slice(raw).unwrap();
        assert_eq!(ev.session_id, None);
        assert_eq!(ev.key_label, None);
        assert_eq!(ev.completion, None);
        assert_eq!(ev.input_tokens, Some(10));
    }

    #[test]
    fn usage_event_v5_fields() {
        let raw = br#"{"event_id":"abc","event_time":"2026-04-17T15:23:45Z","session_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","key_label":"aikeyfounder@gmail.com","completion":"complete","virtual_key_id":"oauth:acct","provider_code":"anthropic","route_source":"oauth","model":"claude-sonnet-4-5","input_tokens":100,"output_tokens":50}"#;
        let ev: UsageEvent = serde_json::from_slice(raw).unwrap();
        assert_eq!(ev.session_id.as_deref(), Some("f47ac10b-58cc-4372-a567-0e02b2c3d479"));
        assert_eq!(ev.key_label.as_deref(), Some("aikeyfounder@gmail.com"));
        assert_eq!(ev.completion.as_deref(), Some("complete"));
    }

    #[test]
    fn scan_finds_newest_match_across_files() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();

        let make_line = |sid: &str, model: &str, ts: &str| -> Vec<u8> {
            let ev = format!(
                r#"{{"wal_seq":1,"written_at":"{ts}","schema_version":1,"event_json":{{"event_id":"{sid}-{model}","event_time":"{ts}","session_id":"{sid}","model":"{model}","virtual_key_id":"x","provider_code":"p","route_source":"personal","request_status":"success"}}}}"#
            );
            let mut v = ev.into_bytes();
            v.push(b'\n');
            v
        };

        // Older file: two events
        let old = tmp.path().join("usage-20260417-14.jsonl");
        {
            let mut f = std::fs::File::create(&old).unwrap();
            f.write_all(&make_line("sess-a", "claude-sonnet-4-5", "2026-04-17T14:50:00Z")).unwrap();
            f.write_all(&make_line("sess-b", "claude-sonnet-4-5", "2026-04-17T14:55:00Z")).unwrap();
        }
        // Newer file: newest event for sess-a
        let new = tmp.path().join("usage-20260417-15.jsonl");
        {
            let mut f = std::fs::File::create(&new).unwrap();
            f.write_all(&make_line("sess-a", "claude-sonnet-4-5", "2026-04-17T15:00:00Z")).unwrap();
        }

        // Disable the age filter so the old (2026-04-17) fixture events
        // aren't pruned. Production callers pick an explicit age bound; the
        // test needs `None` for a stable offline fixture.
        let opts = ScanOptions { max_age: None, max_lines: 500 };
        let found: Option<UsageEvent> = scan_wal_backward(tmp.path(), |ev| {
            if ev.session_id.as_deref() == Some("sess-a") { Some(ev.clone()) } else { None }
        }, opts).unwrap();

        let ev = found.expect("should find newest sess-a event");
        // 2026-04-17T15:00:00Z → 1776438000 s → 1776438000000 ms.
        assert_eq!(ev.event_time, 1776438000000);
    }

    // -----------------------------------------------------------------
    // collect_wal_backward tests
    // -----------------------------------------------------------------

    /// Helper: write a WAL envelope with session_id + provider + wal_seq.
    fn write_envelope(
        f: &mut std::fs::File,
        wal_seq: u64,
        session_id: &str,
        provider: &str,
        event_time: &str,
        in_tok: i64,
        out_tok: i64,
    ) {
        use std::io::Write;
        let line = format!(
            r#"{{"wal_seq":{wal_seq},"written_at":"{event_time}","event_json":{{"event_id":"e-{wal_seq}","event_time":"{event_time}","session_id":"{session_id}","virtual_key_id":"vk","provider_code":"{provider}","route_source":"oauth","input_tokens":{in_tok},"output_tokens":{out_tok},"total_tokens":{t},"request_status":"success","http_status_code":200}}}}"#,
            t = in_tok + out_tok
        );
        writeln!(f, "{line}").unwrap();
    }

    #[test]
    fn collect_returns_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        // Build fixed "now" relative timestamps so the scan window covers them
        let hour_str = chrono_like_hour(&tmp.path().to_path_buf());
        let path = tmp.path().join(format!("usage-{hour_str}.jsonl"));
        let mut f = std::fs::File::create(&path).unwrap();
        let now = rfc3339_now();
        // seq=1 oldest, seq=3 newest — file is append-only
        write_envelope(&mut f, 1, "sess-a", "kimi", &now, 10, 5);
        write_envelope(&mut f, 2, "sess-a", "kimi", &now, 20, 10);
        write_envelope(&mut f, 3, "sess-a", "kimi", &now, 30, 15);
        drop(f);

        let hits = collect_wal_backward(tmp.path(), |hit| hit.event.session_id.as_deref() == Some("sess-a"), ScanOptions::default()).unwrap();
        assert_eq!(hits.len(), 3);
        // newest-first: Vec[0] is seq=3
        assert_eq!(hits[0].wal_seq, 3);
        assert_eq!(hits[1].wal_seq, 2);
        assert_eq!(hits[2].wal_seq, 1);
    }

    #[test]
    fn collect_filters_by_session_and_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let hour_str = chrono_like_hour(&tmp.path().to_path_buf());
        let path = tmp.path().join(format!("usage-{hour_str}.jsonl"));
        let mut f = std::fs::File::create(&path).unwrap();
        let now = rfc3339_now();
        write_envelope(&mut f, 1, "sess-a", "kimi", &now, 10, 5);
        write_envelope(&mut f, 2, "sess-b", "kimi", &now, 99, 99);   // different session
        write_envelope(&mut f, 3, "sess-a", "anthropic", &now, 50, 50); // different provider
        write_envelope(&mut f, 4, "sess-a", "kimi", &now, 20, 10);
        drop(f);

        let hits = collect_wal_backward(
            tmp.path(),
            |hit| {
                hit.event.session_id.as_deref() == Some("sess-a")
                    && hit.event.provider_code == "kimi"
            },
            ScanOptions::default(),
        )
        .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].wal_seq, 4); // newest sess-a kimi
        assert_eq!(hits[1].wal_seq, 1);
    }

    #[test]
    fn collect_budget_bounds_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let hour_str = chrono_like_hour(&tmp.path().to_path_buf());
        let path = tmp.path().join(format!("usage-{hour_str}.jsonl"));
        let mut f = std::fs::File::create(&path).unwrap();
        let now = rfc3339_now();
        for i in 1..=20 {
            write_envelope(&mut f, i, "sess-a", "kimi", &now, 1, 1);
        }
        drop(f);

        let opts = ScanOptions { max_lines: 5, ..ScanOptions::default() };
        let hits = collect_wal_backward(tmp.path(), |_| true, opts).unwrap();
        // We can examine at most 5 lines; some may match, some may be
        // filtered by budget before examination — so we expect ≤5.
        assert!(hits.len() <= 5, "got {} hits, expected ≤5", hits.len());
        // And they should still be newest-first.
        for w in hits.windows(2) {
            assert!(w[0].wal_seq > w[1].wal_seq, "hits not newest-first: {:?}", hits.iter().map(|h| h.wal_seq).collect::<Vec<_>>());
        }
    }

    /// Watermark tuple monotonicity across files (regression guard for the
    /// 4th review round Finding 1): two events in consecutive hourly files
    /// with seq values that would collide within a single file but are
    /// disambiguated by the file-name component of the tuple.
    #[test]
    fn collect_carries_file_name_and_seq_across_files() {
        let tmp = tempfile::tempdir().unwrap();
        let now = rfc3339_now();
        // File 1 (earlier hour) with seq=50
        let f1 = tmp.path().join("usage-20260418-19.jsonl");
        let mut w1 = std::fs::File::create(&f1).unwrap();
        write_envelope(&mut w1, 50, "sess-a", "kimi", &now, 10, 5);
        drop(w1);
        // File 2 (later hour) with seq=1 (simulating proxy restart)
        let f2 = tmp.path().join("usage-20260418-20.jsonl");
        let mut w2 = std::fs::File::create(&f2).unwrap();
        write_envelope(&mut w2, 1, "sess-a", "kimi", &now, 20, 10);
        drop(w2);

        let hits = collect_wal_backward(tmp.path(), |_| true, ScanOptions::default()).unwrap();
        assert_eq!(hits.len(), 2);
        // Newest first by file name (lexicographic = time order).
        assert_eq!(hits[0].wal_file_name, "usage-20260418-20.jsonl");
        assert_eq!(hits[0].wal_seq, 1);
        assert_eq!(hits[1].wal_file_name, "usage-20260418-19.jsonl");
        assert_eq!(hits[1].wal_seq, 50);
    }

    /// Regression guard for review finding #1: when `max_age` is `None`,
    /// events older than any default window must still be returned. This
    /// models a Kimi turn that idles > 5 min mid-turn — the early event
    /// must be aggregated into the turn, not silently dropped.
    #[test]
    fn collect_max_age_none_includes_events_older_than_default_window() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("usage-20260418-20.jsonl");
        let mut w = std::fs::File::create(&f).unwrap();
        // Timestamp 30 minutes before "now" — well past the default 5-min
        // ScanOptions cutoff.
        let thirty_min_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 30 * 60;
        let days_from_epoch = (thirty_min_ago / 86400) as i64;
        let sec_of_day = thirty_min_ago % 86400;
        let (y, m, d) = civil_from_days(days_from_epoch);
        let old_ts = format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            sec_of_day / 3600,
            (sec_of_day % 3600) / 60,
            sec_of_day % 60
        );
        write_envelope(&mut w, 1, "sess-long", "kimi", &old_ts, 100, 10);
        drop(w);

        // With the default (5-min) cutoff, the event IS filtered out.
        let default_hits = collect_wal_backward(
            tmp.path(),
            |h| h.event.session_id.as_deref() == Some("sess-long"),
            ScanOptions::default(),
        )
        .unwrap();
        assert_eq!(
            default_hits.len(),
            0,
            "default cutoff (5 min) must drop the 30-min-old event (baseline)"
        );

        // With `max_age: None` (post-fix behavior), the event survives.
        let unbounded_hits = collect_wal_backward(
            tmp.path(),
            |h| h.event.session_id.as_deref() == Some("sess-long"),
            ScanOptions { max_age: None, max_lines: 500 },
        )
        .unwrap();
        assert_eq!(
            unbounded_hits.len(),
            1,
            "max_age=None must include events older than the default window \
             (long-turn regression guard — review finding #1)"
        );
        assert_eq!(unbounded_hits[0].wal_seq, 1);
    }

    fn rfc3339_now() -> String {
        // "good enough" RFC3339 string for test fixtures; uses current time.
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Approximate — days since epoch for "today" in UTC.
        let days_from_epoch = (secs / 86400) as i64;
        let sec_of_day = secs % 86400;
        let hh = sec_of_day / 3600;
        let mm = (sec_of_day % 3600) / 60;
        let ss = sec_of_day % 60;
        let (y, m, d) = civil_from_days(days_from_epoch);
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    }

    fn chrono_like_hour(_dir: &std::path::Path) -> String {
        // Use a fixed name for the single-file tests.
        "20260418-20".to_string()
    }

    // days-to-civil inverse of the existing days_from_civil helper above.
    fn civil_from_days(days: i64) -> (i32, u32, u32) {
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u32;
        let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
        let y = (yoe as i32) + (era as i32) * 400;
        let doy = doe - (365*yoe + yoe/4 - yoe/100);
        let mp = (5*doy + 2) / 153;
        let d = doy - (153*mp + 2)/5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = y + if m <= 2 { 1 } else { 0 };
        (y, m, d)
    }
}
