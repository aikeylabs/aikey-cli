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

use serde::Deserialize;
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
    #[serde(default)]
    pub event_time: String, // RFC3339 string; parsed lazily

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

    #[serde(default)]
    pub request_status: String,
    #[serde(default)]
    pub http_status_code: Option<i32>,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl UsageEvent {
    /// Returns seconds since the unix epoch for `event_time`, or None when
    /// the field is absent or unparsable. Kept lazy so hot-path callers
    /// (statusline) only parse when they actually need the timestamp.
    pub fn finished_at_unix(&self) -> Option<i64> {
        parse_rfc3339_secs(&self.event_time)
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

/// WAL envelope — `{"wal_seq":..,"written_at":..,"event_json":{...}}`.
/// We only care about `event_json`.
#[derive(Debug, Deserialize)]
struct WalEntry {
    event_json: UsageEvent,
}

/// Options controlling the backward scan budget.
///
/// The scan trades off between "always find my session's event" and "keep
/// statusline fast even under heavy load". `max_age` prunes by time first
/// (stop reading events older than this cutoff), `max_lines` is the hard
/// cap on total lines parsed so a single pathological file can't block us.
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub max_age: Duration,
    pub max_lines: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(300),  // 5 minutes — generous enough
                                                // to survive noisy mixed-session
                                                // machines (see §5.1 of design doc)
            max_lines: 500,
        }
    }
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
    let now = SystemTime::now();
    let cutoff_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 - opts.max_age.as_secs() as i64)
        .unwrap_or(0);

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

        // Infinite age budget so the old (2026-04-17) events aren't pruned.
        // Production callers use Duration::from_secs(300), but for a stable
        // offline fixture we accept anything after the fixture timestamps.
        let opts = ScanOptions { max_age: Duration::from_secs(i32::MAX as u64), max_lines: 500 };
        let found: Option<UsageEvent> = scan_wal_backward(tmp.path(), |ev| {
            if ev.session_id.as_deref() == Some("sess-a") { Some(ev.clone()) } else { None }
        }, opts).unwrap();

        let ev = found.expect("should find newest sess-a event");
        assert_eq!(ev.event_time, "2026-04-17T15:00:00Z");
    }
}
