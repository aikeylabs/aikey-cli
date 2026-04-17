//! `aikey watch` — long-running TUI dashboard reading the same WAL the
//! `aikey statusline` command consumes.
//!
//! Runtime modes:
//!   * **TUI mode** (default when stdout is a terminal): alt-screen +
//!     raw-mode crossterm loop, live WAL tailing via `notify`, key-driven
//!     sort / view / filter toggles.
//!   * **Snapshot mode** (stdout piped or NO_TUI=1): renders a single
//!     frame then exits.  Useful for CI smoke tests and `aikey watch | cat`.
//!
//! Design anchors (see 费用小票-实施方案.md §6):
//!   - aggregator holds only the last 24h; older WAL data is ignored
//!   - `notify` watches the WAL dir; each event pumps its originating file
//!     from where we last stopped reading (offset cache)
//!   - per-key GC runs every minute so idle keys fall out of the table
//!   - proxy liveness is inferred from `~/.aikey/run/proxy.pid` + `kill -0`,
//!     with a data-age fallback when the pid file is missing

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::usage_wal::{default_wal_dir, UsageEvent};

/// Observation window for cold-start ingestion.  Matches §6.2 of the
/// design doc: aggregator holds the last 24h of activity, older WAL files
/// are skipped to keep startup under ~300ms even on busy machines.
const LOOKBACK: Duration = Duration::from_secs(24 * 3600);

/// Gap threshold that separates one "session burst" from the next when
/// grouping events into `session_latest`.  Independent of Claude Code's
/// session_id — this represents "continuous activity on this key" which
/// is a different question.  15 min matches most people's intuition of a
/// single sitting / conversation.
const SESSION_GAP: Duration = Duration::from_secs(15 * 60);

/// Rolling-average smoothing factor for latency.  α = 0.3 gives more
/// weight to recent requests without ignoring history.
const LATENCY_EMA_ALPHA: f64 = 0.3;

/// Entrypoint for `aikey watch`. P1a variant: renders one static snapshot
/// and returns.  P1c/P1d replace this with a long-running TUI loop.
pub fn run() -> io::Result<()> {
    let Some(wal_dir) = default_wal_dir() else {
        eprintln!("aikey watch: HOME unset, cannot resolve WAL directory");
        return Ok(());
    };
    if !wal_dir.exists() {
        println!("aikey watch: no WAL directory at {}", wal_dir.display());
        println!("  (proxy has never run on this machine — make a request first, then retry)");
        return Ok(());
    }

    let now = SystemTime::now();
    let agg = load_aggregator(&wal_dir, now)?;
    render_snapshot(&agg, now);
    Ok(())
}

// ---------------------------------------------------------------------------
// Aggregator — per-key rollup across the 24h window.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct Aggregator {
    by_key: HashMap<String, KeyAggregate>,
    /// Last observed event timestamp across all keys — seed for the TUI's
    /// freshness indicator ("proxy last seen Xs ago").
    last_event_at: Option<SystemTime>,
    /// Absolute range covered by this aggregator; used by the renderer to
    /// compute "today" boundary in the viewer's local timezone.
    observed_since: SystemTime,
}

impl Aggregator {
    fn new(observed_since: SystemTime) -> Self {
        Self { by_key: HashMap::new(), last_event_at: None, observed_since }
    }

    /// Fold one event into the aggregator.  Idempotency is the caller's
    /// responsibility (replaying the same event twice would double-count).
    /// Events whose timestamp can't be parsed are skipped — preserving the
    /// "JSONL is forgiving" property shared with `usage_wal`.
    pub(crate) fn apply(&mut self, ev: &UsageEvent) {
        let Some(ts_secs) = ev.finished_at_unix() else { return; };
        let ts = UNIX_EPOCH + Duration::from_secs(ts_secs as u64);

        let key_id = aggregate_key_id(ev);
        let entry = self.by_key.entry(key_id.clone()).or_insert_with(|| KeyAggregate::empty(ev));
        entry.apply(ev, ts);

        match self.last_event_at {
            Some(prev) if prev >= ts => {}
            _ => self.last_event_at = Some(ts),
        }
    }

    /// Sorted view for TUI rendering.  Primary sort: today's total tokens
    /// (desc).  Ties broken by last_event_at desc so freshly-used keys
    /// surface first even when both are idle today.
    pub(crate) fn rows_sorted(&self) -> Vec<&KeyAggregate> {
        let mut rows: Vec<&KeyAggregate> = self.by_key.values().collect();
        rows.sort_by(|a, b| {
            let ta = a.today.in_tokens + a.today.out_tokens;
            let tb = b.today.in_tokens + b.today.out_tokens;
            tb.cmp(&ta).then_with(|| b.last_event_at.cmp(&a.last_event_at))
        });
        rows
    }

    /// Most recent events seen during ingestion, newest first, bounded
    /// by `limit`.  Backs the "recent" section at the bottom of the TUI.
    pub(crate) fn recent_events(&self, limit: usize) -> Vec<&UsageEvent> {
        let mut all: Vec<&UsageEvent> = self.by_key.values()
            .flat_map(|k| k.recent.iter())
            .collect();
        all.sort_by(|a, b|
            b.finished_at_unix().cmp(&a.finished_at_unix()));
        all.truncate(limit);
        all
    }
}

/// Primary aggregation key.  For OAuth we use the account id (unique per
/// Claude/Codex/Kimi account); for team/personal keys we use virtual_key_id
/// which is guaranteed stable across rotations.
fn aggregate_key_id(ev: &UsageEvent) -> String {
    if !ev.virtual_key_id.is_empty() { ev.virtual_key_id.clone() }
    else if let Some(oid) = ev.oauth_identity.as_deref() { oid.to_string() }
    else { "(unknown)".to_string() }
}

#[derive(Debug, Clone)]
pub(crate) struct KeyAggregate {
    pub(crate) identity: KeyIdentity,
    pub(crate) lifetime: Counters,
    pub(crate) window_1h: MinuteBuckets,
    pub(crate) today: DayCounters,
    pub(crate) session_latest: Option<Session>,
    pub(crate) last_event_at: Option<SystemTime>,
    pub(crate) last_latency_ms: u32,
    pub(crate) avg_latency_ms: u32,
    pub(crate) last_status: Option<i32>,
    /// Ring of recent events for the "recent" strip.  Bounded to keep memory
    /// sane when a key sees thousands of requests in 24h.
    pub(crate) recent: Vec<UsageEvent>,
}

const RECENT_PER_KEY_CAP: usize = 8;

impl KeyAggregate {
    fn empty(seed: &UsageEvent) -> Self {
        Self {
            identity: KeyIdentity::from_event(seed),
            lifetime: Counters::default(),
            window_1h: MinuteBuckets::new(),
            today: DayCounters::empty(),
            session_latest: None,
            last_event_at: None,
            last_latency_ms: 0,
            avg_latency_ms: 0,
            last_status: None,
            recent: Vec::with_capacity(RECENT_PER_KEY_CAP),
        }
    }

    fn apply(&mut self, ev: &UsageEvent, ts: SystemTime) {
        // Keep identity in sync with the most recent event: label / model
        // can change over a key's lifetime (e.g. user renames alias).
        self.identity.update(ev);

        let (in_tok, out_tok) = token_pair(ev);
        self.lifetime.add(in_tok, out_tok);
        self.window_1h.add(ts, in_tok, out_tok);
        self.today.add(ts, in_tok, out_tok);

        self.session_latest = Some(match self.session_latest.take() {
            Some(mut s) if ts.duration_since(s.last_event_at).unwrap_or(Duration::ZERO) <= SESSION_GAP => {
                s.calls += 1;
                s.in_tokens += in_tok;
                s.out_tokens += out_tok;
                s.last_event_at = ts;
                s
            }
            _ => Session { started_at: ts, last_event_at: ts, calls: 1, in_tokens: in_tok, out_tokens: out_tok },
        });

        self.last_event_at = Some(ts);
        // Latency isn't persisted in the WAL schema yet (see design doc
        // Future Directions §11); placeholder fields stay zero until then.
        if let Some(code) = ev.http_status_code { self.last_status = Some(code); }

        if self.recent.len() >= RECENT_PER_KEY_CAP {
            // Keep only the most recent: drop oldest when full.
            self.recent.remove(0);
        }
        self.recent.push(ev.clone());
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KeyIdentity {
    pub(crate) label: String,
    pub(crate) key_type: String,
    pub(crate) provider: String,
    pub(crate) last_model: String,
}

impl KeyIdentity {
    fn from_event(ev: &UsageEvent) -> Self {
        Self {
            label: best_label(ev).to_string(),
            key_type: ev.route_source.clone(),
            provider: ev.provider_code.clone(),
            last_model: ev.model.clone(),
        }
    }
    fn update(&mut self, ev: &UsageEvent) {
        let label = best_label(ev);
        if !label.is_empty() { self.label = label.to_string(); }
        if !ev.route_source.is_empty() { self.key_type = ev.route_source.clone(); }
        if !ev.provider_code.is_empty() { self.provider = ev.provider_code.clone(); }
        if !ev.model.is_empty() { self.last_model = ev.model.clone(); }
    }
}

fn best_label(ev: &UsageEvent) -> &str {
    if let Some(s) = ev.key_label.as_deref() { if !s.is_empty() { return s; } }
    if let Some(s) = ev.oauth_identity.as_deref() { if !s.is_empty() { return s; } }
    if !ev.virtual_key_id.is_empty() { return ev.virtual_key_id.as_str(); }
    "(unknown)"
}

fn token_pair(ev: &UsageEvent) -> (u64, u64) {
    let i = ev.input_tokens.unwrap_or(0).max(0) as u64;
    let o = ev.output_tokens.unwrap_or(0).max(0) as u64;
    (i, o)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Counters {
    pub(crate) calls: u64,
    pub(crate) in_tokens: u64,
    pub(crate) out_tokens: u64,
}

impl Counters {
    fn add(&mut self, in_tok: u64, out_tok: u64) {
        self.calls += 1;
        self.in_tokens += in_tok;
        self.out_tokens += out_tok;
    }
}

/// 60 one-minute buckets forming a sliding 1-hour window.  Each bucket
/// carries the minute-floor timestamp it represents; stale buckets are
/// reset lazily when they're written to again (cheaper than sweeping).
#[derive(Debug, Clone)]
pub(crate) struct MinuteBuckets {
    buckets: [Bucket; 60],
}

#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    minute_secs: u64,  // unix seconds / 60, 0 when slot unused
    calls: u32,
    in_tokens: u64,
    out_tokens: u64,
}

impl MinuteBuckets {
    fn new() -> Self { Self { buckets: [Bucket::default(); 60] } }

    fn add(&mut self, ts: SystemTime, in_tok: u64, out_tok: u64) {
        // Drop events already outside the 1h window: without this guard,
        // replaying an old WAL file during aggregator warm-up could overwrite
        // a valid bucket that happens to share the same `minute % 60` slot
        // (collision frequency = 1/60 per event pair), silently losing data.
        let m = minute_index(ts);
        let now_m = minute_index(SystemTime::now());
        if now_m.saturating_sub(m) >= 60 { return; }

        let slot = (m % 60) as usize;
        let b = &mut self.buckets[slot];
        if b.minute_secs != m {
            *b = Bucket { minute_secs: m, calls: 0, in_tokens: 0, out_tokens: 0 };
        }
        b.calls += 1;
        b.in_tokens += in_tok;
        b.out_tokens += out_tok;
    }

    /// Sum of all buckets whose minute timestamp lies within the last hour
    /// relative to `now`.  Stale buckets (from more than an hour ago) are
    /// filtered out rather than physically removed — lazy rolloff keeps
    /// the hot-path write cheap.
    pub(crate) fn sum(&self, now: SystemTime) -> Counters {
        let now_m = minute_index(now);
        let mut out = Counters::default();
        for b in &self.buckets {
            if b.minute_secs == 0 { continue; }
            let delta = now_m.saturating_sub(b.minute_secs);
            if delta < 60 {
                out.calls += b.calls as u64;
                out.in_tokens += b.in_tokens;
                out.out_tokens += b.out_tokens;
            }
        }
        out
    }
}

fn minute_index(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH).map(|d| d.as_secs() / 60).unwrap_or(0)
}

/// Per-key today-total, keyed by local calendar date.  When the date
/// advances, counters reset — matches a user's mental model of "today".
#[derive(Debug, Clone)]
pub(crate) struct DayCounters {
    local_date: String,  // YYYY-MM-DD; empty until first event seen
    pub(crate) calls: u64,
    pub(crate) in_tokens: u64,
    pub(crate) out_tokens: u64,
}

impl DayCounters {
    fn empty() -> Self { Self { local_date: String::new(), calls: 0, in_tokens: 0, out_tokens: 0 } }
    fn add(&mut self, ts: SystemTime, in_tok: u64, out_tok: u64) {
        let d = local_date_string(ts);
        if self.local_date != d {
            self.local_date = d;
            self.calls = 0;
            self.in_tokens = 0;
            self.out_tokens = 0;
        }
        self.calls += 1;
        self.in_tokens += in_tok;
        self.out_tokens += out_tok;
    }
}

/// "Session" here = a burst of activity on this key, separated by
/// `SESSION_GAP` of idleness.  Distinct from Claude Code's session_id —
/// see design doc §6.3 for the full rationale.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub(crate) started_at: SystemTime,
    pub(crate) last_event_at: SystemTime,
    pub(crate) calls: u64,
    pub(crate) in_tokens: u64,
    pub(crate) out_tokens: u64,
}

impl Session {
    pub(crate) fn is_active(&self, now: SystemTime) -> bool {
        now.duration_since(self.last_event_at).unwrap_or(Duration::ZERO) < SESSION_GAP
    }
}

// ---------------------------------------------------------------------------
// WAL ingestion: scan the last 24h of usage-YYYYMMDD-HH.jsonl files.
// ---------------------------------------------------------------------------

pub(crate) fn load_aggregator(wal_dir: &Path, now: SystemTime) -> io::Result<Aggregator> {
    let cutoff = now.checked_sub(LOOKBACK).unwrap_or(now);
    let cutoff_secs = cutoff.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);

    let mut agg = Aggregator::new(cutoff);
    let files = collect_wal_files(wal_dir)?;

    // Read oldest → newest so the session / today logic sees events in
    // chronological order — otherwise gap-based session segmentation
    // would produce nonsense.
    for path in files {
        ingest_file(&path, cutoff_secs, &mut agg)?;
    }
    Ok(agg)
}

fn collect_wal_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()).map(str::to_string) {
            if name.starts_with("usage-") && name.ends_with(".jsonl") {
                paths.push(entry.path());
            }
        }
    }
    paths.sort();  // file names are YYYYMMDD-HH → lexical sort = chronological
    Ok(paths)
}

fn ingest_file(path: &Path, cutoff_secs: i64, agg: &mut Aggregator) -> io::Result<()> {
    use std::io::BufRead;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = match line { Ok(l) => l, Err(_) => continue };
        if line.is_empty() { continue; }
        let Ok(entry) = serde_json::from_str::<WalEnvelope>(&line) else { continue };
        if let Some(ts) = entry.event_json.finished_at_unix() {
            if ts < cutoff_secs { continue; }
        }
        agg.apply(&entry.event_json);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct WalEnvelope {
    event_json: UsageEvent,
}

// ---------------------------------------------------------------------------
// Timestamp → local date (YYYY-MM-DD).
// ---------------------------------------------------------------------------

fn local_date_string(ts: SystemTime) -> String {
    // Use the current process local-timezone offset by comparing what the
    // OS thinks "now" is in unix time vs what a local datetime would say.
    // This avoids pulling in the `time` / `chrono` crates just for
    // day-bucketing.  Correctness caveat: on a machine that crosses DST
    // during a session, "today" may shift by an hour at the boundary — we
    // treat that as acceptable for a UI dashboard, not accounting.
    let secs = ts.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let local = secs + current_tz_offset_secs();
    let days = local / 86400;
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn current_tz_offset_secs() -> i64 {
    // Rust std doesn't expose local timezone offset portably.  Shell out
    // to libc's localtime_r to read the seconds east of UTC for "now".
    #[cfg(unix)]
    unsafe {
        let t: libc::time_t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64
    }
    #[cfg(not(unix))]
    { 0 }
}

/// Howard Hinnant's civil_from_days algorithm — inverse of
/// days_from_civil in usage_wal.rs.  Kept local to avoid exposing it as
/// a public helper when both modules only need one direction each.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z / 146097 } else { (z - 146096) / 146097 };
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y_out = y + if m <= 2 { 1 } else { 0 };
    (y_out as i32, m, d)
}

// ---------------------------------------------------------------------------
// Static snapshot rendering (P1a) — interactive TUI comes in P1c/P1d.
// ---------------------------------------------------------------------------

fn render_snapshot(agg: &Aggregator, now: SystemTime) {
    use colored::Colorize;
    let rows = agg.rows_sorted();
    println!();
    println!("  {} {}",
        "aikey watch".bold(),
        format!("— {} keys active in last 24h", rows.len()).dimmed());
    println!();

    if rows.is_empty() {
        println!("  {}", "No activity in the last 24 hours.".dimmed());
        println!("  {}", "Make a request through aikey-proxy, then re-run.".dimmed());
        return;
    }

    println!("  {}",
        format!("{:<28} {:<10} {:<10} {:>10} {:>10} {:>12}",
            "KEY", "TYPE", "PROVIDER", "1H", "TODAY", "LAST").dimmed());
    println!("  {}", "─".repeat(84).dimmed());

    for k in &rows {
        let today = &k.today;
        let h1 = k.window_1h.sum(now);
        let last = k.last_event_at
            .and_then(|t| now.duration_since(t).ok())
            .map(humanize_duration)
            .unwrap_or_else(|| "-".into());
        let label = if k.identity.label.len() > 27 {
            format!("{}…", &k.identity.label[..26])
        } else {
            k.identity.label.clone()
        };
        println!("  {:<28} {:<10} {:<10} {:>10} {:>10} {:>12}",
            label,
            k.identity.key_type,
            k.identity.provider,
            format!("{}·{}", h1.calls, humanize_tokens(h1.in_tokens + h1.out_tokens)),
            format!("{}·{}", today.calls, humanize_tokens(today.in_tokens + today.out_tokens)),
            last,
        );
    }

    println!();
    println!("  {}", "recent".dimmed());
    for ev in agg.recent_events(8) {
        let ts_secs = ev.finished_at_unix().unwrap_or(0);
        let ago = now.duration_since(UNIX_EPOCH + Duration::from_secs(ts_secs as u64))
            .map(humanize_duration).unwrap_or_else(|_| "-".into());
        let (i, o) = token_pair(ev);
        let label = best_label(ev);
        let label_trunc = if label.len() > 25 { format!("{}…", &label[..24]) } else { label.to_string() };
        println!("    {:>6}  {:<26} {:<10} ↑{} ↓{}",
            ago, label_trunc, ev.provider_code, humanize_tokens(i), humanize_tokens(o));
    }

    println!();
    println!("  {}", "(P1a snapshot — interactive TUI & live tail land in P1c/P1d)".dimmed());
}

fn humanize_tokens(n: u64) -> String {
    if n < 10_000 { return n.to_string(); }
    if n < 1_000_000 { return format!("{:.1}K", n as f64 / 1_000.0); }
    format!("{:.1}M", n as f64 / 1_000_000.0)
}

fn humanize_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 { return format!("{}s ago", s); }
    if s < 3600 { return format!("{}m ago", s / 60); }
    if s < 86400 { return format!("{}h ago", s / 3600); }
    format!("{}d ago", s / 86400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ev(ts: &str, sid: &str, kid: &str, model: &str, in_tok: i64, out_tok: i64) -> UsageEvent {
        UsageEvent {
            event_id: format!("e-{}", sid),
            event_time: ts.into(),
            session_id: Some(sid.into()),
            key_label: Some(kid.into()),
            completion: Some("complete".into()),
            virtual_key_id: kid.into(),
            provider_code: "anthropic".into(),
            route_source: "oauth".into(),
            model: model.into(),
            oauth_identity: Some(kid.into()),
            input_tokens: Some(in_tok),
            output_tokens: Some(out_tok),
            total_tokens: Some(in_tok + out_tok),
            request_status: "success".into(),
            http_status_code: Some(200),
            error_code: None,
        }
    }

    #[test]
    fn aggregator_collects_per_key_totals() {
        let mut agg = Aggregator::new(SystemTime::now() - LOOKBACK);
        agg.apply(&ev("2026-04-17T15:00:00Z", "s1", "k1", "claude", 10, 20));
        agg.apply(&ev("2026-04-17T15:05:00Z", "s2", "k1", "claude", 30, 40));
        agg.apply(&ev("2026-04-17T15:10:00Z", "s3", "k2", "claude", 100, 200));

        let k1 = &agg.by_key["k1"];
        assert_eq!(k1.lifetime.calls, 2);
        assert_eq!(k1.lifetime.in_tokens, 40);
        assert_eq!(k1.lifetime.out_tokens, 60);

        let k2 = &agg.by_key["k2"];
        assert_eq!(k2.lifetime.calls, 1);
        assert_eq!(k2.lifetime.in_tokens, 100);
    }

    #[test]
    fn sort_prioritizes_today_tokens_then_freshness() {
        let mut agg = Aggregator::new(SystemTime::now() - LOOKBACK);
        let now = now_ts();
        // `heavy` has lots of tokens; `fresh` was used more recently but with fewer tokens.
        agg.apply(&make_event(now - 3600, "heavy", 1000, 1000));
        agg.apply(&make_event(now - 60,   "fresh", 10,   10));
        let rows = agg.rows_sorted();
        assert_eq!(rows[0].identity.label, "heavy");
        assert_eq!(rows[1].identity.label, "fresh");
    }

    #[test]
    fn minute_buckets_roll_off_after_hour() {
        let mut bk = MinuteBuckets::new();
        let now = SystemTime::now();
        bk.add(now - Duration::from_secs(30 * 60), 100, 200);  // 30min ago
        bk.add(now - Duration::from_secs(90 * 60), 400, 800);  // 90min ago — past window
        let sum = bk.sum(now);
        assert_eq!(sum.calls, 1);
        assert_eq!(sum.in_tokens, 100);
        assert_eq!(sum.out_tokens, 200);
    }

    #[test]
    fn session_closes_after_gap() {
        let mut agg = Aggregator::new(SystemTime::now() - LOOKBACK);
        let now = now_ts();
        agg.apply(&make_event(now - 20*60, "k", 10, 10));  // 20min ago — starts session A
        agg.apply(&make_event(now - 19*60, "k", 20, 20));  // still session A
        agg.apply(&make_event(now -  1*60, "k", 30, 30));  // 18min gap > 15min → new session

        let k = &agg.by_key["k"];
        let s = k.session_latest.as_ref().expect("session present");
        assert_eq!(s.calls, 1);
        assert_eq!(s.in_tokens, 30);
    }

    #[test]
    fn load_aggregator_skips_events_older_than_window() {
        let tmp = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let recent_iso = iso_for(now_secs - 60);       // 1 min ago — kept
        let old_iso    = iso_for(now_secs - 48*3600);  // 2 days ago — dropped

        // Create one WAL file with both entries.
        let path = tmp.path().join("usage-20260417-00.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for (iso, kid) in [(recent_iso.as_str(), "recent"), (old_iso.as_str(), "old")] {
            let line = format!(
                r#"{{"wal_seq":1,"written_at":"{iso}","schema_version":1,"event_json":{{"event_id":"e","event_time":"{iso}","session_id":"s","key_label":"{kid}","virtual_key_id":"{kid}","provider_code":"anthropic","route_source":"oauth","model":"m","input_tokens":1,"output_tokens":1,"request_status":"success","http_status_code":200}}}}"#,
                iso = iso, kid = kid,
            );
            writeln!(f, "{}", line).unwrap();
        }

        let agg = load_aggregator(tmp.path(), now).unwrap();
        assert!(agg.by_key.contains_key("recent"), "recent event must be ingested");
        assert!(!agg.by_key.contains_key("old"),   "old event must be filtered out");
    }

    // -- helpers -----------------------------------------------------

    fn now_ts() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }

    fn make_event(ts_secs: u64, label: &str, i: i64, o: i64) -> UsageEvent {
        let iso = iso_for(ts_secs);
        UsageEvent {
            event_id: format!("e-{}", label),
            event_time: iso,
            session_id: None,
            key_label: Some(label.into()),
            completion: None,
            virtual_key_id: label.into(),
            provider_code: "anthropic".into(),
            route_source: "oauth".into(),
            model: "m".into(),
            oauth_identity: None,
            input_tokens: Some(i),
            output_tokens: Some(o),
            total_tokens: Some(i + o),
            request_status: "success".into(),
            http_status_code: Some(200),
            error_code: None,
        }
    }

    fn iso_for(secs: u64) -> String {
        // Minimal UTC ISO8601 formatter so tests don't depend on chrono.
        let total_days = (secs / 86400) as i64;
        let (y, m, d) = civil_from_days(total_days);
        let hms = secs % 86400;
        let h = hms / 3600;
        let mi = (hms % 3600) / 60;
        let s = hms % 60;
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
    }
}
