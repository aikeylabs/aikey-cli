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

/// Entrypoint for `aikey watch`.
///
/// Chooses between TUI and snapshot mode by looking at stdout's TTY state
/// AND the host terminal's alt-screen capability — see
/// `terminal_supports_alt_screen` for the heuristic. Override knobs:
///   * `AIKEY_WATCH_NO_TUI=1`     → force snapshot (debug / unattended runs)
///   * `AIKEY_WATCH_FORCE_TUI=1`  → bypass the broken-terminal check
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

    use std::io::IsTerminal;
    let force_snapshot = !std::io::stdout().is_terminal()
        || !terminal_supports_alt_screen();

    if force_snapshot {
        let now = SystemTime::now();
        let agg = load_aggregator(&wal_dir, now)?;
        render_snapshot(&agg, now);
        return Ok(());
    }

    run_tui(&wal_dir)
}

/// Decide whether the host terminal can be trusted with crossterm's
/// `EnterAlternateScreen` (i.e. the `\x1b[?1049h` sequence).
///
/// Why a heuristic rather than always-on:
///   On terminals that don't actually implement a separate alt-screen
///   buffer, `\x1b[?1049h` falls back to "scroll the main screen out of
///   the viewport, render the TUI, then scroll back on exit". That works
///   visually DURING the session but litters the user's scrollback with
///   blank lines after exit (one full viewport-height per session). The
///   user-visible bug surfaced 2026-04-27 on macOS Terminal.app — see the
///   thread that originated this fix.
///
/// Detection layers (highest precedence first):
///   1. Explicit env opt-out (`AIKEY_WATCH_NO_TUI=1`) — always wins.
///   2. Explicit env opt-in (`AIKEY_WATCH_FORCE_TUI=1`) — bypasses (3-6).
///   3. Hard-incapable: TERM is empty / dumb / unknown.
///   4. Multiplexer present (`TMUX`, `STY`, TERM starts with "screen") —
///      they implement alt-screen reliably regardless of the host terminal.
///   5. Known-broken: macOS Terminal.app builds < 433 (the cutoff used
///      by other TUIs that hit the same bug — 433 ships in macOS 12+).
///   6. Default → trust the terminal. Modern iTerm.app, WezTerm, Kitty,
///      vscode, Hyper, GNOME Terminal, Konsole all handle alt-screen
///      properly. False negatives can opt back in via env (#2).
fn terminal_supports_alt_screen() -> bool {
    // 1. Hard opt-out.
    if std::env::var("AIKEY_WATCH_NO_TUI").is_ok() {
        return false;
    }
    // 2. Hard opt-in.
    if std::env::var("AIKEY_WATCH_FORCE_TUI").is_ok() {
        return true;
    }

    // 3. TERM-based incapacity check.
    let term = std::env::var("TERM").unwrap_or_default();
    if term.is_empty() || term == "dumb" || term == "unknown" {
        return false;
    }

    // 4. Multiplexer pass-through. tmux / GNU screen wrap the host
    //    terminal and reliably handle alt-screen on their own.
    if std::env::var("TMUX").is_ok()
        || std::env::var("STY").is_ok()
        || term.starts_with("screen")
        || term.starts_with("tmux")
    {
        return true;
    }

    // 5. Known-broken Apple Terminal.app builds.
    //    TERM_PROGRAM_VERSION is a build number string like "433" / "447".
    //    Build 433 corresponds to macOS Monterey (12.x); earlier builds
    //    on Big Sur (11.x) and below have the alt-screen scrollback bug.
    //    Best-effort: if version parse fails, treat as broken (safer).
    if std::env::var("TERM_PROGRAM").as_deref() == Ok("Apple_Terminal") {
        let build: u32 = std::env::var("TERM_PROGRAM_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        return build >= 433;
    }

    // 6. Trust everything else.
    true
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
}

impl Aggregator {
    fn new() -> Self {
        Self { by_key: HashMap::new(), last_event_at: None }
    }

    /// Fold one event into the aggregator.  Idempotency is the caller's
    /// responsibility (replaying the same event twice would double-count).
    /// Events whose timestamp can't be parsed are skipped — preserving the
    /// "JSONL is forgiving" property shared with `usage_wal`.
    pub(crate) fn apply(&mut self, ev: &UsageEvent) {
        // Why: proxy writes per-startup canary probes (virtual_key_id="__canary__",
        // route_source="canary") as health signals for the collector pipeline.
        // They carry a fake token count of 1 and shouldn't pollute the user-
        // facing dashboard. Drop at the aggregator entry so every cold start
        // and live tail path filters them consistently.
        if is_canary_event(ev) {
            return;
        }

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

/// Proxy writes synthetic probe events at startup and on a timer to exercise
/// the collector pipeline end-to-end. Recognized by `virtual_key_id="__canary__"`
/// or `route_source="canary"` (either is enough — older proxy builds only set
/// one). These are observability signals, not user usage, so the dashboard
/// filters them out.
fn is_canary_event(ev: &UsageEvent) -> bool {
    ev.virtual_key_id == "__canary__" || ev.route_source == "canary"
}

#[derive(Debug, Clone)]
pub(crate) struct KeyAggregate {
    pub(crate) identity: KeyIdentity,
    pub(crate) lifetime: Counters,
    pub(crate) window_1h: MinuteBuckets,
    pub(crate) today: DayCounters,
    pub(crate) session_latest: Option<Session>,
    pub(crate) last_event_at: Option<SystemTime>,
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

    let mut agg = Aggregator::new();
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
    // Rust std doesn't expose local timezone offset portably. Shell out
    // to the platform API to read the seconds east of UTC for "now".
    //
    // Stage 1.5 windows-compat: previous Windows fallback returned 0
    // (UTC) which made `aikey watch` show wrong-day boundaries for users
    // east/west of UTC. Now we use `GetTimeZoneInformation` so the watch
    // TUI shows local-day rollovers correctly on Windows too.
    #[cfg(unix)]
    unsafe {
        let t: libc::time_t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64
    }
    #[cfg(windows)]
    {
        use std::mem::MaybeUninit;
        use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
        // Win32 stable values; not re-exported by windows-sys 0.52 at the
        // Time module path so we inline them here. See Microsoft docs:
        // https://learn.microsoft.com/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformation
        const TIME_ZONE_ID_STANDARD: u32 = 1;
        const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

        let mut tz = MaybeUninit::<TIME_ZONE_INFORMATION>::zeroed();
        // Why we negate-and-multiply-by-60: Windows reports `Bias` as
        // minutes such that `UTC = local + bias` — so seconds east of UTC
        // = `-bias_minutes * 60`. DaylightBias is added on top when DST
        // is active. StandardBias mirrors the GMT side and is typically 0
        // for most zones; we still sum both so non-zero entries (rare,
        // e.g. some Australian zones) are honoured.
        let id = unsafe { GetTimeZoneInformation(tz.as_mut_ptr()) };
        let tz = unsafe { tz.assume_init() };
        let extra = match id {
            TIME_ZONE_ID_DAYLIGHT => tz.DaylightBias as i64,
            TIME_ZONE_ID_STANDARD => tz.StandardBias as i64,
            // TIME_ZONE_ID_UNKNOWN (0) or TIME_ZONE_ID_INVALID (u32::MAX)
            // → fall back to bias only; better than 0 if the host has any
            // tz config at all.
            _ => 0,
        };
        let offset_minutes = -(tz.Bias as i64 + extra);
        offset_minutes * 60
    }
    #[cfg(not(any(unix, windows)))]
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
    // Title / meta / keys — same three-tier structure as the TUI header so
    // the two modes feel visually related.
    println!("  {} {} {}",
        "aikey watch".bold().truecolor(100, 210, 200),
        "—".truecolor(130, 130, 130),
        format!("{} keys active in last 24h", rows.len()).truecolor(130, 130, 130));
    println!();

    if rows.is_empty() {
        println!("  {}", "No activity in the last 24 hours.".dimmed());
        println!("  {}", "Make a request through aikey-proxy, then re-run.".dimmed());
        return;
    }

    // Snapshot has no interactive sort state; default to TodayTokens so the
    // header shows a reasonable arrow.
    let snapshot_sort = SortKey::TodayTokens;
    println!("  {}", table_header_line(snapshot_sort));
    println!("  {}", table_divider());

    for k in &rows {
        println!("  {}", table_data_line(k, now, snapshot_sort));
    }

    println!();
    // Heading brightness matches TOP of the recent-strip fade (see
    // `recent_fade`) so the block reads as one visual group that starts
    // dimmer than the main table above.
    println!("  {}", "RECENT".truecolor(175, 175, 175));
    let recent: Vec<_> = agg.recent_events(8).into_iter().collect();
    let n = recent.len();
    for (idx, ev) in recent.iter().enumerate() {
        let ts_secs = ev.finished_at_unix().unwrap_or(0);
        let ago = now.duration_since(UNIX_EPOCH + Duration::from_secs(ts_secs as u64))
            .map(humanize_duration).unwrap_or_else(|_| "-".into());
        let (i, o) = token_pair(ev);
        let label = best_label(ev);
        let label_trunc = shorten_str(label, 25);
        println!("{}", recent_fade(&recent_row(&ago, &label_trunc, ev.provider_code.as_str(), i as u64, o as u64), idx, n));
    }

    println!();
    // Two-tier hint: distinguish "auto-fallback because we detected a
    // known-broken alt-screen terminal" from the older "you piped me /
    // I'm not on a TTY" case. Lets users on a buggy emulator know an
    // override exists, instead of accepting snapshot mode as the only
    // option.
    use std::io::IsTerminal;
    let is_tty = std::io::stdout().is_terminal();
    let hint = if !is_tty {
        "(snapshot mode — run in a terminal for interactive TUI)".to_string()
    } else if std::env::var("AIKEY_WATCH_NO_TUI").is_ok() {
        "(snapshot mode — AIKEY_WATCH_NO_TUI=1 set; unset to enable TUI)".to_string()
    } else {
        // Reached only when terminal_supports_alt_screen() returned false
        // for capability reasons (TERM=dumb / old Apple_Terminal / etc.).
        "(snapshot mode — terminal doesn't support alt-screen reliably; \
         set AIKEY_WATCH_FORCE_TUI=1 to override)".to_string()
    };
    println!("  {}", hint.dimmed());
}

/// Build one aligned row for the RECENT strip. Widths chosen to fit the
/// usual ranges without leaving huge gaps:
///   ago  (7)  — covers "XXh ago", "XXm ago", "XXd ago"; rare overflow OK
///   label (26) — already truncated by caller to 25+ellipsis, pad to 26
///   provider (9) — "anthropic" is 9, "moonshot" 8, "openai" 6 → right fits
///   tokens (13) — "↑999.9K ↓999K" fits; enormous outputs overflow but
///                 consciously unbounded per UX note "超出太大不管"
/// Using a helper keeps snapshot + TUI renderers in lockstep.
fn recent_row(ago: &str, label: &str, provider: &str, in_tok: u64, out_tok: u64) -> String {
    let tokens = format!("↑{} ↓{}", humanize_tokens(in_tok), humanize_tokens(out_tok));
    format!("    {:>7}  {:<26}  {:<9}  {:<13}", ago, label, provider, tokens)
}

fn humanize_tokens(n: u64) -> String {
    if n < 10_000 { return n.to_string(); }
    if n < 1_000_000 { return format!("{:.1}K", n as f64 / 1_000.0); }
    format!("{:.1}M", n as f64 / 1_000_000.0)
}

/// Apply a brightness-fade to a recent-strip row based on its index within
/// the list. Newest row gets the brightest grey; older rows fade toward a
/// near-invisible grey so the eye's focus tracks chronological recency.
///
/// Why truecolor rather than the palette (bold/normal/dimmed): those are
/// only 3 tiers, which forces ties between rows #2/#3/#4 in a 6-row strip.
/// Truecolor gives a smooth gradient that's still legible under both dark
/// and light terminal themes — the brightness range (225 → 90) stays inside
/// the middle band rather than hitting pure white or pure black. Terminals
/// without 24-bit support degrade silently to unstyled text.
///
/// Curve shape: **front-loaded** — we apply sqrt(t) to the normalised index
/// before interpolating, so the top 2-3 rows show large brightness deltas
/// and older rows settle toward the background quickly. A linear ramp made
/// the middle rows too close to the newest one to read at a glance.
/// Exponent `0.5` (sqrt) is the knob; lower → even steeper front drop.
fn recent_fade(line: &str, index: usize, total: usize) -> String {
    use colored::Colorize;
    // TOP sits at 175 (not 225) so even the newest row is slightly dimmer than
    // primary text — the recent strip is ancillary, so it shouldn't compete
    // for the eye with the main table above it.
    const TOP: f32 = 175.0; // newest
    const BOT: f32 = 90.0;  // oldest
    // 0.2 produces ~100 drop between row 0 and row 1 (225 → ~125) and then
    // settles to small single-digit drops for the tail, which is the "sharp
    // focus on newest" feel we want.
    const CURVE: f32 = 0.2;
    let t = if total <= 1 { 0.0 } else { index as f32 / (total - 1) as f32 };
    let shaped = t.powf(CURVE);
    let v = (TOP + (BOT - TOP) * shaped).round() as u8;
    line.truecolor(v, v, v).to_string()
}

fn humanize_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 { return format!("{}s ago", s); }
    if s < 3600 { return format!("{}m ago", s / 60); }
    if s < 86400 { return format!("{}h ago", s / 3600); }
    format!("{}d ago", s / 86400)
}

// ---------------------------------------------------------------------------
// TUI loop (P1c + P1d).
// ---------------------------------------------------------------------------
//
// Event loop is manual polling rather than `select!`: crossterm and notify
// both expose channel-ish APIs but integrating them via futures would pull
// in tokio which we deliberately don't depend on elsewhere.  Each iteration:
//   1. Drain any WAL-file changes queued by the notify watcher (applies
//      newly-appended events to the aggregator).
//   2. Block on crossterm::event::poll for up to 250ms so q/Esc/etc.
//      respond quickly; timeout = refresh tick (≤ 10s).
//   3. Redraw if dirty OR the tick timer elapsed (to refresh relative
//      times like "3m ago" even when no new events arrived).
//
// Exit paths uniformly clean up: disable raw mode, leave alt screen,
// show cursor — failures inside the loop still run the shutdown arm.

/// Re-render cadence when no events have arrived — keeps relative times
/// ("3m ago") fresh without burning CPU when idle.
const TICK_INTERVAL: Duration = Duration::from_secs(5);
/// crossterm poll timeout — short enough that keypresses feel instant,
/// long enough that the loop doesn't spin.
const POLL_TIMEOUT: Duration = Duration::from_millis(250);
/// Why a separate polling ticker in addition to the notify watcher:
/// `notify::recommended_watcher` on macOS uses FSEvents, which is famously
/// unreliable for in-place file appends — the proxy writes to today's
/// `usage-YYYYMMDD-HH.jsonl` and FSEvents may buffer the change for 30+
/// seconds (or miss it entirely until a directory-level op fires). A
/// 10-second poll fallback guarantees the dashboard reflects new activity
/// within a user-visible window even when notify lies.
const DRAIN_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    TodayTokens,
    HourTokens,
    SessionTokens,
    LastCalled,
}

impl SortKey {
    fn label(self) -> &'static str {
        match self {
            SortKey::TodayTokens => "today_tokens",
            SortKey::HourTokens => "1h_tokens",
            SortKey::SessionTokens => "session_tokens",
            SortKey::LastCalled => "last_called",
        }
    }
    fn cycle(self) -> Self {
        // Why only 4 variants in the cycle: every sort must highlight a
        // visible column so the user has explicit feedback about the current
        // mode. LifetimeCalls was removed when it landed in an "invisible"
        // state — it had no column to highlight and the header gave zero
        // cues beyond the tiny footer string.
        match self {
            SortKey::TodayTokens => SortKey::HourTokens,
            SortKey::HourTokens => SortKey::SessionTokens,
            SortKey::SessionTokens => SortKey::LastCalled,
            SortKey::LastCalled => SortKey::TodayTokens,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Compact,
    Expanded,
}

struct TuiState {
    agg: Aggregator,
    sort: SortKey,
    view: ViewMode,
    last_render: SystemTime,
    /// Last time we walked the WAL directory regardless of notify. Driven
    /// by DRAIN_INTERVAL to guarantee a bounded lag on macOS FSEvents.
    last_drain_at: SystemTime,
    dirty: bool,
    proxy_pid_cache: Option<u32>,
    proxy_alive_cache: bool,
    proxy_checked_at: SystemTime,
    last_gc_at: SystemTime,
}

impl TuiState {
    fn new(agg: Aggregator) -> Self {
        Self {
            agg,
            sort: SortKey::TodayTokens,
            view: ViewMode::Compact,
            last_render: UNIX_EPOCH,
            last_drain_at: UNIX_EPOCH,
            dirty: true,
            proxy_pid_cache: None,
            proxy_alive_cache: false,
            proxy_checked_at: UNIX_EPOCH,
            last_gc_at: UNIX_EPOCH,
        }
    }

    fn sorted_rows(&self, now: SystemTime) -> Vec<&KeyAggregate> {
        let mut rows: Vec<&KeyAggregate> = self.agg.by_key.values().collect();
        let sort = self.sort;
        rows.sort_by(|a, b| {
            let (ka, kb) = (sort_value(a, sort, now), sort_value(b, sort, now));
            kb.cmp(&ka).then_with(|| b.last_event_at.cmp(&a.last_event_at))
        });
        rows
    }

    fn refresh_proxy_alive(&mut self, now: SystemTime) {
        // Re-check at most every 2s to avoid hammering the filesystem /
        // kill syscall on every redraw tick.
        if now.duration_since(self.proxy_checked_at).unwrap_or(Duration::ZERO) < Duration::from_secs(2) {
            return;
        }
        self.proxy_checked_at = now;
        let (pid, alive) = probe_proxy();
        self.proxy_pid_cache = pid;
        self.proxy_alive_cache = alive;
    }

    fn run_gc(&mut self, now: SystemTime) {
        if now.duration_since(self.last_gc_at).unwrap_or(Duration::ZERO) < Duration::from_secs(60) {
            return;
        }
        self.last_gc_at = now;
        let cutoff = now.checked_sub(LOOKBACK).unwrap_or(now);
        self.agg.by_key.retain(|_, v|
            v.last_event_at.map(|t| t >= cutoff).unwrap_or(false));
    }
}

fn sort_value(k: &KeyAggregate, sort: SortKey, now: SystemTime) -> u64 {
    match sort {
        SortKey::TodayTokens => k.today.in_tokens + k.today.out_tokens,
        SortKey::HourTokens => {
            let c = k.window_1h.sum(now);
            c.in_tokens + c.out_tokens
        }
        SortKey::SessionTokens => k.session_latest.as_ref()
            .map(|s| s.in_tokens + s.out_tokens).unwrap_or(0),
        SortKey::LastCalled => k.last_event_at
            .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()).unwrap_or(0),
    }
}

fn run_tui(wal_dir: &Path) -> io::Result<()> {
    use crossterm::{
        cursor::{Hide, Show},
        event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use std::io::Write;

    // Cold-start aggregate.  Establish file offsets AFTER loading so that
    // the notify-driven tail only picks up rows appended during the TUI
    // lifetime — otherwise we'd double-count the cold-start rows.
    let now = SystemTime::now();
    let agg = load_aggregator(wal_dir, now)?;
    let mut file_tails = snapshot_file_tails(wal_dir)?;

    // Watch for WAL dir mutations.  We don't care about precise event
    // types — any touch triggers a drain pass that handles new files,
    // appends, and rotations uniformly.
    let (watch_tx, watch_rx) = std::sync::mpsc::channel::<()>();
    // Hold the watcher guard for the duration of the TUI session.
    let _watcher = spawn_wal_watcher(wal_dir, watch_tx)?;

    let mut state = TuiState::new(agg);

    // Terminal setup — teardown MUST run on every exit path, so wrap the
    // body in a closure and restore afterwards in a defer-like sequence.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, Hide)?;

    let tui_result = (|| -> io::Result<()> {
        loop {
            let now = SystemTime::now();
            state.refresh_proxy_alive(now);
            state.run_gc(now);

            if state.dirty || now.duration_since(state.last_render).unwrap_or(Duration::ZERO) >= TICK_INTERVAL {
                render_tui(&mut stdout, &state, now)?;
                state.last_render = now;
                state.dirty = false;
            }

            // Drain triggers: notify signal OR elapsed polling interval.
            // We OR the two so macOS FSEvents misses don't leave the user
            // staring at stale data — the periodic poll backstops it.
            let mut had_notify = false;
            while watch_rx.try_recv().is_ok() { had_notify = true; }
            let poll_due = now.duration_since(state.last_drain_at).unwrap_or(Duration::ZERO) >= DRAIN_INTERVAL;
            if had_notify || poll_due {
                let before = state.agg.last_event_at;
                drain_wal_changes(wal_dir, &mut file_tails, &mut state.agg)?;
                state.last_drain_at = now;
                // Only mark dirty when the drain actually advanced state;
                // an empty poll pass shouldn't force a redraw.
                if state.agg.last_event_at != before {
                    state.dirty = true;
                }
            }

            if event::poll(POLL_TIMEOUT)? {
                match event::read()? {
                    Event::Key(KeyEvent { code, modifiers, .. }) => {
                        match (code, modifiers) {
                            (KeyCode::Char('q') | KeyCode::Esc, _) => break,
                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                            (KeyCode::Char('r'), _) => {
                                // Manual refresh: rebuild aggregator from scratch.
                                // Keeps sort / view toggles but ditches stale data
                                // if the user suspects the live tail fell behind.
                                let fresh = load_aggregator(wal_dir, SystemTime::now())?;
                                state.agg = fresh;
                                file_tails = snapshot_file_tails(wal_dir)?;
                                state.dirty = true;
                            }
                            (KeyCode::Char('s'), _) => {
                                state.sort = state.sort.cycle();
                                state.dirty = true;
                            }
                            (KeyCode::Char('v'), _) => {
                                state.view = match state.view {
                                    ViewMode::Compact => ViewMode::Expanded,
                                    ViewMode::Expanded => ViewMode::Compact,
                                };
                                state.dirty = true;
                            }
                            _ => {}
                        }
                    }
                    Event::Resize(_, _) => state.dirty = true,
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    // Teardown (always runs, even on error from the body).
    let _ = execute!(stdout, LeaveAlternateScreen, Show);
    let _ = disable_raw_mode();
    let _ = stdout.flush();

    tui_result
}

// ---------------------------------------------------------------------------
// File tailing — follow usage-*.jsonl appends without re-reading the file.
// ---------------------------------------------------------------------------

struct FileTail {
    path: PathBuf,
    offset: u64,
    leftover: Vec<u8>,  // bytes after the last '\n' from a prior read
}

/// Record current sizes of every WAL file so that subsequent tail passes
/// only surface genuinely new appends.  Called once at cold-start (after
/// `load_aggregator` ingested the historical data) and again on `r`.
fn snapshot_file_tails(dir: &Path) -> io::Result<HashMap<PathBuf, FileTail>> {
    let mut map = HashMap::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.starts_with("usage-") || !name.ends_with(".jsonl") { continue; }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        map.insert(path.clone(), FileTail { path, offset: size, leftover: Vec::new() });
    }
    Ok(map)
}

/// Open each WAL file, read from the stored offset to EOF, parse newly
/// completed lines, and feed them to the aggregator.  New files that
/// appeared since the last scan (e.g. hour rollover) start from offset 0.
fn drain_wal_changes(
    dir: &Path,
    tails: &mut HashMap<PathBuf, FileTail>,
    agg: &mut Aggregator,
) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    // Discover new files first.
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.starts_with("usage-") || !name.ends_with(".jsonl") { continue; }
        tails.entry(path.clone()).or_insert_with(|| FileTail {
            path, offset: 0, leftover: Vec::new(),
        });
    }

    for tail in tails.values_mut() {
        let mut file = match std::fs::File::open(&tail.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let size = file.metadata()?.len();
        if size < tail.offset {
            // Truncation / rotation: restart from 0.
            tail.offset = 0;
            tail.leftover.clear();
        }
        if size == tail.offset { continue; }

        file.seek(SeekFrom::Start(tail.offset))?;
        let mut buf = Vec::with_capacity((size - tail.offset) as usize);
        file.read_to_end(&mut buf)?;
        tail.offset = size;

        // Prepend the previous iteration's remainder so a line that
        // straddled a read boundary can still be parsed as a whole.
        let mut combined = std::mem::take(&mut tail.leftover);
        combined.extend_from_slice(&buf);

        let mut start = 0;
        for i in 0..combined.len() {
            if combined[i] == b'\n' {
                let line = &combined[start..i];
                start = i + 1;
                if line.is_empty() { continue; }
                if let Ok(entry) = serde_json::from_slice::<WalEnvelope>(line) {
                    agg.apply(&entry.event_json);
                }
            }
        }
        if start < combined.len() {
            tail.leftover = combined[start..].to_vec();
        }
    }
    Ok(())
}

/// Spawn a `notify` watcher that sends a unit-value signal whenever the
/// WAL directory changes.  We deliberately don't forward the event itself
/// — the TUI's drain-pass is idempotent and handles "coalesced burst"
/// better than we could by inspecting individual events.
fn spawn_wal_watcher(
    dir: &Path,
    tx: std::sync::mpsc::Sender<()>,
) -> io::Result<Box<dyn std::any::Any + Send>> {
    use notify::{RecursiveMode, Watcher};

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            // Channel send failure means the TUI loop has exited; we can
            // safely drop the event rather than propagate a panic.
            let _ = tx.send(());
        }
    })
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("notify init failed: {}", e)))?;
    watcher
        .watch(dir, RecursiveMode::NonRecursive)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("notify watch failed: {}", e)))?;
    // Returning a trait object keeps the watcher alive as long as the caller
    // holds it without exposing the concrete type across module boundaries.
    Ok(Box::new(watcher))
}

// ---------------------------------------------------------------------------
// Proxy liveness probe.
// ---------------------------------------------------------------------------

/// Returns (pid, alive).  alive=true when a pid file exists and the
/// referenced process is still running (signal 0 sanity check).  Missing
/// file / dead process both produce alive=false; the TUI renders the
/// difference visually.
fn probe_proxy() -> (Option<u32>, bool) {
    let Some(home) = std::env::var_os("HOME") else { return (None, false); };
    let pid_path = PathBuf::from(home).join(".aikey").join("run").join("proxy.pid");
    let Ok(content) = std::fs::read_to_string(&pid_path) else { return (None, false); };
    let pid: u32 = match content.trim().parse() {
        Ok(n) => n,
        Err(_) => return (None, false),
    };

    // Stage 1.5 windows-compat: route through the cross-platform
    // `proxy_proc::process_alive` (Unix `kill(pid, 0)` + Windows
    // `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`) instead of a local
    // libc::kill call. Single source of truth for "is this PID still ours";
    // Windows probe is no longer deferred.
    let alive = crate::proxy_proc::process_alive(pid);

    (Some(pid), alive)
}

// ---------------------------------------------------------------------------
// TUI rendering.
// ---------------------------------------------------------------------------

fn render_tui(
    stdout: &mut io::Stdout,
    state: &TuiState,
    now: SystemTime,
) -> io::Result<()> {
    use colored::Colorize;
    use crossterm::{
        cursor::MoveTo,
        execute,
        terminal::{Clear, ClearType},
    };
    use std::io::Write;

    execute!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;

    let rows = state.sorted_rows(now);

    render_header(stdout, state, rows.len(), now)?;
    writeln!(stdout, "\r")?;

    match state.view {
        ViewMode::Compact => render_compact(stdout, &rows, now, state.sort)?,
        ViewMode::Expanded => render_expanded(stdout, &rows, now)?,
    }

    writeln!(stdout, "\r")?;
    // Match snapshot renderer's heading brightness — see recent_fade TOP.
    writeln!(stdout, "  {}\r", "RECENT".truecolor(175, 175, 175))?;
    let recent: Vec<_> = state.agg.recent_events(6).into_iter().collect();
    let n = recent.len();
    for (idx, ev) in recent.iter().enumerate() {
        let ts_secs = ev.finished_at_unix().unwrap_or(0);
        let ago = now.duration_since(UNIX_EPOCH + Duration::from_secs(ts_secs as u64))
            .map(humanize_duration).unwrap_or_else(|_| "-".into());
        let (i, o) = token_pair(ev);
        let label = best_label(ev);
        let label_trunc = shorten_str(label, 25);
        let line = recent_row(&ago, &label_trunc, ev.provider_code.as_str(), i, o);
        writeln!(stdout, "{}\r", recent_fade(&line, idx, n))?;
    }

    writeln!(stdout, "\r")?;
    // Footer is key-binding help + state indicators — metadata, not content.
    // Uses a flat dark-grey truecolor so it sits below the recent-strip's
    // dimmest row (~90) and reads as chrome. A single colour (not a fade)
    // keeps the two state fields from appearing to "fall off" the line.
    let footer = format!(
        "  [q quit · r refresh · s sort · v view · Esc exit]    sort={} view={:?}",
        state.sort.label(), state.view
    );
    writeln!(stdout, "{}\r", footer.truecolor(85, 85, 85))?;
    stdout.flush()?;
    Ok(())
}

fn render_header(
    stdout: &mut io::Stdout,
    state: &TuiState,
    row_count: usize,
    now: SystemTime,
) -> io::Result<()> {
    use colored::Colorize;
    use std::io::Write;

    // Why split into three visual tiers:
    //   * title  — product name, bold + cyan accent so the user always knows
    //     which tool they're looking at (important in a tab soup)
    //   * meta   — key count / separator, dim grey (supporting info)
    //   * proxy  — status bullet acts as a traffic light: green ● = healthy,
    //     red ● = broken, amber ● = uncertain (no pid file but some activity)
    let title = "aikey watch".bold().truecolor(100, 210, 200);
    let meta_dim = |s: String| s.truecolor(130, 130, 130);

    let (proxy_bullet, proxy_text) = match (state.proxy_pid_cache, state.proxy_alive_cache) {
        (Some(pid), true) => (
            "●".truecolor(95, 200, 120).to_string(),
            format!("proxy: ok (pid {})", pid),
        ),
        (Some(pid), false) => (
            "●".truecolor(225, 95, 95).to_string(),
            format!("proxy: DOWN (pid {} not responding)", pid),
        ),
        (None, _) => {
            let text = match state.agg.last_event_at {
                Some(t) => {
                    let ago = now.duration_since(t).map(humanize_duration).unwrap_or_else(|_| "-".into());
                    format!("proxy: pid unknown · last event {}", ago)
                }
                None => "proxy: no activity recorded".to_string(),
            };
            ("●".truecolor(210, 180, 90).to_string(), text)
        }
    };

    writeln!(
        stdout,
        "  {title} {dash} {keys} {dot} {bullet} {status}\r",
        title = title,
        dash = meta_dim("—".into()),
        keys = meta_dim(format!("{} keys", row_count)),
        dot = meta_dim("·".into()),
        bullet = proxy_bullet,
        status = meta_dim(proxy_text),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Column widths — declared here so header and data rows never drift.
// Totals: 30+10+10+8+8+18 + 5*space = 89 chars (fits 96-col terminals with slack).
// Why drop LAST: SESSION already carries freshness ("active 8m" / "2h ago"),
// so LAST was just repeating "X ago" and causing collision when SESSION content
// spilled into its cell.
// ---------------------------------------------------------------------------
const COL_KEY: usize = 30;
const COL_TYPE: usize = 10;
const COL_PROVIDER: usize = 10;
const COL_TOKENS: usize = 8; // 1H / TODAY
const COL_SESSION: usize = 20;

fn render_compact(
    stdout: &mut io::Stdout,
    rows: &[&KeyAggregate],
    now: SystemTime,
    sort: SortKey,
) -> io::Result<()> {
    use std::io::Write;

    writeln!(stdout, "  {}\r", table_header_line(sort))?;
    writeln!(stdout, "  {}\r", table_divider())?;
    if rows.is_empty() {
        writeln!(stdout, "  (no activity in the last 24 hours — make a request and come back)\r")?;
        return Ok(());
    }
    for k in rows {
        writeln!(stdout, "  {}\r", table_data_line(k, now, sort))?;
    }
    Ok(())
}

/// Shared column-header line with sort-aware styling. Used by both the TUI
/// compact view and the snapshot renderer so headings always match.
///
/// Sort arrow is `↓` (every SortKey sorts desc). The active column gets a
/// brighter + bold style to anchor the arrow visually.
///
/// Why we pad *before* colouring (and not inside the `head` helper like it
/// used to): ANSI escape codes count as visible width to Rust's `{:<N}`
/// formatter, so a pre-coloured header would appear "already full width"
/// and wouldn't get any padding — collapsing the header into a tight bunch
/// while the (correctly padded, then coloured) data rows beneath it still
/// ran at the declared widths. Padding raw text first keeps both lines
/// aligned regardless of colour.
fn table_header_line(sort: SortKey) -> String {
    use colored::Colorize;
    let paint = |padded: String, active: bool| -> String {
        if active { padded.truecolor(210, 210, 210).bold().to_string() }
        else { padded.truecolor(150, 150, 150).to_string() }
    };

    // SESSION column is active for two different SortKey variants:
    //   * SessionTokens → ordered by token volume in the current session
    //   * LastCalled    → ordered by recency of last request
    // Distinguish with a suffix so the user always knows which axis the
    // arrow refers to. Other columns only serve one SortKey.
    let sess_active = sort == SortKey::SessionTokens || sort == SortKey::LastCalled;
    let sess_label = match sort {
        SortKey::SessionTokens => "SESSION ↓".to_string(),
        SortKey::LastCalled    => "SESSION ↓ recency".to_string(),
        _                      => "SESSION".to_string(),
    };

    let h1_active = sort == SortKey::HourTokens;
    let today_active = sort == SortKey::TodayTokens;
    let h1_label    = if h1_active    { "1H ↓".to_string() }    else { "1H".to_string() };
    let today_label = if today_active { "TODAY ↓".to_string() } else { "TODAY".to_string() };

    let key_h   = paint(format!("{:<w$}", "KEY",      w = COL_KEY),      false);
    let type_h  = paint(format!("{:<w$}", "TYPE",     w = COL_TYPE),     false);
    let prov_h  = paint(format!("{:<w$}", "PROTOCOL", w = COL_PROVIDER), false);
    let h1_h    = paint(format!("{:>w$}", h1_label,    w = COL_TOKENS),  h1_active);
    let today_h = paint(format!("{:>w$}", today_label, w = COL_TOKENS),  today_active);
    let sess_h  = paint(format!("{:<w$}", sess_label,  w = COL_SESSION), sess_active);
    format!("{key_h} {type_h} {prov_h} {h1_h} {today_h}  {sess_h}")
}

/// Divider rule in dark grey so the table edges guide the eye without
/// cutting it. Matches footer brightness for a single coherent "chrome" tier.
fn table_divider() -> String {
    use colored::Colorize;
    let rule_len = COL_KEY + COL_TYPE + COL_PROVIDER + COL_TOKENS + COL_TOKENS + COL_SESSION + 5;
    "─".repeat(rule_len).truecolor(85, 85, 85).to_string()
}

/// One data row with full styling applied: KEY primary, TYPE/PROVIDER dim,
/// token columns normal (bold+bright if the column is the active sort),
/// SESSION decorated with a live-activity bullet when applicable.
///
/// Padding is applied before colour to keep column alignment stable —
/// colored strings count ANSI escape bytes as visible width otherwise.
fn table_data_line(k: &KeyAggregate, now: SystemTime, sort: SortKey) -> String {
    use colored::Colorize;

    let h1_tokens = k.window_1h.sum(now);
    let today_tokens = k.today.in_tokens + k.today.out_tokens;
    let hour_total = h1_tokens.in_tokens + h1_tokens.out_tokens;
    let sess_str = session_cell(k.session_latest.as_ref(), now);
    let label = shorten_str(&k.identity.label, COL_KEY - 1);

    let key_cell = format!("{:<w$}", label, w = COL_KEY);
    let type_cell = format!("{:<w$}", k.identity.key_type, w = COL_TYPE).truecolor(140, 140, 140);
    let prov_cell = format!("{:<w$}", k.identity.provider, w = COL_PROVIDER).truecolor(140, 140, 140);

    let h1_raw = format!("{:>w$}", humanize_tokens(hour_total), w = COL_TOKENS);
    let h1_cell = if sort == SortKey::HourTokens {
        h1_raw.bold().truecolor(230, 230, 230).to_string()
    } else {
        h1_raw.truecolor(200, 200, 200).to_string()
    };
    let today_raw = format!("{:>w$}", humanize_tokens(today_tokens), w = COL_TOKENS);
    let today_cell = if sort == SortKey::TodayTokens {
        today_raw.bold().truecolor(230, 230, 230).to_string()
    } else {
        today_raw.truecolor(200, 200, 200).to_string()
    };

    // SESSION cell: don't wrap in bold/brighter colour when sort targets it
    // — `decorate_session` already adds a green bullet for active sessions,
    // and double-wrapping here fights with ANSI reset semantics. The header
    // suffix ("SESSION ↓" / "SESSION ↓ recency") already communicates sort.
    let sess_decorated = decorate_session(&sess_str);
    let sess_cell = format!("{:<w$}", sess_decorated, w = COL_SESSION);

    format!("{key_cell} {type_cell} {prov_cell} {h1_cell} {today_cell}  {sess_cell}")
}

/// Prepend a live-activity bullet when the session cell says "... · active".
/// The bullet reads as a pulse indicator without taking a whole column.
/// Non-active sessions pass through unchanged.
fn decorate_session(cell: &str) -> String {
    use colored::Colorize;
    if cell.contains("· active") {
        format!("{} {}", "●".truecolor(95, 200, 120), cell)
    } else {
        cell.to_string()
    }
}

/// Format the SESSION cell: `<tokens> · active <duration>` when a session is
/// still live, `<tokens> · <age> ago` when it has closed. A missing session
/// prints `-` rather than the ambiguous empty string the old format produced.
fn session_cell(sess: Option<&Session>, now: SystemTime) -> String {
    let Some(s) = sess else { return "-".to_string(); };
    let tokens = humanize_tokens(s.in_tokens + s.out_tokens);
    if s.is_active(now) {
        let elapsed = now.duration_since(s.started_at).unwrap_or(Duration::ZERO);
        format!("{} · active {}", tokens, humanize_duration_short(elapsed))
    } else {
        let ago = now.duration_since(s.last_event_at).unwrap_or(Duration::ZERO);
        format!("{} · {}", tokens, humanize_duration(ago))
    }
}

/// UTF-8 aware truncation with trailing ellipsis when the label exceeds budget.
/// Why not `&s[..n]`: the old code sliced by byte index and panicked on any
/// multi-byte char (e.g. Chinese aliases, ASCII trumping was only coincidental).
fn shorten_str(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max { return s.to_string(); }
    let keep: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{keep}…")
}

fn render_expanded(
    stdout: &mut io::Stdout,
    rows: &[&KeyAggregate],
    now: SystemTime,
) -> io::Result<()> {
    use std::io::Write;
    if rows.is_empty() {
        writeln!(stdout, "  (no activity in the last 24 hours)\r")?;
        return Ok(());
    }
    for k in rows {
        let h1 = k.window_1h.sum(now);
        let today = &k.today;
        writeln!(stdout, "  {}   {} · {}\r",
            k.identity.label, k.identity.key_type, k.identity.provider)?;
        writeln!(stdout, "    ever:    {:>5} calls  ↑{} ↓{}\r",
            k.lifetime.calls,
            humanize_tokens(k.lifetime.in_tokens),
            humanize_tokens(k.lifetime.out_tokens))?;
        writeln!(stdout, "    1h:      {:>5} calls  ↑{} ↓{}\r",
            h1.calls,
            humanize_tokens(h1.in_tokens),
            humanize_tokens(h1.out_tokens))?;
        writeln!(stdout, "    today:   {:>5} calls  ↑{} ↓{}\r",
            today.calls,
            humanize_tokens(today.in_tokens),
            humanize_tokens(today.out_tokens))?;
        if let Some(s) = k.session_latest.as_ref() {
            let state = if s.is_active(now) { "active" } else { "ended" };
            let span = now.duration_since(s.last_event_at).unwrap_or(Duration::ZERO);
            writeln!(stdout, "    session: {:>5} calls  ↑{} ↓{}  ({}, {})\r",
                s.calls,
                humanize_tokens(s.in_tokens),
                humanize_tokens(s.out_tokens),
                state,
                humanize_duration(span))?;
        }
        writeln!(stdout, "\r")?;
    }
    Ok(())
}

fn humanize_duration_short(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 { return format!("{}s", s); }
    if s < 3600 { return format!("{}m", s / 60); }
    if s < 86400 { return format!("{}h", s / 3600); }
    format!("{}d", s / 86400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Stage 1.5 windows-compat regression guard: tz offset must be a
    /// real value within the +/- 14h band (tightest possible bounds —
    /// LINT (Kiribati) is +14:00, Baker Island would be -12:00 if
    /// inhabited; +14h covers the worst real-world case). An out-of-
    /// band value indicates the GetTimeZoneInformation parse went
    /// wrong (e.g. summing Bias as u32 wrap rather than i32 negation).
    #[test]
    fn current_tz_offset_secs_is_in_realistic_band() {
        let offset = current_tz_offset_secs();
        let max = 14 * 3600;
        let min = -12 * 3600;
        assert!(
            (min..=max).contains(&offset),
            "tz offset {offset}s outside realistic band [{min}, {max}]; \
             likely a Bias-sign / DST-arm bug",
        );
    }

    /// Stage 1.5 windows-compat: seconds must align on minute
    /// boundaries — every IANA / Windows tz definition uses
    /// minute-precision Bias values. A non-zero value mod 60 means
    /// either we're truncating wrong (GetTimeZoneInformation gave us
    /// minutes which we forgot to multiply) or we picked up garbage
    /// stack memory.
    #[test]
    fn current_tz_offset_secs_is_minute_aligned() {
        let offset = current_tz_offset_secs();
        assert_eq!(
            offset % 60,
            0,
            "tz offset {offset}s is not a multiple of 60 — Bias parse is suspect",
        );
    }

    /// `ts` is an RFC3339 string for test readability; we parse it into
    /// int64 millis (the post-v1.0.3-alpha storage format) so the test
    /// fixtures remain human-auditable.
    fn ev(ts: &str, sid: &str, kid: &str, model: &str, in_tok: i64, out_tok: i64) -> UsageEvent {
        let ts_ms = rfc3339_to_ms(ts);
        UsageEvent {
            event_id: format!("e-{}", sid),
            event_time: ts_ms,
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
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
            stop_reason: None,
            request_status: "success".into(),
            http_status_code: Some(200),
            error_code: None,
        }
    }

    #[test]
    fn aggregator_collects_per_key_totals() {
        let mut agg = Aggregator::new();
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
    fn canary_events_are_filtered() {
        let mut agg = Aggregator::new();
        // Canary by virtual_key_id sentinel
        let mut canary_vk = ev("2026-04-17T15:00:00Z", "c1", "__canary__", "", 0, 1);
        canary_vk.route_source = "canary".into();
        agg.apply(&canary_vk);
        // Canary by route_source only (older proxy builds)
        let mut canary_rs = ev("2026-04-17T15:01:00Z", "c2", "other-vk", "", 0, 1);
        canary_rs.route_source = "canary".into();
        agg.apply(&canary_rs);
        // Real event should still land
        agg.apply(&ev("2026-04-17T15:02:00Z", "s1", "k1", "claude", 10, 20));

        assert_eq!(agg.by_key.len(), 1, "only the real event should be aggregated");
        assert!(agg.by_key.contains_key("k1"));
        assert!(!agg.by_key.contains_key("__canary__"));
        assert!(!agg.by_key.contains_key("other-vk"));
    }

    #[test]
    fn sort_prioritizes_today_tokens_then_freshness() {
        let mut agg = Aggregator::new();
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
        let mut agg = Aggregator::new();
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
        UsageEvent {
            event_id: format!("e-{}", label),
            event_time: (ts_secs as i64).saturating_mul(1000),
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
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
            stop_reason: None,
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

    /// Convert an RFC3339 UTC literal to Unix millis for test fixtures.
    /// Keeps tests readable (you write a wall-clock string) while the
    /// struct is typed int64 post v1.0.3-alpha. Handles only the
    /// trailing `Z` / `+HH:MM` / `-HH:MM` forms that our test data uses.
    fn rfc3339_to_ms(s: &str) -> i64 {
        let bytes = s.as_bytes();
        if bytes.len() < 19 {
            panic!("rfc3339_to_ms: too short: {s}");
        }
        let parse_num = |range: std::ops::Range<usize>| -> i64 {
            std::str::from_utf8(&bytes[range])
                .unwrap()
                .parse()
                .unwrap_or(0)
        };
        let y = parse_num(0..4) as i32;
        let mo = parse_num(5..7) as u32;
        let d = parse_num(8..10) as u32;
        let h = parse_num(11..13);
        let mi = parse_num(14..16);
        let sec = parse_num(17..19);
        let days = civil_from_days_inv(y, mo, d);
        let mut utc_secs = days * 86400 + h * 3600 + mi * 60 + sec;
        // Consume optional fractional and tz suffix.
        let mut idx = 19;
        if idx < bytes.len() && bytes[idx] == b'.' {
            idx += 1;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                idx += 1;
            }
        }
        if idx < bytes.len() {
            match bytes[idx] {
                b'Z' | b'z' => {}
                b'+' | b'-' => {
                    if idx + 6 <= bytes.len() && bytes[idx + 3] == b':' {
                        let hh = parse_num(idx + 1..idx + 3);
                        let mm = parse_num(idx + 4..idx + 6);
                        let sign = if bytes[idx] == b'+' { -1 } else { 1 };
                        utc_secs += sign * (hh * 3600 + mm * 60);
                    }
                }
                _ => {}
            }
        }
        utc_secs.saturating_mul(1000)
    }

    /// Inverse of the Hinnant days_from_civil — copy-paste with the same
    /// name (civil_from_days already exists on the read side), kept
    /// local to the test module.
    fn civil_from_days_inv(y: i32, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
        let yoe = (y - era * 400) as i64;
        let mu = m as i64;
        let doy = (153 * (if mu > 2 { mu - 3 } else { mu + 9 }) + 2) / 5 + d as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era as i64 * 146097 + doe - 719468
    }
}
