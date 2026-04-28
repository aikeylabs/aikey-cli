//! `aikey statusline` — render a one-line receipt for Claude Code's
//! customizable status line.
//!
//! Claude Code feeds this script a JSON context on stdin (see the official
//! schema at https://code.claude.com/docs/en/statusline.md) and displays
//! whatever we write to stdout. We scan the proxy's WAL for the event
//! belonging to the current Claude Code session, then render a compact
//! line summarizing input/output tokens and latency.
//!
//! Design priorities (from 费用小票-实施方案.md §5):
//!   - session_id precise match is the primary path (正常模式)
//!   - model.id + time window is the fallback for --resume / restart
//!     scenarios where statusline stdin's session_id diverges from the
//!     one the proxy saw as the X-Claude-Code-Session-Id header
//!   - empty output when nothing matches — Claude Code hides the row
//!   - hard cap <20ms via scan budget (see usage_wal::ScanOptions)
//!   - zero side effects on the vault / proxy

use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::usage_wal::{
    collect_wal_backward, default_wal_dir, scan_wal_backward, ScanOptions, UsageEvent,
};

/// Subset of the Claude Code statusLine stdin payload we actually use.
/// Serde rejects unknown fields by default — we set `deny_unknown_fields`
/// off (the default) so forward-compat fields don't break parsing.
#[derive(Debug, Default, Deserialize)]
struct ClaudeCodeCtx {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    model: Option<ModelCtx>,
}

#[derive(Debug, Default, Deserialize)]
struct ModelCtx {
    /// API model ID — e.g. "claude-sonnet-4-5-20250929".  This is what
    /// `x-aikey-model` header (and hence WAL `model` field) carries; matching
    /// on `display_name` would fail for every fallback case.
    #[serde(default)]
    id: Option<String>,
}

pub fn run() -> io::Result<()> {
    // Escape hatch for users who want the CLI rows completely dark.
    if env_flag("AIKEY_NO_STATUSLINE") {
        return Ok(());
    }

    // Why: a human running `aikey statusline` in a terminal gets nothing
    // useful from the Claude-Code-stdin path (no JSON, no match). Redirect
    // them to `last-active` so the bare command is self-explanatory.
    use io::IsTerminal;
    if io::stdin().is_terminal() {
        return last_active();
    }

    let ctx = read_stdin_ctx().unwrap_or_default();

    // `scan_wal_backward` walks newest-first with a bounded budget; see
    // §5.1 of the design doc for why a fixed "tail N" is insufficient.
    let opts = ScanOptions::default();
    let Some(dir) = default_wal_dir() else { return Ok(()); };
    if !dir.exists() {
        return Ok(());  // proxy never wrote a WAL on this machine
    }

    let sid = ctx.session_id.as_deref().unwrap_or("");
    let model_id = ctx.model.as_ref().and_then(|m| m.id.as_deref()).unwrap_or("");

    // First pass: exact session_id match (正常模式 — covers the vast majority
    // of Claude Code sessions).
    let exact = if !sid.is_empty() {
        scan_wal_backward(&dir, |ev| {
            if ev.session_id.as_deref() == Some(sid) { Some(ev.clone()) } else { None }
        }, opts)?
    } else { None };

    // Second pass: model.id + 5min window fallback (resume / restart edge
    // cases where stdin's session_id diverges from the WAL's — see §14
    // of the design doc for context).
    let fallback = if exact.is_none() && !model_id.is_empty() {
        scan_wal_backward(&dir, |ev| {
            if ev.model == model_id { Some(ev.clone()) } else { None }
        }, opts)?
    } else { None };

    let Some(ev) = exact.or(fallback) else {
        // Nothing to show — Claude Code hides the row when stdout is empty.
        return Ok(());
    };

    // Freshness guard: even after a match, if the latest event for this
    // session/model is >1h old we treat it as stale. A live proxy writes
    // one event per request, so a gap this long almost always means proxy
    // has stopped and the previous value is no longer representative.
    if let Some(age) = ev.age(std::time::SystemTime::now()) {
        if age > Duration::from_secs(3600) {
            return Ok(());
        }
    }

    // `[receipt] ` prefix aligns Claude Code's status line with the Kimi
    // toast, which Kimi shell auto-prepends from the notification `type`
    // field. We DON'T add this inside render_line() because the Kimi path
    // would then render `[receipt] [receipt] ❬⦿·⦿❭ …` (Kimi shell still
    // adds its own). Dimmed so it reads as chrome, not a metric.
    use colored::Colorize;
    let line = render_line(&ev);
    let mut out = io::stdout().lock();
    write!(out, "{} {}", "[receipt]".dimmed(), line)?;
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on"))
}

fn read_stdin_ctx() -> io::Result<ClaudeCodeCtx> {
    // Caller (`run`) has already verified stdin is a pipe; we will not block
    // on TTY input. Keep the read bounded: Claude Code's payload is always
    // a small JSON object, so read_to_string is fine.
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Ok(ClaudeCodeCtx::default());
    }
    serde_json::from_str(&buf).or_else(|_| Ok(ClaudeCodeCtx::default()))
}

/// `aikey statusline last-active` — scan the WAL for the newest event and
/// print its `session_id` and model id in a human-readable form.
///
/// Why: primarily a debugging / scripting aid when Claude Code's stdin
/// `session_id` diverges from what the proxy saw (the fallback scenario
/// documented in §14 of 费用小票-实施方案.md). Also the default when a
/// human runs bare `aikey statusline` in a terminal — turning an otherwise
/// useless invocation into an actually informative one.
///
/// Output is stable plain text (two lines), so scripts can grep/cut it:
///     session_id: <id-or-none>
///     model:      <id-or-none>
///     age:        <Ns / Nm / Nh ago>
pub fn last_active() -> io::Result<()> {
    let Some(dir) = default_wal_dir() else {
        writeln!(io::stderr(), "aikey statusline: HOME unset, cannot locate WAL")?;
        return Ok(());
    };
    if !dir.exists() {
        println!("(no WAL on this machine — run aikey-proxy first)");
        return Ok(());
    }

    // Use a wide window (24h, 5000 lines) so "recent" stretches across
    // an idle coffee break. Default ScanOptions (5min) is too narrow
    // for this use case.
    let opts = ScanOptions {
        max_age: Some(Duration::from_secs(24 * 3600)),
        max_lines: 5000,
    };

    let newest = scan_wal_backward(&dir, |ev| Some(ev.clone()), opts)?;

    let Some(ev) = newest else {
        println!("(no recent activity in the last 24h)");
        return Ok(());
    };

    let sid = ev.session_id.as_deref().filter(|s| !s.is_empty()).unwrap_or("(none)");
    let model = if ev.model.is_empty() { "(none)" } else { ev.model.as_str() };
    let age_str = ev.age(std::time::SystemTime::now())
        .map(format_age)
        .unwrap_or_else(|| "(unknown)".to_string());

    let mut out = io::stdout().lock();
    writeln!(out, "session_id: {}", sid)?;
    writeln!(out, "model:      {}", model)?;
    writeln!(out, "age:        {}", age_str)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// render_kimi — Stop hook handler for Kimi receipt
// ---------------------------------------------------------------------------
//
// Lifecycle (see 费用小票-Kimi集成 update doc for full story):
//
//   1. Kimi agent turn ends → Stop hook fires → runs
//      `aikey statusline render kimi` with stdin JSON
//      `{"hook_event_name":"Stop","session_id":"<uuid>","cwd":"/path",…}`
//   2. We read the watermark file for this session (last turn's max seq)
//   3. Scan WAL for events matching session_id + provider=kimi + strictly
//      newer than watermark (tuple compare on (wal_file, wal_seq))
//   4. Aggregate: sum tokens/cache, take newest event's model/time/stop_reason
//   5. Render receipt line (shared with Claude path) as the toast title
//   6. Write event.json + delivery.json to
//      ~/.kimi/sessions/<md5(cwd)>/<session_id>/notifications/<rand>/
//   7. Update watermark to the newest hit's (file, seq) tuple
//
// All errors are swallowed silently — a failed hook must not block Kimi.
// On failure the watermark is NOT updated, giving at-least-once semantics:
// next successful turn picks up the missed events.

/// Stop hook stdin payload. `hook_event_name` and `stop_hook_active` are
/// present but we ignore them.
#[derive(Debug, Deserialize)]
struct KimiStopCtx {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    cwd: String,
}

pub fn render_kimi() -> io::Result<()> {
    // 1. Read stdin JSON (short, non-blocking). Silent on garbage/empty —
    // Kimi may poke us with unexpected payloads across version upgrades
    // and we'd rather no-op than crash the hook.
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        return Ok(());
    }
    let Ok(ctx) = serde_json::from_str::<KimiStopCtx>(&buf) else {
        return Ok(());
    };
    if ctx.session_id.is_empty() || ctx.cwd.is_empty() {
        return Ok(());
    }

    // 2. Resolve WAL and session_dir paths.
    let Some(wal_dir) = default_wal_dir() else { return Ok(()); };
    if !wal_dir.exists() {
        return Ok(()); // proxy never ran on this machine; nothing to render
    }
    let session_dir = kimi_session_dir(&ctx.cwd, &ctx.session_id);
    if !session_dir.exists() {
        // Kimi session dir gone (user closed Kimi mid-turn?); skip silently.
        return Ok(());
    }

    // 3. Read watermark. Absent → ("", 0) is the minimum tuple, meaning
    // "include everything in the scan window" — combined with the 5-min
    // fallback (ScanOptions::default().max_age) this bounds the first
    // turn of a fresh session so we don't scan historical files.
    let turns_dir = kimi_turns_dir();
    let (prev_file, prev_seq) = read_watermark_in(&turns_dir, &ctx.session_id);

    // 4. Collect all kimi events for this session that are strictly newer
    // than the watermark tuple.
    //
    // Why the age budget is watermark-aware: the default 5-min `max_age`
    // is a FIRST-TURN guard to avoid replaying stale historical WAL for a
    // fresh session. Once a watermark exists, the watermark IS the lower
    // bound — a long turn (30-min tool loop, an idle coffee break) must
    // not silently drop its earliest events just because they fell behind
    // the 5-min window. `max_age: None` disables the time filter; we lean
    // on `max_lines` (5000 with watermark, 500 without) to keep the scan
    // bounded against pathological WAL sizes.
    let sid = ctx.session_id.clone();
    let pf = prev_file.clone();
    let has_watermark = !prev_file.is_empty() || prev_seq != 0;
    let opts = if has_watermark {
        ScanOptions { max_age: None, max_lines: 5000 }
    } else {
        ScanOptions::default()
    };
    let hits = collect_wal_backward(&wal_dir, move |hit| {
        hit.event.provider_code == "kimi"
            && hit.event.session_id.as_deref() == Some(sid.as_str())
            && tuple_gt(&hit.wal_file_name, hit.wal_seq, &pf, prev_seq)
    }, opts)?;

    if hits.is_empty() {
        // Nothing to report; do NOT update watermark (at-least-once).
        return Ok(());
    }

    // 5. Aggregate. hits is newest-first; `Vec[0]` is this turn's final LLM call.
    let newest = &hits[0];
    let mut in_sum: i64 = 0;
    let mut out_sum: i64 = 0;
    let mut cache_read_sum: i64 = 0;
    let mut cache_write_sum: i64 = 0;
    for h in &hits {
        in_sum += h.event.input_tokens.unwrap_or(0);
        out_sum += h.event.output_tokens.unwrap_or(0);
        cache_read_sum += h.event.cache_read_input_tokens.unwrap_or(0);
        cache_write_sum += h.event.cache_creation_input_tokens.unwrap_or(0);
    }

    // Build a synthetic UsageEvent so we can reuse render_line (same format
    // as Claude path). Only fields render_line reads are filled.
    let synth = UsageEvent {
        event_id: format!("kimi-turn-{}", ctx.session_id),
        event_time: newest.event.event_time,
        session_id: Some(ctx.session_id.clone()),
        key_label: newest.event.key_label.clone(),
        completion: newest.event.completion.clone(),
        virtual_key_id: newest.event.virtual_key_id.clone(),
        provider_code: newest.event.provider_code.clone(),
        route_source: newest.event.route_source.clone(),
        model: newest.event.model.clone(),
        oauth_identity: newest.event.oauth_identity.clone(),
        input_tokens: Some(in_sum),
        output_tokens: Some(out_sum),
        total_tokens: Some(in_sum + out_sum),
        cache_read_input_tokens: if cache_read_sum > 0 { Some(cache_read_sum) } else { None },
        cache_creation_input_tokens: if cache_write_sum > 0 { Some(cache_write_sum) } else { None },
        stop_reason: newest.event.stop_reason.clone(),
        request_status: newest.event.request_status.clone(),
        http_status_code: newest.event.http_status_code,
        error_code: newest.event.error_code.clone(),
    };

    // 6. Render line (shared with Claude) → use as the notification title.
    let rendered = render_line(&synth);
    // Kimi shell's toast renders plain text; strip ANSI to keep it clean.
    let title = strip_ansi_escapes(&rendered);

    // 7. Write notification files (atomic tmp+rename per file). If either
    // write fails we leave watermark alone → next turn will retry.
    if write_kimi_notification(&session_dir, &ctx.session_id, &title, hits.len()).is_err() {
        return Ok(());
    }

    // 8. Advance watermark. Any error here is non-fatal: next turn will
    // re-aggregate these events (at-least-once display).
    let _ = write_watermark_in(&turns_dir, &ctx.session_id, &newest.wal_file_name, newest.wal_seq);

    // 9. Opportunistic GC (cheap: just stat a few files). Failures ignored.
    let _ = gc_stale_watermarks_in(&turns_dir);

    Ok(())
}

/// Tuple comparison `(file_a, seq_a) > (file_b, seq_b)`.
/// File name precedes seq (lexicographic on file name = hourly-time order),
/// seq is a tie-breaker within the same file.
fn tuple_gt(file_a: &str, seq_a: u64, file_b: &str, seq_b: u64) -> bool {
    use std::cmp::Ordering::*;
    match file_a.cmp(file_b) {
        Greater => true,
        Less => false,
        Equal => seq_a > seq_b,
    }
}

/// Kimi session dir following kimi-cli's `WorkDirMeta.sessions_dir` formula:
/// `~/.kimi/sessions/<md5(cwd)>/<session_id>/`
fn kimi_session_dir(cwd: &str, session_id: &str) -> PathBuf {
    use md5::{Md5, Digest};
    let digest = Md5::digest(cwd.as_bytes());
    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".kimi").join("sessions").join(hex).join(session_id)
}

/// Directory for per-session turn watermarks: `~/.aikey/run/kimi-turns/`.
/// The `_in` variant takes an explicit base dir so tests can substitute a
/// tempdir (setting `$HOME` process-wide would collide with parallel tests).
fn kimi_turns_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".aikey").join("run").join("kimi-turns")
}

/// Read the watermark file. **Fail-closed** in every error / corruption
/// mode — returns `("", 0)` (the minimum tuple, equivalent to "no
/// watermark") whenever content can't be fully trusted:
///   - file absent / unreadable
///   - empty file
///   - missing tab separator
///   - seq portion doesn't parse as u64
///   - file name portion is empty (seq without name is nonsensical)
///
/// Why fail-closed: a partially-trusted watermark can skew `tuple_gt`
/// against legitimate WAL hits. E.g. a garbage file-name string could
/// sort lexicographically past all real `usage-YYYYMMDD-HH.jsonl`
/// names and suppress every future receipt until the file is manually
/// removed. The cost of "no watermark" is one extra turn of
/// at-least-once replay, which is always safe; the cost of "poisoned
/// watermark" is silent permanent data loss. So we bias towards the
/// former.
///
/// File format (when well-formed): `<wal_file_name>\t<wal_seq>` on a
/// single line.
fn read_watermark_in(dir: &Path, session_id: &str) -> (String, u64) {
    let path = dir.join(format!("{session_id}.watermark"));
    let Ok(content) = std::fs::read_to_string(&path) else {
        return (String::new(), 0);
    };
    let line = content.lines().next().unwrap_or("");
    let Some((file_part, seq_part)) = line.split_once('\t') else {
        // No tab → can't distinguish file from seq. Treat as absent.
        return (String::new(), 0);
    };
    if file_part.is_empty() {
        // Seq without a file name is meaningless for tuple_gt.
        return (String::new(), 0);
    }
    let Ok(seq) = seq_part.parse::<u64>() else {
        // Tab present but seq isn't numeric — corrupted file.
        return (String::new(), 0);
    };
    (file_part.to_string(), seq)
}

fn write_watermark_in(
    dir: &Path,
    session_id: &str,
    wal_file_name: &str,
    wal_seq: u64,
) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(format!("{session_id}.watermark"));
    let tmp_path = dir.join(format!("{session_id}.watermark.tmp"));
    std::fs::write(&tmp_path, format!("{wal_file_name}\t{wal_seq}"))?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

/// Purge watermark files older than 7 days. Called opportunistically at
/// end of render_kimi — cheap (handful of files typically) and avoids a
/// dedicated daemon.
fn gc_stale_watermarks_in(dir: &Path) -> io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(()); };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(Duration::from_secs(7 * 24 * 3600))
        .unwrap_or(std::time::UNIX_EPOCH);
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue; };
        let Ok(mtime) = meta.modified() else { continue; };
        if mtime < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Write the notification to the Kimi session's notifications directory.
///
/// **Directory-atomic publishing** (fixes the half-published race where the
/// scanner could see `event.json` without its companion `delivery.json`):
///   1. Build the notification inside a dotted staging directory
///      `notifications/.<id>.staging/` — Kimi skips dotfiles when
///      enumerating new notifications, so partial state is invisible.
///   2. Write `event.json` and `delivery.json` into the staging dir.
///   3. Single `rename(staging → final)` promotes the dir. On POSIX, a dir
///      rename is atomic with respect to other readers iterating the
///      parent: they either see the old name (missing) or the new name
///      (complete), never a half-filled directory.
///   4. If any step before the rename fails, leave a `.staging` leftover
///      and don't advance the watermark — next turn retries with a fresh
///      id. Stale `.staging` dirs are GC-safe (the rename is all-or-nothing
///      and we never pick them up again).
///
/// Notification id matches Kimi's `^[a-z0-9]{2,20}$` regex: `n` + 8 hex chars.
fn write_kimi_notification(
    session_dir: &Path,
    session_id: &str,
    title: &str,
    events_folded: usize,
) -> io::Result<()> {
    use rand::RngCore;

    let mut rng_bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut rng_bytes);
    let notif_id = format!("n{}", hex::encode(rng_bytes));

    let notifs_root = session_dir.join("notifications");
    std::fs::create_dir_all(&notifs_root)?;
    let staging_dir = notifs_root.join(format!(".{notif_id}.staging"));
    let final_dir = notifs_root.join(&notif_id);

    // If a previous attempt left the same-named staging dir behind (extremely
    // unlikely given the 32-bit random id, but defensive), clean it so
    // create_dir_all doesn't mix old + new files.
    if staging_dir.exists() {
        let _ = std::fs::remove_dir_all(&staging_dir);
    }
    std::fs::create_dir_all(&staging_dir)?;

    // event.json — critical: targets=["shell"] only; never include "llm".
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let event = serde_json::json!({
        "version": 1,
        "id": notif_id,
        "category": "system",
        "type": "receipt",
        "source_kind": "aikey",
        "source_id": "wal",
        "title": title,
        "body": "",
        "severity": "info",
        "created_at": now_secs,
        "payload": {
            "session_id": session_id,
            "events_folded": events_folded,
        },
        "targets": ["shell"],
    });
    std::fs::write(
        staging_dir.join("event.json"),
        serde_json::to_string(&event)?,
    )?;

    let delivery = serde_json::json!({
        "sinks": {
            "shell": {
                "status": "pending",
                "claimed_at": serde_json::Value::Null,
                "acked_at": serde_json::Value::Null,
            }
        }
    });
    std::fs::write(
        staging_dir.join("delivery.json"),
        serde_json::to_string(&delivery)?,
    )?;

    // Atomic publish: the scanner either misses the dir entirely or sees
    // both files already present.
    std::fs::rename(&staging_dir, &final_dir)?;
    Ok(())
}

/// Strip ANSI CSI escape sequences from a string. Kimi shell's toast
/// renders plain text; embedded ANSI would show as garbage.
///
/// CSI sequences are `ESC [ <params> <final>` where `<final>` is a byte in
/// 0x40..=0x7E. Naïvely consuming "until a byte in that range" breaks on the
/// leading `[` itself (0x5B), so we special-case CSI: skip the `[`, then
/// consume parameter bytes until a true CSI-final byte.
fn strip_ansi_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            None => break,
            Some('[') => {
                // CSI: swallow parameter / intermediate bytes, stop on final (0x40..=0x7E).
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if ('@'..='~').contains(&nc) { break; }
                }
            }
            // Non-CSI escape (e.g. ESC ]) — drop the one introducer byte.
            Some(_) => {}
        }
    }
    out
}

fn format_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 { return format!("{}s ago", secs); }
    if secs < 3600 { return format!("{}m ago", secs / 60); }
    if secs < 86400 { return format!("{}h {}m ago", secs / 3600, (secs % 3600) / 60); }
    format!("{}d ago", secs / 86400)
}

fn render_line(ev: &UsageEvent) -> String {
    use colored::Colorize;

    let raw_label = ev.key_label.as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| ev.oauth_identity.as_deref().filter(|s| !s.is_empty()))
        .or_else(|| if !ev.virtual_key_id.is_empty() { Some(ev.virtual_key_id.as_str()) } else { None })
        .unwrap_or("(unknown key)");
    let label = shorten_label(raw_label, 22);

    let in_tok = ev.input_tokens.unwrap_or(0);
    let out_tok = ev.output_tokens.unwrap_or(0);

    // Completion prefix: render a dim warning when the proxy recorded a
    // non-complete stream so users see why the numbers look partial.
    let completion = ev.completion.as_deref().unwrap_or("complete");
    let prefix = match completion {
        "partial" => format!("{} ", "⚠ partial".yellow()),
        "interrupted" => format!("{} ", "⚠ error".red()),
        _ => String::new(),
    };

    // Why this ordering — tokens first, then cache, then model, then identity,
    // then timestamp:
    //   tokens update every turn (user eye lands here first) → bold + bright
    //   cache breakdown is supplementary → dimmer than main tokens
    //   model / identity / timestamp are near-static chrome → dim
    // All segments share the same `·` separator for consistent rhythm.
    let sep = " · ".dimmed();
    // Dashed-stem arrows `⇡/⇣` instead of plain `↑/↓`: slightly more refined
    // glyph in modern programming fonts. Semantics unchanged — up = input,
    // down = output. Cache segment uses a different glyph family (`↺`/`+`)
    // on purpose so the eye can tell "primary tokens" from "cache detail".
    let up = "⇡".bold().cyan();
    let down = "⇣".bold().cyan();
    // Primary token numbers are bold + bright white so they anchor the row.
    // format_number already returns an uncolored String; wrap here.
    let in_s = format_number(in_tok).bold();
    let out_s = format_number(out_tok).bold();

    // Cache segment: Anthropic-only today. Glyphs chosen so neither implies
    // a bidirectional "flow" — both fields are input-side counts (already
    // included in the main ↑ total), the split is about provenance and
    // pricing, not traffic direction.
    //   ↺ (cyclic)    for cache-read  → tokens replayed from server cache
    //   ⊕ (circled +) for cache-write → tokens newly added to the cache
    //
    // Why `⊕` not bare `+`: inside a `·`-joined segment like `↺12K ⊕61K` a
    // bare `+` reads as arithmetic ("12K + 61K"). The circled form breaks
    // that illusion by being visually a single glyph, not a binary operator.
    //
    // Why no more parens / no more "hit"/"cache" words: the symbols alone
    // are self-explanatory after a moment of pattern recognition, and
    // dropping the enclosure lets cache align as a peer `·` segment with
    // model / label instead of a parenthetical aside. This also halves
    // the visual width of the segment on cache-heavy Claude turns where
    // most of the line is already tokens.
    //
    // Rendered one brightness tier dimmer than the main tokens since it's
    // supplementary detail, not a primary metric.
    let cache_read = ev.cache_read_input_tokens.unwrap_or(0);
    let cache_write = ev.cache_creation_input_tokens.unwrap_or(0);
    let cache_seg = if cache_read > 0 || cache_write > 0 {
        let body = format!(
            "↺{} ⊕{}",
            format_number(cache_read),
            format_number(cache_write),
        );
        body.truecolor(130, 130, 130).to_string()
    } else {
        String::new()
    };

    let model = shorten_model(&ev.model);

    // Why show refresh time: Claude Code re-invokes the statusline command on
    // every turn. When the same line re-appears with identical numbers the
    // user can't tell "nothing happened" from "aikey stalled". A trailing
    // HH:MM:SS tag proves the receipt is fresh. Dim + parenthesised so it
    // reads as metadata, not another metric.
    let ts = event_time_hm(ev.event_time);

    // Layout (reviewed 2026-04-20):
    //   {prefix}tokens · [cache] · model · label · ❬⦿·⦿❭ HH:MM
    //
    // - Timestamp moves to the far tail as bare `HH:MM` (no parens) so the
    //   right edge reads as a clock, not another data segment.
    // - Brand `❬⦿·⦿❭` sits between the last data segment and the timestamp,
    //   joined with `·` on the left (as a regular segment) and a plain
    //   space on the right (so the clock "floats" off the brand).
    // - `partial` / `error` warning stays in FRONT — buried warnings are
    //   worse than redundant leading chrome.
    //
    // Assemble data segments first, with `·` separators only between
    // non-empty entries so a missing segment never produces "↑3 ↓22 ·  · m".
    let mut parts: Vec<String> = Vec::with_capacity(5);
    parts.push(format!("{up}{in_s} {down}{out_s}"));
    if !cache_seg.is_empty() { parts.push(cache_seg); }
    if !model.is_empty() { parts.push(format!("{}", model.dimmed())); }
    if !label.is_empty() { parts.push(format!("{}", label.dimmed())); }

    let brand = "❬⦿·⦿❭".dimmed();
    // Brand becomes the final `·`-joined segment so it aligns visually
    // with model/label and doesn't look like a ragged appendix.
    parts.push(format!("{}", brand));

    let body = parts.join(&format!("{}", sep));
    // Clock tail: plain `HH:MM`, dim, separated from brand by a single
    // space. Omitted entirely when event_time parse failed so we never
    // render a lone space at the end.
    if ts.is_empty() {
        format!("{prefix}{body}")
    } else {
        format!("{prefix}{body} {}", ts.dimmed())
    }
}

/// Extract `HH:MM` from the event's RFC3339-ish timestamp. The proxy writes
/// `event_time` as "YYYY-MM-DDTHH:MM:SS.ffffff±HH:MM" (local TZ from Go's
/// time.Now()), so the time-of-day bytes always sit at fixed offsets
/// 11..16. That lets us format without pulling in a date-time crate.
///
/// Why minute granularity only: seconds flicker on every turn without adding
/// information — the statusline refreshes per-prompt and the user only needs
/// "is this still fresh" signal. `HH:MM` gives ~60s freshness resolution and
/// reads cleaner in the tag.
///
/// Returns "" when the timestamp is absent / zero.
///
/// Post proxy v1.0.3-alpha (bugfix 20260424) `event_time` is int64
/// millis instead of RFC3339. The output is rendered in the user's
/// **local** timezone so the statusline tag matches wall-clock
/// expectation ("just refreshed at 12:49" on a +08:00 machine should
/// read 12:49, not 04:49 UTC). We use the OS/libc local-time
/// conversion via `chrono` where available, but to keep the CLI's
/// binary size honest we do a small manual local-offset tweak using
/// `libc::timezone` / `tm_gmtoff` — no extra deps.
///
/// The offset probe runs once per call and is cheap (syscall-free on
/// macOS/Linux after the initial tzset).
#[cfg(unix)]
fn event_time_hm(event_time_ms: i64) -> String {
    if event_time_ms <= 0 {
        return String::new();
    }
    let secs = event_time_ms / 1000;
    // Resolve local offset via the standard `time_t → struct tm` path.
    // `libc::localtime_r` populates `tm_gmtoff` which encodes the
    // effective offset (DST-aware) for that specific instant.
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    let t = secs as libc::time_t;
    let rc = unsafe { libc::localtime_r(&t, &mut tm) };
    if rc.is_null() {
        return String::new();
    }
    // tm_hour / tm_min already in local time.
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

/// Windows variant of `event_time_hm` — same contract (UTC millis →
/// local "HH:MM" string) but built on Win32 time APIs because `libc`
/// is not available on `cfg(windows)` (`Cargo.toml` declares libc only
/// under `[target.'cfg(unix)'.dependencies]`).
///
/// Path: UTC millis → FILETIME → UTC SYSTEMTIME → local SYSTEMTIME via
/// `SystemTimeToTzSpecificLocalTime` with NULL TZ pointer (uses the
/// machine's currently-active time zone, DST-aware — semantically the
/// same as `localtime_r` on Unix).  No extra crate deps: `windows-sys`
/// is already declared on cfg(windows) for mlock.
#[cfg(windows)]
fn event_time_hm(event_time_ms: i64) -> String {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

    if event_time_ms <= 0 {
        return String::new();
    }
    // Windows FILETIME is 100-nanosecond intervals since 1601-01-01 UTC.
    // Unix epoch (1970-01-01 UTC) sits at 116_444_736_000_000_000 in that scale.
    let ft100ns = match event_time_ms
        .checked_mul(10_000)
        .and_then(|v| v.checked_add(116_444_736_000_000_000_i64))
    {
        Some(v) if v >= 0 => v as u64,
        _ => return String::new(),
    };
    let utc_ft = FILETIME {
        dwLowDateTime: (ft100ns & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ft100ns >> 32) as u32,
    };
    let mut utc_st = SYSTEMTIME {
        wYear: 0, wMonth: 0, wDayOfWeek: 0, wDay: 0,
        wHour: 0, wMinute: 0, wSecond: 0, wMilliseconds: 0,
    };
    // SAFETY: utc_ft is a valid FILETIME, utc_st is a writable SYSTEMTIME.
    if unsafe { FileTimeToSystemTime(&utc_ft, &mut utc_st) } == 0 {
        return String::new();
    }
    let mut local_st = SYSTEMTIME {
        wYear: 0, wMonth: 0, wDayOfWeek: 0, wDay: 0,
        wHour: 0, wMinute: 0, wSecond: 0, wMilliseconds: 0,
    };
    // Passing NULL for the TZ info uses the system's current time zone
    // (DST-aware), which matches the wall clock on the user's machine —
    // same semantics as `localtime_r` on Unix.
    // SAFETY: utc_st is a valid SYSTEMTIME, local_st is writable.
    if unsafe {
        SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc_st, &mut local_st)
    } == 0 {
        return String::new();
    }
    format!("{:02}:{:02}", local_st.wHour, local_st.wMinute)
}

/// Abbreviate model IDs so they fit comfortably in the receipt.
/// e.g. `claude-sonnet-4-5-20250929` -> `sonnet-4-5`
///      `claude-sonnet-4-6`          -> `sonnet-4-6`
///      `kimi-k2.5`                  -> `kimi-k2.5`
///      `moonshot-v1-128k`           -> `moonshot-v1-128k`
/// The `claude-` prefix is always dropped since the ecosystem context makes
/// it redundant; date suffixes are trimmed to preserve the version family.
fn shorten_model(model: &str) -> String {
    if model.is_empty() { return String::new(); }
    let without_prefix = model.strip_prefix("claude-").unwrap_or(model);
    // Strip the YYYYMMDD date tail Anthropic appends to stable model IDs.
    // Example: "sonnet-4-5-20250929" → "sonnet-4-5"
    let parts: Vec<&str> = without_prefix.rsplitn(2, '-').collect();
    if parts.len() == 2 && parts[0].len() == 8 && parts[0].chars().all(|c| c.is_ascii_digit()) {
        return parts[1].to_string();
    }
    without_prefix.to_string()
}

/// Shorten a label so it fits in a statusline cell without dominating the row.
/// Emails collapse to `prefix…@domain` when the username is too long; anything
/// else just gets a mid-string ellipsis.
fn shorten_label(label: &str, max: usize) -> String {
    if label.chars().count() <= max { return label.to_string(); }

    // Email: keep first few chars of local + "…" + domain.
    if let Some(at) = label.find('@') {
        let (local, domain) = label.split_at(at); // domain begins with '@'
        let budget = max.saturating_sub(domain.chars().count() + 1); // +1 for '…'
        if budget >= 2 {
            let prefix: String = local.chars().take(budget).collect();
            return format!("{prefix}…{domain}");
        }
    }
    // Generic fallback: mid-ellipsis to preserve both ends.
    let keep_head = max.saturating_sub(1).saturating_mul(2) / 3; // ~2/3 from head
    let keep_tail = max.saturating_sub(1).saturating_sub(keep_head);
    let head: String = label.chars().take(keep_head).collect();
    let tail_skip = label.chars().count().saturating_sub(keep_tail);
    let tail: String = label.chars().skip(tail_skip).collect();
    format!("{head}…{tail}")
}

// ---------------------------------------------------------------------------
// `aikey statusline install / uninstall / status`
// ---------------------------------------------------------------------------
//
// These manage the `statusLine` entry in `~/.claude/settings.json` so Claude
// Code calls `aikey statusline` on every prompt refresh.  The algorithm
// mirrors the UX pattern established by `configure_kimi_cli` / `configure_codex_cli`:
//   - idempotent: re-running install on an already-aikey settings file is a no-op
//   - protective: if the user already has a different statusLine we prompt
//     before overwriting, and always back up the original
//   - reversible: uninstall restores from backup when available
// See 费用小票-实施方案.md §5.5 for the full spec.

/// Outcome of `install` / `ensure_claude_statusline_installed`.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Wrote a new statusLine entry.
    Installed,
    /// Already pointed at aikey — nothing to do.
    AlreadyInstalled,
    /// User had a different statusLine; left it alone per their choice.
    SkippedExisting,
    /// No `~/.claude` directory detected (Claude Code probably not installed).
    NotApplicable,
    /// Settings file is unreadable / malformed — refused to touch it.
    RefusedMalformed,
}

/// `aikey statusline install [target] [--all] [--force]` — top-level
/// dispatcher. Defaults to the Claude target for backward compatibility.
pub fn install(target: Option<&str>, all: bool, force: bool) -> io::Result<()> {
    if all {
        install_claude(force)?;
        install_kimi()?;
        return Ok(());
    }
    match target.unwrap_or("claude") {
        "claude" => {
            install_claude(force)?;
        }
        "kimi" => {
            install_kimi()?;
        }
        other => {
            use colored::Colorize;
            eprintln!(
                "  {} Unknown statusline target: {} (expected: claude | kimi | --all)",
                "✗".red(),
                other
            );
        }
    }
    Ok(())
}

/// Claude-specific install — always verbose. `ensure_claude_statusline_installed`
/// is the quiet variant for auto-triggers.
pub fn install_claude(force: bool) -> io::Result<InstallOutcome> {
    install_inner(force, /*quiet=*/ false)
}

/// Ensure the aikey-managed Kimi scaffold exists in `~/.kimi/config.toml`.
///
/// In v3 architecture the scaffold is token-agnostic: it contains placeholder
/// `api_key` and `base_url` that get overridden by `KIMI_API_KEY` / `KIMI_BASE_URL`
/// env vars at runtime. The only piece that genuinely needs file storage is the
/// `[[hooks]]` Stop entry (Kimi does not support env-var-configured hooks).
///
/// This command is idempotent — re-running after the region exists is a no-op
/// unless the hook command path has drifted (e.g. after moving the aikey binary).
pub fn install_kimi() -> io::Result<()> {
    use colored::Colorize;

    let proxy_port = crate::commands_proxy::proxy_port();
    crate::commands_account::configure_kimi_cli(proxy_port);
    eprintln!(
        "  {} Kimi CLI scaffold ensured at {} (token overrides via KIMI_API_KEY).",
        "✓".green(),
        "~/.kimi/config.toml".dimmed()
    );
    eprintln!(
        "    {} {}",
        "Stop hook:".dimmed(),
        aikey_statusline_render_kimi_command()
    );
    Ok(())
}

/// Shared install logic. `quiet=true` suppresses the "already points to
/// aikey" and "installed" success lines so auto-triggers (fired from
/// `aikey auth login claude` / `aikey use`) don't pollute those commands'
/// output. Errors and the surprise-conflict box always print — those need
/// user attention regardless of caller.
fn install_inner(force: bool, quiet: bool) -> io::Result<InstallOutcome> {
    use colored::Colorize;
    let Some(settings_path) = claude_settings_path() else {
        return Ok(InstallOutcome::NotApplicable);
    };

    // Only install if Claude Code plausibly exists on this machine.  We
    // treat a missing ~/.claude as "not applicable" rather than silently
    // creating the directory — otherwise invoking aikey on a non-Claude-Code
    // machine would conjure files the user never asked for.
    let claude_dir = settings_path.parent().expect("settings file has a parent");
    if !claude_dir.exists() {
        if !quiet {
            eprintln!("  {} {}",
                "ⓘ".cyan(),
                format!("Claude Code config directory not found: {}", claude_dir.display()).dimmed());
            eprintln!("  {}",
                "Skipping status-line install. Open Claude Code once and re-run.".dimmed());
        }
        return Ok(InstallOutcome::NotApplicable);
    }

    let current = match read_settings(&settings_path) {
        Ok(v) => v,
        Err(ReadError::Malformed(e)) => {
            // Malformed settings is always user-actionable — print regardless.
            eprintln!("  {} {}",
                "✗".red(),
                format!("Cannot parse {}: {}", settings_path.display(), e).red());
            eprintln!("  {}",
                "Fix or remove the file and re-run `aikey statusline install`.".dimmed());
            return Ok(InstallOutcome::RefusedMalformed);
        }
        Err(ReadError::NotFound) => serde_json::json!({}),
        Err(ReadError::Io(e)) => return Err(e),
    };

    let aikey_cmd = aikey_statusline_command();
    let existing = current
        .as_object()
        .and_then(|o| o.get("statusLine"))
        .and_then(|sl| sl.as_object());
    let existing_cmd = existing
        .and_then(|sl| sl.get("command"))
        .and_then(|c| c.as_str())
        .unwrap_or("");

    if existing_cmd.contains("aikey statusline") {
        // Already ours — idempotent. Quiet mode skips the chatter entirely
        // so `aikey use` / `aikey auth login claude` don't dump this line
        // on every invocation after the initial setup.
        if !quiet {
            eprintln!("  {} {}", "✓".green(), "Claude Code status line already points to aikey.".dimmed());
        }
        return Ok(InstallOutcome::AlreadyInstalled);
    }

    if !existing_cmd.is_empty() && !force {
        // User-actionable conflict — always print. Silencing this would
        // leave the user wondering why their existing statusLine survived.
        let rows = vec![
            format!("File:     {}", settings_path.display()),
            format!("Existing: {}", existing_cmd.dimmed()),
            format!("aikey will {}",
                "not overwrite".yellow()),
            String::new(),
            format!("To install anyway:  aikey statusline install --force"),
            format!("(the existing value will be backed up)"),
        ];
        crate::ui_frame::eprint_box("\u{2753}", "Claude Code statusLine already configured", &rows);
        return Ok(InstallOutcome::SkippedExisting);
    }

    // Back up existing settings (even empty-file case — helps uninstall know
    // whether the file existed before we wrote to it).
    backup_settings(&settings_path)?;

    // Merge: keep whatever else is in settings.json, set statusLine.
    let mut merged = match &current {
        serde_json::Value::Object(_) => current.clone(),
        _ => serde_json::json!({}),
    };
    if let Some(obj) = merged.as_object_mut() {
        obj.insert("statusLine".into(), serde_json::json!({
            "type": "command",
            "command": aikey_cmd,
        }));
    }

    write_settings_atomic(&settings_path, &merged)?;
    if !quiet {
        eprintln!("  {} Claude Code status line installed.", "✓".green());
        eprintln!("    {} {}", "file:".dimmed(), settings_path.display());
        eprintln!("    {} {}", "command:".dimmed(), aikey_cmd);
    }
    Ok(InstallOutcome::Installed)
}

/// Idempotent auto-install called from `aikey auth login claude` / `aikey use`
/// when a Claude credential becomes the active target.  Unlike the top-level
/// `install()`, this variant is silent on success — users expect the key
/// action to succeed quickly without a wall of status output.  Only first-
/// time prompts and errors surface.
pub fn ensure_claude_statusline_installed() {
    // quiet=true suppresses "already points to aikey" / "installed" chatter
    // so `aikey use` / `aikey auth login claude` stay focused on the main
    // task. Errors and the first-time conflict box still surface because
    // `install_inner` gates only the success-path prints on `quiet`.
    let _ = install_inner(false, true);
}

/// `aikey statusline uninstall [target] [--all]` — top-level dispatcher.
pub fn uninstall(target: Option<&str>, all: bool) -> io::Result<()> {
    if all {
        uninstall_claude()?;
        uninstall_kimi()?;
        return Ok(());
    }
    match target.unwrap_or("claude") {
        "claude" => uninstall_claude()?,
        "kimi" => uninstall_kimi()?,
        other => {
            use colored::Colorize;
            eprintln!(
                "  {} Unknown statusline target: {} (expected: claude | kimi | --all)",
                "✗".red(),
                other
            );
        }
    }
    Ok(())
}

/// Remove aikey's Kimi Stop hook (and its co-owned provider/models block —
/// the whole aikey-managed region is the atomic unit of ownership).
pub fn uninstall_kimi() -> io::Result<()> {
    use crate::commands_account::{uninstall_kimi_hook, KimiUninstallOutcome};
    use colored::Colorize;

    match uninstall_kimi_hook() {
        KimiUninstallOutcome::Removed => {
            eprintln!(
                "  {} Removed aikey-managed region from ~/.kimi/config.toml.",
                "✓".green()
            );
            eprintln!(
                "    {}",
                "Note: this also resets the Kimi provider to its pre-aikey state.".dimmed()
            );
        }
        KimiUninstallOutcome::NothingToRemove => {
            eprintln!(
                "  {}",
                "No aikey-managed Kimi config found — nothing to remove.".dimmed()
            );
        }
        KimiUninstallOutcome::HomeMissing => {
            eprintln!("  {} $HOME not set — cannot locate Kimi config.", "!".yellow());
        }
    }
    Ok(())
}

/// Claude-specific uninstall.
pub fn uninstall_claude() -> io::Result<()> {
    use colored::Colorize;
    let Some(settings_path) = claude_settings_path() else {
        eprintln!("  {}", "No Claude Code config directory — nothing to uninstall.".dimmed());
        return Ok(());
    };

    let current = match read_settings(&settings_path) {
        Ok(v) => v,
        Err(ReadError::NotFound) => {
            eprintln!("  {}", "~/.claude/settings.json does not exist — nothing to uninstall.".dimmed());
            return Ok(());
        }
        Err(ReadError::Malformed(e)) => {
            eprintln!("  {} {}", "✗".red(),
                format!("Cannot parse settings.json: {}", e).red());
            return Ok(());
        }
        Err(ReadError::Io(e)) => return Err(e),
    };

    let points_to_us = current
        .get("statusLine")
        .and_then(|sl| sl.get("command"))
        .and_then(|c| c.as_str())
        .map(|c| c.contains("aikey statusline"))
        .unwrap_or(false);

    if !points_to_us {
        eprintln!("  {}", "Claude Code status line is not configured for aikey — nothing to remove.".dimmed());
        return Ok(());
    }

    // Prefer restoring the backup we wrote at install time — it reflects the
    // exact state the user had before we touched the file.
    let backup_path = statusline_backup_path(&settings_path);
    if backup_path.exists() {
        std::fs::rename(&backup_path, &settings_path)?;
        eprintln!("  {} Restored {} from backup.", "✓".green(), settings_path.display());
        return Ok(());
    }

    // No backup (e.g. we created the settings.json from scratch): just drop
    // the statusLine key, leave the rest alone.
    let mut next = current.clone();
    if let Some(obj) = next.as_object_mut() {
        obj.remove("statusLine");
    }
    // If nothing else remains, remove the file entirely rather than leave an
    // empty `{}` that looks like user-configured state.
    if next.as_object().map(|o| o.is_empty()).unwrap_or(false) {
        std::fs::remove_file(&settings_path)?;
        eprintln!("  {} Removed {} (file was otherwise empty).", "✓".green(), settings_path.display());
    } else {
        write_settings_atomic(&settings_path, &next)?;
        eprintln!("  {} Removed aikey statusLine from {}.", "✓".green(), settings_path.display());
    }
    Ok(())
}

/// `aikey statusline status` — print whether aikey owns the receipt hooks
/// for Claude Code and Kimi CLI, without making any changes.
pub fn print_status() -> io::Result<()> {
    use colored::Colorize;
    println!("{}", "Claude Code".bold());
    print_status_claude()?;
    println!();
    println!("{}", "Kimi CLI".bold());
    print_status_kimi();
    Ok(())
}

fn print_status_claude() -> io::Result<()> {
    use colored::Colorize;
    let Some(settings_path) = claude_settings_path() else {
        println!("  {}", "config dir not resolvable (HOME unset?)".yellow());
        return Ok(());
    };

    let exists = settings_path.exists();
    let parsed = match read_settings(&settings_path) {
        Ok(v) => Some(v),
        Err(ReadError::NotFound) => None,
        Err(ReadError::Malformed(e)) => {
            println!("  {}", format!("settings.json cannot be parsed: {e}").red());
            return Ok(());
        }
        Err(ReadError::Io(e)) => return Err(e),
    };

    let cmd = parsed
        .as_ref()
        .and_then(|v| v.get("statusLine"))
        .and_then(|sl| sl.get("command"))
        .and_then(|c| c.as_str());

    println!("  {}: {}", "file".dimmed(), settings_path.display());
    println!("  {}: {}", "exists".dimmed(), if exists { "yes" } else { "no" });
    match cmd {
        None => println!("  {}: {}", "statusLine".dimmed(), "not configured".dimmed()),
        Some(c) if c.contains("aikey statusline") => {
            println!("  {}: {}", "statusLine".dimmed(), format!("aikey ({c})").green());
        }
        Some(c) => {
            println!("  {}: {}", "statusLine".dimmed(), format!("other ({c})").yellow());
        }
    }
    let backup = statusline_backup_path(&settings_path);
    if backup.exists() {
        println!("  {}: {}", "backup".dimmed(), backup.display());
    }
    Ok(())
}

fn print_status_kimi() {
    use colored::Colorize;
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            println!("  {}", "HOME not set — cannot locate Kimi config.".yellow());
            return;
        }
    };
    let config_path = PathBuf::from(&home).join(".kimi").join("config.toml");
    println!("  {}: {}", "file".dimmed(), config_path.display());
    println!(
        "  {}: {}",
        "exists".dimmed(),
        if config_path.exists() { "yes" } else { "no" }
    );

    let (region_present, hook_current) = crate::commands_account::kimi_status();
    let expected_cmd = aikey_statusline_render_kimi_command();
    match (region_present, hook_current) {
        (false, _) => println!(
            "  {}: {}",
            "Stop hook".dimmed(),
            "not configured (run `aikey statusline install kimi`)".dimmed()
        ),
        (true, true) => println!(
            "  {}: {}",
            "Stop hook".dimmed(),
            format!("aikey ({expected_cmd})").green()
        ),
        (true, false) => println!(
            "  {}: {}",
            "Stop hook".dimmed(),
            "aikey region present but hook path differs (re-run `aikey statusline install kimi`)"
                .yellow()
        ),
    }
    let backup = PathBuf::from(&home)
        .join(".kimi")
        .join("config.aikey_backup.toml");
    if backup.exists() {
        println!("  {}: {}", "backup".dimmed(), backup.display());
    }
}

// ---------------------------------------------------------------------------
// Helpers for settings manipulation.
// ---------------------------------------------------------------------------

fn claude_settings_path() -> Option<PathBuf> {
    // Prefer HOME because `dirs::home_dir()` would add a heavy dependency just
    // for this lookup.  Falls back to USERPROFILE for Windows parity with the
    // rest of the CLI (matches `resolve_aikey_dir()`).
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".claude").join("settings.json"))
}

/// Backup path: `<dir>/settings.aikey_backup.json`.  The backup is always a
/// literal byte-for-byte copy of the settings file at the moment of install,
/// so `uninstall` can restore arbitrary user-written JSON without needing
/// to preserve formatting.
fn statusline_backup_path(settings_path: &Path) -> PathBuf {
    settings_path
        .with_file_name("settings.aikey_backup.json")
}

#[derive(Debug)]
enum ReadError {
    NotFound,
    Malformed(serde_json::Error),
    Io(io::Error),
}

fn read_settings(path: &Path) -> Result<serde_json::Value, ReadError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::NotFound),
        Err(e) => return Err(ReadError::Io(e)),
    };
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(&bytes).map_err(ReadError::Malformed)
}

/// Backup the current settings.json verbatim when it exists.  Skips silently
/// if there's nothing to back up, or if a previous backup is already present
/// (we never overwrite — the first backup is the canonical "original state").
fn backup_settings(settings_path: &Path) -> io::Result<()> {
    if !settings_path.exists() {
        return Ok(());
    }
    let backup = statusline_backup_path(settings_path);
    if backup.exists() {
        return Ok(());
    }
    std::fs::copy(settings_path, &backup)?;
    Ok(())
}

/// Atomic settings write: render the JSON into a sibling tmp file then
/// rename it into place.  Matches the pattern the proxy uses for its own
/// snapshot files — Claude Code may be reading settings.json at any moment
/// as it renders the status line, so we can't tolerate a half-written file.
fn write_settings_atomic(settings_path: &Path, value: &serde_json::Value) -> io::Result<()> {
    let parent = settings_path.parent().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidInput, "settings path has no parent",
    ))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(".settings.aikey.tmp");
    let pretty = serde_json::to_vec_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &pretty)?;
    std::fs::rename(&tmp, settings_path)?;
    Ok(())
}

/// Absolute path to the current binary, quoted if it contains whitespace, or
/// bare `aikey` as last resort when `current_exe()` fails (e.g. some unusual
/// platform). Absolute is preferred so hook invocation doesn't depend on the
/// user's PATH.
pub(crate) fn aikey_bin_quoted() -> String {
    match std::env::current_exe() {
        Ok(p) => {
            let s = p.display().to_string();
            if s.chars().any(char::is_whitespace) {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s
            }
        }
        Err(_) => "aikey".to_string(),
    }
}

/// Command string for Claude Code `statusLine` entry.
fn aikey_statusline_command() -> String {
    format!("{} statusline", aikey_bin_quoted())
}

/// Command string for Kimi Stop-hook entry.
pub(crate) fn aikey_statusline_render_kimi_command() -> String {
    format!("{} statusline render kimi", aikey_bin_quoted())
}

/// Compact large numbers: 1234 → "1,234", 12345 → "12.3K".
fn format_number(n: i64) -> String {
    let abs = n.unsigned_abs();
    if abs < 10_000 {
        // Thousands separator for small numbers.
        let s = n.to_string();
        let sign_len = if n < 0 { 1 } else { 0 };
        let digits = &s[sign_len..];
        let bytes = digits.as_bytes();
        let mut out = String::with_capacity(s.len() + digits.len() / 3);
        if sign_len == 1 { out.push('-'); }
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 && (bytes.len() - i) % 3 == 0 {
                out.push(',');
            }
            out.push(*b as char);
        }
        out
    } else if abs < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(session_id: &str, model: &str, completion: &str, in_tok: i64, out_tok: i64) -> UsageEvent {
        UsageEvent {
            event_id: "e1".into(),
            // 2026-04-17T15:23:45Z in Unix millis = 1776439425000
            event_time: 1776439425000,
            session_id: if session_id.is_empty() { None } else { Some(session_id.into()) },
            key_label: Some("aikeyfounder@gmail.com".into()),
            completion: Some(completion.into()),
            virtual_key_id: "oauth:acct".into(),
            provider_code: "anthropic".into(),
            route_source: "oauth".into(),
            model: model.into(),
            oauth_identity: Some("aikeyfounder@gmail.com".into()),
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
    fn render_omits_completion_prefix_on_complete() {
        let rendered = render_line(&ev("s1", "claude-sonnet-4-5", "complete", 1234, 458));
        // We don't assert exact ANSI — just that the key elements are there
        // and no "partial"/"error" marker leaked in.
        assert!(rendered.contains("1,234"));
        assert!(rendered.contains("458"));
        assert!(!rendered.contains("partial"));
        assert!(!rendered.contains("error"));
    }

    #[test]
    fn render_marks_partial() {
        let rendered = render_line(&ev("s1", "m", "partial", 100, 50));
        assert!(rendered.contains("partial"));
    }

    #[test]
    fn format_number_thousands_sep() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(42), "42");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(9999), "9,999");
        // 10_000 and above switch to K-suffix to keep the receipt compact.
        assert_eq!(format_number(10_000), "10.0K");
        assert_eq!(format_number(125_430), "125.4K");
    }

    #[test]
    fn format_number_millions() {
        assert_eq!(format_number(1_234_567), "1.2M");
    }

    #[test]
    fn env_flag_recognizes_true_values() {
        std::env::set_var("__AIKEY_TEST_FLAG", "1");
        assert!(env_flag("__AIKEY_TEST_FLAG"));
        std::env::set_var("__AIKEY_TEST_FLAG", "true");
        assert!(env_flag("__AIKEY_TEST_FLAG"));
        std::env::set_var("__AIKEY_TEST_FLAG", "0");
        assert!(!env_flag("__AIKEY_TEST_FLAG"));
        std::env::remove_var("__AIKEY_TEST_FLAG");
        assert!(!env_flag("__AIKEY_TEST_FLAG"));
    }

    #[test]
    fn format_age_buckets() {
        assert_eq!(format_age(Duration::from_secs(0)), "0s ago");
        assert_eq!(format_age(Duration::from_secs(45)), "45s ago");
        assert_eq!(format_age(Duration::from_secs(60)), "1m ago");
        assert_eq!(format_age(Duration::from_secs(3599)), "59m ago");
        assert_eq!(format_age(Duration::from_secs(3600)), "1h 0m ago");
        assert_eq!(format_age(Duration::from_secs(3661)), "1h 1m ago");
        assert_eq!(format_age(Duration::from_secs(86400)), "1d ago");
    }

    #[test]
    fn shorten_model_drops_claude_prefix_and_date() {
        assert_eq!(shorten_model("claude-sonnet-4-5-20250929"), "sonnet-4-5");
        assert_eq!(shorten_model("claude-sonnet-4-6"), "sonnet-4-6");
        assert_eq!(shorten_model("claude-opus-4-7"), "opus-4-7");
        assert_eq!(shorten_model("kimi-k2.5"), "kimi-k2.5");
        assert_eq!(shorten_model("moonshot-v1-128k"), "moonshot-v1-128k");
        assert_eq!(shorten_model(""), "");
        // 8-digit tail that isn't actually a date still gets trimmed — acceptable
        // tradeoff since no real model ID uses 8 trailing digits for anything else.
        assert_eq!(shorten_model("gpt-4-20241201"), "gpt-4");
    }

    #[test]
    fn shorten_label_collapses_long_email() {
        // Long email: keep prefix chars + … + @domain within budget.
        let out = shorten_label("eFOreadeblakeE96j@muslim.com", 22);
        assert!(out.ends_with("@muslim.com"), "should preserve domain: {out}");
        assert!(out.chars().count() <= 22, "should fit budget: {out}");
        assert!(out.starts_with("eFO"), "should keep local prefix: {out}");
        assert!(out.contains('…'));
    }

    #[test]
    fn shorten_label_passes_through_short() {
        assert_eq!(shorten_label("foo@bar.com", 22), "foo@bar.com");
        assert_eq!(shorten_label("alice@example.org", 22), "alice@example.org");
    }

    #[test]
    fn shorten_label_mid_ellipsis_for_non_email() {
        let out = shorten_label("very-long-non-email-label-xyzzy", 10);
        assert_eq!(out.chars().count(), 10);
        assert!(out.contains('…'));
    }

    #[test]
    fn event_time_hm_renders_local_clock_from_millis() {
        // event_time_hm now takes int64 millis and renders in the process's
        // local timezone (post bugfix 20260424). Exact "HH:MM" output depends
        // on the machine's TZ, so we assert the shape and the zero/edge cases.
        //
        // 2026-04-17T15:23:45Z = 1776439425000ms.
        let hm = event_time_hm(1776439425000);
        assert_eq!(hm.len(), 5, "expected HH:MM, got {hm:?}");
        assert_eq!(hm.as_bytes()[2], b':');
        assert!(hm[..2].chars().all(|c| c.is_ascii_digit()));
        assert!(hm[3..].chars().all(|c| c.is_ascii_digit()));

        // Zero / negative → empty (caller omits the tag).
        assert_eq!(event_time_hm(0), "");
        assert_eq!(event_time_hm(-1), "");
    }

    #[test]
    fn render_line_appends_refresh_timestamp() {
        let rendered = strip_ansi(&render_line(&ev("s", "claude-sonnet-4-6", "complete", 10, 5)));
        // The default ev() uses 1776439425000 millis (= 2026-04-17T15:23:45Z).
        // Post v1.0.3-alpha, event_time_hm renders in the test machine's
        // **local** timezone, so the exact HH:MM depends on TZ. We assert
        // the shape (5 chars, HH:MM, trailing the line) + the invariants
        // that parens are absent and seconds are dropped — the render
        // contract this test was protecting.
        // Extract last 5 chars safely (avoids slicing into multi-byte glyphs
        // like the ❬⦿·⦿❭ brand earlier in the line).
        let tail: String = rendered.chars().rev().take(5).collect::<Vec<char>>().into_iter().rev().collect();
        assert_eq!(tail.len(), 5, "render too short: {rendered}");
        let tb = tail.as_bytes();
        assert_eq!(tb[2], b':', "clock tail shape HH:MM: {rendered}");
        assert!(tb[0].is_ascii_digit() && tb[1].is_ascii_digit(), "clock HH digits: {rendered}");
        assert!(tb[3].is_ascii_digit() && tb[4].is_ascii_digit(), "clock MM digits: {rendered}");
        assert!(!rendered.contains("(:"), "no parens around clock");
        assert!(!rendered.contains(":45"), "seconds should be dropped");
    }

    #[test]
    fn render_line_shows_cache_breakdown_when_present() {
        // Layout (post 2026-04-20 cache reformat):
        //   ⇡70.1K ⇣153 · ↺53.1K ⊕32 · sonnet-4-6 · … · ❬⦿·⦿❭ 15:23
        // Parens and "hit"/"cache" words removed; `+` → `⊕` to avoid
        // misreading the segment as arithmetic `53.1K + 32`.
        let mut e = ev("s", "claude-sonnet-4-6", "complete", 70_100, 153);
        e.cache_read_input_tokens = Some(53_100);
        e.cache_creation_input_tokens = Some(32);
        let rendered = strip_ansi(&render_line(&e));
        assert!(rendered.contains("⇡70.1K"), "missing total input: {rendered}");
        assert!(rendered.contains("⇣153"), "missing output: {rendered}");
        // New compact form.
        assert!(rendered.contains("↺53.1K"), "missing cache-read: {rendered}");
        assert!(rendered.contains("⊕32"), "missing cache-creation: {rendered}");
        // Old form must not regress.
        assert!(!rendered.contains(" hit"), "word 'hit' was dropped: {rendered}");
        assert!(!rendered.contains(" cache)"), "'cache)' suffix was dropped: {rendered}");
        assert!(!rendered.contains("(↺"), "leading '(' around cache was dropped: {rendered}");
        assert!(!rendered.contains("+32 "), "bare '+' was replaced by '⊕': {rendered}");
    }

    #[test]
    fn render_line_omits_cache_segment_when_zero() {
        // Kimi-style event: cache fields absent → cache segment fully
        // omitted (no zero-filled `↺0 ⊕0` noise).
        let rendered = strip_ansi(&render_line(&ev("s", "kimi-k2.5", "complete", 8377, 11)));
        assert!(!rendered.contains("↺"), "should omit cache segment: {rendered}");
        assert!(!rendered.contains("⊕"), "should omit cache segment: {rendered}");
    }

    #[test]
    fn render_line_layout_brand_then_clock() {
        // Layout contract: brand `❬⦿·⦿❭` sits between the last data
        // segment (label) and the clock tail. The absolute last characters
        // on the line are the `HH:MM` clock (no parens, no trailing
        // chrome). Warnings (`⚠ partial` / `⚠ error`) stay at the head.
        //
        // These invariants are load-bearing:
        //   - A refactor that puts brand at tail must fail here.
        //   - A refactor that re-prepends brand (pre-Y2) must fail here.
        //   - A refactor that re-introduces parens around the clock must
        //     fail on `render_line_appends_refresh_timestamp`.
        let complete = strip_ansi(&render_line(&ev("s", "kimi-k2.5", "complete", 42, 9)));
        // Clock is the tail — shape HH:MM, exact value depends on the test
        // machine's local timezone (event_time_hm now renders locally).
        let tail: String = complete.chars().rev().take(5).collect::<Vec<char>>().into_iter().rev().collect();
        assert!(tail.len() == 5, "render too short: {complete}");
        let tb = tail.as_bytes();
        assert_eq!(tb[2], b':', "clock must be the true tail (HH:MM): {complete}");
        assert!(tb[0].is_ascii_digit() && tb[1].is_ascii_digit(), "HH digits: {complete}");
        assert!(tb[3].is_ascii_digit() && tb[4].is_ascii_digit(), "MM digits: {complete}");
        // Brand appears before the clock and after the last `·` segment.
        // Clock's exact HH:MM depends on local tz (renderer is now local),
        // so we anchor on the "HH:MM\0" shape at the end instead of a fixed
        // literal.
        let brand_idx = complete.find("❬⦿·⦿❭").expect("brand present");
        let clock_idx = complete.len() - 5;
        assert!(
            brand_idx < clock_idx,
            "brand must precede clock: {complete}"
        );
        // Brand is not leading any more.
        assert!(
            !complete.starts_with("❬⦿·⦿❭"),
            "brand must not lead the line: {complete}"
        );

        let partial = strip_ansi(&render_line(&ev("s", "kimi-k2.5", "partial", 42, 9)));
        assert!(
            partial.starts_with("⚠ partial"),
            "partial warning must be at the very front: {partial}"
        );
        // Tail is a HH:MM (local tz) — shape check only.
        let partial_tail: String = partial.chars().rev().take(5).collect::<Vec<char>>().into_iter().rev().collect();
        assert_eq!(partial_tail.len(), 5);
        assert_eq!(partial_tail.as_bytes()[2], b':', "clock stays at tail even on partial row: {partial}");
        assert!(
            partial.contains("❬⦿·⦿❭"),
            "brand must still appear between warning and clock: {partial}"
        );
    }

    #[test]
    fn render_line_tokens_come_first() {
        let rendered = render_line(&ev("s", "claude-sonnet-4-5", "complete", 3, 22));
        let plain: String = rendered.chars().filter(|c| *c >= ' ').collect::<String>()
            .replace("\u{1b}[0m", "")
            .replace("\u{1b}[36m", "").replace("\u{1b}[2m", "").replace("\u{1b}[1m", "");
        // Strip ANSI crudely by keeping visible sequence; assert structural order.
        let stripped = strip_ansi(&rendered);
        let up_idx = stripped.find("⇡").expect("⇡ present");
        let label_idx = stripped.find("aikey").unwrap_or(stripped.len());
        assert!(up_idx < label_idx, "tokens should render before label: {stripped}");
        assert!(stripped.contains("⇡3"));
        assert!(stripped.contains("⇣22"));
        let _ = plain; // silence warning about unused pre-stripped copy
    }

    fn strip_ansi(s: &str) -> String {
        // Minimal ANSI stripper — enough for these tests.
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if ('@'..='~').contains(&nc) { break; }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    // -----------------------------------------------------------------
    // Kimi Stop-hook helpers
    // -----------------------------------------------------------------

    #[test]
    fn tuple_gt_orders_file_then_seq() {
        // Different files → lexicographic on file wins, seq ignored.
        assert!(tuple_gt("wal-2026041817.jsonl", 1, "wal-2026041816.jsonl", 9999));
        assert!(!tuple_gt("wal-2026041816.jsonl", 9999, "wal-2026041817.jsonl", 1));
        // Same file → seq decides.
        assert!(tuple_gt("wal-2026041817.jsonl", 5, "wal-2026041817.jsonl", 4));
        assert!(!tuple_gt("wal-2026041817.jsonl", 4, "wal-2026041817.jsonl", 5));
        // Equal tuple is NOT greater — strict inequality.
        assert!(!tuple_gt("wal-2026041817.jsonl", 5, "wal-2026041817.jsonl", 5));
        // Minimum tuple ("", 0) compares less than any real file.
        assert!(tuple_gt("wal-2026041817.jsonl", 1, "", 0));
        assert!(!tuple_gt("", 0, "wal-2026041817.jsonl", 1));
    }

    #[test]
    fn kimi_session_dir_matches_kimi_cli_formula() {
        // kimi-cli computes the dir as ~/.kimi/sessions/<md5(cwd)>/<session_id>/.
        // Lock the md5 bytes we rely on with a known-good fixture.
        let path = kimi_session_dir("/Users/jake/Projects", "abc-123");
        let s = path.to_string_lossy();
        // Ends with the session id and contains /.kimi/sessions/.
        assert!(s.ends_with("/abc-123"), "missing session suffix: {s}");
        assert!(s.contains("/.kimi/sessions/"), "missing .kimi/sessions: {s}");
        // The md5 of "/Users/jake/Projects" must appear as a dir component.
        // md5("/Users/jake/Projects") computed independently.
        use md5::{Digest, Md5};
        let expect_hex: String = Md5::digest(b"/Users/jake/Projects")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(s.contains(&format!("/{expect_hex}/")), "md5 hex missing: {s}");
    }

    #[test]
    fn watermark_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "aikey-test-wm-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Absent → minimum tuple.
        let (f0, s0) = read_watermark_in(&dir, "sess-A");
        assert_eq!(f0, "");
        assert_eq!(s0, 0);

        // Write & read back.
        write_watermark_in(&dir, "sess-A", "wal-2026041817.jsonl", 42).unwrap();
        let (f1, s1) = read_watermark_in(&dir, "sess-A");
        assert_eq!(f1, "wal-2026041817.jsonl");
        assert_eq!(s1, 42);

        // Overwrite keeps atomicity (no .tmp leftover).
        write_watermark_in(&dir, "sess-A", "wal-2026041818.jsonl", 7).unwrap();
        let (f2, s2) = read_watermark_in(&dir, "sess-A");
        assert_eq!(f2, "wal-2026041818.jsonl");
        assert_eq!(s2, 7);
        assert!(
            !dir.join("sess-A.watermark.tmp").exists(),
            "tmp file should be rename-consumed"
        );

        // Sessions are isolated by file name.
        let (fo, so) = read_watermark_in(&dir, "sess-B");
        assert_eq!(fo, "");
        assert_eq!(so, 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn watermark_malformed_fail_closes_to_default() {
        // Fail-closed contract (review finding #2, 2026-04-20): every
        // corruption mode must return ("", 0). Previously we partially
        // trusted broken content, which could poison tuple_gt and
        // silently suppress future receipts. The worst case with the
        // new contract is one extra at-least-once replay — always safe.
        let dir = std::env::temp_dir().join(format!(
            "aikey-test-wm-bad-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let cases: &[(&str, &str)] = &[
            ("no-tab", "garbage-without-tab"),
            ("empty-file", ""),
            ("tab-only", "\t"),
            ("missing-seq", "wal-2026042017.jsonl\t"),
            ("non-numeric-seq", "wal-2026042017.jsonl\tnot-a-number"),
            ("negative-seq", "wal-2026042017.jsonl\t-5"),
            ("empty-file-name", "\t42"),
            ("float-seq", "wal-2026042017.jsonl\t3.14"),
        ];

        for (label, content) in cases {
            let path = dir.join(format!("sess-{label}.watermark"));
            std::fs::write(&path, content).unwrap();
            let got = read_watermark_in(&dir, &format!("sess-{label}"));
            assert_eq!(
                got,
                (String::new(), 0),
                "malformed watermark {label:?} ({content:?}) must fail-close to default, got {got:?}"
            );
        }

        // Positive control: a well-formed file still round-trips.
        std::fs::write(
            dir.join("sess-good.watermark"),
            "wal-2026042017.jsonl\t42",
        )
        .unwrap();
        let (f, s) = read_watermark_in(&dir, "sess-good");
        assert_eq!(f, "wal-2026042017.jsonl");
        assert_eq!(s, 42);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gc_removes_stale_files_only() {
        let dir = std::env::temp_dir().join(format!(
            "aikey-test-gc-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Fresh file — must survive.
        write_watermark_in(&dir, "fresh", "wal.jsonl", 1).unwrap();

        // Stale file — age mtime to 10 days ago via utimensat (libc).
        let stale = dir.join("stale.watermark");
        std::fs::write(&stale, "old\t1").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let c_path = std::ffi::CString::new(stale.as_os_str().as_bytes()).unwrap();
            let ten_days_ago = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 10 * 24 * 3600;
            let ts = libc::timespec {
                tv_sec: ten_days_ago as libc::time_t,
                tv_nsec: 0,
            };
            let times = [ts, ts];
            // SAFETY: C FFI, path and times are valid for the call duration.
            unsafe {
                libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0);
            }
        }

        gc_stale_watermarks_in(&dir).unwrap();

        assert!(dir.join("fresh.watermark").exists(), "fresh file should survive GC");
        #[cfg(unix)]
        assert!(!stale.exists(), "stale file should be purged by GC");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strip_ansi_escapes_drops_csi_keeps_text() {
        let s = "\u{1b}[1;36m⇡42\u{1b}[0m tokens \u{1b}[2m(12:34)\u{1b}[0m";
        let out = strip_ansi_escapes(s);
        assert_eq!(out, "⇡42 tokens (12:34)");
    }

    #[test]
    fn strip_ansi_escapes_no_escape_is_identity() {
        assert_eq!(strip_ansi_escapes("plain 1,234 ⇡⇣"), "plain 1,234 ⇡⇣");
        assert_eq!(strip_ansi_escapes(""), "");
    }

    #[test]
    fn notification_publish_is_directory_atomic_no_staging_leftover() {
        // Fixes the race where Kimi could poll between event.json and
        // delivery.json renames and see a half-published notification.
        // With staging-dir publication, the final dir appears atomically
        // and the `.<id>.staging` leftover must not survive a successful
        // publish. (Regression guard for review finding #2.)
        let session_dir = std::env::temp_dir().join(format!(
            "aikey-test-atomic-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&session_dir).unwrap();

        write_kimi_notification(&session_dir, "sess-atomic", "⇡1 ⇣2 · m", 1).unwrap();

        let notifs_root = session_dir.join("notifications");
        let entries: Vec<_> = std::fs::read_dir(&notifs_root)
            .unwrap()
            .filter_map(Result::ok)
            .collect();

        // Exactly one entry, and it MUST NOT be the staging form.
        assert_eq!(entries.len(), 1, "one published dir expected");
        let name = entries[0].file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with('.') && !name.ends_with(".staging"),
            "staging dir should have been renamed to final form, got: {name}"
        );
        // And both files must be present in it (proving the rename happened
        // AFTER both writes, not between them).
        assert!(entries[0].path().join("event.json").exists());
        assert!(entries[0].path().join("delivery.json").exists());

        std::fs::remove_dir_all(&session_dir).ok();
    }

    #[test]
    fn notification_writes_event_and_delivery_with_shell_only_target() {
        let session_dir = std::env::temp_dir().join(format!(
            "aikey-test-notif-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&session_dir).unwrap();

        write_kimi_notification(&session_dir, "sess-7", "⇡42 ⇣9 · sonnet-4-6", 3).unwrap();

        // Exactly one notification dir under notifications/, named n + 8 hex.
        let notifs_root = session_dir.join("notifications");
        let mut entries: Vec<_> = std::fs::read_dir(&notifs_root)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "one notification dir expected");
        let entry = entries.pop().unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            name.len() == 9 && name.starts_with('n'),
            "id should be n + 8 hex: {name}"
        );
        assert!(
            name.chars().skip(1).all(|c| c.is_ascii_hexdigit()),
            "id body should be hex: {name}"
        );

        // event.json parses and has targets=["shell"] only (CRITICAL — "llm"
        // would cause kimi-cli to feed the toast back into the LLM context).
        let event_raw = std::fs::read_to_string(entry.path().join("event.json")).unwrap();
        let event: serde_json::Value = serde_json::from_str(&event_raw).unwrap();
        assert_eq!(event["version"], 1);
        assert_eq!(event["category"], "system");
        assert_eq!(event["type"], "receipt");
        assert_eq!(event["source_kind"], "aikey");
        assert_eq!(event["severity"], "info");
        assert_eq!(event["title"], "⇡42 ⇣9 · sonnet-4-6");
        let targets = event["targets"].as_array().expect("targets array");
        assert_eq!(targets.len(), 1, "exactly one target");
        assert_eq!(targets[0], "shell", "must be shell (never llm)");
        assert_eq!(event["payload"]["session_id"], "sess-7");
        assert_eq!(event["payload"]["events_folded"], 3);

        // delivery.json has a single shell sink in pending state.
        let delivery_raw =
            std::fs::read_to_string(entry.path().join("delivery.json")).unwrap();
        let delivery: serde_json::Value = serde_json::from_str(&delivery_raw).unwrap();
        assert_eq!(delivery["sinks"]["shell"]["status"], "pending");
        assert!(delivery["sinks"]["shell"]["claimed_at"].is_null());
        assert!(delivery["sinks"]["shell"]["acked_at"].is_null());

        // No tmp files left behind.
        assert!(!entry.path().join("event.json.tmp").exists());
        assert!(!entry.path().join("delivery.json.tmp").exists());

        std::fs::remove_dir_all(&session_dir).ok();
    }
}
