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

use crate::usage_wal::{default_wal_dir, scan_wal_backward, ScanOptions, UsageEvent};

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

    let line = render_line(&ev);
    let mut out = io::stdout().lock();
    out.write_all(line.as_bytes())?;
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
        max_age: Duration::from_secs(24 * 3600),
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
    //   ↺ (cyclic) for cache-read "hits"  → tokens replayed from server cache
    //   + (plus)   for cache-creation     → tokens newly added to the cache
    // Rendered one brightness tier dimmer than the main tokens since it's
    // supplementary detail, not a primary metric.
    let cache_read = ev.cache_read_input_tokens.unwrap_or(0);
    let cache_write = ev.cache_creation_input_tokens.unwrap_or(0);
    let cache_seg = if cache_read > 0 || cache_write > 0 {
        let body = format!(
            "(↺{} hit · +{} cache)",
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
    let ts = event_time_hm(&ev.event_time);

    // Assemble with separators only between non-empty segments so we never
    // get "↑3 ↓22 ·  · sonnet-4-6" when a section is missing. Timestamp
    // uses the same `·` glyph as the other boundaries so the tail doesn't
    // appear orphaned by a bare space.
    let mut parts: Vec<String> = Vec::with_capacity(5);
    parts.push(format!("{up}{in_s} {down}{out_s}"));
    if !cache_seg.is_empty() { parts.push(cache_seg); }
    if !model.is_empty() { parts.push(format!("{}", model.dimmed())); }
    if !label.is_empty() { parts.push(format!("{}", label.dimmed())); }
    if !ts.is_empty() { parts.push(format!("{}", format!("({ts})").dimmed())); }

    format!("{prefix}{}", parts.join(&format!("{}", sep)))
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
/// Returns "" when the input doesn't look like RFC3339 — the caller then
/// omits the tag rather than showing garbage.
fn event_time_hm(ts: &str) -> String {
    if ts.len() < 16 { return String::new(); }
    let bytes = ts.as_bytes();
    // Sanity-check separators so "garbage-long-enough-to-pass" doesn't sneak through.
    if bytes[10] != b'T' && bytes[10] != b' ' { return String::new(); }
    if bytes[13] != b':' { return String::new(); }
    ts[11..16].to_string()
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

/// `aikey statusline install [--force]` entry point — always verbose.
pub fn install(force: bool) -> io::Result<InstallOutcome> {
    install_inner(force, /*quiet=*/ false)
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

/// `aikey statusline uninstall`.
pub fn uninstall() -> io::Result<()> {
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

/// `aikey statusline status` — print whether aikey owns the Claude Code
/// statusLine entry, without making any changes.
pub fn print_status() -> io::Result<()> {
    use colored::Colorize;
    let Some(settings_path) = claude_settings_path() else {
        println!("Claude Code config dir not resolvable (HOME unset?).");
        return Ok(());
    };

    let exists = settings_path.exists();
    let parsed = match read_settings(&settings_path) {
        Ok(v) => Some(v),
        Err(ReadError::NotFound) => None,
        Err(ReadError::Malformed(e)) => {
            println!("settings.json exists but cannot be parsed: {}", e);
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
            println!("  {}: {}", "statusLine".dimmed(), format!("aikey ({})", c).green());
        }
        Some(c) => {
            println!("  {}: {}", "statusLine".dimmed(), format!("other ({})", c).yellow());
        }
    }
    let backup = statusline_backup_path(&settings_path);
    if backup.exists() {
        println!("  {}: {}", "backup".dimmed(), backup.display());
    }
    Ok(())
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

/// Absolute path to the current binary, quoted as a shell command, falling
/// back to just "aikey" if we can't resolve the path (e.g. on platforms
/// where `current_exe()` fails).  Absolute paths are preferred so Claude
/// Code doesn't depend on the user's PATH at statusline-invocation time.
fn aikey_statusline_command() -> String {
    match std::env::current_exe() {
        Ok(p) => {
            let s = p.display().to_string();
            // Wrap in double quotes if the path contains spaces so Claude
            // Code's shell invocation doesn't split the command by spaces.
            if s.chars().any(char::is_whitespace) {
                format!("\"{}\" statusline", s.replace('"', "\\\""))
            } else {
                format!("{} statusline", s)
            }
        }
        Err(_) => "aikey statusline".to_string(),
    }
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
            event_time: "2026-04-17T15:23:45Z".into(),
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
    fn event_time_hm_extracts_clock_segment() {
        assert_eq!(event_time_hm("2026-04-18T12:49:25.009699+08:00"), "12:49");
        assert_eq!(event_time_hm("2026-04-18T00:00:00Z"), "00:00");
        assert_eq!(event_time_hm("2026-04-18 23:59:59"), "23:59");
        assert_eq!(event_time_hm("2026-04-18T12:49"), "12:49");  // minimum length
        // Malformed / too short → empty, caller omits the tag.
        assert_eq!(event_time_hm(""), "");
        assert_eq!(event_time_hm("not-a-time"), "");
        assert_eq!(event_time_hm("2026-04-18X12:49:25Z"), "");  // bad separator
        assert_eq!(event_time_hm("2026-04-18T12-49:25Z"), "");  // bad colon
    }

    #[test]
    fn render_line_appends_refresh_timestamp() {
        let rendered = strip_ansi(&render_line(&ev("s", "claude-sonnet-4-6", "complete", 10, 5)));
        // The default ev() uses "2026-04-17T15:23:45Z" — tag shows HH:MM only.
        assert!(rendered.contains("(15:23)"), "missing timestamp tag: {rendered}");
        assert!(!rendered.contains("(15:23:45)"), "seconds should be dropped: {rendered}");
    }

    #[test]
    fn render_line_shows_cache_breakdown_when_present() {
        let mut e = ev("s", "claude-sonnet-4-6", "complete", 70_100, 153);
        e.cache_read_input_tokens = Some(53_100);
        e.cache_creation_input_tokens = Some(32);
        let rendered = strip_ansi(&render_line(&e));
        assert!(rendered.contains("⇡70.1K"), "missing total input: {rendered}");
        assert!(rendered.contains("⇣153"), "missing output: {rendered}");
        // Cache glyphs chosen to NOT imply bidirectional flow (both fields
        // are input-side counts; ↺ = replayed, + = newly stored).
        assert!(rendered.contains("↺53.1K hit"), "missing cache-read (hit): {rendered}");
        assert!(rendered.contains("+32 cache"), "missing cache-creation: {rendered}");
    }

    #[test]
    fn render_line_omits_cache_segment_when_zero() {
        // Kimi-style event: cache fields absent → no parenthetical.
        let rendered = strip_ansi(&render_line(&ev("s", "kimi-k2.5", "complete", 8377, 11)));
        assert!(!rendered.contains(" hit"), "should omit cache segment: {rendered}");
        assert!(!rendered.contains("↺"), "should omit cache segment: {rendered}");
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
}
