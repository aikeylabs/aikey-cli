//! Shell hook installation and third-party CLI auto-configuration helpers.
//!
//! Extracted from `commands_account.rs` — pure structural refactor, no logic changes.

use std::io;
use std::path::Path;

// ---------------------------------------------------------------------------
// Kimi CLI auto-configuration
// ---------------------------------------------------------------------------
//
// Ownership model (费用小票-Kimi集成.md §2):
//   A single contiguous marker region `# BEGIN aikey …` / `# END aikey`
//   wraps ALL aikey-managed TOML:
//     - [providers.kimi]
//     - [models.kimi-k2-5] + [models.moonshot-v1-128k]
//     - [[hooks]] Stop → `aikey statusline render kimi`
//
// Why one region: the Stop hook and the provider block share one lifecycle
// (both belong to "aikey manages Kimi"). Split ownership caused double-write
// bugs in the previous design.  Uninstall strips the whole region
// atomically — this also resets the provider, which is documented behavior.
//
// Legacy marker `# managed by aikey` (single-line, per-block) is still
// detected and migrated: if a backup exists we restore it before appending
// the new region; otherwise we leave the old blocks intact and append — the
// user can reconcile manually if Kimi rejects duplicate keys.

const AIKEY_BEGIN: &str = "# BEGIN aikey (do not hand-edit between markers)";
const AIKEY_END: &str = "# END aikey";
const LEGACY_MARKER: &str = "# managed by aikey";

/// Build the aikey-managed Kimi config region (hook-only minimal scaffold).
///
/// Why hook-only: Kimi CLI reads `KIMI_API_KEY` / `KIMI_BASE_URL` /
/// `KIMI_MODEL_NAME` / `KIMI_MODEL_MAX_CONTEXT_SIZE` env vars that override
/// config file values ([llm.py augment_provider_with_env_vars]). With all four
/// env vars set by `aikey use`, Kimi's in-code fallback at
/// [app.py:177-185](https://github.com/MoonshotAI/kimi-cli) creates an empty
/// LLMModel/LLMProvider and the env vars populate every field — no config
/// entries needed for providers or models.
///
/// The `[[hooks]]` Stop entry is the ONLY thing that genuinely requires
/// file-backed storage — Kimi has no env var equivalent for hooks. Everything
/// else is moved to env vars (see `provider_extra_env_vars` + active.env
/// writers), giving us the minimum possible write footprint against the
/// user's `~/.kimi/config.toml`.
///
/// Proxy port is carried as a parameter because the hook command resolved at
/// build time depends on the aikey binary absolute path (which is derived
/// from `current_exe()` independently of proxy_port). The proxy port is no
/// longer embedded in this region — it's only referenced via env vars.
fn build_kimi_managed_region(_proxy_port: u16) -> String {
    let hook_cmd = crate::commands_statusline::aikey_statusline_render_kimi_command();
    format!(
        "{begin}\n\
[[hooks]]\n\
event = \"Stop\"\n\
command = \"{cmd}\"\n\
timeout = 5\n\
{end}",
        begin = AIKEY_BEGIN,
        cmd = hook_cmd,
        end = AIKEY_END,
    )
}

/// Strip `default_model = "..."` lines at the top-level (outside any table)
/// that were originally written by old aikey versions when the scaffold still
/// included `[models.kimi-k2-5]`. After shrinking the region to hooks-only,
/// a leftover `default_model = "kimi-k2-5"` line would fail Kimi's
/// cross-validation (Default model not found in models).
///
/// Conservative: only strip if the value matches the known aikey defaults
/// (`kimi-k2-5`, `moonshot-v1-128k`). User-chosen values (e.g. `kimi-dev`)
/// are preserved — we assume they wrote those themselves.
fn strip_legacy_kimi_default_model(content: &str) -> String {
    const AIKEY_LEGACY_DEFAULTS: &[&str] = &["kimi-k2-5", "moonshot-v1-128k"];
    let mut out = String::with_capacity(content.len());
    let mut seen_table = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            seen_table = true;
        }
        // Only strip if: before any [table] header, AND matches `default_model = "<legacy>"`.
        // Inside a table, `default_model` could be a sub-key (e.g. `[something]\ndefault_model = ...`)
        // and we shouldn't touch those.
        let is_our_legacy = !seen_table
            && trimmed.starts_with("default_model")
            && AIKEY_LEGACY_DEFAULTS
                .iter()
                .any(|v| trimmed.contains(&format!("= \"{}\"", v)) || trimmed.contains(&format!("=\"{}\"", v)));
        if is_our_legacy {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Replace the aikey-managed region in place. Returns `None` if no region
/// was found (caller handles that as first-time install).
fn replace_managed_region(content: &str, new_region: &str) -> Option<String> {
    let begin = content.find(AIKEY_BEGIN)?;
    let end_rel = content[begin..].find(AIKEY_END)?;
    let end = begin + end_rel + AIKEY_END.len();
    let mut out = String::with_capacity(content.len() + new_region.len());
    out.push_str(&content[..begin]);
    out.push_str(new_region);
    out.push_str(&content[end..]);
    Some(out)
}

/// Strip the aikey-managed region (plus one trailing newline, if any) and
/// return the remainder. Returns `None` if no region was found.
fn strip_managed_region(content: &str) -> Option<String> {
    let begin = content.find(AIKEY_BEGIN)?;
    let end_rel = content[begin..].find(AIKEY_END)?;
    let mut end = begin + end_rel + AIKEY_END.len();
    if content.as_bytes().get(end) == Some(&b'\n') {
        end += 1;
    }
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..begin]);
    out.push_str(&content[end..]);
    Some(out)
}

/// Atomic write: tmp file in same dir + rename. Returns the io::Result so
/// the caller can report failure visibly on first-time install.
fn write_config_atomic(config_dir: &Path, config_path: &Path, contents: &str) -> io::Result<()> {
    std::fs::create_dir_all(config_dir)?;
    let tmp = config_dir.join("config.toml.aikey.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, config_path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KimiUninstallOutcome {
    Removed,
    NothingToRemove,
    HomeMissing,
}

/// Thin wrapper around `unconfigure_kimi_cli` that reports whether anything
/// actually changed, for consistent top-level CLI output.
pub(crate) fn uninstall_kimi_hook() -> KimiUninstallOutcome {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return KimiUninstallOutcome::HomeMissing,
    };
    let config_path = std::path::PathBuf::from(&home)
        .join(".kimi")
        .join("config.toml");
    let backup_path = std::path::PathBuf::from(&home)
        .join(".kimi")
        .join("config.aikey_backup.toml");

    let had_region = std::fs::read_to_string(&config_path)
        .map(|c| c.contains(AIKEY_BEGIN) || c.contains(LEGACY_MARKER))
        .unwrap_or(false);
    let had_backup = backup_path.exists();

    if !had_region && !had_backup {
        return KimiUninstallOutcome::NothingToRemove;
    }

    unconfigure_kimi_cli();
    KimiUninstallOutcome::Removed
}

/// Inspect the current Kimi config state for `aikey statusline status`. Does
/// not modify anything. Returns (region_present, hook_command_matches_this_bin).
pub(crate) fn kimi_status() -> (bool, bool) {
    let Ok(home) = std::env::var("HOME") else { return (false, false); };
    let config_path = std::path::PathBuf::from(&home)
        .join(".kimi")
        .join("config.toml");
    let Ok(content) = std::fs::read_to_string(&config_path) else {
        return (false, false);
    };
    if !content.contains(AIKEY_BEGIN) {
        return (false, false);
    }
    let expected = crate::commands_statusline::aikey_statusline_render_kimi_command();
    let hook_present = content.contains(&format!("command = \"{expected}\""));
    (true, hook_present)
}

/// Ensure the aikey-managed scaffold exists in `~/.kimi/config.toml`.
///
/// Writes the region only if absent or content-drifted — subsequent `aikey use`
/// calls are no-ops, because the region is token-agnostic (token overrides
/// via `KIMI_API_KEY` env var at runtime). See `build_kimi_managed_region`
/// docstring for why the scaffold is necessary at all.
pub fn configure_kimi_cli(proxy_port: u16) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".kimi");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    let region = build_kimi_managed_region(proxy_port);

    let has_region = existing.contains(AIKEY_BEGIN);
    let has_legacy_only = !has_region && existing.contains(LEGACY_MARKER);

    // Build the desired file contents for each of the three code paths.
    let (desired, first_time) = if has_region {
        // Managed region already present — in-place replace (no prompt).
        // Also strip any legacy `default_model = "<old-aikey-default>"` at the
        // top level. Older aikey versions wrote `default_model = "kimi-k2-5"`
        // outside the region assuming `[models.kimi-k2-5]` existed inside;
        // with the hook-only region, that reference would fail Kimi validation.
        match replace_managed_region(&existing, &region) {
            Some(s) => (strip_legacy_kimi_default_model(&s), false),
            None => return, // defensive; should be unreachable because has_region is true
        }
    } else if has_legacy_only {
        // Legacy upgrade path: user has the old `# managed by aikey` single-line
        // marker but not the new AIKEY_BEGIN region. Strategy:
        //
        // 1. If a backup exists → restore it wholesale, then append fresh region.
        //    This is the clean path and leaves no duplicate TOML keys.
        //
        // 2. Otherwise → strip any line containing the legacy marker before
        //    appending. Without this strip, the legacy provider/model blocks
        //    remain and Kimi's TOML parser rejects the duplicate `[providers.kimi]`
        //    key. The strip is conservative: we only drop lines that explicitly
        //    carry the `# managed by aikey` marker (aikey never wrote those
        //    lines without the marker), preserving any user-added content in
        //    between.
        let (base, stripped_legacy) = match std::fs::read_to_string(&backup_path) {
            Ok(s) => (s, false),
            Err(_) => {
                let sanitized: String = existing
                    .lines()
                    .filter(|l| !l.contains(LEGACY_MARKER))
                    .collect::<Vec<_>>()
                    .join("\n");
                (sanitized, true)
            }
        };
        let mut out = base.trim_end().to_string();
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(&region);
        out.push('\n');
        if stripped_legacy && io::stderr().is_terminal() {
            use colored::Colorize;
            eprintln!(
                "  {} Legacy `# managed by aikey` lines removed before adding new region.",
                "!".yellow()
            );
            eprintln!(
                "    {}",
                "(No backup found; duplicate-key conflict prevented.)".dimmed()
            );
        }
        (out, false)
    } else {
        // First-time install — prompt (TTY only), then backup + append.
        //
        // Hook-only region: we no longer write `[providers.kimi]`, `[models.*]`,
        // or `default_model`. All of those are driven by env vars set in
        // active.env (see `provider_extra_env_vars` for the KIMI_MODEL_NAME /
        // KIMI_MODEL_MAX_CONTEXT_SIZE pairs). Only `[[hooks]]` Stop genuinely
        // requires file-backed storage.
        if io::stderr().is_terminal() {
            let rows: Vec<String> = {
                let mut r = vec![
                    format!("File:    {}", "~/.kimi/config.toml"),
                    format!("Add:     Stop hook → aikey statusline render kimi"),
                    format!("         (provider/models come from env vars)"),
                ];
                if !existing.is_empty() {
                    r.push(format!("Backup:  {}", "~/.kimi/config.aikey_backup.toml"));
                }
                r
            };
            crate::ui_frame::eprint_box("\u{2753}", "Configure Kimi CLI", &rows);
            eprint!("  Proceed? [Y/n] (default Y): ");
            io::stderr().flush().ok();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_ok()
                && input.trim().eq_ignore_ascii_case("n")
            {
                eprintln!("  {}", "Skipped. Run 'aikey use kimi' again to retry.".dimmed());
                return;
            }
        }

        if !existing.is_empty() && !backup_path.exists() {
            let _ = std::fs::create_dir_all(&config_dir);
            let _ = std::fs::copy(&config_path, &backup_path);
        }

        let mut out = existing.trim_end().to_string();
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(&region);
        out.push('\n');
        (out, true)
    };

    // Idempotent: nothing to do if the file is already what we want.
    if desired == existing {
        return;
    }

    match write_config_atomic(&config_dir, &config_path, &desired) {
        Ok(_) => {
            if first_time && io::stderr().is_terminal() {
                eprintln!(
                    "  {} Kimi CLI auto-configured: {}",
                    "✓".green().bold(),
                    config_path.display().to_string().dimmed()
                );
            }
        }
        Err(e) => {
            if first_time && io::stderr().is_terminal() {
                eprintln!("  {} Could not configure Kimi CLI: {}", "!".yellow(), e);
            }
        }
    }
}

/// Revert `~/.kimi/config.toml` to its pre-aikey state.
///
/// Priority: (1) restore `config.aikey_backup.toml` wholesale; (2) failing
/// that, strip the `# BEGIN aikey …` region; (3) legacy fallback — if the
/// file only contains old-style marker lines AND nothing else useful, drop
/// the file entirely.
///
/// **Asymmetry with Claude uninstall**: because provider + hook share a
/// managed region, uninstall resets the Kimi provider to whatever was in the
/// backup (or nothing). This is documented behavior — users who want to keep
/// the provider but drop only the hook must hand-edit the hooks block out of
/// the marker region.
pub fn unconfigure_kimi_cli() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".kimi");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    // Path 1: backup exists — rename overwrites atomically.
    if backup_path.exists() {
        let _ = std::fs::rename(&backup_path, &config_path);
        return;
    }

    let Ok(content) = std::fs::read_to_string(&config_path) else { return };

    // Path 2: strip the new-style managed region if present.
    if let Some(stripped) = strip_managed_region(&content) {
        let cleaned = stripped.trim_end().to_string();
        if cleaned.is_empty() {
            let _ = std::fs::remove_file(&config_path);
        } else {
            let mut with_nl = cleaned;
            with_nl.push('\n');
            let _ = write_config_atomic(&config_dir, &config_path, &with_nl);
        }
        return;
    }

    // Path 3: legacy fallback — file has old-style marker but no region.
    // We created the file from scratch when installing the old-style
    // config, so drop it wholesale to return Kimi to defaults.
    if content.contains(LEGACY_MARKER) {
        let _ = std::fs::remove_file(&config_path);
    }
}

// ============================================================================
// Codex CLI auto-configuration
// ============================================================================

// Codex integration strategy (see workflow/CI/bugfix/2026-04-20-codex-integration-env-var-routing.md):
//
// Codex v0.120+ built-in `openai` provider has `env_key: None` — it does NOT
// read `OPENAI_API_KEY` at request time. Auth goes through `~/.codex/auth.json`
// (ChatGPT OAuth token or piped API key). Also `OPENAI_BASE_URL` env var is not
// supported at all (only `openai_base_url` in config.toml).
//
// To get true per-shell Kimi-style isolation, we define a custom provider
// `[model_providers.aikey]` with `env_key = "OPENAI_API_KEY"`. Codex reads the
// env var at each request, so each shell's `OPENAI_API_KEY` (set by `aikey use` /
// `aikey activate`) routes independently through the local proxy.
//
// File structure we write (three pieces):
//   1. Line: `openai_base_url = "..."  # managed by aikey`  (legacy back-compat)
//   2. Line: `model_provider = "aikey"  # managed by aikey`  (conditional — see below)
//   3. Region at end of file:
//        # BEGIN aikey (do not hand-edit between markers)
//        [model_providers.aikey]
//        name = "aikey"
//        base_url = "..."
//        env_key = "OPENAI_API_KEY"
//        wire_api = "responses"
//        requires_openai_auth = false
//        # END aikey
//
// Why split across region + two single-line markers: TOML forbids top-level
// keys from appearing after any `[table]` header. `[model_providers.aikey]`
// is a table, but `openai_base_url` / `model_provider` are top-level scalars —
// they must live above all tables. We put the single-line markers near the top
// of the file (line-level idempotence) and the table in a region at the end.
//
// Conditional `model_provider` write: only overwrite if the user hasn't set a
// non-default, non-aikey provider (e.g. `model_provider = "ollama"`). If a
// conflict is detected, we skip the line and print a stderr hint so the user
// can resolve it manually without silently breaking their setup.

const CODEX_LINE_MARKER: &str = "# managed by aikey";

fn build_codex_managed_region(proxy_port: u16) -> String {
    let base_url = format!("http://127.0.0.1:{}/openai", proxy_port);
    format!(
        "{begin}\n\
[model_providers.aikey]\n\
name = \"aikey\"\n\
base_url = \"{base_url}\"\n\
env_key = \"OPENAI_API_KEY\"\n\
wire_api = \"responses\"\n\
requires_openai_auth = false\n\
{end}",
        begin = AIKEY_BEGIN,
        end = AIKEY_END,
    )
}

/// Insert or replace a single-line TOML top-level key with an aikey marker.
///
/// Safe to call repeatedly — if the line already exists (with or without our
/// marker) it's replaced in place. Otherwise inserted at the TOML-safe
/// position: immediately before the first `[table]` header (or at end of file
/// if there are no tables), which guarantees the key stays in the top-level
/// scope.
fn upsert_codex_managed_line(content: &str, key: &str, value: &str) -> String {
    let new_line = format!("{} = \"{}\"  {}", key, value, CODEX_LINE_MARKER);
    let key_prefix = format!("{} ", key);
    let key_eq = format!("{}=", key);

    // Pass 1: replace in place if the key already exists at top level.
    //
    // Note: we don't attempt to detect whether the existing key is inside a
    // table scope. If the user put `model_provider = "..."` inside some table
    // (which would actually be a subkey of that table, not our target), we
    // may replace the wrong line. Accept this as a known limitation —
    // legitimate Codex configs use top-level-only for these keys.
    if content
        .lines()
        .any(|l| l.trim_start().starts_with(&key_prefix) || l.trim_start().starts_with(&key_eq))
    {
        let mut out = String::new();
        for line in content.lines() {
            if line.trim_start().starts_with(&key_prefix) || line.trim_start().starts_with(&key_eq)
            {
                out.push_str(&new_line);
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
        return out;
    }

    if content.is_empty() {
        return format!("{}\n", new_line);
    }

    // Pass 2: insert. Find the first `[table]` header line index; insert at
    // that position (which places our new line in the top-level scope just
    // before any tables). If no table exists, append at end — still top-level.
    let lines: Vec<&str> = content.lines().collect();
    let insert_at = lines
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .unwrap_or(lines.len());

    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx == insert_at {
            out.push_str(&new_line);
            out.push('\n');
        }
        out.push_str(line);
        out.push('\n');
    }
    if insert_at >= lines.len() {
        out.push_str(&new_line);
        out.push('\n');
    }
    out
}

/// Append (or replace) the aikey-managed `[model_providers.aikey]` region at
/// the END of the content. Must come after all user tables because TOML table
/// sections don't terminate — anything we append inside a "user table scope"
/// would bind to the wrong table.
fn upsert_codex_region(content: &str, new_region: &str) -> String {
    if content.contains(AIKEY_BEGIN) {
        return replace_managed_region(content, new_region)
            .unwrap_or_else(|| content.to_string());
    }
    let mut out = content.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(new_region);
    out.push('\n');
    out
}

/// Detect whether the user has set a non-default `model_provider` that we
/// should NOT overwrite. Returns `Some(value)` if there's a real conflict.
///
/// Safe-to-overwrite cases (returns None):
/// - No `model_provider` line at all
/// - `model_provider = "openai"` (Codex default — overwriting is a no-op intent change)
/// - `model_provider = "aikey"` (our own past write)
/// - Any `model_provider` line with our `# managed by aikey` marker
fn detect_codex_model_provider_conflict(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("model_provider") {
            continue;
        }
        let after_key = trimmed["model_provider".len()..].trim_start();
        let after_eq = match after_key.strip_prefix('=') {
            Some(s) => s.trim_start(),
            None => continue,
        };
        let rest = match after_eq.strip_prefix('"') {
            Some(s) => s,
            None => continue,
        };
        let end = match rest.find('"') {
            Some(i) => i,
            None => continue,
        };
        let value = &rest[..end];
        if line.contains(CODEX_LINE_MARKER) || value == "openai" || value == "aikey" {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

/// Auto-configure `~/.codex/config.toml` so Codex routes OpenAI requests
/// through aikey's local proxy with per-shell token isolation via env var.
///
/// Idempotent: repeated calls with no config change are safe (short-circuits
/// on `desired == existing`).
pub fn configure_codex_cli(proxy_port: u16) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".codex");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    let base_url = format!("http://127.0.0.1:{}/openai", proxy_port);
    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    let region = build_codex_managed_region(proxy_port);

    let has_region = existing.contains(AIKEY_BEGIN);
    let has_any_marker = existing.contains(CODEX_LINE_MARKER) || has_region;

    // First-time install → prompt (TTY only) + backup.
    let first_time = !has_any_marker;
    if first_time && io::stderr().is_terminal() {
        let mut rows: Vec<String> = vec![
            format!("File:    {}", "~/.codex/config.toml"),
            format!("Add:     openai_base_url + [model_providers.aikey]"),
            format!("         env_key = \"OPENAI_API_KEY\" (per-shell token)"),
        ];
        if !existing.is_empty() {
            rows.push(format!("Backup:  {}", "~/.codex/config.aikey_backup.toml"));
        }
        crate::ui_frame::eprint_box("\u{2753}", "Configure Codex CLI", &rows);
        eprint!("  Proceed? [Y/n] (default Y): ");
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok()
            && input.trim().eq_ignore_ascii_case("n")
        {
            eprintln!("  {}", "Skipped. Run 'aikey use' again to retry.".dimmed());
            return;
        }
    }

    // Build desired content via the three upsert passes.
    let mut desired = existing.clone();
    desired = upsert_codex_managed_line(&desired, "openai_base_url", &base_url);

    // model_provider: conditional on conflict detection. `desired` at this
    // point already has `openai_base_url` added but model_provider detection
    // looks at existing-like lines by key, so order is fine.
    let conflict = detect_codex_model_provider_conflict(&desired);
    let model_provider_written = if let Some(other) = conflict {
        // Print the conflict warning unconditionally — stderr, non-TTY-gated.
        // Rationale: this is operational info the user must see regardless of
        // whether they ran us from a TTY or piped us into a log. Silent
        // non-overwrite would be worse than a visible warning.
        eprintln!(
            "  {} Detected existing `model_provider = \"{}\"` in ~/.codex/config.toml.",
            "!".yellow(),
            other
        );
        eprintln!(
            "    {}",
            "aikey provider block installed but NOT activated. To route through aikey:"
                .dimmed()
        );
        eprintln!(
            "    {}",
            "  • Remove that line (aikey will set `model_provider = \"aikey\"` next run), or"
                .dimmed()
        );
        eprintln!(
            "    {}",
            "  • Invoke as: codex --local-provider aikey".dimmed()
        );
        false
    } else {
        desired = upsert_codex_managed_line(&desired, "model_provider", "aikey");
        true
    };

    desired = upsert_codex_region(&desired, &region);

    if desired == existing {
        return;
    }

    // Backup once, only on first touch.
    if first_time && !existing.is_empty() && !backup_path.exists() {
        let _ = std::fs::create_dir_all(&config_dir);
        let _ = std::fs::copy(&config_path, &backup_path);
    }

    match write_config_atomic(&config_dir, &config_path, &desired) {
        Ok(_) => {
            if first_time && io::stderr().is_terminal() {
                eprintln!(
                    "  {} Codex CLI auto-configured: {}",
                    "\u{2713}".green().bold(),
                    config_path.display().to_string().dimmed()
                );
                if !model_provider_written {
                    eprintln!(
                        "    {}",
                        "Note: your existing `model_provider` was preserved (see warning above)."
                            .dimmed()
                    );
                }
            }
        }
        Err(e) => {
            if first_time && io::stderr().is_terminal() {
                eprintln!("  {} Could not configure Codex CLI: {}", "!".yellow(), e);
            }
        }
    }
}

/// Restore `~/.codex/config.toml` from the backup created by `configure_codex_cli`.
///
/// Priority: (1) restore `config.aikey_backup.toml` wholesale; (2) failing
/// that, strip both the AIKEY_BEGIN/END region AND every line carrying the
/// `# managed by aikey` single-line marker. Never deletes non-aikey user
/// content.
pub fn unconfigure_codex_cli() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".codex");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    // Path 1: backup exists → restore wholesale.
    if backup_path.exists() {
        let _ = std::fs::rename(&backup_path, &config_path);
        return;
    }

    let Ok(content) = std::fs::read_to_string(&config_path) else { return };

    // Path 2: strip region + any single-line markers (covers both the new v3
    // codex format and the legacy per-line-marker-only format from before
    // Option A).
    let stripped_region = strip_managed_region(&content).unwrap_or(content.clone());
    let cleaned: String = stripped_region
        .lines()
        .filter(|line| !line.contains(CODEX_LINE_MARKER))
        .collect::<Vec<_>>()
        .join("\n");

    if cleaned.trim().is_empty() {
        let _ = std::fs::remove_file(&config_path);
    } else {
        let mut final_content = cleaned;
        if !final_content.ends_with('\n') {
            final_content.push('\n');
        }
        let _ = std::fs::write(&config_path, final_content);
    }
}

// ---------------------------------------------------------------------------
// active.env writer
// ---------------------------------------------------------------------------

/// Resolve the ~/.aikey directory path consistently across platforms.
/// Priority: HOME → USERPROFILE → "." (last resort).
/// Why not just HOME: on Windows, HOME is often unset; USERPROFILE is the standard.
/// Why not ".": the old fallback wrote to cwd, which makes the file unfindable by
/// deactivate and other tools that look in the home directory.
pub fn resolve_aikey_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".aikey")
}

pub(super) fn write_active_env(
    key_type: &str,
    key_ref: &str,    // virtual_key_id (team) or alias (personal)
    display_name: &str,
    providers: &[String],
    proxy_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let aikey_dir = resolve_aikey_dir();
    std::fs::create_dir_all(&aikey_dir)?;
    let env_path = aikey_dir.join("active.env");

    // Collect plain key-value pairs (no shell expressions) for both files.
    let mut kv_pairs: Vec<(String, String)> = vec![
        ("AIKEY_ACTIVE_KEY".to_string(), display_name.to_string()),
    ];

    for provider in providers {
        if let Some((api_key_var, base_url_var)) = super::provider_env_vars(provider) {
            let token_value = if key_type == "team" {
                format!("aikey_vk_{}", key_ref)
            } else {
                format!("aikey_personal_{}", key_ref)
            };
            let base_url = format!("http://127.0.0.1:{}/{}", proxy_port, super::provider_proxy_prefix(provider));
            kv_pairs.push((api_key_var.to_string(), token_value));
            kv_pairs.push((base_url_var.to_string(), base_url));
            // Provider-specific extras (e.g. KIMI_MODEL_NAME for the
            // minimal-scaffold Kimi config).
            for (extra_var, extra_val) in super::provider_extra_env_vars(provider) {
                kv_pairs.push((extra_var.to_string(), extra_val.to_string()));
            }
        }
    }

    // no_proxy/NO_PROXY: plain value for the flat file, shell-expansion for sh file.
    let no_proxy_value = "127.0.0.1,localhost";
    if !providers.is_empty() {
        kv_pairs.push(("no_proxy".to_string(), no_proxy_value.to_string()));
        kv_pairs.push(("NO_PROXY".to_string(), no_proxy_value.to_string()));
    }

    // ── 1. Write active.env (sh format, sourced by zsh/bash precmd) ─────────
    //
    // v3 architecture: active.env contains only env vars (no source statements).
    // Wrapper functions and precmd/preexec logic live in ~/.aikey/hook.{zsh,bash}
    // and are loaded once from shell rc. No live-upgrade indirection here — after
    // `aikey init` rewrites hook.*, users open a new shell or `source ~/.aikey/hook.zsh`.
    let mut sh_lines = vec![
        "# aikey active key — auto-generated by 'aikey use', do not edit manually".to_string(),
    ];
    for (k, v) in &kv_pairs {
        sh_lines.push(format!("export {}=\"{}\"", k, v));
    }
    // Append to existing no_proxy (shell expansion) instead of clobbering.
    // Why separate from the flat kv_pairs: ${no_proxy:-} is sh syntax, not valid in
    // PowerShell/cmd. The flat file gets the base value; the sh file appends to existing.
    if !providers.is_empty() {
        let content = sh_lines.join("\n") + "\n";
        let content = content
            .replace(
                &format!("export no_proxy=\"{}\"", no_proxy_value),
                &format!("export no_proxy=\"127.0.0.1,localhost,${{no_proxy:-}}\""),
            )
            .replace(
                &format!("export NO_PROXY=\"{}\"", no_proxy_value),
                &format!("export NO_PROXY=\"127.0.0.1,localhost,${{NO_PROXY:-}}\""),
            );
        std::fs::write(&env_path, content)?;
    } else {
        std::fs::write(&env_path, sh_lines.join("\n") + "\n")?;
    }

    // ── 2. Write active.env.flat (plain KEY=VALUE, no shell syntax) ─────────
    // Why: PowerShell/cmd deactivate needs to restore env vars but cannot parse
    // sh-style ${...} expressions. This file contains only literal values.
    let flat_path = aikey_dir.join("active.env.flat");
    let flat_lines: Vec<String> = kv_pairs.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    std::fs::write(&flat_path, flat_lines.join("\n") + "\n")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Shell Hook v3 installer
// ---------------------------------------------------------------------------
//
// v3 architecture: all wrapper/precmd/preexec logic lives in a single file
// at ~/.aikey/hook.zsh (or hook.bash). The user's shell rc (.zshrc / .bashrc)
// contains only a single source line wrapped in `# aikey shell hook v3 begin/end`
// markers. Future updates rewrite only the hook file — no splice into user rc.
//
// Migration from v1 / v2:
//   - Detect old marker block in rc.
//   - Back up rc to `<rc>.aikey_backup_<unix_ts>` (unique; collision suffix).
//   - Replace old block with the v3 marker + source line.
//   - Delete obsolete ~/.aikey/activate-hook.{zsh,bash} and preexec.{zsh,bash}.

const V1_MARKER: &str = "# aikey shell hook";
const V2_BEGIN: &str = "# aikey shell hook v2 begin";
const V2_END: &str = "# aikey shell hook v2 end";
const V3_BEGIN: &str = "# aikey shell hook v3 begin";
const V3_END: &str = "# aikey shell hook v3 end";

/// Content of `~/.aikey/hook.zsh`. Sourced from `src/templates/hook.zsh` via
/// `include_str!()` so the template authoring experience is plain .zsh with
/// editor syntax highlighting rather than Rust escape strings.
fn hook_zsh_content() -> &'static str {
    include_str!("../templates/hook.zsh")
}

/// Content of `~/.aikey/hook.bash`. Sourced from `src/templates/hook.bash`.
fn hook_bash_content() -> &'static str {
    include_str!("../templates/hook.bash")
}

/// Stable 16-hex-digit FNV-1a-64 hash of the raw template content.
///
/// Why this exists: the hook file on disk is a *snapshot* of the template
/// taken at the time `aikey use` last ran. After an `aikey` binary upgrade
/// the user keeps running the old snapshot until a command refreshes it.
/// Every past drift bug in this module (2026-04-22 stdin-suppression, 2026-
/// 04-22 wrapper preflight not installing) shares that root cause.
///
/// By embedding the hash both in the binary AND in the written file's
/// header, the precmd hook can detect the mismatch in O(1) and tell the
/// user exactly what to run. FNV-1a-64 is non-cryptographic but stable
/// across rustc versions (unlike std's `DefaultHasher`) — operator output
/// stays consistent so the user sees the same short id the binary
/// reports.
pub fn hook_template_hash(kind: HookKind) -> String {
    let content = match kind {
        HookKind::Zsh  => hook_zsh_content(),
        HookKind::Bash => hook_bash_content(),
    };
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for b in content.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    format!("{:016x}", h)
}

/// Shell dialect selector used by the hook-hash + write helpers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HookKind { Zsh, Bash }

/// Prepend a `# Hook-Template-Hash: <hex>` header to the raw template so a
/// running shell can compare its disk copy against the binary's embedded
/// hash. The header sits BELOW the template's existing `# auto-generated`
/// banner (line 1) but ABOVE any code, so naive parsers that read the
/// first few lines pick it up without descending into the body.
fn hook_content_with_hash_header(kind: HookKind) -> String {
    let raw = match kind {
        HookKind::Zsh  => hook_zsh_content(),
        HookKind::Bash => hook_bash_content(),
    };
    let hash = hook_template_hash(kind);
    // Stable format: the hook-check script greps `^# Hook-Template-Hash: `.
    // Keep this literal — tests pin it, and so does _aikey_hook_check_once.
    let header = format!("# Hook-Template-Hash: {}\n", hash);
    // Insert after the first `# ~/.aikey/...` banner line so the header
    // stays near the top but doesn't displace the do-not-hand-edit warning.
    let mut out = String::with_capacity(raw.len() + header.len() + 8);
    let mut lines = raw.lines();
    if let Some(first) = lines.next() {
        out.push_str(first);
        out.push('\n');
    }
    out.push_str(&header);
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Build the v3 rc block: marker + single source line + marker.
fn v3_rc_block(hook_filename: &str) -> String {
    format!(
        "{begin}\n[[ -f ~/.aikey/{hook} ]] && source ~/.aikey/{hook}\n{end}\n",
        begin = V3_BEGIN,
        hook = hook_filename,
        end = V3_END,
    )
}

/// Atomically write `~/.aikey/hook.{zsh,bash}` (write to tmp + rename).
fn write_hook_file(home: &str, is_zsh: bool) -> io::Result<std::path::PathBuf> {
    let filename = if is_zsh { "hook.zsh" } else { "hook.bash" };
    let kind = if is_zsh { HookKind::Zsh } else { HookKind::Bash };
    let content = hook_content_with_hash_header(kind);
    let aikey_dir = std::path::PathBuf::from(home).join(".aikey");
    std::fs::create_dir_all(&aikey_dir)?;
    let target = aikey_dir.join(filename);
    let tmp = aikey_dir.join(format!("{}.aikey.tmp", filename));
    std::fs::write(&tmp, &content)?;
    std::fs::rename(&tmp, &target)?;
    Ok(target)
}

/// Remove obsolete v1/v2 helper files (activate-hook.*, preexec.*) under
/// ~/.aikey/. Silent on errors — files may not exist.
fn cleanup_legacy_hook_files(home: &str) {
    for name in [
        "activate-hook.zsh",
        "activate-hook.bash",
        "preexec.zsh",
        "preexec.bash",
    ] {
        let p = std::path::PathBuf::from(home).join(".aikey").join(name);
        let _ = std::fs::remove_file(&p);
    }
}

/// Back up `rc` to `<rc>.aikey_backup_<unix_ts>` with `_NN` suffix on collision.
/// Returns the backup path on success.
fn backup_rc_file(rc: &std::path::Path) -> io::Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = format!("{}.aikey_backup_{}", rc.display(), secs);
    let mut candidate = std::path::PathBuf::from(&base);
    let mut n: u32 = 0;
    while candidate.exists() {
        n += 1;
        candidate = std::path::PathBuf::from(format!("{}_{:02}", base, n));
    }
    std::fs::copy(rc, &candidate)?;
    Ok(candidate)
}

/// Replace the text between `begin` and `end` markers (inclusive) in `contents`.
/// Returns the replaced content, or None if markers not found.
fn replace_between_markers(contents: &str, begin: &str, end: &str, replacement: &str) -> Option<String> {
    let start_idx = contents.find(begin)?;
    let end_idx = contents.find(end)?;
    if end_idx <= start_idx { return None; }
    let end_line_end = contents[end_idx..].find('\n')
        .map(|i| end_idx + i + 1)
        .unwrap_or(contents.len());
    let mut result = String::with_capacity(contents.len());
    result.push_str(&contents[..start_idx]);
    result.push_str(replacement);
    if !replacement.ends_with('\n') { result.push('\n'); }
    result.push_str(&contents[end_line_end..]);
    Some(result)
}

/// Install or upgrade the aikey shell hook to v3.
///
/// Behavior summary:
/// - Always writes `~/.aikey/hook.{zsh,bash}` (atomic overwrite).
/// - Removes obsolete v2 helper files (`activate-hook.*`, `preexec.*`).
/// - For the user's shell rc (`.zshrc` / `.bashrc`):
///   - If a v3 marker block is present → no-op (already installed).
///   - If a v1 or v2 marker block is present → back up rc, replace block with v3.
///   - If no marker → fresh install: prompt, append v3 block.
///
/// Returns a human-readable status for the caller to display, or `None` when the
/// install/upgrade was silent and idempotent.
///
/// Skipped with `--no-hook` flag or when `AIKEY_NO_HOOK=1` is set.
pub fn ensure_shell_hook(no_hook: bool) -> Option<String> {
    if no_hook || std::env::var("AIKEY_NO_HOOK").map(|v| v == "1").unwrap_or(false) {
        return None;
    }

    let home = std::env::var("HOME").ok()?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let is_zsh = shell.contains("zsh");
    let is_bash = shell.contains("bash");

    if !is_zsh && !is_bash {
        return Some(
            "  Shell not recognized (need zsh/bash). Source ~/.aikey/active.env manually.".to_string(),
        );
    }

    // 1. Write / refresh the hook file (source of truth for wrapper logic).
    let hook_filename = if is_zsh { "hook.zsh" } else { "hook.bash" };
    if let Err(e) = write_hook_file(&home, is_zsh) {
        return Some(format!("  Could not write ~/.aikey/{}: {}", hook_filename, e));
    }

    // 2. Remove obsolete v2 helper files — hook.* is the single source of truth now.
    cleanup_legacy_hook_files(&home);

    let rc_candidates: Vec<String> = if is_zsh {
        vec![format!("{}/.zshrc", home)]
    } else {
        vec![
            format!("{}/.bashrc", home),
            format!("{}/.bash_profile", home),
        ]
    };

    let v3_block = v3_rc_block(hook_filename);

    // 3. Scan rc candidates for existing markers (v1/v2/v3).
    for rc in &rc_candidates {
        let rc_path = std::path::Path::new(rc);
        let contents = match std::fs::read_to_string(rc) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // v3 already installed — idempotent, rewrite block in case marker line drifted.
        if contents.contains(V3_BEGIN) {
            if let Some(updated) = replace_between_markers(&contents, V3_BEGIN, V3_END, &v3_block) {
                if updated != contents {
                    let _ = std::fs::write(rc_path, updated);
                }
            }
            return None;
        }

        // v2 or v1 present — migrate with rc backup.
        let has_v2 = contents.contains(V2_BEGIN);
        let has_v1 = contents.contains(V1_MARKER);
        if has_v2 || has_v1 {
            let backup = match backup_rc_file(rc_path) {
                Ok(p) => p,
                Err(e) => {
                    return Some(format!("  Could not back up {}: {}", rc, e));
                }
            };

            let migrated = if has_v2 {
                replace_between_markers(&contents, V2_BEGIN, V2_END, &v3_block)
                    .unwrap_or_else(|| contents.clone())
            } else {
                // v1 has no end marker — strip line-by-line by scanning for the header.
                strip_v1_block(&contents, &v3_block)
            };

            if let Err(e) = std::fs::write(rc_path, migrated) {
                return Some(format!("  Could not write {}: {}", rc, e));
            }
            return Some(format!(
                "  Shell hook migrated to v3. Backup: {}",
                backup.display()
            ));
        }
    }

    // 4. No marker found — fresh install. Prompt before touching rc.
    let rc_file = rc_candidates
        .iter()
        .find(|rc| std::path::Path::new(rc).exists())
        .or_else(|| rc_candidates.first())
        .cloned()?;

    use std::io::{IsTerminal, Write};
    if io::stderr().is_terminal() {
        let shell_name = if is_zsh { "zsh" } else { "bash" };
        let rows = vec![
            format!("Shell:  {}", shell_name),
            format!("File:   {}", rc_file),
            format!("Add:    source ~/.aikey/{}  (v3)", hook_filename),
        ];
        crate::ui_frame::eprint_box("\u{2753}", "Install Shell Hook", &rows);
        eprint!("  Proceed? [Y/n] (default Y): ");
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok()
            && matches!(input.trim().to_lowercase().as_str(), "n" | "no")
        {
            return Some(format!(
                "  Skipped. To apply once: source ~/.aikey/{}",
                hook_filename
            ));
        }
    }

    match std::fs::OpenOptions::new().append(true).open(&rc_file) {
        Ok(mut f) => {
            let block = format!("\n{}", v3_block);
            let _ = f.write_all(block.as_bytes());
            Some(format!("  Shell hook installed in {}", rc_file))
        }
        Err(_) => Some(format!(
            "  Could not write to {}. Source ~/.aikey/{} manually.",
            rc_file, hook_filename
        )),
    }
}

/// Strip a v1 block from rc contents and splice in the v3 block at the same spot.
///
/// v1 has no end marker — the block is the `# aikey shell hook` header line
/// plus the function definition that follows until the `precmd_functions+=` line
/// (zsh) or `PROMPT_COMMAND='_aikey_precmd_bash'` line (bash). Returns the
/// original contents unchanged if no terminator is found within a bounded
/// window — conservative on purpose, we never want to splice past legitimate
/// user code following a partially-edited v1 block.
fn strip_v1_block(contents: &str, v3_block: &str) -> String {
    let Some(start) = contents.find(V1_MARKER) else {
        return contents.to_string();
    };

    // v1 templates were ~8-12 lines total. Bound the search window to 32 lines
    // after the marker — anything beyond that is likely user code we shouldn't touch.
    let tail = &contents[start..];
    let window_end = tail
        .char_indices()
        .filter(|(_, c)| *c == '\n')
        .nth(32)
        .map(|(i, _)| i + 1)
        .unwrap_or(tail.len());
    let search = &tail[..window_end];

    let terminator_patterns = [
        "precmd_functions+=(_aikey_precmd)",
        "PROMPT_COMMAND='_aikey_precmd_bash'",
    ];
    let mut terminator_end: Option<usize> = None;
    for pat in terminator_patterns {
        if let Some(i) = search.find(pat) {
            let after = i + pat.len();
            let nl = search[after..]
                .find('\n')
                .map(|n| after + n + 1)
                .unwrap_or(search.len());
            terminator_end = Some(match terminator_end {
                Some(prev) => prev.min(nl),
                None => nl,
            });
        }
    }
    let Some(end_rel) = terminator_end else {
        // No terminator in window — refuse to splice. Caller sees unchanged rc;
        // backup has already been created, so user can hand-edit or reinstall.
        return contents.to_string();
    };
    let end_abs = start + end_rel;

    let mut out = String::with_capacity(contents.len() + v3_block.len());
    out.push_str(&contents[..start]);
    out.push_str(v3_block);
    out.push_str(&contents[end_abs..]);
    out
}

#[cfg(test)]
mod hook_tests {
    use super::*;

    // ── v3 hook content sanity ──────────────────────────────────────────────

    #[test]
    fn hook_zsh_contains_wrappers_and_registrations() {
        let c = hook_zsh_content();
        assert!(c.contains("aikey()"));
        assert!(c.contains("ak()"), "zsh hook must define ak() short-alias wrapper");
        assert!(c.contains("activate|deactivate"));
        assert!(c.contains("--shell zsh"));
        assert!(c.contains("AIKEY_ACTIVE_LABEL"));
        assert!(c.contains("_aikey_precmd"));
        assert!(c.contains("_aikey_preexec"));
        assert!(c.contains("precmd_functions"));
        assert!(c.contains("preexec_functions"));
    }

    #[test]
    fn hook_bash_contains_wrappers_and_registrations() {
        let c = hook_bash_content();
        assert!(c.contains("aikey()"));
        assert!(c.contains("ak()"), "bash hook must define ak() short-alias wrapper");
        assert!(c.contains("--shell bash"));
        assert!(c.contains("AIKEY_ACTIVE_LABEL"));
        assert!(c.contains("_aikey_precmd_bash"));
        assert!(c.contains("_aikey_preexec_bash"));
        assert!(c.contains("PROMPT_COMMAND"));
        assert!(c.contains("trap '_aikey_preexec_bash' DEBUG"));
    }

    #[test]
    fn hook_zsh_guards_ak_against_user_conflict() {
        // ak is a short name commonly aliased by users (kubectl, aws, etc.).
        // The hook must defer to pre-existing alias/function rather than overwrite.
        let c = hook_zsh_content();
        assert!(
            c.contains("${+functions[ak]}") && c.contains("alias ak"),
            "zsh hook must guard ak() behind an existence check"
        );
        // Must use `function` keyword form to bypass zsh's parse-time alias
        // expansion on the function name (triggers parse error when the user
        // has `alias ak=...` set before this file is sourced).
        assert!(
            c.contains("function ak"),
            "zsh hook must use `function` keyword form for ak to avoid parse-time alias expansion"
        );
    }

    #[test]
    fn hook_bash_guards_ak_against_user_conflict() {
        let c = hook_bash_content();
        assert!(
            c.contains("type ak >/dev/null 2>&1"),
            "bash hook must guard ak() behind an existence check"
        );
    }

    #[test]
    fn hook_bash_guards_debug_trap_against_user_conflict() {
        // DEBUG trap has a single slot — unconditional install would clobber
        // user's own trap or tools like bash-preexec. Must defer to existing one.
        let c = hook_bash_content();
        assert!(
            c.contains("trap -p DEBUG"),
            "bash hook must probe existing DEBUG trap before installing"
        );
    }

    // ── Preflight wrapper (2026-04-22) ──────────────────────────────────────
    //
    // Context: the 2026-04-22 connectivity-probe bugfix doc listed wrapper
    // preflight as a follow-up. Users kept getting opaque "proxy down" errors
    // 30 seconds into a claude/codex session. The wrapper now runs
    // `aikey test <id>` before handing off, and prompts (default No) if the
    // probe fails. These tests pin the contract so a future hook rewrite
    // can't silently drop it. See:
    // workflow/CI/bugfix/2026-04-22-connectivity-probe-through-proxy.md

    #[test]
    fn hook_zsh_defines_claude_and_codex_preflight_wrappers() {
        let c = hook_zsh_content();
        assert!(c.contains("_aikey_preflight"),
            "zsh hook must define _aikey_preflight helper function");
        // stdin redirect /dev/null is still required — it's a safety belt
        // against any regression that would reintroduce a password prompt
        // under the wrapper (plan D eliminated the normal path; this
        // guards the edge case).
        assert!(c.contains("command aikey test") && c.contains("</dev/null"),
            "preflight must invoke `command aikey test ... </dev/null` so \
             any future interactive prompt fails fast, not hangs");
        // Stderr MUST NOT be redirected — users need to see the
        // Ping/API/Chat table (both on success and failure); a silent
        // 1-2s pause before claude starts looks like a shell hang.
        assert!(!c.contains("command aikey test \"$id\" </dev/null >/dev/null")
             && !c.contains("command aikey test \"$id\" </dev/null 2>/dev/null"),
            "preflight must NOT suppress aikey test output — users need the \
             table rendered both for success confirmation and failure diagnosis");
        // Wrappers must be guarded same as `ak` — never overwrite a user's
        // own claude/codex function or alias.
        assert!(c.contains("${+functions[claude]}") && c.contains("alias claude"),
            "zsh hook must guard claude() behind function+alias existence check");
        assert!(c.contains("${+functions[codex]}") && c.contains("alias codex"),
            "zsh hook must guard codex() behind function+alias existence check");
        // Must use the `function` keyword form for parse-time alias safety.
        assert!(c.contains("function claude"),
            "zsh claude wrapper must use `function` keyword form");
        assert!(c.contains("function codex"),
            "zsh codex wrapper must use `function` keyword form");
        // Must delegate to the real binary via `command` to avoid recursion.
        assert!(c.contains("command claude \"$@\""),
            "claude wrapper must call `command claude \"$@\"` to reach the real binary");
        assert!(c.contains("command codex \"$@\""),
            "codex wrapper must call `command codex \"$@\"` to reach the real binary");
    }

    #[test]
    fn hook_bash_defines_claude_and_codex_preflight_wrappers() {
        let c = hook_bash_content();
        assert!(c.contains("_aikey_preflight"),
            "bash hook must define _aikey_preflight helper function");
        assert!(c.contains("command aikey test") && c.contains("</dev/null"),
            "bash preflight must invoke `command aikey test ... </dev/null`");
        // Stderr must not be redirected — table output is the user-visible
        // feedback. See zsh test for rationale.
        assert!(!c.contains("command aikey test \"$id\" </dev/null >/dev/null")
             && !c.contains("command aikey test \"$id\" </dev/null 2>/dev/null"),
            "bash preflight must NOT suppress aikey test output");
        assert!(c.contains("declare -F claude") && c.contains("alias claude"),
            "bash hook must guard claude() behind declare -F + alias check");
        assert!(c.contains("declare -F codex") && c.contains("alias codex"),
            "bash hook must guard codex() behind declare -F + alias check");
        assert!(c.contains("command claude \"$@\""),
            "claude wrapper must delegate to real binary via `command`");
        assert!(c.contains("command codex \"$@\""),
            "codex wrapper must delegate to real binary via `command`");
    }

    #[test]
    fn hook_preflight_honours_aikey_preflight_off_escape_hatch() {
        // Users on CI or low-bandwidth networks need an opt-out. Contract:
        // `AIKEY_PREFLIGHT=off` makes the preflight a no-op. This is the
        // only env-var knob on the wrapper — keep the surface small.
        for c in [hook_zsh_content(), hook_bash_content()] {
            assert!(c.contains("AIKEY_PREFLIGHT") && c.contains("\"off\""),
                "hook must honour AIKEY_PREFLIGHT=off escape hatch — CI / \
                 offline users can't afford an interactive prompt before \
                 every claude invocation");
        }
    }

    #[test]
    fn hook_preflight_default_answer_is_no() {
        // Critical UX invariant: typing Enter (or anything that isn't y/Y)
        // must NOT proceed into claude/codex. If someone accidentally makes
        // the default Yes, a proxy-down situation drops users into an
        // unusable session with no obvious signal. Pin the contract.
        for (label, c) in [("zsh", hook_zsh_content()), ("bash", hook_bash_content())] {
            // The prompt text must signal default=No (the "[y/N]" convention
            // — capital N indicating default).
            assert!(c.contains("[y/N]"),
                "{}: prompt must show [y/N] to signal default=No", label);
            // The affirmative branch must match only y/Y/yes/YES, never an
            // empty reply or anything else.
            assert!(c.contains("y|Y|yes|YES"),
                "{}: only y/Y/yes/YES must proceed — empty reply is NOT a \
                 proceed signal (would defeat the whole safety purpose)", label);
        }
    }

    #[test]
    fn hook_preflight_hints_when_no_active_binding() {
        // Missing AIKEY_ACTIVE_KEYS means the user hasn't run `aikey use`
        // yet. Silently passing through would leave first-time users staring
        // at `claude`'s native "no BASE_URL" error with no breadcrumb to
        // `aikey use`. The wrapper emits one stderr line naming the fix.
        // Pinned so a future simplification can't quietly drop it.
        for (label, c) in [("zsh", hook_zsh_content()), ("bash", hook_bash_content())] {
            assert!(c.contains("no active binding"),
                "{}: preflight must print an advisory when AIKEY_ACTIVE_KEYS is empty", label);
            assert!(c.contains("aikey use"),
                "{}: advisory must name the command to run (`aikey use <alias>`)", label);
            assert!(c.contains("preflight skipped"),
                "{}: advisory must state the preflight was skipped (so the user \
                 knows why claude/codex still starts despite no binding)", label);
        }
    }

    #[test]
    fn hook_preflight_does_not_shadow_kimi() {
        // The 2026-04-22 requirement names claude and codex only. Kimi is
        // deliberately NOT wrapped — it has its own per-binding health
        // semantics (subscription status checks that differ from the
        // anthropic/openai probe paths), and the preflight's blanket
        // approach could false-positive on a valid kimi setup. If this
        // ever changes, update the requirement first, then this test.
        for (label, c) in [("zsh", hook_zsh_content()), ("bash", hook_bash_content())] {
            // There should be no `function kimi { _aikey_preflight ... }`
            // or `kimi() { _aikey_preflight ... }` in the template.
            assert!(!c.contains("_aikey_preflight kimi"),
                "{}: kimi is intentionally out of scope for the 2026-04-22 \
                 preflight requirement — see the bugfix record before adding", label);
        }
    }

    #[test]
    fn v3_rc_block_has_markers_and_source_line_zsh() {
        let b = v3_rc_block("hook.zsh");
        assert!(b.starts_with(V3_BEGIN));
        assert!(b.trim_end().ends_with(V3_END));
        assert!(b.contains("[[ -f ~/.aikey/hook.zsh ]] && source ~/.aikey/hook.zsh"));
    }

    #[test]
    fn v3_rc_block_has_markers_and_source_line_bash() {
        let b = v3_rc_block("hook.bash");
        assert!(b.starts_with(V3_BEGIN));
        assert!(b.trim_end().ends_with(V3_END));
        assert!(b.contains("[[ -f ~/.aikey/hook.bash ]] && source ~/.aikey/hook.bash"));
    }

    // ── replace_between_markers ─────────────────────────────────────────────

    #[test]
    fn replace_markers_basic() {
        let input = "before\n# BEGIN\nold content\n# END\nafter\n";
        let result = replace_between_markers(input, "# BEGIN", "# END", "new content\n");
        assert_eq!(result.unwrap(), "before\nnew content\nafter\n");
    }

    #[test]
    fn replace_markers_preserves_surrounding() {
        let input = "line1\nline2\n# BEGIN\nstuff\n# END\nline3\nline4\n";
        let result = replace_between_markers(input, "# BEGIN", "# END", "replaced\n");
        let out = result.unwrap();
        assert!(out.starts_with("line1\nline2\n"));
        assert!(out.ends_with("line3\nline4\n"));
        assert!(out.contains("replaced"));
        assert!(!out.contains("stuff"));
    }

    #[test]
    fn replace_markers_not_found() {
        let input = "no markers here\n";
        assert!(replace_between_markers(input, "# BEGIN", "# END", "x").is_none());
    }

    // ── v2 → v3 migration via replace_between_markers ───────────────────────

    #[test]
    fn v2_to_v3_migration_preserves_surrounding() {
        // Simulate a .zshrc with a v2 block between user lines.
        let v2_block = format!(
            "{}\naikey() {{ echo old; }}\nprecmd_functions+=(_aikey_precmd)\n{}\n",
            V2_BEGIN, V2_END
        );
        let rc = format!("export FOO=bar\n{}\n# user code\n", v2_block);
        let v3 = v3_rc_block("hook.zsh");
        let out = replace_between_markers(&rc, V2_BEGIN, V2_END, &v3).unwrap();

        assert!(out.contains(V3_BEGIN));
        assert!(out.contains(V3_END));
        assert!(!out.contains("echo old"), "v2 body must be gone");
        assert!(out.contains("export FOO=bar"));
        assert!(out.contains("# user code"));
    }

    // ── v1 → v3 migration via strip_v1_block ────────────────────────────────

    #[test]
    fn strip_v1_block_replaces_v1_with_v3_zsh() {
        let v1 = "# aikey shell hook\n_aikey_precmd() {\n  [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env\n}\nprecmd_functions+=(_aikey_precmd)\n";
        let rc = format!("export FOO=bar\n\n{}\n# user code\n", v1);
        let v3 = v3_rc_block("hook.zsh");
        let out = strip_v1_block(&rc, &v3);

        assert!(out.contains(V3_BEGIN));
        assert!(out.contains(V3_END));
        assert!(out.contains("export FOO=bar"));
        assert!(out.contains("# user code"));
        assert!(!out.contains("# aikey shell hook\n"), "v1 header must be gone");
    }

    #[test]
    fn strip_v1_block_refuses_without_terminator() {
        // Partially-deleted v1 (no precmd_functions+= line) — must not splice.
        let rc = "export FOO=bar\n# aikey shell hook\n# user hand-edited this\n# user code below\n";
        let v3 = v3_rc_block("hook.zsh");
        let out = strip_v1_block(rc, &v3);
        assert_eq!(out, rc, "strip must refuse when no terminator found");
    }

    #[test]
    fn strip_v1_block_replaces_v1_with_v3_bash() {
        let v1 = "# aikey shell hook\n_aikey_precmd_bash() {\n  [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env\n}\nPROMPT_COMMAND='_aikey_precmd_bash'\n";
        let rc = format!("export FOO=bar\n\n{}\n# user code\n", v1);
        let v3 = v3_rc_block("hook.bash");
        let out = strip_v1_block(&rc, &v3);

        assert!(out.contains(V3_BEGIN));
        assert!(out.contains("export FOO=bar"));
        assert!(out.contains("# user code"));
        assert!(!out.contains("_aikey_precmd_bash"));
    }

    // ── v3 idempotent replace ──────────────────────────────────────────────

    #[test]
    fn v3_hotfix_replacement() {
        let v3 = v3_rc_block("hook.zsh");
        let rc = format!("export FOO=bar\n{}\n# user code\n", v3);

        // Simulate hotfix: replace v3 block with a new v3 (same content OK — tests the path).
        let new_v3 = v3_rc_block("hook.zsh");
        let out = replace_between_markers(&rc, V3_BEGIN, V3_END, &new_v3).unwrap();
        assert!(out.contains(V3_BEGIN));
        assert!(out.contains("export FOO=bar"));
        assert!(out.contains("# user code"));
    }

    // ── Kimi marker-region helpers ──────────────────────────────────────────

    #[test]
    fn kimi_region_contains_only_hook_scaffold() {
        // Minimal scaffold: only the Stop hook lives in config.toml. Providers,
        // models, and default_model are all env-var-driven (see
        // provider_extra_env_vars + active.env writers).
        let r = build_kimi_managed_region(27200);
        assert!(r.starts_with(AIKEY_BEGIN));
        assert!(r.trim_end().ends_with(AIKEY_END));
        // Hook — the only thing that genuinely needs file storage.
        assert!(r.contains("[[hooks]]"));
        assert!(r.contains("event = \"Stop\""));
        assert!(r.contains("statusline render kimi"));
        // Must NOT contain provider/model scaffolding anymore.
        assert!(!r.contains("[providers.kimi]"), "region should not include provider block:\n{}", r);
        assert!(!r.contains("[models."), "region should not include model blocks:\n{}", r);
        assert!(!r.contains("api_key"), "region should not include api_key:\n{}", r);
        assert!(!r.contains("base_url"), "region should not include base_url:\n{}", r);
    }

    #[test]
    fn kimi_region_is_port_agnostic() {
        // Port no longer appears in the region (base_url is env-var-driven).
        let a = build_kimi_managed_region(27200);
        let b = build_kimi_managed_region(19999);
        assert_eq!(a, b, "region content must not depend on proxy_port:\nA={}\nB={}", a, b);
        assert!(!a.contains("27200"));
        assert!(!a.contains("19999"));
    }

    #[test]
    fn kimi_strip_legacy_default_model_removes_matching_top_level() {
        let input = "default_model = \"kimi-k2-5\"\ndefault_thinking = false\n[loop_control]\nmax = 10\n";
        let out = strip_legacy_kimi_default_model(input);
        assert!(!out.contains("default_model = \"kimi-k2-5\""));
        assert!(out.contains("default_thinking = false"));
        assert!(out.contains("[loop_control]"));
        assert!(out.contains("max = 10"));
    }

    #[test]
    fn kimi_strip_legacy_default_model_preserves_user_custom_value() {
        // Users who picked a non-aikey-default value must be preserved.
        let input = "default_model = \"kimi-dev\"\n[loop_control]\n";
        let out = strip_legacy_kimi_default_model(input);
        assert!(out.contains("default_model = \"kimi-dev\""));
    }

    #[test]
    fn kimi_strip_legacy_default_model_ignores_inside_table() {
        // A `default_model = ...` line AFTER a [table] header is a sub-key
        // (e.g. `[some.plugin]\ndefault_model = "..."`), not our target.
        let input = "[some.plugin]\ndefault_model = \"kimi-k2-5\"\n";
        let out = strip_legacy_kimi_default_model(input);
        assert!(out.contains("default_model = \"kimi-k2-5\""));
    }

    #[test]
    fn kimi_replace_region_preserves_surrounding_content() {
        let before = "default_thinking = false\n\n";
        let old_region = format!("{AIKEY_BEGIN}\n[providers.kimi]\napi_key = \"old\"\n{AIKEY_END}");
        let after = "\n\n# user-added provider below\n[providers.custom]\nkey = \"keep-me\"\n";
        let existing = format!("{before}{old_region}{after}");

        let new_region = build_kimi_managed_region(27200);
        let out = replace_managed_region(&existing, &new_region).unwrap();

        assert!(out.starts_with("default_thinking = false\n\n"));
        assert!(!out.contains("api_key = \"old\""));
        assert!(out.contains("[[hooks]]"));
        assert!(out.contains("[providers.custom]"));
        assert!(out.contains("keep-me"));
    }

    #[test]
    fn kimi_replace_region_returns_none_without_markers() {
        let plain = "default_thinking = false\n[providers.custom]\nkey = \"k\"\n";
        let region = build_kimi_managed_region(27200);
        assert!(replace_managed_region(plain, &region).is_none());
    }

    #[test]
    fn kimi_strip_region_removes_region_and_one_trailing_newline() {
        let region = build_kimi_managed_region(27200);
        let existing = format!("default_thinking = false\n\n{region}\n\n# user\n");
        let out = strip_managed_region(&existing).unwrap();
        assert!(out.starts_with("default_thinking = false\n\n"));
        assert!(!out.contains(AIKEY_BEGIN));
        assert!(!out.contains(AIKEY_END));
        assert!(out.contains("# user"));
    }

    #[test]
    fn kimi_strip_region_returns_none_when_absent() {
        let plain = "default_model = \"x\"\n";
        assert!(strip_managed_region(plain).is_none());
    }

    #[test]
    fn kimi_strip_then_replace_round_trip_is_identity() {
        // Stripping a region and re-inserting the same region should
        // produce the original file modulo a trailing-newline variation.
        let region = build_kimi_managed_region(27200);
        let original = format!("user_key = \"a\"\n\n{region}\n");
        let stripped = strip_managed_region(&original).unwrap();
        let mut rebuilt = stripped.trim_end().to_string();
        rebuilt.push_str("\n\n");
        rebuilt.push_str(&region);
        rebuilt.push('\n');
        assert_eq!(rebuilt, original);
    }

    // ── Codex managed region (Option A — env-var-driven custom provider) ──

    #[test]
    fn codex_region_contains_custom_provider_with_env_key() {
        let r = build_codex_managed_region(27200);
        assert!(r.starts_with(AIKEY_BEGIN));
        assert!(r.trim_end().ends_with(AIKEY_END));
        assert!(r.contains("[model_providers.aikey]"));
        assert!(r.contains("name = \"aikey\""));
        assert!(r.contains("base_url = \"http://127.0.0.1:27200/openai\""));
        // THE critical assertion: per-shell token via env_key.
        assert!(r.contains("env_key = \"OPENAI_API_KEY\""));
        assert!(r.contains("wire_api = \"responses\""));
        // Must bypass the auth.json / ChatGPT login path.
        assert!(r.contains("requires_openai_auth = false"));
    }

    #[test]
    fn codex_region_respects_proxy_port() {
        let r = build_codex_managed_region(19999);
        assert!(r.contains("127.0.0.1:19999"));
        assert!(!r.contains(":27200"));
    }

    #[test]
    fn codex_upsert_line_on_empty_file_creates_line() {
        let out = upsert_codex_managed_line("", "openai_base_url", "http://x/y");
        assert_eq!(
            out,
            "openai_base_url = \"http://x/y\"  # managed by aikey\n"
        );
    }

    #[test]
    fn codex_upsert_line_replaces_existing_in_place() {
        let existing = "model = \"gpt-5\"\nopenai_base_url = \"OLD\"\n[projects.x]\n";
        let out = upsert_codex_managed_line(existing, "openai_base_url", "NEW");
        assert!(out.contains("openai_base_url = \"NEW\"  # managed by aikey"));
        assert!(!out.contains("\"OLD\""));
        assert!(out.contains("model = \"gpt-5\""));
        assert!(out.contains("[projects.x]"));
    }

    #[test]
    fn codex_upsert_line_no_duplicate_when_other_keys_exist() {
        // Regression: when `openai_base_url` already exists AND there's a
        // different top-level key (`model_provider = "ollama"`) before any
        // table, upsert must not also prepend a new line — it should JUST
        // replace the existing one.
        let existing = "model = \"gpt-5\"\nopenai_base_url = \"OLD\"  # managed by aikey\nmodel_provider = \"ollama\"\n[projects.x]\n";
        let out = upsert_codex_managed_line(existing, "openai_base_url", "NEW");
        // Exactly one openai_base_url line
        let count = out
            .lines()
            .filter(|l| l.trim_start().starts_with("openai_base_url"))
            .count();
        assert_eq!(count, 1, "got duplicate openai_base_url:\n{}", out);
        // Exactly one model_provider line (user's, untouched here)
        let mp_count = out
            .lines()
            .filter(|l| l.trim_start().starts_with("model_provider ") || l.trim_start().starts_with("model_provider="))
            .count();
        assert_eq!(mp_count, 1, "model_provider duplicated:\n{}", out);
    }

    #[test]
    fn codex_upsert_line_inserts_before_first_table() {
        // TOML constraint: top-level keys must precede any [table] header.
        let existing = "model = \"gpt-5\"\n[projects.x]\ntrust = \"full\"\n";
        let out = upsert_codex_managed_line(existing, "model_provider", "aikey");
        let key_pos = out.find("model_provider").unwrap();
        let table_pos = out.find("[projects.x]").unwrap();
        assert!(key_pos < table_pos, "model_provider must come before table header:\n{}", out);
    }

    #[test]
    fn codex_upsert_line_prepends_when_file_is_all_tables() {
        let existing = "[projects.x]\ntrust = \"full\"\n";
        let out = upsert_codex_managed_line(existing, "model_provider", "aikey");
        assert!(out.starts_with("model_provider = \"aikey\"  # managed by aikey"));
    }

    #[test]
    fn codex_conflict_returns_none_when_no_model_provider() {
        let content = "model = \"gpt-5\"\n[projects.x]\n";
        assert_eq!(detect_codex_model_provider_conflict(content), None);
    }

    #[test]
    fn codex_conflict_returns_none_for_openai_or_aikey() {
        let a = "model_provider = \"openai\"\n";
        let b = "model_provider = \"aikey\"  # managed by aikey\n";
        assert_eq!(detect_codex_model_provider_conflict(a), None);
        assert_eq!(detect_codex_model_provider_conflict(b), None);
    }

    #[test]
    fn codex_conflict_returns_some_for_custom_provider() {
        let content = "model = \"x\"\nmodel_provider = \"ollama\"\n[projects.x]\n";
        assert_eq!(
            detect_codex_model_provider_conflict(content),
            Some("ollama".to_string())
        );
    }

    #[test]
    fn codex_conflict_ignores_value_when_own_marker_present() {
        // Our own write even with value == "custom-thing" must not self-report as conflict.
        let content = "model_provider = \"anything\"  # managed by aikey\n";
        assert_eq!(detect_codex_model_provider_conflict(content), None);
    }

    #[test]
    fn codex_upsert_region_appends_to_end() {
        let existing = "model = \"gpt-5\"\n[projects.x]\ntrust = \"full\"\n";
        let region = build_codex_managed_region(27200);
        let out = upsert_codex_region(existing, &region);
        assert!(out.ends_with(&format!("{}\n", AIKEY_END)));
        assert!(out.contains("model = \"gpt-5\""));
        assert!(out.contains("[projects.x]"));
    }

    #[test]
    fn codex_upsert_region_replaces_existing() {
        let old_region = format!("{AIKEY_BEGIN}\n[model_providers.aikey]\napi_key = \"old\"\n{AIKEY_END}");
        let existing = format!("model = \"gpt-5\"\n\n{old_region}\n");
        let new_region = build_codex_managed_region(27200);
        let out = upsert_codex_region(&existing, &new_region);
        assert!(!out.contains("api_key = \"old\""));
        assert!(out.contains("env_key = \"OPENAI_API_KEY\""));
        assert!(out.contains("model = \"gpt-5\""));
    }
}
