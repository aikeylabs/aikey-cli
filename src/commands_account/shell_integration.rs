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

/// Placeholder token written into the aikey-managed region's `api_key` field.
///
/// Why a placeholder instead of a real token:
/// - Kimi CLI reads `KIMI_API_KEY` env var and **overrides** the config file's
///   `api_key` at request time ([llm.py augment_provider_with_env_vars]). So
///   the file value is only a fallback, never the hot path.
/// - Writing a real token here means every `aikey use <kimi-key>` rewrites the
///   global file. That's invasive to the user (mtime churn, diff noise) and
///   prevents per-shell isolation from the file layer.
/// - Placeholder + self-documenting name → if a request ever escapes to
///   upstream with the placeholder (because the env var wasn't set), the
///   upstream auth error points directly at the cause.
const KIMI_PLACEHOLDER_API_KEY: &str = "aikey-placeholder-override-via-KIMI_API_KEY-env-var";

/// Build the aikey-managed Kimi config region (scaffold only — see Why below).
///
/// Why a scaffold:
/// - `[providers.kimi]` block must exist so Kimi CLI's
///   `augment_provider_with_env_vars` matches `provider.type == "kimi"` and
///   applies `KIMI_API_KEY` / `KIMI_BASE_URL` overrides. The literal values
///   inside are placeholders — env vars replace them at runtime.
/// - `[models.*]` must exist so `default_model` can reference a valid entry.
/// - `[[hooks]]` Stop cannot be expressed as env vars — must live in config.
///   This is the only piece that genuinely demands file-backed storage.
fn build_kimi_managed_region(proxy_port: u16) -> String {
    let hook_cmd = crate::commands_statusline::aikey_statusline_render_kimi_command();
    format!(
        "{begin}\n\
[providers.kimi]\n\
type = \"kimi\"\n\
base_url = \"http://127.0.0.1:{port}/kimi/v1\"\n\
api_key = \"{placeholder}\"\n\
\n\
[models.kimi-k2-5]\n\
provider = \"kimi\"\n\
model = \"kimi-k2.5\"\n\
max_context_size = 131072\n\
\n\
[models.moonshot-v1-128k]\n\
provider = \"kimi\"\n\
model = \"moonshot-v1-128k\"\n\
max_context_size = 131072\n\
\n\
[[hooks]]\n\
event = \"Stop\"\n\
command = \"{cmd}\"\n\
timeout = 5\n\
{end}",
        begin = AIKEY_BEGIN,
        port = proxy_port,
        placeholder = KIMI_PLACEHOLDER_API_KEY,
        cmd = hook_cmd,
        end = AIKEY_END,
    )
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

    let base_url = format!("http://127.0.0.1:{}/kimi/v1", proxy_port);

    // Build the desired file contents for each of the three code paths.
    let (desired, first_time) = if has_region {
        // Managed region already present — in-place replace (no prompt).
        match replace_managed_region(&existing, &region) {
            Some(s) => (s, false),
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
        if io::stderr().is_terminal() {
            let rows: Vec<String> = {
                let mut r = vec![
                    format!("File:    {}", "~/.kimi/config.toml"),
                    format!("Add:     provider  base_url={}", base_url),
                    format!("         models: kimi-k2.5, moonshot-v1-128k"),
                    format!("         Stop hook → aikey statusline render kimi"),
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

        // default_model is user-facing (outside managed region). Set it once
        // if absent or empty; thereafter the user controls the value.
        let mut base = existing.clone();
        if !base.contains("default_model") {
            if !base.trim_end().is_empty() {
                base = base.trim_end().to_string();
                base.push('\n');
            }
            base.push_str("default_model = \"kimi-k2-5\"\n");
        } else {
            base = base.replace("default_model = \"\"", "default_model = \"kimi-k2-5\"");
        }

        let mut out = base.trim_end().to_string();
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

/// Auto-configure `~/.codex/config.toml` so that Codex CLI routes OpenAI
/// requests through the aikey local proxy.
///
/// Pattern mirrors `configure_kimi_cli`: marker-based idempotent updates,
/// backup before first modification, interactive prompt on first touch.
pub fn configure_codex_cli(proxy_port: u16) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".codex");
    let config_path = config_dir.join("config.toml");

    // Why: Codex treats openai_base_url as a replacement for
    // "https://api.openai.com/v1" (including /v1), so paths like /responses
    // are appended directly. The proxy's providerDefaultBaseURL already includes
    // /v1, so applyBaseURL() prepends it correctly. No /v1 needed in CLI config.
    let base_url = format!("http://127.0.0.1:{}/openai", proxy_port);
    let marker = "# managed by aikey";

    // Read existing config or start empty.
    let content = std::fs::read_to_string(&config_path).unwrap_or_default();

    // Already configured — silent update (no prompt needed for subsequent switches).
    if content.contains(marker) {
        let updated = update_codex_base_url(&content, &base_url);
        let _ = std::fs::write(&config_path, updated);
        return;
    }

    // First time — prompt user before modifying their config.
    if io::stderr().is_terminal() {
        let mut rows: Vec<String> = vec![
            format!("File:    {}", "~/.codex/config.toml"),
            format!("Add:     openai_base_url = {}", base_url),
        ];
        if !content.is_empty() {
            rows.push(format!("Backup:  {}", "~/.codex/config.aikey_backup.toml"));
        }
        crate::ui_frame::eprint_box("\u{2753}", "Configure Codex CLI", &rows);
        eprint!("  Proceed? [Y/n] (default Y): ");
        io::stderr().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if input.trim().to_lowercase() == "n" {
                eprintln!("  {}", "Skipped. Run 'aikey use' again to retry.".dimmed());
                return;
            }
        }
    }

    // Backup original config before first modification.
    let backup_path = config_dir.join("config.aikey_backup.toml");
    if !content.is_empty() && !backup_path.exists() {
        let _ = std::fs::copy(&config_path, &backup_path);
    }

    let _ = std::fs::create_dir_all(&config_dir);

    // Inject openai_base_url at the top level of the TOML.
    // Why: Codex v0.118+ deprecated the OPENAI_BASE_URL env var and reads
    // openai_base_url from config.toml instead.
    let new_line = format!("openai_base_url = \"{}\"  {}", base_url, marker);

    let updated = if content.contains("openai_base_url") {
        // Replace existing (non-managed) openai_base_url line.
        let mut result = String::new();
        for line in content.lines() {
            if line.trim_start().starts_with("openai_base_url") {
                result.push_str(&new_line);
            } else {
                result.push_str(line);
            }
            result.push('\n');
        }
        result
    } else if content.is_empty() {
        // No config file existed — create a minimal one.
        format!("{}\n", new_line)
    } else {
        // Append after the first top-level key (e.g. model = "...").
        // Insert right after line 1 so it stays at the top level.
        let mut result = String::new();
        let mut inserted = false;
        for line in content.lines() {
            result.push_str(line);
            result.push('\n');
            // Insert after the first non-comment, non-empty top-level line.
            if !inserted && !line.is_empty() && !line.starts_with('#') && !line.starts_with('[') {
                result.push_str(&new_line);
                result.push('\n');
                inserted = true;
            }
        }
        if !inserted {
            result.push_str(&new_line);
            result.push('\n');
        }
        result
    };

    match std::fs::write(&config_path, &updated) {
        Ok(_) => {
            eprintln!("  {} Codex CLI auto-configured: {}",
                "\u{2713}".green().bold(),
                config_path.display().to_string().dimmed());
        }
        Err(e) => {
            eprintln!("  {} Could not configure Codex CLI: {}",
                "!".yellow(), e);
        }
    }
}

/// Update `openai_base_url` in an already-managed Codex config.
fn update_codex_base_url(content: &str, base_url: &str) -> String {
    let marker = "# managed by aikey";
    let mut result = String::new();
    for line in content.lines() {
        if line.trim_start().starts_with("openai_base_url") && line.contains(marker) {
            result.push_str(&format!("openai_base_url = \"{}\"  {}", base_url, marker));
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    result
}

/// Restore `~/.codex/config.toml` from the backup created by `configure_codex_cli`.
///
/// Called when `aikey use` switches to a key that does not include openai.
/// If a backup exists (`config.aikey_backup.toml`), it is moved back.
/// If no backup but the file was created from scratch by us, remove the
/// managed line (but keep the rest of the config intact).
pub fn unconfigure_codex_cli() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".codex");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    if backup_path.exists() {
        // Restore the original config from backup.
        let _ = std::fs::rename(&backup_path, &config_path);
    } else if config_path.exists() {
        // No backup — remove just the managed line(s) rather than deleting
        // the whole file (user may have added other settings after us).
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();
        if content.contains("# managed by aikey") {
            let cleaned: String = content
                .lines()
                .filter(|line| !line.contains("# managed by aikey"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            // If only whitespace remains, remove the file.
            if cleaned.trim().is_empty() {
                let _ = std::fs::remove_file(&config_path);
            } else {
                let _ = std::fs::write(&config_path, cleaned);
            }
        }
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

/// Content of `~/.aikey/hook.zsh`.
fn hook_zsh_content() -> &'static str {
    r#"# ~/.aikey/hook.zsh — auto-generated by `aikey use`, do not hand-edit
# Version: 3
aikey() {
    case "$1" in
        activate|deactivate)
            local _output
            _output=$(command aikey "$@" --shell zsh)
            local _rc=$?
            if [ $_rc -eq 0 ]; then eval "$_output"; else return $_rc; fi
            ;;
        *) command aikey "$@" ;;
    esac
}

# `ak` is a binary symlink → aikey; this wrapper routes it through aikey() so
# `ak activate|deactivate` also gets eval-captured. Guarded — if the user has
# already defined `ak` (alias or function) for another tool, respect it.
#
# Why `function ak { ... }` (keyword form) not `ak() { ... }`: when the user
# has `alias ak=...` defined BEFORE this file is sourced, the parenthesis form
# triggers parse-time alias expansion on the function name (→ parse error).
# The `function` keyword form bypasses alias expansion on the name.
if ! (( ${+functions[ak]} )) && ! alias ak >/dev/null 2>&1; then
    function ak { aikey "$@"; }
fi

_aikey_precmd() {
    [ -n "$AIKEY_ACTIVE_LABEL" ] && return
    [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env
}

_aikey_preexec() {
    [[ -z "$AIKEY_ACTIVE_KEYS" ]] && return
    local cmd="${1%% *}" prov
    case "$cmd" in
        claude) prov=anthropic ;;
        codex)  prov=openai ;;
        kimi)   prov=kimi ;;
        *) return ;;
    esac
    local id=$(echo "$AIKEY_ACTIVE_KEYS" | tr ',' '\n' | grep "^${prov}=" | cut -d= -f2-)
    [[ -n "$id" ]] && printf '\033[90m[aikey] %s → %s\033[0m\n' "$cmd" "$id"
}

# Dedupe-safe registration — re-sourcing this file is harmless.
(( ${precmd_functions[(I)_aikey_precmd]} )) || precmd_functions+=(_aikey_precmd)
(( ${preexec_functions[(I)_aikey_preexec]} )) || preexec_functions+=(_aikey_preexec)
"#
}

/// Content of `~/.aikey/hook.bash`.
fn hook_bash_content() -> &'static str {
    r#"# ~/.aikey/hook.bash — auto-generated by `aikey use`, do not hand-edit
# Version: 3
aikey() {
    case "$1" in
        activate|deactivate)
            local _output
            _output=$(command aikey "$@" --shell bash)
            local _rc=$?
            if [ $_rc -eq 0 ]; then eval "$_output"; else return $_rc; fi
            ;;
        *) command aikey "$@" ;;
    esac
}

# Guarded: respect a pre-existing ak alias/function (e.g. user's kubectl shortcut).
if ! type ak >/dev/null 2>&1; then
    ak() { aikey "$@"; }
fi

_aikey_precmd_bash() {
    [ -n "$AIKEY_ACTIVE_LABEL" ] && return
    [ -f ~/.aikey/active.env ] && source ~/.aikey/active.env
}

_aikey_preexec_bash() {
    [ -z "$AIKEY_ACTIVE_KEYS" ] && return
    local cmd="${BASH_COMMAND%% *}" prov
    case "$cmd" in
        claude) prov=anthropic ;;
        codex)  prov=openai ;;
        kimi)   prov=kimi ;;
        *) return ;;
    esac
    local id
    id=$(echo "$AIKEY_ACTIVE_KEYS" | tr ',' '\n' | grep "^${prov}=" | cut -d= -f2-)
    [ -n "$id" ] && printf '\033[90m[aikey] %s → %s\033[0m\n' "$cmd" "$id"
}

# Dedupe-safe PROMPT_COMMAND registration. Append-with-check preserves hooks
# from direnv / pyenv / atuin that may have registered first.
case ";$PROMPT_COMMAND;" in
    *\;_aikey_precmd_bash\;*) ;;
    *) PROMPT_COMMAND="_aikey_precmd_bash${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
# bash has no native preexec — fall back to the DEBUG trap. But DEBUG can hold
# only one handler at a time, so unconditionally setting it would clobber any
# trap the user (or tools like bash-preexec) already installed. Defer if one
# exists; we lose the per-command label echo but preserve user plumbing. Users
# who want the label can integrate via `bash-preexec.sh`'s `preexec_functions`.
if [ -z "$(trap -p DEBUG 2>/dev/null)" ]; then
    trap '_aikey_preexec_bash' DEBUG
fi
"#
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
    let content = if is_zsh { hook_zsh_content() } else { hook_bash_content() };
    let aikey_dir = std::path::PathBuf::from(home).join(".aikey");
    std::fs::create_dir_all(&aikey_dir)?;
    let target = aikey_dir.join(filename);
    let tmp = aikey_dir.join(format!("{}.aikey.tmp", filename));
    std::fs::write(&tmp, content)?;
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
    fn kimi_region_contains_scaffold_and_placeholder_api_key() {
        let r = build_kimi_managed_region(27200);
        assert!(r.starts_with(AIKEY_BEGIN));
        assert!(r.trim_end().ends_with(AIKEY_END));
        // Provider block with correct base_url and PLACEHOLDER api_key (token
        // comes from KIMI_API_KEY env var at runtime — see docstring).
        assert!(r.contains("[providers.kimi]"));
        assert!(r.contains("type = \"kimi\""));
        assert!(r.contains("base_url = \"http://127.0.0.1:27200/kimi/v1\""));
        assert!(r.contains(&format!("api_key = \"{}\"", KIMI_PLACEHOLDER_API_KEY)));
        // Placeholder name self-documents its override mechanism.
        assert!(KIMI_PLACEHOLDER_API_KEY.contains("KIMI_API_KEY"));
        // Models.
        assert!(r.contains("[models.kimi-k2-5]"));
        assert!(r.contains("[models.moonshot-v1-128k]"));
        // Stop hook with render-kimi command.
        assert!(r.contains("[[hooks]]"));
        assert!(r.contains("event = \"Stop\""));
        assert!(r.contains("statusline render kimi"));
    }

    #[test]
    fn kimi_region_respects_proxy_port() {
        let r = build_kimi_managed_region(19999);
        assert!(r.contains("127.0.0.1:19999"));
        assert!(!r.contains(":27200")); // no stale default leaks through
    }

    #[test]
    fn kimi_region_is_token_agnostic() {
        // The scaffold no longer embeds a real token — repeated calls with the
        // same port produce identical output. This is what lets `aikey use`
        // be a no-op after the first installation.
        let a = build_kimi_managed_region(27200);
        let b = build_kimi_managed_region(27200);
        assert_eq!(a, b);
    }

    #[test]
    fn kimi_replace_region_preserves_surrounding_content() {
        let before = "default_model = \"kimi-k2-5\"\n\n";
        let old_region = format!("{AIKEY_BEGIN}\n[providers.kimi]\napi_key = \"old\"\n{AIKEY_END}");
        let after = "\n\n# user-added provider below\n[providers.custom]\nkey = \"keep-me\"\n";
        let existing = format!("{before}{old_region}{after}");

        let new_region = build_kimi_managed_region(27200);
        let out = replace_managed_region(&existing, &new_region).unwrap();

        assert!(out.starts_with("default_model = \"kimi-k2-5\"\n\n"));
        assert!(out.contains(KIMI_PLACEHOLDER_API_KEY));
        assert!(!out.contains("api_key = \"old\""));
        assert!(out.contains("[providers.custom]"));
        assert!(out.contains("keep-me"));
    }

    #[test]
    fn kimi_replace_region_returns_none_without_markers() {
        let plain = "default_model = \"kimi-k2-5\"\n[providers.custom]\nkey = \"k\"\n";
        let region = build_kimi_managed_region(27200);
        assert!(replace_managed_region(plain, &region).is_none());
    }

    #[test]
    fn kimi_strip_region_removes_region_and_one_trailing_newline() {
        let region = build_kimi_managed_region(27200);
        let existing = format!("default_model = \"kimi-k2-5\"\n\n{region}\n\n# user\n");
        let out = strip_managed_region(&existing).unwrap();
        assert!(out.starts_with("default_model = \"kimi-k2-5\"\n\n"));
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
}
