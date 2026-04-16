//! Shell hook installation and third-party CLI auto-configuration helpers.
//!
//! Extracted from `commands_account.rs` — pure structural refactor, no logic changes.

use std::io;

// ---------------------------------------------------------------------------
// Kimi CLI auto-configuration
// ---------------------------------------------------------------------------

pub fn configure_kimi_cli(token_value: &str, proxy_port: u16) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".kimi");
    let config_path = config_dir.join("config.toml");

    let base_url = format!("http://127.0.0.1:{}/kimi/v1", proxy_port);

    // Read existing config or start with defaults.
    let mut content = std::fs::read_to_string(&config_path).unwrap_or_default();

    let marker = "# managed by aikey";

    // Already configured — silent update (no prompt needed for subsequent switches).
    if content.contains(marker) {
        let mut updated = String::new();
        let mut in_kimi_provider = false;
        for line in content.lines() {
            if line.starts_with("[providers.kimi]") {
                in_kimi_provider = true;
                updated.push_str(line);
            } else if line.starts_with('[') {
                in_kimi_provider = false;
                updated.push_str(line);
            } else if in_kimi_provider && line.starts_with("api_key = ") {
                updated.push_str(&format!("api_key = \"{}\"", token_value));
            } else if in_kimi_provider && line.starts_with("base_url = ") {
                updated.push_str(&format!("base_url = \"{}\"", base_url));
            } else if line.starts_with("default_model = ") {
                // Why: TOML section keys cannot contain dots, so "kimi-k2.5" becomes
                // key "kimi-k2-5". Kimi CLI validates default_model against key names.
                let fixed = line
                    .replace("\"kimi-k2.5\"", "\"kimi-k2-5\"")
                    .replace("\"moonshot-v1.128k\"", "\"moonshot-v1-128k\"");
                updated.push_str(&fixed);
            } else {
                updated.push_str(line);
            }
            updated.push('\n');
        }
        let _ = std::fs::write(&config_path, updated);
        return;
    }

    // First time — prompt user before modifying their config.
    if io::stderr().is_terminal() {
        let mut rows: Vec<String> = vec![
            format!("File:    {}", "~/.kimi/config.toml"),
            format!("Add:     provider  base_url={}", base_url),
            format!("         models: kimi-k2.5, moonshot-v1-128k"),
        ];
        if !content.is_empty() {
            rows.push(format!("Backup:  {}", "~/.kimi/config.aikey_backup.toml"));
        }
        crate::ui_frame::eprint_box("\u{2753}", "Configure Kimi CLI", &rows);
        eprint!("  Proceed? [Y/n] (default Y): ");
        io::stderr().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if input.trim().to_lowercase() == "n" {
                eprintln!("  {}", "Skipped. Run 'aikey use kimi' again to retry.".dimmed());
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

    // If default_model is empty, set it.
    if content.contains("default_model = \"\"") {
        content = content.replace("default_model = \"\"", "default_model = \"kimi-k2-5\"");
    }

    let kimi_provider = format!(
        "[providers.kimi]  {}\ntype = \"kimi\"\nbase_url = \"{}\"\napi_key = \"{}\"",
        marker, base_url, token_value
    );
    let kimi_models = concat!(
        "[models.kimi-k2-5]\nprovider = \"kimi\"\nmodel = \"kimi-k2.5\"\nmax_context_size = 131072\n\n",
        "[models.moonshot-v1-128k]\nprovider = \"kimi\"\nmodel = \"moonshot-v1-128k\"\nmax_context_size = 131072",
    );

    if content.contains("[providers]") && !content.contains("[providers.") {
        content = content.replace("[providers]", &kimi_provider);
    } else if !content.contains("[providers.kimi]") {
        content.push_str(&format!("\n{}\n", kimi_provider));
    }

    if content.contains("[models]") && !content.contains("[models.") {
        content = content.replace("[models]", kimi_models);
    } else if !content.contains("[models.kimi") {
        content.push_str(&format!("\n{}\n", kimi_models));
    }

    match std::fs::write(&config_path, &content) {
        Ok(_) => {
            eprintln!("  {} Kimi CLI auto-configured: {}",
                "✓".green().bold(),
                config_path.display().to_string().dimmed());
        }
        Err(e) => {
            eprintln!("  {} Could not configure Kimi CLI: {}",
                "!".yellow(), e);
        }
    }
}

/// Restore `~/.kimi/config.toml` from the backup created by `configure_kimi_cli`.
///
/// Called when `aikey use` switches to a key that does not include kimi.
/// If a backup exists (`config.aikey_backup.toml`), it is moved back to `config.toml`.
/// If no backup exists but the config contains our marker, it is left as-is
/// (the user may have modified it after we configured it).
pub fn unconfigure_kimi_cli() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".kimi");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    if backup_path.exists() {
        // Restore the original config from backup.
        let _ = std::fs::rename(&backup_path, &config_path);
    } else if config_path.exists() {
        // No backup but config exists — check if it's ours.
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();
        if content.contains("# managed by aikey") {
            // We created this file from scratch (there was no original).
            // Remove it so Kimi CLI returns to its default behavior.
            let _ = std::fs::remove_file(&config_path);
        }
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
        // Overwrite the plain no_proxy lines with shell-expansion versions.
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
        // Append activate-hook source line for live upgrade (no `source ~/.zshrc` needed).
        // Why: when `aikey use` upgrades the shell hook from v1→v2, the current terminal
        // still has old function definitions. This line injects the new wrapper + sentinel
        // on the very next prompt via the existing v1 precmd → source active.env chain.
        // The hook files are idempotent; re-sourcing them just redefines functions.
        let content = format!(
            "{}# Live-load activate wrapper (idempotent)\n\
             [[ -f ~/.aikey/activate-hook.zsh ]] && source ~/.aikey/activate-hook.zsh\n\
             [[ -f ~/.aikey/activate-hook.bash ]] && source ~/.aikey/activate-hook.bash\n",
            content
        );
        std::fs::write(&env_path, content)?;
    } else {
        sh_lines.push("# Live-load activate wrapper (idempotent)".to_string());
        sh_lines.push("[[ -f ~/.aikey/activate-hook.zsh ]] && source ~/.aikey/activate-hook.zsh".to_string());
        sh_lines.push("[[ -f ~/.aikey/activate-hook.bash ]] && source ~/.aikey/activate-hook.bash".to_string());
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
// Shell hook installer (v2: begin/end markers, activate wrapper, sentinel precmd)
// ---------------------------------------------------------------------------

const V1_MARKER: &str = "# aikey shell hook";
const V2_BEGIN: &str = "# aikey shell hook v2 begin";
const V2_END: &str = "# aikey shell hook v2 end";

/// Known v1 hook templates for precise matching during auto-upgrade.
/// If the v1 block in the user's rc file matches one of these exactly,
/// we can safely replace it. Otherwise we fall back to manual instructions.
fn v1_zsh_template() -> String {
    concat!(
        "# aikey shell hook\n",
        "_aikey_precmd() {\n",
        "  [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env\n",
        "  # Auto-load preexec hook if not yet loaded\n",
        "  if ! (( ${+functions[_aikey_preexec]} )); then\n",
        "    [[ -f ~/.aikey/preexec.zsh ]] && source ~/.aikey/preexec.zsh\n",
        "  fi\n",
        "}\n",
        "precmd_functions+=(_aikey_precmd)\n",
    ).to_string()
}

fn v1_bash_template() -> String {
    concat!(
        "# aikey shell hook\n",
        "_aikey_precmd_bash() {\n",
        "  [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env\n",
        "  if ! type -t _aikey_preexec_bash &>/dev/null; then\n",
        "    [[ -f ~/.aikey/preexec.bash ]] && source ~/.aikey/preexec.bash\n",
        "  fi\n",
        "}\n",
        "PROMPT_COMMAND='_aikey_precmd_bash'\n",
    ).to_string()
}

/// Generate v2 hook block for zsh.
fn v2_zsh_hook() -> String {
    format!(
        concat!(
            "{}\n",
            "aikey() {{\n",
            "    case \"$1\" in\n",
            "        activate|deactivate)\n",
            "            local _output\n",
            "            _output=$(command aikey \"$@\" --shell zsh)\n",
            "            local _rc=$?\n",
            "            if [ $_rc -eq 0 ]; then eval \"$_output\"; else return $_rc; fi\n",
            "            ;;\n",
            "        *) command aikey \"$@\" ;;\n",
            "    esac\n",
            "}}\n",
            "_aikey_precmd() {{\n",
            "    if [ -n \"$AIKEY_ACTIVE_LABEL\" ]; then return; fi\n",
            "    [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env\n",
            "    if ! (( ${{+functions[_aikey_preexec]}} )); then\n",
            "        [[ -f ~/.aikey/preexec.zsh ]] && source ~/.aikey/preexec.zsh\n",
            "    fi\n",
            "}}\n",
            "precmd_functions+=(_aikey_precmd)\n",
            "{}\n",
        ),
        V2_BEGIN, V2_END,
    )
}

/// Generate v2 hook block for bash.
fn v2_bash_hook() -> String {
    format!(
        concat!(
            "{}\n",
            "aikey() {{\n",
            "    case \"$1\" in\n",
            "        activate|deactivate)\n",
            "            local _output\n",
            "            _output=$(command aikey \"$@\" --shell bash)\n",
            "            local _rc=$?\n",
            "            if [ $_rc -eq 0 ]; then eval \"$_output\"; else return $_rc; fi\n",
            "            ;;\n",
            "        *) command aikey \"$@\" ;;\n",
            "    esac\n",
            "}}\n",
            "_aikey_precmd_bash() {{\n",
            "    if [ -n \"$AIKEY_ACTIVE_LABEL\" ]; then return; fi\n",
            "    [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env\n",
            "    if ! type -t _aikey_preexec_bash &>/dev/null; then\n",
            "        [[ -f ~/.aikey/preexec.bash ]] && source ~/.aikey/preexec.bash\n",
            "    fi\n",
            "}}\n",
            "# Why append: direct assignment (PROMPT_COMMAND='...') would clobber existing\n",
            "# hooks from direnv, pyenv, atuin, etc. Append-with-dedup preserves them.\n",
            "[[ \"$PROMPT_COMMAND\" != *_aikey_precmd_bash* ]] && PROMPT_COMMAND=\"_aikey_precmd_bash${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}\"\n",
            "{}\n",
        ),
        V2_BEGIN, V2_END,
    )
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

/// Installs the shell precmd hook into ~/.zshrc or ~/.bashrc on first `aikey use`.
/// Returns the hook lines written, or `None` if no hook is needed / supported.
///
/// Hook versioning:
/// - v1: `# aikey shell hook` (no end marker, no wrapper function)
/// - v2: `# aikey shell hook v2 begin` ... `# aikey shell hook v2 end`
///        (wrapper function for activate/deactivate, sentinel precmd, preexec)
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
        return Some("  Add to your shell config: source ~/.aikey/active.env".to_string());
    }

    // Ensure helper files exist (always overwritten — idempotent).
    // activate-hook: wrapper function + sentinel precmd (sourced from active.env for live upgrade).
    // preexec: prints active key info when running AI CLI tools.
    if is_zsh {
        write_activate_hook_zsh(&home);
        write_preexec_zsh(&home);
    } else {
        write_activate_hook_bash(&home);
        write_preexec_bash(&home);
    }

    let rc_candidates: Vec<String> = if is_zsh {
        vec![format!("{}/.zshrc", home)]
    } else {
        vec![
            format!("{}/.bashrc", home),
            format!("{}/.bash_profile", home),
        ]
    };

    let new_hook = if is_zsh { v2_zsh_hook() } else { v2_bash_hook() };

    // ── Check existing hooks in all rc candidates ───────────────────────────
    for rc in &rc_candidates {
        let contents = match std::fs::read_to_string(rc) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Case 1: v2 already installed — replace in-place (hotfix upgrade).
        if contents.contains(V2_BEGIN) {
            if let Some(updated) = replace_between_markers(&contents, V2_BEGIN, V2_END, &new_hook) {
                let _ = std::fs::write(rc, updated);
            }
            return None; // v2 present, up to date
        }

        // Case 2: v1 detected — try auto-upgrade via precise template matching.
        if contents.contains(V1_MARKER) && !contents.contains(V2_BEGIN) {
            let v1_template = if is_zsh { v1_zsh_template() } else { v1_bash_template() };

            if let Some(idx) = contents.find(&v1_template) {
                // Precise match: replace v1 block with v2.
                let mut updated = String::with_capacity(contents.len());
                updated.push_str(&contents[..idx]);
                updated.push_str(&new_hook);
                updated.push_str(&contents[idx + v1_template.len()..]);
                let _ = std::fs::write(rc, updated);
                eprintln!(
                    "  \x1b[32m\u{2713}\x1b[0m Shell hook upgraded to v2 (activate support) in {}",
                    rc
                );
                return None;
            }

            // v1 present but modified — can't auto-upgrade safely.
            eprintln!();
            eprintln!("  \x1b[33m!\x1b[0m Old aikey shell hook detected in {}", rc);
            eprintln!("    Cannot auto-upgrade (hook was modified). Please:");
            eprintln!();
            eprintln!("    1. Open {} in an editor", rc);
            eprintln!("    2. Delete the block starting with '{}'", V1_MARKER);
            eprintln!("    3. Run 'aikey use' again to install the new hook");
            eprintln!();
            return None;
        }
    }

    // ── No hook found — fresh install ───────────────────────────────────────
    let rc_file = rc_candidates
        .iter()
        .find(|rc| std::path::Path::new(rc).exists())
        .or_else(|| rc_candidates.first())
        .cloned()?;

    // Prompt the user before writing.
    use std::io::{IsTerminal, Write};
    if io::stderr().is_terminal() {
        let shell_name = if is_zsh { "zsh" } else { "bash" };
        let rows = vec![
            format!("Shell:  {}", shell_name),
            format!("File:   {}", rc_file),
            format!("Add:    precmd + activate wrapper (v2)"),
        ];
        crate::ui_frame::eprint_box("\u{2753}", "Install Shell Hook", &rows);
        eprint!("  Proceed? [Y/n] (default Y): ");
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            match input.trim().to_lowercase().as_str() {
                "n" | "no" => {
                    return Some("  Run: source ~/.aikey/active.env  (to apply once)".to_string());
                }
                _ => {}
            }
        }
    }

    match std::fs::OpenOptions::new().append(true).open(&rc_file) {
        Ok(mut f) => {
            use std::io::Write as _;
            let block = format!("\n{}", new_hook);
            let _ = f.write_all(block.as_bytes());
            Some(format!("  Shell hook installed in {}", rc_file))
        }
        Err(_) => Some(format!("  Could not write to {}. Run: source ~/.aikey/active.env", rc_file)),
    }
}

/// Write `~/.aikey/activate-hook.zsh` — standalone file with wrapper function
/// and sentinel precmd, sourced from active.env on every prompt.
///
/// Why: when `aikey use` upgrades the hook in .zshrc from v1 to v2, the current
/// shell session still has the old v1 function definitions loaded. Writing a
/// separate file and sourcing it from active.env injects the new definitions
/// on the very next prompt — no manual `source ~/.zshrc` needed.
///
/// This file is always overwritten (idempotent). Re-sourcing it is harmless
/// since it only (re)defines functions.
fn write_activate_hook_zsh(home: &str) -> Option<String> {
    let path = format!("{}/.aikey/activate-hook.zsh", home);
    let content = r#"# aikey activate hook — auto-generated, do not edit manually
# Defines aikey() wrapper for activate/deactivate and sentinel precmd.
# Sourced from active.env on every prompt for live upgrades.
if ! (( ${+functions[aikey]} )); then
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
fi
# Override precmd to add sentinel check (idempotent — redefining is safe
# because precmd_functions references the function by name).
_aikey_precmd() {
    if [ -n "$AIKEY_ACTIVE_LABEL" ]; then return; fi
    [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env
    if ! (( ${+functions[_aikey_preexec]} )); then
        [[ -f ~/.aikey/preexec.zsh ]] && source ~/.aikey/preexec.zsh
    fi
}
"#;
    std::fs::write(&path, content).ok()?;
    Some(path)
}

/// Write `~/.aikey/activate-hook.bash` — bash equivalent of activate-hook.zsh.
fn write_activate_hook_bash(home: &str) -> Option<String> {
    let path = format!("{}/.aikey/activate-hook.bash", home);
    let content = r#"# aikey activate hook — auto-generated, do not edit manually
# Defines aikey() wrapper for activate/deactivate and sentinel precmd.
# Sourced from active.env on every prompt for live upgrades.
if ! type -t aikey | grep -q function 2>/dev/null; then
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
fi
# Override precmd to add sentinel check.
_aikey_precmd_bash() {
    if [ -n "$AIKEY_ACTIVE_LABEL" ]; then return; fi
    [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env
    if ! type -t _aikey_preexec_bash &>/dev/null; then
        [[ -f ~/.aikey/preexec.bash ]] && source ~/.aikey/preexec.bash
    fi
}
"#;
    std::fs::write(&path, content).ok()?;
    Some(path)
}

/// Write `~/.aikey/preexec.zsh` — the preexec hook sourced on-the-fly by precmd.
/// This file is always overwritten (idempotent), so upgrades take effect immediately
/// on the next prompt without requiring `source ~/.zshrc`.
fn write_preexec_zsh(home: &str) -> Option<String> {
    let path = format!("{}/.aikey/preexec.zsh", home);
    let content = r#"# aikey preexec hook — auto-generated, do not edit manually
# Prints active key/account when running AI CLI tools.
_aikey_preexec() {
  [[ -z "$AIKEY_ACTIVE_KEYS" ]] && return
  local cmd="${1%% *}" prov
  case "$cmd" in
    claude) prov=anthropic ;;
    codex)  prov=openai ;;
    kimi)   prov=kimi ;;
    *)      return ;;
  esac
  local id=$(echo "$AIKEY_ACTIVE_KEYS" | tr ',' '\n' | grep "^${prov}=" | cut -d= -f2-)
  [[ -n "$id" ]] && printf '\033[90m[aikey] %s → %s\033[0m\n' "$cmd" "$id"
}
preexec_functions+=(_aikey_preexec)
"#;
    std::fs::write(&path, content).ok()?;
    Some(path)
}

/// Write `~/.aikey/preexec.bash` — the preexec hook for bash (DEBUG trap).
fn write_preexec_bash(home: &str) -> Option<String> {
    let path = format!("{}/.aikey/preexec.bash", home);
    let content = r#"# aikey preexec hook — auto-generated, do not edit manually
_aikey_preexec_bash() {
  [[ -z "$AIKEY_ACTIVE_KEYS" ]] && return
  local cmd="${BASH_COMMAND%% *}" prov
  case "$cmd" in
    claude) prov=anthropic ;;
    codex)  prov=openai ;;
    kimi)   prov=kimi ;;
    *)      return ;;
  esac
  local id=$(echo "$AIKEY_ACTIVE_KEYS" | tr ',' '\n' | grep "^${prov}=" | cut -d= -f2-)
  [[ -n "$id" ]] && printf '\033[90m[aikey] %s → %s\033[0m\n' "$cmd" "$id"
}
trap '_aikey_preexec_bash' DEBUG
"#;
    std::fs::write(&path, content).ok()?;
    Some(path)
}

#[cfg(test)]
mod hook_tests {
    use super::*;

    // ── v2 hook block structure ─────────────────────────────────────────────

    #[test]
    fn v2_zsh_hook_has_markers() {
        let hook = v2_zsh_hook();
        assert!(hook.starts_with(V2_BEGIN));
        assert!(hook.trim_end().ends_with(V2_END));
    }

    #[test]
    fn v2_bash_hook_has_markers() {
        let hook = v2_bash_hook();
        assert!(hook.starts_with(V2_BEGIN));
        assert!(hook.trim_end().ends_with(V2_END));
    }

    #[test]
    fn v2_zsh_hook_contains_wrapper_and_sentinel() {
        let hook = v2_zsh_hook();
        assert!(hook.contains("aikey()"));
        assert!(hook.contains("activate|deactivate"));
        assert!(hook.contains("--shell zsh"));
        assert!(hook.contains("AIKEY_ACTIVE_LABEL"));
    }

    #[test]
    fn v2_bash_hook_contains_wrapper_and_sentinel() {
        let hook = v2_bash_hook();
        assert!(hook.contains("aikey()"));
        assert!(hook.contains("--shell bash"));
        assert!(hook.contains("AIKEY_ACTIVE_LABEL"));
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

    // ── v1 template matching & upgrade simulation ───────────────────────────

    #[test]
    fn v1_zsh_template_structure() {
        let template = v1_zsh_template();
        assert!(template.starts_with(V1_MARKER));
        assert!(template.contains("_aikey_precmd()"));
        assert!(template.contains("preexec.zsh"));
    }

    #[test]
    fn v1_bash_template_structure() {
        let template = v1_bash_template();
        assert!(template.starts_with(V1_MARKER));
        assert!(template.contains("_aikey_precmd_bash()"));
        assert!(template.contains("preexec.bash"));
    }

    #[test]
    fn v1_upgrade_simulation_zsh() {
        let v1 = v1_zsh_template();
        let rc = format!("export FOO=bar\n\n{}\n# user code\n", v1);

        assert!(rc.contains(V1_MARKER));
        assert!(!rc.contains(V2_BEGIN));

        let idx = rc.find(&v1).unwrap();
        let mut upgraded = String::new();
        upgraded.push_str(&rc[..idx]);
        upgraded.push_str(&v2_zsh_hook());
        upgraded.push_str(&rc[idx + v1.len()..]);

        assert!(upgraded.contains(V2_BEGIN));
        assert!(upgraded.contains(V2_END));
        assert!(upgraded.contains("AIKEY_ACTIVE_LABEL"));
        assert!(upgraded.contains("export FOO=bar"));
        assert!(upgraded.contains("# user code"));
    }

    #[test]
    fn v2_hotfix_replacement() {
        let old_v2 = v2_zsh_hook();
        let rc = format!("export FOO=bar\n{}\n# user code\n", old_v2);

        // Simulate hotfix: replace v2 block with a new v2.
        let new_v2 = v2_zsh_hook(); // same content in this test
        let result = replace_between_markers(&rc, V2_BEGIN, V2_END, &new_v2);
        let out = result.unwrap();
        assert!(out.contains(V2_BEGIN));
        assert!(out.contains("export FOO=bar"));
        assert!(out.contains("# user code"));
    }
}
