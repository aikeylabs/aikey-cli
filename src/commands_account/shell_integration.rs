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

pub(super) fn write_active_env(
    key_type: &str,
    key_ref: &str,    // virtual_key_id (team) or alias (personal)
    display_name: &str,
    providers: &[String],
    proxy_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let aikey_dir = std::path::PathBuf::from(&home).join(".aikey");
    std::fs::create_dir_all(&aikey_dir)?;
    let env_path = aikey_dir.join("active.env");

    let mut lines = vec![
        format!("# aikey active key — auto-generated by 'aikey use', do not edit manually"),
        format!("export AIKEY_ACTIVE_KEY=\"{}\"", display_name),
    ];

    for provider in providers {
        if let Some((api_key_var, base_url_var)) = super::provider_env_vars(provider) {
            let token_value = if key_type == "team" {
                format!("aikey_vk_{}", key_ref)
            } else {
                format!("aikey_personal_{}", key_ref)
            };
            let base_url = format!("http://127.0.0.1:{}/{}", proxy_port, super::provider_proxy_prefix(provider));
            lines.push(format!("export {}=\"{}\"", api_key_var, token_value));
            lines.push(format!("export {}=\"{}\"", base_url_var, base_url));
        }
    }

    // Ensure localhost proxy traffic bypasses user's HTTP proxy.
    // Appends to existing no_proxy via shell expansion — does not clobber.
    if !providers.is_empty() {
        lines.push(format!("export no_proxy=\"127.0.0.1,localhost,${{no_proxy:-}}\""));
        lines.push(format!("export NO_PROXY=\"127.0.0.1,localhost,${{NO_PROXY:-}}\""));
    }

    std::fs::write(&env_path, lines.join("\n") + "\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shell hook installer
// ---------------------------------------------------------------------------

/// Installs the shell precmd hook into ~/.zshrc or ~/.bashrc on first `aikey use`.
/// Returns the hook lines written, or `None` if no hook is needed / supported.
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
        // Unknown shell — print manual instruction.
        return Some(format!(
            "  Add to your shell config: source ~/.aikey/active.env"
        ));
    }

    // Determine the rc file to check/write.
    let rc_candidates: Vec<String> = if is_zsh {
        vec![format!("{}/.zshrc", home)]
    } else {
        vec![
            format!("{}/.bashrc", home),
            format!("{}/.bash_profile", home),
        ]
    };

    // Check if hook is already installed in any candidate.
    let hook_marker = "# aikey shell hook";
    for rc in &rc_candidates {
        if let Ok(contents) = std::fs::read_to_string(rc) {
            if contents.contains(hook_marker) {
                return None; // already installed
            }
        }
    }

    // Write to the first candidate that exists or the first one if none exist.
    let rc_file = rc_candidates
        .iter()
        .find(|rc| std::path::Path::new(rc).exists())
        .or_else(|| rc_candidates.first())
        .cloned()?;

    let hook_block = if is_zsh {
        format!(
            "\n{}\n_aikey_precmd() {{ [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env; }}\nprecmd_functions+=(_aikey_precmd)\n",
            hook_marker
        )
    } else {
        format!(
            "\n{}\nPROMPT_COMMAND='[[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env'\n",
            hook_marker
        )
    };

    // Prompt the user before writing.
    use std::io::{IsTerminal, Write};
    if io::stderr().is_terminal() {
        let shell_name = if is_zsh { "zsh" } else { "bash" };
        let hook_desc = if is_zsh { "precmd hook" } else { "PROMPT_COMMAND" };
        let rows = vec![
            format!("Shell:  {}", shell_name),
            format!("File:   {}", rc_file),
            format!("Add:    {} \u{2192} source ~/.aikey/active.env", hook_desc),
        ];
        crate::ui_frame::eprint_box("\u{2753}", "Install Shell Hook", &rows);
        eprint!("  Proceed? [Y/n] (default Y): ");
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            match input.trim().to_lowercase().as_str() {
                "n" | "no" => {
                    return Some(format!("  Run: source ~/.aikey/active.env  (to apply once)"));
                }
                _ => {}
            }
        }
    }

    match std::fs::OpenOptions::new().append(true).open(&rc_file) {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.write_all(hook_block.as_bytes());
            Some(format!("  Shell hook installed in {}", rc_file))
        }
        Err(_) => Some(format!("  Could not write to {}. Run: source ~/.aikey/active.env", rc_file)),
    }
}
