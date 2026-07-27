use crate::config::{EnvTemplate, LogicalModelMapping, ProjectConfig, ProviderConfig};
use crate::global_config;
use crate::json_output;
use crate::storage;
use secrecy::SecretString;
use std::io::{self, Write};
use zeroize::Zeroizing;

// Connectivity test code moved to `crate::connectivity` in 2026-04-21. The
// `pub use` below preserves callsite paths (`commands_project::TestTarget`
// etc.) while the canonical home is now `crate::connectivity::*`.
pub use crate::connectivity::*;

pub fn handle_project_init(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::path::Path::new("aikey.config.json");

    // Check if config already exists
    if config_path.exists() {
        if json_mode {
            return Err("Config file already exists".into());
        }

        println!("Found existing aikey.config.json");
        print!("Would you like to update it? (y/n): ");
        io::stdout().flush().ok();

        let mut response = String::new();
        io::stdin().read_line(&mut response).ok();

        if !response.trim().eq_ignore_ascii_case("y") {
            return Err("Cancelled".into());
        }
    }

    // Get project name
    let folder_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "My Project".to_string());

    let project_name = if json_mode {
        folder_name
    } else {
        print!("Project name [{}]: ", folder_name);
        io::stdout().flush().ok();

        let mut name = String::new();
        io::stdin().read_line(&mut name).ok();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            folder_name
        } else {
            trimmed.to_string()
        }
    };

    // Get language/stack
    let stack = if json_mode {
        "node".to_string()
    } else {
        println!("\nSelect language/stack:");
        println!("  1) Node.js");
        println!("  2) Python");
        println!("  3) Other");
        print!("Choice [1]: ");
        io::stdout().flush().ok();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).ok();
        match choice.trim() {
            "2" => "python".to_string(),
            "3" => "other".to_string(),
            _ => "node".to_string(),
        }
    };

    // Get .env target
    let env_target = if json_mode {
        ".env".to_string()
    } else {
        print!("\n.env file target [.env]: ");
        io::stdout().flush().ok();

        let mut target = String::new();
        io::stdin().read_line(&mut target).ok();
        let trimmed = target.trim();
        if trimmed.is_empty() {
            ".env".to_string()
        } else {
            trimmed.to_string()
        }
    };

    // Get required variables
    let suggested_vars = match stack.as_str() {
        "python" => EnvTemplate::python_vars(),
        "other" => EnvTemplate::other_vars(),
        _ => EnvTemplate::node_vars(),
    };

    let required_vars = if json_mode {
        suggested_vars.iter().map(|s| s.to_string()).collect()
    } else {
        println!("\nSuggested environment variables for {}:", stack);
        for (i, var) in suggested_vars.iter().enumerate() {
            println!("  {}) {}", i + 1, var);
        }
        print!("Use suggested? (y/n) [y]: ");
        io::stdout().flush().ok();

        let mut response = String::new();
        io::stdin().read_line(&mut response).ok();

        if response.trim().eq_ignore_ascii_case("n") {
            println!("Enter variable names (comma-separated):");
            let mut vars_input = String::new();
            io::stdin().read_line(&mut vars_input).ok();
            vars_input
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            suggested_vars.iter().map(|s| s.to_string()).collect()
        }
    };

    // Create and save config
    let mut config = ProjectConfig::new(project_name);
    config.env.target = env_target;
    config.required_vars = required_vars;

    config.save(config_path)?;

    if !json_mode {
        println!("\n{} Created aikey.config.json", crate::symbols::CHECK.s());
        println!("\nNext steps:");
        println!("  1. Run 'aikey add <provider>:<alias>' to add provider keys (e.g. aikey add anthropic:default)");
        println!(
            "  2. Run 'aikey env generate' to create/update your .env file (non-sensitive only)"
        );
        println!("  3. Use 'aikey run -- <command>' to run with secrets injected");
        println!("  4. Use 'aikey project status' to check configuration");
    }

    Ok(())
}

/// Handle `aikey project status` command
pub fn handle_project_status(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let discovered = ProjectConfig::discover()?;
    let (config_path, config) = match discovered {
        Some(pair) => pair,
        None => {
            if json_mode {
                json_output::print_json_exit(
                    serde_json::json!({
                        "ok": false,
                        "code": crate::error_codes::ErrorCode::InvalidInput.as_str(),
                        "message": "No aikey.config.json found in current directory or parent directories"
                    }),
                    1,
                );
            }
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No aikey.config.json found in current directory or parent directories",
            )));
        }
    };

    let template_parts: Vec<String> = config
        .required_vars
        .iter()
        .map(|var| format!("{}={{{}}}", var, var))
        .collect();
    let _template = template_parts.join("\n");

    let _project_path = config_path.parent().and_then(|p| p.to_str());
    let _config_path_str = config_path.to_str();

    // Check which required vars are satisfied by checking vault entries
    let total = config.required_vars.len();
    let mut satisfied = 0;
    let mut missing_vars = Vec::new();

    let stored = storage::list_entries().unwrap_or_default();
    let stored_set: std::collections::HashSet<&str> = stored.iter().map(|s| s.as_str()).collect();
    for var in &config.required_vars {
        if stored_set.contains(var.as_str()) {
            satisfied += 1;
        } else {
            missing_vars.push(var.clone());
        }
    }

    if json_mode {
        let response = serde_json::json!({
            "ok": true,
            "config_path": config_path.display().to_string(),
            "project_name": config.project.name,
            "required_vars": config.required_vars,
            "satisfied": satisfied,
            "total": total,
            "missing_vars": missing_vars
        });
        json_output::print_json(response);
    } else {
        println!("Project Configuration Status");
        println!("============================");
        println!("Config path: {}", config_path.display());
        println!("Project name: {}", config.project.name);
        println!("Required variables: {}/{} satisfied", satisfied, total);

        if satisfied < total {
            println!("\nMissing variables:");
            for var in &missing_vars {
                println!("  - {}", var);
            }
            println!("\nRun 'aikey env generate' to update your .env file");
        } else {
            println!(
                "\n{} All required variables are satisfied",
                crate::symbols::CHECK.s()
            );
        }
    }

    Ok(())
}

/// Handle `aikey quickstart` command.
///
/// Prints a state-aware landing page showing the most useful next steps.
/// Vault initialization is no longer bundled here — `aikey add` / `aikey auth
/// login` / `aikey login` each handle their own prerequisites when run.
pub fn handle_quickstart(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Gather state. All queries tolerate a missing/unreadable vault by
    // returning empty results — the landing page still works pre-vault.
    let vault_exists = storage::get_vault_path()
        .map(|p| p.exists())
        .unwrap_or(false);
    let personal_count = if vault_exists {
        storage::list_entries().map(|v| v.len()).unwrap_or(0)
    } else {
        0
    };
    let team_active = storage::list_virtual_key_cache()
        .map(|v| v.into_iter().filter(|k| k.key_status == "active").count())
        .unwrap_or(0);
    let oauth_active = storage::list_provider_accounts()
        .map(|v| v.into_iter().filter(|a| a.status == "active").count())
        .unwrap_or(0);
    let logged_in = storage::get_platform_account().ok().flatten().is_some();
    // Round 9 fix #1: migrated from is_proxy_running (PID-only, unsafe per
    // Round 5) to proxy_is_running_managed (Layer 1 identity + ownership +
    // /health). Project status now agrees with `aikey proxy status` in
    // OrphanedPort / Unresponsive / PID-recycle scenarios.
    let proxy_running = crate::commands_proxy::proxy_is_running_managed();

    // User-facing categorization:
    //   key       = personal + team (raw API keys stored in the vault)
    //   account   = OAuth provider accounts
    //   login     = team Control Panel session
    let total_keys = personal_count + team_active;
    let total_credentials = total_keys + oauth_active;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "state": {
                "personal_keys": personal_count,
                "team_keys_active": team_active,
                "oauth_accounts_active": oauth_active,
                "logged_in": logged_in,
                "proxy_running": proxy_running,
            }
        }));
        return Ok(());
    }

    // Helper: print a command + inline description with consistent spacing.
    let tip = |cmd: &str, desc: &str| {
        println!(
            "     {}  {}",
            format!("{:<50}", cmd).cyan(),
            format!("# {}", desc).dimmed()
        );
    };

    // --- Banner --------------------------------------------------------
    println!();
    println!(
        "  {}{}",
        crate::symbols::ICON_ROCKET.pre(),
        "AiKey Quickstart".bold()
    );
    println!(
        "  {}",
        "Next steps tailored to your current state.".dimmed()
    );
    println!("  {}", crate::symbols::BOX_H.s().repeat(68).dimmed());
    println!();

    // --- Section 1: no raw key yet → add one -------------------------
    if total_keys == 0 {
        println!(
            "  {}",
            format!("{}Add your first API key", crate::symbols::ICON_KEY.pre()).bold()
        );
        tip("aikey add my-key --provider openai", "or anthropic | kimi");
        println!();
    }

    // --- Section 2: has key → activate + review ----------------------
    if total_keys > 0 {
        let summary = format!(
            "You have {} key{}",
            total_keys,
            if total_keys == 1 { "" } else { "s" }
        );
        println!(
            "  {} {}",
            crate::symbols::CHECK.s().green().bold(),
            summary.bold()
        );
        tip("aikey use", "pick which key to activate for routing");
        tip("aikey list", "review every credential");
        println!();
    }

    // --- Section 3: no OAuth account → offer to add one ------------
    if oauth_active == 0 {
        println!(
            "  {}",
            format!("{} Add a subscription account", crate::symbols::SUB_DOT.s()).bold()
        );
        tip("aikey auth login claude", "or codex | kimi");
        println!();
    }

    // --- Section 4: not logged into a team → offer team login ------
    if !logged_in {
        println!(
            "  {}",
            format!("{}Join your team", crate::symbols::ICON_PEOPLE.pre()).bold()
        );
        tip(
            "aikey login --control-url https://your.team.host",
            "team-managed keys auto-sync",
        );
        println!();
    }

    // --- Section 5: two or more credentials → show route picker ----
    if total_credentials >= 2 {
        println!(
            "  {}",
            format!(
                "{}Multiple routes available",
                crate::symbols::ICON_LINK.pre()
            )
            .bold()
        );
        tip(
            "aikey route",
            "pick a base_url + api_key for your IDE or CLI",
        );
        println!();
    }

    // --- Section 6: logged in → web console shortcut --------------
    if logged_in {
        println!(
            "  {}",
            format!(
                "{}Manage via the User Console",
                crate::symbols::ICON_GLOBE.pre()
            )
            .bold()
        );
        tip("aikey web", "open the web console in your browser");
        println!();
    }

    // --- Section 7: proxy not running → nudge to start ------------
    if !proxy_running {
        println!(
            "  {}",
            format!("{}  Proxy is not running", crate::symbols::WARN.s())
                .yellow()
                .bold()
        );
        tip("aikey proxy start", "required for routing to work");
        println!();
    }

    // --- Footer --------------------------------------------------
    println!("  {}", crate::symbols::BOX_H.s().repeat(68).dimmed());
    tip("aikey doctor", "check system health");
    tip("aikey --help", "all commands");
    println!();

    Ok(())
}

/// Handle `aikey project map` — bind a required var to a vault alias, and optionally
/// add an envMappings entry when --env, --provider, and --key-alias are provided.
pub fn handle_project_map(
    var: &str,
    alias: &str,
    env: Option<&str>,
    provider: Option<&str>,
    model: Option<&str>,
    key_alias: Option<&str>,
    impl_id: Option<&str>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify master password before mutating config
    let prompt_str = if json_mode {
        ""
    } else {
        &format!("{}Enter Master Password: ", crate::symbols::ICON_LOCK.pre())
    };
    let password = crate::prompt_hidden(prompt_str)?;
    let password_raw = Zeroizing::new(password);
    let secret = SecretString::new(password_raw.trim().to_string());

    // Verify the password is correct by attempting to list secrets
    crate::executor::list_secrets(&secret).map_err(|e| {
        Box::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
            as Box<dyn std::error::Error>
    })?;

    let (config_path, mut config) =
        ProjectConfig::discover()?.ok_or("No aikey.config.json found")?;

    // Always update bindings / required_vars
    config.bindings.insert(var.to_string(), alias.to_string());
    if !config.required_vars.contains(&var.to_string()) {
        config.required_vars.push(var.to_string());
    }

    // Optionally write an envMappings entry
    if let (Some(env_name), Some(prov), Some(ka)) = (env, provider, key_alias) {
        let logical_name = var.to_string();
        let entry = LogicalModelMapping {
            provider: prov.to_string(),
            provider_model_id: model.map(|m| m.to_string()),
            key_alias: ka.to_string(),
            impl_id: impl_id.map(|i| i.to_string()),
        };
        config
            .env_mappings
            .entry(env_name.to_string())
            .or_default()
            .insert(logical_name, entry);
    }

    config.save(&config_path)?;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "var": var,
            "alias": alias
        }));
    } else {
        println!("Mapped {} → {}", var, alias);
    }

    Ok(())
}

/// Handle `aikey provider add` — add/update a provider entry in the project config
pub fn handle_provider_add(
    name: &str,
    key_alias: &str,
    default_model: Option<&str>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, mut config) =
        ProjectConfig::discover()?.ok_or("No aikey.config.json found")?;

    config.providers.insert(
        name.to_string(),
        ProviderConfig {
            key_alias: key_alias.to_string(),
            default_model: default_model.map(|s| s.to_string()),
        },
    );

    config.save(&config_path)?;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "provider": name,
            "key_alias": key_alias,
            "default_model": default_model
        }));
    } else {
        println!("Provider '{}' added (alias: {})", name, key_alias);
    }

    Ok(())
}

/// Handle `aikey provider rm` — remove a provider from the profile config
pub fn handle_provider_rm(name: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, mut config) =
        ProjectConfig::discover()?.ok_or("No aikey.config.json found")?;

    if !json_mode {
        let key_alias = config
            .providers
            .get(name)
            .map(|p| p.key_alias.as_str())
            .unwrap_or(name);
        let profile = global_config::get_current_profile()
            .ok()
            .flatten()
            .unwrap_or_else(|| "default".to_string());
        print!(
            "Remove {}:{} from profile '{}' config? (y/N) ",
            name, key_alias, profile
        );
        io::stdout().flush().ok();
        let mut response = String::new();
        io::stdin().read_line(&mut response).ok();
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    if config.providers.remove(name).is_none() {
        let msg = format!("Provider '{}' not found in config", name);
        if json_mode {
            json_output::print_json_exit(
                serde_json::json!({
                    "ok": false,
                    "message": msg
                }),
                1,
            );
        }
        return Err(msg.into());
    }

    config.save(&config_path)?;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "provider": name
        }));
    } else {
        println!("Provider '{}' removed", name);
    }

    Ok(())
}

/// Handle `aikey provider ls` — list providers in the project config
pub fn handle_provider_ls(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (_, config) = ProjectConfig::discover()?.ok_or("No aikey.config.json found")?;

    if json_mode {
        let providers: Vec<_> = config
            .providers
            .iter()
            .map(|(name, cfg)| {
                serde_json::json!({
                    "name": name,
                    "key_alias": cfg.key_alias,
                    "default_model": cfg.default_model
                })
            })
            .collect();
        json_output::print_json(serde_json::json!({ "ok": true, "providers": providers }));
    } else if config.providers.is_empty() {
        println!("No protocols configured.");
    } else {
        println!("Protocols:");
        let mut names: Vec<_> = config.providers.keys().collect();
        names.sort();
        for name in names {
            let cfg = &config.providers[name];
            if let Some(model) = &cfg.default_model {
                println!("  {} (alias: {}, model: {})", name, cfg.key_alias, model);
            } else {
                println!("  {} (alias: {})", name, cfg.key_alias);
            }
        }
    }

    Ok(())
}

/// Handle `aikey doctor` — connectivity and health diagnostics.
///
/// No master password required. Checks run sequentially and stream output
/// as each result arrives so the user sees progress immediately.
/// Edition banner text for `aikey doctor` (B1). `aikey doctor` is a
/// client-side tool: it runs on Personal (local-server or CLI-only) and
/// Trial hosts. Production is a server-install deployment, not diagnosed via
/// this CLI, so there's no Production variant here.
fn doctor_edition_label(edition: Option<crate::local_server_probe::Edition>) -> &'static str {
    match edition {
        Some(crate::local_server_probe::Edition::Trial) => "Trial (full-trial bundle)",
        Some(crate::local_server_probe::Edition::Personal) => "Personal (local-server)",
        None => "Personal (CLI-only, no local web service)",
    }
}

/// N/A note for the `--detail` ODS panels on non-Trial editions (B2). Those
/// panels read the Trial-server ODS pipeline (control-trial.db/.log); on
/// Personal / CLI-only that pipeline doesn't exist. Returns "" for Trial
/// (the panel renders real data instead).
fn doctor_detail_ods_na_note(edition: Option<crate::local_server_probe::Edition>) -> &'static str {
    match edition {
        Some(crate::local_server_probe::Edition::Personal) => {
            "not applicable on Personal edition — the ODS pipeline is a Trial-server feature"
        }
        None => "not applicable (CLI-only host — no Trial-server ODS pipeline)",
        Some(crate::local_server_probe::Edition::Trial) => "",
    }
}

/// One optional first-party plugin app that `aikey doctor` reports (A2).
struct DoctorPlugin {
    /// Row label shown in the doctor output.
    label: &'static str,
    /// Binary path relative to `$HOME`.
    rel_path: &'static str,
    /// `aikey app install <slug>` name (for the "enable" hint).
    install_slug: &'static str,
    /// Daemon (own port, gets a liveness probe) vs subprocess filter
    /// (spawned per-request by the proxy, presence check only).
    is_daemon: bool,
}

/// The optional first-party plugin apps `aikey doctor` reports (A2).
///
/// Kept as one table so the doctor section, this list, and the app registry
/// (`commands_app::FIRST_PARTY_SLUGS`) stay in lockstep — a slug added there
/// should surface here too (asserted by a unit test). Path note: trust-local
/// installs to the legacy `~/.aikey/bin/`, the compliance apps to the
/// app-manifest convention `~/.aikey/apps/<slug>/bin/`.
fn doctor_plugin_registry() -> Vec<DoctorPlugin> {
    vec![
        DoctorPlugin {
            label: "trust-local",
            rel_path: ".aikey/bin/trust-local",
            install_slug: "degrade-detector",
            is_daemon: true,
        },
        DoctorPlugin {
            label: "compliance-detector",
            rel_path: ".aikey/apps/ai-compliance-detector/bin/ai-compliance-detector",
            install_slug: "ai-compliance-detector",
            is_daemon: false,
        },
        DoctorPlugin {
            label: "compliance-deep-scan",
            rel_path: ".aikey/apps/ai-compliance-deep-scan/bin/ai-compliance-deep-scan",
            install_slug: "ai-compliance-deep-scan",
            is_daemon: false,
        },
    ]
}

/// Resolve a registry binary path for the current platform. Windows plugin
/// installers ship PE binaries with an `.exe` suffix; checking the extensionless
/// registry path made doctor report installed plugins as absent on Windows.
fn doctor_plugin_bin_path(
    home: &std::path::Path,
    plugin: &DoctorPlugin,
    windows: bool,
) -> std::path::PathBuf {
    let path = home.join(plugin.rel_path);
    if windows {
        path.with_extension("exe")
    } else {
        path
    }
}

/// Runs the doctor checks. Returns `true` iff there is ≥1 configured per-account
/// egress and ALL of them failed connectivity — the caller maps that to a
/// non-zero exit ("失败要显眼"). All other check failures stay advisory (doctor
/// has always exited 0 on them).
pub fn handle_doctor(json_mode: bool) -> Result<bool, Box<dyn std::error::Error>> {
    use colored::Colorize;
    use std::time::Instant;

    // Accumulates results for --json mode.
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut any_failed = false;
    // Deferred suite — run after the emit closure is dropped (borrow conflict).
    // (targets, build_errors) — targets flow into run_connectivity_suite;
    // build_errors drive the "cannot test" block beneath the table.
    let mut deferred_suite: Option<(Vec<TestTarget>, Vec<BuildTargetError>)> = None;

    // Helper: print one check row, collect for JSON.
    // label is left-padded to 18 chars; detail is the right-hand info string.
    let mut emit = |label: &str, ok: bool, detail: &str, hint: Option<&str>| {
        // Sub-detail rows (label starts with whitespace) belong to the most
        // recent top-level check. Render them as a dim tree branch so the
        // failure is called out once by its parent instead of stacking ✗ icons.
        let is_sub = label.starts_with(' ');
        if !json_mode {
            if is_sub {
                let trimmed = label.trim_start();
                println!(
                    "    {} {}",
                    format!("{} {:<16}", crate::symbols::HINT_ARROW.s(), trimmed).dimmed(),
                    detail.dimmed()
                );
                if let Some(h) = hint {
                    println!("      {}", format!("· {}", h).dimmed());
                }
            } else {
                let icon = if ok {
                    crate::symbols::CHECK.s().green()
                } else {
                    crate::symbols::CROSS.s().red()
                };
                // Label column width 20 = longest label (`compliance-deep-scan`).
                println!("{} {:<20} {}", icon, label, detail);
                if let Some(h) = hint {
                    println!(
                        "  {}",
                        format!("{} {}", crate::symbols::HINT_ARROW.s(), h).dimmed()
                    );
                }
            }
        }
        results.push(serde_json::json!({
            "check": label,
            "ok": ok,
            "detail": detail,
            "hint": hint,
        }));
        // Only top-level failures bubble up to overall status; sub-rows are
        // already captured via their parent.
        if !ok && !is_sub {
            any_failed = true;
        }
    };

    if !json_mode {
        println!("{}", crate::symbols::BOX_H.s().repeat(52).dimmed());
    }

    // ── 0. Version info ─────────────────────────────────────
    {
        let cli_rev = env!("AIKEY_BUILD_REVISION");
        let cli_bid = env!("AIKEY_BUILD_ID");
        let cli_ver = env!("CARGO_PKG_VERSION");
        let cli_str = if cli_bid == "unknown" {
            format!("{}+{}", cli_ver, cli_rev)
        } else {
            format!("{}+{}.{}", cli_ver, cli_rev, cli_bid)
        };
        emit("cli version", true, &cli_str, None);

        // Edition banner (B1): state up-front which edition doctor is
        // diagnosing so every row below has context and support can tell a
        // Personal host from a Trial one at a glance. `aikey doctor` is a
        // client-side tool — it runs on Personal (local-server or CLI-only)
        // and Trial (full-trial) hosts; Production is a server-install
        // deployment managed on the server, not via this CLI. detect_edition
        // reads install-state.json's installed_components (single source).
        let doctor_edition = crate::local_server_probe::detect_edition();
        emit("edition", true, doctor_edition_label(doctor_edition), None);

        // Probe proxy /version
        let proxy_port = crate::commands_proxy::proxy_port();
        let proxy_url = format!("http://127.0.0.1:{}/version", proxy_port);
        match ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .get(&proxy_url)
            .call()
        {
            Ok(resp) => {
                if let Ok(body) = resp.into_string() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                        let ver = v.get("version").and_then(|x| x.as_str()).unwrap_or("?");
                        let rev = v.get("revision").and_then(|x| x.as_str()).unwrap_or("?");
                        let bid = v.get("build_id").and_then(|x| x.as_str()).unwrap_or("?");
                        let proxy_str = if bid == "unknown" {
                            format!("{}+{}", ver, rev)
                        } else {
                            format!("{}+{}.{}", ver, rev, bid)
                        };
                        let matched = cli_bid != "unknown" && bid != "unknown" && cli_bid == bid;
                        let mismatch_hint = if cli_bid != "unknown"
                            && bid != "unknown"
                            && cli_bid != bid
                        {
                            Some("BuildID mismatch — CLI and proxy from different builds. Run: make restart")
                        } else {
                            None
                        };
                        emit("proxy version", true, &proxy_str, mismatch_hint);
                        if matched {
                            emit("build match", true, &format!("BuildID={}", bid), None);
                        }
                    }
                }
            }
            Err(_) => {
                emit(
                    "proxy version",
                    false,
                    "proxy not reachable",
                    Some("proxy /version check will retry after proxy starts"),
                );
            }
        }

        // ── Model mapping (P3.5 four-surface visibility · reads task-7.9 endpoint) ──
        // Surface "configured but not effective". The proxy's mappingHealth is the
        // single source of truth — doctor renders its verdict, never re-derives it.
        // 3.6: mapping-missing is NOT user-fixable (ships with the installer), so it
        // shows as an informational WARN (never fails the overall doctor). Silent when
        // the proxy is down (the proxy-version row above already flagged that).
        if let Ok(diag) = crate::commands_proxy::fetch_pipeline_diagnostics() {
            let mm = &diag.model_mapping;
            let reg = &diag.registry;
            match mm.status.as_str() {
                "degraded" => emit(
                    "model-mapping",
                    true, // informational — not a doctor failure (unfixable client-side)
                    &format!(
                        "{} configured but not taking effect (registry {})",
                        crate::symbols::WARN.s(),
                        reg.digest
                    ),
                    Some(if mm.reason.is_empty() {
                        "a mapping is set but recent requests didn't match it — update the installer to change mappings"
                    } else {
                        mm.reason.as_str()
                    }),
                ),
                "ok" => emit(
                    "model-mapping",
                    true,
                    &format!("active · registry {} · {} applied", reg.digest, mm.applied),
                    None,
                ),
                "inactive" => emit(
                    "model-mapping",
                    true,
                    &format!("none configured · registry {}", reg.digest),
                    None,
                ),
                _ => {}
            }
        }

        // Usage-receipt pipeline heartbeat. Surfaces "receipts last landed N ago
        // / never observed" so a third-party CLI upgrade that silently broke the
        // kimi/claude receipt path (session-layout / payload drift) is visible
        // here instead of nowhere. Informational (ok=true): a stale/absent
        // heartbeat can also just mean the tool wasn't used, so we never fail
        // doctor on it — but we point at the WARN log for the drift signature.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let fmt_age = |ts: i64| -> String {
                let s = (now - ts).max(0);
                if s >= 86400 {
                    format!("{}d ago", s / 86400)
                } else if s >= 3600 {
                    format!("{}h ago", s / 3600)
                } else if s >= 60 {
                    format!("{}m ago", s / 60)
                } else {
                    format!("{}s ago", s)
                }
            };
            let parts: Vec<String> = ["kimi", "claude"]
                .iter()
                .map(
                    |tool| match crate::commands_statusline::receipt_last_ok(tool) {
                        Some(ts) => format!("{}: {}", tool, fmt_age(ts)),
                        None => format!("{}: never", tool),
                    },
                )
                .collect();
            emit(
                "usage receipts",
                true,
                &parts.join(" · "),
                Some(
                    "if a tool you use shows 'never'/very stale, grep ~/.aikey/logs/aikey-cli/current.jsonl for cli.receipt.* WARNs (may signal a kimi/claude upgrade broke the pipeline)",
                ),
            );
        }

        // Probe backend services (docker or native).
        // control/collector/query = server-mode docker services. Probed
        // silently — failures here aren't actionable for Personal users.
        // local-server is checked separately below (after drop(emit)) so
        // its NOT-RUNNING case can render as a ⚠ warning with a start
        // hint, rather than being silently skipped.
        for (name, port) in &[("control", 8080u16), ("collector", 27300), ("query", 27310)] {
            let url = format!("http://127.0.0.1:{}/version", port);
            match ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_millis(500))
                .build()
                .get(&url)
                .call()
            {
                Ok(resp) => {
                    if let Ok(body) = resp.into_string() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                            let ver = v.get("version").and_then(|x| x.as_str()).unwrap_or("?");
                            let rev = v.get("revision").and_then(|x| x.as_str()).unwrap_or("?");
                            let bid = v.get("build_id").and_then(|x| x.as_str()).unwrap_or("?");
                            let svc_str = if bid == "unknown" {
                                format!("{}+{}", ver, rev)
                            } else {
                                format!("{}+{}.{}", ver, rev, bid)
                            };
                            emit(&format!("{} version", name), true, &svc_str, None);
                        }
                    }
                }
                Err(_) => {} // Silently skip — docker services are optional
            }
        }

        if !json_mode {
            println!("{}", crate::symbols::BOX_H.s().repeat(52).dimmed());
        }
    }

    // ── 1. Internet connectivity ─────────────────────────────
    // Why HTTP GET instead of TCP ping: users behind an HTTP proxy (e.g.
    // upstream_proxy in proxy config) can reach the internet via HTTP but
    // direct TCP to 1.1.1.1:443 is blocked, causing a false "unreachable".
    {
        let start = Instant::now();
        let ok = crate::connectivity::runtime::build_proxy_aware_agent(
            std::time::Duration::from_secs(5),
        )
        .head("https://www.gstatic.com/generate_204")
        .call()
        .is_ok();
        let ms = start.elapsed().as_millis();
        emit(
            "internet",
            ok,
            &if ok {
                format!("reachable  ({} ms)", ms)
            } else {
                "unreachable".to_string()
            },
            if ok {
                None
            } else {
                Some("check network connection or VPN")
            },
        );
    }

    // ── 2. Vault ─────────────────────────────────────────────
    {
        let vault_path = storage::get_vault_path().ok();
        let exists = vault_path.as_ref().map(|p| p.exists()).unwrap_or(false);
        let detail = match &vault_path {
            Some(p) if exists => format!("found  ({})", p.display()),
            Some(p) => format!("not found  ({})", p.display()),
            None => "cannot resolve path".to_string(),
        };
        emit(
            "vault",
            exists,
            &detail,
            if exists {
                None
            } else {
                Some("run 'aikey init' to create your vault")
            },
        );
    }

    // ── 3. Session cache ─────────────────────────────────────
    {
        let cached = crate::session::try_get().is_some();
        emit(
            "session",
            true, // not a failure either way — just informational
            if cached {
                "password cached"
            } else {
                "no cache  (will prompt on next command)"
            },
            None,
        );
    }

    // ── 3.5. Lifecycle state consistency ─────────────────────
    //
    // Audit DB ↔ active.env ↔ kimi.toml ↔ codex.toml. Drift here is
    // a frequent root cause of "I added a key but my CLI still hits
    // the old one" complaints. Reporting it BEFORE provider
    // connectivity means the user sees the right hint instead of
    // re-trying connectivity probes that were never going to work.
    //
    // Pure read-only; no master password, no network. Proxy cache
    // comparison is gated on `--detail` (HTTP call, slower).
    //
    // Each drift becomes a sub-row (label starts with whitespace), so
    // emit renders them as dim tree branches under the parent check.
    // JSON consumers can filter sub-rows by check name prefix.
    {
        let report = crate::commands_account::audit_credential_lifecycle(false);
        // Drift hint: highlight the two actionable commands in cyan-bold
        // inside the surrounding dim emit-wrap. `style::cmd_in_dim` resumes
        // the outer dim after each cyan segment (a raw resume byte colored
        // cannot express — see src/style.rs).
        let drift_hint = format!(
            "run {} to force a reconcile, or {} for per-source diff",
            crate::style::cmd_in_dim("aikey use <alias>"),
            crate::style::cmd_in_dim("aikey doctor --detail"),
        );
        emit(
            "active state sync",
            report.is_consistent,
            &report.summary,
            if report.is_consistent {
                None
            } else {
                Some(&drift_hint)
            },
        );
        if !report.is_consistent {
            for d in &report.diffs {
                let label = format!("  {}", d.source.label());
                emit(&label, false, &d.describe(), d.hint.as_deref());
            }
        }
    }

    // ── 4. Proxy process + reachability ──────────────────────
    //
    // **Round 10 review fix (MEDIUM, Finding 1)**: previously this
    // path consumed `doctor_proxy_status()`'s `(bool, Option<u32>)`
    // 2-tuple, which collapsed `Crashed` / `Unresponsive` /
    // `OrphanedPort` into one "proxy_up == false → attempt restart"
    // branch. For OrphanedPort that is the wrong action policy:
    // Layer 2 will reject the foreign owner anyway (correctly), but
    // an interactive doctor session would have prompted for the vault
    // password first — wasting user input on something we can't fix.
    //
    // Now consume the full `ProxyState` directly so each variant maps
    // to its correct policy:
    //   Running       → green, with /health latency
    //   Stopped       → "not running" + auto-restart attempt
    //   Crashed       → "stale pidfile" + auto-restart (start_proxy
    //                   cleans up)
    //   Unresponsive  → diagnostic only ("try restart manually" —
    //                   auto-restart would just spawn over a sick
    //                   sibling without killing it; user should run
    //                   `aikey proxy restart` which goes through
    //                   Layer 2's full SIGTERM→SIGKILL escalation)
    //   OrphanedPort  → diagnostic only, NO restart attempt, NO
    //                   password prompt — we provably can't manage
    //                   the foreign owner
    use crate::proxy_state::{proxy_state, ProxyState};

    let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
    let initial_state = proxy_state(&proxy_addr);
    let mut proxy_up = matches!(initial_state, ProxyState::Running { .. });
    {
        match &initial_state {
            ProxyState::Running { pid, .. } => {
                // Measure latency against /health.
                let start = Instant::now();
                let url = format!("http://{}/health", proxy_addr);
                let ok = ureq::get(&url).call().is_ok();
                let ms = start.elapsed().as_millis();
                let detail = if ok {
                    format!("running  (pid {}, {} ms)", pid, ms)
                } else {
                    format!("pid {} alive but /health unreachable", pid)
                };
                emit("proxy", true, &detail, None);
            }
            ProxyState::Unresponsive { pid, port } => {
                // Diagnostic-only: don't restart automatically. The
                // sibling process is bound but unhealthy; only an
                // explicit Layer 2 stop+start (with proper SIGTERM
                // escalation) is safe here.
                emit(
                    "proxy",
                    false,
                    &format!("unresponsive (pid {pid}, port {port}, /health failing)"),
                    Some("run 'aikey proxy restart' to recover"),
                );
            }
            ProxyState::OrphanedPort {
                port,
                owner_pid,
                reason,
            } => {
                // Diagnostic-only: no auto-restart, no password prompt.
                // Doing either would be wasted user input — Layer 2
                // can't manage the foreign owner.
                emit(
                    "proxy",
                    false,
                    &format!("orphaned (port {port} owned by something we cannot manage)"),
                    Some(&reason.hint(*port, *owner_pid)),
                );
            }
            ProxyState::Crashed { .. } | ProxyState::Stopped => {
                let detail = match &initial_state {
                    ProxyState::Crashed { stale_pid } => {
                        format!("stale pidfile (was: {stale_pid})")
                    }
                    _ => "not running".to_string(),
                };
                emit("proxy", false, &detail, Some("attempting restart..."));
                if !json_mode {
                    crate::commands_proxy::ensure_proxy_for_use(false);
                    // Re-check via Layer 1 — same single source of truth.
                    let (up, _) = crate::commands_proxy::doctor_proxy_status();
                    if up {
                        proxy_up = true;
                        emit("proxy restart", true, "proxy restarted successfully", None);
                    } else {
                        emit(
                            "proxy restart",
                            false,
                            "restart failed",
                            Some("run 'aikey proxy start' manually to debug"),
                        );
                    }
                }
            }
        }
    }

    // ── 5. Provider + proxy connectivity ────────────────────
    // Build targets via the unified helper so Personal / Team / OAuth go
    // through the same code path as `aikey test` and `aikey add`. Deferred
    // execution happens below the emit closure to avoid the &mut results
    // borrow conflict that predates this refactor.
    if proxy_up {
        let bindings = storage::list_provider_bindings(crate::profile_activation::DEFAULT_PROFILE)
            .unwrap_or_default();

        if bindings.is_empty() {
            if !json_mode {
                println!(
                    "  {} {:<18} {}",
                    "·".dimmed(),
                    "protocols",
                    "no protocol bindings — run 'aikey add' first".dimmed()
                );
            }
        } else {
            // Plan D (2026-04-22): all probes (including personal) go via
            // proxy with a sentinel bearer. Proxy holds vault derived key
            // server-side, so CLI no longer needs the master password —
            // neither from session cache nor an interactive prompt. This
            // makes `aikey doctor` zero-prompt, matching `aikey test`.
            let proxy_port = crate::commands_proxy::proxy_port();
            let (targets, build_errors) = targets_from_active_bindings(None, proxy_port);

            if targets.is_empty() && build_errors.is_empty() {
                if !json_mode {
                    println!(
                        "  {} {:<18} {}",
                        "\u{b7}".dimmed(),
                        "protocols",
                        "no protocol bindings configured".dimmed()
                    );
                }
            } else {
                // Deferred: run after emit closure is dropped (borrow conflict).
                deferred_suite = Some((targets, build_errors));
            }
        }
    }

    // ── 7. Shell hook installed ───────────────────────────────
    {
        // Wired-state predicate unified to `shell_rc_has_aikey_block()`
        // (2026-07-10): the previous inline `# aikey shell hook` grep was
        // the LEGACY V1 marker — a truth-source split from the v3 block
        // that `aikey use` / the web modal actually write, so this check
        // reported "installed" for stale v1 rcs and "not installed" for
        // healthy v3 ones. The shared predicate is the same one the web
        // envelope's `hook_rc_wired` field uses (vault_op.rs), so doctor,
        // `aikey use`, and the web banner can no longer disagree.
        let shell_supported = !matches!(
            crate::commands_account::shell_kind(),
            crate::commands_account::ShellKind::Cmd | crate::commands_account::ShellKind::Unknown
        );
        let rc_wired = crate::commands_account::shell_rc_has_aikey_block();

        if rc_wired {
            emit("shell hook", true, "installed", None);
        } else if shell_supported {
            emit(
                "shell hook",
                false,
                "not installed",
                Some("installing shell hook..."),
            );
            // Trigger installation (prompts user in TTY mode).
            if !json_mode {
                let _ = crate::commands_account::ensure_shell_hook(false);
            }
        } else {
            emit(
                "shell hook",
                false,
                "unsupported shell",
                Some("add 'source ~/.aikey/active.env' to your shell config manually"),
            );
        }

        // ── 7.1. Hook wiring vs active bindings ──────────────
        //
        // Why a separate item: "rc not wired" alone is a setup nit, but
        // "bindings are ACTIVE and the rc is not wired" means the user
        // believes keys are routing while `claude`/`codex` run bare —
        // the exact silent failure of the web-only onboarding path
        // (install → web use → never wire rc). Health signals must be
        // externally readable, so this states the consequence explicitly
        // instead of leaving it implied by two separate green/red items.
        // Skipped for unsupported shells: the item above already reports
        // that there is no rc to wire.
        if shell_supported {
            let has_active_bindings = !crate::storage::list_provider_bindings_readonly(
                crate::profile_activation::DEFAULT_PROFILE,
            )
            .unwrap_or_default()
            .is_empty();
            // Re-check: the auto-install above may have just wired the rc.
            let rc_wired_now = rc_wired || crate::commands_account::shell_rc_has_aikey_block();
            let (ok, detail, hint) = hook_wiring_check(has_active_bindings, rc_wired_now);
            emit("hook wiring", ok, detail, hint);
        }

        // ── 7.2. PowerShell ExecutionPolicy (wired-but-dead guard) ────
        //
        // 2026-07-12 exploratory finding X2: default client Windows keeps
        // every ExecutionPolicy scope Undefined → effective Restricted →
        // profile.ps1 refuses to load, so a WIRED hook never runs while
        // every other check above stays green. The one detector that can
        // see it is this policy probe. No-op on non-PowerShell shells and
        // on Unix (stub returns None).
        if matches!(
            crate::commands_account::shell_kind(),
            crate::commands_account::ShellKind::PowerShell
        ) {
            if crate::commands_account::powershell_profile_load_blocked().is_some() {
                emit(
                    "execution policy",
                    false,
                    "ExecutionPolicy blocks profile loading — the wired hook NEVER runs in new sessions",
                    Some("Set-ExecutionPolicy -Scope CurrentUser RemoteSigned (GPO-managed: ask IT)"),
                );
            } else {
                emit("execution policy", true, "profile loading allowed", None);
            }

            // ── 7.3. pwsh 7+ profile wiring gap ───────────────────
            //
            // 3a (2026-07-12): pwsh 7 reads Documents\PowerShell\profile.ps1
            // — a different file from PS 5.1's. Machines wired before the
            // dual-flavor write (or where pwsh was installed later) run
            // pwsh sessions hookless while the OR-logic wired check above
            // stays green. Silent when pwsh isn't present.
            if let Some(gap) = crate::commands_account::pwsh_profile_wiring_gap() {
                emit(
                    "pwsh profile",
                    false,
                    "pwsh 7+ detected but its profile is not wired — pwsh sessions won't load the hook",
                    Some("run `aikey hook install` (wires every present PowerShell flavor)"),
                );
                let _ = gap;
            }
        }
    }

    // ── 7.5. Optional first-party plugins ────────────────────
    //
    // The `aikey app install <slug>` plugins (registry: FIRST_PARTY_SLUGS).
    // Two shapes, checked differently:
    //   • degrade-detector → trust-local: a DAEMON (:8801). Probe /healthz
    //     for liveness + read the proxy's rhythm-observer build verdict.
    //   • ai-compliance-detector / -deep-scan: stdin/stdout SUBPROCESSES the
    //     proxy spawns per request — there is no port to probe, so the only
    //     honest signal is "binary installed?" (presence = the proxy can
    //     spawn it). deep-scan is the heavy opt-in semantic layer.
    //
    // Why show not-installed rows now (previously the whole section was
    // skipped when trust-local was absent): a health *dashboard* should say
    // which optional capabilities exist and which are off, not go silent —
    // otherwise a user can't tell "compliance filtering isn't running" from
    // "doctor doesn't check it". Not-installed renders dim/informational and
    // never bubbles to the overall pass/fail (these are opt-in).
    {
        let home = dirs::home_dir().unwrap_or_default();
        let plugins = doctor_plugin_registry();
        // Paths come from the registry (single source shared with the
        // consistency test); trust-local keeps its bespoke daemon+observer
        // logic, the subprocess filters loop through a generic presence check.
        let trust_local_plugin = plugins
            .iter()
            .find(|p| p.is_daemon)
            .expect("registry has the trust-local daemon entry");

        // ── degrade-detector / trust-local (daemon) ──
        // Use the shared service module as the install-state truth source.
        // On Windows it resolves %USERPROFILE%\.aikey\bin\trust-local.exe;
        // the old `$HOME/.aikey/bin/trust-local` check bypassed auto-repair,
        // printed "not installed", and left :8801 down (QA20).
        if crate::trust_local_service::is_installed() {
            // (a) trust-local service liveness.
            let trust_local_url = "http://127.0.0.1:8801/healthz";
            let tl_ok = ureq::get(trust_local_url)
                .timeout(std::time::Duration::from_secs(2))
                .call()
                .map(|r| r.status() == 200)
                .unwrap_or(false);
            if tl_ok {
                emit("trust-local", true, "running on :8801", None);
            } else {
                emit(
                    "trust-local",
                    false,
                    "not reachable on :8801",
                    Some("attempting start..."),
                );
                // Auto-fix — mirrors the proxy + web + shell-hook auto-repair. An
                // installed-but-stopped trust-local gets ONE start attempt in
                // interactive mode via the canonical OS-service core
                // `trust_local_service::start` (launchctl/systemctl/schtasks — NO
                // master password). Same one implementation `aikey service start
                // trust-local` uses (extracted to a lib module 2026-07-26 precisely
                // so doctor, which compiles in the lib crate, can reach it). start()
                // already waits up to 30s for the slow (PyInstaller onefile) daemon
                // to answer /healthz, so its Ok/Err is the authoritative verdict.
                // --json stays non-mutating. Bugfix 20260726-doctor-autostart-trust-local.
                if !json_mode {
                    match crate::trust_local_service::start() {
                        Ok(()) => emit(
                            "trust-local start",
                            true,
                            "started — running on :8801",
                            None,
                        ),
                        Err(_) => emit(
                            "trust-local start",
                            false,
                            "start failed",
                            Some("run 'aikey trust-local start' manually to debug"),
                        ),
                    }
                }
            }

            // (b) rhythm observer health — read the freshest line
            // out of aikey-proxy's log. The build outcome shows up
            // as `proxy.observer.built` (good) or
            // `proxy.observer.build_failed` (bad) within the first
            // few hundred lines after a restart.
            let log_path = home.join(".aikey/logs/aikey-proxy/current.jsonl");
            let observer_state = if log_path.exists() {
                std::fs::read_to_string(&log_path).ok().and_then(|s| {
                    // Take the LAST observer line (most recent
                    // restart's verdict). build_failed > built > unknown.
                    s.lines()
                        .filter(|l| {
                            l.contains("proxy.observer.build") || l.contains("rhythm.observer")
                        })
                        .last()
                        .map(String::from)
                })
            } else {
                None
            };
            match observer_state {
                Some(line)
                    if line.contains("proxy.observer.built")
                        || line.contains("rhythm.observer.built") =>
                {
                    emit("rhythm observer", true, "built + reporting", None);
                }
                Some(line) if line.contains("build_failed") => {
                    // Try to pluck error.message out of the JSON line
                    // for a more actionable detail.
                    let reason = serde_json::from_str::<serde_json::Value>(&line)
                        .ok()
                        .and_then(|v| {
                            v.get("error.message")
                                .and_then(|s| s.as_str())
                                .map(String::from)
                        })
                        .unwrap_or_else(|| "build_failed (see proxy log)".to_string());
                    emit("rhythm observer", false, "inactive",
                        Some(&format!("reason: {}; reinstall via: curl -fsSL https://raw.githubusercontent.com/aikeylabs/ai-degrade-detector/main/scripts/install_service.sh | bash", reason)));
                }
                _ => {
                    // No observer line in log = proxy started before
                    // observer registry, or trust-local was installed
                    // after proxy. Hint at a restart.
                    emit(
                        "rhythm observer",
                        false,
                        "state unknown",
                        Some("restart proxy: aikey proxy restart"),
                    );
                }
            }
        } else {
            let hint = format!(
                "enable: aikey app install {}",
                trust_local_plugin.install_slug
            );
            emit(
                trust_local_plugin.label,
                true,
                "not installed (optional degrade-detector plugin)",
                Some(&hint),
            );
        }

        // ── compliance filters (subprocess, presence-only) ──
        // The proxy spawns these per request (stdin/stdout frames), so there
        // is no port to probe — presence of the binary is the honest signal
        // that the proxy *can* spawn it. Looped from the registry's
        // non-daemon entries so adding a filter app is a one-line table edit.
        for p in plugins.iter().filter(|p| !p.is_daemon) {
            if doctor_plugin_bin_path(&home, p, cfg!(windows)).exists() {
                emit(p.label, true, "installed (proxy-spawned filter)", None);
            } else {
                let hint = format!("enable: aikey app install {}", p.install_slug);
                emit(
                    p.label,
                    true,
                    "not installed (optional compliance filter)",
                    Some(&hint),
                );
            }
        }
    }

    // ── 8. SQLite WAL size ──────────────────────────────────
    {
        if let Ok(vault_path) = storage::get_vault_path() {
            let wal_path = vault_path.with_extension("db-wal");
            if wal_path.exists() {
                let wal_size = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
                let wal_mb = wal_size / (1024 * 1024);
                if wal_mb >= 1000 {
                    emit("vault WAL", false,
                        &format!("{}MB — needs checkpoint", wal_mb),
                        Some("run: sqlite3 ~/.aikey/data/vault.db 'PRAGMA wal_checkpoint(TRUNCATE);'"));
                } else {
                    emit("vault WAL", true, &format!("{}MB", wal_mb), None);
                }
            }
        }
    }

    // ── 8b. Disk space (vault / usage-WAL filesystem) ───────
    // Why: a full disk makes SQLite WAL appends fail, which silently stops
    // usage-event capture and billing upload (the proxy degrades its
    // /health usage_pipeline to `wal_append_failed`, but that fires only
    // AFTER the disk is already full). This proactive check warns before the
    // disk fills so the operator can act first — closes the "doctor only
    // checks WAL size, not free space" operability gap (2026-06-10 review #5).
    {
        // Probe the filesystem hosting the vault/WAL (events accumulate there).
        // Pre-init the vault may not exist yet → walk up to the nearest
        // existing ancestor so the check still reports the target disk.
        let target = storage::get_vault_path()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        if let Some(dir) = target {
            let mut probe = dir.clone();
            while !probe.exists() {
                match probe.parent() {
                    Some(parent) => probe = parent.to_path_buf(),
                    None => break,
                }
            }
            // fs2::available_space is cross-platform (statvfs / GetDiskFreeSpaceExW),
            // already a dependency for proxy file locking — no new crate.
            if let Ok(free) = fs2::available_space(&probe) {
                const LOW_DISK_MB: u64 = 500; // headroom below which WAL writes are at risk
                let free_mb = free / (1024 * 1024);
                if free_mb < LOW_DISK_MB {
                    emit(
                        "disk space",
                        false,
                        &format!("{} MB free — low, WAL writes at risk", free_mb),
                        Some("free disk space; a full disk silently stops usage capture + billing upload"),
                    );
                } else {
                    let detail = if free_mb >= 1024 {
                        format!("{:.1} GB free", free_mb as f64 / 1024.0)
                    } else {
                        format!("{} MB free", free_mb)
                    };
                    emit("disk space", true, &detail, None);
                }
            }
        }
    }

    // ── 9. Control service ───────────────────────────────────
    if let Ok(Some(account)) = storage::get_platform_account() {
        let url = format!("{}/health", account.control_url.trim_end_matches('/'));
        let start = Instant::now();
        let ok = ureq::get(&url).call().is_ok();
        let ms = start.elapsed().as_millis();
        let detail = if ok {
            format!("reachable  ({}, {} ms)", account.control_url, ms)
        } else {
            format!("unreachable  ({})", account.control_url)
        };
        emit(
            "control service",
            ok,
            &detail,
            if ok {
                None
            } else {
                Some("check network or try 'aikey login' again")
            },
        );
    }

    // ── 10. Usage pipeline health ─────────────────────────────
    // ── 10. Usage pipeline health ─────────────────────────────
    // Two data sources:
    //   a) Proxy /metrics — reporter delivery state (generated/uploaded/failed/dropped)
    //   b) Control /v1/diagnostics/pipeline — full-chain watermarks + canary health
    //
    // Why both: proxy /metrics shows the "sender side" (is reporter working?),
    // diagnostics shows the "receiver side" (did data arrive and get projected?).
    if !json_mode {
        println!("{}", crate::symbols::BOX_H.s().repeat(52).dimmed());
    }
    // 2026-06-23 UX: print a dim "↻ checking pipeline metrics…" placeholder
    // BEFORE the silent 3–9s HTTP fan-out below (proxy /metrics + control
    // /system/status + collector or fallback control /v1/diagnostics/pipeline
    // — each capped at the agent's 3s ureq timeout, but serial). Without it,
    // the user sees nothing happening between the "✓ control service" row
    // and the eventual "✓ usage-pipeline" emit, and the wait looks like a
    // hang (real user reported it as `卡` 2026-06-23). The hint is overwritten
    // in place by an ANSI "cursor-up + clear-line" right before the real
    // emit, so the final output is identical to before. Skipped when stdout
    // isn't a TTY (CI / piped output stays clean) or in json_mode.
    use std::io::IsTerminal;
    let pipeline_hint_on = !json_mode && std::io::stdout().is_terminal();
    if pipeline_hint_on {
        use colored::Colorize;
        use std::io::Write;
        println!(
            "  {}",
            format!("{} checking pipeline metrics…", crate::symbols::REFRESH.s()).dimmed()
        );
        let _ = std::io::stdout().flush();
    }
    {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(3))
            .build();

        // a) Proxy reporter metrics
        let proxy_metrics = if proxy_up {
            let url = format!("http://{}/metrics", proxy_addr);
            agent
                .get(&url)
                .call()
                .ok()
                .and_then(|r| r.into_string().ok())
        } else {
            None
        };

        // b) Diagnostics — served by collector-service. In trial, control and
        //    collector live on the same port so {control_url}/v1/diagnostics/
        //    pipeline works directly. In production, diagnostics are on the
        //    collector container which is reachable via an endpoint advertised
        //    by {control_url}/system/status under endpoints.collector.
        //    Discovery order: system/status → collector → fallback to control.
        let diag_json = storage::get_platform_account()
            .ok()
            .flatten()
            .and_then(|acct| {
                let control_base = acct.control_url.trim_end_matches('/').to_string();

                // Probe /system/status for a collector endpoint (production path).
                let collector_base: String = agent
                    .get(&format!("{}/system/status", control_base))
                    .call()
                    .ok()
                    .and_then(|r| r.into_string().ok())
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                    .and_then(|v| {
                        v.get("endpoints")
                            .and_then(|e| e.get("collector"))
                            .and_then(|c| c.get("url"))
                            .and_then(|u| u.as_str())
                            .map(|s| s.trim_end_matches('/').to_string())
                    })
                    .unwrap_or_else(|| control_base.clone());

                let url = format!("{}/v1/diagnostics/pipeline", collector_base);
                let resp = agent
                    .get(&url)
                    .call()
                    .ok()
                    .and_then(|r| r.into_string().ok());
                // Fallback: some older deployments serve diagnostics under
                // control_url. If collector probe failed, try control as a
                // last resort before giving up.
                if resp.is_some() || collector_base == control_base {
                    resp
                } else {
                    let fallback = format!("{}/v1/diagnostics/pipeline", control_base);
                    agent
                        .get(&fallback)
                        .call()
                        .ok()
                        .and_then(|r| r.into_string().ok())
                }
            });

        // Overwrite the "↻ checking pipeline metrics…" hint with the real
        // result. ANSI: cursor-up-1 + clear-entire-line + carriage-return →
        // cursor lands at column 0 of the hint's row. The next emit then
        // prints the real "✓ usage-pipeline …" header in that exact slot,
        // followed by its ↳ sub-rows on subsequent lines.
        if pipeline_hint_on {
            use std::io::Write;
            print!("\x1b[1A\x1b[2K\r");
            let _ = std::io::stdout().flush();
        }
        check_usage_pipeline(proxy_metrics.as_deref(), diag_json.as_deref(), &mut emit);
    }

    // Drop emit to release &mut results, then run the deferred suite.
    drop(emit);

    if let Some((targets, build_errors)) = deferred_suite {
        let outcome = run_connectivity_suite(
            targets,
            SuiteOptions {
                show_proxy_row: true,
                header_label: Some("Connectivity Test"),
                password: None, // PersonalApi plaintext is already baked into each target
                proxy_port: crate::commands_proxy::proxy_port(),
                show_key_column: false,
                probe_raw_bearer: None,
                probe_raw_base_url: None,
                probe_oauth_account_id: None,
            },
            json_mode,
        );
        if json_mode {
            results.extend(outcome.json_results);
        } else {
            render_cannot_test_block(&build_errors, json_mode);
        }
    }

    // ── local-server (Personal / Trial only) ──────────────────────────
    //
    // Why placed AFTER drop(emit): we need to write to `results` from a
    // path that mimics emit's warn behavior — ⚠ icon, no `any_failed`
    // bubble. Doing it through emit (which only knows ok/fail) would
    // either trigger a false red ✗ + nonzero exit, or be misclassified
    // as success. The closure's borrow on results would also prevent a
    // sideband warn helper from coexisting. Placing this block after
    // drop(emit) sidesteps both problems.
    //
    // Skip silently on editions without local-server (Personal CLI-only,
    // Production) — there's nothing actionable to report.
    if crate::local_server_probe::is_local_server_installed() {
        // `_or_default`: outer guard already verified install — YAML
        // missing should fall back to 8090, not surface Bulk-Import
        // wording. Bugfix 20260524-aikey-service-restart-web-port-
        // undiscoverable.md.
        let (label, ok_for_json, detail, hint) =
            match crate::local_server_probe::read_local_server_port_or_default() {
                Ok(port) => {
                    let base = format!("http://127.0.0.1:{}", port);
                    let mut status = crate::local_server_probe::probe_vault_status(&base);
                    // Auto-fix — mirrors the proxy + shell-hook auto-repair earlier
                    // in this function. An installed-but-unanswering local-server
                    // gets ONE start attempt in interactive mode. The web start is a
                    // launchd/nohup spawn — NO master password needed — so it's safe
                    // unprompted. Reuses the canonical `aikey service start web` core
                    // (never a parallel path); --json stays non-mutating like the
                    // existing auto-fixes. Bugfix 20260725-doctor-autostart-web-trust-local.
                    let mut restarted = false;
                    if status.is_err() && !json_mode {
                        println!(
                            "{} {:<20} {}",
                            crate::symbols::WARN.s().yellow(),
                            "local-server",
                            format!("not running on port {port} — attempting start...")
                        );
                        let _ = crate::commands_account::handle_web_service("start", false);
                        status = crate::local_server_probe::probe_vault_status(&base);
                        restarted = true;
                    }
                    match status {
                        Ok(unlocked) => (
                            "local-server",
                            true,
                            format!(
                                "{}running on port {} (vault: {})",
                                if restarted { "started — " } else { "" },
                                port,
                                if unlocked { "unlocked" } else { "locked" }
                            ),
                            None,
                        ),
                        Err(_) => (
                            "local-server",
                            false,
                            format!("not running on port {}", port),
                            Some(crate::local_server_probe::start_command_hint()),
                        ),
                    }
                }
                Err(e) => (
                    "local-server",
                    false,
                    format!("configuration unreadable — {}", e),
                    None,
                ),
            };

        if !json_mode {
            let icon = if ok_for_json {
                crate::symbols::CHECK.s().green()
            } else {
                crate::symbols::WARN.s().yellow()
            };
            // Label column width 20 = longest label (`compliance-deep-scan`).
            println!("{} {:<20} {}", icon, label, detail);
            if let Some(ref h) = hint {
                println!(
                    "  {}",
                    format!("{} Start: {}", crate::symbols::HINT_ARROW.s(), h).dimmed()
                );
            }
        }
        results.push(serde_json::json!({
            "check": label,
            "ok": ok_for_json,
            // `severity: "warn"` distinguishes "this is informational and
            // doesn't fail the overall doctor check" from "this is broken".
            // JSON consumers should treat warn === ok for pass/fail purposes
            // but may still surface it as actionable.
            "severity": if ok_for_json { "ok" } else { "warn" },
            "detail": detail,
            "hint": hint,
        }));
        // Deliberately do NOT touch `any_failed` — local-server being down
        // is a Personal-edition convenience problem, not a doctor failure.
    }

    // Per-account egress connectivity (§5.4): dial each configured egress and
    // print it HERE — with the other connectivity checks, before the summary.
    // Silent when none is configured (Personal nodes always → no noise). All-fail
    // folds into any_failed so the summary line and exit code both reflect it.
    let egress_all_failed = crate::commands_proxy::print_egress_doctor(json_mode);
    if egress_all_failed {
        any_failed = true;
    }

    if !json_mode {
        println!("{}", crate::symbols::BOX_H.s().repeat(52).dimmed());
        if any_failed {
            println!("{}", "Some checks failed — see hints above.".yellow());
        } else {
            println!("{}", "All checks passed.".green());
        }
    } else {
        json_output::print_json(serde_json::json!({
            "ok": !any_failed,
            "checks": results,
        }));
    }

    Ok(egress_all_failed)
}

// ---------------------------------------------------------------------------
// Usage pipeline health check for `aikey doctor`
// ---------------------------------------------------------------------------

/// Parses proxy /metrics and control /v1/diagnostics/pipeline to emit a
/// comprehensive usage-pipeline section in `aikey doctor`.
///
/// Two data sources:
///   - proxy_metrics: reporter delivery state (sender side)
///   - diag_json: full-chain watermarks + canary-driven health (receiver side)
fn check_usage_pipeline(
    proxy_metrics: Option<&str>,
    diag_json: Option<&str>,
    emit: &mut dyn FnMut(&str, bool, &str, Option<&str>),
) {
    let metrics: Option<serde_json::Value> =
        proxy_metrics.and_then(|s| serde_json::from_str(s).ok());
    let diag: Option<serde_json::Value> = diag_json.and_then(|s| serde_json::from_str(s).ok());

    // --- Header: use diagnostics health if available, fall back to reporter state ---
    let diag_health = diag
        .as_ref()
        .and_then(|d| d.get("watermark_health").and_then(|v| v.as_str()));
    let diag_stale = diag
        .as_ref()
        .and_then(|d| d.get("stale_stage").and_then(|v| v.as_str()));

    let reporter = metrics.as_ref().and_then(|m| m.get("reporter"));

    // If neither source is available
    if reporter.is_none() && diag.is_none() {
        emit(
            "usage-pipeline",
            true,
            "reporter not enabled (standalone mode)",
            None,
        );
        return;
    }

    // Determine overall health: worst-of-both from diagnostics watermarks AND
    // proxy canary probe result. Why not trust diagnostics health alone: diagnostics
    // only sees watermark freshness (DWD has recent canary → healthy), but misses
    // canary probe failures at the query stage. Doctor has both data sources and
    // must combine them to avoid "healthy overall but canary probe failed" contradiction.
    let canary_status = metrics
        .as_ref()
        .and_then(|m| m.get("canary"))
        .and_then(|c| c.get("status").and_then(|v| v.as_str()))
        .unwrap_or("");
    let canary_stage = metrics
        .as_ref()
        .and_then(|m| m.get("canary"))
        .and_then(|c| c.get("failed_stage").and_then(|v| v.as_str()))
        .unwrap_or("");
    // "unavailable" = diagnostics endpoint missing (server-mode), not a pipeline fault.
    // Only "failed" or "partial" should degrade the overall health.
    let canary_is_failure = canary_status == "failed" || canary_status == "partial";

    let (pipeline_ok, health_label) = if canary_is_failure && !canary_stage.is_empty() {
        // Canary probe failure overrides watermark health
        (
            false,
            format!("degraded — canary failed at {}", canary_stage),
        )
    } else {
        match diag_health {
            Some("healthy") => (true, "healthy".to_string()),
            Some("degraded") => {
                let label = if let Some(stage) = diag_stale {
                    format!("degraded — stale at {}", stage)
                } else {
                    "degraded".to_string()
                };
                (false, label)
            }
            _ => {
                // Fall back to reporter consecutive failures
                let consecutive = reporter
                    .and_then(|r| r.get("consecutive_failures"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                if consecutive >= 5 {
                    (false, "degraded".to_string())
                } else {
                    (true, "healthy".to_string())
                }
            }
        }
    };

    // Override label to "idle" if reporter exists but no events have flowed yet.
    // Avoids showing "healthy" when nothing has been verified.
    let reporter_idle = reporter
        .and_then(|r| {
            r.get("usage_events_generated_total")
                .and_then(|v| v.as_i64())
        })
        .map(|g| g == 0)
        .unwrap_or(false);
    let (pipeline_ok, health_label) = if pipeline_ok && reporter_idle {
        (true, "idle (awaiting first event)".to_string())
    } else {
        (pipeline_ok, health_label)
    };

    let hint = if !pipeline_ok {
        Some("run: curl http://127.0.0.1:8090/v1/diagnostics/pipeline")
    } else {
        None
    };
    emit("usage-pipeline", pipeline_ok, &health_label, hint);

    // --- Reporter stats (from proxy /metrics) ---
    if let Some(r) = reporter {
        let generated = r
            .get("usage_events_generated_total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let uploaded = r
            .get("usage_events_upload_success_total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let failed = r
            .get("usage_events_upload_failed_total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let dropped = r
            .get("usage_events_dropped_total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let consecutive = r
            .get("consecutive_failures")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let terminal = r
            .get("terminal_fail_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let last_status = r
            .get("last_upload_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let last_upload = r
            .get("last_upload_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let last_error_code = r
            .get("last_error_code")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let queue_depth = r
            .get("usage_queue_depth")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let wal_fail = r
            .get("usage_wal_append_failed_total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let upload_time = format_time_short(last_upload);
        let status_display = if last_status.is_empty() {
            "idle"
        } else {
            last_status
        };

        // Reporter is ok if currently healthy (consecutive < 5 and last status not terminal).
        // Historical failures with last_status=ok means it recovered — show ✓ with hint.
        let reporter_ok = consecutive < 5 && last_status != "terminal_failed";
        let reporter_hint = if terminal > 0 && last_status == "ok" {
            Some("recovered, but has terminal failures in dead_letter.jsonl")
        } else if terminal > 0 {
            Some("terminal failures — check collector_token")
        } else if failed > 0 {
            Some("retryable failures detected")
        } else {
            None
        };
        emit(
            "  reporter",
            reporter_ok,
            &format!(
                "{} generated, {} uploaded, {} failed, {} dropped",
                generated, uploaded, failed, dropped
            ),
            reporter_hint,
        );
        let upload_hint = if consecutive > 0 {
            Some(format!(
                "{} consecutive failures, last HTTP {}",
                consecutive, last_error_code
            ))
        } else {
            None
        };
        emit(
            "  last upload",
            reporter_ok,
            &format!("{} ({})", upload_time, status_display),
            upload_hint.as_deref(),
        );

        if queue_depth > 0 || wal_fail > 0 {
            let mut parts = Vec::new();
            if queue_depth > 0 {
                parts.push(format!("{} queued", queue_depth));
            }
            if wal_fail > 0 {
                parts.push(format!("{} WAL write failures", wal_fail));
            }
            emit("  queue/WAL", wal_fail == 0, &parts.join(", "), None);
        }

        if terminal > 0 {
            emit(
                "  dead letters",
                false,
                &format!("{} events", terminal),
                Some("review ~/.aikey/data/usage-wal/dead_letter.jsonl"),
            );
        }
    }

    // --- Watermarks (from diagnostics) ---
    if let Some(ref d) = diag {
        let biz = d.get("business_watermarks");
        let canary_wm = d.get("canary_watermarks");

        let biz_ods = biz
            .and_then(|w| w.get("ods_latest_ingested_at"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let biz_dwd = biz
            .and_then(|w| w.get("dwd_latest_projected_at"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let can_ods = canary_wm
            .and_then(|w| w.get("ods_latest_ingested_at"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let can_dwd = canary_wm
            .and_then(|w| w.get("dwd_latest_projected_at"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let biz_ods_t = format_time_short(biz_ods);
        let biz_dwd_t = format_time_short(biz_dwd);
        let can_dwd_t = format_time_short(can_dwd);

        // Show watermarks if there's any data.
        // Why "(UTC)": watermarks come from SQLite datetime('now') which is UTC,
        // while proxy reporter timestamps are local time. Label prevents confusion.
        if biz_ods_t != "never" || biz_dwd_t != "never" {
            emit(
                "  watermarks",
                true,
                &format!("ODS: {}, DWD: {} (UTC)", biz_ods_t, biz_dwd_t),
                None,
            );
        }

        // Show canary watermark
        if can_dwd_t != "never" {
            emit(
                "  canary last seen",
                true,
                &format!(
                    "ODS: {}, DWD: {} (UTC)",
                    format_time_short(can_ods),
                    can_dwd_t
                ),
                None,
            );
        }

        // Show lag if present
        if let Some(lag) = d
            .get("lag")
            .and_then(|l| l.get("ods_to_dwd_seconds"))
            .and_then(|v| v.as_i64())
        {
            if lag > 60 {
                emit(
                    "  lag",
                    false,
                    &format!("ODS→DWD: {}s", lag),
                    Some("projector may be stalled"),
                );
            }
        }
    }

    // --- Canary probe result (from proxy /metrics) ---
    let canary = metrics.as_ref().and_then(|m| m.get("canary"));

    if let Some(c) = canary {
        let status = c
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let round_trip = c.get("round_trip_ms").and_then(|v| v.as_i64()).unwrap_or(0);
        let failed_stage = c.get("failed_stage").and_then(|v| v.as_str()).unwrap_or("");
        let ods = c
            .get("ods_received")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let dwd = c
            .get("dwd_projected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let ok = status == "ok";
        // Canary checks ODS and DWD only (no query-stage check yet — P2/P3).
        let stages = format!(
            "ODS {} DWD {}",
            if ods {
                crate::symbols::CHECK.s()
            } else {
                crate::symbols::CROSS.s()
            },
            if dwd {
                crate::symbols::CHECK.s()
            } else {
                crate::symbols::CROSS.s()
            }
        );

        let detail = if status == "unavailable" {
            format!("diagnostics endpoint not available  ({})", failed_stage)
        } else if ok {
            format!("ok ({:.1}s)  {}", round_trip as f64 / 1000.0, stages)
        } else {
            format!("{} — stuck at: {}  {}", status, failed_stage, stages)
        };

        let hint = if status == "unavailable" {
            Some("diagnostics not registered on this server — canary limited to reporter metrics")
        } else if !ok && !failed_stage.is_empty() {
            Some(match failed_stage {
                "ingest" => "events not reaching ODS — check reporter + collector",
                "projection" => "ODS ok but DWD stalled — check projector worker",
                _ => "run: curl http://127.0.0.1:8090/v1/diagnostics/pipeline",
            })
        } else {
            None
        };

        emit("  canary probe", ok, &detail, hint);
    }
}

/// Extract a short time display from an RFC3339-ish timestamp.
/// "2026-04-16T16:43:07Z" → "16:43:07"
/// Zero time or empty → "never"
fn format_time_short(ts: &str) -> String {
    if ts.is_empty() || ts.starts_with("0001-") {
        return "never".to_string();
    }
    if let Some(t_part) = ts.split('T').nth(1) {
        let clean = t_part.trim_end_matches('Z');
        // Truncate to HH:MM:SS — drop sub-seconds, timezone offset
        let base = clean.split('+').next().unwrap_or(clean);
        let base = if let Some(p) = base.rfind('-') {
            if p > 0 {
                &base[..p]
            } else {
                base
            }
        } else {
            base
        };
        // Drop fractional seconds (everything after first '.')
        if let Some(dot) = base.find('.') {
            base[..dot].to_string()
        } else {
            base.to_string()
        }
    } else {
        ts.to_string()
    }
}

// ===========================================================================
// `aikey doctor --detail` — extended diagnostics (no new server endpoints)
//
// Three sections, all sourced from local files / SQLite:
//
//   1. Recent failures  ← ~/.aikey/data/control-trial.db (read-only)
//        Last 5 ODS rows where request_status = 'error', with upstream
//        request_id (anthropic / openai support pivot) and error_message.
//
//   2. Ingest health    ← ~/.aikey/logs/control-trial.log
//        Tail and grep for SQLite INSERT failures. The most useful pattern
//        is "no column named X" — that's the schema-code drift signal that
//        caused the 2026-04-25 oauth_identity blackout. Reactive, but
//        cheap and accurate; pre-emptive schema-reflection would require
//        a new endpoint we want to avoid here.
//
//   3. 4xx body capture ← ~/.aikey/logs/aikey-proxy/current.jsonl
//        Render the most recent `proxy.request.4xx_body_capture` events
//        (only present when AIKEY_PROXY_DEBUG_4XX_BODIES was enabled at
//        proxy start). Includes upstream_request_id + truncated bodies.
//
// JSON mode short-circuits in main.rs — --detail extras are tty-only.
// ===========================================================================

/// Pure classifier for doctor's "hook wiring" item (2026-07-10). Extracted
/// so the four-quadrant matrix (bindings × rc-wired) is unit-testable
/// without touching the vault or the filesystem.
///
/// Why this item exists: "rc not wired" alone is a setup nit, but "bindings
/// ACTIVE and rc not wired" means the user believes keys are routing while
/// `claude`/`codex` run bare — the silent failure of the web-only
/// onboarding path (install → web use → never wire rc).
fn hook_wiring_check(
    has_active_bindings: bool,
    rc_wired: bool,
) -> (bool, &'static str, Option<&'static str>) {
    match (has_active_bindings, rc_wired) {
        (true, false) => (
            false,
            "active bindings but shell rc not wired — claude/codex will NOT route through aikey",
            Some("run `aikey hook install`, then open a new terminal"),
        ),
        (true, true) => (true, "active bindings routed via shell hook", None),
        (false, _) => (true, "no active bindings to route", None),
    }
}

#[cfg(test)]
mod hook_wiring_check_tests {
    use super::hook_wiring_check;

    #[test]
    fn red_only_when_bindings_active_and_rc_unwired() {
        let (ok, detail, hint) = hook_wiring_check(true, false);
        assert!(!ok);
        assert!(detail.contains("NOT route through aikey"));
        assert_eq!(
            hint,
            Some("run `aikey hook install`, then open a new terminal")
        );
    }

    #[test]
    fn green_in_the_other_three_quadrants() {
        assert!(hook_wiring_check(true, true).0);
        assert!(hook_wiring_check(false, true).0);
        assert!(hook_wiring_check(false, false).0);
    }
}

/// `aikey doctor --last-errors` — render the proxy's most-recent error responses
/// as a caused-by view (P2 of the error-origin plan, 20260719). Reads the ring
/// buffer state file the proxy writes; no network, no SSH-grepping. Each entry:
/// origin = WHO produced the error, path = hops it traversed, trace_id = the log
/// anchor to grep for the full request.
pub fn handle_doctor_last_errors(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let path = match std::env::var("AIKEY_RUN_DIR") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir).join("last-errors.json"),
        _ => match dirs::home_dir() {
            Some(h) => h.join(".aikey/run/last-errors.json"),
            None => {
                println!(
                    "{}",
                    "  (no home dir — cannot locate last-errors state)".dimmed()
                );
                return Ok(());
            }
        },
    };

    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => {
            // Absent file = the proxy hasn't recorded an error yet (or isn't the
            // one serving). Not an error — say so plainly.
            if json_mode {
                println!("{{\"entries\":[]}}");
            } else {
                println!(
                    "  {}\n  {}",
                    "No recent proxy errors recorded.".green(),
                    "(the proxy writes ~/.aikey/run/last-errors.json on any 4xx/5xx it produces or relays)".dimmed()
                );
            }
            return Ok(());
        }
    };

    if json_mode {
        // Pass the state file through verbatim — it is already the structured
        // summary a machine consumer wants.
        println!("{}", raw.trim());
        return Ok(());
    }

    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::json!({}));
    let entries = parsed
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        println!("  {}", "No recent proxy errors recorded.".green());
        return Ok(());
    }

    println!("  {}", "Recent proxy errors (newest last)".bold());
    println!("  {}", crate::symbols::BOX_H.s().repeat(52).dimmed());
    for e in &entries {
        let status = e.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
        let origin = e.get("origin").and_then(|v| v.as_str()).unwrap_or("");
        let hops = e.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let code = e.get("code").and_then(|v| v.as_str()).unwrap_or("");
        let trace = e.get("trace_id").and_then(|v| v.as_str()).unwrap_or("");
        let req_path = e.get("request_path").and_then(|v| v.as_str()).unwrap_or("");
        let upstream_id = e
            .get("upstream_request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Top line: the request + status. Caused-by lines below name the origin.
        let status_str = format!("{status}");
        let status_col = if status >= 500 {
            status_str.red()
        } else {
            status_str.yellow()
        };
        println!(
            "  {} {}  {}",
            status_col.bold(),
            req_path.bold(),
            code.dimmed()
        );
        // origin = the ROOT CAUSE (deepest producer), rendered Java caused-by style.
        let origin_label = describe_origin(origin);
        println!(
            "    {} {}",
            format!("{} caused by:", crate::symbols::TREE_LAST.s()).dimmed(),
            origin_label
        );
        if !hops.is_empty() {
            println!("       {} {}", "hops:".dimmed(), hops.dimmed());
        }
        if !trace.is_empty() {
            println!(
                "       {} {}  {}",
                "trace:".dimmed(),
                trace.dimmed(),
                format!("(grep {trace} in the proxy log for this hop)").dimmed()
            );
        }
        if !upstream_id.is_empty() {
            // The cross-boundary correlation key (P3): same id the provider logs
            // and support tickets use — JOIN it across the usage store / provider.
            println!(
                "       {} {}  {}",
                "upstream req:".dimmed(),
                upstream_id.cyan(),
                "(the provider's own request id — give it to their support, or JOIN the usage store)".dimmed()
            );
        }
    }
    Ok(())
}

/// Turns an X-Aikey-Error-Origin value into a one-line actionable label.
fn describe_origin(origin: &str) -> String {
    use colored::Colorize;
    if origin.is_empty() {
        return "unknown (error had no origin tag — likely nginx or a pre-P1 hop)"
            .dimmed()
            .to_string();
    }
    if let Some(provider) = origin.strip_prefix("upstream:") {
        return format!(
            "{} — the {} upstream returned this; not an aikey fault",
            origin.cyan(),
            provider
        )
        .to_string();
    }
    // component.CODE
    let component = origin.split('.').next().unwrap_or(origin);
    let hint = match component {
        "oauth-ingress" => "the cluster ingress produced it — check the request path / allowlist",
        "worker-proxy" => {
            "a cluster worker produced it — check that node (routing / account / egress)"
        }
        "local-proxy" => "your local proxy produced it — check local config / vault / binding",
        _ => "an aikey component produced it",
    };
    format!("{} — {}", origin.cyan(), hint)
}

pub fn handle_doctor_detail() -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;
    let dim_rule = crate::symbols::BOX_H.s().repeat(52).dimmed();

    // B2: the first two panels read the Trial-server ODS pipeline
    // (control-trial.db / .log) and are meaningful ONLY on a Trial host.
    // On Personal (local-server or CLI-only) that pipeline doesn't exist, so
    // instead of the misleading "trial DB not present — trial-server hasn't
    // run" (which implies it *should* have), state clearly that the panel is
    // N/A for this edition. The 4xx-captures panel reads aikey-proxy's log,
    // which every edition has, so it always runs.
    //
    // Production note: `aikey doctor` is client-side; a Production server's
    // ODS lives in PostgreSQL on the server host, not reachable from this
    // CLI — the ODS panels there also render as N/A with a pointer.
    let edition = crate::local_server_probe::detect_edition();
    let is_trial = matches!(edition, Some(crate::local_server_probe::Edition::Trial));
    let edition_na_note = doctor_detail_ods_na_note(edition);

    println!();
    println!("{}", dim_rule);
    println!(
        "{}",
        format!(
            "{}Recent failures (last 5 ODS errors)",
            crate::symbols::ICON_SEARCH.pre()
        )
        .bold()
    );
    if is_trial {
        println!("{}  {}", dim_rule, "from control-trial.db".dimmed());
        render_recent_failures();
    } else {
        println!("  {}", edition_na_note.dimmed());
    }

    println!();
    println!("{}", dim_rule);
    println!(
        "{}",
        format!(
            "{}Ingest health (signal-based)",
            crate::symbols::ICON_SEARCH.pre()
        )
        .bold()
    );
    if is_trial {
        println!("{}  {}", dim_rule, "from control-trial.log".dimmed());
        render_ingest_health();
    } else {
        println!("  {}", edition_na_note.dimmed());
    }

    println!();
    println!("{}", dim_rule);
    println!(
        "{}",
        format!("{}4xx body captures", crate::symbols::ICON_SEARCH.pre()).bold()
    );
    println!(
        "{}  {}",
        dim_rule,
        "from aikey-proxy current.jsonl".dimmed()
    );
    render_4xx_captures();

    println!();
    Ok(())
}

// --- Section 1 -------------------------------------------------------------

const TRIAL_DB_PATH: &str = ".aikey/data/control-trial.db";
const TRIAL_LOG_PATH: &str = ".aikey/logs/control-trial.log";
const PROXY_JSONL_PATH: &str = ".aikey/logs/aikey-proxy/current.jsonl";

fn render_recent_failures() {
    use colored::Colorize;
    let Some(home) = dirs::home_dir() else {
        println!("{}", "  (no home dir — cannot locate trial DB)".dimmed());
        return;
    };
    let db_path = home.join(TRIAL_DB_PATH);
    if !db_path.exists() {
        println!(
            "{}",
            "  (trial DB not present — trial-server hasn't run on this machine)".dimmed()
        );
        return;
    }

    // Open read-only so we never lock the WAL of a live trial-server.
    let conn = match rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "  {}",
                format!("(open {}: {})", db_path.display(), e).dimmed()
            );
            return;
        }
    };

    // Probe actual columns so the SELECT survives schema drift — the very
    // condition this tool is here to surface. Without this guard the prepare
    // step crashes when (e.g.) `oauth_identity` is missing, which is exactly
    // when the user most needs the recent-failures view to be readable.
    // Section 2 (ingest health) will still call out the drift; Section 1
    // gracefully degrades by substituting '' for any absent optional column.
    let cols: std::collections::HashSet<String> =
        match conn.prepare("SELECT name FROM pragma_table_info('usage_event_ods')") {
            Ok(mut stmt) => stmt
                .query_map([], |row| row.get::<_, String>(0))
                .and_then(|it| it.collect::<Result<std::collections::HashSet<_>, _>>())
                .unwrap_or_default(),
            Err(_) => {
                println!(
                    "  {}",
                    "(usage_event_ods table not found — trial-server never bootstrapped)".dimmed()
                );
                return;
            }
        };
    if !cols.contains("ods_id") || !cols.contains("request_status") {
        println!(
            "  {}",
            "(usage_event_ods missing required columns — schema not initialized)".dimmed()
        );
        return;
    }

    // Build SELECT dynamically. Required columns are referenced as-is; each
    // optional column is `COALESCE(<col>, '')` if the column exists, or just
    // `''` if it doesn't. Order is stable so the row tuple reads the same
    // positions regardless of which optionals were present.
    let opt = |c: &str| -> String {
        if cols.contains(c) {
            format!("COALESCE({}, '')", c)
        } else {
            "''".to_string()
        }
    };
    let absent: Vec<&str> = [
        "model",
        "virtual_key_id",
        "oauth_identity",
        "error_code",
        "error_message",
        "upstream_request_id",
    ]
    .iter()
    .copied()
    .filter(|c| !cols.contains(*c))
    .collect();
    if !absent.is_empty() {
        println!(
            "  {}",
            format!(
                "(schema partial: {} absent — see Ingest health below for fix)",
                absent.join(", ")
            )
            .yellow()
        );
    }

    let sql = format!(
        "SELECT ods_id, ingest_received_at, http_status_code,
                {model}, {vk}, {oauth}, {ec}, {em}, {urid}
         FROM usage_event_ods
         WHERE request_status = 'error'
         ORDER BY ods_id DESC
         LIMIT 5",
        model = opt("model"),
        vk = opt("virtual_key_id"),
        oauth = opt("oauth_identity"),
        ec = opt("error_code"),
        em = opt("error_message"),
        urid = opt("upstream_request_id"),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            println!("  {}", format!("(prepare query failed: {})", e).dimmed());
            return;
        }
    };

    let rows: Vec<(
        i64,
        i64,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        })
        .and_then(|i| i.collect::<Result<Vec<_>, _>>())
        .unwrap_or_default();

    if rows.is_empty() {
        println!("{}", "  (no error events in usage_event_ods)".dimmed());
        return;
    }

    for (ods_id, recv_ms, status, model, vk, oauth_id, error_code, error_msg, up_req_id) in rows {
        // Display label preference: oauth_identity (email) → vk (truncated).
        let label = if !oauth_id.is_empty() {
            format!("oauth:{}", oauth_id)
        } else if !vk.is_empty() {
            // Hide bulk of vk hash, keep prefix for orientation.
            let max_len = 48;
            if vk.len() > max_len {
                format!("{}…", &vk[..max_len])
            } else {
                vk
            }
        } else {
            "(unknown)".to_string()
        };
        let when = format_local_time_hms(recv_ms);
        println!(
            "  {}  HTTP {}  {}  {}",
            when.bold(),
            status.to_string().yellow(),
            if model.is_empty() {
                "(model?)".to_string()
            } else {
                model.clone()
            }
            .dimmed(),
            label.dimmed(),
        );
        println!("    {} {}", "ods_id:".dimmed(), ods_id.to_string().dimmed());
        if !error_code.is_empty() {
            println!("    {} {}", "error_code:".dimmed(), error_code);
        }
        if !up_req_id.is_empty() {
            println!(
                "    {} {}",
                "upstream_request_id:".dimmed(),
                up_req_id.cyan()
            );
        } else {
            println!(
                "    {}",
                "upstream_request_id:  (proxy didn't capture — check provider headers)".dimmed()
            );
        }
        if !error_msg.is_empty() {
            // Truncate long messages; full content is one query away in the DB.
            let trimmed: String = error_msg.chars().take(280).collect();
            let extra = if error_msg.chars().count() > 280 {
                "…"
            } else {
                ""
            };
            println!("    {} {}{}", "error_message:".dimmed(), trimmed, extra);
        }
        println!();
    }
}

// --- Section 2 -------------------------------------------------------------

fn render_ingest_health() {
    use colored::Colorize;
    use std::collections::HashMap;
    let Some(home) = dirs::home_dir() else { return };
    let log_path = home.join(TRIAL_LOG_PATH);
    if !log_path.exists() {
        println!(
            "{}",
            "  (no trial-server log — service hasn't run on this machine)".dimmed()
        );
        return;
    }

    // Tail the last ~512 KB. Keeping it bounded — we only care about recent
    // signals; older drift was either fixed or already surfaced.
    let tail = match read_tail_bytes(&log_path, 512 * 1024) {
        Ok(t) => t,
        Err(e) => {
            println!("  {}", format!("(read log failed: {})", e).dimmed());
            return;
        }
    };

    // Three patterns — each maps a SQLite INSERT failure to a fix hint.
    // regex unwrap is safe: literals are validated at compile time by the
    // regex test below (kept as a doc-test in spirit).
    let re_no_col = regex::Regex::new(r#"no column named (\w+)"#).unwrap();
    let re_not_null = regex::Regex::new(r#"NOT NULL constraint failed: \w+\.(\w+)"#).unwrap();
    let re_check = regex::Regex::new(r#"CHECK constraint failed: ([\w_]+)"#).unwrap();

    let mut missing_cols: HashMap<String, usize> = HashMap::new();
    let mut not_null_cols: HashMap<String, usize> = HashMap::new();
    let mut check_violations: HashMap<String, usize> = HashMap::new();
    let mut any_insert_fail = 0usize;

    for line in tail.lines() {
        if !line.contains("insert event failed") && !line.contains("INSERT") {
            continue;
        }
        any_insert_fail += 1;
        if let Some(c) = re_no_col.captures(line) {
            *missing_cols.entry(c[1].to_string()).or_insert(0) += 1;
        } else if let Some(c) = re_not_null.captures(line) {
            *not_null_cols.entry(c[1].to_string()).or_insert(0) += 1;
        } else if let Some(c) = re_check.captures(line) {
            *check_violations.entry(c[1].to_string()).or_insert(0) += 1;
        }
    }

    if any_insert_fail == 0 {
        println!(
            "{} {}",
            crate::symbols::CHECK.s().green(),
            "no insert failures in recent log window"
        );
        return;
    }

    // Cross-check log signal against current DB schema to suppress historical
    // false positives. Without this, every doctor run after the migration was
    // applied still flashes "drift detected" red because the log file still
    // contains pre-fix INSERT failures (log doesn't auto-rotate). The state
    // question — "is this column actually missing right now?" — is what the
    // operator cares about; the historical count is just supporting context.
    let live_cols: std::collections::HashSet<String> = {
        let trial_db = home.join(TRIAL_DB_PATH);
        match rusqlite::Connection::open_with_flags(
            &trial_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        ) {
            Ok(conn) => conn
                .prepare("SELECT name FROM pragma_table_info('usage_event_ods')")
                .and_then(|mut s| {
                    s.query_map([], |r| r.get::<_, String>(0))
                        .and_then(|it| it.collect::<Result<std::collections::HashSet<_>, _>>())
                })
                .unwrap_or_default(),
            // Open failed — fall back to "assume no columns known", treats
            // every signal as live drift. Conservative, may over-warn but
            // never silently misses a real problem.
            Err(_) => std::collections::HashSet::new(),
        }
    };
    let (missing_live, missing_historical): (Vec<_>, Vec<_>) = missing_cols
        .iter()
        .partition(|(col, _)| !live_cols.contains(*col));

    let mut printed_any = false;
    if !missing_live.is_empty() {
        printed_any = true;
        println!("{} Schema drift detected:", crate::symbols::CROSS.s().red());
        let mut entries = missing_live.clone();
        entries.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        for (col, n) in entries {
            println!(
                "   collector tried to write column {} but DB doesn't have it",
                col.yellow()
            );
            println!(
                "   {} {} occurrences in tail window",
                crate::symbols::HINT_ARROW.s().dimmed(),
                n.to_string().dimmed()
            );
        }
        let trial_db = home.join(TRIAL_DB_PATH);
        println!(
            "   {} {}",
            "FIX:".bold(),
            format!(
                "aikey-config-tool db upgrade --edition trial --db-path {}",
                trial_db.display()
            )
            .cyan()
        );
    }
    // Historical-only drift: column absent in past log lines but present in
    // current schema → migration already ran. Surface as info-level so the
    // operator knows the tail still contains pre-fix noise, but doesn't
    // mistake it for an active problem.
    if !missing_historical.is_empty() {
        printed_any = true;
        let mut entries = missing_historical;
        entries.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        let total: usize = entries.iter().map(|(_, n)| **n).sum();
        let cols_str = entries
            .iter()
            .map(|(c, n)| format!("{} ({}×)", c, n))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{} {} historical insert failures (already fixed — column now present in DB):",
            crate::symbols::INFO_I.s().cyan(),
            total.to_string().dimmed()
        );
        println!("   {}", cols_str.dimmed());
        println!("   {} log retains pre-fix entries; run a fresh canary or `aikey doctor --detail` later to confirm clean tail",
            crate::symbols::HINT_ARROW.s().dimmed());
    }
    if !not_null_cols.is_empty() {
        printed_any = true;
        println!(
            "{} NOT NULL violations (collector emitted NULL where schema requires value):",
            crate::symbols::CROSS.s().red()
        );
        let mut entries: Vec<_> = not_null_cols.iter().collect();
        entries.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        for (col, n) in entries {
            println!(
                "   {}: {} occurrences",
                col.yellow(),
                n.to_string().dimmed()
            );
        }
        println!(
            "   {} usually means proxy emitted an event with a missing field — check reportable.go",
            crate::symbols::HINT_ARROW.s().dimmed()
        );
    }
    if !check_violations.is_empty() {
        printed_any = true;
        println!(
            "{} CHECK constraint violations:",
            crate::symbols::CROSS.s().red()
        );
        for (constraint, n) in check_violations {
            println!(
                "   {}: {} occurrences",
                constraint.yellow(),
                n.to_string().dimmed()
            );
        }
        println!(
            "   {} an enum value drifted out of allowed range — check provider extractor",
            crate::symbols::HINT_ARROW.s().dimmed()
        );
    }
    if !printed_any {
        println!(
            "{} {} insert failures matched no known pattern (regex needs updating)",
            crate::symbols::WARN.s().yellow(),
            any_insert_fail.to_string()
        );
        println!("   {} grep ~/.aikey/logs/control-trial.log for 'insert event failed' to inspect raw lines",
            crate::symbols::HINT_ARROW.s().dimmed());
    }
}

// --- Section 3 -------------------------------------------------------------

fn render_4xx_captures() {
    use colored::Colorize;
    let Some(home) = dirs::home_dir() else { return };
    let jsonl_path = home.join(PROXY_JSONL_PATH);
    if !jsonl_path.exists() {
        println!(
            "{}",
            "  (proxy jsonl not present — proxy hasn't run on this machine)".dimmed()
        );
        return;
    }

    // Tail bytes for bounded scan.
    let tail = match read_tail_bytes(&jsonl_path, 1024 * 1024) {
        Ok(t) => t,
        Err(e) => {
            println!("  {}", format!("(read jsonl failed: {})", e).dimmed());
            return;
        }
    };

    let mut captures: Vec<serde_json::Value> = Vec::new();
    for line in tail.lines() {
        if !line.contains("4xx_body_capture") {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("event.name").and_then(|x| x.as_str()) != Some("proxy.request.4xx_body_capture") {
            continue;
        }
        captures.push(v);
    }

    if captures.is_empty() {
        println!("{}", "  (no 4xx body captures in tail window)".dimmed());
        println!("  {}", "to enable for next 4xx:".dimmed());
        println!(
            "    {}",
            "AIKEY_PROXY_DEBUG_4XX_BODIES=1 aikey proxy stop && aikey proxy start".cyan()
        );
        return;
    }

    // Show last 3 (already in chronological order from the log; reverse so newest first).
    let last3: Vec<_> = captures.into_iter().rev().take(3).collect();
    for v in last3 {
        let ts = v.get("ts").and_then(|x| x.as_str()).unwrap_or("?");
        let status = v.get("status_code").and_then(|x| x.as_i64()).unwrap_or(0);
        let provider = v.get("provider").and_then(|x| x.as_str()).unwrap_or("?");
        let path = v
            .get("request_path")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let up_id = v
            .get("upstream_request_id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let req_body = v.get("request_body").and_then(|x| x.as_str()).unwrap_or("");
        let resp_body = v
            .get("response_body")
            .and_then(|x| x.as_str())
            .unwrap_or("");

        println!(
            "  {}  HTTP {}  {}  {}",
            ts.bold(),
            status.to_string().yellow(),
            path.dimmed(),
            provider.dimmed()
        );
        if !up_id.is_empty() {
            println!("    {} {}", "upstream_request_id:".dimmed(), up_id.cyan());
        }
        let snip = |s: &str, n: usize| -> String {
            let trimmed: String = s.chars().take(n).collect();
            let extra = if s.chars().count() > n { "…" } else { "" };
            format!("{}{}", trimmed, extra)
        };
        println!("    {} {}", "request_body:".dimmed(), snip(req_body, 400));
        println!("    {} {}", "response_body:".dimmed(), snip(resp_body, 400));
        println!();
    }
}

// --- shared utilities ------------------------------------------------------

/// Read the last `cap` bytes of a file as a UTF-8 String (lossy if needed).
/// Returns the whole file when smaller than cap.
fn read_tail_bytes(path: &std::path::Path, cap: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = if len > cap { len - cap } else { 0 };
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity(cap.min(len) as usize);
    f.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Render an int64 unix-millis timestamp as `HH:MM:SS` in the local TZ.
/// Display-only — used for the recent-failures rows. Invalid / zero → "?".
fn format_local_time_hms(unix_ms: i64) -> String {
    if unix_ms <= 0 {
        return "?".to_string();
    }
    let secs = unix_ms / 1000;
    // Local-time conversion using the chrono crate if it's already available.
    // chrono is in the workspace via aikeytime; using a raw cast keeps this
    // helper dependency-free.
    let mut t = secs;
    // Apply the system TZ offset coarsely (system localtime via libc would
    // require chrono::Local). For doctor display, render UTC HH:MM:SS — same
    // basis as the existing pipeline-watermark rows.
    let h = (t / 3600) % 24;
    t %= 3600;
    let m = t / 60;
    let s = t % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

#[cfg(test)]
mod doctor_detail_tests {
    use super::*;

    #[test]
    fn ingest_health_regexes_compile() {
        // All three must parse — these are user-facing diagnostic patterns.
        let _ = regex::Regex::new(r#"no column named (\w+)"#).unwrap();
        let _ = regex::Regex::new(r#"NOT NULL constraint failed: \w+\.(\w+)"#).unwrap();
        let _ = regex::Regex::new(r#"CHECK constraint failed: ([\w_]+)"#).unwrap();
    }

    #[test]
    fn ingest_health_extracts_missing_column() {
        let re = regex::Regex::new(r#"no column named (\w+)"#).unwrap();
        let line = r#"{"level":"ERROR","msg":"insert event failed","error":"insert ods event canary-x: SQL logic error: table usage_event_ods has no column named oauth_identity (1)"}"#;
        let cap = re
            .captures(line)
            .expect("regex must match real log line shape");
        assert_eq!(&cap[1], "oauth_identity");
    }

    #[test]
    fn ingest_health_extracts_not_null_column() {
        let re = regex::Regex::new(r#"NOT NULL constraint failed: \w+\.(\w+)"#).unwrap();
        let line = "...NOT NULL constraint failed: usage_event_ods.event_time...";
        assert_eq!(&re.captures(line).unwrap()[1], "event_time");
    }

    #[test]
    fn format_local_time_hms_zero_returns_placeholder() {
        assert_eq!(format_local_time_hms(0), "?");
        assert!(!format_local_time_hms(1_700_000_000_000).contains('?'));
    }

    // ── B1: edition banner mapping ──────────────────────────────────
    #[test]
    fn doctor_edition_label_covers_all_editions() {
        use crate::local_server_probe::Edition;
        assert!(doctor_edition_label(Some(Edition::Trial)).starts_with("Trial"));
        assert!(doctor_edition_label(Some(Edition::Personal)).starts_with("Personal"));
        // CLI-only host (no local web service installed).
        assert!(doctor_edition_label(None).contains("CLI-only"));
    }

    // ── B2: --detail ODS panel N/A note by edition ──────────────────
    #[test]
    fn doctor_detail_ods_na_note_empty_only_for_trial() {
        use crate::local_server_probe::Edition;
        // Trial renders real ODS data → no N/A note.
        assert_eq!(doctor_detail_ods_na_note(Some(Edition::Trial)), "");
        // Non-Trial editions get a clear "not applicable" note (never the
        // misleading "trial-server hasn't run" wording).
        assert!(doctor_detail_ods_na_note(Some(Edition::Personal)).contains("not applicable"));
        assert!(doctor_detail_ods_na_note(None).contains("not applicable"));
    }

    // ── A2: plugin registry stays in lockstep with the app registry ──
    #[test]
    fn doctor_plugin_registry_matches_first_party_slugs() {
        use crate::commands_app::FIRST_PARTY_SLUGS;
        let plugins = doctor_plugin_registry();
        // Every first-party app must have a doctor row — otherwise a newly
        // launched plugin is silently un-diagnosed. Compared as sorted sets
        // of install slugs.
        let mut doctor_slugs: Vec<&str> = plugins.iter().map(|p| p.install_slug).collect();
        doctor_slugs.sort_unstable();
        let mut app_slugs: Vec<&str> = FIRST_PARTY_SLUGS.to_vec();
        app_slugs.sort_unstable();
        assert_eq!(
            doctor_slugs, app_slugs,
            "doctor_plugin_registry() and FIRST_PARTY_SLUGS drifted — add the new plugin to doctor"
        );
    }

    #[test]
    fn doctor_plugin_registry_exactly_one_daemon() {
        // trust-local is the only daemon plugin (own port); the compliance
        // filters are subprocesses. The §7.5 code `.find(|p| p.is_daemon)`
        // relies on this — pin it so a future daemon plugin forces a review.
        let plugins = doctor_plugin_registry();
        assert_eq!(plugins.iter().filter(|p| p.is_daemon).count(), 1);
    }

    #[test]
    fn doctor_plugin_paths_add_exe_on_windows() {
        let home = std::path::Path::new(r"C:\Users\Administrator");
        let plugins = doctor_plugin_registry();
        let trust_local = plugins.iter().find(|p| p.is_daemon).unwrap();
        assert!(
            doctor_plugin_bin_path(home, trust_local, true).ends_with("trust-local.exe"),
            "Windows doctor must look for the installed PE binary"
        );
        assert!(
            doctor_plugin_bin_path(home, trust_local, false).ends_with("trust-local"),
            "Unix doctor must keep the extensionless binary path"
        );
    }
}

// ---------------------------------------------------------------------------
// Connectivity-suite unit tests (2026-04-21)
//
// Scope: exercise the pure parts of the target builders + the display-layer
// helpers. Network-bound probes (test_provider_connectivity, tcp_ping) are
// not tested here — they require a running proxy / upstream and belong in
// tests/e2e_*.
// ---------------------------------------------------------------------------
