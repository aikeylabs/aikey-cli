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
    // Salt-based: listing entries needs the salt to decrypt, so a salt-less
    // vault file would fail the read anyway. See storage::vault_is_initialized.
    let vault_exists = storage::vault_is_initialized();
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

/// The `aikey app install` slug of the compliance detector.
///
/// Why a named constant: this string is a cross-process contract — it is the
/// `app_records.slug` the vault stores, the directory aikey-proxy resolves the
/// filter binary from (`internal/supervisor/filter_hook.go`
/// `complianceDetectorSlug`), and the key `aikey doctor` reads the filter toggle
/// with. It was previously a bare literal in the plugin registry; the compliance
/// health row needs the same value, and two literals two hundred lines apart is
/// exactly how the CLI ends up reading a toggle for an app the proxy does not
/// spawn. Pinned to `FIRST_PARTY_SLUGS` by a unit test.
pub const COMPLIANCE_DETECTOR_SLUG: &str = "ai-compliance-detector";

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
            install_slug: COMPLIANCE_DETECTOR_SLUG,
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

/// One rendered `fallback policy` doctor check (task 1b.10 of openspec change
/// `aliyun-aigw-p0-upstream-fallback`).
pub struct FallbackPolicyReport {
    pub ok: bool,
    /// Summary line: source census · rail state · freshness. Written to be
    /// paste-able into a ticket on its own.
    pub detail: String,
    pub hint: Option<String>,
    /// `(label, "<value> ms  (<source>)")`, overall-limit first.
    pub rows: Vec<(String, String)>,
}

/// Builds the `fallback policy` doctor row from the proxy's `/status` body.
///
/// 🔴 WHY THE SOURCE IS THE POINT, NOT THE VALUE. All five thresholds are
/// org-configurable and all five have a builtin default. An admin who set the idle
/// gap to 5 minutes and an admin who never touched it produce an *identical*
/// number on this screen. Without the source column the standard private-deployment
/// conversation — "I definitely changed it in the console" — has no evidence on
/// either side and burns an afternoon. With it, the answer is one line.
///
/// 🔴 A POLL FAILURE IS NOT AN OUTAGE. When the rail is stale or offline the data
/// plane deliberately keeps enforcing the last known values (task 1b.4). The hint
/// says that in the same breath as it reports the problem; otherwise an operator
/// reads "offline" and starts restarting things that are working correctly.
///
/// `now` is passed in rather than read here so the freshness arithmetic is
/// testable.
pub fn fallback_policy_report(
    status: Option<&serde_json::Value>,
    now: i64,
) -> FallbackPolicyReport {
    let fb = status.and_then(|j| j.get("upstream_fallback"));
    let Some(fb) = fb else {
        // Honest absence: /status omits the block on a build where the capability
        // is not wired. Printing defaults instead would invent five numbers that
        // nothing is enforcing — the precise failure the source column exists to
        // prevent, committed by the tool meant to detect it.
        return FallbackPolicyReport {
            ok: true,
            detail: "not reported by this proxy build".to_string(),
            hint: None,
            rows: Vec::new(),
        };
    };

    let synced = fb.get("synced").and_then(|v| v.as_bool()).unwrap_or(false);
    let version = fb.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
    let last_success = fb.get("last_success_at").and_then(|v| v.as_i64());

    // 🔴 Rail health is READ from the SyncRail framework's own block, not derived
    // from a timestamp here. A second definition of "stale" living in the CLI
    // would disagree with the proxy's the first time either side changed, and the
    // operator would be left with two answers and no way to tell which one the
    // data plane actually obeys.
    let rail = status
        .and_then(|j| j.get("control_plane_sync"))
        .and_then(|s| s.get("fallback_policy"));
    let rail_state = rail
        .and_then(|r| r.get("state"))
        .and_then(|v| v.as_str())
        .unwrap_or("not started");
    let rail_failures = rail
        .and_then(|r| r.get("consecutive_failures"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // Overall limit first: the operator's question is "how long can this make me
    // wait in total", so answer that before the per-attempt number feeding into it.
    let fields: [(&str, &str); 5] = [
        ("chain budget", "chain_total_budget_ms"),
        ("attempt timeout", "upstream_attempt_timeout_ms"),
        ("cooldown", "binding_cooldown_ms"),
        ("idle gap", "idle_gap_ms"),
        ("max stickiness", "max_stickiness_ms"),
    ];
    let thresholds = fb.get("thresholds");
    let mut by_source: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut rows: Vec<(String, String)> = Vec::new();
    for (label, key) in fields {
        let entry = thresholds.and_then(|t| t.get(key));
        let value = entry.and_then(|e| e.get("value")).and_then(|v| v.as_i64());
        let source = entry
            .and_then(|e| e.get("source"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        *by_source.entry(source.to_string()).or_insert(0) += 1;
        let shown = match value {
            Some(ms) => format!("{} ms", ms),
            None => "—".to_string(),
        };
        rows.push((label.to_string(), format!("{:<12} ({})", shown, source)));
    }

    // Chain state (task 3.5): how many upstreams are currently being routed
    // around, and how many switches have happened. 🔴 Read-only — a diagnostic
    // command must not change what it is diagnosing, and there is deliberately no
    // way to clear a cooldown from here at all.
    let cooling = fb
        .get("cooling_bindings")
        .and_then(|v| v.as_object())
        .map(|m| m.len())
        .unwrap_or(0);
    let switches = fb
        .get("switches_total")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let census = by_source
        .iter()
        .map(|(s, n)| format!("{} {}", s, n))
        .collect::<Vec<_>>()
        .join(" / ");
    let freshness = match (synced, last_success) {
        (true, Some(t)) => format!("synced {}s ago (v{})", (now - t).max(0), version),
        (true, None) => format!("synced (v{})", version),
        (false, _) => "never synced".to_string(),
    };
    let mut detail = format!("{} · rail {} · {}", census, rail_state, freshness);
    if switches > 0 || cooling > 0 {
        // Only shown when something actually happened. A permanent
        // "switches 0 · cooling 0" trains the reader to skip the line, and then
        // the one time it is not zero they skip it too.
        detail.push_str(&format!(
            " · {} switch(es) · {} upstream(s) cooling",
            switches, cooling
        ));
    }

    // 🔴 What counts as a failure. Never-synced *with a rail running* means the
    // proxy is asking and not being answered — real, and the thresholds in force
    // are not the ones in the console. Never-synced with NO rail is the Personal
    // shape (there is no control plane to ask), which is the correct resting state
    // rather than a fault. That distinction is read from the rail's presence,
    // 🚫 never from an edition branch.
    let rail_running = rail.is_some();
    let ok = match rail_state {
        "offline" | "stale" => false,
        _ => synced || !rail_running,
    };
    let hint = if ok {
        None
    } else {
        Some(format!(
            "control plane not answering ({} consecutive failures); the proxy is still enforcing \
             the last known values above — the data plane is NOT degraded. Check the control URL \
             and this host's network to it.",
            rail_failures
        ))
    };

    FallbackPolicyReport {
        ok,
        detail,
        hint,
        rows,
    }
}

// ── Compliance-detection health (aikey doctor §7.5) ────────────────────────
//
// WHY THIS EXISTS. Four P0s fixed on 2026-08-13 all shared one shape: the
// compliance filter was *configured* but not *effective*, and nothing outside
// the process said so.
//
//   - 20260813-corrupt-address-asset-reports-not-degraded  (a dictionary layer
//     landed but parsed to zero entries; the health flag still said healthy)
//   - 20260813-childhook-write-before-deadline-wedges-main-path  (the detector
//     child stopped answering; requests fell through un-inspected)
//   - 20260813-pipe-input-cap-truncates-silently  (content past 16 KiB was
//     forwarded to the upstream LLM without ever being scanned)
//   - 20260813-audit-only-pack-still-enforces  (a pack lifecycle state whose
//     product meaning is "observe only" was executing like `active`)
//
// Every one of those signals is now readable from outside the proxy — but the
// only place that READS them was the Cluster release gate
// (`workflow/CI/test/e2e/compliance-migration-cluster-live.sh`). Personal /
// Trial / Production had the endpoints and no door. Under 版型意识 a diagnostic
// that only one edition can perform is a bug, and `aikey doctor` is the one
// self-check entry point every edition ships, so it is the correct door.
//
// 🔴 SOURCES ARE EXISTING ENDPOINTS ONLY (慎重新建 API):
//   - GET /admin/compliance/packs      → the LIVE detector child, over IPC:
//     `available`, `address_assets`, `pulled[].status`, `rules_skipped_count`
//   - GET /v1/diagnostics/pipeline     → the PROXY's own counters:
//     `mask_restore.{status,tool_block_scan,scan_truncated_pieces,scan_skipped_bytes}`
//   - the vault (`app_records.filter_stages` + `compliance.master_policy`)
//     → what the user/admin DECLARED
// Both endpoints live on the same aikey-proxy binary that every edition runs,
// so this row behaves identically on all four.
//
// 🔴 THE VERDICT IS "DECLARED vs EFFECTIVE", NOT "IS IT INSTALLED". The old row
// checked only that the binary existed on disk, which is green on a box whose
// detector is crash-looping. Presence is a precondition, not a health signal.

/// Severity of the compliance row. Three levels, because the two-level
/// ok/fail of `emit` cannot express the distinction the four P0s turn on:
/// a capability that is deliberately off is fine, a capability that is
/// silently watered down is not fine but is not an outage either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceSeverity {
    /// Healthy, or deliberately off. Renders green; never fails doctor.
    Ok,
    /// 🟡 The filter runs but its coverage is reduced or its enforcement is
    /// bypassed — including "we could not find out" (an unknown must never
    /// render as healthy: that is the exact false-green these P0s were).
    Warn,
    /// 🔴 Declared ON but demonstrably not filtering. Main path unprotected.
    Error,
}

impl ComplianceSeverity {
    /// Machine-readable tag for `--json` consumers, matching the vocabulary the
    /// existing local-server row already emits (`"ok"` / `"warn"`).
    pub fn as_str(self) -> &'static str {
        match self {
            ComplianceSeverity::Ok => "ok",
            ComplianceSeverity::Warn => "warn",
            ComplianceSeverity::Error => "error",
        }
    }

    /// Only `Error` bubbles into doctor's overall pass/fail. A watered-down
    /// filter is reported loudly on its own row but does not turn the summary
    /// red — same policy the local-server row established.
    pub fn is_ok_for_summary(self) -> bool {
        self != ComplianceSeverity::Error
    }

    fn max(self, other: Self) -> Self {
        if (other as u8) > (self as u8) {
            other
        } else {
            self
        }
    }
}

/// One rendered `compliance` doctor row: a verdict line plus evidence sub-rows.
/// Same shape as `FallbackPolicyReport` above, deliberately — doctor already has
/// a "summary line + indented evidence" idiom and this is not a new one.
pub struct ComplianceHealthReport {
    pub severity: ComplianceSeverity,
    /// The summary line the user reads. Self-contained enough to paste into a
    /// ticket.
    pub detail: String,
    /// Cause + the next action that fixes it. Required on every non-Ok verdict.
    pub hint: Option<String>,
    /// `(label, value)` evidence rows, rendered indented under the verdict.
    pub rows: Vec<(String, String)>,
}

/// What the user/admin declared about compliance detection, read from the vault.
/// A single enum rather than two loose booleans because the three cases need
/// three different hints and 尽量避免由多个值来决定一个开关.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceToggle {
    /// Neither the local toggle nor an org mandate is on.
    Off,
    /// `app_records.filter_stages` is non-NULL on this vault.
    OnLocal,
    /// `compliance.master_policy.enabled` — the org requires it; the proxy
    /// force-spawns the detector even when the local toggle is NULL. Kept
    /// distinct from `OnLocal` because the user CANNOT fix a mandated host by
    /// themselves, so the hint must point at their admin, not at a CLI command.
    OnMandated,
}

impl ComplianceToggle {
    /// Resolve from the two vault reads. Mandate wins: when the org requires
    /// compliance the proxy runs the detector regardless of the local column,
    /// so reporting "off" because `filter_stages` is NULL would describe a host
    /// that is in fact filtering every request.
    pub fn resolve(local_stages_present: bool, org_mandated: bool) -> Self {
        match (org_mandated, local_stages_present) {
            (true, _) => ComplianceToggle::OnMandated,
            (false, true) => ComplianceToggle::OnLocal,
            (false, false) => ComplianceToggle::Off,
        }
    }

    fn is_on(self) -> bool {
        self != ComplianceToggle::Off
    }
}

/// `degraded_reason` → (what it means for the user, what actually fixes it).
///
/// 🔴 WHY A TABLE AND NOT `if` BRANCHES. These are the causes the proxy
/// ENUMERATES (`apphook.DegradeReason*`), they cross a process boundary, and each
/// one has a DIFFERENT remedy — telling someone to reinstall a binary that is
/// present and running (the `write_timeout` wedge) sends them round a loop that
/// cannot terminate. A table keeps "one cause, one remedy" checkable at a glance
/// and makes an unmapped cause obvious instead of silently falling into a
/// neighbour's branch (不要写胶水逻辑，穷举用配置表).
///
/// Not exhaustive over every string the proxy can emit, on purpose: the dynamic
/// causes carry an OS error verbatim (`not_installed: <stat error>`,
/// `write_failed: …`), and flattening those would throw away the only detail
/// that identifies them. They fall to `filter_worker_remedy`'s passthrough.
const FILTER_WORKER_REMEDIES: &[(&str, &str, &str)] = &[
    (
        "write_timeout",
        "WEDGED — the child process is alive but stopped reading its pipe, so requests are never inspected",
        "recover with: aikey proxy restart — the child IS running, so reinstalling it will not help. \
         Then grep ~/.aikey/logs/aikey-proxy/current.jsonl for proxy.apphook.degraded",
    ),
    (
        "not_started",
        "NEVER STARTED — no detector child process was spawned on this proxy generation",
        "the child was never launched (missing/unreadable binary, or the proxy started before it was installed). \
         Fix with: aikey app install ai-compliance-detector && aikey proxy restart",
    ),
    (
        "restarting",
        "RESTARTING — a respawn is in flight",
        "transient: re-run aikey doctor in a few seconds. If it persists the child is crash-looping — \
         grep ~/.aikey/logs/aikey-proxy/current.jsonl for proxy.apphook.degraded",
    ),
];

/// Resolves one worker's `degraded_reason` into (meaning, remedy).
fn filter_worker_remedy(reason: &str) -> (String, String) {
    for (key, meaning, fix) in FILTER_WORKER_REMEDIES {
        if reason == *key {
            return ((*meaning).to_string(), (*fix).to_string());
        }
    }
    // Unmapped or prefixed cause. Report it VERBATIM rather than collapsing it to
    // "unknown": the proxy put an OS error in there and it is the only thing that
    // identifies the failure (禁止静默 return 默认值).
    (
        format!("NOT ANSWERING — the proxy reports: {reason}"),
        "recover with: aikey proxy restart — then grep ~/.aikey/logs/aikey-proxy/current.jsonl \
         for proxy.apphook.degraded to see why"
            .to_string(),
    )
}

/// The generic hint used whenever the per-worker cause cannot be read (older
/// proxy, or the endpoint did not answer). Kept as one constant so the
/// "we could not find out" wording cannot drift between the two places that
/// need it.
const FILTER_FAULT_GENERIC_HINT: &str =
    "the proxy could not reach the detector child (crashed / wedged / version mismatch). \
     Recover with: aikey proxy restart — then grep ~/.aikey/logs/aikey-proxy/current.jsonl \
     for proxy.apphook.degraded to see why";

/// Builds the `compliance` doctor row.
///
/// Pure: every input is passed in so all five states below are reachable from a
/// unit test without a live proxy, a live detector, or a vault — the states that
/// matter most (wedged child, corrupt dictionary) are the ones you cannot stage
/// on a developer box.
///
/// - `toggle`   — what the vault says (see `ComplianceToggle`).
/// - `installed`— detector binary present on disk.
/// - `packs`    — `GET /admin/compliance/packs` envelope; `None` = unreachable
///                / timed out / endpoint absent on an older proxy.
/// - `pipeline` — `GET /v1/diagnostics/pipeline`; `None` = same.
pub fn compliance_health_report(
    toggle: ComplianceToggle,
    installed: bool,
    packs: Option<&serde_json::Value>,
    pipeline: Option<&crate::commands_proxy::PipelineDiagnosticsWire>,
) -> ComplianceHealthReport {
    // ── State 1: off ────────────────────────────────────────────────────
    // Not an error, and deliberately not silent. A health panel that says
    // nothing leaves the user unable to tell "compliance filtering isn't
    // running" from "doctor doesn't check it" — the reason the plugin rows
    // started being printed when absent in the first place.
    if !toggle.is_on() {
        return ComplianceHealthReport {
            severity: ComplianceSeverity::Ok,
            detail: if installed {
                "disabled — detector installed but not enabled for filtering".to_string()
            } else {
                "disabled — optional compliance filter not installed".to_string()
            },
            hint: Some(
                "this is a normal state; enable with: aikey app install ai-compliance-detector"
                    .to_string(),
            ),
            rows: Vec::new(),
        };
    }

    let declared = match toggle {
        ComplianceToggle::OnMandated => "enabled by org policy",
        _ => "enabled",
    };

    // ── State 2: declared ON, binary missing ────────────────────────────
    // 🔴 The single worst state: the console/config promises filtering and not
    // one byte is being inspected. On a MANDATED org it is worse still — the
    // proxy refuses the whole data plane with 501 rather than forward
    // unfiltered (supervisor `declaredButMissing`), so the user's `claude` is
    // also broken and this row explains why.
    if !installed {
        return ComplianceHealthReport {
            severity: ComplianceSeverity::Error,
            detail: format!(
                "{declared} but the detector binary is MISSING — nothing is being filtered"
            ),
            hint: Some(match toggle {
                ComplianceToggle::OnMandated => "your organization mandates compliance detection \
                     and the binary is absent, so the proxy refuses all traffic (501). \
                     Reinstall it with: aikey app install ai-compliance-detector"
                    .to_string(),
                _ => "the toggle is on but ~/.aikey/apps/ai-compliance-detector/bin/ is empty. \
                     Reinstall with: aikey app install ai-compliance-detector"
                    .to_string(),
            }),
            rows: Vec::new(),
        };
    }

    // ── State 3: declared ON, binary present, cannot read the live state ──
    // 🟡 An UNKNOWN, reported as an unknown. Rendering this green would be the
    // same false-green the four P0s were: the wedged-child failure mode
    // (20260813-childhook-write-before-deadline) surfaces exactly here, because
    // a child that stopped reading its pipe also stops answering ListPacks.
    let Some(packs) = packs else {
        return ComplianceHealthReport {
            severity: ComplianceSeverity::Warn,
            detail: format!("{declared} · UNKNOWN — cannot read the live filter state"),
            hint: Some(
                "the proxy did not answer GET /admin/compliance/packs (not running, or a build \
                 without that route). Start it with: aikey proxy start — then re-run aikey doctor"
                    .to_string(),
            ),
            rows: Vec::new(),
        };
    };

    // ── State 4: declared ON, binary present, live child not answering ──
    // 🔴 `available:false` with the binary on disk means the proxy asked the
    // detector child and got nothing: crashed, wedged, protocol-mismatched, or
    // never spawned. Requests keep flowing (fail-open, by design) — un-inspected.
    let available = packs
        .get("available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !available {
        // 🔴 THE B5/B36 DISCRIMINATION. `available:false` is ONE observation with
        // several causes, and until the proxy started publishing per-worker health
        // this row had to lump them together: "crashed / wedged / version
        // mismatch", with a single guessed remedy. The two that matter most look
        // identical from here and need opposite actions —
        //   write_timeout  the child is ALIVE and running; restart the proxy,
        //                  reinstalling changes nothing
        //   not_started    nothing was ever spawned; the binary/install is the
        //                  problem, restarting alone may not help
        // — so the cause now comes from /v1/diagnostics/pipeline `filter_hook`.
        // An older proxy omits that block and keeps exactly the old wording.
        let down: Vec<&crate::commands_proxy::FilterWorkerWire> = pipeline
            .and_then(|d| d.filter_hook.as_ref())
            .map(|f| f.workers.iter().filter(|w| !w.healthy).collect())
            .unwrap_or_default();
        let mut rows: Vec<(String, String)> = Vec::new();
        for w in &down {
            let (meaning, _) = filter_worker_remedy(&w.degraded_reason);
            rows.push((
                format!("worker {}", w.index),
                format!("{meaning} (restarts so far: {})", w.restart_count),
            ));
        }
        let (cause_suffix, hint) = match down.first() {
            // The raw enumerated reason goes in the summary line so it is
            // greppable and pasteable into a ticket; the human sentence is in the
            // evidence row above.
            Some(first) => (
                format!(" ({})", first.degraded_reason),
                filter_worker_remedy(&first.degraded_reason).1,
            ),
            None => (String::new(), FILTER_FAULT_GENERIC_HINT.to_string()),
        };
        return ComplianceHealthReport {
            severity: ComplianceSeverity::Error,
            detail: format!(
                "{declared} and installed, but the live detector is NOT ANSWERING{cause_suffix} — \
                 requests are flowing un-inspected"
            ),
            hint: Some(hint),
            rows,
        };
    }

    // ── State 5: live and answering — grade the coverage ────────────────
    let report = packs.get("report");
    let mut severity = ComplianceSeverity::Ok;
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut faults: Vec<String> = Vec::new();

    // Packs loaded — the baseline "is anything actually detecting" evidence.
    let pulled = report
        .and_then(|r| r.get("pulled"))
        .and_then(|v| v.as_array());
    let built_in_count = report
        .and_then(|r| r.get("built_in"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    rows.push((
        "packs".to_string(),
        format!(
            "{} built-in · {} distributed",
            built_in_count,
            pulled.map(|a| a.len()).unwrap_or(0)
        ),
    ));

    // 🟡 audit_only packs — bugfix 20260813-audit-only-pack-still-enforces.
    // The console publishes a pack in two steps so an admin can watch a round
    // before enforcing. That is a deliberate, correct action — but while it
    // lasts, those rules RECORD and do not intervene, and an operator reading a
    // green "compliance ok" would reasonably assume otherwise. Naming it is the
    // whole point: the bug was that the state existed in the UI and had no
    // effect; the mirror-image failure is having the effect and not showing it.
    let audit_only: Vec<String> = pulled
        .map(|a| {
            a.iter()
                .filter(|p| p.get("status").and_then(|s| s.as_str()) == Some("audit_only"))
                .filter_map(|p| p.get("name").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if !audit_only.is_empty() {
        severity = severity.max(ComplianceSeverity::Warn);
        faults.push(format!("{} pack(s) observe-only", audit_only.len()));
        rows.push((
            "audit-only".to_string(),
            format!(
                "{} — recording findings, NOT enforcing: {}",
                audit_only.len(),
                audit_only.join(", ")
            ),
        ));
    }

    // 🟡 Rules that were shipped but could not be compiled (RE2 rejects
    // lookahead/backreferences). Present in the pack, absent from the engine.
    let skipped = report
        .and_then(|r| r.get("rules_skipped_count"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if skipped > 0 {
        severity = severity.max(ComplianceSeverity::Warn);
        faults.push(format!("{skipped} rule(s) inactive"));
        rows.push((
            "rules skipped".to_string(),
            format!("{skipped} shipped rule(s) failed to compile and are NOT detecting"),
        ));
    }

    // 🟡 CN_ADDRESS opt-in dictionary — bugfix
    // 20260813-corrupt-address-asset-reports-not-degraded.
    //
    // 🔴 THE DISCRIMINATION THAT MATTERS: `degraded == true` is ALSO the resting
    // state of every host that simply never opted into the big dictionary (an
    // absent assets dir degrades all three layers by design). Treating that as a
    // fault would paint most Personal installs red and train users to ignore the
    // row. The dangerous state the bugfix was about is the MIDDLE one — assets
    // were delivered and a layer came back with zero usable entries (truncated
    // download, half-written file, version skew). So: some layers loaded AND
    // some did not ⇒ partial landing ⇒ warn; nothing loaded at all ⇒ not
    // provisioned ⇒ informational.
    if let Some(assets) = report.and_then(|r| r.get("address_assets")) {
        let village = assets
            .get("village_stems")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let community = assets
            .get("community_names")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let degraded = assets
            .get("degraded")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let missing: Vec<String> = assets
            .get("missing_layers")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let anything_loaded = village > 0 || community > 0;
        if degraded && anything_loaded {
            severity = severity.max(ComplianceSeverity::Warn);
            faults.push("address dictionary partial".to_string());
            rows.push((
                "address dict".to_string(),
                format!(
                    "DEGRADED — {} village stems / {} community names loaded; unusable layer(s): {}",
                    village,
                    community,
                    if missing.is_empty() {
                        "(unnamed)".to_string()
                    } else {
                        missing.join(", ")
                    }
                ),
            ));
        } else if degraded {
            rows.push((
                "address dict".to_string(),
                "opt-in big dictionary not installed (built-in minimal set in use)".to_string(),
            ));
        } else {
            rows.push((
                "address dict".to_string(),
                format!("{village} village stems · {community} community names"),
            ));
        }
    }

    // Proxy-side scan SCOPE + fidelity. Absent block = older proxy; say so
    // rather than implying the scope is fine.
    match pipeline {
        None => {
            severity = severity.max(ComplianceSeverity::Warn);
            faults.push("scan scope unknown".to_string());
            rows.push((
                "scan scope".to_string(),
                "UNKNOWN — GET /v1/diagnostics/pipeline did not answer".to_string(),
            ));
        }
        Some(diag) => {
            let mr = &diag.mask_restore;
            rows.push((
                "scan scope".to_string(),
                format!(
                    "roles [{}] · tool blocks {}",
                    mr.scan_roles.join(", "),
                    if mr.tool_block_scan.is_empty() {
                        "unreported"
                    } else {
                        &mr.tool_block_scan
                    }
                ),
            ));
            // 🟡 A deliberately-off lane is still a hole an operator must be able
            // to read from outside the process; agent tool payloads (file reads,
            // pasted logs) are where the sensitive text actually lives.
            if mr.tool_block_scan == "off" {
                severity = severity.max(ComplianceSeverity::Warn);
                faults.push("tool blocks unscanned".to_string());
                rows.push((
                    "tool blocks".to_string(),
                    "OFF — agent tool payloads bypass compliance entirely".to_string(),
                ));
            }
            // 🟡 Truncation — bugfix 20260813-pipe-input-cap-truncates-silently.
            // Anything past the 16 KiB detector input cap reached the upstream
            // LLM uninspected, so every audit number for this proxy generation
            // is a lower bound rather than a measurement.
            if mr.scan_truncated_pieces > 0 {
                severity = severity.max(ComplianceSeverity::Warn);
                faults.push("content truncated".to_string());
                rows.push((
                    "unscanned".to_string(),
                    format!(
                        "{} content piece(s) exceeded the 16 KiB scan cap — {} byte(s) reached the \
                         upstream LLM uninspected (generation {})",
                        mr.scan_truncated_pieces, mr.scan_skipped_bytes, diag.generation_id
                    ),
                ));
            }
            // 🔴 Filter child-process health + verdict cache (review B5/B36/B6).
            //
            // `available:true` above only proves that ONE unit answered a ListPacks
            // call. On a Production/Cluster pool the surviving worker takes that
            // call, so a pool at 1/2 keeps reporting itself up. That is the false
            // green this block exists to break.
            //
            // 🔴 THE CONSEQUENCE SENTENCE COMES FROM THE PROXY, VERBATIM. It used
            // to be re-derived here ("dispatch is round-robin and does not skip
            // dead workers"), and on 2026-08-14 the proxy stopped doing that
            // (review finding B39: dispatch now skips unfit workers, so a partial
            // pool loses headroom rather than coverage) — leaving this row stating
            // the opposite of what the data plane does. `filter_hook.reason` is
            // specified as the one human sentence every surface renders as-is, so
            // rendering it is what keeps the two from drifting again. doctor still
            // owns the severity and the per-worker remedies; it does not own the
            // description of dispatch behaviour.
            match diag.filter_hook.as_ref() {
                None => {
                    // An unknown must never render as healthy — the same rule the
                    // `scan scope` row above follows.
                    severity = severity.max(ComplianceSeverity::Warn);
                    faults.push("detector process health unknown".to_string());
                    rows.push((
                        "detector".to_string(),
                        "UNKNOWN — this proxy build does not report per-worker filter health, so \
                         'the child is wedged' cannot be distinguished from 'the child is fine'. \
                         Upgrade the proxy to see it."
                            .to_string(),
                    ));
                }
                Some(fh) => {
                    match fh.status.as_str() {
                        "ok" => rows.push((
                            "detector".to_string(),
                            format!(
                                "{}/{} worker process(es) answering",
                                fh.workers_healthy, fh.workers_total
                            ),
                        )),
                        "partial" | "degraded" => {
                            severity = severity.max(ComplianceSeverity::Warn);
                            faults.push(format!(
                                "{}/{} detector worker(s) down",
                                fh.workers_total - fh.workers_healthy,
                                fh.workers_total
                            ));
                            rows.push((
                                "detector".to_string(),
                                format!(
                                    "{}/{} worker process(es) answering — {}",
                                    fh.workers_healthy, fh.workers_total, fh.reason
                                ),
                            ));
                            for w in fh.workers.iter().filter(|w| !w.healthy) {
                                let (meaning, fix) = filter_worker_remedy(&w.degraded_reason);
                                rows.push((
                                    format!("worker {}", w.index),
                                    format!(
                                        "{meaning} (restarts so far: {}) · {fix}",
                                        w.restart_count
                                    ),
                                ));
                            }
                        }
                        // "inactive" here would contradict `available:true` (the
                        // detector just answered), and an unrecognised status is a
                        // contract drift. Neither may be silently treated as fine.
                        other => {
                            severity = severity.max(ComplianceSeverity::Warn);
                            faults.push("detector process health unknown".to_string());
                            rows.push((
                                "detector".to_string(),
                                format!(
                                    "UNKNOWN — the proxy reported filter status {:?} while the \
                                     detector was answering; these disagree, so worker health \
                                     cannot be trusted",
                                    other
                                ),
                            ));
                        }
                    }

                    // 🟡 Verdict cache switched off at runtime (review B6). The
                    // BEHAVIOUR is correct and deliberate: a detector that cannot
                    // state which ruleset it is using must not have its verdicts
                    // replayed, or a rule the admin just deleted keeps masking. What
                    // was missing is that the price — every content piece re-scanned
                    // every turn, a ~96% cache hit rate down to 0 — was invisible,
                    // so the only symptom an operator ever saw was "the proxy got
                    // slower" with nothing to attribute it to.
                    if fh.verdict_cache.status == "suspended" {
                        severity = severity.max(ComplianceSeverity::Warn);
                        faults.push("verdict cache disabled".to_string());
                        // The sentence comes from the proxy verbatim: it owns the
                        // one judgment function for this state, and re-deriving the
                        // wording here is how the two surfaces start disagreeing.
                        let mut detail = if fh.verdict_cache.reason.is_empty() {
                            "DISABLED — the detector cannot state which ruleset is live, so every \
                             content piece is re-scanned"
                                .to_string()
                        } else {
                            fh.verdict_cache.reason.clone()
                        };
                        if fh.verdict_cache.cause == "unsupported_op_list_packs" {
                            detail.push_str(
                                " Upgrade with: aikey app install ai-compliance-detector && aikey proxy restart",
                            );
                        }
                        rows.push(("verdict cache".to_string(), detail));
                    }
                }
            }

            // 🟡 Masking works but the models are not returning placeholders, so
            // users see `{{ADDR_1}}` instead of their own text. Not a security
            // hole — a usability one — hence warn, and only once the proxy has
            // enough samples to have a verdict at all.
            if mr.status == "degraded" {
                severity = severity.max(ComplianceSeverity::Warn);
                faults.push("mask restore degraded".to_string());
                rows.push((
                    "mask restore".to_string(),
                    format!(
                        "DEGRADED — {}",
                        if mr.reason.is_empty() {
                            "too few mask placeholders are coming back intact"
                        } else {
                            mr.reason.as_str()
                        }
                    ),
                ));
            }
        }
    }

    let (detail, hint) = if faults.is_empty() {
        (
            format!("{declared} · live filter answering · full coverage"),
            None,
        )
    } else {
        (
            format!(
                "{declared} · live filter answering · REDUCED COVERAGE: {}",
                faults.join(" · ")
            ),
            Some(
                "the filter is running but not inspecting everything it appears to. Read the rows \
                 above for which layer is reduced; each is either an admin choice (audit-only \
                 packs, tool-block lane) or a provisioning gap (dictionary, skipped rules)."
                    .to_string(),
            ),
        )
    };

    ComplianceHealthReport {
        severity,
        detail,
        hint,
        rows,
    }
}

/// One `emit(...)` call, as data: `(label, ok, detail, hint)`.
///
/// Why this exists rather than looping over `report.rows` at the call site:
/// `emit` derives BOTH surfaces from these four values — the human line
/// (`icon label detail` + dim hint) and the `--json` object (`{check, ok,
/// detail, hint}`). Materialising the argument tuples lets a unit test assert
/// what the user actually reads in both modes from the same values the renderer
/// consumes, instead of re-describing the JSON shape in the test and letting the
/// two drift.
pub type DoctorRow = (String, bool, String, Option<String>);

/// Flattens a `ComplianceHealthReport` into the rows doctor emits: the verdict
/// row followed by its evidence rows. Evidence rows are indented (leading space)
/// — `emit` renders a whitespace-prefixed label as a dim sub-branch of the
/// preceding check and never bubbles it into the overall pass/fail, so the
/// failure is called out once, by its parent.
pub fn compliance_doctor_rows(report: &ComplianceHealthReport) -> Vec<DoctorRow> {
    let mut out: Vec<DoctorRow> = vec![(
        "compliance".to_string(),
        report.severity.is_ok_for_summary(),
        report.detail.clone(),
        report.hint.clone(),
    )];
    for (label, value) in &report.rows {
        out.push((format!(" {label}"), true, value.clone(), None));
    }
    out
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

    // ── Licensed identity (specs/license-identity ID-02) ────────────────────
    //
    // 🔴 Printed FIRST and verbatim, exactly as `aikey status` prints it and as
    // the web sign-in and settings pages render it. ID-02 requires all four to
    // be byte-identical, and a diagnostic is the likeliest place for that to
    // break — diagnostics get written in a hurry, against whatever value is
    // nearest. So this row does not go through `emit`: the check-table format
    // would prepend an icon and a padded label to the line, and the line IS the
    // artifact under comparison.
    //
    // 🚫 It is deliberately not a pass/fail check. "This install has no licence"
    // is a resting state for Personal, and a ✗ against it would report the
    // open-source user as broken.
    let licence = crate::license_identity::resolve();
    let licence_reminder = crate::license_identity::reminder();
    if !json_mode {
        println!("{}", crate::license_identity::line(&licence));
        // Same line, same producer, same prohibition on composing our own text.
        if let Some(reminder) = &licence_reminder {
            println!("{reminder}");
        }
        println!();
    } else {
        results.push(serde_json::json!({
            "check": "license_identity",
            "state": match &licence {
                crate::license_identity::State::Licensed(_) => "licensed",
                crate::license_identity::State::Unlicensed => "unlicensed",
                crate::license_identity::State::Error(_) => "error",
            },
            "cause": match &licence {
                crate::license_identity::State::Error(cause) => Some(cause.clone()),
                _ => None,
            },
            "line": crate::license_identity::line(&licence),
            // A field to read, not a line to scrape — the same convention the
            // error cause above follows for scripted callers.
            "reminder": licence_reminder,
        }));
    }
    // 🚫 Human mode only. json_output::print_json writes the report to STDERR
    // (this codebase's long-standing convention), so a warning emitted in --json
    // mode would be interleaved with the machine's own payload. The error state
    // reaches a scripted caller as the `license_identity` check's `state` and
    // `cause` fields instead — a field to read, not a line to scrape.
    if !json_mode {
        crate::license_identity::warn_if_error(&licence);
    }

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

        // ── Baseurl sync (20260728-端口漂移baseurl自愈回写) ──
        // Live actual port (runtime.json, pid-verified) vs the ports already
        // WRITTEN into downstream configs. Port drift self-heals at the
        // ensure-running / service-start seams; this row is the read-only
        // backstop that makes a not-yet-healed stale port visible — before
        // it, doctor probed the actual port and stayed green while claude
        // hit the dead one written on disk ("失败要显眼"). Skipped silently
        // when no live proxy (the proxy-version row above already flagged
        // that) or when nothing local is written yet (no bindings/cluster).
        {
            let live_port = crate::commands_proxy::read_runtime_actual_addr()
                .and_then(|a| a.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()));
            if let Some(actual) = live_port {
                // (surface, written local port) — None entries mean "surface
                // not present / not local", which is healthy, not stale.
                // Same collector the reconcile guard uses (single rule set).
                let surfaces = crate::profile_activation::written_local_baseurl_ports();
                let stale: Vec<String> = surfaces
                    .iter()
                    .filter_map(|(name, port)| {
                        port.filter(|p| *p != actual)
                            .map(|p| format!("{}:{}", name, p))
                    })
                    .collect();
                if stale.is_empty() {
                    if surfaces.iter().any(|(_, p)| p.is_some()) {
                        emit("baseurl sync", true, &format!("port {}", actual), None);
                    }
                } else {
                    emit(
                        "baseurl sync",
                        false,
                        &format!("proxy on {} but stale: {}", actual, stale.join(", ")),
                        Some("launch claude/codex once (auto-heals), or run `aikey use <alias>`"),
                    );
                }
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

    // ── 4b. Upstream-fallback thresholds ────────────────────
    //
    // Task 1b.10 of openspec change `aliyun-aigw-p0-upstream-fallback`.
    //
    // The rendering lives in `fallback_policy_report` (pure, below) so it can be
    // tested against the shapes that actually matter — never synced, stale rail,
    // missing block — none of which are reachable from here without a live proxy
    // in each of those states.
    if proxy_up {
        let url = format!("http://{}/status", proxy_addr);
        let status_json: Option<serde_json::Value> = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(3))
            .call()
            .ok()
            .and_then(|r| r.into_json().ok());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let report = fallback_policy_report(status_json.as_ref(), now);
        emit(
            "fallback policy",
            report.ok,
            &report.detail,
            report.hint.as_deref(),
        );
        for (label, value) in &report.rows {
            emit(&format!(" {}", label), true, value, None);
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

        // ── compliance filters (subprocess) ──
        // The proxy spawns these per request (stdin/stdout frames), so there is
        // no port of their own to probe. Presence of the binary is a
        // PRECONDITION row, kept as-is. Looped from the registry's non-daemon
        // entries so adding a filter app is a one-line table edit.
        //
        // 🔴 Presence is NOT health. A crash-looping or wedged detector has its
        // binary sitting on disk exactly like a working one, so this loop alone
        // was green on every failure the 2026-08-13 P0s describe. The `compliance`
        // row below is the health verdict; these rows only answer "can the proxy
        // spawn it at all".
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

        // ── 7.6. Compliance detection health (declared vs effective) ─────
        //
        // See the block comment on `compliance_health_report` for why this
        // exists and which four P0s it closes. Rendering only — every verdict
        // is made by the pure function so all five states are unit-tested.
        {
            // Declared: read from the vault. Plaintext columns/keys, no master
            // password — doctor stays zero-prompt (交互简洁性优先).
            let toggle = ComplianceToggle::resolve(
                crate::commands_app::get_app_filter_stages(COMPLIANCE_DETECTOR_SLUG)
                    .ok()
                    .flatten()
                    .is_some(),
                crate::storage::compliance_master_enabled(),
            );
            let detector = plugins
                .iter()
                .find(|p| p.install_slug == COMPLIANCE_DETECTOR_SLUG);
            let installed = detector
                .map(|p| doctor_plugin_bin_path(&home, p, cfg!(windows)).exists())
                .unwrap_or(false);

            // Probe the live proxy ONLY when compliance is declared on. A user
            // who never enabled it pays zero network cost, and the "off" verdict
            // does not depend on the proxy being up.
            let (packs, pipeline) = if toggle.is_on() {
                (
                    crate::commands_proxy::fetch_compliance_packs().ok(),
                    crate::commands_proxy::fetch_pipeline_diagnostics().ok(),
                )
            } else {
                (None, None)
            };

            let report =
                compliance_health_report(toggle, installed, packs.as_ref(), pipeline.as_ref());
            // Warn renders green-but-loud (ok=true + the state word spelled out
            // in `detail`), matching the model-mapping row's established
            // treatment of `degraded`; only Error turns the summary red.
            for (label, ok, detail, hint) in compliance_doctor_rows(&report) {
                emit(&label, ok, &detail, hint.as_deref());
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

    // ── 远程诊断信息（2026-09-01，用户要求「一条 ak doctor 收齐」）─────────
    //
    // 为什么并进主命令而不是只留 --last-errors：远程支援时对面是客户，
    // 「再跑一条带 flag 的命令」就是又一轮往返。doctor 一把梭收齐：
    //   · 最近错误响应（proxy last-errors 环：状态/来源/错误码/trace）
    //   · 硬吊销留痕（auth-demotions 环：何时、因上游说了什么、判死了哪把 token 前缀）
    // 两个环都是 proxy 落的本地文件，天然不含密钥（fingerprint 只留 12 字符前缀，
    // 响应体/消息原文一律不落盘）——整段输出可以直接粘进工单。
    // 详细的 caused-by 树仍走 `aikey doctor --last-errors`。
    // bugfix: workflow/CI/bugfix/2026-09-01-auth-failure-demotion-discards-upstream-evidence.md
    let diagnostics = print_remote_diagnostics(json_mode);

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
            // 结构化诊断快照：随 --json 一并带走，远程收集脚本不用再拼文件路径。
            "diagnostics": diagnostics,
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

/// One-shot remote-diagnosis snapshot for plain `aikey doctor` (2026-09-01).
///
/// Reads the proxy's two local diagnostic rings and prints a condensed view;
/// returns the raw JSON for `--json` mode. Both files are written secrets-free
/// by the proxy (truncated fingerprints, no bodies), so the whole section is
/// safe to paste into a ticket. Missing file = "none recorded", never an error:
/// doctor must stay useful on a machine where the proxy has not run yet.
fn print_remote_diagnostics(json_mode: bool) -> serde_json::Value {
    use colored::Colorize;

    let run_dir = match std::env::var("AIKEY_RUN_DIR") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => match dirs::home_dir() {
            Some(h) => h.join(".aikey/run"),
            None => return serde_json::json!({}),
        },
    };
    let read_entries = |name: &str| -> Vec<serde_json::Value> {
        std::fs::read_to_string(run_dir.join(name))
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|v| v.get("entries").and_then(|e| e.as_array()).cloned())
            .unwrap_or_default()
    };
    let errors = read_entries("last-errors.json");
    let demotions = read_entries("auth-demotions.json");

    if !json_mode {
        println!();
        println!("{}", "远程诊断信息 (Remote diagnostics — safe to paste)".bold());
        // 硬吊销留痕：这是「登录成功→一会儿变登录失效」类问题的第一手证据。
        if demotions.is_empty() {
            println!("  {} {}", "硬吊销:".dimmed(), "无记录".dimmed());
        } else {
            println!("  {}", "硬吊销 (token demotions, newest last):".yellow());
            for e in demotions.iter().rev().take(5).rev() {
                let at = e.get("at_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                let status = e.get("upstream_status").and_then(|v| v.as_i64()).unwrap_or(0);
                let etype = e.get("upstream_error_type").and_then(|v| v.as_str()).unwrap_or("-");
                let seat = e.get("seat_id").and_then(|v| v.as_str()).unwrap_or("");
                let fp = e.get("fingerprint_prefix").and_then(|v| v.as_str()).unwrap_or("");
                println!(
                    "    at_ms={} upstream={} type={} seat={} fp={}",
                    at,
                    if status == 0 { "旧版无证据".to_string() } else { status.to_string() },
                    etype, seat, fp
                );
            }
        }
        // 最近错误响应（凝缩版；完整 caused-by 树用 --last-errors）。
        if errors.is_empty() {
            println!("  {} {}", "最近错误:".dimmed(), "无记录".dimmed());
        } else {
            println!("  {}", "最近错误响应 (newest last, full tree: doctor --last-errors):".yellow());
            for e in errors.iter().rev().take(5).rev() {
                let at = e.get("at_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                let status = e.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
                let origin = e.get("origin").and_then(|v| v.as_str()).unwrap_or("");
                let code = e.get("code").and_then(|v| v.as_str()).unwrap_or("");
                let trace = e.get("trace_id").and_then(|v| v.as_str()).unwrap_or("");
                println!("    at_ms={} status={} origin={} code={} trace={}", at, status, origin, code, trace);
            }
        }
    }
    serde_json::json!({
        "auth_demotions": demotions,
        "last_errors": errors,
    })
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

    // ── Compliance-detection health (§7.6) ──────────────────────────
    //
    // These pin the five states a user can be in and, for each, the exact line
    // the user reads — in BOTH surfaces. `compliance_doctor_rows` returns the
    // very tuples `emit` consumes, so `render_human` / `render_json` below
    // reproduce doctor's two renderings from the same values rather than
    // re-describing them.
    //
    // Regression target: the four 2026-08-13 compliance P0s
    // (corrupt-address-asset / childhook-wedge / pipe-input-cap /
    // audit-only-pack). Each has a case here that goes RED if the row it
    // depends on stops being emitted.

    /// Reproduces `emit`'s human line for one row: `<icon> <label:20> <detail>`
    /// plus the indented hint. Colour is dropped (not part of the assertion).
    fn render_human(rows: &[DoctorRow]) -> String {
        let mut s = String::new();
        for (label, ok, detail, hint) in rows {
            if label.starts_with(' ') {
                s.push_str(&format!("    -> {:<16} {}\n", label.trim_start(), detail));
            } else {
                s.push_str(&format!(
                    "{} {:<20} {}\n",
                    if *ok { "OK" } else { "XX" },
                    label,
                    detail
                ));
            }
            if let Some(h) = hint {
                s.push_str(&format!("  -> {h}\n"));
            }
        }
        s
    }

    /// Reproduces `emit`'s `--json` payload for one row.
    fn render_json(rows: &[DoctorRow]) -> Vec<serde_json::Value> {
        rows.iter()
            .map(|(label, ok, detail, hint)| {
                serde_json::json!({
                    "check": label, "ok": ok, "detail": detail, "hint": hint,
                })
            })
            .collect()
    }

    /// The `compliance` verdict row out of a rendered row set.
    fn verdict(rows: &[DoctorRow]) -> &DoctorRow {
        rows.iter()
            .find(|(l, ..)| l == "compliance")
            .expect("every state must emit a `compliance` verdict row")
    }

    /// A live, fully healthy `/admin/compliance/packs` envelope. Field names and
    /// shapes are copied from a real response of the running proxy, not invented.
    fn healthy_packs() -> serde_json::Value {
        serde_json::json!({
            "available": true,
            "report": {
                "built_in": [{"name": "cn-pii"}, {"name": "credentials"}],
                "pulled": [
                    {"pack_id": "p1", "name": "Live Rule Pack", "status": "active"},
                    {"pack_id": "p2", "name": "NSFW · Political", "status": "active"}
                ],
                "rules_skipped_count": 0,
                "address_assets": {
                    "assets_dir": "/home/u/.aikey/apps/ai-compliance-detector/assets/address",
                    "village_stems": 232447,
                    "community_names": 402761,
                    "missing_layers": null,
                    "degraded": false
                }
            }
        })
    }

    fn healthy_pipeline() -> crate::commands_proxy::PipelineDiagnosticsWire {
        serde_json::from_value(serde_json::json!({
            "generation_id": 178,
            "mask_restore": {
                "status": "ok",
                "reason": "",
                "scan_roles": ["assistant", "user"],
                "tool_block_scan": "audit",
                "scan_truncated_pieces": 0,
                "scan_skipped_bytes": 0
            },
            // Field names and shapes copied from the proxy's FilterHookHealth
            // (internal/proxy/diagnostics.go), not invented — a fixture that
            // drifts from the wire turns every assertion below into a green lie.
            "filter_hook": {
                "status": "ok",
                "reason": "All 1 filter unit(s) answering.",
                "name": "ai-compliance-detector",
                "workers_healthy": 1,
                "workers_total": 1,
                "workers": [{
                    "index": 0,
                    "healthy": true,
                    "version": "detector/1.2.0",
                    "content_version": "9f2c1a7b3d4e5f60",
                    "restart_count": 0
                }],
                "verdict_cache": {
                    "status": "active",
                    "reason": "Verdicts are being reused within the current ruleset epoch.",
                    "content_version": "9f2c1a7b3d4e5f60"
                }
            }
        }))
        .expect("fixture must parse as the real wire struct")
    }

    /// A pipeline payload with a degraded filter pool. `down` describes the
    /// unhealthy workers as `(index, degraded_reason, restart_count)`.
    fn pipeline_with_pool(
        total: i64,
        down: &[(i64, &str, u64)],
    ) -> crate::commands_proxy::PipelineDiagnosticsWire {
        let workers: Vec<serde_json::Value> = (0..total)
            .map(|i| match down.iter().find(|(idx, ..)| *idx == i) {
                Some((_, reason, restarts)) => serde_json::json!({
                    "index": i, "healthy": false, "degraded_reason": reason,
                    "content_version_reason": "child_degraded", "restart_count": restarts,
                }),
                None => serde_json::json!({
                    "index": i, "healthy": true, "version": "detector/1.2.0",
                    "content_version": "9f2c1a7b3d4e5f60", "restart_count": 0,
                }),
            })
            .collect();
        let healthy = total - down.len() as i64;
        // 🔴 The `reason` sentences are copied VERBATIM from the proxy
        // (aikey-proxy/internal/proxy/diagnostics.go filterHookHealth). doctor
        // renders this field as-is, so a fixture with an empty/invented sentence
        // would assert nothing about what the user actually reads.
        let reason = if healthy == 0 {
            format!("No filter unit is answering (0/{total}) — inbound content is forwarded un-inspected (fail-open).")
        } else if healthy < total {
            format!("Only {healthy} of {total} filter units are answering. Dispatch skips the unfit units, so content is still inspected — but the pool is below its provisioned process count and the survivors carry all of the load.")
        } else {
            format!("All {total} filter unit(s) answering.")
        };
        let mut wire = healthy_pipeline();
        wire.filter_hook = serde_json::from_value(serde_json::json!({
            "status": if healthy == 0 { "degraded" } else if healthy < total { "partial" } else { "ok" },
            "reason": reason,
            "name": "ai-compliance-detector",
            "workers_healthy": healthy,
            "workers_total": total,
            "workers": workers,
            "verdict_cache": {"status": "active", "reason": "", "content_version": "9f2c1a7b3d4e5f60"}
        }))
        .expect("pool fixture must parse as the real wire struct");
        wire
    }

    // ── State 1/5: not enabled (user choice) ────────────────────────
    #[test]
    fn compliance_disabled_is_green_and_says_so_in_both_modes() {
        for installed in [false, true] {
            let r = compliance_health_report(ComplianceToggle::Off, installed, None, None);
            assert_eq!(
                r.severity,
                ComplianceSeverity::Ok,
                "turning compliance off is a normal state, never a doctor failure"
            );
            let rows = compliance_doctor_rows(&r);
            let human = render_human(&rows);
            assert!(human.contains("OK compliance"), "human line: {human}");
            assert!(
                human.contains("disabled"),
                "the user must be able to tell 'not running' from 'not checked': {human}"
            );
            let json = render_json(&rows);
            assert_eq!(json[0]["check"], "compliance");
            assert_eq!(json[0]["ok"], true);
            assert!(json[0]["detail"].as_str().unwrap().contains("disabled"));
            // Every non-green verdict must carry a next action; the off state
            // carries one too so the user knows how to turn it on.
            assert!(json[0]["hint"]
                .as_str()
                .unwrap()
                .contains("aikey app install ai-compliance-detector"));
        }
    }

    // ── State 2/5: enabled but binary absent (declared ≠ effective) ──
    #[test]
    fn compliance_enabled_without_binary_is_red_with_cause_and_fix() {
        let r = compliance_health_report(ComplianceToggle::OnLocal, false, None, None);
        assert_eq!(
            r.severity,
            ComplianceSeverity::Error,
            "config promises filtering and nothing is filtering — the loudest state there is"
        );
        let rows = compliance_doctor_rows(&r);
        let human = render_human(&rows);
        assert!(human.contains("XX compliance"), "must render red: {human}");
        assert!(human.contains("MISSING"), "cause must be explicit: {human}");
        let json = render_json(&rows);
        assert_eq!(json[0]["ok"], false, "red rows must fail in --json too");
        let hint = json[0]["hint"].as_str().unwrap();
        assert!(
            hint.contains("aikey app install"),
            "every error needs an actionable fix: {hint}"
        );
    }

    #[test]
    fn compliance_org_mandated_without_binary_points_at_the_501_and_the_admin() {
        let r = compliance_health_report(ComplianceToggle::OnMandated, false, None, None);
        assert_eq!(r.severity, ComplianceSeverity::Error);
        let rows = compliance_doctor_rows(&r);
        let human = render_human(&rows);
        // A mandated host refuses the whole data plane; doctor must say why the
        // user's `claude` is also broken rather than reporting only "missing".
        assert!(human.contains("org policy"), "{human}");
        assert!(
            human.contains("501"),
            "the user's requests are being refused — say so: {human}"
        );
    }

    // ── State 3/5: detector unreachable (the wedged-child shape) ────
    #[test]
    fn compliance_live_detector_not_answering_is_red_not_green() {
        // Regression: 20260813-childhook-write-before-deadline-wedges-main-path.
        // A wedged child keeps its binary on disk, so the presence row stays
        // green; `available:false` is the only external tell.
        let packs = serde_json::json!({"available": false});
        let r = compliance_health_report(ComplianceToggle::OnLocal, true, Some(&packs), None);
        assert_eq!(r.severity, ComplianceSeverity::Error);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("NOT ANSWERING"), "{human}");
        assert!(
            human.contains("un-inspected"),
            "state the consequence, not just the symptom: {human}"
        );
        assert!(
            human.contains("aikey proxy restart"),
            "recovery step required: {human}"
        );
    }

    #[test]
    fn compliance_endpoint_unreachable_is_unknown_never_green_claim() {
        // The endpoint not answering must not be dressed up as health — that is
        // the exact false-green shape all four P0s shared.
        let r = compliance_health_report(ComplianceToggle::OnLocal, true, None, None);
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let rows = compliance_doctor_rows(&r);
        let human = render_human(&rows);
        assert!(human.contains("UNKNOWN"), "{human}");
        assert!(
            !human.contains("full coverage"),
            "must never claim coverage it could not verify: {human}"
        );
        let json = render_json(&rows);
        assert!(json[0]["hint"]
            .as_str()
            .unwrap()
            .contains("aikey proxy start"));
    }

    // ── State 4/5: healthy ──────────────────────────────────────────
    #[test]
    fn compliance_healthy_renders_green_with_evidence_rows() {
        let packs = healthy_packs();
        let pipeline = healthy_pipeline();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(r.severity, ComplianceSeverity::Ok);
        assert_eq!(
            verdict(&compliance_doctor_rows(&r)).3,
            None,
            "no hint when clean"
        );
        let rows = compliance_doctor_rows(&r);
        let human = render_human(&rows);
        assert!(human.contains("OK compliance"), "{human}");
        assert!(human.contains("full coverage"), "{human}");
        // Evidence, not just a verdict: the counts are the substance.
        assert!(human.contains("2 built-in · 2 distributed"), "{human}");
        assert!(human.contains("232447 village stems"), "{human}");
        assert!(human.contains("roles [assistant, user]"), "{human}");
        let json = render_json(&rows);
        assert_eq!(json[0]["ok"], true);
        // Sub-rows are indented so `emit` renders them as dim branches and they
        // never bubble into the overall pass/fail.
        assert!(json[1]["check"].as_str().unwrap().starts_with(' '));
    }

    // ── State 5/5: degraded (address dictionary corrupt) ────────────
    #[test]
    fn compliance_partial_address_dictionary_warns_and_names_the_layer() {
        // Regression: 20260813-corrupt-address-asset-reports-not-degraded.
        // Two layers landed, villages.json parsed to zero → partial provisioning.
        let mut packs = healthy_packs();
        packs["report"]["address_assets"] = serde_json::json!({
            "assets_dir": "/home/u/.aikey/apps/ai-compliance-detector/assets/address",
            "village_stems": 0,
            "community_names": 402761,
            "missing_layers": ["villages.json"],
            "degraded": true
        });
        let pipeline = healthy_pipeline();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let rows = compliance_doctor_rows(&r);
        let human = render_human(&rows);
        assert!(human.contains("REDUCED COVERAGE"), "{human}");
        assert!(human.contains("DEGRADED"), "{human}");
        assert!(
            human.contains("villages.json"),
            "must name the broken layer, not just flag 'degraded': {human}"
        );
        // A watered-down filter is loud but does not turn doctor's summary red.
        let json = render_json(&rows);
        assert_eq!(json[0]["ok"], true);
        assert!(json[0]["detail"]
            .as_str()
            .unwrap()
            .contains("address dictionary partial"));
    }

    #[test]
    fn compliance_unprovisioned_address_dictionary_is_not_a_fault() {
        // 🔴 The discrimination that keeps this row credible: a host that never
        // opted into the B2 big dictionary reports degraded=true with all layers
        // at zero. Calling that a fault would paint most Personal installs red
        // and train users to ignore the row.
        let mut packs = healthy_packs();
        packs["report"]["address_assets"] = serde_json::json!({
            "assets_dir": "",
            "village_stems": 0,
            "community_names": 0,
            "missing_layers": ["villages.json", "osm-communities.txt", "osm-pois.txt"],
            "degraded": true
        });
        let pipeline = healthy_pipeline();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(
            r.severity,
            ComplianceSeverity::Ok,
            "not installing an opt-in dictionary is a choice, not a degradation"
        );
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(
            human.contains("opt-in big dictionary not installed"),
            "{human}"
        );
    }

    // ── The other two P0s ───────────────────────────────────────────
    #[test]
    fn compliance_audit_only_packs_are_named_as_not_enforcing() {
        // Regression: 20260813-audit-only-pack-still-enforces. The fix made
        // audit_only actually observe-only; this row makes that visible, so an
        // operator cannot read "compliance ok" and assume those rules intervene.
        let mut packs = healthy_packs();
        packs["report"]["pulled"][0]["status"] = serde_json::json!("audit_only");
        let pipeline = healthy_pipeline();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("NOT enforcing"), "{human}");
        assert!(
            human.contains("Live Rule Pack"),
            "name the pack so the admin knows which one to promote: {human}"
        );
    }

    #[test]
    fn compliance_truncated_content_is_reported_as_unscanned_bytes() {
        // Regression: 20260813-pipe-input-cap-truncates-silently. Non-zero
        // counters mean audit numbers are a lower bound, not a measurement.
        let packs = healthy_packs();
        let pipeline: crate::commands_proxy::PipelineDiagnosticsWire =
            serde_json::from_value(serde_json::json!({
                "generation_id": 178,
                "mask_restore": {
                    "status": "inactive",
                    "scan_roles": ["assistant", "user"],
                    "tool_block_scan": "audit",
                    "scan_truncated_pieces": 3,
                    "scan_skipped_bytes": 7617
                }
            }))
            .unwrap();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(
            human.contains("7617 byte(s) reached the upstream LLM uninspected"),
            "{human}"
        );
        assert!(
            human.contains("generation 178"),
            "counters are generation-scoped: {human}"
        );
    }

    #[test]
    fn compliance_tool_block_lane_off_is_reported_as_a_bypass() {
        let packs = healthy_packs();
        let pipeline: crate::commands_proxy::PipelineDiagnosticsWire =
            serde_json::from_value(serde_json::json!({
                "mask_restore": {"scan_roles": ["user"], "tool_block_scan": "off"}
            }))
            .unwrap();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("bypass compliance entirely"), "{human}");
    }

    #[test]
    fn compliance_old_proxy_without_truncation_counters_stays_silent() {
        // A proxy built before the pipe-cap fix omits the two counters. serde
        // defaults them to 0, and 0 renders nothing — an old proxy must not be
        // falsely accused of truncating.
        //
        // 🔴 It is nonetheless NOT green overall, and that changed deliberately on
        // 2026-08-13. The same old build also omits `filter_hook`, so worker
        // health is unreadable — and unlike a missing counter (0 has a safe
        // meaning) there is no safe default for "is the detector wedged?".
        // Rendering that unknown as OK is the exact false-green the four P0s
        // shared. So: silent about truncation (nothing was measured), loud about
        // the unknown (nothing could be measured).
        let packs = healthy_packs();
        let pipeline: crate::commands_proxy::PipelineDiagnosticsWire =
            serde_json::from_value(serde_json::json!({
                "mask_restore": {
                    "status": "inactive",
                    "scan_roles": ["assistant", "user"],
                    "tool_block_scan": "audit"
                }
            }))
            .expect("an older proxy's payload must still parse");
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(
            !human.contains("uninspected"),
            "an old proxy must not be accused of truncating: {human}"
        );
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        assert!(
            human.contains("UNKNOWN"),
            "unreadable worker health must be reported as unknown, never as healthy: {human}"
        );
        assert!(
            !human.contains("full coverage"),
            "must never claim coverage it could not verify: {human}"
        );
    }

    // ── Filter child-process health (review B5 / B36) ───────────────
    //
    // Before the proxy published `filter_hook`, `available:false` was the ONLY
    // external tell for every way the detector child can stop working, so the
    // two states with opposite remedies — a wedged child (alive, restart the
    // proxy) and a child that never spawned (nothing running, fix the install) —
    // rendered as one line with one guessed hint.

    /// Builds the State-4 (`available:false`) report with a given worker cause.
    fn detector_not_answering(reason: &str) -> ComplianceHealthReport {
        let packs = serde_json::json!({"available": false});
        let mut pipeline = healthy_pipeline();
        pipeline.filter_hook = serde_json::from_value(serde_json::json!({
            "status": "degraded",
            "reason": "No filter unit is answering (0/1).",
            "name": "ai-compliance-detector",
            "workers_healthy": 0,
            "workers_total": 1,
            "workers": [{
                "index": 0, "healthy": false, "degraded_reason": reason,
                "content_version_reason": "child_degraded", "restart_count": 4
            }],
            "verdict_cache": {"status": "suspended", "reason": "", "cause": "child_degraded"}
        }))
        .unwrap();
        compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        )
    }

    #[test]
    fn compliance_wedged_child_and_never_started_get_different_causes_and_fixes() {
        let wedged = detector_not_answering("write_timeout");
        let never = detector_not_answering("not_started");
        for r in [&wedged, &never] {
            assert_eq!(r.severity, ComplianceSeverity::Error);
        }

        let wedged_human = render_human(&compliance_doctor_rows(&wedged));
        let never_human = render_human(&compliance_doctor_rows(&never));

        // Both still say what is happening to traffic — that assertion predates
        // this change and must survive it.
        for h in [&wedged_human, &never_human] {
            assert!(h.contains("NOT ANSWERING"), "{h}");
            assert!(h.contains("un-inspected"), "{h}");
        }
        // …and now they differ in BOTH the cause and the remedy.
        assert!(
            wedged_human.contains("write_timeout") && wedged_human.contains("WEDGED"),
            "the wedge must be named, not folded into 'crashed / wedged / mismatch': {wedged_human}"
        );
        assert!(
            wedged_human.contains("reinstalling it will not help"),
            "a wedged child IS running — sending the user to reinstall is a loop that cannot \
             terminate: {wedged_human}"
        );
        assert!(
            never_human.contains("not_started") && never_human.contains("NEVER STARTED"),
            "{never_human}"
        );
        assert!(
            never_human.contains("aikey app install ai-compliance-detector"),
            "nothing was ever spawned — the fix is the install, not just a restart: {never_human}"
        );
        assert_ne!(
            wedged_human, never_human,
            "the two failure modes rendered identically — that IS the bug (B5)"
        );

        // Both surfaces, not just the human one.
        let json = render_json(&compliance_doctor_rows(&wedged));
        assert_eq!(json[0]["ok"], false);
        assert!(json[0]["detail"]
            .as_str()
            .unwrap()
            .contains("write_timeout"));
        assert!(json[0]["hint"]
            .as_str()
            .unwrap()
            .contains("aikey proxy restart"));
        assert!(
            json[1]["check"].as_str().unwrap().starts_with(' '),
            "the per-worker evidence must be an indented sub-row"
        );
        assert!(json[1]["detail"]
            .as_str()
            .unwrap()
            .contains("restarts so far: 4"));
    }

    #[test]
    fn compliance_not_answering_on_an_old_proxy_keeps_the_generic_wording() {
        // No `filter_hook` block ⇒ no cause to report. The row must not invent
        // one, and must keep working exactly as it did before.
        let packs = serde_json::json!({"available": false});
        let r = compliance_health_report(ComplianceToggle::OnLocal, true, Some(&packs), None);
        assert_eq!(r.severity, ComplianceSeverity::Error);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("NOT ANSWERING"), "{human}");
        assert!(human.contains("aikey proxy restart"), "{human}");
        assert!(
            !human.contains("WEDGED") && !human.contains("NEVER STARTED"),
            "an old proxy reports no cause — doctor must not fabricate one: {human}"
        );
    }

    #[test]
    fn compliance_unmapped_degraded_reason_is_reported_verbatim() {
        // The proxy also emits prefixed causes carrying an OS error
        // (`not_installed: stat …`). Those must reach the user intact rather than
        // being flattened into "unknown" — the error text is the only thing that
        // identifies them (禁止静默 return 默认值).
        let r =
            detector_not_answering("not_installed: stat /opt/detector: no such file or directory");
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(
            human.contains("no such file or directory"),
            "the underlying OS error must survive to the user: {human}"
        );
    }

    // ── Partial pool: the false green (review B39 intersection) ─────
    #[test]
    fn compliance_pool_with_a_dead_worker_is_not_reported_as_full_coverage() {
        // 🔴 THE CORE JUDGMENT. A pool with a dead worker reports
        // Status().Healthy = true and "1/2 workers healthy", and
        // `/admin/compliance/packs` still answers `available:true` because the
        // surviving worker takes the call — which is precisely why doctor cannot
        // derive this from that endpoint alone.
        //
        // What is at stake changed on 2026-08-14 (review B39): dispatch used to
        // include the dead worker, so a 2-worker pool really did fail open on
        // half its traffic (measured: 10 Detects → 5 fail-opens; live 3-worker
        // rerun: 4 of 12, at positions 1/4/7/10). Dispatch now skips it, so the
        // loss is headroom, not coverage. Either way the row must not be green
        // and must not describe dispatch in its own words — see below.
        let packs = healthy_packs();
        let pipeline = pipeline_with_pool(2, &[(1, "write_timeout", 2)]);
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(
            r.severity,
            ComplianceSeverity::Warn,
            "half the requests are un-inspected — this must not render as healthy"
        );
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(
            !human.contains("full coverage"),
            "FALSE GREEN: a pool with a dead worker claimed full coverage: {human}"
        );
        assert!(human.contains("1/2 detector worker(s) down"), "{human}");
        // 🔴 The consequence sentence must be the PROXY's, rendered verbatim.
        // Asserting on the proxy's wording (not on doctor's own phrasing) is what
        // makes this fence catch the drift that actually happened: the data plane
        // changed and doctor kept telling users the old story.
        assert!(
            human.contains(
                "Dispatch skips the unfit units, so content is still inspected — but the pool is \
                 below its provisioned process count and the survivors carry all of the load."
            ),
            "doctor must render filter_hook.reason verbatim, not re-derive its own description of \
             what dispatch does with a dead worker: {human}"
        );
        assert!(
            human.contains("worker 1") && human.contains("WEDGED"),
            "name WHICH worker and WHY: {human}"
        );
        // A single-worker (Personal / Trial) host is the M=1 degenerate case and
        // must stay green when its one worker is up.
        let ok = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&healthy_pipeline()),
        );
        assert_eq!(ok.severity, ComplianceSeverity::Ok);
        assert!(
            render_human(&compliance_doctor_rows(&ok)).contains("1/1 worker process(es) answering")
        );
    }

    #[test]
    fn compliance_filter_hook_status_disagreeing_with_packs_is_unknown_not_ok() {
        // `available:true` (the detector answered) plus a filter status that says
        // otherwise is contract drift between two endpoints on the same binary.
        // Silently trusting either one is how a false green gets built.
        let packs = healthy_packs();
        let mut pipeline = healthy_pipeline();
        pipeline.filter_hook = serde_json::from_value(serde_json::json!({
            "status": "inactive", "workers_healthy": 0, "workers_total": 0,
            "workers": [], "verdict_cache": {"status": "disabled"}
        }))
        .unwrap();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("UNKNOWN"), "{human}");
        assert!(human.contains("disagree"), "{human}");
    }

    // ── Verdict cache switched off (review B6) ──────────────────────
    #[test]
    fn compliance_old_detector_disables_the_verdict_cache_and_says_how_to_fix_it() {
        // Regression: 20260813-pack-swap-does-not-invalidate-proxy-cache. A
        // detector too old to answer op=ListPacks is HEALTHY and answering Detect,
        // so every other signal is green — while the proxy has switched its
        // verdict cache off (correctly: verdicts from an unstatable ruleset must
        // not be replayed) and re-scans every content piece on every turn. Hit
        // rate 96% → 0. Without this row the only symptom is "the proxy is slow".
        let packs = healthy_packs();
        let mut pipeline = healthy_pipeline();
        pipeline.filter_hook = serde_json::from_value(serde_json::json!({
            "status": "ok",
            "reason": "All 1 filter unit(s) answering.",
            "name": "ai-compliance-detector",
            "workers_healthy": 1,
            "workers_total": 1,
            "workers": [{
                "index": 0, "healthy": true, "version": "detector/1.0.0",
                "content_version_reason": "unsupported_op_list_packs", "restart_count": 0
            }],
            "verdict_cache": {
                "status": "suspended",
                "cause": "unsupported_op_list_packs",
                "reason": "Verdict caching is OFF because the detector build cannot report which \
                           ruleset it is using (it does not answer op=ListPacks). Every content \
                           piece is re-scanned, so filter latency is at its cold-path cost. \
                           Upgrade the detector to restore caching."
            }
        }))
        .unwrap();
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        assert_eq!(
            r.severity,
            ComplianceSeverity::Warn,
            "a silent, permanent latency regression is not a healthy state"
        );
        let human = render_human(&compliance_doctor_rows(&r));
        // The worker itself is fine — the row must not read as an outage.
        assert!(
            human.contains("1/1 worker process(es) answering"),
            "{human}"
        );
        assert!(human.contains("verdict cache"), "{human}");
        assert!(
            human.contains("re-scanned"),
            "explain the cost, not just the state: {human}"
        );
        assert!(
            human.contains("aikey app install ai-compliance-detector"),
            "the remedy is an UPGRADE and it must be spelled out: {human}"
        );
        let json = render_json(&compliance_doctor_rows(&r));
        assert_eq!(
            json[0]["ok"], true,
            "a latency regression must not fail the summary"
        );
        assert!(json[0]["detail"]
            .as_str()
            .unwrap()
            .contains("verdict cache disabled"));
    }

    #[test]
    fn compliance_verdict_cache_suspended_by_a_crash_does_not_advise_an_upgrade() {
        // Same suspended state, different cause. Printing "upgrade the detector"
        // for a crashed child sends the operator down the wrong path entirely.
        let packs = healthy_packs();
        let mut pipeline = pipeline_with_pool(2, &[(1, "write_timeout", 1)]);
        if let Some(fh) = pipeline.filter_hook.as_mut() {
            fh.verdict_cache = serde_json::from_value(serde_json::json!({
                "status": "suspended", "cause": "child_degraded",
                "reason": "Verdict caching is OFF because the filter child is degraded and cannot \
                           vouch for its ruleset. It clears when the child recovers."
            }))
            .unwrap();
        }
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&packs),
            Some(&pipeline),
        );
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("clears when the child recovers"), "{human}");
        assert!(
            !human.contains("Upgrade with: aikey app install"),
            "a crashed child must not be sent for an upgrade: {human}"
        );
    }

    #[test]
    fn compliance_active_verdict_cache_adds_no_noise() {
        // A healthy cache is the steady state; a row for it on every run would
        // dilute the rows that mean something (简化设计去除冗余).
        let r = compliance_health_report(
            ComplianceToggle::OnLocal,
            true,
            Some(&healthy_packs()),
            Some(&healthy_pipeline()),
        );
        assert!(!render_human(&compliance_doctor_rows(&r)).contains("verdict cache"));
    }

    #[test]
    fn compliance_new_wire_block_is_optional_in_both_directions() {
        // 向后兼容, all four version pairings:
        //  - new CLI + new proxy   → the block parses and grades (covered above)
        //  - new CLI + old proxy   → absent block ⇒ None ⇒ UNKNOWN, never a panic
        //  - old CLI + new proxy   → serde ignores unknown fields by default
        //  - old CLI + old proxy   → unchanged
        let old_proxy: crate::commands_proxy::PipelineDiagnosticsWire =
            serde_json::from_value(serde_json::json!({"mask_restore": {}}))
                .expect("an old proxy payload must still parse");
        assert!(
            old_proxy.filter_hook.is_none(),
            "an absent block must be None, not a zero-valued 0/0 that renders green"
        );
        // A block with only some fields (a proxy mid-upgrade, or a future one that
        // adds fields) must also parse rather than failing the whole document.
        let partial: crate::commands_proxy::PipelineDiagnosticsWire =
            serde_json::from_value(serde_json::json!({
                "filter_hook": {"status": "ok", "future_field": 42},
                "unknown_top_level": true
            }))
            .expect("unknown and missing fields must both be tolerated");
        let fh = partial.filter_hook.expect("present block must decode");
        assert_eq!(fh.status, "ok");
        assert_eq!(fh.workers_total, 0);
        assert!(fh.workers.is_empty());
        assert_eq!(fh.verdict_cache.status, "");
    }

    #[test]
    fn compliance_missing_pipeline_block_marks_scan_scope_unknown() {
        let packs = healthy_packs();
        let r = compliance_health_report(ComplianceToggle::OnLocal, true, Some(&packs), None);
        assert_eq!(r.severity, ComplianceSeverity::Warn);
        let human = render_human(&compliance_doctor_rows(&r));
        assert!(human.contains("scan scope"), "{human}");
        assert!(human.contains("UNKNOWN"), "{human}");
    }

    // ── Toggle resolution ───────────────────────────────────────────
    #[test]
    fn compliance_toggle_resolution_is_exhaustive_and_mandate_wins() {
        use ComplianceToggle::*;
        // (local filter_stages present, org mandate on) → toggle
        let cases = [
            ((false, false), Off),
            ((true, false), OnLocal),
            // 🔴 Mandate wins even with a NULL local column: the proxy
            // force-spawns the detector, so reporting "off" would describe a
            // host that is in fact filtering every request.
            ((false, true), OnMandated),
            ((true, true), OnMandated),
        ];
        for ((local, org), want) in cases {
            assert_eq!(
                ComplianceToggle::resolve(local, org),
                want,
                "resolve(local={local}, org={org})"
            );
        }
    }

    #[test]
    fn compliance_severity_only_error_fails_the_summary() {
        assert!(ComplianceSeverity::Ok.is_ok_for_summary());
        assert!(
            ComplianceSeverity::Warn.is_ok_for_summary(),
            "a watered-down filter is loud on its own row but must not turn the summary red — \
             same policy as the local-server row"
        );
        assert!(!ComplianceSeverity::Error.is_ok_for_summary());
        assert_eq!(ComplianceSeverity::Ok.as_str(), "ok");
        assert_eq!(ComplianceSeverity::Warn.as_str(), "warn");
        assert_eq!(ComplianceSeverity::Error.as_str(), "error");
    }

    // ── Edition coverage (版型意识) ──────────────────────────────────
    #[test]
    fn compliance_row_is_identical_across_all_four_editions() {
        // 🔴 THE POINT OF THIS TEST. The bug being closed is that the runtime
        // compliance health gate existed ONLY for Cluster. The fix is that the
        // verdict is derived from the LOCAL aikey-proxy — the one binary every
        // edition runs — so it cannot be edition-shaped by construction. This
        // asserts that: identical inputs must produce a byte-identical row on
        // every edition, and every edition must produce a row at all.
        //
        // NOTE on the edition axis: `local_server_probe::Edition` models only
        // what THIS CLI can detect on its own host — Trial, Personal
        // (local-server), and None. A Production or Cluster host presents to
        // `detect_edition()` as one of those same three (see the doc comment on
        // `detect_edition`), which is why the deployment shapes below map onto
        // them rather than onto four enum variants.
        use crate::local_server_probe::Edition;
        let deployment_shapes: [(&str, Option<Edition>); 4] = [
            ("Personal (local-server)", Some(Edition::Personal)),
            ("Trial (full-trial bundle)", Some(Edition::Trial)),
            (
                "Production (server-install; CLI host has no local web service)",
                None,
            ),
            (
                "Cluster (node/operator host; CLI host has no local web service)",
                None,
            ),
        ];
        let packs = healthy_packs();
        let pipeline = healthy_pipeline();
        let mut rendered: Vec<(&str, String)> = Vec::new();
        for (shape, edition) in deployment_shapes {
            // The edition banner must resolve for every shape (no panic, no
            // empty label) — doctor prints it above these rows as context.
            let label = doctor_edition_label(edition);
            assert!(!label.is_empty(), "{shape} has no edition banner");
            let r = compliance_health_report(
                ComplianceToggle::OnLocal,
                true,
                Some(&packs),
                Some(&pipeline),
            );
            let rows = compliance_doctor_rows(&r);
            assert!(
                rows.iter().any(|(l, ..)| l == "compliance"),
                "{shape} produced no compliance row — an edition-shaped diagnostic hole is a bug"
            );
            rendered.push((shape, render_human(&rows)));
        }
        let (first_shape, first) = &rendered[0];
        for (shape, out) in &rendered[1..] {
            assert_eq!(
                out, first,
                "compliance row differs between {first_shape} and {shape} — the verdict must come \
                 from the local proxy, never from an edition branch"
            );
        }
    }

    #[test]
    fn compliance_detector_slug_matches_the_app_registry() {
        // The slug is a cross-process contract (vault app_records.slug, the
        // proxy's filter-binary directory, this CLI's toggle read). Pin it.
        assert!(crate::commands_app::FIRST_PARTY_SLUGS.contains(&COMPLIANCE_DETECTOR_SLUG));
        let plugins = doctor_plugin_registry();
        assert!(
            plugins
                .iter()
                .any(|p| p.install_slug == COMPLIANCE_DETECTOR_SLUG && !p.is_daemon),
            "the compliance health row resolves its binary through this registry entry"
        );
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
