mod storage;
mod crypto;
mod session;
mod executor;
mod synapse;
mod audit;
mod ratelimit;
mod json_output;
mod error_codes;
mod config;
mod env_resolver;
mod env_renderer;
mod commands_project;
// mod commands_env; // removed: env commands dropped
mod commands_proxy;
mod commands_account;
mod migrations;
mod platform_client;
// mod profiles; // removed: profile commands dropped
// mod core; // removed: profile-based resolver dropped
mod global_config;
mod providers;
mod resolver;
mod events;
mod observability;
mod ui_frame;
mod ui_select;
mod proxy_env;
mod profile_activation;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::io::{self, IsTerminal, Write};
use zeroize::Zeroizing;
use error_codes::msgs;

use aikeylabs_aikey_cli::prompt_hidden;

#[derive(Parser)]
#[command(
    name = "aikey",
    about = "AiKey - Secure local-first secret management",
    version = "0.2.0",
    disable_version_flag = true,
    override_usage = "aikey [OPTIONS] [COMMAND]",
    after_long_help = "",
    help_template = "\
{about}

Usage: {usage}

Commands:
  \x1b[1madd\x1b[0m <alias>              Save a new secret to the vault
  \x1b[1mlist\x1b[0m                     Show all personal and team keys
  \x1b[1mtest\x1b[0m <alias>             Test whether a stored API key alias is working
  \x1b[1muse\x1b[0m [alias]              Select the active key for routing (shortcut for `key use`)
  \x1b[1mlogin\x1b[0m                    Log in to aikey service (shortcut for `account login`)
  \x1b[1mbrowse\x1b[0m [page]            Open the User Console in your default browser
  \x1b[1mdoctor\x1b[0m                   Check system health, connectivity, and configuration
  \x1b[1menv\x1b[0m [command]            View or set proxy environment variables
  \x1b[1mproxy\x1b[0m <command>          Manage the local proxy process
  \x1b[1mstatus\x1b[0m                   Show a summary of gateway, login, keys, and providers
  \x1b[1mwhoami\x1b[0m                   Show your current login, active key, and vault status
  \x1b[1mget\x1b[0m <alias>              Retrieve a secret and copy it to the clipboard
  \x1b[1mrun\x1b[0m -- <command>         Run a command with secrets injected as environment variables
  \x1b[1mkey\x1b[0m <command>            Manage API keys (rotate, list, sync, use)
  \x1b[1mquickstart\x1b[0m               Initialize vault and set up a new project
  \x1b[1mproject\x1b[0m <command>        Manage project configuration
  \x1b[1mlogs\x1b[0m                     Show recent activity logs
  \x1b[1mupdate\x1b[0m <alias>           Update an existing secret
  \x1b[1mdelete\x1b[0m <alias>           Delete a secret from the vault
  \x1b[1mexport\x1b[0m <pattern> <file>  Export secrets to an encrypted backup file
  \x1b[1mchange-password\x1b[0m          Change the vault master password
  \x1b[1maccount\x1b[0m <command>        Manage your aikey account session
  \x1b[1mlogout\x1b[0m                   Log out of the current session (shortcut for `account logout`)
  \x1b[1msecret\x1b[0m <command>         Manage secrets and platform-backed secret actions
  \x1b[1mhelp\x1b[0m                     Show this help message or help for a command

Options:
      --password-stdin  Read password from stdin instead of prompting
      --json            Output in JSON format (where supported)
  -V, --version         Print version information
  -h, --help            Print help
      --detail          Print detailed help for all commands"
)]
struct Cli {
    /// Read password from stdin instead of prompting (for automation/testing)
    #[arg(long, global = true)]
    password_stdin: bool,

    /// Output in JSON format (where supported)
    #[arg(long, global = true)]
    json: bool,

    /// Print version information
    #[arg(short = 'V', long)]
    version: bool,

    /// Print detailed help for all commands
    #[arg(long)]
    detail: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the vault (runs automatically on first use)
    #[command(hide = true)]
    Init,
    /// Internal: database rollback for upgrade recovery (not shown in help)
    #[command(hide = true)]
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
    /// Save a new secret to the vault
    #[command(display_order = 1)]
    Add {
        alias: String,
        /// Provider code for proxy routing (e.g. openai, anthropic). Makes this
        /// key selectable via `aikey use` with path-prefix routing in the proxy.
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
    },
    /// Show all personal and team keys
    #[command(alias = "ls", display_order = 2)]
    List,
    /// Test whether a stored API key alias is working
    #[command(display_order = 3)]
    Test {
        /// Alias of the key to test (omit to test all current Primary keys)
        alias: Option<String>,
        /// Provider code to test against (overrides stored provider)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
    },
    /// Select the active key for routing (shortcut for `key use`)
    #[command(display_order = 4)]
    Use {
        /// Virtual key alias or ID to activate (omit for interactive picker)
        alias_or_id: Option<String>,
        /// Skip installing the shell precmd hook into ~/.zshrc / ~/.bashrc
        #[arg(long)]
        no_hook: bool,
        /// Narrow to a specific provider (e.g. --provider anthropic).
        /// When given without a value, shows an interactive menu to select one.
        /// Without this flag, all default providers are injected (generic gateway mode).
        #[arg(long, value_name = "PROVIDER", num_args = 0..=1, default_missing_value = "")]
        provider: Option<String>,
    },
    /// Log in to aikey service (shortcut for `account login`)
    #[command(display_order = 5)]
    Login {
        /// Control Panel URL (e.g. http://192.168.1.100:3000)
        #[arg(long = "control-url", alias = "url")]
        url: Option<String>,
        /// One-time login token for copy-paste fallback: SESSION_ID:LOGIN_TOKEN
        #[arg(long)]
        token: Option<String>,
        /// Pre-fill email on the browser login page (skips manual entry)
        #[arg(long)]
        email: Option<String>,
    },
    /// Open the User Console in your default browser
    #[command(display_order = 6)]
    Browse {
        /// Page to open: overview (default), keys, account, usage
        page: Option<String>,
        /// Override port for dev mode (e.g. --port 3000 for Vite dev server)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Check system health, connectivity, and configuration
    #[command(display_order = 7)]
    Doctor,
    /// View or set proxy environment variables
    #[command(display_order = 8)]
    Env {
        #[command(subcommand)]
        action: Option<EnvAction>,
    },
    /// Manage the local proxy process
    #[command(display_order = 9)]
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Show a summary of gateway, login, keys, and providers
    #[command(display_order = 9)]
    Status,
    /// Show your current login, active key, and vault status
    #[command(display_order = 9)]
    Whoami,
    /// Retrieve a secret and copy it to the clipboard
    #[command(display_order = 10)]
    Get {
        alias: String,
        /// Clipboard auto-clear timeout in seconds (default: 30, 0 to disable)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
    /// Run a command with secrets injected as environment variables
    #[command(display_order = 11)]
    Run {
        /// Resolve a specific provider's key and inject it (e.g. openai, anthropic)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,

        /// Logical model name for narrowing injection (e.g. chat-main, embeddings)
        #[arg(long, value_name = "LOGICAL_MODEL")]
        logical_model: Option<String>,

        /// Model hint passed through to the process (sets AIKEY_MODEL env var)
        #[arg(long, value_name = "MODEL")]
        model: Option<String>,

        /// Tenant override for multi-tenant key resolution
        #[arg(long, value_name = "TENANT")]
        tenant: Option<String>,

        /// Override the active profile for this invocation (e.g. personal, work)
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,

        /// Show what would be resolved without executing the command
        #[arg(long)]
        dry_run: bool,

        /// Bypass the proxy: decrypt the real key from the vault and inject it directly
        /// into the child process environment, overriding any proxy env vars inherited
        /// from the shell. Only valid for personal keys. Useful for verifying that a
        /// direct connection to the real provider/gateway works.
        #[arg(long)]
        direct: bool,

        /// The command to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Manage API keys (rotate, list, sync, use)
    #[command(display_order = 12)]
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Initialize vault and set up a new project
    #[command(display_order = 13)]
    Quickstart,
    /// Manage project configuration
    #[command(display_order = 14)]
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Show recent activity logs
    #[command(display_order = 15)]
    Logs {
        /// Number of entries to show (default: 20)
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },
    /// Update an existing secret
    #[command(display_order = 16)]
    Update {
        alias: String,
    },
    /// Delete a secret from the vault
    #[command(display_order = 17)]
    Delete {
        alias: String,
    },
    /// Export secrets to an encrypted backup file
    #[command(display_order = 18)]
    Export {
        /// Pattern to match secrets (e.g., "*", "api_*")
        pattern: String,
        /// Output file path (.akb format)
        output: String,
    },
    /// Change the vault master password
    #[command(display_order = 19)]
    ChangePassword,
    /// Manage your aikey account session
    #[command(display_order = 20)]
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Log out of the current session (shortcut for `account logout`)
    #[command(display_order = 21)]
    Logout,
    /// Manage secrets and platform-backed secret actions
    #[command(display_order = 22)]
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
}

#[derive(Subcommand)]
enum DbAction {
    /// Apply pending schema upgrades for the current version
    Upgrade,
    /// Rollback database schema to a previous version
    Rollback {
        /// Target version to roll back to (e.g. v1.0.1-alpha)
        #[arg(long)]
        to: String,
    },
}

#[derive(Subcommand)]
enum EnvAction {
    /// Set proxy environment variables (written to ~/.aikey/proxy.env)
    Set {
        /// KEY=VALUE pairs (after --)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Start the local aikey-proxy (authenticates once, no separate password needed)
    Start {
        /// Path to aikey-proxy.yaml (auto-detected if omitted)
        #[arg(long)]
        config: Option<String>,
        /// Run in foreground (default: start in background and return immediately)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the running aikey-proxy
    Stop,
    /// Show aikey-proxy status and health
    Status,
    /// Restart aikey-proxy (stop + start in background)
    Restart {
        /// Path to aikey-proxy.yaml (auto-detected if omitted)
        #[arg(long)]
        config: Option<String>,
    },
    /// Verify current project/env/provider connectivity through the proxy
    Verify,
}

#[derive(Subcommand)]
enum KeyAction {
    /// Rotate a local secret to a new value
    Rotate {
        /// Secret name/alias to rotate
        name: String,
        /// Read new value from stdin instead of interactive prompt
        #[arg(long)]
        from_stdin: bool,
    },
    /// List all team-managed virtual keys (fetches from server if logged in)
    List,
    /// Sync all team key metadata from the control service
    Sync,
    /// Activate a key for proxy routing and write ~/.aikey/active.env
    Use {
        /// Virtual key alias or ID to activate
        alias_or_id: String,
        /// Skip installing the shell precmd hook into ~/.zshrc / ~/.bashrc
        #[arg(long)]
        no_hook: bool,
    },
    /// Set a local display name for a team key (does not affect server alias)
    Alias {
        /// Current alias or virtual key ID
        old_alias: String,
        /// New local display name
        new_alias: String,
    },
}

#[derive(Subcommand)]
enum AccountAction {
    /// Log in to an aikey-control-service instance via browser + email activation (OAuth device flow)
    Login {
        /// Control Panel URL (e.g. http://192.168.1.100:3000)
        #[arg(long = "control-url", alias = "url")]
        url: Option<String>,
        /// One-time login token for copy-paste fallback: SESSION_ID:LOGIN_TOKEN
        /// (shown on the activation page when the browser flow does not complete)
        #[arg(long)]
        token: Option<String>,
        /// Pre-fill email on the browser login page (skips manual entry)
        #[arg(long)]
        email: Option<String>,
    },
    /// Show current login status
    Status,
    /// Log out (removes stored JWT)
    Logout,
    /// Update the control panel URL without re-logging in
    #[command(name = "set-url")]
    SetUrl {
        /// New control panel URL (e.g. http://192.168.1.100:3000)
        url: String,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Set a secret value (reads from stdin for security)
    Set {
        /// Secret name/alias
        name: String,
        /// Provider code for proxy routing (e.g. openai, anthropic)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// Read secret value from stdin
        #[arg(long)]
        from_stdin: bool,
    },
    /// Upsert a secret value (reads from stdin for security)
    Upsert {
        /// Secret name/alias
        name: String,
        /// Provider code for proxy routing (e.g. openai, anthropic)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// Read secret value from stdin
        #[arg(long)]
        from_stdin: bool,
    },
    /// List all secrets (metadata only)
    List,
    /// Delete a secret
    Delete {
        /// Secret name/alias
        name: String,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Initialize a new project configuration
    Init,
    /// Show project configuration status
    Status,
    /// Map a required variable to a vault alias in the project config
    Map {
        /// Environment variable name (e.g. OPENAI_API_KEY)
        var: String,
        /// Vault alias to bind it to (e.g. openai-work)
        alias: String,
        /// Logical environment name for envMappings (e.g. dev, prod)
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Provider name for envMappings entry (e.g. openai)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// Concrete model ID for envMappings entry (e.g. gpt-4o-mini)
        #[arg(long, value_name = "MODEL")]
        model: Option<String>,
        /// Vault key alias for envMappings entry (overrides positional alias for envMappings)
        #[arg(long = "key-alias", value_name = "ALIAS")]
        key_alias: Option<String>,
        /// Provider-specific model implementation ID (e.g. gpt-4o-mini)
        #[arg(long, value_name = "IMPL")]
        impl_id: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise process-global trace context (trace_id, span_id, command_id).
    // This must be called before any logging or proxy calls.
    observability::init_trace();

    let cli = Cli::try_parse().unwrap_or_else(|err| {
        // Intercept "unrecognized subcommand" errors and show a friendly message
        // with fuzzy suggestions instead of the raw clap output.
        use clap::error::ErrorKind;

        // Intercept top-level --help / -h: use our styled version.
        // Subcommand help (e.g. `aikey add --help`) still uses clap's default.
        if matches!(err.kind(), ErrorKind::DisplayHelp) {
            // Check if this is the top-level help (no subcommand context).
            // Clap's rendered help for subcommands contains "Usage: aikey <subcmd>",
            // while top-level contains "Usage: aikey [OPTIONS]".
            let rendered = err.to_string();
            if rendered.contains("aikey [OPTIONS]") {
                print_short_help();
                std::process::exit(0);
            }
            // Subcommand help — print clap's output, then append detailed notes.
            // Extract command path from "Usage: aikey <cmd> ..." line.
            let cmd_path = rendered.lines()
                .find(|l| l.starts_with("Usage: aikey "))
                .and_then(|l| {
                    // "Usage: aikey add [OPTIONS] <ALIAS>" → extract "add"
                    // "Usage: aikey proxy start [OPTIONS]" → extract "proxy start"
                    let after = l.strip_prefix("Usage: aikey ")?;
                    let parts: Vec<&str> = after.split_whitespace()
                        .take_while(|w| !w.starts_with('[') && !w.starts_with('<') && !w.starts_with('-'))
                        .collect();
                    if parts.is_empty() { None } else { Some(parts.join(" ")) }
                });

            // Print clap's rendered help first.
            eprint!("{}", rendered);

            // Append detailed notes if available.
            if let Some(ref cmd) = cmd_path {
                if let Some(notes) = command_detail_notes(cmd) {
                    eprintln!();
                    eprintln!("{}", notes);
                }
            }
            std::process::exit(0);
        }

        if matches!(err.kind(), ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument) {
            // Extract the bad token from the error message (clap embeds it in single quotes).
            let bad = err.to_string();
            let token = bad
                .split('\'')
                .nth(1)
                .unwrap_or("?")
                .to_string();

            // All top-level subcommand names for fuzzy matching.
            const KNOWN: &[&str] = &[
                "add", "get", "delete", "list", "update", "test", "export",
                "run", "use", "whoami", "login", "logout", "browse",
                "init", "doctor", "env", "key", "account", "secret",
                "project", "proxy",
                "change-password", "quickstart", "logs",
            ];

            let suggestion = KNOWN.iter()
                .filter_map(|s| {
                    let score = similarity(&token.to_lowercase(), s);
                    if score >= 0.5 { Some((*s, score)) } else { None }
                })
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            eprintln!("error: unrecognized command '{}'", token);
            if let Some((hint, _)) = suggestion {
                eprintln!();
                eprintln!("  Did you mean '{}'?  Try: aikey {} --help", hint, hint);
            }
            eprintln!();
            eprintln!("  Run 'aikey --help' for a list of all commands.");
            std::process::exit(2);
        }
        // All other clap errors (missing required args, bad values, etc.) — print as-is.
        err.exit()
    });

    // Handle --version flag
    if cli.version {
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        if cli.json {
            json_output::success(serde_json::json!({
                "version": VERSION
            }));
        } else {
            print_banner();
        }
        return Ok(());
    }

    // Handle --detail flag
    if cli.detail {
        print_detailed_help();
        return Ok(());
    }

    // Ensure a command was provided
    if cli.command.is_none() {
        if cli.json {
            json_output::error("No command specified. Use --help for usage information.", 1);
        } else {
            print_banner();
            eprintln!();
            eprintln!("  Run 'aikey --help' for a list of commands.");
            std::process::exit(1);
        }
    }

    // Determine command name for structured log fields (best-effort, no secrets).
    let cmd_name = command_name(cli.command.as_ref());

    observability::log_event(
        observability::EVENT_CLI_COMMAND_STARTED,
        &format!("command started: {}", cmd_name),
    );

    let start = std::time::Instant::now();

    // Execute command and log outcome.
    match run_command(&cli) {
        Ok(()) => {
            let duration_ms = start.elapsed().as_millis() as i64;
            let mut extra = std::collections::BTreeMap::new();
            extra.insert("duration_ms", serde_json::Value::from(duration_ms));
            extra.insert("command", serde_json::Value::from(cmd_name.clone()));
            observability::write_log(
                observability::Level::Info,
                &format!("command completed: {}", cmd_name),
                Some(observability::EVENT_CLI_COMMAND_COMPLETED),
                None,
                None,
                extra,
            );
        }
        Err(e) => {
            let duration_ms = start.elapsed().as_millis() as i64;
            use std::collections::BTreeMap;
            let mut extra = BTreeMap::new();
            extra.insert("duration_ms", serde_json::Value::from(duration_ms));
            extra.insert("command", serde_json::Value::from(cmd_name.clone()));
            observability::write_log(
                observability::Level::Error,
                &format!("command failed: {}", cmd_name),
                Some(observability::EVENT_CLI_COMMAND_FAILED),
                None,
                Some(&e.to_string()),
                extra,
            );
            // If vault authentication failed, the session cache may hold a stale password.
            // Auto-invalidate so the next command prompts fresh instead of silently
            // reusing the wrong password and triggering the rate-limiter again.
            let err_str = e.to_string();
            let is_auth_error = err_str.contains("Invalid master password")
                || err_str.contains("vault authentication failed");
            if is_auth_error {
                session::invalidate();
            }
            if cli.json {
                json_output::error(&err_str, 1);
            } else {
                eprintln!("Error: {}", e);
                if is_auth_error {
                    eprintln!("  Hint: Session cache cleared — next command will prompt for your password.");
                }
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Returns a stable command name string suitable for log fields.
/// Never includes secret values or passwords.
fn command_name(cmd: Option<&Commands>) -> String {
    match cmd {
        None => "unknown".to_string(),
        Some(c) => match c {
            Commands::Init => "init".to_string(),
            Commands::Db { action } => format!("db.{}", match action {
                DbAction::Upgrade => "upgrade",
                DbAction::Rollback { .. } => "rollback",
            }),
            Commands::Add { .. } => "add".to_string(),
            Commands::Get { .. } => "get".to_string(),
            Commands::Delete { .. } => "delete".to_string(),
            Commands::List => "list".to_string(),
            Commands::Update { .. } => "update".to_string(),
            Commands::Test { .. } => "test".to_string(),
            Commands::Export { .. } => "export".to_string(),
            Commands::Run { .. } => "run".to_string(),
            Commands::ChangePassword => "change-password".to_string(),
            Commands::Secret { action } => format!("secret.{}", match action {
                SecretAction::Set { .. } => "set",
                SecretAction::Upsert { .. } => "upsert",
                SecretAction::List => "list",
                SecretAction::Delete { .. } => "delete",
            }),
            Commands::Project { action } => format!("project.{}", match action {
                ProjectAction::Init => "init",
                ProjectAction::Status => "status",
                ProjectAction::Map { .. } => "map",
            }),
            Commands::Quickstart => "quickstart".to_string(),
            Commands::Logs { .. } => "logs".to_string(),
            Commands::Key { action } => format!("key.{}", match action {
                KeyAction::Rotate { .. } => "rotate",
                KeyAction::List => "list",
                KeyAction::Sync => "sync",
                KeyAction::Use { .. } => "use",
                KeyAction::Alias { .. } => "alias",
            }),
            Commands::Use { .. } => "key.use".to_string(),
            Commands::Status => "status".to_string(),
            Commands::Whoami => "whoami".to_string(),
            Commands::Account { action } => format!("account.{}", match action {
                AccountAction::Login { .. } => "login",
                AccountAction::Status => "status",
                AccountAction::Logout => "logout",
                AccountAction::SetUrl { .. } => "set-url",
            }),
            Commands::Login { .. } => "account.login".to_string(),
            Commands::Logout => "account.logout".to_string(),
            Commands::Env { .. } => "env".to_string(),
            Commands::Browse { .. } => "browse".to_string(),
            Commands::Doctor => "doctor".to_string(),
            Commands::Proxy { action } => format!("proxy.{}", match action {
                ProxyAction::Start { .. } => "start",
                ProxyAction::Stop => "stop",
                ProxyAction::Status => "status",
                ProxyAction::Restart { .. } => "restart",
                ProxyAction::Verify => "verify",
            }),
        },
    }
}

/// Handle `aikey stats` command
fn handle_stats(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Count project configs
    let mut project_count = 0;
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.starts_with("aikey.config.")) {
                project_count += 1;
            }
        }
    }

    // Count profiles from global config
    let mut profile_count = 0;
    if let Ok(config_file) = crate::global_config::config_path() {
        if config_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&config_file) {
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(profiles) = config.get("profiles").and_then(|v| v.as_array()) {
                        profile_count = profiles.len();
                    }
                }
            }
        }
    }

    // Check if vault exists
    let vault_exists = if let Ok(vault_path) = crate::storage::get_vault_path() {
        vault_path.exists()
    } else {
        false
    };

    if json_mode {
        let response = serde_json::json!({
            "ok": true,
            "projects": project_count,
            "profiles": profile_count,
            "vault_initialized": vault_exists
        });
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("AiKey Local Statistics");
        println!("======================");
        println!("Projects (current dir): {}", project_count);
        println!("Profiles: {}", profile_count);
        println!("Vault: {}", if vault_exists { "initialized" } else { "not initialized" });
        println!("\nNote: These statistics are local-only and do not involve any remote calls.");
    }

    Ok(())
}

fn run_command(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let command = cli.command.as_ref().unwrap();

    // Auto-start proxy silently when AIKEY_MASTER_PASSWORD (or AK_TEST_PASSWORD)
    // is available in the environment.  Skipped for proxy lifecycle commands which
    // manage the process themselves, and for version/init which predate the proxy.
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } => {}
        _ => { commands_proxy::try_auto_start_from_env(); }
    }

    // Non-blocking snapshot sync: checks server sync_version and pulls fresh
    // key state if it has changed since the last local pull. Skipped for proxy
    // lifecycle and init commands which either predate the vault or manage the
    // process themselves.
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } => {}
        _ => { commands_account::try_background_snapshot_sync(); }
    }

    match command {
        Commands::Init => {
            let password = prompt_password_secure("\u{1F512} Set Master Password: ", cli.password_stdin, cli.json)?;
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;

            if !cli.json {
                println!("Initializing vault...");
            }

            let result = storage::initialize_vault(&salt, &password);
            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            audit::initialize_audit_log()?;
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Init, None, true);

            if cli.json {
                json_output::success(serde_json::json!({
                    "message": "Vault initialized successfully"
                }));
            } else {
                println!("Vault initialized successfully!");
            }
        }
        // Internal: database upgrade/rollback for schema management.
        // Why hidden: operational tool for install scripts and rollback automation,
        // not for end-user daily use. rollback.sh calls `aikey db rollback --to <ver>`
        // using the CURRENT binary BEFORE restoring the old binary from backup.
        Commands::Db { action } => {
            match action {
                DbAction::Upgrade => {
                    eprintln!("[db upgrade] Applying pending vault schema upgrades...");
                    let vault_path = storage::get_vault_path()
                        .map_err(|e| format!("Failed to resolve vault path: {}", e))?;
                    if !vault_path.exists() {
                        eprintln!("[db upgrade] No vault.db found — nothing to upgrade");
                        return Ok(());
                    }
                    let conn = rusqlite::Connection::open(&vault_path)
                        .map_err(|e| format!("Failed to open vault: {}", e))?;
                    migrations::upgrade_all(&conn)?;
                    eprintln!("[db upgrade] Done");
                }
                DbAction::Rollback { to } => {
                    eprintln!("[db rollback] Rolling back vault schema to {}", to);
                    let vault_path = storage::get_vault_path()
                        .map_err(|e| format!("Failed to resolve vault path: {}", e))?;
                    if !vault_path.exists() {
                        eprintln!("[db rollback] No vault.db found — nothing to rollback");
                        return Ok(());
                    }
                    let conn = rusqlite::Connection::open(&vault_path)
                        .map_err(|e| format!("Failed to open vault: {}", e))?;
                    migrations::rollback_to(&conn, &to)?;
                    eprintln!("[db rollback] Vault schema rolled back to {}", to);
                }
            }
        }
        Commands::Add { alias, provider } => {
            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Early password validation: fail fast before asking for API key,
            // providers, base URL, etc. Skip for first-time vault init.
            // Why: without this, users enter wrong password and go through the entire
            // interactive flow only to fail at the final write step.
            if storage::get_salt().is_ok() {
                if let Err(e) = executor::verify_vault_password(&password) {
                    if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
                }
            }

            // Step 2: read secret value (from env, hidden TTY prompt, or stdin).
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else if std::io::stdin().is_terminal() {
                let val = prompt_hidden("\u{1F511} Enter API Key: ")
                    .map_err(|e| format!("Failed to read API Key value: {}", e))?;
                Zeroizing::new(val)
            } else {
                // Non-TTY (pipe / automation): read from stdin directly — no flag needed.
                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            // Step 3: resolve providers + base_url.
            // v1.0.2: multi-provider selection with checkbox TUI.
            const KNOWN_PROVIDERS: &[(&str, &str)] = &[
                ("anthropic", "https://api.anthropic.com"),
                ("openai",    "https://api.openai.com/v1"),
                ("google",    "https://generativelanguage.googleapis.com"),
                ("deepseek",  "https://api.deepseek.com/v1"),
                ("kimi",      "https://api.moonshot.cn/v1"),
            ];

            let (resolved_providers, resolved_base_url): (Vec<String>, Option<String>) =
                if let Some(code) = provider {
                    (vec![code.to_lowercase()], None)
                } else if std::io::stdin().is_terminal() && !cli.json {
                    use colored::Colorize;
                    let mut items: Vec<String> = KNOWN_PROVIDERS.iter().map(|(n, _)| n.to_string()).collect();
                    items.push("Custom providers...".to_string());
                    let custom_idx = KNOWN_PROVIDERS.len();
                    let mut selected: Vec<String>;
                    let mut checked_state: Vec<bool> = vec![false; items.len()];

                    loop {
                        let selected_indices = match ui_select::box_multi_select("Select provider(s)", &items, &checked_state)? {
                            ui_select::MultiSelectResult::Confirmed(idx) => idx,
                            ui_select::MultiSelectResult::Cancelled => { eprintln!("  Cancelled."); return Ok(()); }
                        };
                        checked_state = vec![false; items.len()];
                        for &i in &selected_indices { if i < checked_state.len() { checked_state[i] = true; } }
                        selected = Vec::new();
                        let mut wants_custom = false;
                        for &idx in &selected_indices {
                            if idx < KNOWN_PROVIDERS.len() {
                                let name = KNOWN_PROVIDERS[idx].0.to_string();
                                if !selected.contains(&name) { selected.push(name); }
                            } else if idx == custom_idx { wants_custom = true; }
                        }
                        if wants_custom {
                            print!("  Custom provider(s), comma-separated: ");
                            io::stdout().flush()?;
                            let mut custom = String::new();
                            io::stdin().read_line(&mut custom)?;
                            for code in custom.split(',').map(|s| s.trim().to_lowercase()) {
                                if !code.is_empty() && !selected.contains(&code) { selected.push(code); }
                            }
                        }
                        if !selected.is_empty() { break; }
                        use colored::Colorize;
                        eprintln!("  {} At least one provider is required.\n", "\u{26A0}".yellow());
                    }

                    print!("  Base URL (press Enter for provider defaults): ");
                    io::stdout().flush()?;
                    let mut url_input = String::new();
                    io::stdin().read_line(&mut url_input)?;
                    let url_input = url_input.trim().to_string();
                    let base_url = if url_input.is_empty() { None } else { Some(url_input) };

                    eprintln!("  Providers: {}", selected.join(", ").bold());
                    if let Some(ref u) = base_url { eprintln!("  Base URL:  {}", u.dimmed()); }
                    (selected, base_url)
                } else {
                    return Err("--provider is required in non-interactive mode.".into());
                };

            let resolved_provider = resolved_providers.first().cloned();

            // Step 4: connectivity test.
            if !cli.json && std::io::stdin().is_terminal() && env::var("AK_TEST_SECRET").is_err() {
                let test_targets: Vec<(String, String)> = resolved_providers.iter().map(|code| {
                    let url = resolved_base_url.as_deref()
                        .or_else(|| commands_project::default_base_url(code))
                        .unwrap_or("https://unknown").to_string();
                    (code.clone(), url)
                }).collect();
                if !test_targets.is_empty() {
                    eprintln!();
                    let suite = commands_project::run_connectivity_test(&test_targets, secret.trim(), false);
                    if !suite.any_chat_ok {
                        eprintln!();
                        eprint!("  No chat test passed. Add anyway? [y/N]: ");
                        io::stdout().flush()?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                            eprintln!("  Cancelled."); return Ok(());
                        }
                    }
                    eprintln!();
                }
            }

            // Step 5: write to vault.
            let result = executor::add_secret(alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(alias), result.is_ok());
            if let Err(e) = result {
                if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
            }

            // Persist provider metadata.
            let _ = storage::set_entry_supported_providers(alias, &resolved_providers);
            if let Some(ref code) = resolved_provider {
                let _ = storage::set_entry_provider_code(alias, Some(code.as_str()));
            }
            if let Some(ref url) = resolved_base_url {
                let _ = storage::set_entry_base_url(alias, Some(url.as_str()));
            }

            // Auto-assign as Primary + refresh active.env.
            let newly_primary = profile_activation::auto_assign_primaries_for_key(
                "personal", alias, &resolved_providers,
            ).unwrap_or_default();
            if !newly_primary.is_empty() || !resolved_providers.is_empty() {
                let _ = profile_activation::refresh_implicit_profile_activation();
            }

            // Auto-configure third-party CLI tools when relevant providers are added.
            if !cli.json {
                let proxy_port = commands_proxy::proxy_port();
                let has_openai = resolved_providers.iter().any(|p| {
                    let c = p.to_lowercase();
                    c == "openai" || c == "gpt" || c == "chatgpt"
                });
                if has_openai {
                    commands_account::configure_codex_cli(proxy_port);
                }

                let has_kimi = resolved_providers.iter().any(|p| {
                    let c = p.to_lowercase();
                    c == "kimi" || c == "moonshot"
                });
                if has_kimi {
                    let token_value = format!("aikey_personal_{}", alias);
                    commands_account::configure_kimi_cli(&token_value, proxy_port);
                }
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "Added key and refreshed current default activation.",
                    "providers": resolved_providers,
                    "primary_for": newly_primary,
                    "base_url": resolved_base_url,
                }));
            } else {
                use colored::Colorize;
                eprintln!("{} API Key '{}' added.", "\u{2713}".green(), alias.bold());
                eprintln!("  providers: {}", resolved_providers.join(", ").dimmed());
                if let Some(ref url) = resolved_base_url { eprintln!("  base_url:  {}", url.dimmed()); }
                if !newly_primary.is_empty() {
                    eprintln!("  {} Primary for: {}", "\u{2B50}".yellow(), newly_primary.join(", ").bold());
                }
                eprintln!("  Added key and refreshed current default activation.");
                commands_proxy::maybe_warn_stale();
            }
        }
        Commands::Get { alias, timeout } => {
            let password = prompt_vault_password(cli.password_stdin, cli.json)?;
            let result = executor::get_secret(alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Get, Some(alias), result.is_ok());

            let secret = match result {
                Ok(s) => s,
                Err(e) => {
                    if cli.json {
                        json_output::error(&e, 1);
                    } else {
                        return Err(e.into());
                    }
                }
            };

            if cli.json {
                // JSON output: return the secret value directly for testing
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "value": secret.as_str()
                }));
            } else {
                // Check if clipboard should be disabled (for testing)
                if std::env::var("AK_NO_CLIPBOARD").is_ok() {
                    println!("{}", secret.as_str());
                } else {
                    // Copy to clipboard
                    executor::copy_to_clipboard(&secret)?;
                    println!("Secret copied to clipboard.");

                    // Auto-clear clipboard after timeout (if enabled)
                    if *timeout > 0 {
                        println!("Clipboard will be cleared in {} seconds...", timeout);
                        executor::schedule_clipboard_clear(*timeout);
                    }
                }
            }
        }
        Commands::Delete { alias } => {
            // Confirm before deletion (skip in JSON / non-interactive mode).
            if !cli.json && std::io::stdin().is_terminal() {
                use colored::Colorize;
                eprint!("  Delete API Key '{}'? This cannot be undone. [y/N]: ", alias.bold());
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                    eprintln!("  Cancelled.");
                    return Ok(());
                }
            }

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;
            let result = executor::delete_secret(alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(alias), result.is_ok());

            if let Err(e) = result {
                if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
            }

            // Reconcile provider bindings after removal.
            let actions = profile_activation::reconcile_provider_primary_after_key_removal(
                "personal", alias,
            ).unwrap_or_default();
            if !actions.is_empty() {
                let _ = profile_activation::refresh_implicit_profile_activation();
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "API Key deleted successfully"
                }));
            } else {
                use colored::Colorize;
                eprintln!("  {} API Key '{}' deleted.", "\u{2713}".green(), alias);
                for action in &actions {
                    match &action.outcome {
                        profile_activation::ReconcileOutcome::Replaced { new_source_ref, .. } => {
                            eprintln!("  {} '{}' promoted to Primary for {}",
                                "\u{2B50}".yellow(), new_source_ref.bold(), action.provider_code);
                        }
                        profile_activation::ReconcileOutcome::Cleared => {
                            eprintln!("  {} No replacement for {} — provider has no Primary",
                                "\u{26A0}".yellow(), action.provider_code);
                        }
                    }
                }
                commands_proxy::maybe_warn_stale();
            }
        }
        Commands::List => {
            // Version-gated sync: only prompt for Master Password when the
            // server has changes (new keys, status updates, etc.).
            // No password needed when version is unchanged (most common case).
            match commands_account::check_sync_version_changed() {
                Ok(true) => {
                    // Server has new data — need password for full sync (claim + encrypt).
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    let _ = commands_account::run_full_snapshot_sync(&password);
                }
                Ok(false) => {
                    // Already up-to-date — no sync needed, no password.
                }
                Err(_) => {
                    // Server unreachable (timeout / network error) — skip sync,
                    // show local cache as-is.
                }
            }

            // Only active keys are shown; revoked / recycled / expired keys
            // are hidden so the output reflects currently usable keys only.
            let managed: Vec<_> = storage::list_virtual_key_cache()
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.key_status == "active")
                .collect();

            let entries = storage::list_entries_with_metadata().unwrap_or_default();

            if cli.json {
                json_output::success(serde_json::json!({
                    "secrets": entries,
                    "managed_keys": managed.iter().map(|e| serde_json::json!({
                        "virtual_key_id": e.virtual_key_id,
                        "alias":          e.alias,
                        "provider_code":  e.provider_code,
                        "key_status":     e.key_status,
                        "share_status":   e.share_status,
                        "local_state":    e.local_state,
                        "has_key":        e.provider_key_ciphertext.is_some(),
                    })).collect::<Vec<_>>(),
                }));
            } else {
                use colored::Colorize;

                let bindings = storage::list_provider_bindings(
                    profile_activation::DEFAULT_PROFILE
                ).unwrap_or_default();

                // Collect row data for auto-width calculation.
                struct RowData { alias: String, providers: String, primary_for: String, has_primary: bool, key: String, status: String, created: String, suffix: String }
                let mut personal_rows: Vec<RowData> = Vec::new();
                let mut team_rows: Vec<RowData> = Vec::new();

                for entry in &entries {
                    let providers = if let Some(ref sp) = entry.supported_providers {
                        if !sp.is_empty() { sp.join(",") } else { entry.provider_code.clone().unwrap_or_default() }
                    } else { entry.provider_code.clone().unwrap_or_default() };
                    let pf: Vec<&str> = bindings.iter()
                        .filter(|b| b.key_source_type == "personal" && b.key_source_ref == entry.alias)
                        .map(|b| b.provider_code.as_str()).collect();
                    personal_rows.push(RowData {
                        alias: entry.alias.clone(), providers,
                        primary_for: pf.join(","), has_primary: !pf.is_empty(),
                        key: "\u{2713}".to_string(), status: String::new(),
                        created: entry.created_at.map(|ts| format_date(ts)).unwrap_or_default(),
                        suffix: String::new(),
                    });
                }
                for e in &managed {
                    let display = e.local_alias.as_deref().unwrap_or(e.alias.as_str()).to_string();
                    let pf: Vec<&str> = bindings.iter()
                        .filter(|b| b.key_source_type == "team" && b.key_source_ref == e.virtual_key_id)
                        .map(|b| b.provider_code.as_str()).collect();
                    let status = match e.local_state.as_str() {
                        "active" | "synced_inactive" => e.key_status.clone(),
                        "disabled_by_account_scope" => "other-account".to_string(),
                        "disabled_by_key_status" => "key-disabled".to_string(),
                        other => other.to_string(),
                    };
                    let suffix = if e.local_alias.is_some() { format!(" (\u{2190} {})", e.alias) } else { String::new() };
                    team_rows.push(RowData {
                        alias: display, providers: e.provider_code.clone(),
                        primary_for: pf.join(","), has_primary: !pf.is_empty(),
                        key: if e.provider_key_ciphertext.is_some() { "\u{2713}".to_string() } else { String::new() },
                        status, created: format_date(e.synced_at), suffix,
                    });
                }

                let all_data: Vec<&RowData> = personal_rows.iter().chain(team_rows.iter()).collect();
                let headers = ["ALIAS", "PROVIDERS", "PRIMARY FOR", "KEY", "STATUS", "CREATED"];
                let pad = 2;
                let w_alias   = headers[0].len().max(all_data.iter().map(|r| r.alias.len()).max().unwrap_or(0)) + pad;
                let w_prov    = headers[1].len().max(all_data.iter().map(|r| r.providers.len()).max().unwrap_or(0)) + pad;
                let w_primary = headers[2].len().max(all_data.iter().map(|r| r.primary_for.len()).max().unwrap_or(0)) + pad;
                let w_key     = headers[3].len().max(1) + pad;
                let w_status  = headers[4].len().max(all_data.iter().map(|r| r.status.len()).max().unwrap_or(0)) + pad;

                let fmt_row = |r: &RowData| -> String {
                    let pf_padded = format!("{:<w$}", r.primary_for, w = w_primary);
                    let pf_col = if r.has_primary { pf_padded.green().to_string() } else { pf_padded };
                    let created_col = format!("\x1b[90m{}\x1b[0m", r.created);
                    let prov_display = if r.providers.len() > w_prov {
                        format!("{}...", &r.providers[..w_prov - 3])
                    } else { r.providers.clone() };
                    format!("{:<wa$}  {:<wp$}  {}  {:<wk$}  {:<ws$}  {}{}",
                        r.alias, prov_display, pf_col, r.key, r.status, created_col, r.suffix,
                        wa = w_alias, wp = w_prov, wk = w_key, ws = w_status)
                };
                let sep_width = w_alias + 2 + w_prov + 2 + w_primary + 2 + w_key + 2 + w_status + 2 + 10;

                let mut rows: Vec<String> = Vec::new();
                rows.push(format!("\u{1FAAA} Personal Keys ({})", entries.len()));
                rows.push(format!("{:<wa$}  {:<wp$}  {:<wf$}  {:<wk$}  {:<ws$}  {}",
                    headers[0], headers[1], headers[2], headers[3], headers[4], headers[5],
                    wa = w_alias, wp = w_prov, wf = w_primary, wk = w_key, ws = w_status));
                rows.push("\u{2500}".repeat(sep_width));
                if personal_rows.is_empty() { rows.push("(none)".to_string()); }
                else { for r in &personal_rows { rows.push(fmt_row(r)); } }

                rows.push(String::new());
                rows.push(format!("\u{1F465} Team Keys ({})", managed.len()));
                rows.push("\u{2500}".repeat(sep_width));
                if team_rows.is_empty() { rows.push("(none)".to_string()); }
                else { for r in &team_rows { rows.push(fmt_row(r)); } }

                ui_frame::print_box("\u{1F511}", "Keys", &rows);
            }

            // Post-operation: warn if proxy is unreachable (e.g. after kill -9).
            commands_proxy::warn_if_proxy_down();
        }
        Commands::Update { alias } => {
            // Confirm before update (skip in JSON / non-interactive / test mode).
            if !cli.json && std::io::stdin().is_terminal() && env::var("AK_TEST_SECRET").is_err() {
                use colored::Colorize;
                eprint!("  Update API Key '{}'? The old value will be overwritten. [y/N]: ", alias.bold());
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                    eprintln!("  Cancelled.");
                    return Ok(());
                }
            }

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Early password validation — same reason as `add`.
            if storage::get_salt().is_ok() {
                if let Err(e) = executor::verify_vault_password(&password) {
                    if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
                }
            }

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else if std::io::stdin().is_terminal() {
                // Hidden prompt on TTY
                let val = prompt_hidden("\u{1F511} Enter new API Key value: ")
                    .map_err(|e| format!("Failed to read API Key value: {}", e))?;
                Zeroizing::new(val)
            } else {
                // Plain stdin for pipes / automation
                if !cli.json {
                    print!("\u{1F511} Enter new API Key value: ");
                    io::stdout().flush()?;
                }
                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            let result = executor::update_secret(alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(alias), result.is_ok());

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "API Key updated successfully"
                }));
            } else {
                use colored::Colorize;
                eprintln!("  {} API Key '{}' updated.", "\u{2713}".green(), alias);
                commands_proxy::maybe_warn_stale();
            }
        }
        Commands::Test { alias, provider: test_provider } => {
            let password = prompt_vault_password(cli.password_stdin, cli.json)?;

            if let Some(ref alias) = alias {
                // ── Test a specific key by alias ─────────────────────
                let key_value = match executor::get_secret(alias, &password) {
                    Ok(s) => s,
                    Err(e) => { if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); } }
                };
                let meta = storage::list_entries_with_metadata().unwrap_or_default()
                    .into_iter().find(|m| m.alias == *alias);
                let provider_code = test_provider.as_ref().map(|p| p.to_lowercase())
                    .or_else(|| meta.as_ref().and_then(|m| m.provider_code.clone()));
                let base_url_override = meta.as_ref().and_then(|m| m.base_url.clone());

                let targets: Vec<(String, String)> = if let Some(ref code) = provider_code {
                    let url = base_url_override.as_deref()
                        .or_else(|| commands_project::default_base_url(code))
                        .unwrap_or("https://unknown").to_string();
                    vec![(code.clone(), url)]
                } else if let Some(ref url) = base_url_override {
                    let mut t: Vec<(String, String)> = commands_project::PROVIDER_DEFAULTS.iter()
                        .map(|(c, _)| (c.to_string(), url.clone())).collect();
                    t.push(("custom".to_string(), url.clone())); t
                } else {
                    commands_project::PROVIDER_DEFAULTS.iter().map(|(c, u)| (c.to_string(), u.to_string())).collect()
                };

                if cli.json {
                    let suite = commands_project::run_connectivity_test(&targets, key_value.trim(), true);
                    json_output::success(serde_json::json!({ "alias": alias, "results": suite.json_results }));
                } else {
                    use colored::Colorize;
                    if targets.len() == 1 { let (code, url) = &targets[0]; eprintln!("  Testing '{}' ({} \u{2192} {})", alias.bold(), code, url.dimmed()); }
                    else { eprintln!("  Testing '{}' against {} providers", alias.bold(), targets.len()); }
                    eprintln!();
                    commands_project::run_connectivity_test(&targets, key_value.trim(), false);
                }
            } else {
                // ── No alias: test all current Primary keys in one table ─
                let bindings = storage::list_provider_bindings(profile_activation::DEFAULT_PROFILE).unwrap_or_default();
                if bindings.is_empty() {
                    if cli.json { json_output::error("No active provider bindings. Add a key first.", 1); }
                    else { return Err("No active provider bindings. Add a key with `aikey add` first.".into()); }
                }
                use colored::Colorize;

                struct TestItem { provider: String, url: String, key: String, display: String, source_type: String }
                let mut items: Vec<TestItem> = Vec::new();
                let mut skipped_team: Vec<(String, String)> = Vec::new();

                for b in &bindings {
                    let display = resolve_binding_display_name(&b.key_source_type, &b.key_source_ref);
                    if b.key_source_type == "personal" {
                        let kv = match executor::get_secret(&b.key_source_ref, &password) {
                            Ok(s) => s,
                            Err(e) => { if !cli.json { eprintln!("  {} {} \u{2192} '{}': {}", "\u{2717}".red(), b.provider_code, b.key_source_ref, e); } continue; }
                        };
                        let bu = storage::get_entry_base_url(&b.key_source_ref).unwrap_or(None);
                        let url = bu.as_deref().or_else(|| commands_project::default_base_url(&b.provider_code)).unwrap_or("https://unknown").to_string();
                        items.push(TestItem { provider: b.provider_code.clone(), url, key: kv.to_string(), display, source_type: b.key_source_type.clone() });
                    } else { skipped_team.push((b.provider_code.clone(), display)); }
                }

                if cli.json {
                    let mut all_json: Vec<serde_json::Value> = Vec::new();
                    for item in &items {
                        let r = commands_project::test_provider_connectivity(&item.provider, &item.url, item.key.trim());
                        all_json.push(serde_json::json!({ "provider": item.provider, "alias": item.display, "source_type": item.source_type, "base_url": item.url,
                            "ping_ok": r.ping_ok, "ping_ms": r.ping_ms, "api_ok": r.api_ok, "api_ms": r.api_ms, "api_status": r.api_status,
                            "chat_ok": r.chat_ok, "chat_ms": r.chat_ms, "chat_status": r.chat_status }));
                    }
                    json_output::success(serde_json::json!({ "bindings_tested": all_json }));
                } else {
                    eprintln!("  Testing {} active provider binding(s)...\n", bindings.len());
                    const W_PROV: usize = 12; const W_ALIAS: usize = 16; const W_PING: usize = 16; const W_API: usize = 30;
                    eprintln!("  {:<wp$} {:<wa$} {:<wpi$} {:<wap$} {}", "Provider".dimmed(), "Key".dimmed(), "Ping".dimmed(), "API".dimmed(), "Chat".dimmed(),
                        wp = W_PROV, wa = W_ALIAS, wpi = W_PING, wap = W_API);
                    eprintln!("  {}", "\u{2500}".repeat(W_PROV + W_ALIAS + W_PING + W_API + 20).dimmed());

                    let mut any_reachable = false;
                    for item in &items {
                        eprint!("  {:<wp$} {:<wa$} ", item.provider.bold(), item.display.dimmed(), wp = W_PROV, wa = W_ALIAS);
                        let _ = io::stderr().flush();
                        let r = commands_project::test_provider_connectivity(&item.provider, &item.url, item.key.trim());
                        let ping_raw = if r.ping_ok { format!("ok ({}ms)", r.ping_ms) } else { format!("fail ({}ms)", r.ping_ms) };
                        let ping_col = if r.ping_ok { format!("{:<w$}", ping_raw, w = W_PING).green().to_string() } else { format!("{:<w$}", ping_raw, w = W_PING).red().to_string() };
                        eprint!("{} ", ping_col); let _ = io::stderr().flush();
                        if !r.ping_ok { eprintln!("{:<w$} {}", "\u{2014}".dimmed(), "\u{2014}".dimmed(), w = W_API); }
                        else {
                            any_reachable = true;
                            let api_raw = if r.api_ok { let h = r.api_status.map(|s| commands_project::api_status_hint(s)).unwrap_or_default(); format!("ok ({}ms, {})", r.api_ms, h) } else { format!("fail ({}ms)", r.api_ms) };
                            let api_col = if r.api_ok { format!("{:<w$}", api_raw, w = W_API).green().to_string() } else { format!("{:<w$}", api_raw, w = W_API).red().to_string() };
                            eprint!("{} ", api_col); let _ = io::stderr().flush();
                            if !r.api_ok { eprintln!("{}", "\u{2014}".dimmed()); }
                            else if r.chat_ok { let h = r.chat_status.map(|s| commands_project::chat_status_hint(s)).unwrap_or_default(); eprintln!("{}", format!("ok ({}ms, {})", r.chat_ms, h).green()); }
                            else { eprintln!("{}", format!("fail ({}ms)", r.chat_ms).red()); }
                        }
                    }
                    for (prov, display) in &skipped_team { eprintln!("  {:<wp$} {:<wa$} {}", prov.bold(), display.dimmed(), "skipped [team]".dimmed(), wp = W_PROV, wa = W_ALIAS); }

                    eprintln!();
                    if !any_reachable { eprintln!("  {:<12} {}", "proxy".bold(), "skipped (all providers unreachable)".dimmed()); }
                    else if commands_proxy::is_proxy_running() {
                        let proxy_addr = commands_proxy::doctor_proxy_addr();
                        if let Some(prov) = items.first().map(|i| i.provider.as_str()) {
                            eprint!("  {:<12} ", "proxy".bold());
                            let r = commands_project::test_proxy_connectivity(&proxy_addr, prov);
                            if r.ok { let h = r.status.map(|s| commands_project::proxy_status_hint(s)).unwrap_or_default(); eprintln!("{} ({} ms, {})", "ok".green(), r.ms, h); }
                            else { eprintln!("{} ({} ms)", "failed".red(), r.ms); }
                        }
                    } else { eprintln!("  {:<12} {}", "proxy".bold(), "not running".dimmed()); }
                }
            }
        }
        Commands::Export { pattern, output } => {
            let vault_password = prompt_password_secure("\u{1F512} Enter Master Password: ", cli.password_stdin, cli.json)?;
            let export_password = prompt_password_secure("\u{1F512} Enter Export Password: ", cli.password_stdin, cli.json)?;
            let output_path = std::path::Path::new(output);

            let result = synapse::export_vault(pattern, output_path, &vault_password, &export_password);
            let _ = audit::log_audit_event(&vault_password, audit::AuditOperation::Export, Some(pattern), result.is_ok());

            let count = match result {
                Ok(c) => c,
                Err(e) => {
                    if cli.json {
                        json_output::error(&e.to_string(), 1);
                    } else {
                        return Err(e.into());
                    }
                }
            };

            if cli.json {
                json_output::success(serde_json::json!({
                    "count": count,
                    "output": output,
                    "message": format!("Exported {} secret(s)", count)
                }));
            } else {
                println!("Exported {} secret(s) to {}", count, output);
            }
        }
        Commands::Run { provider, logical_model, model, tenant, profile, dry_run, direct, command } => {
            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error_stderr(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            // Tenant precedence: --tenant > AIKEY_TENANT env var
            let env_tenant = std::env::var("AIKEY_TENANT").ok();
            let resolved_tenant = tenant.as_deref().or(env_tenant.as_deref());

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Profile override: --profile temporarily switches the active profile for this run.
            let _profile_guard = if let Some(p) = profile {
                let prev = global_config::get_current_profile().ok().flatten();
                global_config::set_current_profile(p)
                    .map_err(|e| format!("failed to set profile '{}': {}", p, e))?;
                Some(prev)
            } else {
                None
            };

            // --direct: bypass proxy — decrypt the real key and inject it directly
            // into the child process, overriding any proxy env vars from the shell.
            // Only personal keys are supported (team keys are always proxy-routed).
            if *direct {
                commands_account::handle_run_direct(command, &password, cli.json)?;
                return Ok(());
            }

            // Proxy guard: ensure aikey-proxy is running before executing the command.
            // Runs silently in the happy path; warns on failure but does not abort.
            if !*dry_run {
                commands_proxy::proxy_guard(&password);
            }

            if *dry_run {
                let infos = if let Some(provider_name) = provider {
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);
                    executor::dry_run_provider(provider_name, model.as_deref(), resolved_tenant, project_config.as_ref())?
                } else {
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);
                    if let Some(cfg) = project_config.as_ref() {
                        executor::dry_run_project_config(cfg, logical_model.as_deref(), resolved_tenant)?
                    } else {
                        return Err("No aikey.config.json found and no --provider specified.\n\
                            For dry-run, use: aikey run --provider anthropic --dry-run -- <cmd>".into());
                    }
                };

                if cli.json {
                    json_output::print_json(serde_json::json!({
                        "dry_run": true,
                        "command": command,
                        "injections": infos
                    }));
                } else {
                    // P1-Q4: Enhanced dry-run output
                    println!("Dry Run — Resolution Summary");
                    println!("============================");
                    println!();

                    for info in &infos {
                        println!("Environment Variable: {}", info.env_var);
                        println!("  Provider:      {}", info.provider);
                        if let Some(model) = &info.model {
                            println!("  Model:         {}", model);
                        }
                        if !info.key_alias.is_empty() {
                            println!("  Key Alias:     {}", info.key_alias);
                        }
                        println!("  Source:        {}", info.source);
                        if info.tenant_override {
                            println!("  Tenant Override: YES");
                        }
                        println!();
                    }

                    println!("Will inject {} variable(s) into:", infos.len());
                    println!("  {}", command.join(" "));
                    println!();
                    println!("Note: Secret values are hidden. Use 'aikey run' without --dry-run to execute.");
                }
            } else {
                let result = if let Some(provider_name) = provider {
                    // Provider-mode: resolve a single provider key via the 5-step resolver
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);

                    executor::run_with_provider(
                        provider_name,
                        model.as_deref(),
                        resolved_tenant,
                        project_config.as_ref(),
                        &password,
                        command,
                        cli.json,
                    )
                } else {
                    // No --provider: use project config if present, then active key
                    // via proxy, and finally fall back to vault-auto detection.
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);

                    if let Some(cfg) = project_config.as_ref() {
                        executor::run_with_project_config(cfg, &password, command, cli.json, logical_model.as_deref(), resolved_tenant)
                    } else if !storage::list_provider_bindings("default").unwrap_or_default().is_empty()
                        || storage::get_active_key_config().ok().flatten().is_some()
                    {
                        // Provider bindings exist, or legacy active key — route via proxy.
                        executor::run_with_active_key(command, cli.json)
                    } else {
                        executor::run_from_vault(&password, command, cli.json)
                    }
                };

                match result {
                    Ok((secrets_count, exit_code)) => {
                        if cli.json {
                            json_output::success_stderr(serde_json::json!({
                                "secrets_injected": secrets_count,
                                "exit_code": exit_code
                            }));
                        }
                    }
                    Err(e) => {
                        // Extract exit code from error message if present
                        let exit_code = if let Some(code_str) = e.strip_prefix("Command exited with code ") {
                            code_str.parse::<i32>().unwrap_or(1)
                        } else {
                            1
                        };

                        if cli.json {
                            json_output::error_with_data_stderr(
                                &e,
                                serde_json::json!({
                                    "exit_code": exit_code
                                }),
                                exit_code
                            );
                        } else {
                            eprintln!("Error: {}", e);
                            std::process::exit(exit_code);
                        }
                    }
                }
            }

            // Restore previous profile if we overrode it.
            if let Some(prev_profile) = _profile_guard {
                if let Some(p) = prev_profile {
                    let _ = global_config::set_current_profile(&p);
                }
            }

            // Post-operation: warn if proxy is unreachable (complements proxy_guard
            // which may have failed to start the proxy after a kill -9).
            if !*dry_run {
                commands_proxy::warn_if_proxy_down();
            }
        }
        Commands::ChangePassword => {
            let old_password = prompt_password_secure("\u{1F512} Enter Master Password: ", cli.password_stdin, cli.json)?;
            let new_password = prompt_password_secure("\u{1F512} Enter New Master Password: ", false, cli.json)?;
            let confirm_password = prompt_password_secure("\u{1F512} Confirm New Master Password: ", false, cli.json)?;

            if new_password.expose_secret() != confirm_password.expose_secret() {
                if cli.json {
                    json_output::error("Passwords do not match", 1);
                } else {
                    return Err("Passwords do not match".into());
                }
            }

            if !cli.json {
                println!("Changing master password...");
            }
            let result = storage::change_password(&old_password, &new_password);
            let _ = audit::log_audit_event(&old_password, audit::AuditOperation::Init, None, result.is_ok());

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            // Invalidate cached session — the password has changed.
            session::invalidate();

            if cli.json {
                json_output::success(serde_json::json!({
                    "message": "Master password changed successfully."
                }));
            } else {
                println!("Master password changed successfully!");
            }
        }
        Commands::Secret { action } => {
            match action {
                SecretAction::Set { name, provider, from_stdin } => {
                    if !from_stdin {
                        let err_msg = "The --from-stdin flag is required for security. API Key values must not be passed via command-line arguments.";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    if let Err(e) = validate_secret_name(name) {
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": e
                            }), 1);
                        } else {
                            return Err(e.into());
                        }
                    }

                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    let existing = executor::list_secrets(&password);
                    let existing = match existing {
                        Ok(list) => list,
                        Err(e) => {
                            if cli.json {
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    };

                    if existing.iter().any(|alias| alias == name) {
                        let err_msg = format!(
                            "API Key '{}' already exists. Use 'aikey secret upsert {}' to overwrite.",
                            name, name
                        );
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::AliasExists.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    // Read secret value: hidden prompt on TTY, plain stdin for pipes
                    let secret = if std::io::stdin().is_terminal() {
                        let val = prompt_hidden("\u{1F511} Enter API Key value: ")
                            .map_err(|e| format!("Failed to read secret value: {}", e))?;
                        Zeroizing::new(val)
                    } else {
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    };
                    let secret_value = secret.trim();

                    if secret_value.is_empty() {
                        let err_msg = "Secret value cannot be empty";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    let result = executor::add_secret(name, secret_value, &password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            // Persist provider_code if supplied.
                            if let Some(code) = provider {
                                let _ = storage::set_entry_provider_code(name, Some(code.to_lowercase().as_str()));
                            }
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("API Key '{}' set successfully", name);
                                commands_proxy::maybe_warn_stale();
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                SecretAction::Upsert { name, provider, from_stdin } => {
                    if !from_stdin {
                        let err_msg = "The --from-stdin flag is required for security. API Key values must not be passed via command-line arguments.";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    if let Err(e) = validate_secret_name(name) {
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": e
                            }), 1);
                        } else {
                            return Err(e.into());
                        }
                    }

                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    // Read secret value: hidden prompt on TTY, plain stdin for pipes
                    let secret = if std::io::stdin().is_terminal() {
                        let val = prompt_hidden("\u{1F511} Enter API Key value: ")
                            .map_err(|e| format!("Failed to read secret value: {}", e))?;
                        Zeroizing::new(val)
                    } else {
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    };
                    let secret_value = secret.trim();

                    if secret_value.is_empty() {
                        let err_msg = "Secret value cannot be empty";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    // Check if secret exists to determine add vs update
                    let existing = executor::list_secrets(&password).unwrap_or_default();
                    let result = if existing.iter().any(|alias| alias == name) {
                        executor::update_secret(name, secret_value, &password)
                    } else {
                        executor::add_secret(name, secret_value, &password)
                    };
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            // Persist provider_code if supplied.
                            if let Some(code) = provider {
                                let _ = storage::set_entry_provider_code(name, Some(code.to_lowercase().as_str()));
                            }
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("API Key '{}' upserted successfully", name);
                                commands_proxy::maybe_warn_stale();
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                SecretAction::List => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;

                    let result = executor::list_secrets_with_metadata(&password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::List, None, result.is_ok());

                    match result {
                        Ok(secrets) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "secrets": secrets
                                }));
                            } else if secrets.is_empty() {
                                println!("No API Keys stored.");
                            } else {
                                println!("Stored API Keys:");
                                for secret in secrets {
                                    println!("  {}", secret.alias);
                                }
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                SecretAction::Delete { name } => {
                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    let result = executor::delete_secret(name, &password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            // Reconcile provider bindings after removal.
                            let actions = profile_activation::reconcile_provider_primary_after_key_removal(
                                "personal", name,
                            ).unwrap_or_default();
                            if !actions.is_empty() {
                                let _ = profile_activation::refresh_implicit_profile_activation();
                            }

                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name,
                                    "reconciled_providers": actions.iter().map(|a| &a.provider_code).collect::<Vec<_>>(),
                                }));
                            } else {
                                use colored::Colorize;
                                println!("API Key '{}' deleted successfully", name);
                                for action in &actions {
                                    match &action.outcome {
                                        profile_activation::ReconcileOutcome::Replaced { new_source_ref, .. } => {
                                            eprintln!("  {} '{}' promoted to Primary for {}",
                                                "\u{2B50}".yellow(), new_source_ref.bold(), action.provider_code);
                                        }
                                        profile_activation::ReconcileOutcome::Cleared => {
                                            eprintln!("  {} No replacement for {} — provider has no Primary",
                                                "\u{26A0}".yellow(), action.provider_code);
                                        }
                                    }
                                }
                                commands_proxy::maybe_warn_stale();
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
            }
        }
        Commands::Project { action } => {
            match action {
                ProjectAction::Init => {
                    commands_project::handle_project_init(cli.json)?;
                }
                ProjectAction::Status => {
                    commands_project::handle_project_status(cli.json)?;
                }
                ProjectAction::Map { var, alias, env, provider, model, key_alias, impl_id } => {
                    commands_project::handle_project_map(var, alias, env.as_deref(), provider.as_deref(), model.as_deref(), key_alias.as_deref(), impl_id.as_deref(), cli.json)?;
                }
            }
        }
        Commands::Quickstart => {
            commands_project::handle_quickstart(cli.json)?;
        }
        Commands::Key { action } => {
            match action {
                KeyAction::Rotate { name, from_stdin } => {
                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    let new_value = if *from_stdin {
                        eprint!("Enter new value for '{}' (then press Enter): ", name);
                        let _ = io::stderr().flush();
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    } else {
                        let val = prompt_hidden(&format!("\u{1F511} New value for '{}': ", name))
                            .map_err(|e| format!("Failed to read new key value: {}", e))?;
                        Zeroizing::new(val)
                    };
                    let new_value_str = new_value.trim();

                    if new_value_str.is_empty() {
                        let err_msg = "New key value cannot be empty";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    // Check if secret exists to determine add vs update
                    let existing = executor::list_secrets(&password).unwrap_or_default();
                    let result = if existing.iter().any(|alias| alias == name) {
                        executor::update_secret(name, new_value_str, &password)
                    } else {
                        executor::add_secret(name, new_value_str, &password)
                    };
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("Key '{}' rotated successfully", name);
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                KeyAction::List => {
                    commands_account::handle_key_list(cli.json)?;
                }
                KeyAction::Sync => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    commands_account::handle_key_sync(&password, cli.json)?;
                }
                KeyAction::Use { alias_or_id, no_hook } => {
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    commands_account::handle_key_use(alias_or_id, *no_hook, None, cli.json)?;
                    commands_proxy::warn_if_proxy_down();
                }
                KeyAction::Alias { old_alias, new_alias } => {
                    commands_account::handle_key_alias(old_alias, new_alias, cli.json)?;
                }
            }
        }
        Commands::Account { action } => {
            match action {
                AccountAction::Login { url, token, email } => {
                    commands_account::handle_login(
                        cli.json,
                        url.clone(),
                        token.clone(),
                        email.clone(),
                    )?;
                }
                AccountAction::Status => {
                    commands_account::handle_account_status(cli.json)?;
                }
                AccountAction::Logout => {
                    commands_account::handle_logout(cli.json)?;
                }
                AccountAction::SetUrl { url } => {
                    commands_account::handle_set_control_url(url, cli.json)?;
                }
            }
        }
        Commands::Login { url, token, email } => {
            commands_account::handle_login(cli.json, url.clone(), token.clone(), email.clone())?;
        }
        Commands::Logout => {
            commands_account::handle_logout(cli.json)?;
        }
        Commands::Use { alias_or_id, no_hook, provider } => {
            match alias_or_id {
                Some(a) => {
                    // `aikey use <alias>` — provider-level promotion via handle_key_use.
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    commands_account::handle_key_use(
                        a, *no_hook, provider.as_deref(), cli.json,
                    )?;
                }
                None => {
                    // `aikey use` (no args) — provider-tree interactive editor.
                    if !std::io::stdin().is_terminal() || cli.json {
                        return Err("alias required in non-interactive mode (usage: aikey use <ALIAS>)".into());
                    }
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    let changes = pick_providers_interactively()?;
                    if changes.is_empty() {
                        eprintln!("  No changes.");
                    } else {
                        for (prov, src_type, src_ref) in &changes {
                            storage::set_provider_binding(
                                profile_activation::DEFAULT_PROFILE,
                                prov, src_type, src_ref,
                            ).map_err(|e| format!("Failed to set binding: {}", e))?;
                        }
                        let refresh = profile_activation::refresh_implicit_profile_activation()
                            .map_err(|e| format!("Failed to refresh activation: {}", e))?;
                        if !*no_hook {
                            commands_account::ensure_shell_hook(false);
                        }

                        // Auto-configure / unconfigure third-party CLI tools.
                        let proxy_port = commands_proxy::proxy_port();
                        let all_providers: Vec<String> = refresh.bindings.iter()
                            .map(|b| b.provider_code.clone())
                            .collect();

                        let has_kimi = all_providers.iter().any(|p| {
                            let c = p.to_lowercase();
                            c == "kimi" || c == "moonshot"
                        });
                        if has_kimi {
                            if let Some(b) = refresh.bindings.iter().find(|b| {
                                let c = b.provider_code.to_lowercase();
                                c == "kimi" || c == "moonshot"
                            }) {
                                let token = format!("aikey_{}_{}", b.key_source_type, b.key_source_ref);
                                commands_account::configure_kimi_cli(&token, proxy_port);
                            }
                        } else {
                            commands_account::unconfigure_kimi_cli();
                        }

                        let has_openai = all_providers.iter().any(|p| {
                            let c = p.to_lowercase();
                            c == "openai" || c == "gpt" || c == "chatgpt"
                        });
                        if has_openai {
                            commands_account::configure_codex_cli(proxy_port);
                        } else {
                            commands_account::unconfigure_codex_cli();
                        }

                        // Print a summary box showing the final state.
                        use colored::Colorize;
                        let changed_providers: Vec<&str> = changes.iter()
                            .map(|(p, _, _)| p.as_str())
                            .collect();
                        let mut box_rows: Vec<String> = Vec::new();
                        for b in &refresh.bindings {
                            let display_name = resolve_binding_display_name(&b.key_source_type, &b.key_source_ref);
                            let is_changed = changed_providers.contains(&b.provider_code.as_str());
                            let value_raw = format!("\u{2192} {}", display_name);
                            let value_padded = format!("{:<28}", value_raw);
                            let value_col = if is_changed {
                                value_padded.green().to_string()
                            } else {
                                value_padded
                            };
                            box_rows.push(format!("  {:<14} {} \x1b[90m[{}]\x1b[0m",
                                b.provider_code, value_col, b.key_source_type));
                        }
                        box_rows.push(String::new());
                        box_rows.push(format!("{} Saved provider primary selections and refreshed current activation.",
                            "\u{2713}".green()));
                        ui_frame::print_box(
                            "\u{1F7E2}",
                            "Provider Key Selection — Confirmed",
                            &box_rows,
                        );
                        println!();
                    }
                }
            }
            commands_proxy::warn_if_proxy_down();
        }
        Commands::Env { action } => {
            match action {
                None => {
                    // `aikey env` — read-only display of active.env + proxy.env.
                    use colored::Colorize;
                    let active_path = proxy_env::active_env_path().unwrap_or_default();
                    let proxy_path = proxy_env::proxy_env_path().unwrap_or_default();

                    // Active env section.
                    eprintln!("{}", "Active env:".bold());
                    eprintln!("  Path: {}", active_path.display().to_string().dimmed());
                    if active_path.exists() {
                        match proxy_env::read_active_env_lines() {
                            Ok(entries) if entries.is_empty() => {
                                eprintln!("  (empty)");
                            }
                            Ok(entries) => {
                                for (k, v) in &entries {
                                    eprintln!("  {}={}", k, proxy_env::mask_value(k, v).dimmed());
                                }
                            }
                            Err(e) => eprintln!("  {}", format!("Error: {}", e).red()),
                        }
                    } else {
                        eprintln!("  {}", "(not found)".dimmed());
                    }
                    eprintln!();

                    // Proxy env section.
                    eprintln!("{}", "Proxy env:".bold());
                    eprintln!("  Path: {}", proxy_path.display().to_string().dimmed());
                    if proxy_path.exists() {
                        match proxy_env::read_proxy_env() {
                            Ok(map) if map.is_empty() => {
                                eprintln!("  (empty)");
                            }
                            Ok(map) => {
                                for (k, v) in &map {
                                    eprintln!("  {}={}", k, proxy_env::mask_value(k, v).dimmed());
                                }
                                eprintln!();
                                eprintln!("  Entries: {}  Hash: {}",
                                    map.len(), proxy_env::config_hash(&map).dimmed());
                            }
                            Err(e) => eprintln!("  {}", format!("Error: {}", e).red()),
                        }
                    } else {
                        eprintln!("  {}", "(not found — use `aikey env set -- KEY=VALUE` to create)".dimmed());
                    }
                }
                Some(EnvAction::Set { args }) => {
                    // `aikey env set -- KEY=VALUE ...`
                    // Also supports stdin pipe: echo "K=V" | aikey env set
                    use colored::Colorize;

                    // Collect input: from args, or from stdin if args empty and stdin is piped.
                    let effective_args: Vec<String> = if !args.is_empty() {
                        args.clone()
                    } else if !std::io::stdin().is_terminal() {
                        let mut buf = String::new();
                        io::stdin().read_line(&mut buf)?;
                        vec![buf]
                    } else {
                        return Err(
                            "Usage: aikey env set -- KEY=VALUE [KEY2=VALUE2 ...]\n\
                             \n\
                             Examples:\n  \
                               aikey env set -- http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890\n  \
                               echo 'http_proxy=http://127.0.0.1:7890' | aikey env set\n\
                             \n\
                             Note: use spaces (not semicolons) to separate multiple entries,\n\
                             or quote the entire argument if using semicolons:\n  \
                               aikey env set -- 'export A=1; export B=2'".into()
                        );
                    };

                    // Parse new entries from args.
                    let new_entries = proxy_env::parse_set_args(&effective_args)
                        .map_err(|e| format!("Parse error: {}", e))?;

                    if new_entries.is_empty() {
                        return Err("No valid KEY=VALUE pairs found.".into());
                    }

                    // Read existing, merge, write back.
                    // Why explicit error: if the old file is corrupt, we must not
                    // silently discard it — user should fix it first.
                    let mut existing = proxy_env::read_proxy_env()
                        .map_err(|e| format!(
                            "Cannot parse existing ~/.aikey/proxy.env: {}\n\
                             Fix or remove the file before setting new values.", e
                        ))?;
                    for (k, v) in &new_entries {
                        existing.insert(k.clone(), v.clone());
                    }
                    proxy_env::write_proxy_env(&existing)?;

                    let path = proxy_env::proxy_env_path().unwrap_or_default();
                    eprintln!("{} Updated {}", "\u{2713}".green(), path.display());
                    for (k, _) in &new_entries {
                        eprintln!("  {} {}", "+".green(), k);
                    }

                    // Auto-restart proxy if running so new env takes effect immediately.
                    if commands_proxy::is_proxy_running() {
                        eprintln!();
                        eprintln!("  Restarting proxy to apply changes...");
                        let pw = session::try_get()
                            .or_else(|| std::env::var("AK_TEST_PASSWORD").ok().map(SecretString::new));
                        match pw {
                            Some(password) => {
                                match commands_proxy::handle_restart(None, &password) {
                                    Ok(()) => {
                                        eprintln!("  {} Proxy restarted with new env.", "\u{2713}".green());
                                    }
                                    Err(e) => {
                                        eprintln!("  {} Auto-restart failed: {}", "\u{26A0}".yellow(), e);
                                        eprintln!("  Run manually: {}", "aikey proxy restart".bold());
                                    }
                                }
                            }
                            None => {
                                eprintln!("  {} Cannot auto-restart (no cached password).",
                                    "\u{26A0}".yellow());
                                eprintln!("  Run manually: {}", "aikey proxy restart".bold());
                            }
                        }
                    } else {
                        eprintln!();
                        eprintln!("  Proxy not running. Changes will apply on next {}.",
                            "aikey proxy start".bold());
                    }
                }
            }
        }
        Commands::Browse { page, port } => {
            commands_account::handle_browse(page.as_deref(), *port, cli.json)?;
        }
        Commands::Status => {
            commands_account::handle_status_overview(cli.json)?;
        }
        Commands::Whoami => {
            commands_account::handle_whoami(cli.json)?;
        }
        Commands::Doctor => {
            commands_project::handle_doctor(cli.json)?;
        }
        Commands::Proxy { action } => {
            match action {
                ProxyAction::Start { config, foreground } => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    // Verify the password is valid before handing it to the proxy.
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    // Why: default is background (detach=true) so the terminal is not blocked.
                    // Use --foreground for debugging or when running under a process manager.
                    commands_proxy::handle_start(
                        config.as_deref(),
                        !*foreground,  // detach = !foreground
                        &password,
                    )?;
                }
                ProxyAction::Stop => {
                    commands_proxy::handle_stop()?;
                }
                ProxyAction::Status => {
                    commands_proxy::handle_status()?;
                }
                ProxyAction::Restart { config } => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    commands_proxy::handle_restart(config.as_deref(), &password)?;
                }
                ProxyAction::Verify => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    commands_proxy::handle_verify(&password)?;
                }
            }
        }
        Commands::Logs { limit } => {
            let entries = events::list_events(*limit)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("No events recorded yet.");
            } else {
                println!("{:<6} {:<20} {:<10} {:<12} {:<5} {}",
                    "ID", "TIMESTAMP", "TYPE", "PROVIDER", "EXIT", "COMMAND");
                println!("{}", "-".repeat(72));
                for e in &entries {
                    let ts = e.timestamp.to_string();
                    println!("{:<6} {:<20} {:<10} {:<12} {:<5} {}",
                        e.id,
                        ts,
                        e.event_type,
                        e.provider.as_deref().unwrap_or("-"),
                        e.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()),
                        e.command.as_deref().unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Secure password prompt with Zeroizing protection
///
/// SECURITY HARDENING:
/// - Wraps password in Zeroizing<String> IMMEDIATELY upon input
/// P1-Q3: Handle aikey shell command
/// Starts an interactive subshell with non-sensitive context only.
/// Secrets are NOT exported as long-lived env vars; each command uses aikey run injection.
fn handle_shell_command(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json_mode {
        return Err("Shell mode is not supported in JSON mode".into());
    }

    // Get project config to determine context
    let config = config::ProjectConfig::discover()
        .ok()
        .flatten()
        .map(|(_, cfg)| cfg);

    let project_name = config.as_ref().map(|c| c.project.name.as_str()).unwrap_or("unknown");

    // Get current environment and profile
    let current_env = global_config::get_current_env().ok().flatten();
    let current_profile = global_config::get_current_profile().ok().flatten();

    println!("AiKey Shell - Advanced Mode");
    println!("===========================");
    println!("Project: {}", project_name);
    if let Some(env) = &current_env {
        println!("Environment: {}", env);
    }
    if let Some(profile) = &current_profile {
        println!("Profile: {}", profile);
    }
    println!();
    println!("⚠️  Security Notice:");
    println!("   Secrets are NOT exported to this shell.");
    println!("   Use 'aikey run -- <command>' to inject secrets per-command.");
    println!();
    println!("Type 'exit' to leave the AiKey shell.");
    println!();

    // Determine user's shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    // Build environment with non-sensitive context only
    let mut cmd = std::process::Command::new(&shell);

    // P1-Q3: Export only non-sensitive context
    if let Some(env) = current_env {
        cmd.env("AIKEY_ENV", env);
    }
    if let Some(profile) = current_profile {
        cmd.env("AIKEY_PROFILE", profile);
    }
    cmd.env("AIKEY_PROJECT", project_name);

    // Set a marker so users know they're in an aikey shell
    cmd.env("AIKEY_SHELL", "1");

    // Customize prompt to show we're in aikey shell
    let ps1 = std::env::var("PS1").unwrap_or_else(|_| "\\$ ".to_string());
    cmd.env("PS1", format!("(aikey) {}", ps1));

    // Start the subshell
    let status = cmd.status()?;

    // Cleanup message on exit
    println!();
    println!("Exited AiKey shell.");

    if !status.success() {
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
    }

    Ok(())
}

/// - Disables TTY echo for interactive password entry
/// - Converts to SecretString only after zeroizing wrapper is in place
/// Validate a secret key name (alias).
/// Allowed: alphanumeric, `_`, `-`, `:` (for provider:alias format).
/// Max length: 256 characters. Empty names and names with spaces/slashes are rejected.
fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Secret name cannot be empty.".to_string());
    }
    if name.len() > 256 {
        return Err(format!("Secret name is too long ({} chars). Maximum is 256 characters.", name.len()));
    }
    if let Some(bad) = name.chars().find(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | ':' | '.')) {
        return Err(format!(
            "Secret name contains invalid character '{bad}'. \
             Allowed: letters, digits, '_', '-', ':', '.'"
        ));
    }
    Ok(())
}

/// - Ensures raw password string is wiped from memory on scope exit
/// - Supports AK_TEST_PASSWORD environment variable for testing
/// - Supports reading from stdin when password_stdin is true
/// Prompt for the vault master password, adapting the message to whether the
/// vault already exists ("Enter") or is about to be created ("Set").
/// Returns the master password, using the 30-minute session cache when available.
/// Use for LOW-sensitivity commands (list, get, run, key sync, proxy start, …).
/// After a successful vault operation the caller should call `session::refresh()`.
/// Returns detailed notes for a command path (e.g. "add", "proxy start").
/// Used to append contextual notes after clap's rendered `--help` output.
fn command_detail_notes(cmd: &str) -> Option<&'static str> {
    match cmd {
        "add" => Some("\
Notes:
    - Stores a new local secret under <ALIAS>.
    - --provider binds the secret to a provider such as openai or anthropic.
    - On TTY, the secret value is entered interactively.
    - In non-interactive mode, the secret value is read from stdin.
    - In interactive mode, AiKey may run connectivity checks before saving."),

        "list" => Some("\
Notes:
    - Shows both Personal Keys and Team Keys.
    - Team keys are filtered to active keys only.
    - May perform a lightweight sync first.
    - If server state changed, AiKey may prompt for the vault password to complete a full sync.
    - If the control service is unreachable, AiKey falls back to local cache."),

        "test" => Some("\
Notes:
    - --provider overrides the stored provider for this test only.
    - The test may include TCP reachability, API probe, chat/completion probe, and proxy probe.
    - If no provider metadata is stored, AiKey may test multiple known providers."),

        "use" => Some("\
Notes:
    - Accepts either a team key alias/ID or a personal key alias.
    - If ALIAS_OR_ID is omitted on a TTY, AiKey opens an interactive picker.
    - In non-interactive mode, ALIAS_OR_ID is required.
    - AiKey ensures the local proxy is running before activation.
    - --provider <PROVIDER> narrows a personal key to a specific provider.
    - --provider with no value opens an interactive provider selector.
    - --no-hook skips shell hook installation."),

        "login" => Some("\
Notes:
    - Shortcut for `aikey account login`.
    - Default flow uses browser + email activation.
    - --token is the copy-paste fallback for non-completing browser flow.
    - Control URL precedence:
      1. --control-url
      2. AIKEY_CONTROL_URL
      3. saved local config
      4. interactive prompt
    - --email pre-fills the login page."),

        "browse" => Some("\
Notes:
    - PAGE: overview | keys | account | usage
    - In local mode, AiKey can open the local console directly.
    - In team/trial mode, AiKey requires a valid account session.
    - If the control URL is local, AiKey may auto-detect common dev ports such as 3000 and 5173.
    - --port forces a specific local web port."),

        "doctor" => Some("\
Notes:
    - Checks include internet reachability, vault presence, session cache, proxy status,
      provider/proxy connectivity, shell hook state, and vault WAL size.
    - In interactive mode, AiKey may try to restart the proxy automatically.
    - In interactive mode, AiKey may also try to install the shell hook if missing."),

        "env" => Some("\
Notes:
    - `aikey env` shows both `~/.aikey/active.env` and `~/.aikey/proxy.env`.
    - `active.env` is the shell-facing derived environment.
    - `proxy.env` is the user-managed environment file for the `aikey-proxy` process.
    - Values are masked on display when the variable name looks sensitive.
    - If `proxy.env` exists and is valid, AiKey also shows entry count and a short config hash."),

        "env set" => Some("\
Notes:
    - Writes only `~/.aikey/proxy.env`.
    - Does not modify `~/.aikey/active.env`.
    - Merge-updates the existing file instead of replacing it completely.
    - Accepts `KEY=VALUE`, multiple pairs, optional `export` prefixes, and semicolon-separated input.
    - If the existing `proxy.env` is invalid, AiKey stops and asks the user to fix it first.
    - Restart the proxy after changes: `aikey proxy restart`"),

        "proxy start" => Some("\
Notes:
    - Starts the proxy with vault authentication.
    - Starts in background by default.
    - Use --foreground for debugging."),

        "whoami" => Some("\
Notes:
    - Includes vault state, logged-in account, control URL, active key, and sync version.
    - Useful for confirming the current working context before running or debugging."),

        "get" => Some("\
Notes:
    - Default clipboard clear timeout is 30 seconds.
    - Use --timeout 0 to disable auto-clear.
    - In JSON mode, AiKey returns the plaintext value instead of using the clipboard."),

        "run" => Some("\
Notes:
    - Use -- to separate AiKey flags from the child command.
    - Resolution path without --provider:
      1. project config if present
      2. active key via proxy if configured
      3. vault-auto fallback
    - --dry-run prints what would be injected without executing.
    - --direct bypasses the proxy and injects the real decrypted key directly.
    - --direct only supports active personal keys."),

        "key list" => Some("\
Notes:
    - Lists team-managed virtual keys.
    - May refresh metadata from server when possible."),

        "key sync" => Some("\
Notes:
    - Forces a full metadata refresh and downloads missing key material.
    - Requires the vault password."),

        "quickstart" => Some("\
Notes:
    - Initializes the vault if it does not exist.
    - Creates `aikey.config.json` if needed.
    - This is an onboarding wizard, not a required prerequisite for normal commands."),

        "project map" => Some("\
Notes:
    - Binds an env var name to a vault alias.
    - Can also write envMappings entries when the mapping flags are provided.
    - Requires an existing `aikey.config.json`."),

        "update" => Some("\
Notes:
    - In interactive mode, AiKey asks for confirmation first.
    - If the proxy is already running, AiKey may warn that restart is needed."),

        "delete" => Some("\
Notes:
    - In interactive mode, AiKey asks for confirmation first.
    - If the proxy is already running, AiKey may warn that restart is needed."),

        "export" => Some("\
Notes:
    - <PATTERN> supports matching such as '*' or 'api_*'.
    - Requires both the vault password and a separate export password.
    - Treat the output file as sensitive material."),

        "change-password" => Some("\
Notes:
    - Prompts for old password, new password, and confirmation.
    - Invalidates the cached local session after success."),

        "logout" => Some("\
Notes:
    - Shortcut for `aikey account logout`.
    - Does not delete local vault contents."),

        "secret set" | "secret upsert" => Some("\
Notes:
    - --from-stdin is required for security."),

        "logs" => Some("\
Notes:
    - Default limit is 20."),

        _ => None,
    }
}

/// Fuzzy similarity in [0.0, 1.0] combining prefix match, edit distance, and bigrams.
fn print_short_help() {
    let b = "\x1b[1m";
    let r = "\x1b[0m";
    println!("\
AiKey - Secure local-first secret management

Usage: aikey [OPTIONS] [COMMAND]

Commands:
  {b}add{r} <alias>              Save a new secret to the vault
  {b}list{r}                     Show all personal and team keys
  {b}test{r} <alias>             Test whether a stored API key alias is working
  {b}use{r} [alias]              Select the active key for routing (shortcut for `key use`)
  {b}login{r}                    Log in to aikey service (shortcut for `account login`)
  {b}browse{r} [page]            Open the User Console in your default browser
  {b}doctor{r}                   Check system health, connectivity, and configuration
  {b}env{r} [command]            View or set proxy environment variables
  {b}proxy{r} <command>          Manage the local proxy process
  {b}status{r}                   Show a summary of gateway, login, keys, and providers
  {b}whoami{r}                   Show your current login, active key, and vault status
  {b}get{r} <alias>              Retrieve a secret and copy it to the clipboard
  {b}run{r} -- <command>         Run a command with secrets injected as environment variables
  {b}key{r} <command>            Manage API keys (rotate, list, sync, use)
  {b}quickstart{r}               Initialize vault and set up a new project
  {b}project{r} <command>        Manage project configuration
  {b}logs{r}                     Show recent activity logs
  {b}update{r} <alias>           Update an existing secret
  {b}delete{r} <alias>           Delete a secret from the vault
  {b}export{r} <pattern> <file>  Export secrets to an encrypted backup file
  {b}change-password{r}          Change the vault master password
  {b}account{r} <command>        Manage your aikey account session
  {b}logout{r}                   Log out of the current session (shortcut for `account logout`)
  {b}secret{r} <command>         Manage secrets and platform-backed secret actions
  {b}help{r}                     Show this help message or help for a command

Options:
      --password-stdin  Read password from stdin instead of prompting
      --json            Output in JSON format (where supported)
  -V, --version         Print version information
  -h, --help            Print help
      --detail          Print detailed help for all commands");
}

fn print_detailed_help() {
    print!("\
AiKey - Secure local-first secret management

Usage:
  aikey [OPTIONS] <COMMAND>

Global options:
  --password-stdin   Read the vault master password from stdin
  --json             Output JSON where supported
  -V, --version      Print version information
  -h, --help         Print help

Detailed Commands

[1madd[0m
  Save a new personal key/secret to the local vault.

  Usage:
    aikey add [--provider <PROVIDER>] <ALIAS>

  Notes:
    - Stores a new local secret under <ALIAS>.
    - --provider binds the secret to a provider such as openai or anthropic.
    - On TTY, the secret value is entered interactively.
    - In non-interactive mode, the secret value is read from stdin.
    - In interactive mode, AiKey may run connectivity checks before saving.

[1mlist[0m
  Show all personal and team keys in one view.

  Usage:
    aikey list

  Notes:
    - Shows both Personal Keys and Team Keys.
    - Team keys are filtered to active keys only.
    - May perform a lightweight sync first.
    - If server state changed, AiKey may prompt for the vault password to complete a full sync.
    - If the control service is unreachable, AiKey falls back to local cache.

[1mtest[0m
  Test whether a stored API key alias is reachable and usable.

  Usage:
    aikey test [--provider <PROVIDER>] <ALIAS>

  Notes:
    - <ALIAS> is the stored key alias.
    - --provider overrides the stored provider for this test only.
    - The test may include TCP reachability, API probe, chat/completion probe, and proxy probe.
    - If no provider metadata is stored, AiKey may test multiple known providers.

[1muse[0m
  Activate the current key for routing.

  Usage:
    aikey use [--no-hook] [--provider [<PROVIDER>]] [ALIAS_OR_ID]

  Notes:
    - Accepts either a team key alias/ID or a personal key alias.
    - If ALIAS_OR_ID is omitted on a TTY, AiKey opens an interactive picker.
    - In non-interactive mode, ALIAS_OR_ID is required.
    - AiKey ensures the local proxy is running before activation.
    - --provider <PROVIDER> narrows a personal key to a specific provider.
    - --provider with no value opens an interactive provider selector.
    - --no-hook skips shell hook installation.

[1mlogin[0m
  Log in to the control service.

  Usage:
    aikey login [--control-url <URL>] [--token <TOKEN>] [--email <EMAIL>]

  Notes:
    - Shortcut for `aikey account login`.
    - Default flow uses browser + email activation.
    - --token is the copy-paste fallback for non-completing browser flow.
    - Control URL precedence:
      1. --control-url
      2. AIKEY_CONTROL_URL
      3. saved local config
      4. interactive prompt
    - --email pre-fills the login page.

[1mbrowse[0m
  Open the User Console in the default browser.

  Usage:
    aikey browse [--port <PORT>] [PAGE]

  Arguments:
    PAGE: overview | keys | account | usage

  Notes:
    - In local mode, AiKey can open the local console directly.
    - In team/trial mode, AiKey requires a valid account session.
    - If the control URL is local, AiKey may auto-detect common dev ports such as 3000 and 5173.
    - --port forces a specific local web port.

[1mdoctor[0m
  Check system health, connectivity, and configuration.

  Usage:
    aikey doctor

  Notes:
    - Checks include internet reachability, vault presence, session cache, proxy status,
      provider/proxy connectivity, shell hook state, and vault WAL size.
    - In interactive mode, AiKey may try to restart the proxy automatically.
    - In interactive mode, AiKey may also try to install the shell hook if missing.

[1menv[0m
  View or set proxy environment variables.

  Usage:
    aikey env [COMMAND]

  Notes:
    - `aikey env` shows both `~/.aikey/active.env` and `~/.aikey/proxy.env`.
    - `active.env` is the shell-facing derived environment.
    - `proxy.env` is the user-managed environment file for the `aikey-proxy` process.
    - Values are masked on display when the variable name looks sensitive.
    - If `proxy.env` exists and is valid, AiKey also shows entry count and a short config hash.

  Subcommands:
    [1mset[0m
      Usage:
        aikey env set -- KEY=VALUE [KEY2=VALUE2 ...]
      Notes:
        - Writes only `~/.aikey/proxy.env`.
        - Does not modify `~/.aikey/active.env`.
        - Merge-updates the existing file instead of replacing it completely.
        - Accepts `KEY=VALUE`, multiple pairs, optional `export` prefixes, and semicolon-separated input.
        - If the existing `proxy.env` is invalid, AiKey stops and asks the user to fix it first.
        - Restart the proxy after changes:
          `aikey proxy restart`

[1mproxy[0m
  Manage the local aikey-proxy process.

  Usage:
    aikey proxy <SUBCOMMAND>

  Subcommands:
    [1mstart[0m
      Usage:
        aikey proxy start [--config <CONFIG>] [--foreground]
      Notes:
        - Starts the proxy with vault authentication.
        - Starts in background by default.
        - Use --foreground for debugging.

    [1mstop[0m
      Usage:
        aikey proxy stop

    [1mstatus[0m
      Usage:
        aikey proxy status

    [1mrestart[0m
      Usage:
        aikey proxy restart [--config <CONFIG>]

    [1mverify[0m
      Usage:
        aikey proxy verify

[1mstatus[0m
  Show a combined dashboard: gateway, login, keys, and providers.

  Usage:
    aikey status

  Notes:
    - Gateway section reuses `aikey proxy status` output.
    - Keys section shows personal count, team count (total/active), and active key.
    - Providers section lists all providers discovered from personal and team keys.
    - Supports --json for structured output.

[1mwhoami[0m
  Show the current local identity summary.

  Usage:
    aikey whoami

  Notes:
    - Includes vault state, logged-in account, control URL, active key, and sync version.
    - Useful for confirming the current working context before running or debugging.

[1mget[0m
  Retrieve a secret and copy it to the clipboard.

  Usage:
    aikey get [-t <TIMEOUT>] <ALIAS>

  Notes:
    - Default clipboard clear timeout is 30 seconds.
    - Use --timeout 0 to disable auto-clear.
    - In JSON mode, AiKey returns the plaintext value instead of using the clipboard.

[1mrun[0m
  Execute a command with resolved secrets injected as environment variables.

  Usage:
    aikey run [--provider <PROVIDER>] [--logical-model <LOGICAL_MODEL>] [--model <MODEL>] [--tenant <TENANT>] [--profile <PROFILE>] [--dry-run] [--direct] -- <COMMAND>...

  Notes:
    - Use -- to separate AiKey flags from the child command.
    - Resolution path without --provider:
      1. project config if present
      2. active key via proxy if configured
      3. vault-auto fallback
    - --dry-run prints what would be injected without executing.
    - --direct bypasses the proxy and injects the real decrypted key directly.
    - --direct only supports active personal keys.

[1mkey[0m
  Manage team-key lifecycle and local team-key metadata.

  Usage:
    aikey key <SUBCOMMAND>

  Subcommands:
    [1mlist[0m
      Usage:
        aikey key list
      Notes:
        - Lists team-managed virtual keys.
        - May refresh metadata from server when possible.

    [1msync[0m
      Usage:
        aikey key sync
      Notes:
        - Forces a full metadata refresh and downloads missing key material.
        - Requires the vault password.

    [1muse[0m
      Usage:
        aikey key use [--no-hook] <ALIAS_OR_ID>

    [1mrotate[0m
      Usage:
        aikey key rotate [--from-stdin] <NAME>

    [1malias[0m
      Usage:
        aikey key alias <OLD_ALIAS> <NEW_ALIAS>

[1mquickstart[0m
  Initialize vault and set up a new project.

  Usage:
    aikey quickstart

  Notes:
    - Initializes the vault if it does not exist.
    - Creates `aikey.config.json` if needed.
    - This is an onboarding wizard, not a required prerequisite for normal commands.

[1mproject[0m
  Manage optional project configuration.

  Usage:
    aikey project <SUBCOMMAND>

  Subcommands:
    [1minit[0m
      Usage:
        aikey project init

    [1mstatus[0m
      Usage:
        aikey project status

    [1mmap[0m
      Usage:
        aikey project map [--env <ENV>] [--provider <PROVIDER>] [--model <MODEL>] [--key-alias <ALIAS>] [--impl-id <IMPL>] <VAR> <ALIAS>
      Notes:
        - Binds an env var name to a vault alias.
        - Can also write envMappings entries when the mapping flags are provided.
        - Requires an existing `aikey.config.json`.

[1mlogs[0m
  Show recent local activity events.

  Usage:
    aikey logs [--limit <LIMIT>]

  Notes:
    - Default limit is 20.

[1mupdate[0m
  Replace the value of an existing local secret.

  Usage:
    aikey update <ALIAS>

  Notes:
    - In interactive mode, AiKey asks for confirmation first.
    - If the proxy is already running, AiKey may warn that restart is needed.

[1mdelete[0m
  Remove a local secret from the vault.

  Usage:
    aikey delete <ALIAS>

  Notes:
    - In interactive mode, AiKey asks for confirmation first.
    - If the proxy is already running, AiKey may warn that restart is needed.

[1mexport[0m
  Export selected secrets to an encrypted backup file.

  Usage:
    aikey export <PATTERN> <OUTPUT>

  Notes:
    - <PATTERN> supports matching such as \"*\" or \"api_*\".
    - Requires both the vault password and a separate export password.
    - Treat the output file as sensitive material.

[1mchange-password[0m
  Change the vault master password.

  Usage:
    aikey change-password

  Notes:
    - Prompts for old password, new password, and confirmation.
    - Invalidates the cached local session after success.

[1maccount[0m
  Manage the current control-service account session.

  Usage:
    aikey account <SUBCOMMAND>

  Subcommands:
    [1mlogin[0m
      Usage:
        aikey account login [--control-url <URL>] [--token <TOKEN>] [--email <EMAIL>]

    [1mstatus[0m
      Usage:
        aikey account status

    [1mlogout[0m
      Usage:
        aikey account logout

    [1mset-url[0m
      Usage:
        aikey account set-url <URL>

[1mlogout[0m
  Log out of the current account session.

  Usage:
    aikey logout

  Notes:
    - Shortcut for `aikey account logout`.
    - Does not delete local vault contents.

[1msecret[0m
  Low-level secret management commands.

  Usage:
    aikey secret <SUBCOMMAND>

  Subcommands:
    [1mset[0m
      Usage:
        aikey secret set --from-stdin [--provider <PROVIDER>] <NAME>
      Notes:
        - --from-stdin is required for security.

    [1mupsert[0m
      Usage:
        aikey secret upsert --from-stdin [--provider <PROVIDER>] <NAME>
      Notes:
        - --from-stdin is required for security.

    [1mlist[0m
      Usage:
        aikey secret list

    [1mdelete[0m
      Usage:
        aikey secret delete <NAME>

[1mhelp[0m
  Show top-level or command-specific help.

  Usage:
    aikey help [COMMAND]
");
}


fn print_banner() {
    use colored::Colorize;
    let version = env!("CARGO_PKG_VERSION");
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    let aikey_home = format!("{}/.aikey", home);

    // Muted gold: RGB(160, 135, 75) — subtle on dark terminals.
    let g = |s: &str| s.truecolor(160, 135, 75);

    eprintln!();
    eprintln!("     {}        {}", g("▄███▄"), g("▄███▄"));
    eprintln!("   {}", g("▄████████▄▄▄▄████████▄"));
    eprintln!("  {}", g("████▀▀▀▀████████▀▀▀▀████"));
    eprintln!("  {}      {}      {}      {}   v{}", g("███"), g("▀████▀"), g("███"), "AiKey CLI".bold(), version);
    eprintln!("  {}  {}   {}   {}  {}      {}", g("███"), g("██"), g("▀██▀"), g("██"), g("███"), "------------------------------------".dimmed());
    eprintln!("  {}  {}  {}  {}  {}      FinOps & AI Governance Center", g("███"), g("██"), g("▄████▄"), g("██"), g("███"));
    eprintln!("  {}    {}    {}      {}", g("███▄"), g("▄██▀▀██▄"), g("▄███"), aikey_home);
    eprintln!("   {}", g("▀███▄▄▄███  ███▄▄▄███▀"));
    eprintln!("     {}    {}", g("▀▀████▀"), g("▀████▀▀"));
    eprintln!();
}

/// Format a unix timestamp as YYYY/MM/DD.
fn format_date(ts: i64) -> String {
    use std::time::{UNIX_EPOCH, Duration};
    let d = UNIX_EPOCH + Duration::from_secs(ts as u64);
    let secs = d.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // Days since epoch → year/month/day (civil calendar).
    let days = (secs / 86400) as i64;
    // Algorithm from Howard Hinnant's chrono-compatible date library.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}/{:02}/{:02}", y, m, d)
}

fn similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    if a == b { return 1.0; }
    if b.starts_with(a) || a.starts_with(b) { return 0.95; }

    // Edit distance (insertions/deletions/substitutions), normalised.
    let ed = edit_distance(a, b);
    let max_len = a.len().max(b.len()) as f64;
    let ed_score = 1.0 - (ed as f64 / max_len);

    // Bigram Jaccard.
    let bigram_score = {
        fn bigrams(s: &str) -> std::collections::HashSet<(char, char)> {
            let ch: Vec<char> = s.chars().collect();
            ch.windows(2).map(|w| (w[0], w[1])).collect()
        }
        let ba = bigrams(a);
        let bb = bigrams(b);
        if ba.is_empty() || bb.is_empty() { 0.0 } else {
            let i = ba.intersection(&bb).count() as f64;
            let u = ba.union(&bb).count() as f64;
            if u == 0.0 { 0.0 } else { i / u }
        }
    };

    // Weighted combination: edit distance is more reliable for short tokens.
    0.6 * ed_score + 0.4 * bigram_score
}

/// Simple edit distance (Levenshtein) for short strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i-1] == b[j-1] {
                dp[i-1][j-1]
            } else {
                1 + dp[i-1][j].min(dp[i][j-1]).min(dp[i-1][j-1])
            };
        }
    }
    dp[m][n]
}

/// Resolve a binding's key_source_ref to a human-readable display name.
fn resolve_binding_display_name(source_type: &str, source_ref: &str) -> String {
    if source_type == "team" {
        if let Ok(Some(entry)) = storage::get_virtual_key_cache(source_ref) {
            return entry.local_alias.unwrap_or(entry.alias);
        }
    }
    source_ref.to_string()
}

fn prompt_vault_password(password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    // Skip cache when reading from stdin or in automated test mode.
    if !password_stdin && std::env::var("AK_TEST_PASSWORD").is_err() {
        if let Some(cached) = session::try_get() {
            // Slide the TTL forward on each successful cached use.
            session::refresh();
            return Ok(cached);
        }
    }
    let pw = prompt_vault_password_fresh(password_stdin, json_mode)?;
    // One-time prompt: ask user which session backend to use (keychain/file/disabled).
    session::maybe_configure_backend();
    // Store in cache after a fresh prompt (low-sensitivity path).
    session::store(&pw);
    Ok(pw)
}

/// Always prompts for the master password — never reads from cache.
/// Use for HIGH-sensitivity commands (add, delete, update, import, export,
/// secret set/upsert/delete, change-password, exec, run --direct).
fn prompt_vault_password_fresh(password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    let vault_exists = storage::get_vault_path()
        .map(|p| p.exists())
        .unwrap_or(false);
    let prompt = if vault_exists {
        "\u{1F512} Enter Master Password: "
    } else {
        if !json_mode && !password_stdin && std::env::var("AK_TEST_PASSWORD").is_err() {
            eprintln!("Welcome to aikey! No vault found — setting up for the first time.");
            eprintln!("Choose a master password to protect your API Keys (you cannot recover it if lost).");
        }
        "\u{1F512} Set Master Password: "
    };
    prompt_password_secure(prompt, password_stdin, json_mode)
}

fn prompt_password_secure(prompt: &str, password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    // Check for test password environment variable
    if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        return Ok(SecretString::new(test_password));
    }

    // If password_stdin is true, read directly from stdin without prompt or TTY interaction
    if password_stdin {
        let mut password_raw = Zeroizing::new(String::new());
        io::stdin().read_line(&mut password_raw)?;
        let trimmed = password_raw.trim().to_string();
        return Ok(SecretString::new(trimmed));
    }

    // Interactive TTY path: show `*` per keystroke for visual feedback.
    let prompt_str = if json_mode { "" } else { prompt };
    let password = prompt_hidden(prompt_str).map_err(|e| {
        if e.kind() == io::ErrorKind::Other || e.raw_os_error() == Some(6) {
            io::Error::new(
                io::ErrorKind::Other,
                "aikey requires an interactive terminal to read the master password.\n\
                 Tip: run from a terminal, or set AK_TEST_PASSWORD for scripted use.",
            )
        } else {
            e
        }
    })?;

    // Wrap in Zeroizing for additional in-memory protection
    let password_raw = Zeroizing::new(password);
    let trimmed = password_raw.trim().to_string();
    Ok(SecretString::new(trimmed))
}

/// Show an interactive arrow-key picker with all available personal + team keys.
/// Returns the alias/id that the user selected.
fn pick_key_interactively() -> Result<String, Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Gather personal keys
    let personal = storage::list_entries_with_metadata().unwrap_or_default();
    // Gather team keys
    let team = storage::list_virtual_key_cache().unwrap_or_default();

    if personal.is_empty() && team.is_empty() {
        return Err("No keys found. Add a personal key with `aikey add` or sync team keys with `aikey key sync`.".into());
    }

    // Active key for LOCAL column
    let active_cfg = storage::get_active_key_config().ok().flatten();

    // Build display rows; keep alias/id parallel for lookup after selection.
    // Format: TYPE  ALIAS  PROVIDER / BASE_URL  [active marker]
    let mut items: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    // Track which rows are selectable (false for separator & other-account keys).
    let mut selectable: Vec<bool> = Vec::new();

    // Dynamic column widths based on terminal size.
    // Layout: "personal  " (10) + alias_w + "  " (2) + provider_w + " ◀ active" (9)
    let tw = ui_frame::term_width();
    // Reserve: 10 (type+space) + 2 (gap) + 9 (active marker) + 10 (box borders/margins)
    let available = tw.saturating_sub(31);
    // Split available space: ~40% alias, ~60% provider, with minimums.
    let alias_w = (available * 2 / 5).max(10).min(30);
    let provider_w = available.saturating_sub(alias_w).max(10).min(40);

    for entry in &personal {
        let provider_col = match (&entry.base_url, &entry.provider_code) {
            (Some(url), _) if !url.is_empty() => url.clone(),
            (_, Some(code)) if !code.is_empty() => code.clone(),
            _ => String::new(),
        };
        let is_active = active_cfg.as_ref().map_or(false, |cfg| {
            cfg.key_type == "personal" && cfg.key_ref == entry.alias
        });
        let active_marker = if is_active { " ◀ active" } else { "" };
        let alias_display = if entry.alias.len() > alias_w { &entry.alias[..alias_w] } else { &entry.alias };
        let prov_display = if provider_col.len() > provider_w { &provider_col[..provider_w] } else { &provider_col };
        let row = format!(
            "personal  {:<aw$}  {:<pw$}{}",
            alias_display,
            prov_display,
            active_marker,
            aw = alias_w,
            pw = provider_w,
        );
        items.push(row);
        aliases.push(entry.alias.clone());
        selectable.push(true);
    }

    // Filter out unusable team keys (revoked, expired, stale, etc.).
    // Only show keys that are either usable or belong to another account (for visibility).
    let visible_team: Vec<_> = team.iter()
        .filter(|e| {
            e.key_status == "active"
                && e.local_state != "stale"
                && e.local_state != "disabled_by_key_status"
                && e.local_state != "disabled_by_seat_status"
                && e.local_state != "disabled_by_account_status"
        })
        .collect();

    // Partition: current account (selectable) vs other account (view-only).
    let (own_team, other_account_team): (Vec<_>, Vec<_>) = visible_team.into_iter()
        .partition(|e| e.local_state != "disabled_by_account_scope");

    for e in &own_team {
        let display_name = e.local_alias.as_deref().unwrap_or(e.alias.as_str());
        let is_active = active_cfg.as_ref().map_or(false, |cfg| {
            cfg.key_type == "team" && cfg.key_ref == e.virtual_key_id
        });
        let active_marker = if is_active { " ◀ active" } else { "" };
        let alias_display = if display_name.len() > alias_w { &display_name[..alias_w] } else { display_name };
        let prov_display = if e.provider_code.len() > provider_w { &e.provider_code[..provider_w] } else { &e.provider_code };
        let row = format!(
            "team      {:<aw$}  {:<pw$}{}",
            alias_display,
            prov_display,
            active_marker,
            aw = alias_w,
            pw = provider_w,
        );
        items.push(row);
        aliases.push(e.virtual_key_id.clone());
        selectable.push(true);
    }

    // Other-account keys: shown at the bottom, dimmed, not selectable.
    if !other_account_team.is_empty() {
        let sep = format!("{}", "───── Other accounts (not selectable) ─────".dimmed());
        items.push(sep);
        aliases.push(String::new());
        selectable.push(false);

        for e in &other_account_team {
            let display_name = e.local_alias.as_deref().unwrap_or(e.alias.as_str());
            let alias_display = if display_name.len() > alias_w { &display_name[..alias_w] } else { display_name };
            let prov_display = if e.provider_code.len() > provider_w { &e.provider_code[..provider_w] } else { &e.provider_code };
            let raw = format!(
                "team      {:<aw$}  {:<pw$}  [other account]",
                alias_display,
                prov_display,
                aw = alias_w,
                pw = provider_w,
            );
            items.push(format!("{}", raw.dimmed()));
            aliases.push(e.virtual_key_id.clone());
            selectable.push(false);
        }
    }

    let header = format!("        {:<aw$}  {:<pw$}", "Alias", "Provider / Base URL", aw = alias_w, pw = provider_w);

    // Find initial cursor: prefer the currently active key, else first selectable.
    let initial = active_cfg.as_ref()
        .and_then(|cfg| {
            aliases.iter().position(|a| {
                (cfg.key_type == "team" && *a == cfg.key_ref)
                    || (cfg.key_type == "personal" && *a == cfg.key_ref)
            })
        })
        .and_then(|i| if selectable[i] { Some(i) } else { None })
        .or_else(|| selectable.iter().position(|&s| s))
        .unwrap_or(0);

    match ui_select::box_select(
        "Select a key to activate",
        &header,
        &items,
        &selectable,
        initial,
    )? {
        ui_select::SelectResult::Selected(idx) => Ok(aliases[idx].clone()),
        ui_select::SelectResult::Cancelled => Err("Selection cancelled.".into()),
    }
}

/// Build provider groups and show the provider-tree interactive editor.
/// Returns a list of (provider_code, source_type, source_ref) changes to apply.
fn pick_providers_interactively() -> Result<Vec<(String, String, String)>, Box<dyn std::error::Error>> {
    let personal = storage::list_entries_with_metadata().unwrap_or_default();
    let team = storage::list_virtual_key_cache().unwrap_or_default();

    if personal.is_empty() && team.is_empty() {
        return Err("No keys found. Add a personal key with `aikey add` or sync team keys with `aikey key sync`.".into());
    }

    let bindings = storage::list_provider_bindings(
        profile_activation::DEFAULT_PROFILE
    ).unwrap_or_default();

    // Collect all known provider codes.
    let mut all_providers: Vec<String> = Vec::new();
    let mut add_prov = |code: &str| {
        let lc = code.to_lowercase();
        if !lc.is_empty() && !all_providers.contains(&lc) {
            all_providers.push(lc);
        }
    };
    for e in &personal {
        if let Some(ref sp) = e.supported_providers {
            for p in sp { add_prov(p); }
        } else if let Some(ref code) = e.provider_code {
            add_prov(code);
        }
    }
    let usable_team: Vec<_> = team.iter()
        .filter(|e| e.key_status == "active"
            && !e.local_state.starts_with("disabled_by_")
            && e.local_state != "stale"
            && e.provider_key_ciphertext.is_some())
        .collect();
    for e in &usable_team {
        if !e.supported_providers.is_empty() {
            for p in &e.supported_providers { add_prov(p); }
        } else {
            add_prov(&e.provider_code);
        }
    }
    for b in &bindings {
        add_prov(&b.provider_code);
    }
    all_providers.sort();

    if all_providers.is_empty() {
        return Err("No providers found on any key.".into());
    }

    // Build ProviderGroup for each provider.
    let mut groups: Vec<ui_select::ProviderGroup> = Vec::new();

    for prov in &all_providers {
        let mut candidates: Vec<ui_select::KeyCandidate> = Vec::new();

        for e in &personal {
            let providers = if let Some(ref sp) = e.supported_providers {
                sp.clone()
            } else if let Some(ref code) = e.provider_code {
                vec![code.clone()]
            } else {
                vec![]
            };
            if providers.iter().any(|p| p.to_lowercase() == *prov) {
                candidates.push(ui_select::KeyCandidate {
                    label: e.alias.clone(),
                    source_type: "personal".to_string(),
                    source_ref: e.alias.clone(),
                });
            }
        }

        for e in &usable_team {
            let providers = if !e.supported_providers.is_empty() {
                e.supported_providers.clone()
            } else {
                vec![e.provider_code.clone()]
            };
            if providers.iter().any(|p| p.to_lowercase() == *prov) {
                let label = e.local_alias.as_deref().unwrap_or(e.alias.as_str()).to_string();
                candidates.push(ui_select::KeyCandidate {
                    label,
                    source_type: "team".to_string(),
                    source_ref: e.virtual_key_id.clone(),
                });
            }
        }

        let current_binding = bindings.iter().find(|b| b.provider_code == *prov);
        let selected = current_binding.and_then(|b| {
            candidates.iter().position(|c|
                c.source_type == b.key_source_type && c.source_ref == b.key_source_ref
            )
        });

        groups.push(ui_select::ProviderGroup {
            provider_code: prov.clone(),
            candidates,
            selected,
            expanded: true,
        });
    }

    // Snapshot original selections for diffing.
    let original_selections: Vec<Option<usize>> = groups.iter()
        .map(|g| g.selected)
        .collect();

    match ui_select::provider_tree_select(&mut groups)? {
        ui_select::ProviderTreeResult::Confirmed(updated_groups) => {
            let mut changes: Vec<(String, String, String)> = Vec::new();
            for (i, g) in updated_groups.iter().enumerate() {
                if g.selected != original_selections[i] {
                    if let Some(sel) = g.selected {
                        let c = &g.candidates[sel];
                        changes.push((
                            g.provider_code.clone(),
                            c.source_type.clone(),
                            c.source_ref.clone(),
                        ));
                    }
                }
            }
            Ok(changes)
        }
        ui_select::ProviderTreeResult::Cancelled => {
            eprintln!("  Selection cancelled.");
            Ok(vec![])
        }
    }
}
