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
mod commands_env;
mod commands_proxy;
mod commands_account;
mod platform_client;
mod profiles;
mod core;
mod global_config;
mod providers;
mod resolver;
mod events;
mod observability;
mod ui_frame;
mod ui_select;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::io::{self, IsTerminal, Write};
use zeroize::Zeroizing;
use error_codes::msgs;

use aikeylabs_aikey_cli::prompt_hidden;

#[derive(Parser)]
#[command(name = "aikey", about = "AiKey - Secure local-first secret management", version = "0.2.0", disable_version_flag = true)]
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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the vault (runs automatically on first use)
    #[command(hide = true)]
    Init,
    Add {
        alias: String,
        /// Provider code for proxy routing (e.g. openai, anthropic). Makes this
        /// key selectable via `aikey use` with path-prefix routing in the proxy.
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
    },
    Get {
        alias: String,
        /// Clipboard auto-clear timeout in seconds (default: 30, 0 to disable)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
    Delete {
        alias: String,
    },
    #[command(alias = "ls")]
    List,
    Update {
        alias: String,
    },
    Export {
        /// Pattern to match secrets (e.g., "*", "api_*")
        pattern: String,
        /// Output file path (.akb format)
        output: String,
    },
    Import {
        /// Input file path (.akb format)
        file: String,
    },
    /// Execute a command with secrets injected as environment variables
    Exec {
        /// Environment variable mappings in the form ENV_VAR=alias
        #[arg(short, long = "env", value_name = "ENV_VAR=alias")]
        env_mappings: Vec<String>,
        /// The command to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Execute a command with all secrets automatically injected as environment variables
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
    /// Change the master password
    ChangePassword,
    /// Secret management commands (Platform API v0.2)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Profile management commands
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Environment variable management commands
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Project configuration commands
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Provider management commands
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },
    /// Quick setup wizard for new projects
    Quickstart,
    /// Show local usage statistics
    Stats,
    /// Show recent run/exec event log
    Logs {
        /// Number of entries to show (default: 20)
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },
    /// Manage API keys (rotate, list, sync, use)
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Manage your aikey-control-service account session
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Log in to an aikey-control-service (shortcut for `account login`)
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
    /// Log out from the current session (shortcut for `account logout`)
    Logout,
    /// Activate a key for proxy routing (shortcut for `key use`)
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
    /// Open the User Console in the default browser (restores login session)
    Browse {
        /// Page to open: overview (default), keys, account, usage
        page: Option<String>,
        /// Override port for dev mode (e.g. --port 3000 for Vite dev server)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Show current identity: login session, active key, and vault state
    Whoami,
    /// Run diagnostics and health checks
    Doctor,
    /// Show project/env/profile status and resolution summary (no secrets)
    Status,
    /// Start an interactive shell with non-sensitive context (advanced mode)
    Shell,
    /// Manage the local aikey-proxy process
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Start the local aikey-proxy (authenticates once, no separate password needed)
    Start {
        /// Path to aikey-proxy.yaml (auto-detected if omitted)
        #[arg(long)]
        config: Option<String>,
        /// Run in background and return immediately
        #[arg(short, long)]
        detach: bool,
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
enum ProfileAction {
    /// List all profiles
    List,
    /// Switch to a different profile
    Use { name: String },
    /// Show profile details
    Show { name: String },
    /// Show current active profile
    Current,
    /// Create a new profile
    Create { name: String },
    /// Delete a profile
    Delete { name: String },
}

#[derive(Subcommand)]
enum EnvAction {
    /// Generate or update .env file from project config
    Generate {
        /// Preview changes without writing
        #[arg(long)]
        dry_run: bool,
        /// Override the target .env file path
        #[arg(long)]
        env_file: Option<String>,
    },
    /// Run a command with secrets injected, or show an injection preview
    Inject {
        /// Command to run with secrets injected (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// Logical model name for narrowing injection (e.g. chat-main, embeddings)
        #[arg(long, value_name = "LOGICAL_MODEL")]
        logical_model: Option<String>,
        /// Tenant override for multi-tenant key resolution
        #[arg(long, value_name = "TENANT")]
        tenant: Option<String>,
        /// Show what would be resolved without executing the command
        #[arg(long)]
        dry_run: bool,
    },
    /// Check if all required environment variables can be resolved
    Check,
    /// Switch the active logical environment (e.g. dev, staging, prod)
    Use {
        /// Environment name to activate
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

#[derive(Subcommand)]
enum ProviderAction {
    /// Add a provider to the project config
    Add {
        /// Provider name (e.g. openai, anthropic)
        name: String,
        /// Vault alias for the provider's API key
        #[arg(long, value_name = "ALIAS")]
        key_alias: String,
        /// Default model for this provider
        #[arg(long, value_name = "MODEL")]
        default_model: Option<String>,
    },
    /// Remove a provider from the profile config
    Rm {
        /// Provider name to remove
        name: String,
    },
    /// List providers in the project config
    Ls,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise process-global trace context (trace_id, span_id, command_id).
    // This must be called before any logging or proxy calls.
    observability::init_trace();

    let cli = Cli::try_parse().unwrap_or_else(|err| {
        // Intercept "unrecognized subcommand" errors and show a friendly message
        // with fuzzy suggestions instead of the raw clap output.
        use clap::error::ErrorKind;
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
                "add", "get", "delete", "list", "update", "export", "import",
                "exec", "run", "use", "whoami", "login", "logout", "browse",
                "init", "status", "doctor", "shell", "key", "account", "secret",
                "profile", "env", "project", "provider", "proxy",
                "change-password", "quickstart", "stats", "logs",
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
            println!("aikey {}", VERSION);
        }
        return Ok(());
    }

    // Ensure a command was provided
    if cli.command.is_none() {
        if cli.json {
            json_output::error("No command specified. Use --help for usage information.", 1);
        } else {
            eprintln!("Error: No command specified. Use --help for usage information.");
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
            Commands::Add { .. } => "add".to_string(),
            Commands::Get { .. } => "get".to_string(),
            Commands::Delete { .. } => "delete".to_string(),
            Commands::List => "list".to_string(),
            Commands::Update { .. } => "update".to_string(),
            Commands::Export { .. } => "export".to_string(),
            Commands::Import { .. } => "import".to_string(),
            Commands::Exec { .. } => "exec".to_string(),
            Commands::Run { .. } => "run".to_string(),
            Commands::ChangePassword => "change-password".to_string(),
            Commands::Secret { action } => format!("secret.{}", match action {
                SecretAction::Set { .. } => "set",
                SecretAction::Upsert { .. } => "upsert",
                SecretAction::List => "list",
                SecretAction::Delete { .. } => "delete",
            }),
            Commands::Profile { action } => format!("profile.{}", match action {
                ProfileAction::List => "list",
                ProfileAction::Use { .. } => "use",
                ProfileAction::Show { .. } => "show",
                ProfileAction::Current => "current",
                ProfileAction::Create { .. } => "create",
                ProfileAction::Delete { .. } => "delete",
            }),
            Commands::Env { action } => format!("env.{}", match action {
                EnvAction::Generate { .. } => "generate",
                EnvAction::Inject { .. } => "inject",
                EnvAction::Check => "check",
                EnvAction::Use { .. } => "use",
            }),
            Commands::Project { action } => format!("project.{}", match action {
                ProjectAction::Init => "init",
                ProjectAction::Status => "status",
                ProjectAction::Map { .. } => "map",
            }),
            Commands::Provider { action } => format!("provider.{}", match action {
                ProviderAction::Add { .. } => "add",
                ProviderAction::Rm { .. } => "rm",
                ProviderAction::Ls => "ls",
            }),
            Commands::Quickstart => "quickstart".to_string(),
            Commands::Stats => "stats".to_string(),
            Commands::Logs { .. } => "logs".to_string(),
            Commands::Key { action } => format!("key.{}", match action {
                KeyAction::Rotate { .. } => "rotate",
                KeyAction::List => "list",
                KeyAction::Sync => "sync",
                KeyAction::Use { .. } => "use",
                KeyAction::Alias { .. } => "alias",
            }),
            Commands::Use { .. } => "key.use".to_string(),
            Commands::Whoami => "whoami".to_string(),
            Commands::Account { action } => format!("account.{}", match action {
                AccountAction::Login { .. } => "login",
                AccountAction::Status => "status",
                AccountAction::Logout => "logout",
                AccountAction::SetUrl { .. } => "set-url",
            }),
            Commands::Login { .. } => "account.login".to_string(),
            Commands::Logout => "account.logout".to_string(),
            Commands::Browse { .. } => "browse".to_string(),
            Commands::Doctor => "doctor".to_string(),
            Commands::Status => "status".to_string(),
            Commands::Shell => "shell".to_string(),
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
        Commands::Proxy { .. } | Commands::Init => {}
        _ => { commands_proxy::try_auto_start_from_env(); }
    }

    // Non-blocking snapshot sync: checks server sync_version and pulls fresh
    // key state if it has changed since the last local pull. Skipped for proxy
    // lifecycle and init commands which either predate the vault or manage the
    // process themselves.
    match command {
        Commands::Proxy { .. } | Commands::Init => {}
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
        Commands::Add { alias, provider } => {
            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

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

            let result = executor::add_secret(alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(alias), result.is_ok());

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            // Step 3: resolve provider + base_url.
            // --provider flag takes precedence; otherwise prompt interactively on TTY.
            let (resolved_provider, resolved_base_url): (Option<String>, Option<String>) =
                if let Some(code) = provider {
                    // Flag provided — use it, no base_url prompt.
                    (Some(code.to_lowercase()), None)
                } else if std::io::stdin().is_terminal() && !cli.json {
                    // Interactive TTY: show a numbered provider menu.
                    use colored::Colorize;
                    const KNOWN: &[(&str, &str)] = &[
                        ("anthropic", "https://api.anthropic.com"),
                        ("openai",    "https://api.openai.com"),
                        ("google",    "https://generativelanguage.googleapis.com"),
                        ("deepseek",  "https://api.deepseek.com"),
                        ("kimi",      "https://api.moonshot.cn"),
                    ];
                    println!();
                    println!("Select provider:");
                    for (i, (name, _)) in KNOWN.iter().enumerate() {
                        println!("  {}  {}", format!("[{}]", i + 1).dimmed(), name);
                    }
                    println!("  {}  other / custom base URL", "[6]".dimmed());
                    print!("Choice (or press Enter to skip): ");
                    io::stdout().flush()?;
                    let mut choice = String::new();
                    io::stdin().read_line(&mut choice)?;
                    let choice = choice.trim();

                    if choice.is_empty() {
                        (None, None)
                    } else if let Ok(n) = choice.parse::<usize>() {
                        if n >= 1 && n <= KNOWN.len() {
                            let (name, default_url) = KNOWN[n - 1];
                            println!();
                            println!("  Using {}  →  {}", name.bold(), default_url.dimmed());
                            print!("  Custom URL (press Enter to use default): ");
                            io::stdout().flush()?;
                            let mut url_input = String::new();
                            io::stdin().read_line(&mut url_input)?;
                            let url_input = url_input.trim().to_string();
                            let base_url = if url_input.is_empty() {
                                None  // use provider default; proxy falls back automatically
                            } else {
                                Some(url_input)
                            };
                            (Some(name.to_string()), base_url)
                        } else if n == KNOWN.len() + 1 {
                            // Custom — provider code is optional (leave blank for a generic gateway).
                            print!("Provider code (e.g. openai, leave blank for generic gateway): ");
                            io::stdout().flush()?;
                            let mut pcode = String::new();
                            io::stdin().read_line(&mut pcode)?;
                            let pcode = pcode.trim().to_lowercase();
                            print!("Base URL: ");
                            io::stdout().flush()?;
                            let mut url = String::new();
                            io::stdin().read_line(&mut url)?;
                            let url = url.trim().to_string();
                            (
                                if pcode.is_empty() { None } else { Some(pcode) },
                                if url.is_empty() { None } else { Some(url) },
                            )
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                } else {
                    // Non-TTY / JSON: no interactive prompt, provider stays unset.
                    (None, None)
                };

            if let Some(ref code) = resolved_provider {
                let _ = storage::set_entry_provider_code(alias, Some(code.as_str()));
            }
            if let Some(ref url) = resolved_base_url {
                let _ = storage::set_entry_base_url(alias, Some(url.as_str()));
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "Secret added successfully",
                    "provider": resolved_provider,
                    "base_url": resolved_base_url,
                }));
            } else {
                use colored::Colorize;
                eprintln!("API Key '{}' added.", alias.bold());
                if let Some(ref code) = resolved_provider {
                    eprintln!("  provider: {}", code.dimmed());
                }
                if let Some(ref url) = resolved_base_url {
                    eprintln!("  base_url: {}", url.dimmed());
                }
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
            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;
            let result = executor::delete_secret(alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(alias), result.is_ok());

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
                    "message": "API Key deleted successfully"
                }));
            } else {
                println!("Secret deleted.");
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

                // Read active key config once for LOCAL column.
                let active_cfg = storage::get_active_key_config().ok().flatten();

                let mut rows: Vec<String> = Vec::new();

                // ── Personal keys section ──────────────────────────────
                rows.push(format!("\u{1F4CB} Personal Keys ({})", entries.len()));
                rows.push(format!("{:<20}  {:<28}  {:<10}  {}",
                    "ALIAS", "PROVIDER / BASE_URL", "LOCAL", "KEY"));
                rows.push("\u{2500}".repeat(80));
                if entries.is_empty() {
                    rows.push("(none)".to_string());
                } else {
                    for entry in &entries {
                        let provider_col = match (&entry.base_url, &entry.provider_code) {
                            (Some(url), _) if !url.is_empty() => url.as_str().to_string(),
                            (_, Some(code)) if !code.is_empty() => code.clone(),
                            _ => String::new(),
                        };
                        let is_active = active_cfg.as_ref().map_or(false, |cfg| {
                            cfg.key_type == "personal" && cfg.key_ref == entry.alias
                        });
                        let local_col = if is_active {
                            format!("{:<10}", "active").green().to_string()
                        } else {
                            format!("{:<10}", "")
                        };
                        rows.push(format!("{:<20}  {:<28}  {}  {}",
                            &entry.alias,
                            if provider_col.len() > 28 { &provider_col[..28] } else { &provider_col },
                            local_col,
                            "\u{2713}",
                        ));
                    }
                }

                // ── Blank separator ──────────────────────────────────
                rows.push(String::new());

                // ── Team keys section ────────────────────────────────
                rows.push(format!("\u{1F465} Team Keys ({})", managed.len()));
                rows.push(format!("{:<24}  {:<16}  {:<16}  {:<16}  {:<4}  {}",
                    "ALIAS", "PROVIDER", "LOCAL", "REMOTE STATUS", "KEY", "SHARE"));
                rows.push("\u{2500}".repeat(80));
                if managed.is_empty() {
                    rows.push("(none)".to_string());
                } else {
                    for e in &managed {
                        let has_key = if e.provider_key_ciphertext.is_some() { "\u{2713}" } else { "" };
                        let display_name = e.local_alias.as_deref().unwrap_or(e.alias.as_str());
                        let raw_alias = if display_name.len() > 24 { &display_name[..24] } else { display_name };
                        let server_alias_hint = if e.local_alias.is_some() {
                            format!(" (\u{2190} {})", e.alias)
                        } else {
                            String::new()
                        };
                        let local_str = match e.local_state.as_str() {
                            "active"                     => format!("{:<16}", "active").green().to_string(),
                            "synced_inactive"            => format!("{:<16}", "inactive").dimmed().to_string(),
                            "disabled_by_account_scope"  => format!("{:<16}", "other-account").yellow().to_string(),
                            "disabled_by_account_status" => format!("{:<16}", "acct-disabled").red().to_string(),
                            "disabled_by_seat_status"    => format!("{:<16}", "seat-disabled").red().to_string(),
                            "disabled_by_key_status"     => format!("{:<16}", "key-disabled").red().to_string(),
                            "prompt_dismissed"           => format!("{:<16}", "dismissed").dimmed().to_string(),
                            "stale"                      => format!("{:<16}", "stale").dimmed().to_string(),
                            other                        => format!("{:<16}", other).dimmed().to_string(),
                        };
                        let status_str = &e.key_status;
                        let share = match e.share_status.as_str() {
                            "pending_claim" => "pending \u{2190}".yellow().to_string(),
                            _ => String::new(),
                        };
                        rows.push(format!("{:<24}  {:<16}  {}  {}  {:<4}  {}{}",
                            raw_alias, &e.provider_code, local_str, status_str, has_key, share, server_alias_hint));
                    }
                }

                ui_frame::print_box(
                    "\u{1F511}",
                    "Keys",
                    &rows,
                );
            }
        }
        Commands::Update { alias } => {
            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else if std::io::stdin().is_terminal() {
                // Hidden prompt on TTY
                let val = prompt_hidden("\u{1F511} Enter New Secret: ")
                    .map_err(|e| format!("Failed to read secret value: {}", e))?;
                Zeroizing::new(val)
            } else {
                // Plain stdin for pipes / automation
                if !cli.json {
                    print!("\u{1F511} Enter New Secret: ");
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
                    "message": "Secret updated successfully"
                }));
            } else {
                eprintln!("API Key '{}' updated successfully", alias);
                commands_proxy::maybe_warn_stale();
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
        Commands::Import { file } => {
            let export_password = prompt_password_secure("\u{1F512} Enter Export Password: ", cli.password_stdin, cli.json)?;
            let vault_password = prompt_password_secure("\u{1F512} Enter Master Password: ", cli.password_stdin, cli.json)?;
            let input_path = std::path::Path::new(file);

            let result = synapse::import_vault(input_path, &export_password, &vault_password);
            let _ = audit::log_audit_event(&vault_password, audit::AuditOperation::Import, Some(file), result.is_ok());

            let import_result = match result {
                Ok(r) => r,
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
                    "added": import_result.added,
                    "updated": import_result.updated,
                    "skipped": import_result.skipped
                }));
            } else {
                eprintln!("Import complete:");
                eprintln!("  Added: {}", import_result.added);
                eprintln!("  Updated: {}", import_result.updated);
                eprintln!("  Skipped: {}", import_result.skipped);
            }
        }
        Commands::Exec { env_mappings, command } => {
            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            let result = executor::exec_with_env(env_mappings, &password, command);

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
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
                    } else if storage::get_active_key_config().ok().flatten().is_some() {
                        // Active key exists (team or personal) — route via proxy.
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
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("API Key '{}' deleted successfully", name);
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
        Commands::Profile { action } => {
            match action {
                ProfileAction::List => {
                    let profiles = storage::get_all_profiles()
                        .map(|ps| ps.into_iter().map(|p| p.name).collect::<Vec<_>>());
                    match profiles {
                        Ok(profiles) => {
                            if cli.json {
                                let profiles_json: Vec<_> = profiles
                                    .iter()
                                    .map(|name| serde_json::json!({
                                        "name": name,
                                        "description": serde_json::Value::Null
                                    }))
                                    .collect();
                                json_output::print_json(serde_json::Value::Array(profiles_json));
                            } else {
                                if profiles.is_empty() {
                                    println!("No profiles configured.");
                                } else {
                                    println!("Profiles:");
                                    for profile in profiles {
                                        println!("  {}", profile);
                                    }
                                }
                            }
                        }
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
                    }
                }
                ProfileAction::Use { name } => {
                    match storage::set_active_profile(name) {
                        Ok(profile) => {
                            let _ = global_config::set_current_profile(&profile.name);
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "profile": profile.name
                                }));
                            } else {
                                println!("Switched to profile: {}", profile.name);
                            }
                        }
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
                    }
                }
                ProfileAction::Show { name } => {
                    let profiles = storage::get_all_profiles()
                        .map(|ps| ps.into_iter().map(|p| p.name).collect::<Vec<_>>());
                    match profiles {
                        Ok(profiles) => {
                            if profiles.contains(name) {
                                if cli.json {
                                    json_output::success(serde_json::json!({
                                        "profile": name
                                    }));
                                } else {
                                    println!("Profile: {}", name);
                                }
                            } else {
                                let err_msg = format!("Profile '{}' not found", name);
                                if cli.json {
                                    json_output::error(&err_msg, 1);
                                } else {
                                    return Err(err_msg.into());
                                }
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                json_output::error(&e, 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                ProfileAction::Current => {
                    match global_config::get_current_profile() {
                        Ok(Some(profile_name)) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "profile": profile_name
                                }));
                            } else {
                                println!("Current profile: {}", profile_name);
                            }
                        }
                        Ok(None) => {
                            if cli.json {
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "profile": serde_json::Value::Null,
                                    "code": error_codes::ErrorCode::NoActiveProfile.as_str()
                                }), 1);
                            } else {
                                return Err("No active profile set".into());
                            }
                        }
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
                    }
                }
                ProfileAction::Create { name } => {
                    match storage::create_profile(name) {
                        Ok(profile) => {
                            if cli.json {
                                json_output::success(serde_json::json!({
                                    "ok": true,
                                    "profile": profile.name
                                }));
                            } else {
                                println!("Profile '{}' created successfully", profile.name);
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                json_output::error(&e, 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                ProfileAction::Delete { name } => {
                    match storage::delete_profile(name) {
                        Ok(_) => {
                            if cli.json {
                                json_output::success(serde_json::json!({
                                    "ok": true,
                                    "message": format!("Profile '{}' deleted", name)
                                }));
                            } else {
                                println!("Profile '{}' deleted successfully", name);
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                json_output::error(&e, 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
            }
        }
        Commands::Env { action } => {
            match action {
                EnvAction::Generate { dry_run, env_file } => {
                    commands_env::handle_env_generate(*dry_run, env_file.as_deref(), cli.json)?;
                }
                EnvAction::Inject { command, logical_model, tenant, dry_run } => {
                    if command.is_empty() {
                        commands_env::handle_env_inject(cli.json)?;
                    } else {
                        // P0-B1: env inject -- <cmd> MUST be equivalent to run -- <cmd>
                        // Apply same tenant precedence: --tenant > AIKEY_TENANT env var
                        let env_tenant = std::env::var("AIKEY_TENANT").ok();
                        let resolved_tenant = tenant.as_deref().or(env_tenant.as_deref());

                        commands_env::handle_env_run(command, cli.json, logical_model.as_deref(), resolved_tenant, *dry_run)?;
                    }
                }
                EnvAction::Check => {
                    commands_env::handle_env_check(cli.json)?;
                }
                EnvAction::Use { name } => {
                    global_config::set_current_env(name)
                        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                    if cli.json {
                        json_output::print_json(serde_json::json!({
                            "ok": true,
                            "env": name
                        }));
                    } else {
                        println!("Switched to environment: {}", name);
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
        Commands::Provider { action } => {
            match action {
                ProviderAction::Add { name, key_alias, default_model } => {
                    commands_project::handle_provider_add(name, key_alias, default_model.as_deref(), cli.json)?;
                }
                ProviderAction::Rm { name } => {
                    commands_project::handle_provider_rm(name, cli.json)?;
                }
                ProviderAction::Ls => {
                    commands_project::handle_provider_ls(cli.json)?;
                }
            }
        }
        Commands::Quickstart => {
            commands_project::handle_quickstart(cli.json)?;
        }
        Commands::Stats => {
            handle_stats(cli.json)?;
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
            // Resolve alias: if omitted, show interactive picker (TTY only).
            let resolved_alias: String = match alias_or_id {
                Some(a) => a.clone(),
                None => {
                    if !std::io::stdin().is_terminal() || cli.json {
                        return Err("alias required in non-interactive mode (usage: aikey use <ALIAS>)".into());
                    }
                    pick_key_interactively()?
                }
            };
            commands_proxy::ensure_proxy_for_use(cli.password_stdin);
            commands_account::handle_key_use(
                &resolved_alias, *no_hook, provider.as_deref(), cli.json,
            )?;
        }
        Commands::Browse { page, port } => {
            commands_account::handle_browse(page.as_deref(), *port, cli.json)?;
        }
        Commands::Whoami => {
            commands_account::handle_whoami(cli.json)?;
        }
        Commands::Doctor => {
            commands_project::handle_doctor(cli.json)?;
        }
        Commands::Status => {
            commands_project::handle_project_status(cli.json)?;
        }
        Commands::Shell => {
            handle_shell_command(cli.json)?;
        }
        Commands::Proxy { action } => {
            match action {
                ProxyAction::Start { config, detach } => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    // Verify the password is valid before handing it to the proxy.
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    commands_proxy::handle_start(
                        config.as_deref(),
                        *detach,
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
/// Fuzzy similarity in [0.0, 1.0] combining prefix match, edit distance, and bigrams.
/// Used to suggest close matches for mistyped subcommands.
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
    // Format: TYPE  ALIAS                  PROVIDER / BASE_URL             LOCAL
    let mut items: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    // Track which rows are selectable (false for separator & other-account keys).
    let mut selectable: Vec<bool> = Vec::new();

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
        let row = format!(
            "personal  {:<22}  {:<28}{}",
            if entry.alias.len() > 22 { &entry.alias[..22] } else { &entry.alias },
            if provider_col.len() > 28 { &provider_col[..28] } else { &provider_col },
            active_marker,
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
        let row = format!(
            "team      {:<22}  {:<28}{}",
            if display_name.len() > 22 { &display_name[..22] } else { display_name },
            if e.provider_code.len() > 28 { &e.provider_code[..28] } else { &e.provider_code },
            active_marker,
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
            let raw = format!(
                "team      {:<22}  {:<28}  [other account]",
                if display_name.len() > 22 { &display_name[..22] } else { display_name },
                if e.provider_code.len() > 28 { &e.provider_code[..28] } else { &e.provider_code },
            );
            items.push(format!("{}", raw.dimmed()));
            aliases.push(e.virtual_key_id.clone());
            selectable.push(false);
        }
    }

    let header = format!("        {:<22}  {:<28}", "ALIAS", "PROVIDER / BASE_URL");

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
