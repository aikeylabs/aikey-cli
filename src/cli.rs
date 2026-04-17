use clap::{Parser, Subcommand};
use std::collections::HashSet;

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
  \x1b[1mactivate\x1b[0m <alias>          Temporarily activate a key in the current terminal
  \x1b[1mdeactivate\x1b[0m               Restore global settings in the current terminal
  \x1b[1mroute\x1b[0m [label]            Show proxy route tokens for third-party AI clients
  \x1b[1mlogin\x1b[0m                    Log in to aikey service (shortcut for `account login`)
  \x1b[1mweb\x1b[0m [page]               Open the User Console in your default browser
  \x1b[1mmaster\x1b[0m [page]            Open the Master Console (admin) in your default browser
  \x1b[1mdoctor\x1b[0m                   Check system health, connectivity, and configuration
  \x1b[1menv\x1b[0m [command]            View or set proxy environment variables
  \x1b[1mproxy\x1b[0m <command>          Manage the local proxy process
  \x1b[1mstatus\x1b[0m                   Show a summary of gateway, login, keys, and providers
  \x1b[1mwhoami\x1b[0m                   Show your current login, active key, and vault status
  \x1b[1mget\x1b[0m <alias>              Retrieve a secret and copy it to the clipboard
  \x1b[1mrun\x1b[0m -- <command>         Run a command with secrets injected as environment variables
  \x1b[1mkey\x1b[0m <command>            Manage API keys (rotate, list, sync, use)
  \x1b[1mquickstart\x1b[0m               Show a state-aware landing page with the next most useful commands
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
pub(crate) struct Cli {
    /// Read password from stdin instead of prompting (for automation/testing)
    #[arg(long, global = true)]
    pub password_stdin: bool,

    /// Output in JSON format (where supported)
    #[arg(long, global = true)]
    pub json: bool,

    /// Print version information
    #[arg(short = 'V', long)]
    pub version: bool,

    /// Print detailed help for all commands
    #[arg(long)]
    pub detail: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Show version info (CLI + local proxy if running)
    #[command(display_order = 100)]
    Version,
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
    /// Temporarily activate a key in the current terminal (does not write active.env)
    #[command(display_order = 4)]
    Activate {
        /// Key alias, team display alias, or OAuth identity.
        /// Omit to pick from an interactive list (TTY only).
        alias: Option<String>,
        /// Target provider (required when key supports multiple providers)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// Target shell for eval-safe output (zsh, bash, powershell, cmd).
        /// Passed automatically by the shell wrapper; required.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
    },
    /// Restore global active.env settings in the current terminal
    #[command(display_order = 4)]
    Deactivate {
        /// Target shell for eval-safe output (zsh, bash, powershell, cmd).
        /// Passed automatically by the shell wrapper; required.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
    },
    /// Show proxy route tokens for third-party AI clients (Cursor, OpenCode, etc.)
    #[command(display_order = 5)]
    Route {
        /// Key label to show configuration for (alias, team display alias, or OAuth email)
        label: Option<String>,
        /// Show full (untruncated) route tokens in list view
        #[arg(long)]
        full: bool,
    },
    /// Log in to aikey service (shortcut for `account login`)
    #[command(display_order = 6)]
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
    #[command(alias = "browse", display_order = 6)]
    Web {
        /// Page to open: overview (default), keys, account, usage
        page: Option<String>,
        /// Override port for dev mode (e.g. --port 3000 for Vite dev server)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Open the Master Console (admin) in your default browser
    #[command(display_order = 7)]
    Master {
        /// Page to open: dashboard (default), seats, virtual-keys, bindings, providers, events, usage
        page: Option<String>,
        /// Control panel URL (e.g. --url http://192.168.1.100:3000)
        #[arg(long)]
        url: Option<String>,
        /// Override port on localhost (e.g. --port 8090 for trial)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Check system health, connectivity, and configuration
    #[command(display_order = 8)]
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
    /// Show a state-aware landing page with the next most useful commands
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
    /// Authenticate with provider OAuth accounts (Claude, Codex, Kimi)
    #[command(display_order = 2)]
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuthAction {
    /// Login to a provider OAuth account
    #[command(after_help = "\x1b[1mSupported providers:\x1b[0m
  claude    Claude (Anthropic) — requires Pro or Max subscription
  codex     Codex / ChatGPT (OpenAI) — requires ChatGPT Pro/Plus
  kimi      Kimi (Moonshot AI)

\x1b[1mExamples:\x1b[0m
  aikey auth login claude
  aikey auth login codex
  aikey auth login kimi")]
    Login {
        /// Provider name: claude, codex, kimi (omit for interactive picker)
        provider: Option<String>,
    },
    /// Logout from a provider account
    Logout {
        /// Provider name or account ID
        target: String,
    },
    /// List all provider OAuth accounts
    List,
    /// Set a provider account as active for routing
    Use {
        /// Account ID or display identity (email)
        account: String,
    },
    /// Show provider account health and token status
    Status {
        /// Specific account ID (optional, default: all)
        account: Option<String>,
    },
    /// Diagnose provider account connectivity
    Doctor {
        /// Specific provider (optional, default: all)
        provider: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum DbAction {
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
pub(crate) enum EnvAction {
    /// Set proxy environment variables (written to ~/.aikey/proxy.env)
    Set {
        /// KEY=VALUE pairs (after --)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProxyAction {
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
pub(crate) enum KeyAction {
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
pub(crate) enum AccountAction {
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
pub(crate) enum SecretAction {
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
    /// [DEPRECATED] List all secrets — use `aikey list` for unified view
    List,
    /// Delete a secret
    Delete {
        /// Secret name/alias
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProjectAction {
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

/// Returns a stable command name string suitable for log fields.
/// Never includes secret values or passwords.
pub(crate) fn command_name(cmd: Option<&Commands>) -> String {
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
            Commands::Activate { .. } => "activate".to_string(),
            Commands::Deactivate { .. } => "deactivate".to_string(),
            Commands::Route { .. } => "route".to_string(),
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
            Commands::Web { .. } => "web".to_string(),
            Commands::Master { .. } => "master".to_string(),
            Commands::Doctor => "doctor".to_string(),
            Commands::Proxy { action } => format!("proxy.{}", match action {
                ProxyAction::Start { .. } => "start",
                ProxyAction::Stop => "stop",
                ProxyAction::Status => "status",
                ProxyAction::Restart { .. } => "restart",
                ProxyAction::Verify => "verify",
            }),
            Commands::Auth { action } => format!("auth.{}", match action {
                AuthAction::Login { .. } => "login",
                AuthAction::Logout { .. } => "logout",
                AuthAction::List => "list",
                AuthAction::Use { .. } => "use",
                AuthAction::Status { .. } => "status",
                AuthAction::Doctor { .. } => "doctor",
            }),
            Commands::Version => "version".to_string(),
        },
    }
}

/// Validate a secret key name (alias).
/// Allowed: alphanumeric, `_`, `-`, `:` (for provider:alias format).
/// Max length: 256 characters. Empty names and names with spaces/slashes are rejected.
pub(crate) fn validate_secret_name(name: &str) -> Result<(), String> {
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

/// Returns detailed notes for a command path (e.g. "add", "proxy start").
/// Used to append contextual notes after clap's rendered `--help` output.
pub(crate) fn command_detail_notes(cmd: &str) -> Option<&'static str> {
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

        "activate" => Some("\
Notes:
    - Temporarily sets API key environment variables in the current terminal.
    - Does not write to active.env or modify provider bindings.
    - Closing the terminal automatically reverts to global settings.
    - --provider is required when the key supports multiple providers.
    - --shell is passed automatically by the aikey() shell wrapper.
    - Use `aikey deactivate` to restore global settings in the same terminal."),

        "deactivate" => Some("\
Notes:
    - Restores global active.env settings in the current terminal.
    - Undoes the effect of `aikey activate`.
    - --shell is passed automatically by the aikey() shell wrapper."),

        "route" => Some("\
Notes:
    - Shows route tokens for configuring third-party AI clients (Cursor, OpenCode, etc.).
    - Each key/account gets a random aikey_vk_ token used as the API_KEY in client config.
    - `aikey route` lists all available routes (tokens truncated by default).
    - `aikey route <label>` shows full token + base_url for copy-paste configuration.
    - `aikey route --json` outputs all routes as JSON with full tokens (for scripts).
    - `aikey route --full` shows full tokens in the list view.
    - This command is read-only; it does not modify the vault or proxy state.
    - If tokens are missing, run `aikey use` or `aikey add` to trigger migration."),

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

        "web" | "browse" => Some("\
Notes:
    - PAGE: overview | keys | account | usage
    - In local/trial mode, opens the local console directly.
    - In team mode, requires a valid account session.
    - If the control URL is local, AiKey may auto-detect common dev ports such as 3000 and 5173.
    - --port forces a specific local web port.
    - `aikey browse` is an alias for `aikey web`."),

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
    - Prints a state-aware landing page showing the most useful next steps.
    - Read-only: does not change the vault, config, or proxy state.
    - Safe to re-run at any time — the output adapts to what you've already set up.
    - For per-project env management, see `aikey project init`."),

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
pub(crate) fn print_short_help() {
    let b = "\x1b[1m";
    let r = "\x1b[0m";
    println!("\
AiKey - Secure local-first secret management

Usage: aikey [OPTIONS] [COMMAND]

Commands:
  {b}add{r} <alias>              Save a new secret to the vault
  {b}auth{r} <command>           Manage provider OAuth accounts (Claude, Codex, Kimi)
  {b}list{r}                     Show all personal and team keys
  {b}test{r} <alias>             Test whether a stored API key alias is working
  {b}use{r} [alias]              Select the active key for routing (shortcut for `key use`)
  {b}activate{r} <alias>          Temporarily activate a key in the current terminal
  {b}deactivate{r}               Restore global settings in the current terminal
  {b}route{r} [label]            Show proxy route tokens for third-party AI clients
  {b}login{r}                    Log in to aikey service (shortcut for `account login`)
  {b}web{r} [page]               Open the User Console in your default browser
  {b}master{r} [page]            Open the Master Console (admin) in your default browser
  {b}doctor{r}                   Check system health, connectivity, and configuration
  {b}env{r} [command]            View or set proxy environment variables
  {b}proxy{r} <command>          Manage the local proxy process
  {b}status{r}                   Show a summary of gateway, login, keys, and providers
  {b}whoami{r}                   Show your current login, active key, and vault status
  {b}get{r} <alias>              Retrieve a secret and copy it to the clipboard
  {b}run{r} -- <command>         Run a command with secrets injected as environment variables
  {b}key{r} <command>            Manage API keys (rotate, list, sync, use)
  {b}quickstart{r}               Show a state-aware landing page with the next most useful commands
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

pub(crate) fn print_detailed_help() {
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

[1madd[0m
  Save a new personal key/secret to the local vault.

  Usage:
    aikey add [--provider <PROVIDER>] <ALIAS>

  Notes:
    - Stores a new local secret under <ALIAS>.
    - --provider binds the secret to a provider such as openai or anthropic.
    - On TTY, the secret value is entered interactively.
    - In non-interactive mode, the secret value is read from stdin.
    - In interactive mode, AiKey may run connectivity checks before saving.

[1mlist[0m
  Show all personal and team keys in one view.

  Usage:
    aikey list

  Notes:
    - Shows both Personal Keys and Team Keys.
    - Team keys are filtered to active keys only.
    - May perform a lightweight sync first.
    - If server state changed, AiKey may prompt for the vault password to complete a full sync.
    - If the control service is unreachable, AiKey falls back to local cache.

[1mtest[0m
  Test whether a stored API key alias is reachable and usable.

  Usage:
    aikey test [--provider <PROVIDER>] <ALIAS>

  Notes:
    - <ALIAS> is the stored key alias.
    - --provider overrides the stored provider for this test only.
    - The test may include TCP reachability, API probe, chat/completion probe, and proxy probe.
    - If no provider metadata is stored, AiKey may test multiple known providers.

[1muse[0m
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

[1mactivate[0m
  Temporarily activate a key in the current terminal.

  Usage:
    aikey activate [--provider <PROVIDER>] [--shell <SHELL>] <ALIAS>

  Notes:
    - Sets environment variables in the current shell only (does not write active.env).
    - Closing the terminal reverts to global settings.
    - --provider is required when the key supports multiple providers.
    - --shell is passed automatically by the shell wrapper function.
    - Use `aikey deactivate` to restore global settings without closing the terminal.

[1mdeactivate[0m
  Restore global active.env settings in the current terminal.

  Usage:
    aikey deactivate [--shell <SHELL>]

  Notes:
    - Undoes `aikey activate` — restores environment variables from active.env.
    - --shell is passed automatically by the shell wrapper function.

[1mroute[0m
  Show proxy route tokens for third-party AI clients (Cursor, OpenCode, etc.).

  Usage:
    aikey route [--full] [--json] [LABEL]

  Notes:
    - Each key/account gets a random aikey_vk_ token used as API_KEY in client config.
    - Without LABEL: lists all routes (tokens truncated; use --full for complete tokens).
    - With LABEL: shows full base_url + api_key ready to copy-paste.
    - --json outputs all routes as JSON with full tokens (for scripts).
    - Read-only command — does not modify vault or proxy.

  Example:
    $ aikey route my-key
    # Configuration for: my-key (personal, anthropic)
    base_url:  http://127.0.0.1:27200/anthropic
    api_key:   aikey_vk_b82ef1d49c3a7e08...

[1mlogin[0m
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

[1mweb[0m
  Open the User Console in the default browser.

  Usage:
    aikey web [--port <PORT>] [PAGE]

  Aliases:
    aikey browse

  Arguments:
    PAGE: overview | keys | account | usage

  Notes:
    - In local/trial mode, opens the local console directly.
    - In team mode, requires a valid account session.
    - If the control URL is local, AiKey may auto-detect common dev ports such as 3000 and 5173.
    - --port forces a specific local web port.

[1mmaster[0m
  Open the Master Console (admin) in the default browser.

  Usage:
    aikey master [--port <PORT>] [PAGE]

  Arguments:
    PAGE: dashboard | seats | virtual-keys | bindings | providers | events | usage

  Notes:
    - The Master Console requires admin login (handled by the web frontend).
    - URL is resolved from install-state.json, stored account, or --port.
    - --port forces a specific local web port.

[1mdoctor[0m
  Check system health, connectivity, and configuration.

  Usage:
    aikey doctor

  Notes:
    - Checks include internet reachability, vault presence, session cache, proxy status,
      provider/proxy connectivity, shell hook state, and vault WAL size.
    - In interactive mode, AiKey may try to restart the proxy automatically.
    - In interactive mode, AiKey may also try to install the shell hook if missing.

[1menv[0m
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
    [1mset[0m
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

[1mproxy[0m
  Manage the local aikey-proxy process.

  Usage:
    aikey proxy <SUBCOMMAND>

  Subcommands:
    [1mstart[0m
      Usage:
        aikey proxy start [--config <CONFIG>] [--foreground]
      Notes:
        - Starts the proxy with vault authentication.
        - Starts in background by default.
        - Use --foreground for debugging.

    [1mstop[0m
      Usage:
        aikey proxy stop

    [1mstatus[0m
      Usage:
        aikey proxy status

    [1mrestart[0m
      Usage:
        aikey proxy restart [--config <CONFIG>]

    [1mverify[0m
      Usage:
        aikey proxy verify

[1mstatus[0m
  Show a combined dashboard: gateway, login, keys, and providers.

  Usage:
    aikey status

  Notes:
    - Gateway section reuses `aikey proxy status` output.
    - Keys section shows personal count, team count (total/active), and active key.
    - Providers section lists all providers discovered from personal and team keys.
    - Supports --json for structured output.

[1mwhoami[0m
  Show the current local identity summary.

  Usage:
    aikey whoami

  Notes:
    - Includes vault state, logged-in account, control URL, active key, and sync version.
    - Useful for confirming the current working context before running or debugging.

[1mget[0m
  Retrieve a secret and copy it to the clipboard.

  Usage:
    aikey get [-t <TIMEOUT>] <ALIAS>

  Notes:
    - Default clipboard clear timeout is 30 seconds.
    - Use --timeout 0 to disable auto-clear.
    - In JSON mode, AiKey returns the plaintext value instead of using the clipboard.

[1mrun[0m
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

[1mkey[0m
  Manage team-key lifecycle and local team-key metadata.

  Usage:
    aikey key <SUBCOMMAND>

  Subcommands:
    [1mlist[0m
      Usage:
        aikey key list
      Notes:
        - Lists team-managed virtual keys.
        - May refresh metadata from server when possible.

    [1msync[0m
      Usage:
        aikey key sync
      Notes:
        - Forces a full metadata refresh and downloads missing key material.
        - Requires the vault password.

    [1muse[0m
      Usage:
        aikey key use [--no-hook] <ALIAS_OR_ID>

    [1mrotate[0m
      Usage:
        aikey key rotate [--from-stdin] <NAME>

    [1malias[0m
      Usage:
        aikey key alias <OLD_ALIAS> <NEW_ALIAS>

[1mquickstart[0m
  Show a state-aware landing page with the next most useful commands.

  Usage:
    aikey quickstart

  Notes:
    - Read-only: does not change the vault, config, or proxy state.
    - Safe to re-run at any time — the output adapts to what you've already set up.
    - For per-project env management, see `aikey project init`.

[1mproject[0m
  Manage optional project configuration.

  Usage:
    aikey project <SUBCOMMAND>

  Subcommands:
    [1minit[0m
      Usage:
        aikey project init

    [1mstatus[0m
      Usage:
        aikey project status

    [1mmap[0m
      Usage:
        aikey project map [--env <ENV>] [--provider <PROVIDER>] [--model <MODEL>] [--key-alias <ALIAS>] [--impl-id <IMPL>] <VAR> <ALIAS>
      Notes:
        - Binds an env var name to a vault alias.
        - Can also write envMappings entries when the mapping flags are provided.
        - Requires an existing `aikey.config.json`.

[1mlogs[0m
  Show recent local activity events.

  Usage:
    aikey logs [--limit <LIMIT>]

  Notes:
    - Default limit is 20.

[1mupdate[0m
  Replace the value of an existing local secret.

  Usage:
    aikey update <ALIAS>

  Notes:
    - In interactive mode, AiKey asks for confirmation first.
    - If the proxy is already running, AiKey may warn that restart is needed.

[1mdelete[0m
  Remove a local secret from the vault.

  Usage:
    aikey delete <ALIAS>

  Notes:
    - In interactive mode, AiKey asks for confirmation first.
    - If the proxy is already running, AiKey may warn that restart is needed.

[1mexport[0m
  Export selected secrets to an encrypted backup file.

  Usage:
    aikey export <PATTERN> <OUTPUT>

  Notes:
    - <PATTERN> supports matching such as \"*\" or \"api_*\".
    - Requires both the vault password and a separate export password.
    - Treat the output file as sensitive material.

[1mchange-password[0m
  Change the vault master password.

  Usage:
    aikey change-password

  Notes:
    - Prompts for old password, new password, and confirmation.
    - Invalidates the cached local session after success.

[1mauth[0m
  Manage provider OAuth accounts. Supports Claude (Setup Token), Codex (Auth Code),
  and Kimi (Device Code) OAuth flows. OAuth accounts are an alternative to API keys —
  they use your existing provider subscription (Claude Pro, ChatGPT Plus, Kimi, etc.)
  and are managed alongside personal/team keys in `aikey use`.

  Usage:
    aikey auth <SUBCOMMAND>

  Subcommands:
    [1mlogin[0m
      Authenticate with a provider OAuth account.

      Usage:
        aikey auth login <PROVIDER>

      Arguments:
        PROVIDER: claude, codex, kimi

      Notes:
        - Claude: opens browser for Setup Token, paste the code back into the terminal.
        - Codex: opens browser for OAuth authorization, callback received automatically.
        - Kimi: displays a device code, open the URL and enter the code in browser.
        - If the account already exists, tokens are refreshed (no duplicate accounts).
        - Proxy must be running (auto-started if needed).

      Examples:
        aikey auth login claude
        aikey auth login codex
        aikey auth login kimi

    [1mlogout[0m
      Remove a provider OAuth account and its tokens from the local vault.

      Usage:
        aikey auth logout <TARGET>

      Arguments:
        TARGET: provider name (e.g. claude) or account ID

      Notes:
        - If the account is currently active (via `aikey use`), the binding is also removed.
        - Prompts for confirmation in interactive mode.

    [1mlist[0m
      Show all registered provider OAuth accounts.

      Usage:
        aikey auth list

      Notes:
        - Shows identity (email), provider, status, tier, and token expiry.
        - Equivalent to the OAuth section in `aikey list`.

    [1muse[0m
      Set a provider OAuth account as the active key for its provider.

      Usage:
        aikey auth use <ACCOUNT>

      Arguments:
        ACCOUNT: account ID or display identity (email)

      Notes:
        - Mutual exclusion: activating an OAuth account deactivates any API key for the
          same provider, and vice versa.
        - Equivalent to selecting the account in `aikey use` interactive picker.

    [1mstatus[0m
      Show health and token status for provider accounts.

      Usage:
        aikey auth status [ACCOUNT]

      Notes:
        - Without ACCOUNT, shows all accounts.
        - Displays token validity, refresh status, and upstream connectivity.

    [1mdoctor[0m
      Diagnose provider account connectivity end-to-end.

      Usage:
        aikey auth doctor [PROVIDER]

      Notes:
        - Tests: token freshness → proxy injection → upstream API reachability.
        - Without PROVIDER, checks all registered accounts.

[1maccount[0m
  Manage the current control-service account session.

  Usage:
    aikey account <SUBCOMMAND>

  Subcommands:
    [1mlogin[0m
      Usage:
        aikey account login [--control-url <URL>] [--token <TOKEN>] [--email <EMAIL>]

    [1mstatus[0m
      Usage:
        aikey account status

    [1mlogout[0m
      Usage:
        aikey account logout

    [1mset-url[0m
      Usage:
        aikey account set-url <URL>

[1mlogout[0m
  Log out of the current account session.

  Usage:
    aikey logout

  Notes:
    - Shortcut for `aikey account logout`.
    - Does not delete local vault contents.

[1msecret[0m
  Low-level secret management commands.

  Usage:
    aikey secret <SUBCOMMAND>

  Subcommands:
    [1mset[0m
      Usage:
        aikey secret set --from-stdin [--provider <PROVIDER>] <NAME>
      Notes:
        - --from-stdin is required for security.

    [1mupsert[0m
      Usage:
        aikey secret upsert --from-stdin [--provider <PROVIDER>] <NAME>
      Notes:
        - --from-stdin is required for security.

    [1mlist[0m
      Usage:
        aikey secret list

    [1mdelete[0m
      Usage:
        aikey secret delete <NAME>

[1mhelp[0m
  Show top-level or command-specific help.

  Usage:
    aikey help [COMMAND]
");
}


// Build-time constants injected by build.rs.
const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_REVISION: &str = env!("AIKEY_BUILD_REVISION");
const BUILD_ID: &str = env!("AIKEY_BUILD_ID");
const BUILD_TIME: &str = env!("AIKEY_BUILD_TIME");

/// Returns structured version info as a JSON value (for --json and version --json).
pub(crate) fn build_version_json() -> serde_json::Value {
    serde_json::json!({
        "version": BUILD_VERSION,
        "revision": BUILD_REVISION,
        "dirty": BUILD_REVISION.ends_with("-dirty"),
        "build_id": BUILD_ID,
        "build_time": BUILD_TIME,
    })
}

/// Print detailed version information (for `aikey version` subcommand).
pub(crate) fn print_version_detail() {
    use colored::Colorize;
    eprintln!("{}", "AiKey CLI".bold());
    eprintln!("  Version:   {}", BUILD_VERSION);
    eprintln!("  Revision:  {}", BUILD_REVISION);
    eprintln!("  BuildID:   {}", BUILD_ID);
    eprintln!("  Built:     {}", BUILD_TIME);

    // Probe local proxy for its version (best effort, silent on failure).
    if let Some(proxy_info) = probe_proxy_version() {
        eprintln!();
        eprintln!("{}", "AiKey Proxy (127.0.0.1:27200)".bold());
        if let Some(v) = proxy_info.get("version").and_then(|v| v.as_str()) {
            eprintln!("  Version:   {}", v);
        }
        if let Some(r) = proxy_info.get("revision").and_then(|v| v.as_str()) {
            eprintln!("  Revision:  {}", r);
        }
        if let Some(b) = proxy_info.get("build_id").and_then(|v| v.as_str()) {
            eprintln!("  BuildID:   {}", b);
        }
        if let Some(t) = proxy_info.get("build_time").and_then(|v| v.as_str()) {
            eprintln!("  Built:     {}", t);
        }
    }
}

/// Try to fetch version info from the local proxy via GET http://127.0.0.1:27200/version.
/// Returns None on any failure (proxy not running, timeout, parse error).
fn probe_proxy_version() -> Option<serde_json::Value> {
    use std::io::Read;
    use std::net::TcpStream;
    use std::time::Duration;

    let mut stream = TcpStream::connect_timeout(
        &"127.0.0.1:27200".parse().ok()?,
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1000))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(500))).ok()?;

    use std::io::Write;
    stream.write_all(b"GET /version HTTP/1.1\r\nHost: 127.0.0.1:27200\r\nConnection: close\r\n\r\n").ok()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let response = String::from_utf8_lossy(&buf);

    // Find the JSON body after the HTTP headers (separated by \r\n\r\n).
    let body = response.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body.trim()).ok()
}

pub(crate) fn print_banner() {
    use colored::Colorize;
    let version = BUILD_VERSION;
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    let aikey_home = format!("{}/.aikey", home);

    // Muted gold: RGB(160, 135, 75) — subtle on dark terminals.
    let g = |s: &str| s.truecolor(160, 135, 75);

    // Lines 2–5 of the icon carry side labels (title/divider/tagline/home).
    // Lines 1 and 6 are purely decorative.
    eprintln!();
    eprintln!("   {}", g("\u{25B2}           \u{25B2}"));
    eprintln!("   {}       {}   v{}",
        g("\u{256D}\u{2588}\u{2588}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}\u{2588}\u{2588}\u{256E}"),
        "AiKey CLI".bold(),
        version);
    eprintln!(" {}       {}",
        g("\u{00B7}\u{2590}\u{2588}  \u{27E8}\u{29BF}\u{27E9} \u{27E8}\u{29BF}\u{27E9}  \u{2588}\u{258C}\u{00B7}"),
        "------------------------------------".dimmed());
    eprintln!("  {}        FinOps & AI Governance Center",
        g("\u{2590}\u{2588}     \u{25BC}     \u{2588}\u{258C}"));
    eprintln!("   {}       {}",
        g("\u{2570}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{256F}"),
        aikey_home);
    eprintln!("       {}", g("\u{2579}   \u{2579}"));
    eprintln!();
}

/// Format a unix timestamp as YYYY/MM/DD.
pub(crate) fn format_date(ts: i64) -> String {
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

pub(crate) fn similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() || b.is_empty() { return 0.0; }
    if a == b { return 1.0; }
    if b.starts_with(a) || a.starts_with(b) { return 0.95; }

    // Edit distance (insertions/deletions/substitutions), normalised.
    let ed = edit_distance(a, b);
    let max_len = a.len().max(b.len()) as f64;
    let ed_score = 1.0 - (ed as f64 / max_len);

    // Bigram Jaccard.
    let bigram_score = {
        fn bigrams(s: &str) -> HashSet<(char, char)> {
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
pub(crate) fn edit_distance(a: &str, b: &str) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_secret_name ─────────────────────────────────────────────

    #[test]
    fn test_validate_secret_name_valid() {
        assert!(validate_secret_name("my-key").is_ok());
        assert!(validate_secret_name("openai_key_1").is_ok());
        assert!(validate_secret_name("provider:alias").is_ok());
        assert!(validate_secret_name("key.with.dots").is_ok());
        assert!(validate_secret_name("A").is_ok());
    }

    #[test]
    fn test_validate_secret_name_empty() {
        assert!(validate_secret_name("").is_err());
    }

    #[test]
    fn test_validate_secret_name_too_long() {
        let long = "a".repeat(257);
        assert!(validate_secret_name(&long).is_err());
        // Exactly 256 should be fine
        let exact = "a".repeat(256);
        assert!(validate_secret_name(&exact).is_ok());
    }

    #[test]
    fn test_validate_secret_name_invalid_chars() {
        assert!(validate_secret_name("has space").is_err());
        assert!(validate_secret_name("has/slash").is_err());
        assert!(validate_secret_name("has@at").is_err());
        assert!(validate_secret_name("emoji🔑").is_err());
    }

    // ── format_date ──────────────────────────────────────────────────────

    #[test]
    fn test_format_date_epoch() {
        assert_eq!(format_date(0), "1970/01/01");
    }

    #[test]
    fn test_format_date_known_dates() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(format_date(1704067200), "2024/01/01");
        // 2026-04-13 00:00:00 UTC = 1776038400
        assert_eq!(format_date(1776038400), "2026/04/13");
    }

    // ── similarity & edit_distance ───────────────────────────────────────

    #[test]
    fn test_similarity_exact_match() {
        assert_eq!(similarity("add", "add"), 1.0);
    }

    #[test]
    fn test_similarity_empty_strings() {
        assert_eq!(similarity("", "add"), 0.0);
        assert_eq!(similarity("add", ""), 0.0);
    }

    #[test]
    fn test_similarity_prefix_match() {
        assert_eq!(similarity("add", "addition"), 0.95);
        assert_eq!(similarity("pro", "proxy"), 0.95);
    }

    #[test]
    fn test_similarity_fuzzy() {
        let score = similarity("aad", "add");
        assert!(score >= 0.5, "Expected >= 0.5, got {}", score);

        let score_unrelated = similarity("xyz", "add");
        assert!(score_unrelated < 0.5, "Expected < 0.5, got {}", score_unrelated);
    }

    #[test]
    fn test_edit_distance_identical() {
        assert_eq!(edit_distance("hello", "hello"), 0);
    }

    #[test]
    fn test_edit_distance_single_edit() {
        assert_eq!(edit_distance("add", "aad"), 1);
        assert_eq!(edit_distance("cat", "bat"), 1);
    }

    #[test]
    fn test_edit_distance_empty() {
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", ""), 3);
    }

    // ── command_name ─────────────────────────────────────────────────────

    #[test]
    fn test_command_name_none() {
        assert_eq!(command_name(None), "unknown");
    }

    #[test]
    fn test_command_name_simple() {
        assert_eq!(command_name(Some(&Commands::Init)), "init");
        assert_eq!(command_name(Some(&Commands::List)), "list");
        assert_eq!(command_name(Some(&Commands::ChangePassword)), "change-password");
    }

    #[test]
    fn test_command_name_nested() {
        let cmd = Commands::Account { action: AccountAction::Login { url: None, token: None, email: None } };
        assert_eq!(command_name(Some(&cmd)), "account.login");

        let cmd = Commands::Key { action: KeyAction::Sync };
        assert_eq!(command_name(Some(&cmd)), "key.sync");
    }

    // ── command_detail_notes ─────────────────────────────────────────────

    #[test]
    fn test_command_detail_notes_known() {
        assert!(command_detail_notes("add").is_some());
        assert!(command_detail_notes("run").is_some());
        assert!(command_detail_notes("login").is_some());
    }

    #[test]
    fn test_command_detail_notes_unknown() {
        assert!(command_detail_notes("nonexistent").is_none());
    }
}
