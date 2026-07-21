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
  \x1b[1mlist\x1b[0m                     Show all personal, team, and OAuth keys (alias for `key list`)
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
  \x1b[1mstatusline\x1b[0m               Render a one-line usage receipt for Claude Code's status line
  \x1b[1mwatch\x1b[0m                    Show a top-style dashboard of recent key usage
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
    /// Internal: stdin-json IPC 子命令组，供 aikey-local-server (Go) spawn 调用
    #[command(hide = true, name = "_internal")]
    Internal {
        #[command(subcommand)]
        action: crate::commands_internal::InternalAction,
    },
    /// Internal: print the FNV-1a-64 hash of the embedded hook template.
    ///
    /// Consumed by `aikey_hook_check_once` in hook.zsh / hook.bash to detect
    /// an outdated `~/.aikey/hook.{zsh,bash}` (user upgraded the `aikey`
    /// binary without re-running `aikey use`, so the on-disk hook lags
    /// behind the binary's embedded template). Output format is a bare
    /// 16-hex-digit hash on stdout — kept minimal so the shell can compare
    /// it with a trivial `[[ "$a" == "$b" ]]`.
    #[command(hide = true, name = "_hook-hash")]
    HookHash {
        /// Which shell template to hash: zsh | bash
        shell: String,
    },
    /// Hidden: regenerate `~/.aikey/active.env` after the 2026-04-29
    /// token-prefix rename. Called by installer scripts at upgrade time, and
    /// by the CLI main dispatch as a safety net when the on-disk file
    /// contains legacy-form tokens.
    ///
    /// Does NOT require the vault password — `user_profile_provider_bindings`
    /// is not encrypted, so we can re-read the bindings + write the new
    /// per-provider sentinels (`aikey_active_<provider>`) without prompting.
    ///
    /// The `--if-legacy` flag (the canonical installer-callable form) makes
    /// this a no-op when no legacy form is detected — safe to call on every
    /// upgrade regardless of whether the user already migrated.
    #[command(hide = true, name = "_refresh-active-env")]
    RefreshActiveEnv {
        /// Only refresh if the on-disk file contains a legacy-form token.
        /// Idempotent: safe to call on every install/upgrade.
        #[arg(long)]
        if_legacy: bool,
    },
    /// Manage the shell precmd hook installed under ~/.aikey/hook.{zsh,bash}
    ///
    /// Subcommands:
    ///   update     regenerate the hook file from the binary (Layer 1 only)
    ///   install    render the hook file AND wire it into your shell rc
    ///   reinstall  force-rewrite both layers (use after a template change)
    ///   uninstall  remove the hook from every shell rc (keeps the hook file)
    ///   status     report file / binary / loaded hashes and flag drift
    ///
    /// All subcommands are idempotent. Update is the manual escape hatch for
    /// users who want to refresh the hook without running `aikey use`; status
    /// is for diagnostics when the precmd auto-reload prints a drift warning
    /// and the user wants to confirm what's misaligned; uninstall is the
    /// counterpart to install for users who want to stop routing through
    /// aikey without uninstalling the binary.
    #[command(display_order = 10)]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Manage this host as a龙虾/OpenClaw digital employee (unattended daemon).
    ///
    /// `register` self-enrolls the host into an org using a join token from the
    /// admin console and stores the daemon credential in the vault. (The
    /// long-running `start` daemon that syncs the assigned VK + writes OpenClaw
    /// config arrives in a follow-up phase.)
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Save a new secret to the vault
    #[command(display_order = 1)]
    Add {
        alias: String,
        /// Provider code for proxy routing (e.g. openai, anthropic). Makes this
        /// key selectable via `aikey use` with path-prefix routing in the proxy.
        ///
        /// Single-protocol shorthand. For multi-protocol (aggregator gateway like
        /// 0011 / openrouter that supports both Anthropic and OpenAI protocols),
        /// use `--providers anthropic,openai` instead.
        #[arg(long, value_name = "PROVIDER", conflicts_with = "providers")]
        provider: Option<String>,
        /// v4.1 Stage 5+: Multi-protocol binding for one KEY (comma-separated).
        ///
        /// Use this when a KEY supports several API protocols (typical for
        /// aggregator gateways: 0011 / openrouter / yunwu accept both Anthropic
        /// and OpenAI). Stored to `entries.supported_providers` as a JSON array.
        ///
        /// Example: `--providers anthropic,openai` or `--providers anthropic --providers openai`
        ///
        /// Mutually exclusive with `--provider`. If neither is given, the entry
        /// has no provider binding (legacy behavior).
        #[arg(long, value_name = "PROVIDERS", value_delimiter = ',', num_args = 1..)]
        providers: Vec<String>,
        /// Custom upstream base URL for this key, overriding the provider's
        /// default endpoint. Use for self-hosted or aggregator gateways (e.g. an
        /// Anthropic-compatible endpoint like https://my-gateway.example/anthropic).
        /// Stored on the vault entry; the local proxy routes this key there.
        #[arg(long, value_name = "URL")]
        base_url: Option<String>,
        /// Skip installing the shell precmd hook into ~/.zshrc / ~/.bashrc.
        /// Hook coverage v1: `aikey add` now installs the hook on first use
        /// (parity with `aikey use`); pass this to opt out, or set
        /// `AIKEY_NO_HOOK=1` in the environment.
        #[arg(long)]
        no_hook: bool,
    },
    /// Show all personal, team, and OAuth keys (alias for `aikey key list`)
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
        /// Test EVERY stored credential (personal + team + OAuth) regardless
        /// of activation state. Without this flag, omitting `<alias>` only
        /// tests the current Primary binding for each provider.
        ///
        /// Mutually exclusive with `<alias>`: pass one or the other.
        #[arg(long, conflicts_with = "alias")]
        all: bool,
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
    /// Remove the active binding for one or more providers
    #[command(display_order = 4)]
    Unuse {
        /// Provider codes to unbind (e.g. openai, anthropic, kimi)
        #[arg(required = true, num_args = 1..)]
        providers: Vec<String>,
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
        /// Force a new activation email even if one was sent within the last 60 seconds
        #[arg(long)]
        resend: bool,
    },
    /// Open the User Console in your default browser, or control the local
    /// web service with `start` / `stop` / `restart`.
    #[command(alias = "browse", display_order = 6)]
    Web {
        /// Page to open: overview (default), keys, vault, account, usage, import,
        /// referrals, trust-check. Also accepts aliases (virtual-keys, team-keys,
        /// secrets, profile, usage-ledger, bulk-import, quick-import, trust) —
        /// resolved by the web UI.
        ///
        /// Service control: pass `start`, `stop`, `restart`, or `status`
        /// instead of a page name to control / inspect the local web service
        /// (aikey-local-server on Personal, aikey-trial-server on Trial).
        /// `status` reports whether it's running, on which port, and the
        /// vault lock state. Production servers are not managed here — use the
        /// server-install runbook on the server host instead.
        page: Option<String>,
        /// Shortcut for `aikey web import` — opens the Import page directly.
        #[arg(long)]
        import: bool,
        /// Shortcut for `aikey web vault` — opens the Personal Vault page directly.
        #[arg(long)]
        vault: bool,
        /// Override port for dev mode (e.g. --port 3000 for Vite dev server)
        #[arg(long)]
        port: Option<u16>,
        /// Copy the URL (with auth token attached) to the system clipboard
        /// instead of opening the browser. Useful for pasting into a
        /// non-default browser, an incognito window, or a remote machine.
        /// No auto-clear: the URL stays on the clipboard until the next
        /// copy overwrites it (the embedded JWT itself expires in 24h).
        /// If clipboard access fails (no display server, sandbox, etc.)
        /// the URL is printed to stdout for manual copy.
        #[arg(long = "copy-url")]
        copy_url: bool,
    },
    /// Bulk-import credentials from unstructured text via the Web UI
    ///
    /// Opens the local-server `/user/import` page in the default browser. If a
    /// FILE path is given, its contents are pre-parsed so the Web UI can skip
    /// the empty state. Requires the local-server to be running (managed by
    /// launchctl on macOS / systemctl on Linux — installer registers it).
    #[command(display_order = 7)]
    Import {
        /// Optional file path to seed the import with
        file: Option<std::path::PathBuf>,
        /// Skip browser; run the full parse+confirm flow headlessly
        #[arg(long)]
        non_interactive: bool,
        /// With --non-interactive: auto-accept all high-confidence drafts
        #[arg(long)]
        yes: bool,
        /// With --non-interactive: force provider for all drafts
        #[arg(long)]
        provider: Option<String>,
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
    Doctor {
        /// Show extended diagnostics: recent failed events, schema drift
        /// signals from trial-server log, and captured 4xx bodies (when
        /// AIKEY_PROXY_DEBUG_4XX_BODIES was on). All sources are local
        /// files / SQLite; no network calls beyond the existing checks.
        #[arg(long)]
        detail: bool,
        /// Show the proxy's most-recent error responses as a caused-by tree
        /// (origin → who produced it, path → hops traversed, trace_id → the
        /// log anchor). Reads ~/.aikey/run/last-errors.json; no network.
        #[arg(long)]
        last_errors: bool,
    },
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
    Update { alias: String },
    /// Delete one or more API Keys from the vault
    ///
    /// Batch mode: pass multiple aliases at once — `ak delete alias1 alias2 alias3`.
    /// A single confirmation is asked for the whole batch, and the vault
    /// password is prompted only once. Per-alias outcome is reported at the
    /// end; partial failures do not abort the batch.
    #[command(display_order = 17)]
    Delete {
        /// One or more aliases to delete. At least one is required.
        #[arg(required = true, num_args = 1..)]
        aliases: Vec<String>,
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
    /// Render a one-line usage receipt for Claude Code's custom status line
    /// (wired up automatically by `aikey statusline install`).
    #[command(display_order = 20)]
    Statusline {
        #[command(subcommand)]
        action: Option<StatuslineAction>,
    },
    /// Manage Claude Desktop routing through aikey (takeover status /
    /// manual install / restore to official mode).
    #[command(display_order = 20)]
    Desktop {
        #[command(subcommand)]
        action: DesktopAction,
    },
    /// Show a top-style dashboard of recent key usage from the local WAL.
    #[command(display_order = 21)]
    Watch,
    /// Audit usage-delivery completeness (allocated / confirmed / gaps / known-loss).
    #[command(display_order = 21)]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
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
    /// Detect LLM model substitution / degradation per KEY
    /// (M4: passthrough to trust-local on :8801; requires degrade-detector installed)
    #[command(display_order = 25)]
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Manage third-party Agent integrations (Phase 4).
    ///
    /// An "app" is an external client (Claude Code / Codex / a custom Agent)
    /// that talks to AiKey via a per-app bearer token + a per-app provider
    /// binding. `aikey app register` declares the app AND issues the bearer
    /// in one step — output includes the env lines (OPENAI_API_KEY +
    /// OPENAI_BASE_URL) for the Agent to use, plus a binding summary
    /// snapshotted from your `aikey use` selection. `aikey app route` is
    /// **optional**, only needed when you want to override per-app
    /// bindings (e.g., lock this app to a specific team key). `aikey app
    /// revoke / pause / resume / rotate` manage the bearer's lifecycle.
    /// See `aikey app list` for current state.
    ///
    /// The bearer is sent at:
    ///   http://127.0.0.1:<proxy-port>/apps/<slug>/v1/...
    /// Upstream provider is inferred from body.model at request time
    /// (claude-* → anthropic, gpt-* → openai, ...). No `<protocol>` URL
    /// segment since Phase 2 Day 7.
    #[command(display_order = 26)]
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// Manage AiKey background services (`start` / `stop` / `restart` / `status`).
    ///
    /// Umbrella service-control namespace for the AiKey-owned daemons.
    /// Registered services (closed whitelist): `web` (local-server /
    /// trial-server console), `proxy` (aikey-proxy), `trust-local`
    /// (degrade-detector observer). Refuses names outside the whitelist —
    /// this is NOT a generic launchd/systemd wrapper.
    ///
    /// The per-service namespaces (`aikey proxy ...`, `aikey web ...`) and
    /// this umbrella share ONE implementation core per service, so
    /// `aikey service status proxy` and `aikey proxy status` print the same
    /// thing. Bare `aikey service status` (no name) prints a one-line
    /// summary of every service at once.
    ///
    /// Examples:
    ///   aikey service status                 # all services, one line each
    ///   aikey service status trust-local     # one service, full detail
    ///   aikey service restart web
    ///   aikey service stop proxy
    #[command(display_order = 27)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

/// Subcommands for `aikey service`.
///
/// `name` is a short identifier (e.g. `trust-local`), not a launchd
/// label. We map short name → label internally so the user doesn't
/// have to memorize `aikey.trust-local`.
#[derive(Subcommand)]
pub(crate) enum ServiceAction {
    /// Start a registered AiKey service.
    Start {
        /// Service short name (e.g. `trust-local`). Run without a
        /// name to see the list of supported services.
        name: Option<String>,
    },
    /// Stop a registered AiKey service.
    Stop { name: Option<String> },
    /// Restart a registered AiKey service.
    Restart { name: Option<String> },
    /// Show service status. Without a name: one-line summary of every
    /// service. With a name (`web` / `proxy` / `trust-local`): full detail
    /// for that one — delegates to the same probe as `aikey <name> status`.
    Status { name: Option<String> },
}

/// Subcommands for `aikey trust` (M4).
#[derive(Subcommand)]
pub(crate) enum TrustAction {
    /// Run cascade L3 verification against a KEY (asks ~10 model-specific questions).
    /// Real cost: ~$0.01-0.15 / run, ~30s. Mock mode (default in M3): <100ms, free.
    Verify {
        /// Vault alias name to verify (must exist in `aikey list`).
        alias: String,
        /// Skip the 24h × 1 rate-limit (audited). Default off.
        #[arg(long)]
        force: bool,
        /// Don't wait for cascade completion; print verify_id and return immediately.
        #[arg(long, conflicts_with = "wait")]
        no_wait: bool,
        /// Explicitly wait (default behavior; flag present for symmetry).
        #[arg(long)]
        wait: bool,
    },
    /// Show current trust state for an alias (or list all aliases if omitted).
    Status {
        /// Alias to inspect. Omit to list all observed aliases.
        alias: Option<String>,
    },
    /// Show recent verify runs for an alias.
    History {
        /// Vault alias name.
        alias: String,
    },
    /// Trigger baseline / question-bank sync from trust-central.
    Sync {
        /// What to sync. Default: both.
        #[arg(long, value_enum, default_value_t = SyncTarget::Both)]
        target: SyncTarget,
    },
    /// Recompute L1 from observed proxy traffic (no cascade verify run).
    ///
    /// L1 is rolled up from `local_observations` (D-rule hits the
    /// proxy plugin recorded). It's normally refreshed as a side
    /// effect of `aikey trust verify`, `aikey trust sync`, and
    /// trust-local boot — this command is the explicit-only path.
    ///
    /// With no alias argument, sweeps every (alias, provider, model)
    /// trust-local knows about. With an alias, recomputes just that one.
    /// No upstream traffic, no token cost.
    Refresh {
        /// Alias to recompute. Omit to sweep all aliases.
        alias: Option<String>,
    },
}

/// Choices for `aikey trust sync --target`.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub(crate) enum SyncTarget {
    Baseline,
    Questions,
    Both,
}

/// Subcommands for `aikey app` (Phase 4 third-party Agent integration,
/// Phase 2 Day 7 + 2026-05-21 register-one-step redesign).
///
/// Typical flow:
///   `aikey app register --slug X --upstreams openai,anthropic`  (one step:
///                              writes metadata + issues bearer + snapshots
///                              bindings from `aikey use` + prints env lines)
///   `aikey app list / revoke / pause / resume / rotate`          (manage)
///
/// Optional override:
///   `aikey app route X --upstream U --key-type T --key-ref R`    (lock the
///                              app to a specific key for upstream U; bearer
///                              is NOT re-issued)
///
/// `aikey app authorize` was removed in Phase 2 Day 7 — bearer issuance
/// moved into `aikey app register` itself (see 2026-05-21 design note
/// `20260521-app-register-issues-bearer-and-default-from-aikey-use.md`).
#[derive(Subcommand)]
pub(crate) enum AppAction {
    /// Declare a new third-party Agent integration AND issue its bearer
    /// in one step (2026-05-21 redesign).
    ///
    /// What this command does (atomic):
    ///   1. UPSERT `app_records` with metadata + upstreams
    ///   2. For each upstream, snapshot the user's current `aikey use`
    ///      selection into a per-app binding (profile `app:<slug>`)
    ///      — unless `--follow-user-active` is set (then resolver
    ///      dynamically falls back to the default profile)
    ///   3. Issue a bearer token (reuses existing if any; pass
    ///      `--rotate-bearer` to force a new one)
    ///   4. Print the env lines the Agent needs:
    ///        OPENAI_API_KEY=aikey_app_xxx
    ///        OPENAI_BASE_URL=http://127.0.0.1:<port>/apps/<slug>/v1
    ///      plus a "snapshotted from your aikey use" binding summary,
    ///      and warnings for any upstream where `aikey use` had no
    ///      selection.
    ///
    /// `--upstreams` is the set of UPSTREAM PROVIDERS the Agent will use.
    /// At request time, AiKey infers the upstream from body.model
    /// (claude-* → anthropic, gpt-* → openai, ...) and looks up the
    /// binding written for that upstream.
    ///
    /// Re-running this command is safe (idempotent): app_records UPSERT,
    /// bearer reused, and user overrides set via `aikey app route` are
    /// preserved (not overwritten by the snapshot).
    Register {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        name: String,
        /// Free-text vendor/owner identifier. Optional but recommended
        /// (shows up in `aikey app list` for audit).
        #[arg(long, default_value = "")]
        vendor: String,
        /// Comma-separated upstream provider list (e.g. `openai` or
        /// `openai,anthropic`). At least one required — UNLESS this is a
        /// filter-only app (`--filter-stages` set), which has no LLM upstream.
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        upstreams: Vec<String>,
        /// Mark this app as first-party (AiKey-owned). Unlocks
        /// `--follow-user-active` and other privileged modes. Default:
        /// third-party (the safe default for unknown integrations).
        #[arg(long)]
        first_party: bool,
        /// Use the user's current `aikey use` selection as the binding
        /// instead of a frozen per-app binding. First-party only.
        #[arg(long)]
        follow_user_active: bool,
        /// Reserved for forward compatibility — not yet enforced at
        /// request time. Stored as a JSON array on the app_records row.
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        requested_permissions: Vec<String>,
        /// Comma-separated filter stage names (e.g. `pre_forward`). When set,
        /// this app is registered as a proxy filter: the proxy supervisor
        /// discovers it via `app_records.filter_stages IS NOT NULL` and spawns
        /// it on the data plane (e.g. ai-compliance-detector). Filter-only
        /// apps may register with no `--upstreams`.
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        filter_stages: Vec<String>,
        /// Filter chain priority (lower = earlier). Only meaningful with
        /// `--filter-stages`. Default 100.
        #[arg(long)]
        filter_priority: Option<i64>,
        /// Filter timeout behavior: `fail_open` (forward unfiltered on filter
        /// failure) or `fail_closed`. Only meaningful with `--filter-stages`.
        /// Default `fail_open`.
        #[arg(long)]
        filter_timeout_policy: Option<String>,
        /// Force a new bearer to be issued even if the app already has
        /// an active one. Default: reuse existing bearer on
        /// re-register (vendor installer can re-run register safely).
        #[arg(long)]
        rotate_bearer: bool,
    },
    /// List all registered apps + their active key + last-used timestamp.
    List,
    /// Override the per-upstream binding for an already-registered app
    /// (optional; default binding is the snapshot taken at `aikey app
    /// register` time, inherited from `aikey use`).
    ///
    /// Bearer issuance has moved into `aikey app register` (2026-05-21
    /// redesign); this command only writes the binding row and DOES NOT
    /// issue or rotate a bearer. The `--yes` flag is preserved for
    /// backward compatibility but is a no-op (you'll get a deprecation
    /// warning).
    ///
    /// Default UX is INTERACTIVE: shows one table row per declared
    /// upstream, lets you pick a key (personal alias / OAuth account /
    /// team-managed key) for each.
    ///
    /// CI / non-interactive mode: pass `--upstream X --key-type Y
    /// --key-ref Z` to set one specific binding.
    Route {
        slug: String,
        /// Non-interactive: which upstream provider to bind (must be one
        /// of the values declared via `aikey app register --upstreams`).
        #[arg(long)]
        upstream: Option<String>,
        /// Non-interactive: `personal` / `team` / `personal_oauth_account`.
        #[arg(long, requires = "upstream", requires = "key_ref")]
        key_type: Option<String>,
        /// Non-interactive: vault alias / virtual_key_id / OAuth account_id
        /// matching the chosen --key-type.
        #[arg(long, requires = "upstream", requires = "key_type")]
        key_ref: Option<String>,
        /// Auto-accept the bearer-issuance consent prompt (CI-only).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Revoke ALL active bearer tokens for an app. History rows are
    /// preserved for audit; the app stays registered. Re-issue by
    /// running `aikey app route <slug>` again.
    Revoke { slug: String },
    /// Mark all active keys for an app as paused (state column flipped
    /// to 'paused'). Pause is reversible via `aikey app resume`.
    Pause { slug: String },
    /// Re-activate all paused keys for an app (state 'paused' → 'active').
    Resume { slug: String },
    /// Rotate the bearer: in one atomic transaction, revoke the current
    /// active key and issue a new one with the same bindings. Used when
    /// you suspect the bearer was leaked.
    Rotate { slug: String },
    /// Install a first-party / deep-partner app from the aikeylabs/launch
    /// manifest registry.
    ///
    /// Plugin-autonomy model (2026-05-22):
    ///   1. CLI validates `<slug>` against a built-in TRUSTED_APPS allow-list
    ///      (slug + manifest URL + SHA-256 are all pinned at compile time).
    ///   2. Downloads the manifest, verifies SHA-256 against the built-in
    ///      hash (zero phishing window — the binary is the trust anchor),
    ///      caches at `~/.aikey/apps-cache/<slug>/manifest.json`.
    ///   3. Curl-pipes the manifest's `service_installer.url` to the user's
    ///      shell. The installer script is owned by the plugin and is
    ///      responsible for ALL plugin-specific setup:
    ///        - downloading the plugin's binary
    ///        - registering launchd / systemd services
    ///        - writing any required env / token files
    ///        - and (idempotently) calling `aikey app register` to surface
    ///          the app in the vault — see the install_service.sh fallback
    ///          for the canonical pattern
    ///
    /// CLI is intentionally NOT in charge of register / authorize for these
    /// installs — that's the plugin's domain (it knows its own manifest
    /// fields). CLI is a launcher, not an orchestrator of plugin state.
    ///
    /// Third-party Agents do NOT use this command — they ship their own
    /// installer and call `aikey app register` directly. See
    /// `roadmap20260320/技术实现/阶段4-增值版/第三方Agent自助接入与应用级Key方案.md`
    /// §2.6 + §11.B for the design rationale.
    Install {
        /// Trusted app slug. Must match an entry in CLI's built-in
        /// allow-list (currently: degrade-detector).
        slug: String,
    },
    /// Uninstall a first-party app: stop its service, remove its binary,
    /// and clean up its vault rows (app_keys + app_records + bindings).
    ///
    /// Added 2026-05-23 alongside the rc.5 default-install flip for
    /// degrade-detector — users who got the service auto-installed need
    /// a single command to opt out cleanly. Bypasses the revoke/rotate
    /// lock (mutationLockedSlugs in aikey-control) because uninstall is
    /// whole-system: the service goes down BEFORE the bearer is
    /// removed, so there's no half-state where a running agent has no
    /// bearer (the failure mode the revoke lock guards against).
    ///
    /// Re-install any time with `aikey app install <slug>`.
    Uninstall {
        /// Trusted app slug. Must match an entry in CLI's built-in
        /// allow-list (currently: degrade-detector). Third-party apps
        /// have to clean up via their own tooling — CLI doesn't know
        /// their service-installer URL.
        slug: String,
    },
    /// Print the currently-active route token (plaintext bearer) for an
    /// already-registered app. Use when you've misplaced the value
    /// originally shown by `aikey app register` and don't want to
    /// disrupt the running agent with `aikey app rotate`.
    ///
    /// Why this exists (2026-05-25): the token IS stored in vault
    /// plaintext (`app_keys.route_token`) and accessible to any process
    /// the user owns. Forcing rotate-only recovery added more friction
    /// than security on a single-user local toolchain. The reveal path
    /// is gated by vault unlock; auditing lives in shell history (CLI)
    /// or audit log (Web — handler emits an audit event).
    ///
    /// Output (default): just the token on stdout for easy `$(aikey app
    /// reveal-token foo)` substitution. With `--json`, returns a richer
    /// envelope `{slug, key_id, route_token, base_url}` matching the
    /// shape of `aikey app rotate --json` so scripts can swap freely.
    RevealToken {
        /// App slug. Must match an existing registered app (any kind:
        /// first-party or third-party).
        slug: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuthAction {
    /// Login to a provider OAuth account
    // 2026-05-08 Kimi 双平台拆分 review feedback [中]: 标签 "Kimi (Moonshot AI)"
    // 误导用户(实际是 Kimi Code OAuth);改为明确 "Kimi Code (kimi_code)" 并提示
    // Moonshot 走 API key 路径。'kimi' 仍作为 deprecated alias 接受。
    #[command(after_help = "\x1b[1mSupported providers:\x1b[0m
  claude              Claude (Anthropic) — requires Pro or Max subscription
  codex               Codex / ChatGPT (OpenAI) — requires ChatGPT Pro/Plus
  kimi_code (or kimi) Kimi Code (api.kimi.com) — Kimi Coding Plan
                      Note: Moonshot (api.moonshot.cn) does NOT support OAuth.
                            Use `aikey add <alias> --provider moonshot` instead.

\x1b[1mExamples:\x1b[0m
  aikey auth login claude
  aikey auth login codex --alias dev@acme.io
  aikey auth login kimi_code --alias my-kimi")]
    Login {
        /// Provider name: claude, codex, kimi (omit for interactive picker)
        provider: Option<String>,
        /// Display name/alias for the account (non-interactive mode).
        ///
        /// When given, `aikey auth login` skips the post-login prompt that asks
        /// for a display name, and uses this value directly. Typical use cases:
        ///   - Bulk-import Done page generates `aikey auth login <p> --alias <email>`
        ///     so the user can finish each OAuth flow with zero keyboard input.
        ///   - CI / scripted login where stdin is unavailable.
        ///
        /// Accepts up to 256 chars, no control characters.
        #[arg(long, value_name = "ALIAS")]
        alias: Option<String>,
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
pub(crate) enum DesktopAction {
    /// Diagnose Claude Desktop routing: detection, ownership, consent,
    /// gateway reachability, port consistency, and claude.ai account-plane
    /// reachability (Desktop chat needs BOTH planes — the gateway only
    /// carries inference).
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Route Claude Desktop through aikey now (follows the active claude
    /// credential; requires one). Also lifts a standing "never" refusal.
    Install,
    /// Restore Claude Desktop to official mode (1p) and clear the consent
    /// preference. Only undoes aikey's own takeover.
    Uninstall,
}

#[derive(Subcommand)]
pub(crate) enum StatuslineAction {
    /// Install the receipt display for Claude Code (default) or Kimi CLI.
    ///
    /// Targets:
    ///   claude  — write `~/.claude/settings.json` statusLine entry (default)
    ///   kimi    — ensure Kimi Stop hook in `~/.kimi/config.toml` managed region
    ///   (omit target = claude, for backward compat)
    Install {
        /// Target CLI: `claude` or `kimi`. Defaults to `claude`.
        target: Option<String>,
        /// Install for both targets. Mutually exclusive with `target`.
        #[arg(long, conflicts_with = "target")]
        all: bool,
        /// For claude: overwrite an existing non-aikey statusLine (backup kept).
        #[arg(long)]
        force: bool,
    },
    /// Remove the aikey install from Claude Code (default) or Kimi CLI.
    ///
    /// For kimi, this strips the entire aikey-managed region from
    /// `~/.kimi/config.toml` — resetting the Kimi provider to its pre-aikey
    /// state (the Kimi provider block is co-owned with the hook).
    Uninstall {
        /// Target CLI: `claude` or `kimi`. Defaults to `claude`.
        target: Option<String>,
        /// Uninstall for both targets.
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Print whether the Claude Code + Kimi CLI receipt hooks are currently
    /// wired up to aikey, without making any changes.
    Status,
    /// Print the session_id and model id of the most recent WAL event.
    /// Useful for debugging Claude Code session divergence (see §14 of
    /// 费用小票-实施方案.md) or for feeding into shell scripts.
    #[command(name = "last-active")]
    LastActive,
    /// Render a receipt for a specific agent target. Invoked by a CLI hook
    /// (e.g. Kimi's Stop hook); reads a JSON context from stdin. For Claude
    /// Code, the bare `aikey statusline` path is the statusLine entry —
    /// this subcommand is only useful for push-based hosts like Kimi.
    Render {
        /// Target CLI: currently only `kimi`. Claude Code uses the stdin
        /// statusLine path (no subcommand).
        target: String,
    },
    /// Fire-and-forget auto-install for the shell wrapper. Resolves the
    /// active Claude config dir (`$CLAUDE_CONFIG_DIR` or `~/.claude`), then
    /// installs the aikey statusLine if the slot is empty. Silent on every
    /// path — never prints, never blocks `claude` startup. Set
    /// `AIKEY_DISABLE_STATUSLINE_ENSURE=1` to short-circuit if you ran
    /// `aikey statusline uninstall` and want it to stay uninstalled.
    Ensure,
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
pub(crate) enum AuditAction {
    /// Show per-source delivery completeness (allocated / confirmed / gaps / known-loss / quarantine).
    Status,
    /// Force an immediate reconciliation (scan + known-loss promotion), then show the verdict.
    Reconcile,
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
    /// Re-deliver dead-lettered usage events to the collector. Triggers
    /// the proxy's POST /admin/replay-dead-letter endpoint using the
    /// reporter's CURRENT config (post-login JWT, current route URLs).
    /// Idempotent: events that re-deliver are removed from
    /// dead_letter.jsonl; events still failing stay for a future try.
    ///
    /// Use after fixing the upstream cause of a terminal failure (e.g.
    /// re-logging in to refresh an expired JWT, restoring a collector
    /// that was briefly down) to recover events that would otherwise
    /// be permanently lost.
    #[command(name = "replay-dead-letter")]
    ReplayDeadLetter,
    /// (internal) Ensure aikey-proxy is running. No-op if already up; auto-
    /// starts via the same env-var/cache/TTY-prompt chain `aikey use` uses.
    /// Hidden from `--help` because it's a wrapper-internal entry point used
    /// by the claude/codex/kimi shell hooks — end-users should reach for
    /// `aikey proxy start` instead.
    #[command(hide = true, name = "ensure-running")]
    EnsureRunning,
}

/// Subcommand verbs for `aikey hook`. Stage 8 (Stage 8-1 / 8-2 in the
/// active-state cross-shell sync plan, 2026-04-27): exposes the hash-based
/// drift detector that lives in hook.{zsh,bash} as an explicit user entry
/// point so a user who only wants to refresh the hook (without changing any
/// vault binding) doesn't have to run `aikey use` and worry about side
/// effects on third-party CLI configs.
/// Subcommands for `aikey agent` (龙虾/OpenClaw digital-employee daemon).
#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Self-register this host as a digital employee using an org join token.
    ///
    /// Validates the join token against the Control plane, which creates the
    /// service account + seat (no VK yet — the admin assigns one later), and
    /// returns a long-lived daemon credential that is stored in the local vault.
    /// Run once, typically from the install script. The vault master password is
    /// taken from the `AIKEY_MASTER_PASSWORD` env (same as the cluster daemon);
    /// if unset and a TTY is present, you are prompted.
    Register {
        /// Org join token from the admin console.
        ///
        /// allow_hyphen_values: join tokens are base64url (server GenerateOpaqueToken),
        /// whose alphabet includes '-', so ~1/64 tokens start with '-'. Without this,
        /// the documented space form `--join-token -Mxxx…` makes clap parse the value
        /// as an unknown flag → cryptic "unrecognized command '-M'" and ~1.6% of DE
        /// registrations fail. Bugfix: 2026-06-22-agent-register-join-token-leading-dash.
        #[arg(long = "join-token", allow_hyphen_values = true)]
        join_token: String,
        /// Control Panel URL (e.g. http://192.168.1.100:3000). Defaults to the
        /// value already saved in this host's config, if any.
        #[arg(long = "control-url", alias = "url")]
        url: Option<String>,
        /// Display name shown in the console (default: this host's hostname).
        #[arg(long)]
        name: Option<String>,
    },
    /// Run the unattended sync daemon (foreground; managed by systemd/launchd).
    ///
    /// Each cycle refreshes the assigned virtual key into the local vault (what
    /// the proxy serves) and keeps OpenClaw pointed at the proxy. Waits quietly
    /// until an admin assigns a VK. Retries on transient errors; never exits.
    Start {
        /// Seconds between sync cycles (default 30, minimum 5).
        #[arg(long, default_value_t = crate::commands_agent::DEFAULT_INTERVAL_SECS)]
        interval: u64,
    },
    /// Show this host's digital-employee enrollment + sync status.
    Status,
}

#[derive(Subcommand)]
pub(crate) enum HookAction {
    /// Regenerate ~/.aikey/hook.{zsh,bash} from the binary's embedded
    /// template (Layer 1 only — does NOT touch your shell rc). Idempotent.
    Update,
    /// Report file / binary / loaded hashes and flag drift.
    Status {
        /// Integration target. Omit = shell hook status (default).
        /// `openclaw` = show whether OpenClaw is wired to the aikey proxy.
        #[arg(value_name = "TARGET")]
        target: Option<String>,
        /// Override shell detection (zsh | bash). Default: detect from $SHELL.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
    },
    /// First-time install: render hook file AND wire ~/.zshrc / ~/.bashrc
    /// (Layer 1 + Layer 2). Will prompt before modifying rc.
    ///
    /// Hook coverage v1: this is the explicit entry point for users who
    /// went through Web-only onboarding (e.g. clicked 「Set as active key」
    /// in the Web UI without ever running CLI commands). Web operations
    /// only render the hook file; rc wiring still requires a CLI prompt.
    Install {
        /// Integration target. Omit = install the shell precmd hook (default).
        /// `openclaw` = wire OpenClaw (龙虾 digital employee) to route its LLM
        /// calls through the local aikey proxy using the active team key.
        /// `codex` = clear a standing Codex "never" refusal so the next
        /// `aikey use` of an OpenAI key offers Codex configuration again.
        #[arg(value_name = "TARGET")]
        target: Option<String>,
        /// Override shell detection (zsh | bash). Default: detect from $SHELL.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
        /// Skip Layer 2 (rc wiring). Equivalent to `aikey hook update`.
        /// Useful in CI / sandbox tests that want Layer 1 only.
        #[arg(long)]
        no_hook: bool,
    },
    /// Force re-write both layers (hook file + rc block) and report which
    /// file was touched. Use after a major hook template change (e.g. the
    /// 2026-05-18 codex sentinel-gate) to make the propagation visible.
    /// Idempotent; safe to run repeatedly.
    Reinstall {
        /// Override shell detection (zsh | bash). Default: detect from $SHELL.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
    },
    /// Remove the aikey shell hook from your shell startup files.
    ///
    /// Strips the `# aikey shell hook v3 begin … end` block from EVERY shell
    /// rc across all shells (~/.zshrc, ~/.bashrc, ~/.bash_profile, and the
    /// PowerShell profile), backing up each file it edits. Legacy v2 blocks
    /// are stripped too. Takes no flags — uninstall is always all-shells.
    ///
    /// Layer 1 hook files (~/.aikey/hook.{zsh,bash,ps1}) are KEPT — only the
    /// rc `source` reference is removed, so `aikey hook install` can re-wire
    /// without regenerating them. New shells will no longer load the hook;
    /// already-running shells keep any variables they already exported until
    /// you open a new terminal.
    ///
    /// Idempotent: a no-op (still exits 0) when no hook block is present.
    Uninstall {
        /// Integration target. Omit = remove the shell hook (default).
        /// `openclaw` = remove the aikey provider from OpenClaw config.
        #[arg(value_name = "TARGET")]
        target: Option<String>,
    },
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
    /// Show all personal, team, and OAuth keys (alias: `aikey list`)
    List,
    /// Sync all team key metadata from the control service
    Sync {
        /// Clear local team key ciphertext before sync and re-download under
        /// the current vault_key. Recovery path when proxy logs
        /// "managed key: decryption failed, skipping" (e.g. after a vault
        /// state where ciphertext was written with an inconsistent key).
        #[arg(long = "force-reencrypt")]
        force_reencrypt: bool,
    },
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
        /// Force a new activation email even if one was sent within the last 60 seconds
        #[arg(long)]
        resend: bool,
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
            Commands::Db { action } => format!(
                "db.{}",
                match action {
                    DbAction::Upgrade => "upgrade",
                    DbAction::Rollback { .. } => "rollback",
                }
            ),
            Commands::Internal { action } => format!(
                "_internal.{}",
                match action {
                    crate::commands_internal::InternalAction::VaultOp(_) => "vault-op",
                    crate::commands_internal::InternalAction::Query(_) => "query",
                    crate::commands_internal::InternalAction::UpdateAlias(_) => "update-alias",
                    crate::commands_internal::InternalAction::Parse(_) => "parse",
                    crate::commands_internal::InternalAction::Rules(_) => "rules",
                    crate::commands_internal::InternalAction::App(_) => "app",
                    crate::commands_internal::InternalAction::Init(_) => "init",
                    crate::commands_internal::InternalAction::HookOp(_) => "hook-op",
                }
            ),
            Commands::Add { .. } => "add".to_string(),
            Commands::Get { .. } => "get".to_string(),
            Commands::Delete { .. } => "delete".to_string(),
            Commands::List => "list".to_string(),
            Commands::Update { .. } => "update".to_string(),
            Commands::Test { .. } => "test".to_string(),
            Commands::Export { .. } => "export".to_string(),
            Commands::Run { .. } => "run".to_string(),
            Commands::ChangePassword => "change-password".to_string(),
            Commands::Secret { action } => format!(
                "secret.{}",
                match action {
                    SecretAction::Set { .. } => "set",
                    SecretAction::Upsert { .. } => "upsert",
                    SecretAction::List => "list",
                    SecretAction::Delete { .. } => "delete",
                }
            ),
            Commands::Project { action } => format!(
                "project.{}",
                match action {
                    ProjectAction::Init => "init",
                    ProjectAction::Status => "status",
                    ProjectAction::Map { .. } => "map",
                }
            ),
            Commands::Quickstart => "quickstart".to_string(),
            Commands::Logs { .. } => "logs".to_string(),
            Commands::Key { action } => format!(
                "key.{}",
                match action {
                    KeyAction::Rotate { .. } => "rotate",
                    KeyAction::List => "list",
                    KeyAction::Sync { .. } => "sync",
                    KeyAction::Use { .. } => "use",
                    KeyAction::Alias { .. } => "alias",
                }
            ),
            Commands::Use { .. } => "key.use".to_string(),
            Commands::Unuse { .. } => "key.unuse".to_string(),
            Commands::Activate { .. } => "activate".to_string(),
            Commands::Deactivate { .. } => "deactivate".to_string(),
            Commands::Route { .. } => "route".to_string(),
            Commands::Status => "status".to_string(),
            Commands::Whoami => "whoami".to_string(),
            Commands::Account { action } => format!(
                "account.{}",
                match action {
                    AccountAction::Login { .. } => "login",
                    AccountAction::Status => "status",
                    AccountAction::Logout => "logout",
                    AccountAction::SetUrl { .. } => "set-url",
                }
            ),
            Commands::Login { .. } => "account.login".to_string(),
            Commands::Logout => "account.logout".to_string(),
            Commands::Env { .. } => "env".to_string(),
            Commands::Web { .. } => "web".to_string(),
            Commands::Master { .. } => "master".to_string(),
            Commands::Import { .. } => "import".to_string(),
            Commands::Doctor { .. } => "doctor".to_string(),
            Commands::Proxy { action } => format!(
                "proxy.{}",
                match action {
                    ProxyAction::Start { .. } => "start",
                    ProxyAction::Stop => "stop",
                    ProxyAction::Status => "status",
                    ProxyAction::Restart { .. } => "restart",
                    ProxyAction::Verify => "verify",
                    ProxyAction::ReplayDeadLetter => "replay-dead-letter",
                    ProxyAction::EnsureRunning => "ensure-running",
                }
            ),
            Commands::Auth { action } => format!(
                "auth.{}",
                match action {
                    AuthAction::Login { .. } => "login",
                    AuthAction::Logout { .. } => "logout",
                    AuthAction::List => "list",
                    AuthAction::Use { .. } => "use",
                    AuthAction::Status { .. } => "status",
                    AuthAction::Doctor { .. } => "doctor",
                }
            ),
            Commands::Version => "version".to_string(),
            Commands::Desktop { action } => format!(
                "desktop.{}",
                match action {
                    DesktopAction::Status { .. } => "status",
                    DesktopAction::Install => "install",
                    DesktopAction::Uninstall => "uninstall",
                }
            ),
            Commands::Statusline { action } => match action {
                None => "statusline".to_string(),
                Some(StatuslineAction::Install { target, all, .. }) => {
                    let t = if *all {
                        "all".to_string()
                    } else {
                        target.clone().unwrap_or_else(|| "claude".to_string())
                    };
                    format!("statusline.install.{t}")
                }
                Some(StatuslineAction::Uninstall { target, all }) => {
                    let t = if *all {
                        "all".to_string()
                    } else {
                        target.clone().unwrap_or_else(|| "claude".to_string())
                    };
                    format!("statusline.uninstall.{t}")
                }
                Some(StatuslineAction::Status) => "statusline.status".to_string(),
                Some(StatuslineAction::LastActive) => "statusline.last-active".to_string(),
                Some(StatuslineAction::Render { target }) => {
                    format!("statusline.render.{target}")
                }
                Some(StatuslineAction::Ensure) => "statusline.ensure".to_string(),
            },
            Commands::Watch => "watch".to_string(),
            Commands::Audit { action } => format!(
                "audit.{}",
                match action {
                    AuditAction::Status => "status",
                    AuditAction::Reconcile => "reconcile",
                }
            ),
            Commands::HookHash { .. } => "_hook-hash".to_string(),
            Commands::RefreshActiveEnv { .. } => "_refresh-active-env".to_string(),
            Commands::Hook { action } => match action {
                HookAction::Update => "hook.update".to_string(),
                HookAction::Status { .. } => "hook.status".to_string(),
                HookAction::Install { .. } => "hook.install".to_string(),
                HookAction::Reinstall { .. } => "hook.reinstall".to_string(),
                HookAction::Uninstall { .. } => "hook.uninstall".to_string(),
            },
            Commands::Agent { action } => match action {
                AgentAction::Register { .. } => "agent.register".to_string(),
                AgentAction::Start { .. } => "agent.start".to_string(),
                AgentAction::Status => "agent.status".to_string(),
            },
            Commands::Trust { action } => match action {
                TrustAction::Verify { .. } => "trust.verify".to_string(),
                TrustAction::Status { .. } => "trust.status".to_string(),
                TrustAction::History { .. } => "trust.history".to_string(),
                TrustAction::Sync { .. } => "trust.sync".to_string(),
                TrustAction::Refresh { .. } => "trust.refresh".to_string(),
            },
            Commands::App { action } => match action {
                AppAction::Register { .. } => "app.register".to_string(),
                AppAction::List => "app.list".to_string(),
                AppAction::Route { .. } => "app.route".to_string(),
                AppAction::Revoke { .. } => "app.revoke".to_string(),
                AppAction::Pause { .. } => "app.pause".to_string(),
                AppAction::Resume { .. } => "app.resume".to_string(),
                AppAction::Rotate { .. } => "app.rotate".to_string(),
                AppAction::Install { .. } => "app.install".to_string(),
                AppAction::Uninstall { .. } => "app.uninstall".to_string(),
                AppAction::RevealToken { .. } => "app.reveal-token".to_string(),
            },
            Commands::Service { action } => match action {
                ServiceAction::Start { .. } => "service.start".to_string(),
                ServiceAction::Stop { .. } => "service.stop".to_string(),
                ServiceAction::Restart { .. } => "service.restart".to_string(),
                ServiceAction::Status { .. } => "service.status".to_string(),
            },
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
        return Err(format!(
            "Secret name is too long ({} chars). Maximum is 256 characters.",
            name.len()
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | ':' | '.'))
    {
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
    - --no-hook skips shell hook installation.

Runtime switching of a running CLI (e.g. an open `claude` chat):
    - For ANY credential type (personal API key, OAuth, team), a later
      `aikey use` takes effect immediately in already-running CLI sessions
      launched via plain `claude` / `codex` / `kimi` — no restart needed
      (e.g. swap to a fresh OAuth account when one runs out of quota).
    - The 2026-04-29 token-prefix rename refactor unified all credential
      types under one namespace-authority dispatch model — the previous
      'team is locked' asymmetry has been removed.
    - Sessions launched via `aikey activate` are pinned and DO NOT follow.
    - See: workflow/Docs/Production/aikey-use-runtime-switching.md"),

        "activate" => Some("\
Notes:
    - Temporarily sets API key environment variables in the current terminal.
    - Does not write to active.env or modify provider bindings.
    - Closing the terminal automatically reverts to global settings.
    - --provider is required when the key supports multiple providers.
    - --shell is passed automatically by the aikey() shell wrapper.
    - Use `aikey deactivate` to restore global settings in the same terminal.

Pinning semantics (vs. `aikey use`):
    - `aikey activate` PINS the launched CLI to the named key for any
      credential type (personal / OAuth / team). A later `aikey use` from
      another shell does NOT switch the pinned CLI — restart it to change.
    - Use `aikey use` (not `activate`) if you want runtime switching of a
      running CLI session for personal / OAuth keys.
    - See: workflow/Docs/Production/aikey-use-runtime-switching.md"),

        "deactivate" => Some("\
Notes:
    - Restores global active.env settings in the current terminal.
    - Undoes the effect of `aikey activate`.
    - --shell is passed automatically by the aikey() shell wrapper."),

        "route" => Some("\
Notes:
    - Shows route tokens for configuring third-party AI clients (Cursor, OpenCode, etc.).
    - Each key/account gets a random aikey_personal_<64-hex> token used as the API_KEY in client config.
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
    - PAGE: overview | keys | vault | account | usage | import | referrals | trust-check
    - Service control: PAGE = start | stop | restart  →  controls the local
      web service (aikey-local-server on Personal, aikey-trial-server on Trial).
      Bare `aikey web` opens the browser; `aikey web restart` reboots the backend.
    - --vault and --import are shortcut flags for opening those pages directly.
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
    - Shows Personal Keys, Team Keys, and OAuth Accounts in one view.
    - `aikey list` is a shortcut for this command.
    - May refresh metadata from server when possible.
    - If server state changed, AiKey may prompt for the vault password to complete a full sync."),

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
    println!(
        "\
AiKey - Secure local-first secret management

Usage: aikey [OPTIONS] [COMMAND]

Commands:
  {b}account{r} <command>        Manage your aikey account session
  {b}activate{r} <alias>          Temporarily activate a key in the current terminal
  {b}add{r} <alias>              Save a new secret to the vault
  {b}auth{r} <command>           Manage provider OAuth accounts (Claude, Codex, Kimi)
  {b}change-password{r}          Change the vault master password
  {b}deactivate{r}               Restore global settings in the current terminal
  {b}delete{r} <alias>           Delete a secret from the vault
  {b}doctor{r}                   Check system health, connectivity, and configuration
  {b}env{r} [command]            View or set proxy environment variables
  {b}export{r} <pattern> <file>  Export secrets to an encrypted backup file
  {b}get{r} <alias>              Retrieve a secret and copy it to the clipboard
  {b}help{r}                     Show this help message or help for a command
  {b}key{r} <command>            Manage API keys (rotate, list, sync, use)
  {b}list{r}                     Show all personal, team, and OAuth keys (alias for `key list`)
  {b}login{r}                    Log in to aikey service (shortcut for `account login`)
  {b}logout{r}                   Log out of the current session (shortcut for `account logout`)
  {b}logs{r}                     Show recent activity logs
  {b}master{r} [page]            Open the Master Console (admin) in your default browser
  {b}project{r} <command>        Manage project configuration
  {b}proxy{r} <command>          Manage the local proxy process
  {b}quickstart{r}               Show a state-aware landing page with the next most useful commands
  {b}route{r} [label]            Show proxy route tokens for third-party AI clients
  {b}run{r} -- <command>         Run a command with secrets injected as environment variables
  {b}secret{r} <command>         Manage secrets and platform-backed secret actions
  {b}status{r}                   Show a summary of gateway, login, keys, and providers
  {b}statusline{r}               Render a one-line usage receipt for Claude Code's status line
  {b}test{r} <alias>             Test whether a stored API key alias is working
  {b}unuse{r} <provider...>      Remove the active binding for one or more providers
  {b}update{r} <alias>           Update an existing secret
  {b}use{r} [alias]              Select the active key for routing (shortcut for `key use`)
  {b}watch{r}                    Show a top-style dashboard of recent key usage
  {b}web{r} [page]               Open the User Console in your default browser
  {b}whoami{r}                   Show your current login, active key, and vault status

Options:
      --password-stdin  Read password from stdin instead of prompting
      --json            Output in JSON format (where supported)
  -V, --version         Print version information
  -h, --help            Print help
      --detail          Print detailed help for all commands

Frequently used:
  {b}use{r} [alias]              Select the active key for routing (shortcut for `key use`)
  {b}login{r}                    Log in to aikey service (shortcut for `account login`)
  {b}doctor{r}                   Check system health, connectivity, and configuration
  {b}web{r} [page]               Open the User Console in your default browser
  {b}master{r} [page]            Open the Master Console (admin) in your default browser"
    );
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
  Show all personal, team, and OAuth keys in one view (alias for `aikey key list`).

  Usage:
    aikey list

  Notes:
    - Shows Personal Keys, Team Keys, and OAuth Accounts.
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

  Runtime switching of a running CLI (e.g. an open `claude` chat):
    - For ANY credential type (personal API key, OAuth, team), a later
      `aikey use` takes effect immediately in already-running CLI sessions
      launched via plain `claude` / `codex` / `kimi` — no restart needed.
    - The 2026-04-29 token-prefix rename refactor unified all credential
      types; the previous 'team is locked' asymmetry has been removed.
    - Sessions launched via `aikey activate` are pinned and DO NOT follow.
    - See: workflow/Docs/Production/aikey-use-runtime-switching.md

[1munuse[0m
  Remove the active binding for one or more providers.

  Usage:
    aikey unuse <PROVIDER>...

  Notes:
    - Inverse of `aikey use`. Clears the active-key binding for the
      named provider(s) so subsequent CLI launches start without a
      pre-selected key. Accepts one or more provider codes
      (e.g. `aikey unuse openai anthropic`).
    - Takes effect immediately in already-running CLI sessions for the
      same runtime-switching reasons `aikey use` does (no restart needed).
    - To remove the credential entry itself (not just the binding),
      use `aikey delete <ALIAS>`.

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

  Pinning semantics (vs. `aikey use`):
    - `aikey activate` PINS the launched CLI to the named key for any
      credential type (personal / OAuth / team). A later `aikey use` from
      another shell does NOT switch the pinned CLI — restart it to change.
    - Use `aikey use` (not `activate`) if you want runtime switching of a
      running CLI session for personal / OAuth keys.
    - See: workflow/Docs/Production/aikey-use-runtime-switching.md

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
    - Each key/account gets a random aikey_personal_<64-hex> token used as API_KEY in client config.
    - Without LABEL: lists all routes (tokens truncated; use --full for complete tokens).
    - With LABEL: shows full base_url + api_key ready to copy-paste.
    - --json outputs all routes as JSON with full tokens (for scripts).
    - Read-only command — does not modify vault or proxy.

  Example:
    $ aikey route my-key
    # Configuration for: my-key (personal, anthropic)
    base_url:  http://127.0.0.1:27200/anthropic
    api_key:   aikey_personal_b82ef1d49c3a7e08...

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
    aikey web [--port <PORT>] [--vault] [--import] [PAGE]

  Aliases:
    aikey browse

  Arguments:
    PAGE: overview | keys | vault | account | usage | import | referrals | trust-check
          (also: virtual-keys, team-keys, secrets, my-vault, profile,
          usage-ledger, bulk-import, quick-import, trust — resolved by the web UI)

  Flags:
    --vault    Shortcut for `aikey web vault` — opens the Personal Vault
               page directly so users can review / edit / route stored
               credentials without remembering the page name.
    --import   Shortcut for `aikey web import` — jumps straight to the
               Import page so pasted credentials can be landed in one step.

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
    - Protocols section lists all protocols discovered from personal and team keys.
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
        - Shows Personal Keys, Team Keys, and OAuth Accounts in one view.
        - `aikey list` is a shortcut for this command.
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

    let mut stream =
        TcpStream::connect_timeout(&"127.0.0.1:27200".parse().ok()?, Duration::from_millis(500))
            .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;

    use std::io::Write;
    stream
        .write_all(b"GET /version HTTP/1.1\r\nHost: 127.0.0.1:27200\r\nConnection: close\r\n\r\n")
        .ok()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let response = String::from_utf8_lossy(&buf);

    // Find the JSON body after the HTTP headers (separated by \r\n\r\n).
    let body = response.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body.trim()).ok()
}

// Eye row glyphs shared between the initial banner render and the blink
// animation. Centralizing them keeps the two paths byte-identical — a drift
// here would make the "reopen" frame look visibly different from the static
// eyes the banner first printed.
const BANNER_EYE_OPEN: &str =
    "\u{254D}\u{2588}  \u{27E8}\u{29BF}\u{27E9} \u{27E8}\u{29BF}\u{27E9}  \u{2588}\u{254D}";
// Closed eye uses `—` (U+2014 em dash) for a flat, "squint shut" look that
// reads more as a blink than a filled dot would.
const BANNER_EYE_SHUT: &str =
    "\u{254D}\u{2588}  \u{27E8}\u{2014}\u{27E9} \u{27E8}\u{2014}\u{27E9}  \u{2588}\u{254D}";
const BANNER_EYE_RIGHT: &str = "------------------------------------";

// Tagline shared between the initial banner render and the shimmer animation
// (like BANNER_EYE_* above — one source so the animated row can never drift
// from the statically-printed one). 2026-07-18: "FinOps & AI Governance
// Center" → "AI RUNTIME GOVERNANCE" per brand.
const BANNER_TAGLINE: &str = "AI RUNTIME GOVERNANCE";
// The owl mouth row art (`╍█  ▼  █╍`) that sits to the LEFT of the tagline;
// the shimmer redraws the whole row so it needs this prefix verbatim.
const BANNER_ROW_MOUTH_ART: &str = "\u{254D}\u{2588}     \u{25BC}     \u{2588}\u{254D}";
// Repo URL — 2026-07-18 moved out of the banner (was on the logo feet row)
// down to the very bottom under the "Run 'aikey --help'" hint (print_repo_url).
const BANNER_REPO_URL: &str = "https://github.com/aikeylabs";

// Muted gold: RGB(160, 135, 75). Defined here so both functions colorize
// consistently without duplicating the tuple.
fn banner_gold(s: &str) -> colored::ColoredString {
    use colored::Colorize;
    s.truecolor(160, 135, 75)
}

pub(crate) fn print_banner() {
    use colored::Colorize;
    let version = BUILD_VERSION;
    // Stage 2.6 windows-compat: `format!("{}/...", home)` produced
    // mixed separators on Windows (`C:\Users\michael/.aikey`). Route
    // through the canonical resolver so the banner shows native paths.
    let aikey_home = crate::commands_account::resolve_aikey_dir()
        .display()
        .to_string();

    // win10-conhost-compat: the owl art uses glyphs (╍ ⟨⦿⟩ ╭╮ ▀▄) that
    // conhost fonts cannot render — the logo would come out as □ noise.
    // Safe tier keeps the same information rows (name/version, tagline,
    // URL) as plain text and skips the art + blink entirely.
    if crate::term_caps::unicode_tier() == crate::term_caps::UnicodeTier::Safe {
        eprintln!();
        eprintln!("  {}   v{}", "AiKey CLI".bold(), version);
        eprintln!("  {}", BANNER_TAGLINE.cyan().bold());
        // URL moved to the bottom (print_repo_url) — see art-tier comment below.
        eprintln!();
        return;
    }

    // Lines 2–5 of the icon carry side labels (title/divider/tagline/home).
    // Lines 1 and 6 are purely decorative. Initial eyes render OPEN —
    // `animate_banner_blink` drives the close-and-reopen blink once the
    // caller has finished all subsequent output.
    eprintln!();
    eprintln!("   {}", banner_gold("\u{25B2}           \u{25B2}"));
    eprintln!("   {}       {}   v{}",
        banner_gold("\u{256D}\u{2588}\u{2588}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}\u{2588}\u{2588}\u{256E}"),
        "AiKey CLI".bold(),
        version);
    eprintln!(
        "  {}       {}",
        banner_gold(BANNER_EYE_OPEN),
        BANNER_EYE_RIGHT.dimmed()
    );
    // 2026-05-29 — mirror local-install.sh banner colors so brand looks
    // identical from install time through every `ak` / `aikey` run:
    //   tagline → cyan + bold (matches installer's `C_CYAN="\033[1;36m"`)
    //   path    → bright_black (matches installer's `C_DIM="\033[90m"`,
    //              renders as solid medium-grey vs `.dimmed()` which is
    //              a faint-intensity attribute that some terminals
    //              under-render)
    // Tagline printed in its FINAL static style (cyan + bold). When a TTY is
    // present, animate_banner_shimmer redraws this row with a left→right
    // brightness sweep, then settles it back to exactly this.
    eprintln!(
        "  {}        {}",
        banner_gold(BANNER_ROW_MOUTH_ART),
        BANNER_TAGLINE.cyan().bold()
    );
    // 2026-05-29 — banner restructured per UX:
    //   - Path row removed (aikey_home was here; redundant with `aikey
    //     config show` and rarely the info users want at every CLI run)
    //   - Open-source URL moved into row 5 (logo bottom) right-side as
    //     the top-of-banner trust signal; URL is underlined +
    //     bright_black so it visually reads as a clickable link while
    //     staying visually quiet. Mirrors local-install.sh feet row
    //     exactly (workflow commit chain b4b3a2a → 6b8b9f6 → follow-up)
    //     so brand looks identical at install time and every `ak` run.
    let _ = aikey_home; // kept reachable for future re-introduction
                        // 2026-07-18 user request: the repo URL moved off this feet row down to
                        // the very bottom of the no-arg screen (under "Run 'aikey --help'"), so
                        // the logo bottom is now just the owl feet. print_repo_url() emits the URL
                        // at its new home. (Previously the URL sat here as a top-of-banner trust
                        // signal; the user preferred it as a footer.)
    eprintln!("   {}",
        banner_gold("\u{2570}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{256F}"));
    eprintln!("       {}", banner_gold("\u{2579}   \u{2579}"));
    eprintln!();
}

/// Print the open-source repo URL as its own footer line (bright_black +
/// underline so it reads as a quiet clickable link). 2026-07-18: extracted so
/// both the `--version` banner and the no-command screen render the same URL
/// line at their respective bottoms (it left the banner's logo feet row).
pub(crate) fn print_repo_url() {
    use colored::Colorize;
    eprintln!("  {}", BANNER_REPO_URL.bright_black().underline());
}

/// Run the banner's one-shot eye blink: ⦿ → ● → ⦿. Call AFTER all static
/// output (banner + whatever the caller prints underneath) has been emitted
/// so the user sees the full screen first, then the eyes wink.
///
/// `extra_lines` is the number of lines the caller printed after
/// `print_banner()` returned. The eye row sits 5 rows above where
/// `print_banner` last left the cursor, so the animation steps up
/// `5 + extra_lines` lines to rewrite it.
///
/// No-ops on non-TTY or when `AIKEY_NO_ANIMATION=1`. Uses plain
/// `\x1b[nA` / `\x1b[nB` (not `\x1b[s` save/restore) because saved
/// positions become invalid if the banner caused scroll-buffer shifts
/// during the sleep.
pub(crate) fn animate_banner_blink(extra_lines: usize) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let enabled = std::io::stderr().is_terminal()
        && std::env::var("AIKEY_NO_ANIMATION").map_or(true, |v| v != "1" && v != "true");
    if !enabled {
        return;
    }
    // win10-conhost-compat: Safe tier renders the text banner (no eye row),
    // so there is nothing to blink — and rewriting 5 rows up would clobber
    // unrelated output.
    if crate::term_caps::unicode_tier() == crate::term_caps::UnicodeTier::Safe {
        return;
    }

    let up = 5 + extra_lines;
    let right = BANNER_EYE_RIGHT.dimmed();
    let mut err = std::io::stderr().lock();

    // Blink sequence modelled on a real owl's double-wink:
    //   F1 open 1500ms → long gaze, the dominant visual state
    //   F2 shut  120ms → crisp snap-closed
    //   F3 open  180ms → brief reopen between winks
    //   F4 shut  120ms → second snap-closed
    //   F1 open  500ms tail → settle back to the static final state
    // Total ≈ 2.4s, most of which is the initial 1500ms during which the
    // user is already reading the banner + hints, so it feels like ambient
    // motion rather than a blocking delay.
    let render = |eyes: colored::ColoredString| {
        // Each frame: jump to eye row, clear, rewrite, jump back.
        format!(
            "\x1b[{n}A\r\x1b[2K  {eyes}       {right}\r\x1b[{n}B",
            n = up,
            eyes = eyes,
            right = right
        )
    };
    let shut = render(banner_gold(BANNER_EYE_SHUT));
    let open = render(banner_gold(BANNER_EYE_OPEN));

    let frames: [(&str, u64); 5] = [
        (&shut, 1000), // F1 pause, then F2 snap shut
        (&open, 120),  // F3 reopen
        (&shut, 180),  // F4 snap shut again
        (&open, 120),  // settle back to open
        ("", 500),     // tail pause with open eyes before returning
    ];

    for (frame, pre_sleep_ms) in frames {
        std::thread::sleep(std::time::Duration::from_millis(pre_sleep_ms));
        if !frame.is_empty() {
            let _ = err.write_all(frame.as_bytes());
            let _ = err.flush();
        }
    }
}

/// Sweep a left→right brightness highlight across the "AI RUNTIME GOVERNANCE"
/// tagline (like Codex's shimmering "wait" text), then settle it back to the
/// static cyan style. Call AFTER all static output, same as
/// `animate_banner_blink`; `extra_lines` is the number of lines the caller
/// printed after `print_banner()` returned. The tagline sits on banner row 4,
/// which is `4 + extra_lines` rows above the final cursor.
///
/// No-ops on non-TTY, when `AIKEY_NO_ANIMATION=1`, in the Safe unicode tier
/// (no owl art there), or when colour is disabled (`NO_COLOR` etc.) — a moving
/// highlight is meaningless without truecolor, so we skip the redraws entirely
/// rather than flicker uncoloured text.
pub(crate) fn animate_banner_shimmer(extra_lines: usize) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let enabled = std::io::stderr().is_terminal()
        && std::env::var("AIKEY_NO_ANIMATION").map_or(true, |v| v != "1" && v != "true")
        && colored::control::SHOULD_COLORIZE.should_colorize();
    if !enabled || crate::term_caps::unicode_tier() == crate::term_caps::UnicodeTier::Safe {
        return;
    }

    let up = 4 + extra_lines;
    let art = banner_gold(BANNER_ROW_MOUTH_ART);
    let chars: Vec<char> = BANNER_TAGLINE.chars().collect();
    let n = chars.len() as f64;
    let mut err = std::io::stderr().lock();

    // Base = the resting cyan; peak = a near-white crest. Each char blends
    // between them by proximity to the moving sweep centre `p` (triangular
    // falloff, smoothstep-eased), so a soft bright band glides across.
    const BASE: (f64, f64, f64) = (99.0, 188.0, 205.0);
    const PEAK: (f64, f64, f64) = (245.0, 248.0, 255.0);
    const WINDOW: f64 = 4.0; // half-width of the bright band, in chars
    const PASSES: usize = 1; // 2026-07-18 user request: sweep exactly once
    const STEP_MS: u64 = 20;

    let lerp = |a: f64, b: f64, t: f64| (a + (b - a) * t).round() as u8;
    let frame_for = |p: f64| -> String {
        let mut tag = String::new();
        for (i, &ch) in chars.iter().enumerate() {
            let dist = (i as f64 - p).abs();
            let mut f = (1.0 - dist / WINDOW).max(0.0);
            f = f * f * (3.0 - 2.0 * f); // smoothstep
            let (r, g, b) = (
                lerp(BASE.0, PEAK.0, f),
                lerp(BASE.1, PEAK.1, f),
                lerp(BASE.2, PEAK.2, f),
            );
            let c = ch.to_string().truecolor(r, g, b);
            let c = if f > 0.5 { c.bold() } else { c };
            tag.push_str(&c.to_string());
        }
        // Rewrite the full row (clear-line wiped the gold art too).
        format!("\x1b[{up}A\r\x1b[2K  {art}        {tag}\r\x1b[{up}B")
    };

    for _ in 0..PASSES {
        let mut p = -WINDOW;
        while p <= n + WINDOW {
            let _ = err.write_all(frame_for(p).as_bytes());
            let _ = err.flush();
            std::thread::sleep(std::time::Duration::from_millis(STEP_MS));
            p += 1.0;
        }
    }

    // Settle back to exactly the static style print_banner first drew.
    let final_tag = BANNER_TAGLINE.cyan().bold();
    let _ = err
        .write_all(format!("\x1b[{up}A\r\x1b[2K  {art}        {final_tag}\r\x1b[{up}B").as_bytes());
    let _ = err.flush();
}

/// Format a unix timestamp as YYYY/MM/DD.
pub(crate) fn format_date(ts: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
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
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    if a == b {
        return 1.0;
    }
    if b.starts_with(a) || a.starts_with(b) {
        return 0.95;
    }

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
        if ba.is_empty() || bb.is_empty() {
            0.0
        } else {
            let i = ba.intersection(&bb).count() as f64;
            let u = ba.union(&bb).count() as f64;
            if u == 0.0 {
                0.0
            } else {
                i / u
            }
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
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── agent register: join token with leading '-' ──────────────────────
    // Regression for 2026-06-22-agent-register-join-token-leading-dash:
    // base64url join tokens (~1/64) start with '-'; the documented space form
    // `--join-token -Mxxx` must parse the value, not error "unrecognized command
    // '-M'". Guards the allow_hyphen_values on the --join-token arg.
    #[test]
    fn agent_register_accepts_leading_dash_join_token() {
        let cli = Cli::try_parse_from([
            "aikey",
            "agent",
            "register",
            "--join-token",
            "-Mq8_sample-TOKEN_value",
            "--control-url",
            "http://127.0.0.1:3000",
        ])
        .expect("a leading-dash join token (space form) must parse, not be read as a flag");
        match cli.command {
            Some(Commands::Agent {
                action: AgentAction::Register { join_token, .. },
            }) => assert_eq!(join_token, "-Mq8_sample-TOKEN_value"),
            _ => panic!("expected `agent register` to parse"),
        }
    }

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
        assert!(validate_secret_name("emoji\u{1f511}").is_err());
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
        assert!(
            score_unrelated < 0.5,
            "Expected < 0.5, got {}",
            score_unrelated
        );
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
        assert_eq!(
            command_name(Some(&Commands::ChangePassword)),
            "change-password"
        );
    }

    #[test]
    fn test_command_name_nested() {
        let cmd = Commands::Account {
            action: AccountAction::Login {
                url: None,
                token: None,
                email: None,
                resend: false,
            },
        };
        assert_eq!(command_name(Some(&cmd)), "account.login");

        let cmd = Commands::Key {
            action: KeyAction::Sync {
                force_reencrypt: false,
            },
        };
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

    // ── service-control fence tests ──────────────────────────────────────
    //
    // These tests are the "重构前后行为一致" safety net for the
    // `aikey service` introduction (M5 Day 5 follow-up Z series). They
    // pin:
    //   (1) the existing `aikey web start` / `aikey proxy start` /
    //       `aikey trust verify` parsings are NOT broken by the new
    //       Service / ServiceAction additions
    //   (2) `aikey service start <name>` parses as expected, with
    //       missing-name and unknown-name handled at dispatch (not at
    //       parse — clap accepts arbitrary strings)
    //
    // What these DON'T cover: actual launchctl / systemctl dispatch
    // (would require shelling out under test, fragile). The dispatch
    // is mostly passthrough so the parse-level pin is the load-bearing
    // half of the contract.

    use clap::Parser;

    /// `aikey web start` MUST keep parsing exactly as before — the
    /// service-control intercept lives in main.rs and depends on the
    /// page-positional Some("start"). If clap derive ever changes
    /// this we want to know.
    #[test]
    fn fence_aikey_web_start_parses_unchanged() {
        let cli = Cli::try_parse_from(["aikey", "web", "start"]).expect("parse");
        match cli.command {
            Some(Commands::Web { page, .. }) => {
                assert_eq!(page.as_deref(), Some("start"));
            }
            other => panic!(
                "expected Web {{ page: Some(\"start\") }}, got {:?}",
                command_name(other.as_ref())
            ),
        }
    }

    /// Same fence for `aikey proxy start`.
    #[test]
    fn fence_aikey_proxy_start_parses_unchanged() {
        let cli = Cli::try_parse_from(["aikey", "proxy", "start"]).expect("parse");
        match cli.command {
            Some(Commands::Proxy { action }) => {
                assert!(matches!(action, ProxyAction::Start { .. }));
            }
            other => panic!(
                "expected Proxy Start, got {:?}",
                command_name(other.as_ref())
            ),
        }
    }

    /// `aikey trust verify <alias>` — the cli.rs add of ServiceAction
    /// shouldn't change TrustAction ordering / parsing.
    #[test]
    fn fence_aikey_trust_verify_parses_unchanged() {
        let cli = Cli::try_parse_from(["aikey", "trust", "verify", "my-alias"]).expect("parse");
        match cli.command {
            Some(Commands::Trust { action }) => match action {
                TrustAction::Verify { alias, .. } => assert_eq!(alias, "my-alias"),
                _ => panic!("expected TrustAction::Verify"),
            },
            _ => panic!("expected Commands::Trust"),
        }
    }

    /// `aikey service start trust-local` — new command path.
    #[test]
    fn aikey_service_start_named() {
        let cli = Cli::try_parse_from(["aikey", "service", "start", "trust-local"]).expect("parse");
        match cli.command {
            Some(Commands::Service { action }) => match action {
                ServiceAction::Start { name } => assert_eq!(name.as_deref(), Some("trust-local")),
                _ => panic!("expected ServiceAction::Start"),
            },
            _ => panic!("expected Commands::Service"),
        }
    }

    /// `aikey service start` (no name) — should parse with name=None
    /// so the dispatcher can print the supported list. Clap doesn't
    /// require the optional positional.
    #[test]
    fn aikey_service_start_no_name() {
        let cli = Cli::try_parse_from(["aikey", "service", "start"]).expect("parse");
        match cli.command {
            Some(Commands::Service {
                action: ServiceAction::Start { name },
            }) => {
                assert!(name.is_none());
            }
            _ => panic!("expected ServiceAction::Start with name=None"),
        }
    }

    /// Stop / restart parse the same way as start.
    #[test]
    fn aikey_service_stop_restart_named() {
        let stop = Cli::try_parse_from(["aikey", "service", "stop", "web"]).expect("parse");
        assert!(matches!(
            stop.command,
            Some(Commands::Service { action: ServiceAction::Stop { ref name } })
                if name.as_deref() == Some("web")
        ));
        let restart = Cli::try_parse_from(["aikey", "service", "restart", "proxy"]).expect("parse");
        assert!(matches!(
            restart.command,
            Some(Commands::Service { action: ServiceAction::Restart { ref name } })
                if name.as_deref() == Some("proxy")
        ));
    }

    /// Unknown service NAMES (e.g. "foo") DO parse — the whitelist
    /// rejection happens at dispatch in commands_service. This test
    /// pins that distinction so a future "reject at parse" tightening
    /// is an intentional decision, not a silent regression.
    #[test]
    fn aikey_service_unknown_name_parses_then_rejected_at_dispatch() {
        let cli = Cli::try_parse_from(["aikey", "service", "start", "some-rogue-name"]);
        assert!(cli.is_ok(), "clap accepts arbitrary name string");
    }

    /// command_name reports `service.*` for telemetry. Pin the format.
    #[test]
    fn fence_command_name_for_service() {
        let cmd = Commands::Service {
            action: ServiceAction::Start {
                name: Some("trust-local".to_string()),
            },
        };
        assert_eq!(command_name(Some(&cmd)), "service.start");

        let cmd = Commands::Service {
            action: ServiceAction::Stop { name: None },
        };
        assert_eq!(command_name(Some(&cmd)), "service.stop");

        let cmd = Commands::Service {
            action: ServiceAction::Restart {
                name: Some("proxy".to_string()),
            },
        };
        assert_eq!(command_name(Some(&cmd)), "service.restart");

        let cmd = Commands::Service {
            action: ServiceAction::Status { name: None },
        };
        assert_eq!(command_name(Some(&cmd)), "service.status");
    }

    /// `aikey service status` (no name) parses with name=None so the
    /// dispatcher renders the aggregate dashboard.
    #[test]
    fn aikey_service_status_no_name() {
        let cli = Cli::try_parse_from(["aikey", "service", "status"]).expect("parse");
        assert!(matches!(
            cli.command,
            Some(Commands::Service {
                action: ServiceAction::Status { name: None }
            })
        ));
    }

    /// `aikey service status <name>` parses the name through for per-service
    /// detail (web / proxy / trust-local).
    #[test]
    fn aikey_service_status_named() {
        for svc in ["web", "proxy", "trust-local"] {
            let cli = Cli::try_parse_from(["aikey", "service", "status", svc]).expect("parse");
            assert!(matches!(
                cli.command,
                Some(Commands::Service { action: ServiceAction::Status { ref name } })
                    if name.as_deref() == Some(svc)
            ));
        }
    }

    /// `aikey web status` parses as the Web command with page="status" —
    /// main.rs intercepts that positional and routes to handle_web_status
    /// (read-only) instead of opening a browser page named "status".
    #[test]
    fn aikey_web_status_parses_as_page_verb() {
        let cli = Cli::try_parse_from(["aikey", "web", "status"]).expect("parse");
        assert!(matches!(
            cli.command,
            Some(Commands::Web { ref page, .. }) if page.as_deref() == Some("status")
        ));
    }
}
