# AiKey CLI (Stage 0)

**AiKey** is a secure, local-first secret management CLI for developers. It provides runtime credential injection without storing secrets in project files.

## Stage 0 Contract

AiKey is a **runtime credential layer** ("management, not a password book"). Projects declare intent in `aikey.config.json` (no secrets). At runtime, credentials are resolved and injected via **one blessed path**: `aikey run -- <cmd>`.

**What Stage 0 includes:**
- Config-driven secret injection (`aikey.config.json`)
- Runtime-only credential access (`aikey run -- <cmd>`)
- Local encrypted vault (Argon2id + AES-256-GCM)
- Non-sensitive context variables in `.env` files

**What Stage 0 does NOT include:**
- Plaintext secret export workflows
- Eval-style shell injection
- Writing secrets to files or environment variables outside child processes

> **Important:** The Stage 0 contract does not include plaintext secret export or inject workflows. If the current binary still exposes legacy flags or subcommands, they are out of contract and will be removed in a future release. Integrations must not rely on them.

## Quick Start (5 minutes)

### 1. Initialize Vault (one-time per machine)

The vault is created automatically when you run any `aikey` command for the first time (e.g. `aikey quickstart` or `aikey add`). You'll be prompted to set a master password.

### 2. Create Project Config (no secrets)

```bash
cd your-project
aikey project init
```

This creates `aikey.config.json` - a committable declaration file that specifies which secrets your project needs, but contains no actual secret values.

> **Note:** Run `aikey --help` to see your build's available commands. The project config file is always `aikey.config.json`.

### 3. Add API Keys to Vault

Two paths, pick whichever matches your situation:

**Single key — CLI prompt:**
```bash
aikey add anthropic:default
```

**Many keys from unstructured notes — Web UI:**
```bash
aikey import ~/my-keys.txt   # or just: aikey import
```
This opens `http://127.0.0.1:<port>/user/import` in your browser. Paste any
mixed-format text (credentials copied from 1Password, team onboarding emails,
`.env` fragments, Keychain exports — anything); the parser extracts API keys,
email/password pairs, and OAuth handoffs into a review list. You check which
drafts to import and click **Import N records**. See the "Bulk Import" section
below for details and the full supported provider list.

Either way: API Keys are stored encrypted in your local vault, never in
project files.

### 4. Run Commands (the blessed path)

```bash
aikey run -- <your-command>
```

This is the **only blessed execution path**. Secrets are injected into the child process environment at runtime and exist only in that process's memory.

**Examples:**
```bash
aikey run -- npm start
aikey run -- python app.py
aikey run -- ./my-script.sh
```

### What About .env Files?

If your project generates a `.env` file, it contains **non-sensitive context only** (project name, environment name, etc.) plus placeholders. Actual secret values are never written to `.env` files.

For workflows that need repeated commands, you can use `aikey shell` to set up non-sensitive context, but each command execution still goes through `aikey run`.

## For Integrations and Automation

If you're building integrations or automation, see `docs/cli-platform-contract.md` for the minimal external contract around:
- `--json` mode behavior
- stdout/stderr handling
- Exit codes
- Password input in automation

**Key principle:** Integrations must use `aikey run -- <cmd>` for secret injection. The CLI does not provide plaintext secret export functionality.

## Security Posture

**Core principles:**
1. **Secrets never in files** - No secrets in `aikey.config.json`, `.env`, or any project files
2. **Runtime-only injection** - Secrets exist only in child process memory during execution
3. **Local-first encryption** - All secrets encrypted with Argon2id + AES-256-GCM
4. **No network transmission** - Secrets never leave your machine
5. **Single blessed path** - Only `aikey run -- <cmd>` injects secrets

**What this means:**
- Your `aikey.config.json` is safe to commit (it declares intent, not values)
- Generated `.env` files contain only non-sensitive context
- Secrets are decrypted on-demand and injected directly into child process environment
- No plaintext secret export or eval-style injection workflows

For security vulnerability reporting, see `SECURITY.md`.

## Provider OAuth Accounts (`aikey auth`)

Use subscription plans (Claude Pro/Max, ChatGPT Plus, Kimi Code) instead of API Keys.
OAuth tokens are managed by [aikey-auth-broker](../aikey-auth-broker/README.md) via the proxy.

```bash
# Login to a provider (opens browser for OAuth authorization)
aikey auth login claude    # Claude Pro/Max — paste code from callback page
aikey auth login codex     # ChatGPT Plus/Pro — auto callback
aikey auth login kimi      # Kimi Code — enter device code in browser

# List OAuth accounts
aikey auth list

# Set an OAuth account as active (replaces API Key for that provider)
aikey auth use <account_id>

# Check account health
aikey auth status <account_id>

# Logout
aikey auth logout <account_id>
```

Supported providers:

| Provider | Flow | Token Lifetime | Subscription |
|----------|------|---------------|-------------|
| Claude (Anthropic) | Setup Token (manual paste) | 1 year | Pro/Max required |
| Codex (ChatGPT) | Auth Code (auto callback) | 10 days | Plus/Pro (free works too) |
| Kimi (Moonshot) | Device Code (polling) | 15 minutes | Coding Plan |

OAuth and API Key are mutually exclusive per provider — `aikey auth use` replaces `aikey use` for the same provider, and vice versa.

## Web UI (`aikey web`)

Opens the local-only User Console in your default browser. The console is
served by `aikey-local-server` (started by the installer) and aggregates the
vault, OAuth accounts, virtual keys, usage ledger, and bulk-import pages —
all over `localhost`, no cloud calls.

```bash
aikey web                  # open the default landing page
aikey web vault            # → Personal Vault page
aikey web import           # → Bulk Import page
aikey web --port 18090     # force a specific local port
aikey web --json           # print the URL as JSON, don't launch the browser
```

Prerequisites are the same as Bulk Import below (`aikey-local-server` must
be running).

## Bulk Import

Opens a local-only Web UI (`/user/import`) for bringing credentials in from
unstructured text. The parser is three layers (rule v2 → CRF + shape filter →
Provider Fingerprint) and runs **entirely offline** — no telemetry, no
network calls for parsing.

### Prerequisites
- `local-install.sh` (or `trial-install.sh`) has run. The installer writes the
  console port to `~/.aikey/config/local-server.port` and starts the server.
- `aikey status` shows a `local-server: running on port <p>` line.

If the server is not running:
- **macOS:** `launchctl start com.aikey.local-server`
- **Linux:** `systemctl --user start aikey-local-server`
- **Anywhere:** `~/.aikey/bin/aikey-local-server --config ~/.aikey/config/control-trial.yaml &`

### Usage
```bash
aikey import                         # open empty paste page
aikey import ~/notes.txt             # open page primed to re-parse that file
aikey import --json                  # print the URL as JSON, no browser
```

### Recognized formats
- API keys with known prefixes: `sk-ant-api03-`, `sk-proj-`, `AIza`, `gsk_`,
  `ghp_`, `AKIA`, `SG.`, `eyJ…`, plus 15 more providers (openrouter, stripe,
  slack, huggingface, perplexity, xai, …)
- Email + password pairs (English or Chinese field labels: `email:` `邮箱:`
  `password:` `密码:`)
- OAuth handoff rows (Claude / Codex / Kimi) — the UI emits the exact
  `aikey auth login <provider>` command for you to copy-paste to a terminal
- Third-party gateway `base_url` (e.g. OpenAI-compatible endpoints)

### Privacy
The page runs `OFFLINE · NOTHING LEAVES` across the top strip. The textarea
content stays in the browser and in the local server process; it is never
sent to any cloud. The vault stays locked until you explicitly unlock via the
inline banner.

## Additional Notes

- Historical daemon/prototype subsystems have been removed; Stage 0 focuses on the single blessed path (`aikey run -- <cmd>`)
- For the complete list of available commands in your build, run `aikey --help`
- This is an open-source project under Apache-2.0 license - contributions welcome! See `CONTRIBUTING.md`

## License

Apache-2.0 - See `LICENSE` file for details.
