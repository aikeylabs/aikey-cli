# AiKey CLI v0.3

A secure, local-first secret management tool built with Rust. Store API keys, tokens, and other sensitive data encrypted on your machine.

**Status**: Beta release - Core functionality complete with comprehensive testing and developer workflow support.

**Primary command**: `aikey` (short alias: `ak`)

## Features (v0.3)

### Developer Workflow (New in v0.3)
- **Project configuration**: Initialize and manage project-specific environment variables
- **Environment generation**: Automatically generate `.env` files from your vault
- **Environment injection**: Inject secrets into your shell environment
- **Template support**: Pre-configured templates for Node.js, Python, and other stacks
- **Smart merging**: Preserve comments and unknown variables when updating `.env` files

### Secure Storage
- **Local-first**: All secrets stored encrypted in `~/.aikey/vault.db`
- **Strong encryption**: AES-256-GCM with Argon2id key derivation
- **Zero dependencies on cloud services**: Complete offline operation
- **Secure by default**: 0700/0600 file permissions, memory zeroization
- **Password verification**: Prevents vault corruption from wrong passwords

### Environment Injection
- **Seamless integration**: Run any command with secrets as environment variables
- **Signal propagation**: Proper handling of exit codes and signals (SIGINT, SIGTERM)
- **Clean output**: Secrets injected transparently without noise

### User Experience
- **Simple CLI**: Easy to use commands for daily workflows
- **JSON output mode**: Machine-readable output with `--json` flag for automation
- **Magic Add**: Automatically detect and add secrets from clipboard
- **Smart Detection**: Recognizes common API key patterns (OpenAI, GitHub, AWS, etc.)

### Advanced Features (Preview)
- **Profile management**: Organize secrets by profile (e.g., dev, staging, prod)
- **Environment templates**: Define reusable environment configurations
- **Project contexts**: Manage secrets per project with automatic context switching

### Testing & Quality
- **Comprehensive test suite**: 90+ tests covering all core functionality
- **Unit tests**: Config parsing, environment resolution, and rendering logic
- **Integration tests**: Full command workflows including v0.3 developer features
- **Security testing**: Authentication failure, injection safety, special characters
- **Persistence testing**: Vault integrity across operations

## Installation

### From source

```bash
cargo install --path .
```

The binary will be installed as `aikey` (with `ak` as a short alias) in your cargo bin directory.

## Usage

### Initialize the vault

```bash
aikey init
```

You'll be prompted to create a master password. This password is used to derive the encryption key for all your secrets.

### Add a secret

```bash
aikey add my-api-key
```

You'll be prompted for your master password and the secret value.

**Magic Add**: If you already have a secret in your clipboard:

```bash
aikey add my-api-key --magic
```

This will automatically use the clipboard content as the secret value without prompting.

**Smart Detection**: When adding a secret normally, `aikey` will detect common secret patterns in your clipboard (API keys, tokens, JWTs) and offer to use them automatically.

### Retrieve a secret

```bash
aikey get my-api-key
```

The secret will be copied to your clipboard for easy pasting.

### Run commands with secrets

```bash
aikey run -- npm start
```

All secrets in your vault are injected as environment variables. Examples:

```bash
# Run a Node.js application
aikey run -- node server.js

# Run a Python script
aikey run -- python app.py

# Run any command with arguments
aikey run -- ./deploy.sh --production
```

### List all secrets

```bash
aikey list
```

Shows all stored secret aliases (not the values).

### Update a secret

```bash
aikey update my-api-key
```

Updates an existing secret with a new value.

### Delete a secret

```bash
aikey delete my-api-key
```

Permanently removes the secret from the vault.

### JSON Output Mode

All commands support `--json` flag for machine-readable output:

```bash
# List secrets in JSON format
aikey list --json

# Get secret value in JSON
aikey get my-api-key --json

# Add secret with JSON output
aikey add new-key --json

# Run command with JSON metadata
aikey run --json -- echo "test"
```

JSON output is written to stderr to avoid mixing with command output, making it safe for automation and scripting.

## Developer Workflow (v0.3)

The v0.3 release introduces a complete developer workflow for managing environment variables across projects and profiles.

### Initialize a project

```bash
aikey project init
```

This interactive command will:
1. Prompt for project name (defaults to folder name)
2. Ask for language/stack (Node.js, Python, or Other)
3. Set the `.env` file target
4. Suggest common environment variables based on your stack
5. Create an `aikey.config.json` file in your project

Example `aikey.config.json`:
```json
{
  "version": "1",
  "project": {
    "name": "my-app"
  },
  "env": {
    "target": ".env"
  },
  "requiredVars": [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DATABASE_URL"
  ]
}
```

### Check project status

```bash
aikey project status
```

Shows:
- Project configuration path
- Current profile
- Required variables and their satisfaction status
- Helpful hints for next steps

### Generate .env file

```bash
aikey env generate
```

Generates or updates your `.env` file with values from your current profile:
- Preserves comments and unknown variables
- Updates only the variables listed in `requiredVars`
- Writes empty placeholders for missing values

Options:
```bash
# Preview changes without writing
aikey env generate --dry-run

# Use a different .env file
aikey env generate --env-file .env.local
```

### Inject variables into shell

```bash
eval "$(AIKEY_INJECT_MODE=eval aikey env inject)"
```

Injects your project's required variables into the current shell environment. This is useful for:
- Running commands that need environment variables
- Testing without creating `.env` files
- Temporary environment setup

Alternatively, use the existing `aikey run` command:
```bash
aikey run -- npm start
```

### Preview Features

The following commands are available but still in development:

```bash
# Profile management (Preview)
aikey profile create dev
aikey profile list
aikey profile switch dev

# Environment templates (Preview)
aikey env create staging
aikey env set staging DATABASE_URL=db_secret_alias

# Project contexts (Preview)
aikey project init
aikey project link my-project
```

Note: Preview features may have incomplete functionality or breaking changes in future releases.

## Security

- **Encryption**: AES-256-GCM authenticated encryption
- **Key derivation**: Argon2id with secure parameters (64 MiB memory, 3 iterations, 4 parallelism)
- **Random nonces**: Each encryption uses a unique random nonce
- **Memory safety**: Sensitive data is zeroized after use
- **File permissions**: Vault directory (0700) and database (0600) are restricted to owner only
- **Error handling**: Graceful handling of decryption failures and corrupted vaults
- **Signal propagation**: Child processes in `aikey run` properly propagate exit codes and signals

## Architecture

```
~/.aikey/
└── vault.db          # SQLite database (0600 permissions)
    ├── config        # Stores the random salt
    └── entries       # Encrypted secrets with nonces
```

Each secret is encrypted with:
1. Master password + salt → Argon2id → 256-bit key
2. Secret + key + random nonce → AES-256-GCM → ciphertext
3. Store: (alias, nonce, ciphertext)

## Development

### Build

```bash
cargo build --release
```

The optimized binary will be available at `./target/release/aikey`.

### Run tests

```bash
cargo test
```

### Project structure

```
src/
├── main.rs              # CLI interface and command handlers
├── crypto.rs            # Encryption/decryption and key derivation
├── storage.rs           # SQLite database operations
├── config.rs            # Project configuration management
├── env_resolver.rs      # Environment variable resolution
├── env_renderer.rs      # .env file rendering and merging
├── commands_project.rs  # Project command handlers
└── commands_env.rs      # Environment command handlers
```

## Roadmap

### Completed in v0.3
- [x] Developer workflow commands (`project init`, `project status`)
- [x] Environment generation (`env generate` with merge support)
- [x] Environment injection (`env inject` with shell eval support)
- [x] Project configuration management
- [x] Template support for Node.js, Python, and other stacks
- [x] Comprehensive unit and integration tests

### Planned for v0.4
- [ ] Complete profile management implementation
- [ ] Shell completion scripts
- [ ] Password strength meter during init

### Future Enhancements
- [ ] Export/import vault functionality
- [ ] Vault backup and restore
- [ ] Secret expiration and rotation reminders
- [ ] Multi-vault support
- [ ] `aikey quickstart` command for first-time users

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.
