# AiKey CLI (`ak`) v0.0.1-alpha

A secure, local-first secret management tool built with Rust. Store API keys, tokens, and other sensitive data encrypted on your machine.

**Status**: Alpha release - Core functionality complete with comprehensive testing.

## Features (v0.0.1-alpha)

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
- **Magic Add**: Automatically detect and add secrets from clipboard
- **Smart Detection**: Recognizes common API key patterns (OpenAI, GitHub, AWS, etc.)

### Testing & Quality
- **Comprehensive test suite**: 8 integration tests covering all core functionality
- **Security testing**: Authentication failure, injection safety, special characters
- **Persistence testing**: Vault integrity across operations

## Installation

### From source

```bash
cargo install --path .
```

The binary will be installed as `ak` in your cargo bin directory.

## Usage

### Initialize the vault

```bash
ak init
```

You'll be prompted to create a master password. This password is used to derive the encryption key for all your secrets.

### Add a secret

```bash
ak add my-api-key
```

You'll be prompted for your master password and the secret value.

**Magic Add**: If you already have a secret in your clipboard:

```bash
ak add my-api-key --magic
```

This will automatically use the clipboard content as the secret value without prompting.

**Smart Detection**: When adding a secret normally, `ak` will detect common secret patterns in your clipboard (API keys, tokens, JWTs) and offer to use them automatically.

### Retrieve a secret

```bash
ak get my-api-key
```

The secret will be copied to your clipboard for easy pasting.

### Run commands with secrets

```bash
ak run -- npm start
```

All secrets in your vault are injected as environment variables. Examples:

```bash
# Run a Node.js application
ak run -- node server.js

# Run a Python script
ak run -- python app.py

# Run any command with arguments
ak run -- ./deploy.sh --production
```

### List all secrets

```bash
ak list
```

Shows all stored secret aliases (not the values).

### Delete a secret

```bash
ak delete my-api-key
```

Permanently removes the secret from the vault.

## Security

- **Encryption**: AES-256-GCM authenticated encryption
- **Key derivation**: Argon2id with secure parameters (64 MiB memory, 3 iterations, 4 parallelism)
- **Random nonces**: Each encryption uses a unique random nonce
- **Memory safety**: Sensitive data is zeroized after use
- **File permissions**: Vault directory (0700) and database (0600) are restricted to owner only
- **Error handling**: Graceful handling of decryption failures and corrupted vaults
- **Signal propagation**: Child processes in `ak run` properly propagate exit codes and signals

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

The optimized binary will be available at `./target/release/ak`.

### Run tests

```bash
cargo test
```

### Project structure

```
src/
├── main.rs       # CLI interface and command handlers
├── crypto.rs     # Encryption/decryption and key derivation
└── storage.rs    # SQLite database operations
```

## Roadmap

- [ ] Export/import vault functionality
- [ ] Vault backup and restore
- [ ] Secret expiration and rotation reminders
- [ ] Multi-vault support
- [ ] Shell completion scripts
- [ ] Password strength meter during init

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.
