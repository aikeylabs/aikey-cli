# AiKeyLabs-AK User Manual

**Version:** 0.0.1-alpha
**Last Updated:** February 15, 2026

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [Command Reference](#command-reference)
6. [Security Features](#security-features)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Introduction

AiKeyLabs-AK (`ak`) is a secure, local-first secret management CLI tool built with Rust. It provides military-grade encryption for storing API keys, tokens, passwords, and other sensitive credentials on your local machine.

### Key Features

- **Zero-Trust Architecture**: All secrets encrypted with AES-256-GCM
- **Local-First**: No cloud dependencies, complete offline operation
- **Memory Safety**: Automatic memory wiping with `mlock` and `zeroize`
- **Clipboard Auto-Clear**: Secrets automatically cleared after timeout
- **Tamper-Proof Audit Logs**: HMAC-verified operation history
- **Secure Deletion**: Deleted data overwritten with zeros
- **Environment Injection**: Seamlessly inject secrets into command environments

### System Requirements

- **Operating Systems**: macOS, Linux, Windows
- **Rust**: 1.70+ (for building from source)
- **Disk Space**: ~10 MB for binary, minimal for vault storage

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/AiKey-Founder/aikey-labs.git
cd aikeylabs-ak

# Build and install
cargo install --path .
```

The binary will be installed as `ak` in your cargo bin directory (typically `~/.cargo/bin/`).

### Verify Installation

```bash
ak --version
# Output: ak 0.1.0
```

---

## Quick Start

### 1. Initialize Your Vault

```bash
ak init
```

You'll be prompted to create a master password. This password:
- Derives the encryption key using Argon2id (64 MiB memory, 3 iterations)
- Is **never stored** anywhere
- Cannot be recovered if forgotten (your secrets will be permanently inaccessible)

**Example:**
```
$ ak init
Set Master Password: ********
Initializing vault...
Vault initialized successfully!
```

### 2. Add Your First Secret

```bash
ak add github-token
```

You'll be prompted for:
1. Master password (to unlock the vault)
2. Secret value (the actual token/key)

**Example:**
```
$ ak add github-token
Enter Master Password: ********
Enter Secret: ghp_xxxxxxxxxxxxxxxxxxxx
Secret added successfully!
```

### 3. Retrieve a Secret

```bash
ak get github-token
```

The secret will be copied to your clipboard and automatically cleared after 30 seconds.

**Example:**
```
$ ak get github-token
Enter Master Password: ********
Secret copied to clipboard.
Clipboard will be cleared in 30 seconds...
```

### 4. Use Secrets in Commands

```bash
ak exec --env GITHUB_TOKEN=github-token -- git push
```

The secret is injected as an environment variable without ever touching disk.

---

## Core Concepts

### Vault Structure

```
~/.aikey/
└── vault.db          # SQLite database (0600 permissions)
    ├── config        # Stores salt and password hash
    ├── entries       # Encrypted secrets with nonces
    └── audit_log     # Tamper-proof operation logs
```

### Encryption Flow

```
┌─────────────────┐
│ Master Password │
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │Argon2id│ (64 MiB, 3 iter, 4 threads)
    └────┬───┘
         │
         ▼
   ┌──────────┐
   │ 256-bit  │
   │   Key    │
   └─────┬────┘
         │
         ▼
  ┌──────────────┐
  │  AES-256-GCM │ + Random Nonce
  └──────┬───────┘
         │
         ▼
   ┌──────────┐
   │Ciphertext│ → Stored in vault.db
   └──────────┘
```

### Security Layers

1. **Encryption Layer**: AES-256-GCM authenticated encryption
2. **Key Derivation**: Argon2id with secure parameters
3. **Memory Protection**: `mlock` prevents swapping to disk
4. **Secure Deletion**: SQLite `PRAGMA secure_delete = ON`
5. **Audit Trail**: HMAC-SHA256 verified logs

---

## Command Reference

### `ak init`

Initialize a new vault with a master password.

**Usage:**
```bash
ak init
```

**Options:**
- `--password-stdin`: Read password from stdin (for automation)

**Example:**
```bash
# Interactive mode
ak init

# Automation mode
echo "my_master_password" | ak --password-stdin init
```

**Notes:**
- Creates `~/.aikey/vault.db` with 0600 permissions
- Generates random 128-bit salt
- Stores password hash for verification
- Initializes audit log table

---

### `ak add <alias>`

Add a new secret to the vault.

**Usage:**
```bash
ak add <alias>
```

**Arguments:**
- `<alias>`: Unique identifier for the secret (e.g., `github-token`, `aws-key`)

**Options:**
- `--password-stdin`: Read password from stdin

**Example:**
```bash
# Add GitHub token
ak add github-token

# Add with automation
echo -e "master_password\ngh_token_value" | ak add github-token
```

**Notes:**
- If alias already exists, it will be updated (version incremented)
- Secret is encrypted before storage
- Operation is logged in audit trail

---

### `ak get <alias>`

Retrieve a secret and copy to clipboard.

**Usage:**
```bash
ak get <alias> [OPTIONS]
```

**Arguments:**
- `<alias>`: Secret identifier to retrieve

**Options:**
- `-t, --timeout <SECONDS>`: Clipboard auto-clear timeout (default: 30, 0 to disable)
- `--password-stdin`: Read password from stdin

**Examples:**
```bash
# Get with default 30-second timeout
ak get github-token

# Get with 60-second timeout
ak get github-token --timeout 60

# Get without auto-clear
ak get github-token --timeout 0

# Automation mode
echo "master_password" | ak --password-stdin get github-token --timeout 0
```

**Security Notes:**
- Secret is copied to clipboard (not printed to terminal)
- Clipboard automatically cleared after timeout
- Secret never written to disk
- Memory wiped immediately after copy

---

### `ak update <alias>`

Update an existing secret's value.

**Usage:**
```bash
ak update <alias>
```

**Arguments:**
- `<alias>`: Secret identifier to update

**Example:**
```bash
ak update github-token
# Enter Master Password: ********
# Enter New Secret: ghp_new_token_value
# Secret updated successfully!
```

**Notes:**
- Version tag is incremented
- Old value is securely overwritten
- Audit log records the update

---

### `ak delete <alias>`

Permanently delete a secret from the vault.

**Usage:**
```bash
ak delete <alias>
```

**Arguments:**
- `<alias>`: Secret identifier to delete

**Example:**
```bash
ak delete old-api-key
# Enter Master Password: ********
# Secret deleted.
```

**Security Notes:**
- Data is overwritten with zeros (secure delete)
- Cannot be recovered after deletion
- Audit log records the deletion

---

### `ak list`

List all secret aliases (not values) in the vault.

**Usage:**
```bash
ak list
```

**Example:**
```bash
$ ak list
Enter Master Password: ********
Stored secrets:
  aws-access-key
  github-token
  openai-api-key
```

**Notes:**
- Only shows aliases, never values
- Secrets are sorted alphabetically
- Empty vault shows "No secrets stored."

---

### `ak exec`

Execute a command with secrets injected as environment variables.

**Usage:**
```bash
ak exec --env <ENV_VAR>=<alias> [--env ...] -- <command>
```

**Options:**
- `-e, --env <ENV_VAR>=<alias>`: Map environment variable to secret alias (can be used multiple times)
- `--password-stdin`: Read password from stdin

**Examples:**
```bash
# Single secret injection
ak exec --env GITHUB_TOKEN=github-token -- git push

# Multiple secrets
ak exec \
  --env AWS_ACCESS_KEY_ID=aws-key \
  --env AWS_SECRET_ACCESS_KEY=aws-secret \
  -- aws s3 ls

# Complex command
ak exec --env API_KEY=openai-key -- bash -c 'curl -H "Authorization: Bearer $API_KEY" https://api.openai.com/v1/models'
```

**Security Features:**
- **Minimal Window Pattern**: Secrets wiped from parent memory immediately after child spawn
- **No Disk Writes**: Secrets only exist in child process environment
- **Signal Propagation**: SIGINT/SIGTERM properly forwarded
- **Exit Code Preservation**: Child exit status returned to parent

**Process Flow:**
```
1. Decrypt secrets → 2. Spawn child process → 3. Wipe parent memory → 4. Wait for child
```

---

### `ak export`

Export secrets to encrypted `.akb` binary format.

**Usage:**
```bash
ak export <pattern> <output-file>
```

**Arguments:**
- `<pattern>`: Glob pattern to match secrets (e.g., `*`, `api_*`, `aws-*`)
- `<output-file>`: Path to output `.akb` file

**Examples:**
```bash
# Export all secrets
ak export "*" backup.akb

# Export specific pattern
ak export "aws-*" aws-backup.akb

# Export single secret
ak export "github-token" github.akb
```

**File Format (.akb):**
```
[Header: 64 bytes] + [Encrypted Payload] + [HMAC: 32 bytes]

Header:
- Magic: "AKB1" (4 bytes)
- Version: 1 (1 byte)
- KDF Salt: 16 bytes
- KDF Params: m_cost, t_cost, p_cost
- Encryption Nonce: 12 bytes
```

**Security Properties:**
- **Forward Secrecy**: Each export uses fresh random salt
- **Integrity**: HMAC-SHA256 detects tampering
- **Authenticity**: HMAC proves correct password
- **Confidentiality**: AES-256-GCM encryption

---

### `ak import`

Import secrets from encrypted `.akb` file.

**Usage:**
```bash
ak import <input-file>
```

**Arguments:**
- `<input-file>`: Path to `.akb` file

**Example:**
```bash
$ ak import backup.akb
Enter Master Password: ********
Import complete:
  Added: 5
  Updated: 2
  Skipped: 1
```

**Merge Strategy:**
- **Added**: New secrets not in current vault
- **Updated**: Existing secrets with newer version/timestamp
- **Skipped**: Existing secrets with same or newer version

**Security Notes:**
- HMAC verified before decryption (fail-fast on tampering)
- Wrong password detected immediately
- Smart merge prevents data loss

---

## Security Features

### 1. Memory Safety

**mlock Protection:**
```rust
// Secrets are locked in RAM, preventing swap to disk
SecureBuffer::new(key) // Calls mlock() on Unix, VirtualLock() on Windows
```

**Automatic Zeroization:**
```rust
// All sensitive data wrapped in Zeroizing containers
let secret = Zeroizing::new(secret_string);
// Automatically wiped when dropped
```

**Minimal Window Pattern:**
```
Parent Process:
1. Decrypt secrets
2. Spawn child with env vars
3. IMMEDIATELY wipe secrets ← Critical security improvement
4. Wait for child (with clean memory)
```

### 2. Clipboard Auto-Clear

**Default Behavior:**
- Secrets copied to clipboard
- Background thread spawned
- After 30 seconds (configurable), clipboard cleared

**Configuration:**
```bash
# 30 seconds (default)
ak get my-key

# 60 seconds
ak get my-key --timeout 60

# Disable auto-clear
ak get my-key --timeout 0
```

### 3. Secure Deletion

**SQLite Configuration:**
```sql
PRAGMA secure_delete = ON;  -- Overwrite deleted data with zeros
PRAGMA auto_vacuum = FULL;  -- Reclaim space immediately
```

**Impact:**
- Deleted secrets cannot be recovered via forensics
- No data remnants in free pages
- Automatic space reclamation

### 4. Tamper-Proof Audit Logs

**Log Structure:**
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    operation TEXT NOT NULL,      -- 'init', 'add', 'get', 'delete', etc.
    alias TEXT,                    -- Secret identifier (if applicable)
    success INTEGER NOT NULL,      -- 1 = success, 0 = failure
    hmac TEXT NOT NULL             -- HMAC-SHA256 signature
);
```

**HMAC Computation:**
```
HMAC-SHA256(audit_key, timestamp || operation || alias || success)
```

**Verification:**
```bash
# Future feature: Verify audit log integrity
ak audit verify
```

**Security Properties:**
- **Append-Only**: Logs cannot be deleted
- **Tamper-Proof**: Any modification breaks HMAC
- **Key Separation**: Audit key derived independently
- **Forensic Capability**: Complete operation history

### 5. Password Verification

**Mechanism:**
- Password hash stored during `ak init`
- Every operation verifies password before decryption
- Prevents vault corruption from wrong password

**Migration Support:**
- Old vaults without password_hash automatically upgraded
- First successful access creates hash for future verification

---

## Advanced Usage

### Automation & Scripting

**Non-Interactive Mode:**
```bash
# Using environment variables
export AK_TEST_PASSWORD="my_master_password"
export AK_TEST_SECRET="my_secret_value"
ak add my-key

# Using stdin
echo "master_password" | ak --password-stdin list
```

**Batch Operations:**
```bash
#!/bin/bash
# backup-secrets.sh

MASTER_PASSWORD="your_password"
BACKUP_DIR="/secure/backups"
DATE=$(date +%Y%m%d)

echo "$MASTER_PASSWORD" | ak --password-stdin export "*" "$BACKUP_DIR/vault-$DATE.akb"
```

### Custom Vault Location

**Environment Variables:**
```bash
# Use custom vault path
export AK_VAULT_PATH="/custom/path/vault.db"
ak init

# Or specify directory
export AK_VAULT_PATH="/custom/path"
ak init  # Creates /custom/path/vault.db
```

### Integration Examples

**Git with Private Repos:**
```bash
# Store GitHub token
ak add github-token

# Use in git operations
ak exec --env GITHUB_TOKEN=github-token -- \
  git clone https://oauth2:$GITHUB_TOKEN@github.com/user/private-repo.git
```

**AWS CLI:**
```bash
# Store AWS credentials
ak add aws-access-key
ak add aws-secret-key

# Use with AWS CLI
ak exec \
  --env AWS_ACCESS_KEY_ID=aws-access-key \
  --env AWS_SECRET_ACCESS_KEY=aws-secret-key \
  -- aws s3 ls
```

**Docker:**
```bash
# Store Docker Hub token
ak add docker-token

# Login to Docker Hub
ak exec --env DOCKER_TOKEN=docker-token -- \
  bash -c 'echo $DOCKER_TOKEN | docker login -u username --password-stdin'
```

**CI/CD Integration:**
```bash
# .github/workflows/deploy.yml
- name: Deploy with secrets
  run: |
    echo "$MASTER_PASSWORD" | ak --password-stdin exec \
      --env API_KEY=production-key \
      --env DB_PASSWORD=db-pass \
      -- ./deploy.sh
```

---

## Troubleshooting

### Common Issues

#### 1. "Vault not initialized"

**Error:**
```
Error: "Vault not initialized. Run 'ak init' first."
```

**Solution:**
```bash
ak init
```

#### 2. "Invalid master password"

**Error:**
```
Error: "Invalid master password."
```

**Solutions:**
- Verify you're using the correct password
- Check for typos (passwords are case-sensitive)
- If password is truly forgotten, vault cannot be recovered

#### 3. "Salt not found in vault"

**Error:**
```
Error: "Salt not found in vault. Vault may be corrupted."
```

**Solutions:**
- Vault database may be corrupted
- Try restoring from backup (`.akb` file)
- If no backup exists, vault is unrecoverable

#### 4. Clipboard not clearing

**Issue:** Secret remains in clipboard after timeout

**Solutions:**
- Check if background process is running: `ps aux | grep ak`
- Verify timeout setting: `ak get my-key --timeout 30`
- Some clipboard managers may interfere (disable clipboard history)

#### 5. Permission denied errors

**Error:**
```
Error: "Failed to create vault directory: Permission denied"
```

**Solutions:**
```bash
# Check home directory permissions
ls -la ~

# Ensure ~/.aikey is writable
chmod 700 ~/.aikey

# Check vault.db permissions
chmod 600 ~/.aikey/vault.db
```

### Debug Mode

**Enable verbose output:**
```bash
# Set Rust log level
export RUST_LOG=debug
ak list
```

### Recovery Procedures

**Backup Strategy:**
```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
BACKUP_DIR="$HOME/vault-backups"

mkdir -p "$BACKUP_DIR"
echo "$MASTER_PASSWORD" | ak --password-stdin export "*" "$BACKUP_DIR/vault-$DATE.akb"

# Keep only last 30 days
find "$BACKUP_DIR" -name "vault-*.akb" -mtime +30 -delete
```

**Restore from Backup:**
```bash
# 1. Initialize new vault
ak init

# 2. Import from backup
ak import vault-20260215.akb
```

---

## Best Practices

### Password Management

**Strong Master Password:**
- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, symbols
- Use a passphrase: "correct-horse-battery-staple-2026"
- Never reuse passwords from other services

**Password Storage:**
- Store master password in a password manager (e.g., 1Password, Bitwarden)
- Write it down and store in a physical safe
- Never store in plain text files

### Secret Organization

**Naming Conventions:**
```bash
# Good: Descriptive, hierarchical
ak add github-personal-token
ak add github-work-token
ak add aws-prod-access-key
ak add aws-dev-access-key

# Bad: Ambiguous
ak add token1
ak add key
ak add secret
```

**Categorization:**
```bash
# Use prefixes for grouping
ak add prod-db-password
ak add prod-api-key
ak add dev-db-password
ak add dev-api-key

# Export by category
ak export "prod-*" prod-backup.akb
ak export "dev-*" dev-backup.akb
```

### Backup Strategy

**3-2-1 Rule:**
- **3** copies of data (original + 2 backups)
- **2** different storage media (local + external drive)
- **1** off-site backup (cloud storage, encrypted)

**Backup Schedule:**
```bash
# Weekly full backup
0 0 * * 0 /home/user/scripts/backup-vault.sh

# Daily incremental (if supported in future)
0 2 * * * /home/user/scripts/backup-vault-incremental.sh
```

### Security Hygiene

**Regular Rotation:**
```bash
# Rotate secrets every 90 days
# 1. Generate new secret at provider
# 2. Update in vault
ak update github-token

# 3. Verify new secret works
ak exec --env GITHUB_TOKEN=github-token -- git ls-remote

# 4. Revoke old secret at provider
```

**Audit Review:**
```bash
# Regularly review audit logs (future feature)
ak audit list --since "7 days ago"

# Check for suspicious activity
ak audit verify
```

**Access Control:**
```bash
# Ensure vault permissions are correct
chmod 700 ~/.aikey
chmod 600 ~/.aikey/vault.db

# Verify no other users can access
ls -la ~/.aikey
# Should show: drwx------ (700)
```

### Performance Optimization

**Argon2id Parameters:**
- Default: 64 MiB memory, 3 iterations
- Adjust for slower/faster machines (future feature)
- Balance security vs. performance

**Vault Maintenance:**
```bash
# Vacuum database periodically (future feature)
ak vacuum

# Check vault integrity
ak verify
```

---

## Appendix

### File Permissions

| Path | Permissions | Description |
|------|-------------|-------------|
| `~/.aikey/` | 0700 (drwx------) | Vault directory |
| `~/.aikey/vault.db` | 0600 (-rw-------) | Database file |
| `*.akb` | 0600 (-rw-------) | Export files |

### Cryptographic Specifications

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | Argon2id | 64 MiB memory, 3 iterations, 4 threads |
| Encryption | AES-256-GCM | 256-bit key, 96-bit nonce |
| Integrity | HMAC-SHA256 | 256-bit key |
| Random | OsRng | Cryptographically secure |

### Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `AK_VAULT_PATH` | Custom vault location | `/custom/path/vault.db` |
| `AK_TEST_PASSWORD` | Testing: Master password | `test_password_123` |
| `AK_TEST_SECRET` | Testing: Secret value | `test_secret_value` |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid password |
| 3 | Vault not found |
| 4 | Secret not found |

---

## Support & Contributing

### Getting Help

- **Documentation**: https://github.com/AiKey-Founder/aikey-labs
- **Issues**: https://github.com/AiKey-Founder/aikey-labs/issues
- **Discussions**: https://github.com/AiKey-Founder/aikey-labs/discussions

### Reporting Bugs

Include:
1. `ak --version` output
2. Operating system and version
3. Steps to reproduce
4. Expected vs. actual behavior
5. Relevant error messages

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## License

Apache License 2.0

Copyright © 2026 AiKey Labs

---

**Document Version:** 1.0.0
**Last Updated:** February 15, 2026
**Maintained By:** AiKey Labs Team
