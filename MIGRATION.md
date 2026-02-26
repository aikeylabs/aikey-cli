# Migration Guide: v0.3 → v0.4.0-alpha.1

This guide covers breaking changes and upgrade steps when moving from AiKey CLI v0.3 to v0.4.0-alpha.1.

## Breaking Changes

### Configuration File

The `aikey.config.json` format is unchanged. No migration required.

### Vault Format

The vault database format (`~/.aikey/vault.db`) is unchanged. Your existing secrets are fully compatible.

### Command Changes

No commands have been removed or renamed. All v0.3 commands continue to work as-is.

## New in v0.4.0-alpha.1

- Complete profile management with vault integration
- Shell completion scripts
- Password strength meter during `aikey init`

## Upgrade Steps

1. Build and install the new binary:

```bash
cargo install --path .
```

2. Verify the version:

```bash
aikey --version
```

3. Your existing vault and project configurations are ready to use — no further steps needed.

## Known Alpha Limitations

As an alpha release, v0.4.0-alpha.1 may contain rough edges. Please report issues at https://github.com/anthropics/claude-code/issues.
