# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AiKey CLI, please report it responsibly:

**Email:** aikeyfounder@gmail.com

**Please do NOT:**
- Create a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed

**What to include in your report:**
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

We take security seriously and will respond to vulnerability reports as quickly as possible.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Security Best Practices

When using AiKey CLI:

1. **Never commit secrets** - AiKey is designed to keep secrets out of your repository
2. **Protect your master password** - Your vault encryption depends on it
3. **Use strong passwords** - The vault uses Argon2id for key derivation
4. **Keep your system secure** - AiKey stores encrypted secrets locally
5. **Review config files** - Ensure `aikey.config.json` contains no sensitive data before committing

## Security Features

- **Local-first encryption** - All secrets encrypted with Argon2id + AES-256-GCM
- **No network transmission** - Secrets never leave your machine
- **Memory safety** - Built in Rust with secure memory handling
- **Minimal attack surface** - Direct password-based vault access (no daemon)
- **Runtime-only injection** - Secrets only exist in child process memory

## Audit History

- **2026-03**: Stage 0 security audit - removed daemon infrastructure, implemented direct vault access
