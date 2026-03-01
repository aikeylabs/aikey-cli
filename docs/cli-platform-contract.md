# AiKey CLI Platform Contract

This document defines the **minimal, externally-consumable** contract for automation and integrations.

It is intentionally small. Everything not stated here is **non-contractual**.

## Core Principle

**The only blessed path for secret injection is `aikey run -- <cmd>`.**

The CLI does not provide plaintext secret export, eval-style injection, or any workflow that writes secrets to files or environment variables outside of child process execution.

## Scope

This contract covers:
- `--json` mode behavior
- stdout/stderr channel rules (for automation)
- Exit codes
- Password/secret input constraints in automation

This contract does NOT cover:
- Plaintext secret export (not provided)
- Eval-style shell injection (not provided)
- Writing secrets to files or persistent environment variables (not provided)

## `--json` mode (general)

- `--json` is a **global flag**.
- In `--json` mode, the CLI emits **machine-readable JSON**.
- **Important**: different commands currently write JSON to **different channels**.
  - Some commands emit JSON on **stdout** (e.g. `aikey stats`, `aikey env generate`, `aikey env check`).
  - Some commands emit JSON on **stderr** (via the shared JSON helpers, and especially for `aikey run --json`).

**External contract for consumers**:

- Always capture **both stdout and stderr**.
- Parse JSON from whichever stream contains it.
- Treat the process **exit code** as the primary success/failure signal.

## stdout / stderr rules

- **Text mode (default)**
  - stdout: human-readable output
  - stderr: warnings/errors/diagnostics

- **JSON mode**
  - JSON may appear on stdout or stderr depending on the command.
  - For `aikey run --json`, JSON metadata is emitted to **stderr** to avoid mixing with child process output.

## Password prompts in JSON mode

In `--json` mode, interactive password prompts are intentionally **suppressed** (no prompt text is printed) to avoid polluting machine-readable output.

**Automation contract**:

- Use `--password-stdin` for commands that support it.
- For setting secrets via the Platform API, use commands that read values from stdin (e.g. `aikey secret set --from-stdin`).

## Exit codes

- `0`: success
- `1`: general error / invalid input / command failed before spawning child
- `2`: environment check failed (used by `aikey env check` when required variables are missing)
- For commands that spawn a child process (e.g. `aikey run`, `aikey exec`):
  - the CLI **propagates the child process exit code** when the child exits non-zero.

## Non-goals

- Stable, uniform JSON schema across *all* commands is **not** promised here.
- Stable stdout/stderr placement for JSON across *all* commands is **not** promised here (capture both).

## Security Invariants (Stage 0)

**Secrets are never written to files:**
- Secrets must not be written to project files (including `.env`)
- `.env` files (if generated) contain only non-sensitive context variables
- Secrets are injected only into child process memory via `aikey run -- <cmd>`

**No plaintext export:**
- The Stage 0 CLI does not provide plaintext secret export functionality
- There is no eval-style injection mode
- Integrations must use `aikey run -- <cmd>` for secret access

**Runtime-only injection:**
- Secrets exist only in the child process environment during execution
- Secrets are decrypted on-demand and never persisted to disk in plaintext
- Child process inherits secrets; they are cleared when the process exits

## Integration Guidelines

**For automation and CI/CD:**
1. Use `aikey run -- <cmd>` to execute commands with secrets
2. Use `--json` mode for machine-readable output
3. Use `--password-stdin` for non-interactive password input
4. Capture both stdout and stderr (JSON may appear on either)
5. Check exit codes for success/failure

**What NOT to do:**
- Do not attempt to export secrets to environment variables
- Do not rely on any legacy flags or commands outside this contract
- Do not write secrets to files or logs
