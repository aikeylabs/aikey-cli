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
- JSON payloads go to **stdout**; human diagnostics go to **stderr** (the universal
  convention). One documented exception: **`aikey run --json`** keeps its own
  envelope on **stderr**, because `run` hands stdout to the child process it wraps.
- One command emits **one** envelope. A failing command does not print both its
  own result and a second top-level error object.

> Changed 2026-08-20. Before that, every `--json` payload went to stderr, so
> `aikey <cmd> --json > file` produced an empty file and any consumer that
> discarded stderr silently saw nothing. See
> `workflow/CI/bugfix/2026-08-20-aikey-json-output-on-stderr.md`. Consumers that
> must support older CLIs can detect the contract once with
> `aikey --version --json` and observe which stream carries the payload
> (aikey-tray does exactly this).

**External contract for consumers**:

- Read **stdout** for JSON. Capturing stderr as well is still useful for
  diagnostics, and remains REQUIRED for `aikey run --json`.
- Parse JSON from whichever stream contains it.
- Treat the process **exit code** as the primary success/failure signal.

## stdout / stderr rules

- **Text mode (default)**
  - stdout: human-readable output
  - stderr: warnings/errors/diagnostics

- **JSON mode**
  - JSON appears on **stdout** (since 2026-08-20).
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
