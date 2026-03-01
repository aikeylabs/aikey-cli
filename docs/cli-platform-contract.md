# AiKey CLI Platform Contract (minimal)

This document defines the **minimal, externally-consumable** contract for automation and integrations.

It is intentionally small. Everything not stated here is **non-contractual**.

## Scope

- `--json` mode behavior
- stdout/stderr channel rules (for automation)
- exit codes
- password/secret input constraints in automation

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

## Security invariants (Stage 0 alignment)

- Secrets must not be written to project files (including `.env`).
- Plaintext exposure is an advanced/dangerous escape hatch only; integrations should not rely on it.
