# AiKey CLI (Stage 0)

This folder contains the **AiKey CLI implementation**.

Stage 0 goal: AiKey is a **runtime credential layer** ("management, not a password book"). Projects declare intent in `aikey.config.json` (no secrets). At runtime, credentials are resolved and injected via **one blessed path**: `aikey run -- <cmd>`.

## Authoritative Stage 0 docs (repo root)

The CLI docs in this folder are intentionally minimal. The **authoritative** Stage 0 contracts live in the repo root:

- `Stage0-End-State-Blueprint-en.md` (end-state product shape)
- `AiKey-Stage0-Interaction-Spec-en.md` (CLI/SDK interaction + UX/output contracts)
- `AiKey-Stage0-TechSpec.md` (engineering contract/invariants)
- `Stage0-Decisions-Execution-Semantics.md` (decisions: `.env`, `env inject`, `--dry-run`, config)

If anything here conflicts with the files above, treat the root docs as the source of truth.

## 5-minute main path (Stage 0)

1) **Setup** (one-time on a machine)

```bash
aikey setup
```

2) **Project init** (write a committable declaration, no secrets)

```bash
aikey init
# (or legacy) aikey project init
```

This creates `aikey.config.json`.

3) **Run** (the only blessed execution path)

```bash
aikey run -- <cmd>
```

- Secrets are injected **only into the child process environment**.
- `.env` (if generated) stores **non-sensitive context only**.
- For repeat-run workflows, use `aikey shell` (non-sensitive context only; each command still uses `aikey run`).

## Machine-readable interface (`--json`)

If you build integrations, see `docs/cli-platform-contract.md` for the minimal external contract around `--json`, stdout/stderr, and exit codes.

## Security posture (Stage 0)

- Secrets must never be written to project files (including `.env`).
- Plaintext exposure is an **advanced/dangerous escape hatch** only (behind an explicit flag like `--unsafe-plaintext`) and must be kept out of new-user Quickstart.

## Notes

- This repo currently contains legacy subsystems (e.g. daemon/prototype flows). Stage 0 documentation is intentionally focused on **CLI+SDK** and the single blessed path.
- For actual available commands in your build, run `aikey --help`.
