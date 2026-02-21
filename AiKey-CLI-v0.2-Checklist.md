# AiKey CLI v0.2 – Engineering Checklist

## A. Spec & Design

- [x] Review `CLI_SPEC.md` and confirm the v0.2 Platform API section is stable.
- [x] Decide final command names and flags for:
  - [x] `aikey secret set <name> --from-stdin --json`
  - [x] `aikey profile current --json`
  - [x] `aikey --version` / `--json` (version already in Cargo.toml, JSON output not yet implemented)
- [x] Confirm non-goals: no crypto/storage changes, no telemetry/org features.

---

## B. Command Wiring

- [x] Ensure `aikey` is the primary binary name (with `ak` as alias if needed).
- [x] Add or confirm `secret` domain in the CLI parser.
- [x] Wire `secret set` to existing add/update vault logic.
- [x] Add `profile current` subcommand under the `profile` domain.
- [x] Standardize `--version` output format (text and optional JSON).

---

## C. `secret set` Implementation

- [x] Read secret value from **stdin** only (no `--value` flag).
- [x] Implement vault write using existing secure primitives.
- [x] On success, return JSON:
  - [x] `{ "ok": true, "name": "<name>" }`
- [x] On error, map to JSON:
  - [x] Duplicate alias → `code: "ALIAS_EXISTS"`
  - [x] Vault locked / unavailable → `code: "VAULT_LOCKED"`
  - [x] Other errors → `code: "UNKNOWN_ERROR"`
- [x] Ensure no secret plaintext appears in logs or JSON output.

---

## D. `profile current --json` Implementation

- [x] Choose storage for `currentProfile` (e.g. config file) without changing vault schema.
- [x] On active profile:
  - [x] Return `{ "ok": true, "profile": "<name>" }`.
- [x] On no active profile:
  - [x] Return `{ "ok": false, "profile": null, "code": "NO_ACTIVE_PROFILE" }`.

---

## E. Version Reporting

- [x] Implement `aikey --version` to print a single-line semantic version.
- [x] (Optional) Implement `aikey --version --json`:
  - [x] `{ "ok": true, "version": "0.2.0" }`.
- [x] Keep output stable across minor/patch releases.

---

## F. Tests

- [x] Add unit/integration tests for `secret set` happy paths and common failures.
- [x] Add tests for `profile current --json` with and without an active profile.
- [x] Add tests (or golden files) for JSON schemas to guard against accidental changes.
- [x] Add tests for `--version` output format.

---

## G. Integration Smoke Tests (with VS Code)

- [ ] Install the built CLI (`cargo install --path . --force`).
- [ ] In the VS Code extension dev environment:
  - [ ] Run `AiKey: Check CLI Status` / `AiKey: Check Setup` and confirm version is detected as >= v0.2.
  - [ ] Run `AiKey: Register Secret Name` and verify:
    - [ ] Secret is created in the vault.
    - [ ] No secret plaintext appears in logs.
  - [ ] Confirm status bar profile indicator behaves correctly with/without active profile.

When all items above are checked, the AiKey CLI v0.2 Platform API can be considered ready for IDE and tool integrations.