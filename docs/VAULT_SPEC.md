# AiKey Vault Format Specification

**Internal document** — describes the on-disk format of `vault.db` and the `_internal` IPC protocol used by `aikey-local-server` (Go) to talk to the CLI.

**Audience**: CLI maintainers, security reviewers, future language bindings (if we add a Go or Python reader). Not user-facing.

**Status**: Stage 2 Phase G (2026-04-22). Subject to versioning via `migrations.rs`.

**Not a cross-language contract** — the Go proxy's `internal/vault/` reads a subset of this format (delivery key mechanism); it's kept in sync by code review, not by this spec.

---

## 1. File layout

| Path | Purpose |
|---|---|
| `~/.aikey/data/vault.db` | SQLite database, mode 0600 |
| `~/.aikey/data/vault.db-wal` | SQLite WAL journal |
| `~/.aikey/data/vault.db-shm` | SQLite shared-memory index |
| `~/.aikey/` | Directory mode 0700 |

**Override**: env vars `AK_VAULT_PATH` or `AK_STORAGE_PATH` (if path ends in `.db`, that's the full DB path; else appended with `vault.db`).

---

## 2. Cryptography

### 2.1 Argon2id key derivation

```
master_key = Argon2id(password, salt, m=65536 KiB, t=3, p=4, keyLen=32)
```

| Parameter | Value | Rust const | Notes |
|---|---|---|---|
| Algorithm | Argon2id | `argon2::Algorithm::Argon2id` | |
| Version | 0x13 | `Version::V0x13` | |
| Memory cost (m) | 65536 (64 MiB) | `ARGON2_M_COST` | |
| Time cost (t) | 3 iterations | `ARGON2_T_COST` | |
| Parallelism (p) | 4 | `ARGON2_P_COST` | |
| Key length | 32 bytes | `KEY_SIZE` | |
| Salt size | 32 bytes | `SALT_SIZE` | Random per-vault |

**Salt storage**: `config.master_salt` (blob). Legacy vaults may use `config.salt` — code reads both (fallback).

**Optional parameter override**: columns `config.kdf_m_cost` / `kdf_t_cost` / `kdf_p_cost` (little-endian u32 blobs) allow per-vault KDF parameter override. Also honored by `aikey-proxy/internal/vault/crypto.go` `DeriveKeyWithParams`.

### 2.2 AES-256-GCM encryption

```
nonce        = 12 random bytes (CSPRNG via OsRng)
ciphertext   = AES-256-GCM.encrypt(master_key, nonce, plaintext)
# ciphertext includes 16-byte authentication tag appended
```

Stored as separate `nonce` (12 bytes) and `ciphertext` (N+16 bytes) blobs in `entries`.

### 2.3 Password verification

Stored as `config.password_hash` = the raw 32-byte Argon2id output (equals the vault master key). Verifying a candidate password:

```
candidate_key = Argon2id(candidate_password, salt, ...)
if candidate_key == config.password_hash: UNLOCKED
```

**Fallback** (legacy vaults missing `password_hash`): attempt AES-GCM decryption of one arbitrary `entries` row; if successful, accept and write the `password_hash` on the first successful unlock.

### 2.4 Audit HMAC chain

Existing `aikey add`/etc. paths: `audit_key = Argon2id(password, "AK_AUDIT_SALT_V1", ...)`.

**`_internal` IPC path** (Stage 2 Phase F): audit key derived from vault_key:

```
audit_key = HMAC-SHA256(vault_key, "AK_AUDIT_V2:audit-v1")
```

Each audit_log row signed by:

```
hmac = HMAC-SHA256(audit_key, timestamp_le || operation || alias? || success?)
```

**Design decision**: audit chain is now bound to vault_key rather than password. Since change_password rotates vault_key, old audit rows become unverifiable after password change — same limitation as the password-salt scheme. See `src/audit.rs::derive_audit_key_from_vault_key` doc for full Why.

---

## 3. SQLite schema

### 3.1 `config` — KV table for vault-wide settings

| Key | Type | Meaning |
|---|---|---|
| `master_salt` | blob (32 B) | Argon2id salt. Fallback key `salt` for legacy vaults. |
| `password_hash` | blob (32 B) | Argon2id output; also the vault master key. |
| `kdf_m_cost` / `kdf_t_cost` / `kdf_p_cost` | blob (LE u32) | Optional KDF parameter override. |

### 3.2 `entries` — credential store

```sql
CREATE TABLE entries (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    alias                  TEXT NOT NULL UNIQUE,
    nonce                  BLOB NOT NULL,     -- 12 bytes
    ciphertext             BLOB NOT NULL,     -- plaintext + 16-byte GCM tag
    version_tag            INTEGER NOT NULL DEFAULT 1,
    metadata               TEXT,              -- arbitrary JSON blob
    created_at             INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    provider_code          TEXT,              -- single provider (legacy)
    base_url               TEXT,              -- custom upstream URL
    supported_providers    TEXT,              -- JSON array of provider codes (v1.0.2+)
    route_token            TEXT               -- aikey_vk_* for third-party clients (v1.0.4+)
);
CREATE UNIQUE INDEX idx_entries_route_token ON entries(route_token) WHERE route_token IS NOT NULL;
```

### 3.3 `audit_log` — tamper-evident event log

```sql
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,    -- unix epoch seconds
    operation   TEXT NOT NULL,       -- "init" | "add" | "get" | "update" | "delete" | "list" | "export" | "import" | "exec"
    alias       TEXT,
    success     INTEGER NOT NULL,    -- 0 | 1
    hmac        TEXT NOT NULL        -- hex-encoded HMAC-SHA256
);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
```

### 3.4 `import_jobs` / `import_items` (v1.0.5-alpha, Stage 2 Phase F)

```sql
CREATE TABLE import_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          TEXT NOT NULL UNIQUE,   -- UUID, Go local-server-generated
    source_type     TEXT,                    -- "paste" | "file" | "manual"
    source_hash     TEXT,                    -- sha256: (from _internal parse response)
    created_at      INTEGER NOT NULL,
    completed_at    INTEGER,                 -- NULL while in_progress
    total_items     INTEGER NOT NULL DEFAULT 0,
    inserted_count  INTEGER NOT NULL DEFAULT 0,
    replaced_count  INTEGER NOT NULL DEFAULT 0,
    skipped_count   INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'in_progress'  -- "in_progress" | "completed" | "aborted"
);
CREATE INDEX idx_import_jobs_created_at ON import_jobs(created_at DESC);

CREATE TABLE import_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          TEXT NOT NULL,           -- FK → import_jobs.job_id (not enforced at DB level)
    alias           TEXT NOT NULL,
    action          TEXT NOT NULL,           -- "inserted" | "replaced" | "skipped"
    provider_code   TEXT,
    created_at      INTEGER NOT NULL
);
CREATE INDEX idx_import_items_job_id ON import_items(job_id);
```

### 3.5 Other tables (not part of v1.0 batch-import scope)

See `src/storage.rs` + `src/migrations.rs` for: `platform_account`, `user_profiles`, `user_profile_provider_bindings`, `provider_accounts`, `provider_account_tokens`, `managed_virtual_keys_cache`.

---

## 4. Schema migrations

Registered in `src/migrations.rs::VERSIONS` array. Each version has `upgrade()` + `rollback()`.

| Version | Date | Change |
|---|---|---|
| v1.0.1-alpha | baseline | `entries`, `config`, `audit_log`, `platform_account` — created by `storage.rs::initialize_vault` |
| v1.0.2-alpha | 2026-03 | `user_profiles`, `user_profile_provider_bindings`, `platform_account.refresh_token/token_expires_at` |
| v1.0.3-alpha | 2026-04 | `provider_accounts`, `provider_account_tokens` |
| v1.0.4-alpha | 2026-04 | `entries.route_token`, `provider_accounts.route_token` |
| **v1.0.5-alpha** | **2026-04-22** | **`import_jobs`, `import_items`** (Stage 2 Phase F) |

**Auto-upgrade** runs on every `aikey` command startup via `executor::verify_password_internal` → `migrations::upgrade_all()`. Idempotent (CREATE TABLE IF NOT EXISTS, pragma_table_info guards on ALTER).

**Manual**: `aikey db upgrade` / `aikey db rollback --to <version>` (hidden from `--help`).

---

## 5. `_internal` IPC protocol

### 5.1 Invocation

`aikey-local-server` (Go) spawns:

```
aikey _internal <subcommand> --stdin-json
```

Subcommands: `vault-op` / `query` / `update-alias` / `parse`. All hidden from `aikey --help`.

### 5.2 Envelope contract

**stdin (JSON)**:

```json
{
  "vault_key_hex": "<64 hex chars = 32-byte vault_key from Argon2id>",
  "action": "<action name, see §5.3>",
  "request_id": "<optional UUID, echoed back>",
  "payload": { "action-specific": "..." }
}
```

**stdout (JSON, one line + newline)** — always exit code 0 (except on panic):

```json
// success:
{"request_id":"...","status":"ok","data":{"...":"..."}}
// error:
{"request_id":"...","status":"error","error_code":"I_*","error_message":"human readable"}
```

### 5.3 Action catalog

#### `vault-op`

| Action | Purpose | Payload | Side effect |
|---|---|---|---|
| `verify` | Check vault_key unlocks vault | `{}` | audit: none |
| `add` | Insert/replace credential | `{alias, secret_plaintext, provider?, on_conflict?}` | audit: Add, entries: insert |
| `batch_import` | Batch insert | `{items[], on_conflict?, job_id?, source_type?, source_hash?}` | audit: Import per item; import_jobs + import_items written if job_id present |
| `update_secret` | Re-encrypt existing alias | `{alias, new_secret_plaintext}` | audit: Update |
| `delete` | Remove credential | `{alias}` | audit: Delete |

#### `query`

| Action | Payload | Requires valid key? |
|---|---|---|
| `list` | `{}` | ✅ |
| `list_with_metadata` | `{}` | ✅ |
| `get` | `{alias, include_secret?}` | ✅ |
| `check_alias_exists` | `{alias}` | ❌ (existence-only, no decryption) |
| `list_import_jobs` | `{limit?, status?}` | ✅ |
| `get_import_job_items` | `{job_id}` | ✅ |

#### `update-alias`

All actions require valid vault_key verification.

| Action | Payload | Effect |
|---|---|---|
| `rename_alias` | `{old_alias, new_alias}` | UPDATE entries SET alias |
| `set_provider` | `{alias, provider?}` | UPDATE entries SET provider_code (null = clear) |
| `set_base_url` | `{alias, base_url?}` | UPDATE entries SET base_url |
| `set_supported_providers` | `{alias, providers: []}` | UPDATE entries SET supported_providers (JSON) |
| `set_metadata` | `{alias, metadata: JSON}` | UPDATE entries SET metadata (null = clear) |

#### `parse`

**Stage 2 skeleton** — regex-only Layer 1-lite. Stage 3 fills in three-layer pipeline (rule v2 + CRF + Fingerprint).

| Action | Payload | Requires valid key? |
|---|---|---|
| `parse` | `{text, source_type?, batch_provider_hint?, max_candidates?}` | ❌ (protocol format check only; parse is pure function of text) |

Response schema (forward-compatible with Stage 3):

```json
{
  "source_hash": "sha256:<64 hex>",
  "candidates": [{"id","kind","value","tier","source_span":[start,end]}, ...],
  "drafts": [],
  "weak_drafts": [],
  "orphans": ["candidate_id", ...],
  "warnings": ["stage-2-parse-skeleton"],
  "layer_versions": {"rules":"1.0-lite","crf":"disabled","fingerprint":"disabled","grouper":"disabled"}
}
```

### 5.4 Error codes

All `_internal` errors use `I_` prefix. Numeric mapping: -32101 to -32199 (separate from JSON-RPC reserved -32000..-32099 range).

| Code | Meaning |
|---|---|
| `I_STDIN_INVALID_JSON` | stdin parse failed, or missing required fields |
| `I_STDIN_READ_FAILED` | I/O error reading stdin |
| `I_VAULT_KEY_MALFORMED` | vault_key_hex wrong length / non-hex chars |
| `I_VAULT_KEY_INVALID` | key well-formed but doesn't match vault |
| `I_VAULT_NOT_INITIALIZED` | no vault.db yet |
| `I_VAULT_OPEN_FAILED` | SQLite open error |
| `I_UNKNOWN_ACTION` | action string not recognized |
| `I_NOT_IMPLEMENTED` | action reserved but not yet implemented |
| `I_CREDENTIAL_NOT_FOUND` | alias / job_id not in DB |
| `I_CREDENTIAL_CONFLICT` | alias / job_id already exists (on_conflict=error) |
| `I_PARSE_FAILED` | regex/parse engine error |
| `I_INTERNAL` | unexpected error (SQL, encryption, serialization) |

### 5.5 Go local-server contract

- **Always** pass `--stdin-json` flag (clap requires it)
- **Never** pipe raw passwords — only derived vault_key_hex
- After receiving response with plaintext (`query get` with `include_secret:true`), Go MUST zeroize the value after use and not forward to logs
- If subprocess exits non-zero, treat as `I_SUBPROCESS_CRASH` (cli never intentionally exits non-zero from `_internal`)

---

## 6. Concurrency

- SQLite WAL mode (see `storage::open_connection`)
- Multiple reader processes OK
- Multiple writer processes SQLite-serializes via busy_timeout
- `_internal` IPC invocations from Go local-server are serialized client-side via `cli_bridge` mutex (see Stage 0 §0.4 finding: 2 writer no-wait scenarios can produce 2.01s waits)

---

## 7. Security invariants

1. `config.password_hash` == vault master key (32 bytes). Changing password rotates this + the salt.
2. `entries.ciphertext` includes GCM auth tag; tampering detected on decrypt.
3. `audit_log.hmac` signed with vault-key-derived audit key (§2.4); tampering with audit rows detected by `verify_audit_log`.
4. `_internal` IPC: no secrets on argv (all via stdin).
5. `_internal` IPC: no plaintext in response unless `include_secret:true` explicit.

---

## 8. Change log

- **2026-04-22**: Stage 2 Phase F+G — added v1.0.5-alpha migration (`import_jobs` / `import_items`), `_internal` IPC protocol, `I_*` error codes, audit-from-vault-key path.
- 2026-04-13: Structural refactoring (commands_account / storage_platform modules).
- 2026-04: v1.0.2/3/4-alpha migrations.
- 2026-03: Initial vault format.
