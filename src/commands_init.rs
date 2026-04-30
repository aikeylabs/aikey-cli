//! Vault initialization core — shared business logic for `aikey init`
//! (CLI shell) and `_internal vault-op` action `init` (web-driven first
//! run via aikey-local-server).
//!
//! Per CLAUDE.md `_internal` 必须复用公开命令核心 rule: this module is
//! the single source of truth. Both call paths produce identical on-disk
//! state — vault.db with master_salt / kdf_* / password_hash rows, plus
//! an initialised audit log and an INIT audit event.
//!
//! What lives where:
//! - `core::initialize`: generates salt, calls `storage::initialize_vault`,
//!   sets up the audit log, emits the INIT audit event. No I/O on TTY,
//!   no prompts, no println.
//! - The `aikey init` CLI handler (in main.rs) wraps this with the
//!   master-password prompt and "Initializing..." / "Vault initialized!"
//!   user-facing prints.
//! - The `_internal vault-op` `init` action reads `payload.password` from
//!   stdin JSON and invokes `core::initialize` directly.

pub mod core {
    use secrecy::SecretString;

    use crate::audit::{self, AuditOperation};
    use crate::crypto;
    use crate::storage;

    /// Initialize the vault using the given master password.
    ///
    /// Steps:
    ///   1. Generate a fresh 16-byte salt.
    ///   2. `storage::initialize_vault` creates the SQLite file and
    ///      writes salt + KDF params + password hash. Errors when the
    ///      vault is already initialized (idempotent guard at storage
    ///      layer; see storage::initialize_vault).
    ///   3. Initialize the audit log.
    ///   4. Emit an INIT audit event (best-effort: a logging failure
    ///      does not roll back the vault creation).
    ///
    /// Returns Ok(()) on success. Errors are propagated as strings —
    /// callers translate to user-facing or JSON-envelope errors.
    pub fn initialize(password: &SecretString) -> Result<(), String> {
        let mut salt = [0u8; 16];
        crypto::generate_salt(&mut salt)?;

        storage::initialize_vault(&salt, password)?;

        audit::initialize_audit_log()
            .map_err(|e| format!("Failed to initialize audit log: {}", e))?;

        // Audit event is best-effort — the vault is already on disk and
        // the user expects success. A subsequent audit write failure is
        // surfaced via the boolean return of log_audit_event but we do
        // not bubble it up here.
        let _ = audit::log_audit_event(password, AuditOperation::Init, None, true);

        Ok(())
    }
}
