//! Credential lifecycle management.
//!
//! All write paths that touch `user_profile_provider_bindings` MUST funnel
//! through `apply_credential_lifecycle` (or `apply_credential_lifecycle_batch`
//! for picker-style bulk writes). The helper owns the canonical
//! side-effect chain so individual call sites can't drift.
//!
//! Side-effect chain (preserved across all entries):
//!   1. write/reconcile bindings via the appropriate per-event helper
//!      - Added    → `auto_assign_primaries_for_key` (only fills empty slots)
//!      - Switched → `write_bindings_canonical` (overwrites)
//!      - Removed  → `reconcile_provider_primary_after_key_removal`
//!   2. `profile_activation::refresh_implicit_profile_activation()`
//!   3. `apply_third_party_cli_configs(active_providers, proxy_port)`
//!
//! Companion read-only API: `audit_credential_lifecycle()` compares the
//! DB binding table against active.env and the kimi/codex toml regions
//! to surface drift. Used by `aikey doctor` and tests.
//!
//! See `bugfix/2026-05-07-handle-add-skips-third-party-cli-config.md` Phase 5
//! for the systemic-fix history this module closes.

pub mod audit;
pub mod event;

pub use audit::{
    audit_credential_lifecycle, AuditReport, DiffEntry, DiffSeverity, DiffSource,
};
pub use event::{
    apply_credential_lifecycle, apply_credential_lifecycle_batch,
    CredentialLifecycleEvent, LifecycleOutcome,
};
