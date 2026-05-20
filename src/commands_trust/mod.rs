//! `aikey trust` — passthrough commands to the user-local trust-local service
//! (degrade-detector M3). Verifies cascade L3, queries per-KEY trust state,
//! triggers manual sync from trust-central.
//!
//! Boundary: this module is a thin HTTP client. All trust algorithms /
//! storage live in `aikeylabs/degrade-detector/server_local/` (Python).
//! aikey-cli never owns trust data — vault.app_keys is the only AiKey-side
//! source of truth for keys; trust state belongs to trust-local's SQLite.
//!
//! Discovery: defaults to `http://127.0.0.1:8801` (install_service.sh's
//! systemd / launchd default). Override with env `DEGRADE_DETECTOR_LOCAL_URL`.
//! No vault config field — trust-local is installed via aikey-cli's app
//! pipeline (M3.J `aikey app install degrade-detector` → install_service.sh),
//! so its URL is conventionally fixed.

pub(crate) mod client;
pub(crate) mod commands;

pub(crate) use commands::{
    handle_history, handle_status, handle_sync, handle_verify,
};
