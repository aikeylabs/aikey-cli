//! `aikey service` — unified start / stop / restart / status entry point
//! for AiKey-owned background services.
//!
//! Today's whitelist: `trust-local`, `web`, `proxy`. The whitelist is
//! deliberately closed — `aikey service` is NOT a generic launchctl /
//! systemctl wrapper. We refuse anything not in this short list so a
//! malicious page can't ask the local-server to start arbitrary user
//! services via the future `/api/internal/services/<name>/start`
//! endpoint that mirrors this CLI.
//!
//! Dispatch:
//!   - `trust-local` → launchctl (macOS) / systemctl --user (Linux)
//!     against label `aikey.trust-local`. Owned by this module.
//!   - `web` → delegates to `commands_account::handle_web_service`,
//!     which already manages aikey-local-server's launchd label
//!     (Personal vs Trial edition-aware).
//!   - `proxy` → delegates to `commands_proxy::handle_*` (existing
//!     PID-file lifecycle). Full launchd migration for the proxy
//!     deferred — needs a master-password-without-TTY design first;
//!     see kickoff §11.
//!
//! See workflow/CD/installer/quickstart-personal.md "Trust Check"
//! section for user-facing docs.

pub(crate) mod commands;

pub(crate) use commands::handle_service;
