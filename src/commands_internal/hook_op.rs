//! `_internal hook-op` action — Web-modal "Allow" path.
//!
//! Per 20260507-web-hook-rc-modal-自动注入.md: when the Web bridge gets
//! `hook_rc_wired=false` in a vault-op envelope, the SPA pops a modal
//! showing the 3-line v3 marker block + an "Allow" button. Allow → POST
//! /api/user/hook/install → Go forwards stdin JSON to this subprocess.
//!
//! Unlike vault-op, this action does NOT need `vault_key_hex`: it only
//! touches `~/.aikey/hook.{zsh,bash}` and the user's `.zshrc` / `.bashrc`.
//! Hence the dedicated handler with its own envelope shape (mirrors how
//! `init` was special-cased on 2026-04-30).
//!
//! Edition guard is enforced **upstream** in the Go HTTP layer: only
//! `local-user` and `trial-full` modes register the route. Production
//! returns 403 before this handler ever runs. We do not double-check
//! mode here because the CLI binary has no concept of edition.

use std::io::{self, Read, Write};

use serde::Deserialize;

use crate::commands_account::{wire_rc_with_consent, HookFailureReason, shell_rc_has_aikey_block};
use super::internal_log;
use super::protocol::ResultEnvelope;

#[derive(Debug, Deserialize)]
struct HookOpEnvelope {
    /// "wire-rc" — currently the only action. Future: "uninstall-rc",
    /// "status", etc. Keep the field so the same handler can grow.
    action: String,
    #[serde(default)]
    request_id: Option<String>,
}

const ACTION: &str = "hook-op";

/// Entry point — reads its own envelope so the shared envelope reader
/// doesn't trip on the missing `vault_key_hex`.
pub fn handle() {
    let started = std::time::Instant::now();

    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        emit_error(
            None,
            "I_STDIN_READ_FAILED",
            format!("failed to read stdin: {}", e),
            started,
        );
        return;
    }
    if buf.trim().is_empty() {
        emit_error(
            None,
            "I_STDIN_INVALID_JSON",
            "stdin is empty (expected JSON envelope)".to_string(),
            started,
        );
        return;
    }

    let env: HookOpEnvelope = match serde_json::from_str(&buf) {
        Ok(e) => e,
        Err(e) => {
            emit_error(
                None,
                "I_STDIN_INVALID_JSON",
                format!("stdin is not valid JSON: {}", e),
                started,
            );
            return;
        }
    };

    let req_id = env.request_id.clone();

    match env.action.as_str() {
        "wire-rc" => handle_wire_rc(req_id, started),
        other => emit_error(
            req_id,
            "I_UNKNOWN_ACTION",
            format!("unknown hook-op action: '{}'", other),
            started,
        ),
    }
}

/// `wire-rc` action: render hook file (Layer 1) + write rc marker block
/// (Layer 2). Always returns the same envelope shape as the vault-op
/// hook-status fields so the front-end's `setReadiness` handler is
/// symmetric — Allow → setReadiness({fileInstalled:true, rcWired:true,
/// failureReason:null}) closes the modal and clears the banner without
/// any extra round-trip.
fn handle_wire_rc(req_id: Option<String>, started: std::time::Instant) {
    let result_data = match wire_rc_with_consent() {
        Ok(()) => serde_json::json!({
            "hook_file_installed": true,
            "hook_rc_wired": true,
            "hook_failure_reason": serde_json::Value::Null,
        }),
        Err(reason) => {
            // For partial failure (e.g. Layer 1 wrote OK but Layer 2
            // io-errored), `wire_rc_with_consent` returned the first
            // err it hit. Re-probe rc state so the front-end has an
            // accurate picture even on failure paths — `shell_rc_has_aikey_block`
            // is a cheap read.
            let rc_wired_now = shell_rc_has_aikey_block();
            // file_installed: best-effort flag — for AikeyNoHook the
            // file was never written this call but might exist from a
            // prior run; for ShellUndetectable the file was never
            // attempted; for IoError we don't know. Conservative
            // false matches what `web_install_hook_file_layer1` would
            // return for these reasons.
            let file_installed = matches!(reason, HookFailureReason::IoError);
            serde_json::json!({
                "hook_file_installed": file_installed,
                "hook_rc_wired": rc_wired_now,
                "hook_failure_reason": reason.as_envelope_str(),
            })
        }
    };

    let result = ResultEnvelope::ok(req_id.clone(), result_data);
    internal_log::log_dispatch_success(
        ACTION,
        req_id.as_deref(),
        result.data.as_ref().unwrap_or(&serde_json::Value::Null),
        started.elapsed().as_millis(),
    );
    emit(&result);
}

fn emit(result: &ResultEnvelope) {
    let out = serde_json::to_string(result).unwrap_or_else(|_| {
        r#"{"status":"error","error_code":"I_INTERNAL","error_message":"failed to serialize"}"#
            .to_string()
    });
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{}", out);
    let _ = stdout.flush();
}

fn emit_error(
    req_id: Option<String>,
    code: &'static str,
    message: String,
    started: std::time::Instant,
) {
    let env = ResultEnvelope::error(req_id.clone(), code, message.clone());
    internal_log::log_dispatch_error(
        ACTION,
        req_id.as_deref(),
        code,
        &message,
        started.elapsed().as_millis(),
    );
    emit(&env);
}
