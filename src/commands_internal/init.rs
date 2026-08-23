//! `_internal init` action — vault first-time setup driven by Web UI.
//!
//! Unlike vault-op, this action precedes vault existence: there is no
//! vault_key to derive yet. Hence the dedicated handler with its own
//! envelope shape that omits `vault_key_hex`.
//!
//! Per 20260430-个人vault-Web首次设置-方案A.md: aikey-local-server's
//! POST /api/user/vault/init invokes this subprocess with stdin JSON
//! `{password, request_id?}`, and the same business logic core that
//! `aikey init` (CLI shell) uses runs end-to-end. No prompts, no TTY.

use std::io::{self, Read, Write};

use secrecy::SecretString;
use serde::Deserialize;

use super::internal_log;
use super::protocol::ResultEnvelope;
use crate::commands_init::core as init_core;

#[derive(Debug, Deserialize)]
struct InitEnvelope {
    password: String,
    #[serde(default)]
    request_id: Option<String>,
    /// Optional: which session-cache backend to remember this password in
    /// ("keychain" | "file" | "disabled"). Omitted → nothing is cached, which
    /// is the behaviour every existing caller already gets.
    ///
    /// WHY (2026-08-17, AiKey.app first-run):
    /// Setting a master password in the web console creates the vault, but the
    /// CLI session cache stays empty — and `aikey proxy start` under launchd has
    /// no terminal, so it takes the unattended path, finds nothing cached and
    /// fails with "no master password available". The user would have just set
    /// a password and still be looking at a stopped proxy with no way to fix it
    /// from the GUI. Caching here is what closes that loop.
    ///
    /// 🔴 This is NOT "keychain as the vault's root of trust" — the design
    /// (20260430-个人vault-Web首次设置-方案A.md §6) defers that deliberately.
    /// The user still chooses the password and it remains the vault's root
    /// secret; this only remembers it the same way `session::store` already
    /// does after an interactive CLI prompt. The threat model is unchanged.
    #[serde(default)]
    session_backend: Option<String>,
}

const ACTION: &str = "init";

/// Entry point — reads its own envelope so it doesn't trip on the
/// vault-op envelope's `vault_key_hex` requirement.
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

    let env: InitEnvelope = match serde_json::from_str(&buf) {
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

    if env.password.is_empty() {
        emit_error(
            req_id,
            "I_PASSWORD_REQUIRED",
            "password must be non-empty".to_string(),
            started,
        );
        return;
    }

    let password = SecretString::from(env.password);

    match init_core::initialize(&password) {
        Ok(()) => {
            // Cache AFTER the vault exists: the backend preference lives in the
            // vault's own config table, so storing it before init would have
            // nowhere to go.
            //
            // Best-effort by design. A keychain that refuses to store (locked
            // login keychain, a policy-managed Mac) must not turn a successful
            // vault creation into a reported failure — the vault IS created,
            // and the only consequence is that the proxy asks for the password
            // once. Reporting failure here would send the user back to set a
            // password that already exists.
            let cached = env
                .session_backend
                .as_deref()
                .map(|backend| cache_password(backend, &password));

            let result = ResultEnvelope::ok(
                req_id.clone(),
                serde_json::json!({
                    "message": "vault initialized",
                    // Reported so the caller can tell the user the truth: the
                    // proxy may still ask for the password once.
                    "session_cached": cached,
                }),
            );
            internal_log::log_dispatch_success(
                ACTION,
                req_id.as_deref(),
                result.data.as_ref().unwrap_or(&serde_json::Value::Null),
                started.elapsed().as_millis(),
            );
            emit(&result);
        }
        Err(msg) => {
            // storage::initialize_vault returns this exact error string when
            // the vault is already initialized — map to a stable error code
            // so the web layer can render "already initialized, refresh
            // status" without parsing the human message.
            let code = if msg.contains("Vault already initialized") {
                "I_VAULT_ALREADY_INITIALIZED"
            } else {
                "I_VAULT_INIT_FAILED"
            };
            emit_error(req_id, code, msg, started);
        }
    }
}

/// Remember the freshly-set password in the CLI session cache, and report
/// whether it actually landed.
///
/// Verifies by READING IT BACK rather than trusting the write: `session::store`
/// is documented as silent on failure ("the caller must not depend on the cache
/// being populated"), so a keychain that declined would otherwise be reported as
/// success — and the user would be told the proxy is set up when it will still
/// ask for a password.
pub(super) fn cache_password(backend: &str, password: &SecretString) -> bool {
    // Whitelist: the value crosses a process boundary from the web layer, and
    // the preference is persisted into the vault. An unknown string would be
    // written and then silently mean "no cache" to every later reader.
    if !matches!(backend, "keychain" | "file" | "disabled") {
        crate::observability::log_warn_event(
            crate::observability::EVENT_CLI_VAULT_SESSION_CACHE_SKIPPED,
            &format!(
                "unknown session_backend {:?}; the password was not cached and the proxy will ask for it",
                backend
            ),
            Some(crate::observability::ERRCODE_SESSION_BACKEND_UNKNOWN),
        );
        return false;
    }

    crate::storage::set_session_backend_pref(backend);
    if backend == "disabled" {
        return false;
    }

    crate::session::store(password);
    let cached = crate::session::try_get_unattended().is_some();
    if !cached {
        crate::observability::log_warn_event(
            crate::observability::EVENT_CLI_VAULT_SESSION_CACHE_SKIPPED,
            &format!(
                "session_backend {:?} accepted no password (locked or policy-restricted keychain); \
                 the vault IS initialized but the proxy will ask for the password once",
                backend
            ),
            None,
        );
    }
    cached
}

pub(super) fn emit(result: &ResultEnvelope) {
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

#[cfg(test)]
mod session_cache_tests {
    use super::*;
    use tempfile::TempDir;

    /// Isolates a vault so these tests never touch the developer's real one.
    fn isolated_vault() -> (TempDir, std::sync::MutexGuard<'static, ()>) {
        let guard = crate::storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("tempdir");
        unsafe {
            std::env::set_var(
                "AK_VAULT_PATH",
                dir.path().join("vault.db").to_str().unwrap(),
            );
        }
        (dir, guard)
    }

    /// An unrecognised backend must not be persisted. It crosses a process
    /// boundary from the web layer and lands in the vault's config table, where
    /// every later reader would silently interpret it as "no cache" — the
    /// proxy would keep asking for a password with nothing explaining why.
    #[test]
    fn unknown_backend_is_rejected_and_not_persisted() {
        let (_dir, _lock) = isolated_vault();
        let pw = SecretString::from("pw-for-test".to_string());
        init_core::initialize(&pw).expect("init vault");

        assert!(
            !cache_password("nonsense", &pw),
            "an unknown backend must report 'not cached'"
        );
        assert_eq!(
            crate::storage::get_session_backend_pref(),
            None,
            "an unknown backend must not be written into the vault"
        );
    }

    /// "disabled" is a real user choice: record it, cache nothing, and say so.
    #[test]
    fn disabled_backend_is_persisted_but_caches_nothing() {
        let (_dir, _lock) = isolated_vault();
        let pw = SecretString::from("pw-for-test".to_string());
        init_core::initialize(&pw).expect("init vault");

        assert!(!cache_password("disabled", &pw));
        assert_eq!(
            crate::storage::get_session_backend_pref().as_deref(),
            Some("disabled")
        );
        assert!(
            crate::session::try_get_unattended().is_none(),
            "'disabled' must leave nothing readable"
        );
    }

    /// The honesty property: whatever this returns must match what a later
    /// unattended reader actually finds. session::store is silent on failure,
    /// so a version that returned `true` unconditionally would tell the user
    /// the proxy is ready when it will still stop and ask for a password.
    #[test]
    fn reported_result_matches_what_an_unattended_reader_sees() {
        let (_dir, _lock) = isolated_vault();
        let pw = SecretString::from("pw-for-test".to_string());
        init_core::initialize(&pw).expect("init vault");

        let reported = cache_password("file", &pw);
        let actually_readable = crate::session::try_get_unattended().is_some();
        assert_eq!(
            reported, actually_readable,
            "session_cached was reported as {} but an unattended read finds {} — \
             the caller would tell the user something untrue about whether the \
             proxy can start on its own",
            reported, actually_readable
        );
    }
}
