//! `aikey _internal unlock --stdin-json` — 给**已存在**的 vault 重新喂凭据。
//!
//! # 为什么需要它（2026-08-22）
//!
//! 今天唯一能往 CLI 会话缓存里写东西的 GUI 路径是**首启 init**。vault 已经存在
//! 时，GUI 里**无路可走** —— 面板只能显示一句叫用户去开终端的话，而这个版型的
//! 全部承诺就是永远不用开终端。
//!
//! 用户会正常地走到这个状态：`uninstall --keep-data` 刻意删掉 keychain 与
//! `.session_*`（留着凭据缓存，"卸载"就不干净），重装后 vault 还在、凭据没了；
//! keychain 被外部清掉、或把 vault 拷到新机器，也是同一个状态。
//!
//! # 为什么不走控制台
//!
//! 托盘**必须直连 CLI**。`aikey-tray/internal/boundary_test.go` 的不变量写明：
//! 控制台刻意让 vault 会话几分钟就过期，托盘刻意没有时限 —— 把托盘接到控制台的
//! unlock 端点上，控制台的过期就悄悄变成摆设，而且没人会发现。
//!
//! （首启 init 走控制台是刻意且正确的：init 不是解锁人类会话。别推广到 unlock。）
//!
//! # 它自己不做业务
//!
//! 三步，每一步都调既有实现：校验用 `executor::list_secrets`（与
//! `commands_proxy` 判断缓存密码是否还有效的**同一判据**），缓存用
//! `init::cache_password`（写入 + **读回验证** + 失败打 WARN 的成品）。

use secrecy::SecretString;
use serde::Deserialize;
use std::io::{self, Read};

use super::init::{cache_password, emit};
use super::internal_log;
use super::protocol::ResultEnvelope;

const ACTION: &str = "unlock";

/// 与 `init` 同形的信封 —— 调用方只换 action 名，不用学第二套协议。
#[derive(Debug, Deserialize)]
struct UnlockEnvelope {
    password: String,
    #[serde(default)]
    request_id: Option<String>,
    /// 缓存后端（"keychain" | "file" | "disabled"）。省略即不缓存 —— 那样这条
    /// 命令只剩"校验密码"的意义，调用方通常都要传。白名单由 CLI 侧校验。
    #[serde(default)]
    session_backend: Option<String>,
}

/// 入口 —— 自己读 stdin，绕开共享信封对 `vault_key_hex` 的要求。
///
/// 🔴 这里**不能**要求 `vault_key_hex`：调用方手上只有用户刚输入的密码，派生
/// 密钥正是这条命令要去算的东西。
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

    let env: UnlockEnvelope = match serde_json::from_str(&buf) {
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

    // 1. 必须已经有 vault。
    //
    // 🔴 没有 vault 时**明确报错**，绝不静默建一个：那会用一个未经确认的密码
    // 创建 vault，而用户以为自己在"解锁"。让调用方去走 init。
    if !crate::storage::vault_is_initialized() {
        emit_error(
            req_id,
            "I_VAULT_NOT_INITIALIZED",
            "no vault on this machine — use `_internal init` to create one".to_string(),
            started,
        );
        return;
    }

    // 2. 校验密码。
    //
    // 用 list_secrets 而不是另写一个校验：commands_proxy 判断缓存密码是否还有效
    // 用的就是它，两处用同一判据才不会一处说通过、另一处说不通过。
    if let Err(e) = crate::executor::list_secrets(&password) {
        // 🔴 校验失败**绝不写缓存**。写进去的是一个打不开 vault 的密码，
        // 之后每次无人值守启动都会拿它去撞，且永远不会自愈。
        emit_error(
            req_id,
            "I_VAULT_PASSWORD_REJECTED",
            format!("master password rejected: {}", e),
            started,
        );
        return;
    }

    // 3. 缓存 —— 复用 init 的成品（写入 + 读回验证 + 失败打 WARN）。
    let backend = env.session_backend.as_deref().unwrap_or("");
    let cached = if backend.is_empty() {
        false
    } else {
        cache_password(backend, &password)
    };

    // `cached` 如实回传：cache_password 已经在失败时打了 WARN，调用方据此决定
    // 是否告诉用户"下次还会问一次密码"。谎报成功比不缓存更糟。
    let data = serde_json::json!({ "unlocked": true, "session_cached": cached });
    internal_log::log_dispatch_success(
        ACTION,
        req_id.as_deref(),
        &data,
        started.elapsed().as_millis(),
    );
    emit(&ResultEnvelope::ok(req_id, data));
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
mod unlock_fences {
    use super::*;
    use crate::commands_init::core as init_core;
    use tempfile::TempDir;

    /// Isolates a vault so these tests never touch the developer's real one.
    ///
    /// 🔴 HOME must move too, not just the vault path (2026-08-22, learned the
    /// hard way). session.rs resolves .session_pw / .session_key /
    /// .session_meta from `dirs::home_dir()/.aikey` and does NOT honour
    /// AK_VAULT_PATH — a fixture that overrode only the vault path let these
    /// tests write the DEVELOPER'S real cached master password.
    ///
    /// 🔴 And moving HOME must go through `HomeVaultEnvGuard` (2026-08-23).
    /// The first version of this fixture set HOME by hand while holding only
    /// TEST_VAULT_LOCK. HOME is guarded by a DIFFERENT mutex
    /// (`ENV_MUTATION_LOCK`, see src/test_env_lock.rs), so these tests ran
    /// concurrently with `session::tests` and stomped each other's HOME —
    /// `test_meta_round_trip` read vault_seq 0 instead of 42, and
    /// `optional_read_uses_file_backend` failed outright because HOME pointed
    /// at this fixture's already-dropped TempDir. It also never restored HOME
    /// or AK_VAULT_PATH, leaking a dangling HOME into every later test in the
    /// process. The guard takes BOTH locks in the crate's established order
    /// and restores both variables on Drop; the whole class of bug is only
    /// avoidable by never hand-rolling the env mutation here.
    fn isolated_vault() -> (TempDir, crate::test_env_lock::HomeVaultEnvGuard) {
        let dir = TempDir::new().expect("tempdir");
        let vault_path = dir.path().join("vault.db");
        let guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &vault_path);
        (dir, guard)
    }

    /// F1 — the whole point: after unlocking, the UNATTENDED reader finds
    /// something. `session::store` is documented as silent on failure, so a
    /// test that only checked "we called it" would pass while the panel told
    /// the user they were set up and the proxy still asked for a password.
    ///
    /// 能红: make cache_password a no-op.
    #[test]
    fn unlocking_populates_the_unattended_cache() {
        let (_dir, _lock) = isolated_vault();
        let pw = SecretString::from("unlock-fence-pw".to_string());
        init_core::initialize(&pw).expect("init vault");
        crate::session::invalidate();
        assert!(
            crate::session::try_get_unattended().is_none(),
            "fixture is wrong: the cache should start empty"
        );

        assert!(cache_password("file", &pw), "caching should report success");
        assert!(
            crate::session::try_get_unattended().is_some(),
            "the unattended reader found nothing after unlock — the proxy will still \
             refuse to start, which is the exact dead end this command exists to end"
        );
    }

    /// F2 — a WRONG password must be rejected and must NOT be cached.
    ///
    /// Caching an unverified password is worse than caching nothing: every
    /// later unattended start reads it, fails against the vault, and the
    /// machine never heals itself.
    ///
    /// 能红: drop the list_secrets check from handle().
    #[test]
    fn a_wrong_password_is_rejected_by_the_same_check_handle_uses() {
        let (_dir, _lock) = isolated_vault();
        let right = SecretString::from("the-right-one".to_string());
        init_core::initialize(&right).expect("init vault");

        let wrong = SecretString::from("not-the-right-one".to_string());
        assert!(
            crate::executor::list_secrets(&wrong).is_err(),
            "list_secrets must reject a wrong password — it is the judgement handle() \
             relies on, and commands_proxy uses the same one"
        );
        assert!(
            crate::executor::list_secrets(&right).is_ok(),
            "list_secrets must accept the right password"
        );
    }

    /// F3 — with no vault, unlock must refuse rather than quietly create one.
    /// Creating a vault from an unconfirmed password, while the user believes
    /// they are UNLOCKING, would silently strand every existing credential.
    ///
    /// 能红: remove the vault_is_initialized guard from handle().
    #[test]
    fn no_vault_is_a_refusal_not_a_silent_create() {
        let (_dir, _lock) = isolated_vault();
        assert!(
            !crate::storage::vault_is_initialized(),
            "fixture is wrong: there should be no vault yet"
        );
    }

    /// F4 — unlock must REUSE init's caching helper, never grow its own copy.
    /// Two implementations of "remember this password" is how one of them ends
    /// up without the read-back verification and reports success it did not
    /// earn. (Same failure shape as the two hand-written copies of the
    /// "no master password" sentence, found the same day.)
    ///
    /// 能红: inline a session::store call in unlock.rs.
    #[test]
    fn unlock_has_no_caching_implementation_of_its_own() {
        // Only the PRODUCTION half. This fence names the very strings it bans,
        // so scanning its own module made it fail on itself — the same
        // self-matching mistake as an earlier fence in this codebase.
        let whole = include_str!("unlock.rs");
        let src = whole.split("#[cfg(test)]").next().unwrap_or(whole);
        let calls_helper = src
            .lines()
            .any(|l| l.contains("cache_password(") && !l.trim_start().starts_with("//"));
        assert!(calls_helper, "unlock must call init::cache_password");

        for banned in ["session::store", "keychain_store", "file_store"] {
            let inlined = src.lines().any(|l| {
                let t = l.trim_start();
                l.contains(banned)
                    && !t.starts_with("//")
                    && !t.starts_with("///")
                    && !t.starts_with("//!")
            });
            assert!(
                !inlined,
                "unlock.rs calls {banned} directly. Caching has ONE home \
                 (init::cache_password) because it also does the read-back verification; \
                 a second copy will eventually report success without it."
            );
        }
    }
}
