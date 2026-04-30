//! `aikey _internal *` 子命令组 —— Go local-server ↔ Rust cli 的唯一 IPC 协议
//!
//! # 定位
//! - 所有子命令都 `#[command(hide = true)]`，不出现在 `aikey --help`
//! - 所有子命令都通过 `--stdin-json` 读统一 JSON 信封（见 `protocol.rs`）
//! - 所有子命令都输出统一 JSON 信封到 stdout（成功/失败同一格式）
//!
//! # 子命令清单（v1.0 目标 4 个 + 一个静态数据出口）
//! | 子命令 | Phase | 作用 |
//! |---|---|---|
//! | `vault-op` | A/B | vault 读写加密操作（verify/add/batch_import/update_secret/delete）|
//! | `query` | C | vault 读（带解密）|
//! | `update-alias` | D | 编辑非敏感元数据 |
//! | `parse` | E (Stage 3) | 文本解析三层流水（规则+CRF+Fingerprint）|
//! | `rules` | — | 把 provider_fingerprint.yaml 静态映射透传给 Web UI（无 vault 访问）|
//!
//! # 错误码约定
//! 所有错误码用 `I_` 前缀（Internal），详见 `error_codes::ErrorCode` 的 I_* 变体。

use clap::{Args, Subcommand};

pub mod protocol;
pub mod stdin_json;
pub mod vault_op;
pub mod query;
pub mod update_alias;
pub mod parse;
pub mod rules;
pub mod init;
pub mod internal_log;

#[cfg(test)]
mod tests;

/// `_internal` 子命令 enum（挂在 cli::Commands::Internal 下）
#[derive(Subcommand, Debug)]
pub enum InternalAction {
    /// vault 加密读写操作（verify / add / batch_import / update_secret / delete）
    VaultOp(StdinOnlyArgs),

    /// vault 读（含解密）
    Query(StdinOnlyArgs),

    /// 编辑非敏感元数据（alias / tag / note / enabled）
    UpdateAlias(StdinOnlyArgs),

    /// 文本解析三层流水（Stage 3 实施）
    Parse(StdinOnlyArgs),

    /// provider_fingerprint.yaml 静态映射透传（layer 版本 / family_*_urls / sample_providers）
    Rules(StdinOnlyArgs),

    /// Vault first-time initialization (web-driven first-run flow).
    /// Per 20260430-个人vault-Web首次设置-方案A.md: aikey-local-server
    /// invokes `aikey _internal init --stdin-json` with `{password}`.
    /// Distinct from vault-op because vault doesn't exist yet (no
    /// vault_key to derive); uses its own envelope shape in init.rs.
    Init(StdinOnlyArgs),
}

/// 所有 `_internal` 子命令都只接受 `--stdin-json`，JSON 从 stdin 读
#[derive(Args, Debug)]
pub struct StdinOnlyArgs {
    /// Read request envelope from stdin as JSON (required; the only supported input mode)
    #[arg(long, required = true)]
    pub stdin_json: bool,
}

/// 从 cli main 调过来的单一入口
///
/// 这里负责：
/// 1. 从 stdin 读 envelope
/// 2. 派发到对应 action 模块
/// 3. 失败统一由各 action 模块 `emit_error` 输出 JSON 后 return（不 panic 不 exit 非 0）
///
/// Why 不 exit(N)：Go local-server 只解析 stdout JSON，靠 status 字段判失败。
/// exit code 仅在进程意外崩溃时触发（此时 Go 侧读到 "Unexpected EOF" 之类，按 I_SUBPROCESS_CRASH 处理）。
pub fn dispatch(action: &InternalAction) {
    // 注意：所有 action 接收同一 envelope；action 名称通过 envelope.action 字段传
    // —— 这与子命令名（vault-op/query/...）**不冲突**：subcommand 选择模块，envelope.action 选择 action
    // （例如 `_internal vault-op --stdin-json` 下 envelope.action 可以是 "verify"/"add"/...）
    // Init has its own envelope shape (no vault_key_hex — vault doesn't
    // exist yet) and reads stdin internally. Dispatch to it before the
    // shared envelope reader rejects the missing field.
    if let InternalAction::Init(_) = action {
        init::handle();
        return;
    }

    let action_name = match action {
        InternalAction::VaultOp(_)     => "vault-op",
        InternalAction::Query(_)       => "query",
        InternalAction::UpdateAlias(_) => "update-alias",
        InternalAction::Parse(_)       => "parse",
        InternalAction::Rules(_)       => "rules",
        InternalAction::Init(_)        => unreachable!("handled above"),
    };
    let env = match stdin_json::read_envelope() {
        Ok(e) => e,
        Err((code, msg)) => {
            // Stage logging before emit: even read-failures deserve a trace
            // in internal.jsonl so an operator can see "request arrived but
            // the envelope was malformed" without guessing.
            internal_log::log_dispatch_error(action_name, None, code, &msg, 0);
            stdin_json::emit_error(None, code, msg);
            return;
        }
    };

    // Record the "in" event now; matching "ok" / "err" is emitted from
    // `stdin_json::emit` / `emit_error` once the handler returns.
    internal_log::log_dispatch_start(action_name, &env);
    stdin_json::set_dispatch_context(action_name, env.request_id.clone());

    match action {
        InternalAction::VaultOp(_) => vault_op::handle(env),
        InternalAction::Query(_) => query::handle(env),
        InternalAction::UpdateAlias(_) => update_alias::handle(env),
        InternalAction::Parse(_) => parse::handle(env),
        InternalAction::Rules(_) => rules::handle(env),
        InternalAction::Init(_) => unreachable!("handled above"),
    }
}
