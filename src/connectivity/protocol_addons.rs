//! OAuth-credential 调用时的协议增量配置表 — single source of truth.
//!
//! 背景: bugfix 20260523-aikey-test-anthropic-via-proxy-misadds-beta-query.md
//!
//! `aikey test` doctor 在 anthropic via aikey-proxy 时无脑加 `?beta=true` +
//! `metadata.user_id`,因为代码用 `is_via_proxy` 当成 "is OAuth flow" 的近似判
//! 定。但 `is_via_proxy` 的语义只是 "base_url 指向 aikey-proxy 本身",同时覆盖:
//!   (a) OAuth claude 走 proxy        ← 需要 ?beta=true (Anthropic OAuth 要求)
//!   (b) personal API key 走 proxy
//!       转发到自定义 anthropic 网关  ← 绝对不能 ?beta=true (aicoding 等网关
//!                                       不认这个 query → 404)
//!
//! 修复方向: 不再用三维 `provider × via_proxy × kind` if-else 散弹判定,而是
//! 把 OAuth 协议增量声明在**本配置表一处**。`aikey test` doctor probe / 未来
//! `aikey-proxy` outbound transform middleware / `aikey run` 路径都查这同
//! 一份表 → 加新 OAuth provider 改一行,加新协议字段改一行,不再到处审视
//! 三维条件。
//!
//! CLAUDE.md: "不要写胶水逻辑,或者补丁逻辑(多个 if else 组成的逻辑特别注意),
//! 如果做不到简洁通用,那么就采用配置表的形式进行穷举"。

use serde_json::Value;

/// 一个 OAuth 凭证调用 chat completion 时必须附加的协议增量。
///
/// 设计契约:
/// - 仅对 `CredentialKind::OAuth` 应用 — personal API key / managed team
///   走干净路径,不需要任何协议增量。
/// - `url(base_url, default_path)` 和 `body(default_body)` 是组合点 —
///   消费方传入"按 provider 计算出的默认路径/body",addons 决定是覆盖还是
///   增量 merge。
pub struct ProtocolAddons {
    /// URL 末尾要附加的 query params, e.g. `[("beta", "true")]`.
    query: &'static [(&'static str, &'static str)],

    /// JSON body 顶层要 merge 进去的字段。用闭包返回是为了允许动态值
    /// (e.g. metadata.user_id) — 当前实现是静态值,但接口预留 dyn 可能。
    /// 与 `body_override` 互斥语义: override 在前,inject 在后。
    body_inject: fn() -> Vec<(String, Value)>,

    /// 路径覆盖。Codex OAuth 的 `/responses` 不是 `chat_suffix()` 的标准
    /// `/chat/completions`,需要完全替换。None = 用 `chat_suffix()` 默认值。
    path_override: Option<&'static str>,

    /// Body 完全覆盖。Codex OAuth 的 Responses API body shape 跟通用
    /// chat body 不兼容 (model=gpt-5.5 / instructions / input array /
    /// store / stream),必须完全替换而不是 merge。None = 用 `chat_body()` 默认值。
    body_override: Option<fn() -> Value>,
}

impl ProtocolAddons {
    /// 根据 addons 构造最终 chat probe URL。
    ///
    /// `default_path` = 消费方算好的 `chat_suffix(provider, base_url)`。
    pub fn url(&self, base_url: &str, default_path: &str) -> String {
        let path = self.path_override.unwrap_or(default_path);
        let mut url = format!("{}{}", base_url.trim_end_matches('/'), path);
        for (k, v) in self.query {
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(k);
            url.push('=');
            url.push_str(v);
        }
        url
    }

    /// 根据 addons 构造最终 chat probe body。
    ///
    /// `default_body` = 消费方算好的 `chat_body(provider)`。
    pub fn body(&self, default_body: Value) -> Value {
        let mut body = match self.body_override {
            Some(f) => f(),
            None => default_body,
        };
        if let Some(obj) = body.as_object_mut() {
            for (k, v) in (self.body_inject)() {
                obj.insert(k, v);
            }
        }
        body
    }
}

/// OAuth 协议增量注册表。返回 `Some(addons)` 表示该 provider 的 OAuth 流
/// 需要协议增量;`None` 表示无增量(走默认 chat_suffix + chat_body)。
///
/// **加新 OAuth provider 改这里一处即可**,不要在 doctor probe / proxy
/// transform / cli run 路径上散弹判定。
pub fn oauth_addons_for(provider_code: &str) -> Option<ProtocolAddons> {
    match provider_code {
        // Anthropic OAuth (Claude Pro/Max): API 要求 ?beta=true query 和
        // metadata.user_id body 字段。漏其中任一 → Anthropic 返 429 业务
        // 拒绝 (不是真限流)。aicoding 等自定义 anthropic 网关**不实现**这
        // 个变体,personal API key 经它们转发时必须**不**加这个增量,否则
        // 404 page not found。
        "anthropic" => Some(ProtocolAddons {
            query: &[("beta", "true")],
            body_inject: || {
                vec![(
                    "metadata".to_string(),
                    serde_json::json!({"user_id": "aikey_doctor_probe"}),
                )]
            },
            path_override: None,
            body_override: None,
        }),

        // Codex OAuth (ChatGPT Plus/Pro): 走 Responses API 不是 chat
        // completions,且必须用 store=false + stream=true + Codex-specific
        // 模型 (ChatGPT 账户只支持 Codex-specific 模型)。
        //
        // Model resolution = codex_probe_model() — see that function for
        // the single-truth chain. Short version: read the user's own
        // ~/.codex/config.toml so codex-cli updates are auto-tracked,
        // fall back to a hardcoded recent model only if config is missing.
        "openai" => Some(ProtocolAddons {
            query: &[],
            body_inject: || vec![],
            path_override: Some("/responses"),
            body_override: Some(|| {
                serde_json::json!({
                    "model": codex_probe_model(),
                    "instructions": "Say hi.",
                    "input": [{"role": "user", "content": "hi"}],
                    "store": false,
                    "stream": true
                })
            }),
        }),

        // 未来加 Kimi OAuth / Gemini OAuth / ... → 加一行
        _ => None,
    }
}

/// Fallback model used only on the very first probe before the proxy
/// has observed any real Codex OAuth request. Bump alongside codex-cli
/// major releases.
///
/// History: 2026-04-16 gpt-5.4 → 2026-06-05 gpt-5.5 (gpt-5.4 retired on
/// chatgpt.com/backend-api/codex/responses, returns HTTP 404 even for
/// valid OAuth tokens).
const CODEX_PROBE_FALLBACK_MODEL: &str = "gpt-5.5";

/// Resolve the model to use for the Codex OAuth connectivity probe.
///
/// Two layers:
///   1. **Proxy-observed model** (`~/.aikey/state/codex_last_model`) —
///      aikey-proxy writes the `model` field from every successful Codex
///      OAuth request here. Reading this means our probe sends EXACTLY
///      what the user's running codex CLI just used; self-healing across
///      codex CLI upgrades with no aikey release needed.
///   2. **`CODEX_PROBE_FALLBACK_MODEL` constant** — only hit on first
///      probe before the user has ever run codex through the proxy.
pub fn codex_probe_model() -> String {
    proxy_observed_codex_model().unwrap_or_else(|| CODEX_PROBE_FALLBACK_MODEL.to_string())
}

/// Read the model from the state file aikey-proxy writes after every
/// successful Codex OAuth request (see aikey-proxy's
/// codex_model_capture.go). Returns None when the file is missing or
/// blank — those are "no observation yet" cases, caller falls back to
/// the constant.
///
/// File format: a single text line containing the model name (e.g.
/// `gpt-5.5\n`). Plain text instead of JSON because there's only one
/// value, and `cat`/`tail` debugging stays trivial.
fn proxy_observed_codex_model() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".aikey/state/codex_last_model");
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_oauth_adds_beta_query_and_metadata() {
        let a = oauth_addons_for("anthropic").expect("anthropic OAuth addons must exist");
        let url = a.url("http://127.0.0.1:27200/anthropic", "/v1/messages");
        assert!(
            url.ends_with("/v1/messages?beta=true"),
            "anthropic OAuth must end with ?beta=true; got: {}",
            url
        );

        let body =
            a.body(serde_json::json!({"model": "claude-haiku-4-5-20251001", "max_tokens": 1}));
        let meta = body
            .get("metadata")
            .expect("metadata field must be injected");
        assert_eq!(meta["user_id"], "aikey_doctor_probe");
        // 原有字段保留
        assert_eq!(body["model"], "claude-haiku-4-5-20251001");
    }

    #[test]
    fn openai_oauth_overrides_path_and_body_with_responses_shape() {
        let a = oauth_addons_for("openai").expect("openai OAuth addons must exist");
        let url = a.url("http://127.0.0.1:27200/openai", "/v1/chat/completions");
        // path_override 取代了默认
        assert!(
            url.ends_with("/responses"),
            "Codex OAuth must use /responses; got: {}",
            url
        );
        // 无 query
        assert!(
            !url.contains('?'),
            "Codex OAuth should not add query params; got: {}",
            url
        );

        // Hermetic: redirect HOME to a temp dir + drop a fake proxy-
        // observed state file there so codex_probe_model() resolves
        // through the highest-priority path. We don't touch the user's
        // real ~/.aikey/state directory.
        let tmp = std::env::temp_dir().join(format!("aikey_probe_test_{}", std::process::id()));
        let state_dir = tmp.join(".aikey/state");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("codex_last_model"), "gpt-probe-fixture\n").unwrap();
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &tmp);
        let body = a.body(serde_json::json!({"unused": "default body should be replaced"}));
        assert_eq!(body["model"], "gpt-probe-fixture");
        // Restore HOME + clean up the temp dir.
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(body["store"], false);
        assert_eq!(body["stream"], true);
        assert!(
            body.get("unused").is_none(),
            "body_override must drop default body"
        );
    }

    #[test]
    fn unknown_provider_returns_none() {
        assert!(
            oauth_addons_for("kimi_code").is_none(),
            "kimi_code OAuth not yet in registry — should return None until explicitly added"
        );
        assert!(oauth_addons_for("gemini").is_none());
        assert!(oauth_addons_for("").is_none());
    }
}
