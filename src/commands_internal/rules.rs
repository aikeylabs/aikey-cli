//! `_internal rules`：把 provider_fingerprint.yaml 里 Web UI 关心的静态数据透传出去。
//!
//! # 出现的原因
//! Go local-server 的 `/api/user/import/rules` 之前是把 YAML 里的 `family_base_urls`
//! / `family_login_urls` 等数据**手抄一份**塞在 Go 源码里，与 CLI 这边 YAML 是两份维护，
//! YAML 一改前端要等 Go service 同步发版才能拿到——典型的偷懒默认。
//!
//! 现在 CLI 出这个子命令把数据吐成 JSON，Go service 改成调它（`Bridge.Invoke("rules", ...)`），
//! YAML 仍是单一事实源，Go 端只剩 spawn-failure 兜底用的 fallback 常量。
//!
//! # 协议
//! - stdin envelope：`vault_key_hex`（占位 64 个 0 即可，本子命令不读 vault）、`action="get"`
//!   或留空、`payload={}` 任意；任何字段都不强校验
//! - stdout envelope.data 形如：
//!   ```json
//!   {
//!     "layer_versions":   { "rules": "...", "crf": "...", "fingerprint": "..." },
//!     "sample_providers": [...],
//!     "family_base_urls": { "anthropic": "https://api.anthropic.com", ... },
//!     "family_login_urls":{ "anthropic": "https://claude.ai/login", ... }
//!   }
//!   ```
//!
//! # 不持有 vault
//! `_internal rules` 是只读、无 vault 访问的纯数据接口。但 IPC 协议要求 envelope 里
//! 必须带 64-char `vault_key_hex`，调用方传 64 个 0 即可（与 `_internal parse` 同款套路）。

use serde_json::{json, Value};

use super::parse::provider_fingerprint;
use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::emit;

/// 当前的 layer 版本号。和 Go 端 fallback 保持一致；改 YAML 不需要动这里。
const LAYER_VERSION_RULES: &str = "2.0-full";
const LAYER_VERSION_CRF: &str = "1.0";
const LAYER_VERSION_FINGERPRINT: &str = "1.0";

/// 静态 sample_providers 列表（前端 Quick Import 提示词用）。
/// 改之前先确认 Go 端 fallback ([handlers.go RulesHandler]) 也同步——
/// 这里和 fallback 是一份语义，但后者是 spawn-fail 兜底所以仍要内嵌一次。
const SAMPLE_PROVIDERS: &[&str] = &[
    "anthropic_api", "openai_project", "openai_admin", "google_gemini",
    "groq", "xai_grok", "github_classic", "github_fine_grained",
    "aws_access_key", "stripe_live", "stripe_restricted", "sendgrid",
    "slack_bot", "slack_user", "huggingface", "perplexity",
    "openrouter", "anthropic_oauth", "generic_jwt", "pem_block",
    "generic_sk", "short_hex_raw", "uuid",
];

pub fn handle(env: StdinEnvelope) {
    // envelope.action 暂时不分支——本子命令只一种行为（dump 全表）。预留 string 以便
    // 将来添加 `family_only` / `versions_only` 等子动作时不破协议。
    let data = build_rules_payload();
    emit(&ResultEnvelope::ok(env.request_id, data));
}

fn build_rules_payload() -> Value {
    let fp = provider_fingerprint::instance();

    // 把 HashMap<String, String> 转成 sorted Map<String, Value>，让 JSON 输出稳定
    // ——避免每次进程启动 family 顺序漂移导致 caller 缓存抖动。
    let to_sorted_obj = |m: &std::collections::HashMap<String, String>| -> Value {
        let mut keys: Vec<&String> = m.keys().collect();
        keys.sort();
        let mut out = serde_json::Map::with_capacity(keys.len());
        for k in keys {
            if let Some(v) = m.get(k) {
                out.insert(k.clone(), Value::String(v.clone()));
            }
        }
        Value::Object(out)
    };

    json!({
        "layer_versions": {
            "rules":       LAYER_VERSION_RULES,
            "crf":         LAYER_VERSION_CRF,
            "fingerprint": LAYER_VERSION_FINGERPRINT,
        },
        "sample_providers": SAMPLE_PROVIDERS,
        "family_base_urls":  to_sorted_obj(fp.family_base_urls_map()),
        "family_login_urls": to_sorted_obj(fp.family_login_urls_map()),
        // v4.2.1 (2026-05-01): per-host base_url 精分流表。前端
        // applyOfficialDefaults Rule 2 在查 family_base_urls 之前先查它。
        // 解决同 family 多 host 各走不同 endpoint 的场景 (kimi.com 编程
        // 模型 vs moonshot.cn 平台)。Go 端 rulesFallback 也得同步加。
        "host_to_base_url":  to_sorted_obj(fp.host_to_base_url_map()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_payload_carries_both_maps() {
        let v = build_rules_payload();
        // shape sanity
        assert!(v["layer_versions"]["rules"].is_string());
        assert!(v["sample_providers"].is_array());

        // both YAML maps reach the wire
        let base = &v["family_base_urls"];
        assert_eq!(base["anthropic"], "https://api.anthropic.com");
        assert_eq!(base["openai"], "https://api.openai.com/v1");

        let login = &v["family_login_urls"];
        // Critical: this is the gap that motivated the whole refactor —
        // user pastes aistudio.google.com / dashscope.console.aliyun.com,
        // Web UI's host-match Rule 2 only fires if these hosts are in the
        // login_urls payload.
        assert_eq!(login["google_gemini"], "https://aistudio.google.com/app/apikey");
        assert_eq!(login["qwen"], "https://dashscope.console.aliyun.com/apiKey");

        // v4.2.1: kimi family 下两个不同 endpoint 都被 host_to_base_url 精分
        // 流到正确 URL。这是修 "web import 把 sk-kimi-* 错误路由到 moonshot
        // 端点" 的根因(2026-05-01 bugfix)。
        let h2b = &v["host_to_base_url"];
        assert_eq!(h2b["api.kimi.com"], "https://api.kimi.com/coding/v1");
        assert_eq!(h2b["api.moonshot.cn"], "https://api.moonshot.cn/v1");
    }

    #[test]
    fn family_base_urls_keys_are_sorted() {
        let v = build_rules_payload();
        let obj = v["family_base_urls"].as_object().expect("object");
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "family_base_urls keys must be sorted for stable wire output");
    }
}
