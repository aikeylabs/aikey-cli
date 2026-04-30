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

    // v4.3 (2026-05-01): 把 provider_routes 整张表透传给 Web UI / proxy。
    // 顺序保留 yaml 声明序 (host 不去重排,因为多 host 行的相对顺序在 yaml
    // 里是设计意图,前端按 host map 查表与顺序无关;但稳定输出对调试更友好)。
    let routes_json = serde_json::to_value(fp.provider_routes())
        .expect("provider_routes serialise");

    json!({
        "layer_versions": {
            "rules":       LAYER_VERSION_RULES,
            "crf":         LAYER_VERSION_CRF,
            "fingerprint": LAYER_VERSION_FINGERPRINT,
        },
        "sample_providers":  SAMPLE_PROVIDERS,
        "family_login_urls": to_sorted_obj(fp.family_login_urls_map()),
        // v4.3: per-host upstream routing table. Each entry:
        //   { host, protocol, provider, base_url, version }
        // 替代旧 family_base_urls + host_to_base_url 两层 + proxy applyBaseURL
        // 的 dedup 算法。前端 / Go fallback / proxy 全部从这一张表取数。
        "provider_routes":   routes_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_payload_exposes_provider_routes() {
        let v = build_rules_payload();
        assert!(v["layer_versions"]["rules"].is_string());
        assert!(v["sample_providers"].is_array());

        let login = &v["family_login_urls"];
        assert_eq!(login["google_gemini"], "https://aistudio.google.com/app/apikey");
        assert_eq!(login["qwen"], "https://dashscope.console.aliyun.com/apiKey");

        // v4.3: provider_routes 表是单一权威源。前端 + proxy 都从这取。
        let routes = v["provider_routes"].as_array().expect("provider_routes array");
        assert!(!routes.is_empty(), "provider_routes must have entries");

        // pin: kimi family 下 api.kimi.com 与 api.moonshot.cn 是两条独立
        // 路由(同 provider=kimi,但 base_url 不同),修 2026-05-01 bug 的关键。
        let kimi_coding = routes.iter()
            .find(|r| r["host"] == "api.kimi.com")
            .expect("api.kimi.com route present");
        assert_eq!(kimi_coding["provider"], "kimi");
        assert_eq!(kimi_coding["base_url"], "https://api.kimi.com/coding");
        assert_eq!(kimi_coding["version"], "/v1");

        let moonshot = routes.iter()
            .find(|r| r["host"] == "api.moonshot.cn")
            .expect("api.moonshot.cn route present");
        assert_eq!(moonshot["provider"], "kimi");      // same family
        assert_eq!(moonshot["base_url"], "https://api.moonshot.cn");  // but different upstream
        assert_eq!(moonshot["version"], "/v1");

        // perplexity: empty version (no /v1 path segment in upstream)
        let perplexity = routes.iter()
            .find(|r| r["host"] == "api.perplexity.ai")
            .expect("api.perplexity.ai route present");
        assert_eq!(perplexity["version"], "");
    }
}
