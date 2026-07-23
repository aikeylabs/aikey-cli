//! H 层 Provider Fingerprint 分类器（Stage 3 Phase 3）
//!
//! # 定位（与 vault_op / crf 严格区分）
//! - **不做抽取**：已抽取的 secret token 才进这里
//! - **不做 gate**：即使判错或 unknown，不影响候选是否出现
//! - **只做软性分类 + 权重**：UI 层用它做 auto-fill provider 下拉 + confidence tier 渲染
//!
//! # Tier 层级
//! - `confirmed`：前缀高特异性（sk-ant-api03 / AKIA / gsk_ / AIza 等 18 条）→ UI 自动填 provider
//! - `ambiguous`：通用前缀（`sk-*` / `{id}.{secret}` 等）→ UI 显示候选 siblings 列表，用户手选；若同文档 URL 匹配 disambiguators 则精确到具体 provider
//! - `warn`：UUID / 短 hex → UI 标警示"看起来不像凭证，请确认"
//!
//! # POC 验证（2026-04-21）
//! - 27 条已标注 secret 样本上直接分类准确率 100%
//!
//! # 运行时
//! - YAML 通过 `include_str!` 编译期嵌入（v1.0 M2 决策；v1.1+ 评估 runtime override + 签名校验）
//! - Registry 用 `OnceLock` 全局单例，首次调用时解析一次（~几百 μs），后续 O(1) 查询

use regex::Regex;
use serde::Deserialize;
use std::sync::OnceLock;

/// 编译期嵌入的 YAML registry
const FINGERPRINT_YAML: &str = include_str!("../../../data/provider_fingerprint.yaml");

// ========== YAML schema ==========

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderEntry {
    pub id: String,
    pub display: String,
    pub regex: String,
    #[serde(default)]
    #[allow(dead_code)] // 供 v1.1+ 长度二次校验用
    pub length_range: Option<[usize; 2]>,
    pub tier: Tier,
    #[serde(default)]
    pub hint: Option<String>,
    /// ambiguous tier 用 URL 域名消歧
    #[serde(default)]
    pub disambiguators: Vec<Disambiguator>,
    /// M3 评审：ambiguous URL 消歧失败时，UI 手选下拉优先展示的候选 provider id
    #[serde(default)]
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Confirmed,
    #[allow(dead_code)] // YAML 保留 `likely` 但当前 registry 未用
    Likely,
    Ambiguous,
    Warn,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Disambiguator {
    pub url_domain: String,
    pub suggest: String,
}

/// v4.3 (2026-05-01): per-host upstream routing entry. See yaml `provider_routes`
/// section for full schema. Replaces former family_base_urls + host_to_base_url
/// + proxy applyBaseURL tail-overlap dedup with a single declarative table.
#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
pub struct ProviderRoute {
    pub host: String,
    pub protocol: String,
    pub provider: String,
    pub base_url: String,
    #[serde(default)]
    pub version: String,
    /// P1b / design D-2b: second half of the row key. A host may carry
    /// multiple rows distinguished by the stored base_url's path prefix
    /// (GLM open.bigmodel.cn has /api/anthropic vs /api/coding/paas/v4
    /// endpoints). `route_for_base_url` does a segment-aligned
    /// longest-prefix match on this field, mirroring Go's Table.Lookup.
    /// Default "" is the host fallback row; with all-empty prefixes lookup
    /// degrades to exact host match, so the pre-P1b 18 rows are unchanged.
    /// skip_serializing_if keeps the rules-endpoint JSON identical to Go's
    /// `omitempty` for cross-language parity (P1c).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_prefix: String,
    /// Explicit canonical endpoint for a Provider+Protocol pair that has
    /// multiple hosts. This keeps fallback routing independent of YAML order.
    #[serde(
        default,
        rename = "default",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_default: bool,
}

/// P1 / design D-2: one model_map rule (client model name → upstream model).
/// `match` is a Rust keyword → renamed. Mirrors Go providerroutes.ModelRule.
#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
pub struct ModelRule {
    #[serde(rename = "match")]
    pub match_: String,
    pub requested_model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub supports_1m: bool,
}

/// P1 / design D-2: a provider's model_map (keyed by provider CODE). Mirrors
/// Go providerroutes.ModelMap.
#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
pub struct ModelMap {
    pub provider: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unmatched: String,
    #[serde(default)]
    pub models: Vec<ModelRule>,
}

#[derive(Debug, Deserialize)]
struct Registry {
    #[allow(dead_code)]
    version: u32,
    providers: Vec<ProviderEntry>,
    /// P1 / design D-2: per-provider-code model name maps. See yaml
    /// `provider_model_maps` section. Parsed for cross-language parity with
    /// Go's providerroutes (the proxy is the primary consumer).
    #[serde(default)]
    provider_model_maps: Vec<ModelMap>,
    /// v4.1 Stage 5+: 聚合网关 family 清单(openrouter / yunwu / zeroeleven 等)
    /// 见 yaml 顶部 `aggregator_families` 段落。
    #[serde(default)]
    aggregator_families: Vec<String>,
    /// v4.1 Stage 10+: family → 官方登录/API Key 页面 URL
    /// UI "Open login page" 按钮消费此字段(window.open)
    #[serde(default)]
    family_login_urls: std::collections::HashMap<String, String>,
    /// v4.3 (2026-05-01): per-host upstream routing table. 替代 v4.2 的
    /// family_base_urls + v4.2.1 的 host_to_base_url + proxy applyBaseURL
    /// 的 dedup 算法。每行声明 host → (protocol, provider, base_url, version),
    /// proxy/CLI/UI 共用单一查表。
    #[serde(default)]
    provider_routes: Vec<ProviderRoute>,
}

// ========== Classifier ==========

pub struct FingerprintClassifier {
    entries: Vec<(ProviderEntry, Regex)>,
    /// v4.1 Stage 5+: 聚合网关 family 集合(从 yaml 加载)
    aggregator_families: std::collections::HashSet<String>,
    /// v4.1 Stage 10+: family → 登录页 URL 映射(从 yaml 加载)
    family_login_urls: std::collections::HashMap<String, String>,
    /// v4.3 (2026-05-01): per-host upstream routing table. Lookup by host
    /// returns the full route declaration (protocol, provider, base_url,
    /// version). 同一 provider 可有多 host 行 (e.g. kimi 下 api.kimi.com 与
    /// api.moonshot.cn 是两行,都 provider=kimi 但 base_url 不同)。
    provider_routes: Vec<ProviderRoute>,
    /// P1 / design D-2: per-provider-code model_map (keyed by provider code).
    provider_model_maps: Vec<ModelMap>,
}

impl FingerprintClassifier {
    /// 加载编译期嵌入的 registry。YAML 格式错误或 regex 非法会 panic —— 这是可接受的
    /// 因为 YAML 是 build-time 资产，运行时再出错意味着构建时遗漏了校验。
    pub fn new_embedded() -> Self {
        let reg: Registry = serde_yaml::from_str(FINGERPRINT_YAML)
            .expect("embedded provider_fingerprint.yaml must be valid");
        let mut entries = Vec::new();
        for p in reg.providers {
            // (?s) 让 . 匹配换行（PEM 形态 regex 需要跨行）
            let compiled = Regex::new(&format!("(?s){}", p.regex))
                .unwrap_or_else(|e| panic!("bad regex for provider '{}': {}", p.id, e));
            entries.push((p, compiled));
        }
        let aggregator_families: std::collections::HashSet<String> =
            reg.aggregator_families.into_iter().collect();
        let family_login_urls = reg.family_login_urls;
        let provider_routes = reg.provider_routes;
        let provider_model_maps = reg.provider_model_maps;
        Self {
            entries,
            aggregator_families,
            family_login_urls,
            provider_routes,
            provider_model_maps,
        }
    }

    /// Test-only: build a classifier from an arbitrary yaml string, mirroring
    /// new_embedded's construction path. Lets resolve-parity hand-vectors use
    /// the SAME yaml as the Go TestResolveModelAnchoredRoles fence.
    #[cfg(test)]
    fn from_yaml_str(yaml: &str) -> Result<Self, String> {
        let reg: Registry = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
        let mut entries = Vec::new();
        for p in reg.providers {
            let compiled = Regex::new(&format!("(?s){}", p.regex)).map_err(|e| e.to_string())?;
            entries.push((p, compiled));
        }
        Ok(Self {
            entries,
            aggregator_families: reg.aggregator_families.into_iter().collect(),
            family_login_urls: reg.family_login_urls,
            provider_routes: reg.provider_routes,
            provider_model_maps: reg.provider_model_maps,
        })
    }

    /// P1 / design D-2: the model_map for a provider code (case-insensitive).
    pub fn model_map_for(&self, provider: &str) -> Option<&ModelMap> {
        self.provider_model_maps
            .iter()
            .find(|m| m.provider.eq_ignore_ascii_case(provider))
    }

    /// P1 / design D-2 & D-3: resolve a client model to the upstream model via
    /// a provider's model_map. Precedence exact → role → wildcard. Returns
    /// (effective_model, matched). Mirrors Go providerroutes.ResolveModel.
    pub fn resolve_model(&self, provider: &str, requested: &str) -> (String, bool) {
        let Some(mm) = self.model_map_for(provider) else {
            return (requested.to_string(), false);
        };
        for r in &mm.models {
            if r.match_ == requested {
                return (r.requested_model.clone(), true);
            }
        }
        if let Some(role) = role_of_model(requested) {
            for r in &mm.models {
                if is_role_token(&r.match_) && r.match_.eq_ignore_ascii_case(&role) {
                    return (r.requested_model.clone(), true);
                }
            }
        }
        for r in &mm.models {
            if r.match_ == "*" {
                return (r.requested_model.clone(), true);
            }
        }
        (requested.to_string(), false)
    }

    /// v4.1 Stage 5+: 从 inferred provider family 派生 protocol_types 列表。
    ///
    /// - family ∈ aggregator_families   → vec![]        (聚合网关,UI multi-select 让用户手选)
    /// - 其他 family (官方厂商)          → vec![family]  (单元素)
    pub fn protocol_types_for_family(&self, family: &str) -> Vec<String> {
        if self.aggregator_families.contains(family) {
            Vec::new()
        } else {
            vec![family.to_string()]
        }
    }

    /// v4.1 Stage 10+: 查 family 的登录页 URL (UI "Open login page" 用)
    pub fn login_url_for_family(&self, family: &str) -> Option<String> {
        self.family_login_urls.get(family).cloned()
    }

    /// v4.3: lookup provider_route by host (exact match, lowercase host expected).
    /// Returns None if host not in table (UI/proxy treats as "third-party gateway,
    /// no auto routing"; user must declare it via a new yaml row).
    pub fn route_for_host(&self, host: &str) -> Option<&ProviderRoute> {
        self.provider_routes
            .iter()
            .find(|r| r.host.eq_ignore_ascii_case(host))
    }

    /// P1b / design D-2b: path-aware route lookup. Extracts host + path from
    /// a stored base_url and does a segment-aligned longest-prefix match on
    /// `path_prefix`, mirroring Go's `Table.Lookup`. This keeps CLI display
    /// (`official_url_for_route`) consistent with proxy execution for
    /// multi-endpoint hosts (GLM's /api/anthropic vs /api/paas). For
    /// single-row hosts it returns the same row as `route_for_host`.
    pub fn route_for_base_url(&self, base_url: &str) -> Option<&ProviderRoute> {
        let host = route_host_of(base_url)?;
        let path = route_path_of(base_url);
        let mut best: Option<&ProviderRoute> = None;
        let mut best_len: i64 = -1;
        for r in &self.provider_routes {
            if r.host.eq_ignore_ascii_case(&host)
                && path_prefix_matches(&r.path_prefix, &path)
                && (r.path_prefix.len() as i64) > best_len
            {
                best_len = r.path_prefix.len() as i64;
                best = Some(r);
            }
        }
        best
    }

    /// Compatibility lookup for callers that know only a Provider. It succeeds
    /// only when the Provider declares one protocol; the exact pair resolver
    /// then requires a unique or explicitly-defaulted endpoint.
    pub fn route_for_provider(&self, provider: &str) -> Option<&ProviderRoute> {
        let protocols = self.protocols_for_provider(provider);
        (protocols.len() == 1)
            .then(|| self.route_for_provider_protocol(provider, &protocols[0]))
            .flatten()
    }

    /// Exact Provider+Protocol lookup. This is the only safe provider-level
    /// lookup for multi-protocol suppliers such as Mock Provider.
    pub fn route_for_provider_protocol(
        &self,
        provider: &str,
        protocol: &str,
    ) -> Option<&ProviderRoute> {
        let matches = self
            .provider_routes
            .iter()
            .filter(|r| {
                r.provider.eq_ignore_ascii_case(provider)
                    && r.protocol.eq_ignore_ascii_case(protocol)
            })
            .collect::<Vec<_>>();
        let defaults = matches
            .iter()
            .copied()
            .filter(|r| r.is_default)
            .collect::<Vec<_>>();
        match defaults.as_slice() {
            [route] => return Some(*route),
            [] => {}
            _ => return None,
        }
        match matches.as_slice() {
            [route] => Some(*route),
            _ => {
                let catchalls = matches
                    .iter()
                    .copied()
                    .filter(|r| r.path_prefix.is_empty())
                    .collect::<Vec<_>>();
                match catchalls.as_slice() {
                    [route] => Some(*route),
                    _ => None,
                }
            }
        }
    }

    /// Distinct protocols declared for a Provider, in YAML order.
    pub fn protocols_for_provider(&self, provider: &str) -> Vec<String> {
        let mut out = Vec::new();
        for route in &self.provider_routes {
            if route.provider.eq_ignore_ascii_case(provider)
                && !out
                    .iter()
                    .any(|p: &String| p.eq_ignore_ascii_case(&route.protocol))
            {
                out.push(route.protocol.clone());
            }
        }
        out
    }

    /// v4.3: full official URL = base_url + version (with empty-version edge case).
    /// 这是用户在 UI 上看到 / 期望粘贴的 endpoint URL。
    pub fn official_url_for_route(route: &ProviderRoute) -> String {
        if route.version.is_empty() {
            route.base_url.clone()
        } else {
            format!("{}{}", route.base_url, route.version)
        }
    }

    /// 整张 provider_routes 列表 (供 `_internal rules` 透传给 Web UI / proxy 编译期 embed)
    pub fn provider_routes(&self) -> &[ProviderRoute] {
        &self.provider_routes
    }

    /// P1 / design D-2: whole provider_model_maps list (cross-language parity).
    pub fn provider_model_maps(&self) -> &[ModelMap] {
        &self.provider_model_maps
    }

    /// 全量 family → 登录页 URL 映射 (用于 `_internal rules` 把整张表透出给 Web UI)
    pub fn family_login_urls_map(&self) -> &std::collections::HashMap<String, String> {
        &self.family_login_urls
    }

    /// 直接分类（不用上下文）
    pub fn classify(&self, token: &str) -> Option<&ProviderEntry> {
        // 按 YAML 中顺序匹配：YAML 里更具体的 pattern 放前面，第一个 match 赢
        // 例如 `sk-ant-api03` 必须放在 `sk-*` 通用之前
        for (entry, re) in &self.entries {
            if re.is_match(token) {
                return Some(entry);
            }
        }
        None
    }

    /// 分类 + URL 消歧：ambiguous tier 会尝试用 url_domains 提升精度
    ///
    /// 返回 (匹配到的 provider entry, 消歧建议的更精确 provider id)
    /// - 非 ambiguous：suggestion = None
    /// - ambiguous + URL 匹配某 disambiguator：suggestion = Some(<suggest id>)
    /// - ambiguous + URL 不匹配：suggestion = None（UI 回退到 siblings 列表）
    pub fn classify_with_context<'a>(
        &'a self,
        token: &str,
        url_domains: &[String],
    ) -> (Option<&'a ProviderEntry>, Option<String>) {
        let matched = self.classify(token);
        let Some(entry) = matched else {
            return (None, None);
        };
        if entry.tier != Tier::Ambiguous {
            return (Some(entry), None);
        }
        for d in &entry.disambiguators {
            if url_domains.iter().any(|u| u.contains(&d.url_domain)) {
                return (Some(entry), Some(d.suggest.clone()));
            }
        }
        (Some(entry), None)
    }
}

/// 全局单例（首次调用解析一次 YAML，后续 O(1) 查询）
pub fn instance() -> &'static FingerprintClassifier {
    static INSTANCE: OnceLock<FingerprintClassifier> = OnceLock::new();
    INSTANCE.get_or_init(FingerprintClassifier::new_embedded)
}

/// The ONE protocol-axis resolver. Every surface that prints a PROTOCOL column
/// must call this so they cannot disagree about the same key.
///
/// Resolution order, most authoritative first:
///   1. the route row owning `base_url` — endpoint truth, same source as the
///      vault two-axis read model;
///   2. `declared` — what the record itself says (team keys cache
///      `protocol_type` alongside their base_url);
///   3. the provider's own first route row — heuristic for multi-host
///      providers, but still a PROTOCOL.
///
/// Returns empty when nothing resolves. 🚫 Never fall back to a provider
/// family/code here: this column is the protocol axis, and a provider name in
/// it is the exact two-axis conflation this work exists to kill.
///
/// Why it exists: `aikey list` grew steps 1-3 while `aikey use` had only 1-2
/// and then fell back to `provider_registry::family_of()`. For any key without
/// a stored base_url — every key created by `aikey add --provider x` with no
/// `--base-url` — `use` printed `zhipu` / `openai` (provider families) where
/// `list` printed `openai_compatible`. Same key, two commands, two answers, and
/// one of them naming the wrong axis.
pub fn protocol_for(base_url: &str, provider: &str, declared: &str) -> String {
    let c = instance();
    c.route_for_base_url(base_url)
        .map(|r| r.protocol.clone())
        .filter(|p| !p.is_empty())
        .or_else(|| (!declared.is_empty()).then(|| declared.to_string()))
        .or_else(|| {
            c.route_for_provider(provider)
                .map(|r| r.protocol.clone())
                .filter(|p| !p.is_empty())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod protocol_axis_tests {
    use super::protocol_for;

    #[test]
    fn base_url_wins_over_declared() {
        // anthropic's official endpoint speaks the anthropic protocol even if a
        // stale record declares otherwise
        let p = protocol_for(
            "https://api.anthropic.com",
            "anthropic",
            "openai_compatible",
        );
        assert_eq!(p, "anthropic");
    }

    #[test]
    fn declared_is_used_when_base_url_is_unknown() {
        let p = protocol_for("https://gateway.invalid/v1", "zhipu", "anthropic");
        assert_eq!(p, "anthropic");
    }

    /// The regression: no base_url, nothing declared. `aikey use` used to print
    /// the provider family here (`zhipu`, `openai`) — a PROVIDER in the
    /// PROTOCOL column, and a disagreement with `aikey list`.
    #[test]
    fn falls_back_to_the_providers_route_protocol_never_to_a_provider_name() {
        for (provider, expected) in [("openai", "openai_compatible"), ("anthropic", "anthropic")] {
            let p = protocol_for("", provider, "");
            assert_eq!(p, expected, "provider {provider} resolved to {p}");
        }
        // `anthropic` above is a protocol that happens to share its provider's
        // name, so it can't witness the bug. `openai` can: the provider family
        // is `openai`, the protocol is `openai_compatible`, and printing the
        // former under a PROTOCOL header is exactly what regressed.
        assert_ne!(protocol_for("", "openai", ""), "openai");
        assert_ne!(protocol_for("", "zhipu", ""), "zhipu");
    }

    #[test]
    fn unknown_provider_resolves_to_empty_rather_than_its_own_name() {
        let p = protocol_for("", "totally-unknown-provider", "");
        assert!(p.is_empty(), "expected empty, got {p}");
    }
}

// ─── v4.1 Stage 3 L3 enrich 扩展 ────────────────────────────────────────
//
// V4.1 spike 在 YAML 里为每个 provider 增加了 `provider_family` /
// `provider_label_keywords` / `shell_var_patterns` / `url_host_patterns` 字段。
// CLI 为最小改动,用硬编码映射表达同样信息,保持 YAML schema 向后兼容。
//
// family 是 provider 的"家族"(比如 anthropic_api / anthropic_oauth 都属 family=anthropic),
// 下游 enrich 5 证据投票时按 family 累加权重。

/// provider_id → family 映射 (V4.1 spike YAML provider_family 等价)
pub fn provider_family_of(id: &str) -> Option<&'static str> {
    match id {
        "anthropic_api" | "anthropic_oauth" => Some("anthropic"),
        "openai_project" | "openai_admin" | "openai_svcacct" => Some("openai"),
        "openrouter" => Some("openrouter"),
        "google_gemini" => Some("google_gemini"),
        "groq" => Some("groq"),
        "xai_grok" => Some("xai_grok"),
        "github_classic" | "github_fine_grained" => Some("github"),
        "aws_access_key" => Some("aws"),
        "stripe_live" | "stripe_restricted" => Some("stripe"),
        "sendgrid" => Some("sendgrid"),
        "slack_bot" | "slack_user" => Some("slack"),
        "huggingface" => Some("huggingface"),
        "perplexity" => Some("perplexity"),
        "generic_jwt" => Some("generic_jwt"),
        "pem_block" => Some("pem_block"),
        "zhipu_glm" => Some("zhipu"),
        // 2026-05-08 Kimi 双平台拆分: kimi_code 是 confirmed-tier id,family 也叫
        // 'kimi_code' (而非笼统的 'kimi') —— enrich 阶段把 sk-kimi-* 的 E1
        // fingerprint 证据按 'kimi_code' 评分;若改为 'kimi' family 会与
        // generic_sk URL host 推断 ('moonshot') 在同一个 family bucket 里互相
        // 冲销得分。
        "kimi_code" => Some("kimi_code"),
        // ambiguous / warn 档不参与 family 归属 (evidence 不采纳)
        _ => None,
    }
}

/// 文本关键词 → family (E2 InlineTitleKeyword + E3 SectionHeadingKeyword 用)
///
/// 返回 (family, matched_keyword)。与 V4.1 spike
/// `registry.text_keyword_family_and_keyword(text)` 行为一致:
/// case-insensitive substring 匹配,返回首匹配。
pub fn text_keyword_family_and_keyword(text: &str) -> Option<(String, String)> {
    let lc = text.to_lowercase();
    // 按 family 粒度声明 (不一定每个都有),匹配优先级:长 → 短,特异 → 通用
    // BUG-05 fix: 补齐聚合网关 / 次级官方 family (yunwu / zeroeleven / mistral),
    // 让行首 label "🔑 yunwu:" 经 E6 InlineLabelKeyword 通路推断到正确 family。
    // 与 spike `provider_fingerprint.yaml::keyword_to_family` 保持一致。
    const MAP: &[(&str, &str)] = &[
        ("anthropic", "anthropic"),
        ("claude", "anthropic"),
        ("openrouter", "openrouter"),
        ("openai", "openai"),
        ("gpt-4o", "openai"),
        ("gpt4o", "openai"),
        ("gpt-4", "openai"),
        ("gemini", "google_gemini"),
        ("google ai", "google_gemini"),
        // v4.1 family rename: kimi/moonshot → "kimi" (与 connectivity/runtime PROVIDER_DEFAULTS 字典对齐;
        // 旧 family 名 "moonshot_kimi" 与 CLI 其他地方一律叫 "kimi" 不一致,UI Provider 字段直接消费此值)
        // 2026-05-08 Kimi 双平台拆分: provider_code 'kimi' 拆为 'moonshot' + 'kimi_code'。
        //   - keyword "moonshot" → moonshot (精确品牌)
        //   - keyword "kimi" 单字 → moonshot (用户决策 #4: 两个平台都叫 Kimi,默认归 moonshot;
        //     URL 强证据 api.kimi.com / www.kimi.com 走 url_host_family_and_pattern 下钻 kimi_code)
        ("moonshot", "moonshot"),
        ("kimi", "moonshot"),
        ("groq", "groq"),
        ("deepseek", "deepseek"),
        ("mistral", "mistral"),
        ("yunwu", "yunwu"),
        ("zeroeleven", "zeroeleven"),
        ("0011", "zeroeleven"),
        ("xai", "xai_grok"),
        ("grok", "xai_grok"),
        ("zhipu", "zhipu"),
        ("glm", "zhipu"),
        ("\u{8C46}\u{5305}", "doubao"), // 豆包
        ("doubao", "doubao"),
        ("volces", "doubao"),
        ("silicon", "siliconflow"),
        ("\u{7845}\u{57FA}", "siliconflow"), // 硅基
        ("huggingface", "huggingface"),
        ("perplexity", "perplexity"),
        ("sendgrid", "sendgrid"),
        ("stripe", "stripe"),
        ("slack", "slack"),
        ("github", "github"),
        ("aws", "aws"),
    ];
    for (kw, family) in MAP {
        if lc.contains(kw) {
            return Some((family.to_string(), kw.to_string()));
        }
    }
    None
}

/// shell var 名 → family (E4 ShellVarPattern)
///
/// 如 `OPENAI_API_KEY` → family="openai" / pattern="OPENAI_*"
pub fn shell_var_family_and_pattern(var_name: &str) -> Option<(String, String)> {
    let uc = var_name.to_uppercase();
    const MAP: &[(&str, &str, &str)] = &[
        ("ANTHROPIC", "anthropic", "ANTHROPIC_*"),
        ("CLAUDE", "anthropic", "CLAUDE_*"),
        ("OPENAI", "openai", "OPENAI_*"),
        ("OPENROUTER", "openrouter", "OPENROUTER_*"),
        ("GEMINI", "google_gemini", "GEMINI_*"),
        ("GOOGLE_AI", "google_gemini", "GOOGLE_AI_*"),
        // 2026-05-08 Kimi 双平台拆分: MOONSHOT_* / KIMI_* 都映射到 moonshot。
        //
        // 这不只是"按 #4 默认"——而是当前调用链路里**唯一逻辑自洽**的答案。论证:
        //   1. 决策 #3 已确认所有 Kimi Code 的 KEY 都以稳定的 'sk-kimi-' 前缀开头。
        //   2. providers 列表里 'kimi_code' (confirmed tier) 排在 'generic_sk' (ambiguous)
        //      之前,first-match-wins 保证 sk-kimi-* 的 key 在 regex 直接命中阶段就拿到
        //      id=kimi_code,**不会走到 env var 推断 (E4 ShellVarPattern) 这一层**。
        //   3. 反推:本函数被调用时,key 一定不是 sk-kimi-* 形态,即一定不是 Kimi Code。
        //   4. KIMI_*/MOONSHOT_* env var 又把 key 锁定在 Kimi family 内 → 唯一可能是 Moonshot。
        //
        // 维护警告:future 若想把 'KIMI' 改回归 'kimi'(family) 或 'kimi_code',必须先验
        // 证 #1-#2 前提是否仍成立(Kimi Code 是否还坚持稳定前缀 / kimi_code 规则是否
        // 还在 generic_sk 之前)。否则会引入"KIMI_API_KEY=非kimi-code形态 → 误判 kimi_code"
        // 的回归 bug。decision #4 的命名歧义解释见 text_keyword_family_and_keyword。
        ("MOONSHOT", "moonshot", "MOONSHOT_*"),
        ("KIMI", "moonshot", "KIMI_*"),
        ("GROQ", "groq", "GROQ_*"),
        ("DEEPSEEK", "deepseek", "DEEPSEEK_*"),
        ("MISTRAL", "mistral", "MISTRAL_*"),
        ("YUNWU", "yunwu", "YUNWU_*"),
        ("XAI", "xai_grok", "XAI_*"),
        ("HUGGINGFACE", "huggingface", "HUGGINGFACE_*"),
        ("HF_TOKEN", "huggingface", "HF_TOKEN"),
        ("PERPLEXITY", "perplexity", "PERPLEXITY_*"),
        ("SENDGRID", "sendgrid", "SENDGRID_*"),
        ("STRIPE", "stripe", "STRIPE_*"),
        ("SLACK", "slack", "SLACK_*"),
        ("GITHUB", "github", "GITHUB_*"),
        ("AWS_ACCESS", "aws", "AWS_ACCESS_*"),
    ];
    for (prefix, family, pattern) in MAP {
        if uc.starts_with(prefix) {
            return Some((family.to_string(), pattern.to_string()));
        }
    }
    None
}

/// P1b / design D-2b: lowercase host of a base_url ("" scheme tolerant).
fn route_host_of(url: &str) -> Option<String> {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let end = after.find(['/', '?', '#', ':']).unwrap_or(after.len());
    let host = &after[..end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// P1b / design D-2b: path component of a base_url (leading '/', no query).
fn route_path_of(url: &str) -> String {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    match after.find('/') {
        Some(i) => {
            let rest = &after[i..];
            let end = rest.find(['?', '#']).unwrap_or(rest.len());
            rest[..end].to_string()
        }
        None => String::new(),
    }
}

/// P1b / design D-2b: segment-aligned prefix match, mirror of Go's
/// `pathPrefixMatches`. "/api/anthropic" matches "/api/anthropic" and
/// "/api/anthropic/v1" but NOT "/api/anthropicfoo". "" is the fallback.
fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if path == prefix {
        return true;
    }
    path.starts_with(&format!("{prefix}/"))
}

/// P1 / design D-3: known role families a model_map `match` may name, in a
/// FIXED iteration order (mirror of Go rolesInMatchOrder). The order is
/// load-bearing: when two role tokens co-occur in one id (e.g.
/// "claude-opus-haiku-1"), role_of_model returns the first match in THIS order.
/// An array iterates deterministically, matching Go's ordered slice.
const KNOWN_ROLES: [&str; 4] = ["opus", "sonnet", "haiku", "fable"];

fn is_role_token(s: &str) -> bool {
    KNOWN_ROLES.iter().any(|r| r.eq_ignore_ascii_case(s))
}

/// Extract the role family from a claude-style model id ("claude-opus-4-8" →
/// "opus"). Mirrors Go roleOfModel.
///
/// Segment-aligned ONLY — the role must be a whole "-"-delimited token: exact,
/// prefix ("opus-…"), suffix ("…-opus"), or infix ("…-opus-…"). A loose
/// `contains("-{role}")` fallback used to live here; it made the anchored arms
/// dead code and mis-classified ids like "claude-haikuish-1" as haiku. Removed
/// — it feeds resolve_model → wrong upstream model otherwise.
///
/// Case-folding parity: Rust to_ascii_lowercase and Go strings.ToLower (Unicode)
/// agree on the claude-id charset (ASCII a–z / 0–9 / '-'). They diverge only on
/// non-ASCII code points, none of which appear in a claude model id — no
/// residual behavioral difference on real ids.
fn role_of_model(model: &str) -> Option<String> {
    let lower = model.to_ascii_lowercase();
    for role in KNOWN_ROLES {
        if lower == role
            || lower.starts_with(&format!("{role}-"))
            || lower.ends_with(&format!("-{role}"))
            || lower.contains(&format!("-{role}-"))
        {
            return Some(role.to_string());
        }
    }
    None
}

/// URL host → family (E5 UrlHostPattern)
///
/// 从 URL 抽 host,匹配 substring → 返回 (family, matched_pattern)
pub fn url_host_family_and_pattern(url: &str) -> Option<(String, String)> {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_lc = host
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    if host_lc.is_empty() {
        return None;
    }
    const MAP: &[(&str, &str)] = &[
        ("anthropic.com", "anthropic"),
        ("claude.com", "anthropic"),
        ("claude.ai", "anthropic"),
        ("openai.com", "openai"),
        ("openrouter.ai", "openrouter"),
        ("generativelanguage.googleapis.com", "google_gemini"),
        ("aistudio.google.com", "google_gemini"),
        // 2026-05-08 Kimi 双平台拆分: URL host 强证据下钻到具体 provider_code
        //   - moonshot.cn / moonshot.ai → moonshot
        //   - kimi.com (api.kimi.com / www.kimi.com) → kimi_code (Kimi Code 平台)
        ("moonshot.cn", "moonshot"),
        ("moonshot.ai", "moonshot"),
        ("kimi.com", "kimi_code"),
        ("groq.com", "groq"),
        ("deepseek.com", "deepseek"),
        ("mistral.ai", "mistral"),
        ("yunwu.ai", "yunwu"),
        ("0011.ai", "zeroeleven"),
        ("x.ai", "xai_grok"),
        ("huggingface.co", "huggingface"),
        ("perplexity.ai", "perplexity"),
        ("sendgrid.com", "sendgrid"),
        ("stripe.com", "stripe"),
        ("slack.com", "slack"),
        ("github.com", "github"),
        ("amazonaws.com", "aws"),
        ("bigmodel.cn", "zhipu"),
        ("volces.com", "doubao"),
        ("siliconflow.cn", "siliconflow"),
    ];
    for (needle, family) in MAP {
        if host_lc.contains(needle) {
            return Some((family.to_string(), (*needle).to_string()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_yaml_loads() {
        let c = FingerprintClassifier::new_embedded();
        // Registry 至少 22 条（参考 POC 基线）
        assert!(c.entries.len() >= 20, "registry size: {}", c.entries.len());
    }

    // --- P1b / design D-2b: (host, path_prefix) longest-prefix lookup ---

    #[test]
    fn path_prefix_matches_segment_aligned() {
        assert!(path_prefix_matches("", "/anything"));
        assert!(path_prefix_matches("/api/anthropic", "/api/anthropic"));
        assert!(path_prefix_matches("/api/anthropic", "/api/anthropic/v1"));
        // segment alignment: must NOT swallow
        assert!(!path_prefix_matches("/api/anthropic", "/api/anthropicfoo"));
        assert!(!path_prefix_matches("/api/anth", "/api/anthropic"));
    }

    #[test]
    fn route_host_and_path_extraction() {
        assert_eq!(
            route_host_of("https://open.bigmodel.cn/api/anthropic").as_deref(),
            Some("open.bigmodel.cn")
        );
        assert_eq!(
            route_path_of("https://open.bigmodel.cn/api/anthropic"),
            "/api/anthropic"
        );
        assert_eq!(route_path_of("https://open.bigmodel.cn"), "");
        assert_eq!(
            route_path_of("https://open.bigmodel.cn/api/paas?x=1"),
            "/api/paas"
        );
    }

    #[test]
    fn route_for_base_url_selects_glm_endpoint() {
        let c = instance();
        // anthropic endpoint → anthropic row
        let r = c
            .route_for_base_url("https://open.bigmodel.cn/api/anthropic")
            .expect("anthropic row");
        assert_eq!(r.protocol, "anthropic");
        assert_eq!(r.base_url, "https://open.bigmodel.cn/api/anthropic");
        // coding endpoint → openai row
        let r2 = c
            .route_for_base_url("https://open.bigmodel.cn/api/coding/paas/v4")
            .expect("coding row");
        assert_eq!(r2.protocol, "openai_compatible");
        // bare host → "" fallback (paas)
        let r3 = c
            .route_for_base_url("https://open.bigmodel.cn")
            .expect("fallback row");
        assert_eq!(r3.base_url, "https://open.bigmodel.cn/api/paas");
    }

    // P1c (design D-9): Rust half of the cross-language golden-fixture parity.
    // Deserializes the SAME golden file the Go test uses (pkg/providerroutes/
    // testdata/registry_golden.json) with Rust structs and asserts the Rust
    // parse of the embedded yaml matches it. If serde and Go's yaml.v3 diverge,
    // one side fails against the shared golden. Path is relative to the crate
    // root (cargo test CWD) in the monorepo workspace.
    #[test]
    fn golden_fixture_parity_rust() {
        #[derive(serde::Deserialize)]
        struct Golden {
            provider_routes: Vec<ProviderRoute>,
            provider_model_maps: Vec<ModelMap>,
        }
        let path = "../pkg/providerroutes/testdata/registry_golden.json";
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("read golden {path}: {e} (monorepo workspace required)"));
        let golden: Golden = serde_json::from_slice(&bytes).expect("parse golden json");
        // 防空断言
        assert!(
            !golden.provider_routes.is_empty(),
            "golden has zero routes — anti-empty assertion"
        );

        let c = instance();
        assert_eq!(
            c.provider_routes(),
            golden.provider_routes.as_slice(),
            "Rust provider_routes parse != golden (regenerate golden + mirror in Go)"
        );
        assert_eq!(
            c.provider_model_maps(),
            golden.provider_model_maps.as_slice(),
            "Rust provider_model_maps parse != golden"
        );
    }

    #[test]
    fn provider_protocol_default_is_explicit_and_multi_protocol_provider_is_not_collapsed() {
        let c = instance();
        let kimi = c
            .route_for_provider_protocol("kimi_code", "openai_compatible")
            .expect("kimi_code explicit default");
        assert_eq!(kimi.host, "api.kimi.com");
        assert!(kimi.is_default);

        assert!(c.route_for_provider("mock").is_none());
        assert_eq!(
            c.route_for_provider_protocol("mock", "anthropic")
                .expect("mock anthropic")
                .protocol,
            "anthropic"
        );
        assert_eq!(
            c.route_for_provider_protocol("mock", "openai_compatible")
                .expect("mock openai")
                .protocol,
            "openai_compatible"
        );
    }

    #[test]
    fn model_map_resolve_zhipu_embedded() {
        // P1 / design D-2/D-3: embedded zhipu map resolves opus family + exact.
        let c = instance();
        assert_eq!(
            c.resolve_model("zhipu", "claude-opus-4-8"),
            ("glm-4.6".to_string(), true)
        );
        // role opus (升版本不失效)
        assert_eq!(
            c.resolve_model("zhipu", "claude-opus-4-9"),
            ("glm-4.6".to_string(), true)
        );
        assert_eq!(
            c.resolve_model("zhipu", "claude-sonnet-4-6"),
            ("glm-4.5".to_string(), true)
        );
        // provider without a map → passthrough, unmatched
        let (m, matched) = c.resolve_model("openai", "gpt-4o");
        assert!(!matched);
        assert_eq!(m, "gpt-4o");
    }

    // Unit-level resolve-parity fence for the role extractor. Mirror of the Go
    // `TestRoleOfModelAnchored` test — the two must agree token-for-token.
    // Covers every anchored position, ASCII case-folding, deterministic
    // co-occurrence, and the NEGATIVE the old loose contains() missed.
    #[test]
    fn role_of_model_anchored() {
        assert_eq!(role_of_model("claude-opus-4-8").as_deref(), Some("opus")); // infix
        assert_eq!(role_of_model("opus-4").as_deref(), Some("opus")); // prefix
        assert_eq!(role_of_model("claude-4-haiku").as_deref(), Some("haiku")); // suffix
        assert_eq!(role_of_model("sonnet").as_deref(), Some("sonnet")); // exact
        assert_eq!(role_of_model("CLAUDE-OPUS-4-8").as_deref(), Some("opus")); // case-fold
                                                                               // co-occurrence → first in KNOWN_ROLES order (deterministic)
        assert_eq!(
            role_of_model("claude-opus-haiku-1").as_deref(),
            Some("opus")
        );
        assert_eq!(role_of_model("gpt-4o"), None); // no role token
                                                   // NEGATIVE: the removed loose contains("-haiku") would have mis-matched.
        assert_eq!(role_of_model("claude-haikuish-1"), None);
    }

    // Resolve-level (not just parse-level) parity fence. Hand-vectors mirror the
    // Go `TestResolveModelAnchoredRoles` fence 1:1 against the SAME yaml. Shared
    // golden of (provider,requested)->(effective,matched,policy) deferred as a
    // follow-up: resolve_model returns (effective, matched) without policy, so a
    // policy-carrying golden would need a wider signature (out of scope here).
    #[test]
    fn resolve_model_anchored_roles() {
        let yaml = r#"
version: 1
providers: []
provider_model_maps:
  - provider: zhipu
    unmatched: reject
    models:
      - { match: "opus",   requested_model: "glm-4.6" }
      - { match: "sonnet", requested_model: "glm-4.5" }
      - { match: "haiku",  requested_model: "glm-4.5-air" }
      - { match: "fable",  requested_model: "glm-4-flash" }
      - { match: "claude-opus-4-8", requested_model: "glm-4.6-pinned" }
"#;
        let c = FingerprintClassifier::from_yaml_str(yaml).expect("parse test yaml");
        let want = |s: &str, m: bool| (s.to_string(), m);
        assert_eq!(
            c.resolve_model("zhipu", "claude-opus-4-8"),
            want("glm-4.6-pinned", true)
        ); // exact beats role
        assert_eq!(
            c.resolve_model("zhipu", "claude-opus-4-9"),
            want("glm-4.6", true)
        ); // infix
        assert_eq!(
            c.resolve_model("zhipu", "haiku-4-5"),
            want("glm-4.5-air", true)
        ); // prefix
        assert_eq!(
            c.resolve_model("zhipu", "claude-4-fable"),
            want("glm-4-flash", true)
        ); // suffix
        assert_eq!(c.resolve_model("zhipu", "sonnet"), want("glm-4.5", true)); // exact token
        assert_eq!(
            c.resolve_model("zhipu", "claude-opus-haiku-1"),
            want("glm-4.6", true)
        ); // co-occurrence → opus
           // NEGATIVE: no wildcard + anchored role → genuine miss.
        assert_eq!(
            c.resolve_model("zhipu", "claude-haikuish-1"),
            want("claude-haikuish-1", false)
        );
    }

    #[test]
    fn route_for_base_url_backward_compat_single_row_hosts() {
        // Fence (task 1b.4): a pre-P1b single-row host resolves identically
        // for any path — extended key degrades to exact host match.
        let c = instance();
        let by_host = c.route_for_host("api.anthropic.com").expect("host row");
        for p in ["", "/v1/messages", "/deep/path"] {
            let url = format!("https://api.anthropic.com{p}");
            let r = c.route_for_base_url(&url).expect("must resolve");
            assert_eq!(r.provider, by_host.provider, "url={url}");
            assert_eq!(r.base_url, by_host.base_url, "url={url}");
        }
    }

    #[test]
    fn classify_anthropic_api_key() {
        let c = instance();
        let tok = "sk-ant-api03-FakeKey_12345678_abcdefghijklmnopqrstuvwxyz_ABCDEFGH";
        let e = c.classify(tok).expect("should classify");
        assert_eq!(e.id, "anthropic_api");
        assert_eq!(e.tier, Tier::Confirmed);
    }

    #[test]
    fn classify_openai_project() {
        let c = instance();
        let tok = "sk-proj-FakeKey_abcdef_0123456789_GhijklMNOPQRSTU_VwxyZ_abcDEFg123";
        let e = c.classify(tok).expect("should classify");
        assert_eq!(e.id, "openai_project");
    }

    #[test]
    fn classify_aws_access_key() {
        let c = instance();
        let e = c.classify("AKIAIOSFODNN7EXAMPLE").expect("AWS fmt");
        assert_eq!(e.id, "aws_access_key");
    }

    #[test]
    fn classify_generic_sk_ambiguous() {
        let c = instance();
        let tok = "sk-genericABC123DEF456ghi789jkl012mno345pqr678STU";
        let e = c.classify(tok).expect("sk-generic");
        assert_eq!(e.tier, Tier::Ambiguous);
        // siblings 至少含 kimi / deepseek 等（M3 评审要求）
        assert!(!e.siblings.is_empty(), "generic_sk must have siblings");
    }

    #[test]
    fn classify_with_context_disambiguates_moonshot() {
        let c = instance();
        let tok = "sk-cafebabedeadbeef0123456789abcdef0123456789abcdef";
        let urls = vec!["platform.moonshot.cn".to_string()];
        let (entry, suggest) = c.classify_with_context(tok, &urls);
        let entry = entry.expect("should classify");
        // ambiguous tier 的 disambiguator 命中 → suggest 非空
        if entry.tier == Tier::Ambiguous {
            assert!(suggest.is_some(), "url context should disambiguate");
        }
    }

    #[test]
    fn classify_uuid_is_warn() {
        let c = instance();
        let e = c
            .classify("550e8400-e29b-41d4-a716-446655440000")
            .expect("uuid");
        assert_eq!(e.id, "uuid");
        assert_eq!(e.tier, Tier::Warn);
    }

    #[test]
    fn classify_unknown_returns_none() {
        let c = instance();
        let e = c.classify("completely_random_nothing_matches_12345");
        assert!(e.is_none());
    }

    #[test]
    fn classify_pem_block() {
        let c = instance();
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC\n-----END OPENSSH PRIVATE KEY-----";
        let e = c.classify(pem).expect("pem");
        assert_eq!(e.id, "pem_block");
    }

    // ── 2026-05-08 Kimi 双平台拆分回归断言 ────────────────────────────────────

    /// sk-kimi-* 前缀必须命中 confirmed-tier `kimi_code` (排在 `generic_sk` 之前)。
    /// 防退化:若 YAML 顺序被改回 generic_sk 在前,sk-kimi-* 会落 ambiguous,
    /// E2E case 1 + import flow 受影响。
    #[test]
    fn classify_sk_kimi_prefix_to_kimi_code_confirmed() {
        let c = instance();
        let tok = "sk-kimi-FakeKey_abcdefg1234567890sampleTokenZZZZZZZZ";
        let e = c.classify(tok).expect("sk-kimi-*");
        assert_eq!(e.id, "kimi_code");
        assert_eq!(e.tier, Tier::Confirmed);
    }

    /// `provider_family_of("kimi_code")` 必须返回 `Some("kimi_code")`,否则
    /// E1 fingerprint 证据(评审反馈 [高] #2)在 enrich 时会被丢弃,
    /// 用户粘 sk-kimi-* 不带 URL 时无法推断 kimi_code。
    #[test]
    fn provider_family_of_kimi_code_resolves() {
        assert_eq!(provider_family_of("kimi_code"), Some("kimi_code"));
        // 防退化:不能改回笼统的 'kimi' family,会与 generic_sk URL host
        // 推断 ('moonshot') 在同一 family bucket 内互相冲销
        assert_ne!(provider_family_of("kimi_code"), Some("kimi"));
    }

    /// keyword "kimi" 单字 (无 URL / 无前缀) 默认归 'moonshot' (决策 #4)。
    /// keyword "moonshot" 显式归 'moonshot'。
    #[test]
    fn keyword_to_family_kimi_defaults_moonshot_per_decision_4() {
        let (fam, _) = text_keyword_family_and_keyword("kimi 备份号").expect("kimi keyword");
        assert_eq!(fam, "moonshot");
        let (fam, _) = text_keyword_family_and_keyword("moonshot dev").expect("moonshot keyword");
        assert_eq!(fam, "moonshot");
    }

    /// URL host `api.kimi.com` / `www.kimi.com` 强证据下钻到 `kimi_code`,
    /// `moonshot.cn` / `moonshot.ai` 下钻到 `moonshot`。
    #[test]
    fn url_host_kimi_com_routes_to_kimi_code() {
        let (fam, _) =
            url_host_family_and_pattern("https://api.kimi.com/coding/v1").expect("kimi url");
        assert_eq!(fam, "kimi_code");
        let (fam, _) =
            url_host_family_and_pattern("https://www.kimi.com/code/console").expect("kimi.com url");
        assert_eq!(fam, "kimi_code");
        let (fam, _) = url_host_family_and_pattern("https://platform.moonshot.cn/console")
            .expect("moonshot url");
        assert_eq!(fam, "moonshot");
    }

    /// 2026-05-08 第三方评审第七轮反馈 [中]#3:补 api.moonshot.cn 直接断言。
    /// 之前测了 platform.moonshot.cn,但 api.moonshot.cn 是上游官方推荐 host
    /// (provider_routes 里也是这条),helper 层显式锁定。
    #[test]
    fn url_host_api_moonshot_cn_routes_to_moonshot() {
        let (fam, _) = url_host_family_and_pattern("https://api.moonshot.cn/v1")
            .expect("api.moonshot.cn host should match");
        assert_eq!(
            fam, "moonshot",
            "api.moonshot.cn 必须 family-resolve 到 moonshot,不能误归 kimi_code"
        );
        // .ai 别名一并锁定
        let (fam, _) = url_host_family_and_pattern("https://api.moonshot.ai")
            .expect("moonshot.ai host should match");
        assert_eq!(fam, "moonshot");
    }

    /// 2026-05-08 第三方评审第七轮反馈 [中]#3:补 rk-kimi-* 对抗样本反向断言。
    /// fingerprint helper 层确认 rk- 前缀**不命中** sk-kimi-* confirmed 规则,
    /// 防止未来 regex 改动让对抗样本误归 kimi_code。
    /// 与 [enrich.rs::w6_rk_kimi_adversarial_url_host_wins_over_keyword_stack]
    /// 形成两层防护(integration + helper unit)。
    #[test]
    fn classify_rk_kimi_prefix_does_not_match_kimi_code_confirmed() {
        let registry = FingerprintClassifier::new_embedded();
        let id = registry
            .classify("rk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL")
            .map(|e| e.id.as_str())
            .unwrap_or("<none>");
        assert_ne!(
            id, "kimi_code",
            "rk- 前缀必须不触发 sk-kimi-* confirmed 规则 (对抗样本 regression guard)"
        );
    }

    /// shell var KIMI_*/MOONSHOT_* 都默认归 'moonshot' —— 论证见
    /// shell_var_family_and_pattern 注释 (env var 推断这一层不可能遇到
    /// kimi_code 的 key,因为 sk-kimi-* 已被 confirmed regex 捕获)。
    #[test]
    fn shell_var_kimi_and_moonshot_default_to_moonshot() {
        let (fam, _) = shell_var_family_and_pattern("KIMI_API_KEY").expect("KIMI shell var");
        assert_eq!(fam, "moonshot");
        let (fam, _) =
            shell_var_family_and_pattern("MOONSHOT_BASE_URL").expect("MOONSHOT shell var");
        assert_eq!(fam, "moonshot");
    }
}
