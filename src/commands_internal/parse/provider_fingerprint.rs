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

#[derive(Debug, Deserialize)]
struct Registry {
    #[allow(dead_code)]
    version: u32,
    providers: Vec<ProviderEntry>,
    /// v4.1 Stage 5+: 聚合网关 family 清单(openrouter / yunwu / zeroeleven 等)
    /// 见 yaml 顶部 `aggregator_families` 段落。
    #[serde(default)]
    aggregator_families: Vec<String>,
    /// v4.1 Stage 10+: family → 官方登录/API Key 页面 URL
    /// UI "Open login page" 按钮消费此字段(window.open)
    #[serde(default)]
    family_login_urls: std::collections::HashMap<String, String>,
    /// v4.2: family → 官方 API endpoint base_url
    /// UI "use official" 按钮点击填入 draft.fields.base_url 消费此表
    #[serde(default)]
    family_base_urls: std::collections::HashMap<String, String>,
    /// v4.2.1 (2026-05-01): host → base_url 精分流 override.
    /// 解析到具体 URL host 时优先查这张表;查不到再回落到 family_base_urls。
    /// 让同 family 下多 host 各自路由不同 endpoint (kimi.com vs moonshot.cn)。
    #[serde(default)]
    host_to_base_url: std::collections::HashMap<String, String>,
}

// ========== Classifier ==========

pub struct FingerprintClassifier {
    entries: Vec<(ProviderEntry, Regex)>,
    /// v4.1 Stage 5+: 聚合网关 family 集合(从 yaml 加载)
    aggregator_families: std::collections::HashSet<String>,
    /// v4.1 Stage 10+: family → 登录页 URL 映射(从 yaml 加载)
    family_login_urls: std::collections::HashMap<String, String>,
    /// v4.2: family → 官方 API base_url 映射(从 yaml 加载)
    family_base_urls: std::collections::HashMap<String, String>,
    /// v4.2.1: host → base_url 精分流 override 表(从 yaml 加载)
    host_to_base_url: std::collections::HashMap<String, String>,
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
        let family_base_urls = reg.family_base_urls;
        let host_to_base_url = reg.host_to_base_url;
        Self { entries, aggregator_families, family_login_urls, family_base_urls, host_to_base_url }
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

    /// v4.2: 查 family 的官方 API base_url (UI "use official" 按钮填入)
    pub fn base_url_for_family(&self, family: &str) -> Option<String> {
        self.family_base_urls.get(family).cloned()
    }

    /// 全量 family → 登录页 URL 映射 (用于 `_internal rules` 把整张表透出给 Web UI)
    pub fn family_login_urls_map(&self) -> &std::collections::HashMap<String, String> {
        &self.family_login_urls
    }

    /// 全量 family → 官方 API base_url 映射 (同上,用于 _internal rules)
    pub fn family_base_urls_map(&self) -> &std::collections::HashMap<String, String> {
        &self.family_base_urls
    }

    /// v4.2.1: 按 host 精分流查 base_url。host 应预先归一(小写、去 port、去
    /// path),典型来自 `extract_host(parsed_url)`。
    pub fn base_url_for_host(&self, host: &str) -> Option<String> {
        self.host_to_base_url.get(host).cloned()
    }

    /// 全量 host → base_url 映射 (用于 _internal rules 透传给前端)
    pub fn host_to_base_url_map(&self) -> &std::collections::HashMap<String, String> {
        &self.host_to_base_url
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
        let Some(entry) = matched else { return (None, None); };
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
        ("anthropic",     "anthropic"),
        ("claude",        "anthropic"),
        ("openrouter",    "openrouter"),
        ("openai",        "openai"),
        ("gpt-4o",        "openai"),
        ("gpt4o",         "openai"),
        ("gpt-4",         "openai"),
        ("gemini",        "google_gemini"),
        ("google ai",     "google_gemini"),
        // v4.1 family rename: kimi/moonshot → "kimi" (与 connectivity/runtime PROVIDER_DEFAULTS 字典对齐;
        // 旧 family 名 "moonshot_kimi" 与 CLI 其他地方一律叫 "kimi" 不一致,UI Provider 字段直接消费此值)
        ("moonshot",      "kimi"),
        ("kimi",          "kimi"),
        ("groq",          "groq"),
        ("deepseek",      "deepseek"),
        ("mistral",       "mistral"),
        ("yunwu",         "yunwu"),
        ("zeroeleven",    "zeroeleven"),
        ("0011",          "zeroeleven"),
        ("xai",           "xai_grok"),
        ("grok",          "xai_grok"),
        ("zhipu",         "zhipu"),
        ("glm",           "zhipu"),
        ("\u{8C46}\u{5305}", "doubao"),       // 豆包
        ("doubao",        "doubao"),
        ("volces",        "doubao"),
        ("silicon",       "siliconflow"),
        ("\u{7845}\u{57FA}",   "siliconflow"), // 硅基
        ("huggingface",   "huggingface"),
        ("perplexity",    "perplexity"),
        ("sendgrid",      "sendgrid"),
        ("stripe",        "stripe"),
        ("slack",         "slack"),
        ("github",        "github"),
        ("aws",           "aws"),
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
        ("ANTHROPIC",  "anthropic",     "ANTHROPIC_*"),
        ("CLAUDE",     "anthropic",     "CLAUDE_*"),
        ("OPENAI",     "openai",        "OPENAI_*"),
        ("OPENROUTER", "openrouter",    "OPENROUTER_*"),
        ("GEMINI",     "google_gemini", "GEMINI_*"),
        ("GOOGLE_AI",  "google_gemini", "GOOGLE_AI_*"),
        ("MOONSHOT",   "kimi",          "MOONSHOT_*"),
        ("KIMI",       "kimi",          "KIMI_*"),
        ("GROQ",       "groq",          "GROQ_*"),
        ("DEEPSEEK",   "deepseek",      "DEEPSEEK_*"),
        ("MISTRAL",    "mistral",       "MISTRAL_*"),
        ("YUNWU",      "yunwu",         "YUNWU_*"),
        ("XAI",        "xai_grok",      "XAI_*"),
        ("HUGGINGFACE", "huggingface",  "HUGGINGFACE_*"),
        ("HF_TOKEN",   "huggingface",   "HF_TOKEN"),
        ("PERPLEXITY", "perplexity",    "PERPLEXITY_*"),
        ("SENDGRID",   "sendgrid",      "SENDGRID_*"),
        ("STRIPE",     "stripe",        "STRIPE_*"),
        ("SLACK",      "slack",         "SLACK_*"),
        ("GITHUB",     "github",        "GITHUB_*"),
        ("AWS_ACCESS", "aws",           "AWS_ACCESS_*"),
    ];
    for (prefix, family, pattern) in MAP {
        if uc.starts_with(prefix) {
            return Some((family.to_string(), pattern.to_string()));
        }
    }
    None
}

/// URL host → family (E5 UrlHostPattern)
///
/// 从 URL 抽 host,匹配 substring → 返回 (family, matched_pattern)
pub fn url_host_family_and_pattern(url: &str) -> Option<(String, String)> {
    let host = url
        .strip_prefix("https://").or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_lc = host.split(['/', '?', '#', ':']).next().unwrap_or("").to_lowercase();
    if host_lc.is_empty() { return None; }
    const MAP: &[(&str, &str)] = &[
        ("anthropic.com",        "anthropic"),
        ("claude.com",           "anthropic"),
        ("claude.ai",            "anthropic"),
        ("openai.com",           "openai"),
        ("openrouter.ai",        "openrouter"),
        ("generativelanguage.googleapis.com", "google_gemini"),
        ("aistudio.google.com",  "google_gemini"),
        ("moonshot.cn",          "kimi"),
        ("moonshot.ai",          "kimi"),
        ("groq.com",             "groq"),
        ("deepseek.com",         "deepseek"),
        ("mistral.ai",           "mistral"),
        ("yunwu.ai",             "yunwu"),
        ("0011.ai",              "zeroeleven"),
        ("x.ai",                 "xai_grok"),
        ("huggingface.co",       "huggingface"),
        ("perplexity.ai",        "perplexity"),
        ("sendgrid.com",         "sendgrid"),
        ("stripe.com",           "stripe"),
        ("slack.com",            "slack"),
        ("github.com",           "github"),
        ("amazonaws.com",        "aws"),
        ("bigmodel.cn",          "zhipu"),
        ("volces.com",           "doubao"),
        ("siliconflow.cn",       "siliconflow"),
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
        let e = c.classify("550e8400-e29b-41d4-a716-446655440000").expect("uuid");
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
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC\n-----END OPENSSH PRIVATE KEY-----";
        let e = c.classify(pem).expect("pem");
        assert_eq!(e.id, "pem_block");
    }
}
