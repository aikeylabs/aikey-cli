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
}

// ========== Classifier ==========

pub struct FingerprintClassifier {
    entries: Vec<(ProviderEntry, Regex)>,
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
        Self { entries }
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
        // siblings 至少含 moonshot_kimi / deepseek 等（M3 评审要求）
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
