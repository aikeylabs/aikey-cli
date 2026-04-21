//! 解析候选的数据模型
//!
//! 与 `批量导入-最终方案-v2.md §5.3` 的 `Candidate` TypeScript 接口对齐。
//! Phase 2 只填 confirmed tier；Phase 3 (H 层 Fingerprint) 补 provider 字段；
//! Phase 4 (CRF + shape filter) 补 suggested tier。

use serde::Serialize;

/// 单个抽取候选
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// 稳定 id，`c-{kind_char}-{seq}` 形态（UI 用它做 orphan 映射）
    pub id: String,
    pub kind: Kind,
    pub value: String,
    pub tier: Tier,
    /// 原文字节位置 [start, end)；tokenize 派生的候选可能为 None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_span: Option<[usize; 2]>,
    /// H 层 Provider Fingerprint 打的标签（Phase 3 填充）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderGuess>,
}

/// 字段种类（与 WebUI 的 `FieldKind` 对齐）
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Email,
    Url,
    PasswordLike,
    SecretLike,
    #[allow(dead_code)] // Phase 3/4 grouper 可能输出 base_url 分类
    BaseUrl,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Url => "url",
            Kind::PasswordLike => "password_like",
            Kind::SecretLike => "secret_like",
            Kind::BaseUrl => "base_url",
        }
    }
    pub fn id_prefix(&self) -> char {
        match self {
            Kind::Email => 'e',
            Kind::Url => 'u',
            Kind::PasswordLike => 'p',
            Kind::SecretLike => 's',
            Kind::BaseUrl => 'b',
        }
    }
}

/// 字段级抽取置信度（与 WebUI `CandidateTier` 对齐）
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// 规则层命中；默认勾选导入
    Confirmed,
    /// CRF 输出（过 shape filter）；默认不勾选
    #[allow(dead_code)] // Phase 4 CRF 启用后开始填
    Suggested,
    /// 形态可疑（UUID / 短 hex），UI 标警示
    #[allow(dead_code)] // Phase 3 H 层启用后开始填
    Warn,
    /// 抽取成功但 provider 未识别
    #[allow(dead_code)]
    Unknown,
}

/// Provider 猜测（Phase 3 H 层填充）
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct ProviderGuess {
    pub id: String,
    pub display: String,
    pub tier: ProviderTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// ambiguous tier 的候选 provider 列表（UI 手选下拉优先展示）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ProviderTier {
    Confirmed,
    Ambiguous,
    Warn,
}

/// 辅助：生成 Candidate 的稳定 id
pub fn make_id(kind: Kind, seq: usize) -> String {
    format!("c-{}-{}", kind.id_prefix(), seq)
}
