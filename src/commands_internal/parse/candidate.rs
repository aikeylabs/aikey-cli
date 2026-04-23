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

    // ─── v4.1 Method B (Candidate Lifecycle) 扩字段 (Stage 2b) ──────────────
    //
    // 用于 trace/debug/UI "为什么这条 candidate 出现了 / 被拒了"的透明度。
    // 均为 optional + serde skip，默认不出现在 HTTP 响应里，保持 schema 向后兼容。
    //
    /// 规则来源归因 (rule_email / yaml_fingerprint / anchored_password / label_password /
    /// dash_split_password / pipe_sep_password / labeled_secret / pem_block /
    /// anchored_secret / crf_arbiter)。spike 对齐。Stage 2c+ 开始填。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Active / Review / Suppressed。默认 None = Active (隐式)。
    /// Review = CRF 标注但默认不勾；Suppressed = 规则已拒，保留给 trace/debug 看。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// 被 suppress 的原因 (status=Suppressed/Review 时有值)，如
    /// "is_comment" / "placeholder" / "crf_rejected_O" / "trailing_sep_truncation"。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_reason: Option<String>,
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
    /// v4.2: block 首行"自然语言短文本",用户手写的 Draft 卡片标题。
    /// 由 rule_title 抽取,grouper 回挂到对应 block 的 draft。
    Title,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Url => "url",
            Kind::PasswordLike => "password_like",
            Kind::SecretLike => "secret_like",
            Kind::BaseUrl => "base_url",
            Kind::Title => "title",
        }
    }
    pub fn id_prefix(&self) -> char {
        match self {
            Kind::Email => 'e',
            Kind::Url => 'u',
            Kind::PasswordLike => 'p',
            Kind::SecretLike => 's',
            Kind::BaseUrl => 'b',
            Kind::Title => 't',
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

// ─── v4.1 Method B (Candidate Lifecycle) 枚举 ──────────────────────────

/// 候选生命周期状态 (V4.1 Method B)
///
/// - `Active`  — 进入下游 grouper/HTTP 响应（默认，隐式 None）
/// - `Review`  — CRF 标注为疑似，UI 默认不勾（等同当前 Tier::Suggested 语义一部分）
/// - `Suppressed` — 规则已拒，保留供 trace/debug 看（不进 HTTP 响应数据）
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Stage 2c+ 开始用
pub enum Status {
    Active,
    Review,
    Suppressed,
}

/// 候选来源归因 (V4.1 Method B source 字符串枚举化版本)
///
/// 用于 trace log 里看"这条 candidate 是哪条规则抽出来的"。
/// 与 V4.1 spike 的 source 字符串值完全对齐 (snake_case 序列化)。
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Stage 2c+ 开始用
pub enum Source {
    RuleEmail,
    RuleUrl,
    YamlFingerprint,
    DashSplitPassword,
    LabelPassword,
    PipeSepPassword,
    LabeledSecret,
    PemBlock,
    AnchoredPassword,
    AnchoredSecret,     // v4.1 Method B Phase 4
    CrfArbiter,
}
