//! DraftRecord / DraftFields / GroupReason — L2 grouper 数据模型
//!
//! 从 V4.1 spike `workflow/CI/research/ablation/ablation-spike-v4.1/src/grouping.rs:77-168`
//! 迁移而来,保留 spike 的字段名与语义,**额外加 `#[derive(Serialize)]`** 以供 HTTP
//! 响应序列化(CLI 之外;spike 只用内部 debug 打印)。
//!
//! # 对 Web UI 的合约 (v4.1 Stage 3 新增字段)
//!
//! HTTP 响应 `data.drafts[]` 按本文件结构序列化。字段名约定:
//!   - 枚举 snake_case (`"single_line_complex"` / `"key"` / `"oauth"`)
//!   - Option<T> 用 `#[serde(skip_serializing_if = "Option::is_none")]`
//!   - Vec<T> 默认空时显式输出 `[]`(UI 直接消费,不需 undefined-check)
//!
//! # 字段级别证据 (inference_evidence)
//!
//! L3 endpoint cluster 会填充 `inferred_provider` + `inference_confidence` +
//! `inference_evidence`。Stage 3 Phase C 仅填空,Phase D HTTP layer 透传。
//! 详细算法在 v1 计划 Stage 4(L3 endpoint cluster + 多源证据 enrich)。

use serde::Serialize;

/// Draft 的字段集合 (email/password/api_key/base_url + extra_secrets + title)
#[derive(Debug, Default, Clone, Serialize)]
pub struct DraftFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// 同 block 内多余的 secret token (Stage 2 分发剩余)。
    /// 前端 Draft 卡片可选择展示为 "+ N extra secrets" 提示。
    #[serde(default)]
    pub extra_secrets: Vec<String>,
    /// v4.2: 用户手写的 Draft 标题 (block 首行的"自然语言短文本"),
    /// UI 卡片预览优先用它。由 `rule_title::rule_extract_title` 抽取,
    /// grouper 按 block line_range 回挂。
    ///
    /// Why 不放 provider_hint 里:provider_hint 是推断 provider 的提示词
    /// (如 "kimi" "anthropic"),title 是用户取的卡片名 (如 "Kimitest8"
    /// "工作号"),两者语义不同。
    ///
    /// Ablation 证据: `workflow/CI/research/ablation/ablation-spike-v4.1/TITLE_
    /// ABLATION_REPORT.md` — 现有 5 字段 R/P/FP 零回归,R_title 91.2%。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// v4.1 Draft 类型:区分以账号为主的 OAuth 凭证与纯 API KEY 凭证
///
/// 规则 (v4.1 Post-Stage4 更新):
///   1. 有 email                  → Oauth (账号-based,api_key 是 account 颁发的 token;
///                                   用户可通过浏览器登录重新颁发)
///   2. 无 email 但有 api_key      → Key   (纯 API KEY 凭证,无 account 概念)
///   3. 无 email 无 api_key 有 password → Oauth (password 组合天然属 account-based)
///   4. 其他 (URL-only / 空)      → Key 兜底
///
/// 和旧规则差异:有 email+api_key 的 Draft 从 Key 改判 Oauth。
/// Why: UI 语义上 "email+password+key" 对应"账号+访问令牌"的 OAuth 模型;
///   primary 凭证是 account,api_key 是附属 token(可重新颁发)。
///
/// 序列化 `UPPERCASE`: KEY / OAUTH (JSON/YAML 大写输出,和 UI chip 视觉一致)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DraftType {
    Key,
    Oauth,
}

impl DraftType {
    pub fn classify(fields: &DraftFields) -> Self {
        // email 存在 → Oauth (account-first 语义)
        if fields.email.is_some()   { return DraftType::Oauth; }
        // 无 email 但有 api_key → Key
        if fields.api_key.is_some() { return DraftType::Key; }
        // 只有 password → Oauth
        if fields.password.is_some() { return DraftType::Oauth; }
        DraftType::Key
    }
    #[allow(dead_code)] // 供 trace dump 等调试路径使用
    pub fn as_str(&self) -> &'static str {
        match self {
            DraftType::Key   => "KEY",
            DraftType::Oauth => "OAUTH",
        }
    }
}

/// Draft 产生的原因 —— UI 可展示为 "why this draft was grouped this way"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupReason {
    /// 同 line 内 email + pwd + secret/url 一次抽成 Draft (Stage 1)
    SingleLineComplex,
    /// Title 行驱动的 Block → 合并为一个 Draft (Stage 3 fallback)
    TitleBlock,
    /// 典型 block:email + pwd + secret(标签 + `----` 分隔) (Stage 3 fallback)
    CredentialBlock,
    /// 单 secret / 孤立值 Block (Stage 3 fallback)
    Standalone,
    /// v4.1 M4:Block 内 ≥2 合法 password,额外 password 独立 Draft
    MultiPasswordExpand,
}

/// L3 endpoint cluster 的证据来源 (Stage 3 Phase C 不生成,Phase F 透传)
///
/// V4.1 spike `grouping.rs:131-156` 迁移。CLI L3 cluster 未实现前,
/// `DraftRecord.inference_evidence` 保持空 Vec,UI 侧不依赖。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
#[allow(dead_code)] // Phase C 不填,Phase D HTTP 透传;Stage 4 才真正生成
pub enum InferenceSource {
    /// E1: api_key fingerprint 命中 (tier 决定强度)
    FingerprintConfirmed { provider_id: String },
    FingerprintLikely    { provider_id: String },
    /// E2: block.provider_hint 字符串里含 provider_label_keywords
    InlineTitleKeyword   { hint: String, keyword: String },
    /// E3: block 之前最近的 ## heading / Note 行含 keyword
    SectionHeadingKeyword { line: usize, keyword: String },
    /// E4: 该 Draft 所在行 (或 block 内) shell var 名 (CLAUDE_KEY 等)
    ShellVarPattern      { var_name: String, pattern: String },
    /// E5: Draft 自带 base_url 的 host 匹配 url_host_patterns
    UrlHostPattern       { url: String, pattern: String },
    /// E6 (BUG-04 fix): Draft 自己 line_range 内某行的 "label 区"（首 secret 前缀之前 /
    /// 首 40 字符）含 provider keyword。
    /// 触发场景:单行 Complex（`🔑 kimi: sk-moonshot_... 邮箱: ...`）— block.provider_hint
    /// 取首 token 丢了 kimi,E2/E3 都打不上;E6 直接扫 label 区兜底。
    /// Why 限定 label zone:防止匹配到 secret 值内部(如 `sk-kimi_...` 的 "kimi")误作 heading 证据。
    InlineLabelKeyword   { line: usize, keyword: String },
}

impl InferenceSource {
    #[allow(dead_code)] // Stage 4 才用
    pub fn weight(&self) -> f32 {
        match self {
            InferenceSource::FingerprintConfirmed{..} => 1.0,
            InferenceSource::FingerprintLikely{..}    => 0.7,
            InferenceSource::InlineTitleKeyword{..}   => 0.9,
            InferenceSource::SectionHeadingKeyword{..} => 0.8,
            InferenceSource::ShellVarPattern{..}      => 0.85,
            InferenceSource::UrlHostPattern{..}       => 0.6,
            InferenceSource::InlineLabelKeyword{..}   => 0.75,
        }
    }
}

/// L2 grouper 的主输出 —— Web UI 的 "Draft 卡片" 一对一映射
#[derive(Debug, Clone, Serialize)]
pub struct DraftRecord {
    /// 稳定 id,`d-{N}` 形态 (UI 用它做 expand/select 状态键)
    pub id: String,
    /// v4.1 Stage 6+: 建议 alias (vault 写入时的 key 名)。由 parse handler 在
    /// group 之后填充:基于 inferred_provider / provider_hint 生成,并与 vault 现有
    /// aliases + 本 batch 其他 draft aliases 做 dedupe(`-2`/`-3`/... 后缀)。
    ///
    /// UI 合约:默认值即本字段;用户可在卡片里手改(mutate `record.alias` 即可)。
    /// 初始状态(group_and_cluster 返回时)为空字符串,由 parse handler 填充。
    #[serde(default)]
    pub alias: String,
    /// Block 的 provider 提示 (来自 Title 行的首 token,如 `claude3:` 的 "claude3")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
    /// 主字段集合 —— UI Draft 卡片的核心内容
    pub fields: DraftFields,
    /// Draft 覆盖的源文本行范围 (闭区间 [start, end])
    /// Web UI 点击 "Jump to source" 用此信息滚动定位
    pub line_range: (usize, usize),
    /// Draft 产生原因
    pub reason: GroupReason,
    /// Key / Oauth 分类 (DraftType::classify(&fields) 派生)
    pub draft_type: DraftType,
    /// L3 cluster 填充的推断 provider (如 "anthropic" / "openai_project")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_provider: Option<String>,
    /// Provider 推断置信度 [0.0, 2.5] (五证据加权和),Stage 4 前保持 0.0
    #[serde(default)]
    pub inference_confidence: f32,
    /// 推断证据列表 (Stage 4 前空 Vec)
    #[serde(default)]
    pub inference_evidence: Vec<InferenceSource>,
    /// v4.1 Stage 5+: 严格协议类型列表 (从 inferred_provider 派生)
    ///
    /// - 官方厂商指纹命中            → `[family]` (如 `["anthropic"]`)
    /// - 聚合网关命中 (openrouter等)  → `[]` (UI multi-select 让用户手选)
    /// - 推断不到 / enrich 未运行     → `[]`
    ///
    /// UI 合约:`[]` 表示 dropdown 默认无选中,占位提示 "Select protocols";
    /// 非空时默认勾选 vec 内全部 protocol。聚合网关 family 清单见
    /// `data/provider_fingerprint.yaml::aggregator_families`。
    #[serde(default)]
    pub protocol_types: Vec<String>,
    /// v4.1 Stage 10+: 推断出的 provider 对应的官方登录/API Key 页面 URL
    ///
    /// 由 parse handler 从 `FingerprintClassifier::login_url_for_family` 填充;
    /// 未推断出 provider 或 yaml 未配时为 None。UI "Open login page" 按钮消费此字段,
    /// window.open() 让用户直接到官方登录页完成 OAuth / 申请 API Key。
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub login_url: Option<String>,
    /// v4.2: 推断出的 provider 对应的官方 API base_url。
    ///
    /// 由 parse handler 从 `FingerprintClassifier::base_url_for_family` 填充;
    /// 未推断 / yaml 未配时为 None。UI "use official" 按钮消费此字段填入
    /// `fields.base_url`。之前硬编码在前端 PROVIDER_DEFAULT_BASE_URL Record,
    /// 现挪 YAML —— ControlPanel 可热更新,新聚合网关出现无需前端发版。
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub official_base_url: Option<String>,
}

/// L2 grouper 内部 block 数据 (从 V4.1 spike `grouping.rs:338-343` 迁移)
#[derive(Debug, Clone)]
pub struct Block {
    pub start_line: usize,
    pub end_line: usize,
    pub provider_hint: Option<String>,
    /// Block 内每行的 LineKind 列表 (去重前)
    pub kinds: Vec<super::super::line_class::LineKind>,
}

// ─── v4.1 Stage 4: L3 EndpointGroup (endpoint cluster) ──────────────────

/// EndpointGroup 产生原因 —— UI 可展示为 "why drafts were clustered this way"
///
/// 语义 (与 V4.1 spike `ClusterReason` 对齐):
/// - `Explicit`: draft 自带 base_url,不走 sticky 推断
/// - `SameBlockLabeled`: 同 block 有 URL 行,且 URL 前有 "base_url:"/"endpoint:" 标签
/// - `SameBlock`: 同 block 有 URL 行 (无标签)
/// - `InheritedSticky`: 跨 block 继承 URL (sticky 评分 ≥ 阈值)
/// - `Default`: 未推断 (base_url = None)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterReason {
    Explicit,
    SameBlockLabeled,
    SameBlock,
    InheritedSticky,
    Default,
}

/// L3 endpoint 聚类输出:同 provider + 同 base_url 的 Draft 聚成一组
///
/// 每个 Draft 会映射到恰好一个 group。UI 可按 group 分层展示 Draft 列表,
/// 共享 endpoint 的 Drafts 在视觉上可见为 "N keys under X (provider@url)"。
#[derive(Debug, Clone, Serialize)]
pub struct EndpointGroup {
    /// 稳定 id,`g-{N}` 形态
    pub id: String,
    /// 规范化的 provider family (anthropic / openai / kimi / 等;v4.1 与 connectivity/runtime 字典对齐)
    /// None 表示未推断。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// 规范化的 base_url (已去 query/fragment/尾斜杠)。None 表示该 group 无 URL。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// 成员 draft ID 列表 (如 ["d-1", "d-2", "d-5"])
    pub member_draft_ids: Vec<String>,
    /// Group 可信度 (所有 member 的最低 sticky 分数,反映最弱链)
    pub confidence: f32,
    /// Group 由哪种方式产生
    pub reason: ClusterReason,
}
