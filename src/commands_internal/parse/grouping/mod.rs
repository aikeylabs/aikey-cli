//! L2 / L3 Grouper - 从 V4.1 spike 的 grouping.rs 迁移而来
//!
//! # 迁移路线图
//!
//! 此 module 在 **Stage 0** 创建占位，随 Stage 3/4 填充。
//!
//! - Stage 3: `stage.rs` - L2 Stage 1 (SingleLineComplex) / Stage 2 (multi-secret 分发) /
//!   Stage 3 (safe fallback + M4 multi-password partition)
//! - Stage 4: `cluster.rs` - L3 EndpointGroup / ClusterReason / collect_url_anchors /
//!   normalize_provider_with_registry
//! - Stage 4: `enrich.rs` - 多源证据投票 (fingerprint / section_heading / url_host /
//!   inline_title / shell_var)
//!
//! # 合约
//!
//! - drafts/groups/orphans 的 per-sample 数字必须与 `workflow/CI/research/ablation-spike-v4.1/`
//!   同一 canary bit-for-bit 对齐 (见 `tests/fixtures/v41_spike_baseline.json`)
//! - DraftRecord / Block / GroupReason 名称和字段与 V4.1 spike 一致
//! - 新增的 `MultiPasswordExpand` GroupReason 要同时进 serde 序列化路径
//!
//! # 依赖
//!
//! - 上游：`parse::candidate::Candidate` (Stage 1 扩了 status/suppress_reason/span)
//! - 上游：`parse::line_class::LineKind / LineFlags` (Stage 1 引入)
//! - 下游：`parse::rule::run(text)` 返回的 `Vec<Candidate>` 作为 grouper 输入

// placeholder — filled in Stage 3/4
