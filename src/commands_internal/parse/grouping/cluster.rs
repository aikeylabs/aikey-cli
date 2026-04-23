//! L3 Endpoint Cluster — 把 Draft 按 base_url + provider 聚成 EndpointGroup
//!
//! 从 V4.1 spike `grouping.rs::cluster_endpoints` (L920-1159) 迁移。
//!
//! # 算法总览
//!
//! 1. `collect_url_anchors` 收集文档内所有 URL 位置 → `Vec<UrlAnchor>`
//!    (每个 anchor 知道自己在哪个 block,以及是否有 `base_url:` 标签)
//!
//! 2. 对每个 Draft:
//!    a. 若 draft 自带 `base_url` → `Explicit`,conf=1.0
//!    b. 否则跑 **find_best_url** sticky 打分:
//!       - 对每 anchor 计算 `BlockGap` 距离分(Same 1.0 / SoftAdjacent 0.7 /
//!         AdjacentWithSeparator 0.3 / AdjacentWithTitle 0.2 / Far 0)
//!       - 与 `ProviderMatch` 一致性分(Exact 1.0 / AnchorUnlabeled 0.7 /
//!         DraftUnknown 0.4 / BothUnknown 0.3 / Mismatch 0)
//!       - `score = distance × provider_match`,取最高分
//!       - 阈值 0.5,低于不命中
//!    c. provider 走 `normalize_provider_with_registry` 规范化
//!
//! 3. 按 `(provider, normalize_url(base_url))` 去重聚合成 EndpointGroup
//!
//! # 合约
//!
//! - 每个 Draft 映射到恰好一个 Group。drafts.len() ≥ groups.len()。
//! - Group.confidence 取所有 member 的最低分(反映最弱链)
//! - 空 drafts → 空 groups

use std::collections::HashMap;

use regex::Regex;
use std::sync::OnceLock;

// R-5 P2-A (2026-04-23): cached regexes (collect_url_anchors runs per-line).
fn re_url() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"https?://[^\s"',}\])）】」〕]+"#).unwrap())
}
fn label_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)\b(base[_\s\-]?url|endpoint|host|api)\s*[:=]"#).unwrap())
}

use super::super::line_class::{classify_line, LineKind};
use super::super::provider_fingerprint::{
    self, text_keyword_family_and_keyword, url_host_family_and_pattern, FingerprintClassifier,
};
use super::types::{Block, ClusterReason, DraftRecord, EndpointGroup};

// ─── UrlAnchor + 收集 ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct UrlAnchor {
    url: String,
    #[allow(dead_code)] // 供 trace dump 用,cluster 本身只需 block_id
    line: usize,
    /// URL 所在行的 block 索引。若不在任何 block 内(独立 URL 行)→ usize::MAX
    block_id: usize,
    /// 行内是否有 `base_url:` / `endpoint:` / `host:` / `api:` 等标签
    labeled_as_endpoint: bool,
}

fn collect_url_anchors(text: &str, blocks: &[Block]) -> Vec<UrlAnchor> {
    let lines: Vec<&str> = text.lines().collect();
    let mut anchors = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        for m in re_url().find_iter(line) {
            let url = m.as_str().to_string();
            let bi = blocks
                .iter()
                .position(|b| i >= b.start_line && i <= b.end_line)
                .unwrap_or(usize::MAX);
            let labeled = label_re().is_match(line);
            anchors.push(UrlAnchor {
                url,
                line: i,
                block_id: bi,
                labeled_as_endpoint: labeled,
            });
        }
    }
    anchors
}

// ─── Provider 规范化 ────────────────────────────────────────────────

/// V4.1 M3 治:provider 归一化走 YAML + 硬编码 family 映射,不再硬编码 provider 词表
///
/// 优先级:
///   1. `draft.inferred_provider` (enrich_drafts 五证据投票)
///   2. `draft.provider_hint` + `text_keyword_family_and_keyword` 推断
///   3. `draft.provider_hint` 原文 lowercase
///   4. "unknown"
fn normalize_provider_with_registry(
    draft: &DraftRecord,
    _registry: &FingerprintClassifier,
) -> String {
    if let Some(fam) = &draft.inferred_provider {
        return fam.clone();
    }
    if let Some(hint) = &draft.provider_hint {
        if let Some((fam, _kw)) = text_keyword_family_and_keyword(hint) {
            return fam;
        }
        return hint.to_lowercase();
    }
    "unknown".to_string()
}

/// URL → provider family 推断 (E5 逻辑复用)
fn infer_provider_from_url(url: &str) -> Option<String> {
    url_host_family_and_pattern(url).map(|(fam, _)| fam)
}

fn normalize_url(u: &str) -> String {
    let mut s = u.to_string();
    if let Some(q) = s.find('?') { s.truncate(q); }
    if let Some(h) = s.find('#') { s.truncate(h); }
    s.trim_end_matches('/').to_string()
}

// ─── Sticky 评分:BlockGap × ProviderMatch ────────────────────────────────

/// 硬阈值:score < 0.5 不命中 sticky
pub const STICKY_THRESHOLD: f32 = 0.5;

#[derive(Debug, Clone, Copy)]
enum BlockGap {
    /// 同 block → 1.0
    Same,
    /// 紧邻块,中间仅 Empty → 0.7
    SoftAdjacent,
    /// 紧邻块,中间含 `---/===/***` Separator → 0.3
    AdjacentWithSeparator,
    /// 紧邻块,中间跨新 Title 行 → 0.2
    AdjacentWithTitle,
    /// > 1 block 间距 → 0.0 (硬截断)
    Far,
}

impl BlockGap {
    fn score(self) -> f32 {
        match self {
            BlockGap::Same => 1.0,
            BlockGap::SoftAdjacent => 0.7,
            BlockGap::AdjacentWithSeparator => 0.3,
            BlockGap::AdjacentWithTitle => 0.2,
            BlockGap::Far => 0.0,
        }
    }
}

fn classify_gap(
    text: &str,
    draft_block: Option<usize>,
    anchor_block: usize,
    blocks: &[Block],
) -> BlockGap {
    let Some(db) = draft_block else { return BlockGap::Far; };
    if db == anchor_block { return BlockGap::Same; }
    if anchor_block == usize::MAX { return BlockGap::Far; }
    if anchor_block >= db { return BlockGap::Far; }
    if db - anchor_block > 1 { return BlockGap::Far; }

    let lines: Vec<&str> = text.lines().collect();
    let gap_start = blocks[anchor_block].end_line + 1;
    let gap_end = blocks[db].start_line;
    let mut saw_separator = false;
    let mut saw_title = false;
    for ln in gap_start..gap_end {
        if ln >= lines.len() { continue; }
        let k = classify_line(lines[ln]);
        match k {
            LineKind::Separator => saw_separator = true,
            LineKind::Title => saw_title = true,
            _ => {}
        }
    }
    if saw_separator {
        BlockGap::AdjacentWithSeparator
    } else if saw_title {
        BlockGap::AdjacentWithTitle
    } else {
        BlockGap::SoftAdjacent
    }
}

#[derive(Debug, Clone, Copy)]
enum ProviderMatch {
    Exact,           // 都明确且相同 → 1.0
    AnchorUnlabeled, // draft 明确,anchor 无推断 → 0.7
    DraftUnknown,    // anchor 明确,draft 无 → 0.4
    BothUnknown,     // 都 unknown → 0.3 (v3 补)
    Mismatch,        // 明确不同 → 0.0 (硬截断)
}

impl ProviderMatch {
    fn score(self) -> f32 {
        match self {
            ProviderMatch::Exact => 1.0,
            ProviderMatch::AnchorUnlabeled => 0.7,
            ProviderMatch::DraftUnknown => 0.4,
            ProviderMatch::BothUnknown => 0.3,
            ProviderMatch::Mismatch => 0.0,
        }
    }
}

fn classify_match(draft_p: Option<&str>, anchor_p: Option<&str>) -> ProviderMatch {
    match (draft_p, anchor_p) {
        (Some(d), Some(a)) if d == "unknown" && a == "unknown" => ProviderMatch::BothUnknown,
        (Some(d), Some(a)) if d == a => ProviderMatch::Exact,
        (Some(d), _) if d == "unknown" => ProviderMatch::DraftUnknown,
        (_, Some(a)) if a == "unknown" => ProviderMatch::AnchorUnlabeled,
        (Some(d), Some(a)) if d != a => ProviderMatch::Mismatch,
        (Some(_), None) => ProviderMatch::AnchorUnlabeled,
        (None, Some(_)) => ProviderMatch::DraftUnknown,
        (None, None) => ProviderMatch::BothUnknown,
        _ => ProviderMatch::BothUnknown,
    }
}

/// 为 draft 找最佳 base_url + ClusterReason + 置信度
///
/// 若 draft 自带 base_url → Explicit,conf=1.0
/// 否则:对每 anchor 算 distance × provider_match 分,取最高 (≥ 0.5)
fn find_best_url(
    text: &str,
    draft: &DraftRecord,
    anchors: &[UrlAnchor],
    blocks: &[Block],
    registry: &FingerprintClassifier,
) -> (Option<String>, ClusterReason, f32) {
    if let Some(u) = &draft.fields.base_url {
        return (Some(u.clone()), ClusterReason::Explicit, 1.0);
    }

    let draft_block = blocks.iter().position(|b| {
        let (s, e) = draft.line_range;
        s >= b.start_line && e <= b.end_line
    });
    let draft_provider = normalize_provider_with_registry(draft, registry);

    let mut best: Option<(String, ClusterReason, f32)> = None;
    for a in anchors {
        let gap = classify_gap(text, draft_block, a.block_id, blocks);
        let d = gap.score();
        if d == 0.0 { continue; }
        let anchor_provider = infer_provider_from_url(&a.url);
        let pm = classify_match(Some(draft_provider.as_str()), anchor_provider.as_deref());
        let p = pm.score();
        if p == 0.0 { continue; }
        let score = d * p;
        if score < STICKY_THRESHOLD { continue; }

        let reason = match gap {
            BlockGap::Same => {
                if a.labeled_as_endpoint {
                    ClusterReason::SameBlockLabeled
                } else {
                    ClusterReason::SameBlock
                }
            }
            _ => ClusterReason::InheritedSticky,
        };

        if best.as_ref().map(|(_, _, s)| score > *s).unwrap_or(true) {
            best = Some((a.url.clone(), reason, score));
        }
    }

    match best {
        Some((u, r, c)) => (Some(u), r, c),
        None => (None, ClusterReason::Default, 1.0),
    }
}

// ─── 主入口 ────────────────────────────────────────────────────────

/// 把 drafts 聚成 EndpointGroup (同 provider + 同 base_url 一组)
///
/// 返回稳定顺序:按 group 首次出现的 draft id 排序 (插入顺序保留)
pub fn cluster_endpoints(
    text: &str,
    drafts: &[DraftRecord],
    blocks: &[Block],
) -> Vec<EndpointGroup> {
    let registry = provider_fingerprint::instance();
    let url_anchors = collect_url_anchors(text, blocks);

    // 用 Vec 保持插入顺序 + HashMap 做 key 去重
    let mut groups: Vec<EndpointGroup> = Vec::new();
    let mut key_to_idx: HashMap<(String, Option<String>), usize> = HashMap::new();

    for draft in drafts {
        let (base_url, reason, conf) =
            find_best_url(text, draft, &url_anchors, blocks, registry);
        let provider = Some(normalize_provider_with_registry(draft, registry));
        let key = (provider.clone().unwrap(), base_url.as_ref().map(|u| normalize_url(u)));

        if let Some(&idx) = key_to_idx.get(&key) {
            groups[idx].member_draft_ids.push(draft.id.clone());
            if conf < groups[idx].confidence { groups[idx].confidence = conf; }
        } else {
            let next_id = groups.len() + 1;
            let idx = groups.len();
            groups.push(EndpointGroup {
                id: format!("g-{}", next_id),
                provider,
                base_url: base_url.clone(),
                member_draft_ids: vec![draft.id.clone()],
                confidence: conf,
                reason,
            });
            key_to_idx.insert(key, idx);
        }
    }

    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands_internal::parse::candidate::{make_id, Candidate, Kind, Tier as CTier};
    use super::super::block::split_into_blocks;
    use super::super::group_candidates;

    fn cand(kind: Kind, value: &str) -> Candidate {
        Candidate {
            id: make_id(kind, 1),
            kind,
            value: value.to_string(),
            tier: CTier::Confirmed,
            source_span: None,
            provider: None,
            source: None,
            status: None,
            suppress_reason: None,
        }
    }

    #[test]
    fn explicit_base_url_draft() {
        // Draft 自带 base_url → ClusterReason::Explicit,conf=1.0
        let text = "claude3:\nalice@acme.io\nhttps://api.anthropic.com/v1\nsk-ant-api03-Fake_AAA_BBB_CCC_DDD_EEE_FFF_GGG_HHH_III_JJJ_KKK_LLL_valid";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::Url, "https://api.anthropic.com/v1"),
            cand(Kind::SecretLike, "sk-ant-api03-Fake_AAA_BBB_CCC_DDD_EEE_FFF_GGG_HHH_III_JJJ_KKK_LLL_valid"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        let groups = cluster_endpoints(text, &drafts, &blocks);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].reason, ClusterReason::Explicit);
        assert_eq!(groups[0].base_url.as_deref(), Some("https://api.anthropic.com/v1"));
        assert_eq!(groups[0].provider.as_deref(), Some("anthropic"));
    }

    #[test]
    fn two_drafts_one_group_same_block_url() {
        // 同 block 内两个 api_key 共享一 URL → 聚成 1 group,2 members
        let text = "OpenAI:\nhttps://api.openai.com/v1\nsk-proj-FakeKey_A_aBcDeFgHiJ_kLmNoPqRsT_uVwXyZ_1234567890_abcdef\nsk-proj-FakeKey_B_xYzWvUtSrQ_pOnMlKjIhG_fEdCbA_0987654321_fedcba";
        let cands = vec![
            cand(Kind::Url, "https://api.openai.com/v1"),
            cand(Kind::SecretLike, "sk-proj-FakeKey_A_aBcDeFgHiJ_kLmNoPqRsT_uVwXyZ_1234567890_abcdef"),
            cand(Kind::SecretLike, "sk-proj-FakeKey_B_xYzWvUtSrQ_pOnMlKjIhG_fEdCbA_0987654321_fedcba"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        let groups = cluster_endpoints(text, &drafts, &blocks);
        assert!(!groups.is_empty(), "expected at least 1 group");
        // 至少应有一个 openai group 包含两 drafts
        let openai_group = groups.iter().find(|g| g.provider.as_deref() == Some("openai"));
        assert!(openai_group.is_some(), "expected openai group");
        assert!(openai_group.unwrap().member_draft_ids.len() >= 1);
    }

    #[test]
    fn different_providers_different_groups() {
        let text = "claude:\nhttps://api.anthropic.com/v1\nsk-ant-api03-Claude_Key_A_aBcDeFgHiJk_LmNoPqRsT_uVwXyZ_RealishFormat_123\n\nopenai:\nhttps://api.openai.com/v1\nsk-proj-OpenAI_Key_A_xYzWvUtSrQp_OnMlKjIhG_fEdCbA_DifferentFormat_456_fin";
        let cands = vec![
            cand(Kind::Url, "https://api.anthropic.com/v1"),
            cand(Kind::SecretLike, "sk-ant-api03-Claude_Key_A_aBcDeFgHiJk_LmNoPqRsT_uVwXyZ_RealishFormat_123"),
            cand(Kind::Url, "https://api.openai.com/v1"),
            cand(Kind::SecretLike, "sk-proj-OpenAI_Key_A_xYzWvUtSrQp_OnMlKjIhG_fEdCbA_DifferentFormat_456_fin"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        let groups = cluster_endpoints(text, &drafts, &blocks);
        // 至少 2 groups (anthropic / openai)
        assert!(groups.len() >= 2, "expected ≥2 groups, got {}", groups.len());
    }

    #[test]
    fn draft_without_url_default_group() {
        let text = "just some note\nsk-ant-api03-LonelyKey_Anthropic_NoUrlNearby_0000_1111_2222_3333_fin";
        let cands = vec![cand(Kind::SecretLike, "sk-ant-api03-LonelyKey_Anthropic_NoUrlNearby_0000_1111_2222_3333_fin")];
        let (drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        let groups = cluster_endpoints(text, &drafts, &blocks);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].reason, ClusterReason::Default);
        assert!(groups[0].base_url.is_none());
    }

    #[test]
    fn normalize_url_strips_query_and_trailing_slash() {
        assert_eq!(normalize_url("https://api.openai.com/v1/"), "https://api.openai.com/v1");
        assert_eq!(
            normalize_url("https://api.openai.com/v1?key=abc#frag"),
            "https://api.openai.com/v1"
        );
        assert_eq!(normalize_url("https://api.openai.com"), "https://api.openai.com");
    }

    #[test]
    fn empty_drafts_empty_groups() {
        let groups = cluster_endpoints("", &[], &[]);
        assert_eq!(groups.len(), 0);
    }
}
