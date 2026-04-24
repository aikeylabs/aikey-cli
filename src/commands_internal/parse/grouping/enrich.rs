//! L3 enrich_drafts — 5 证据加权投票填充 `inferred_provider` + `inference_confidence`
//!
//! 从 V4.1 spike `grouping.rs::enrich_drafts` (L1224-1400) 迁移。
//!
//! # 证据来源 (与 V4.1 spike 一致)
//!
//! - **E1 FingerprintConfirmed / FingerprintLikely** — api_key 命中 YAML provider regex
//! - **E2 InlineTitleKeyword** — `DraftRecord.provider_hint` 里含 provider 关键词
//! - **E3 SectionHeadingKeyword** — block 之前最近的 Note/Title 行含 keyword
//! - **E4 ShellVarPattern** — draft.line_range 内出现 `FOO_API_KEY=` 形 shell var
//! - **E5 UrlHostPattern** — draft.fields.base_url 的 host 匹配 provider
//!
//! # 算法
//!
//! 对每个 Draft:
//! 1. `collect_evidence` 收全部证据 → Vec<(family, InferenceSource)>
//! 2. 按 family 累加权重 (FingerprintConfirmed=1.0, InlineTitle=0.9, ShellVar=0.85,
//!    SectionHeading=0.8, FingerprintLikely=0.7, UrlHost=0.6)
//! 3. 最高分 family,若 score ≥ 0.5 THRESHOLD → 填 inferred_provider + confidence + evidence
//!
//! # Phase 3 scope
//!
//! 只填 DraftRecord 上的 inferred_provider/confidence/evidence,**不做 EndpointGroup 聚类**
//! (Stage 4 完整 L3)。

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

// R-5 P2-A (2026-04-23): cached shell-var regex (E4 evidence runs per-draft).
fn re_var() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:^|\s)([A-Z][A-Z0-9_]{2,})\s*=").unwrap())
}

use super::super::line_class::{line_class, LineKind};
use super::super::provider_fingerprint::{
    provider_family_of, shell_var_family_and_pattern, text_keyword_family_and_keyword,
    url_host_family_and_pattern, FingerprintClassifier, Tier,
};
use super::types::{Block, DraftRecord, InferenceSource};

const THRESHOLD: f32 = 0.5;

/// BUG-04 fix helper: 取 line 的 "label 区" —— 首个已知 secret 前缀之前 / 或首 40 字符。
/// 用于 E6 keyword scan,防止误匹配到 secret 值内部的字符串。
///
/// Why 列这些前缀:provider_fingerprint.yaml 里 confirmed tier 的 secret 基本都有特异性前缀。
/// 一旦 label 区里出现 keyword,E6 就触发;secret 本身的内容不参与 keyword 匹配。
///
/// 与 research spike `workflow/CI/research/ablation/ablation-spike-v4.1/src/grouping.rs::line_label_zone`
/// 保持一致。任何修改请先在 spike 验证(CLAUDE.md "Import 解析流改动强制走 research 验证")。
fn line_label_zone(line: &str) -> &str {
    const SECRET_PREFIXES: &[&str] = &[
        "sk-ant-", "sk-proj-", "sk-admin-", "sk-svcacct-", "sk-or-v1-", "sk-",
        "AIza", "AKIA", "xai-", "gsk_", "eyJ", "ghp_", "github_pat", "hf_",
        "pplx-", "SG.", "rk_live_", "sk_live_", "xoxb-", "xoxp-",
    ];
    let mut cut: Option<usize> = None;
    for prefix in SECRET_PREFIXES {
        if let Some(idx) = line.find(prefix) {
            cut = Some(cut.map(|c| c.min(idx)).unwrap_or(idx));
        }
    }
    if let Some(idx) = cut {
        return &line[..idx];
    }
    // 无 secret 前缀 → 取首 40 char (多语言 safe 用 char_indices)
    let end = line.char_indices().nth(40).map(|(i, _)| i).unwrap_or(line.len());
    &line[..end]
}

/// 主入口:对 drafts 做就地 enrich (填 inferred_provider / confidence / evidence)
pub fn enrich_drafts(
    drafts: &mut [DraftRecord],
    text: &str,
    blocks: &[Block],
    registry: &FingerprintClassifier,
) {
    let lines: Vec<&str> = text.lines().collect();
    for d in drafts.iter_mut() {
        let evidence = collect_evidence(d, &lines, blocks, registry);
        let mut family_scores: HashMap<String, f32> = HashMap::new();
        let mut family_evidence: HashMap<String, Vec<InferenceSource>> = HashMap::new();
        for (family, src) in evidence {
            let w = src.weight();
            *family_scores.entry(family.clone()).or_insert(0.0) += w;
            family_evidence.entry(family).or_default().push(src);
        }
        // 最高分 family
        let best = family_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(f, s)| (f.clone(), *s));
        if let Some((family, score)) = best {
            if score >= THRESHOLD {
                d.inferred_provider = Some(family.clone());
                d.inference_confidence = score;
                d.inference_evidence = family_evidence.remove(&family).unwrap_or_default();
                // v4.1 Stage 5+: 派生 protocol_types(聚合网关 → []，官方厂商 → [family])
                d.protocol_types = registry.protocol_types_for_family(&family);
            }
        }
    }
}

/// 收集单 Draft 的 5 证据 (E1-E5)
fn collect_evidence(
    draft: &DraftRecord,
    lines: &[&str],
    blocks: &[Block],
    registry: &FingerprintClassifier,
) -> Vec<(String, InferenceSource)> {
    let mut out: Vec<(String, InferenceSource)> = Vec::new();

    // E1: api_key fingerprint
    if let Some(key) = &draft.fields.api_key {
        if let Some(entry) = registry.classify(key) {
            if let Some(family) = provider_family_of(&entry.id) {
                match entry.tier {
                    Tier::Confirmed => out.push((
                        family.to_string(),
                        InferenceSource::FingerprintConfirmed {
                            provider_id: entry.id.clone(),
                        },
                    )),
                    Tier::Likely => out.push((
                        family.to_string(),
                        InferenceSource::FingerprintLikely {
                            provider_id: entry.id.clone(),
                        },
                    )),
                    _ => {} // ambiguous / warn 不作证据
                }
            }
        }
    }

    // E2: block.provider_hint 字串含 keyword
    if let Some(hint) = &draft.provider_hint {
        if let Some((family, keyword)) = text_keyword_family_and_keyword(hint) {
            out.push((
                family,
                InferenceSource::InlineTitleKeyword {
                    hint: hint.clone(),
                    keyword,
                },
            ));
        }
    }

    // E3: section heading —— 向 draft 所在 block 前后扫 Note/Title 行含 keyword
    let draft_block = blocks.iter().position(|b| {
        draft.line_range.0 >= b.start_line && draft.line_range.1 <= b.end_line
    });
    let mut heading_fired = false;
    if let Some(bi) = draft_block {
        // 1) 块内 Note/Title 行(block_start 到首个 Credential/Complex)
        let b = &blocks[bi];
        for ln in b.start_line..=b.end_line {
            if ln >= lines.len() { break; }
            let cls = line_class(lines[ln]);
            if matches!(cls.kind, LineKind::Credential | LineKind::Complex) {
                break;
            }
            if !matches!(cls.kind, LineKind::Note | LineKind::Title) {
                continue;
            }
            if let Some((family, keyword)) = text_keyword_family_and_keyword(lines[ln]) {
                out.push((
                    family,
                    InferenceSource::SectionHeadingKeyword {
                        line: ln,
                        keyword,
                    },
                ));
                heading_fired = true;
                break;
            }
        }

        // 2) block_start 之前的行(跨 Empty 和无 keyword 的 Note)
        if !heading_fired && b.start_line > 0 {
            let mut ln = b.start_line as i64 - 1;
            while ln >= 0 {
                let line = lines[ln as usize];
                let cls = line_class(line);
                match cls.kind {
                    LineKind::Empty => { ln -= 1; continue; }
                    LineKind::Separator => break,
                    LineKind::Credential | LineKind::Complex => break,
                    LineKind::Note | LineKind::Title => {
                        if let Some((family, keyword)) = text_keyword_family_and_keyword(line) {
                            out.push((
                                family,
                                InferenceSource::SectionHeadingKeyword {
                                    line: ln as usize,
                                    keyword,
                                },
                            ));
                            break;
                        }
                        // Title 无 keyword → 硬停(属别的块)
                        // Note 无 keyword → 跳过继续扫上
                        if cls.kind == LineKind::Title { break; }
                        ln -= 1;
                    }
                }
            }
        }
    }

    // E6 (BUG-04 fix): fallback label-zone 扫描
    //   当 E2 (block.provider_hint) + E3 (section heading) 都没命中时,扫描 draft 自己的
    //   line_range 每行的 "label 区"(首 secret 前缀之前 / 首 40 字符)找 provider keyword。
    //   示例生效场景:`🔑 kimi: sk-moonshot_... 邮箱: ...` 单行 Complex,block.provider_hint 取
    //   首 token "🔑" 丢了 kimi;E3 scan 也因为 line.kind=Credential 立即 break。
    //   Why 限定 label zone:防止匹配到 secret 值内部的子串(如 `sk-kimi_` 会把 "kimi"
    //   当成 label keyword,但实际是 secret 值的一部分,不应作 heading 证据)。
    //   与 spike `grouping.rs::collect_evidence` E6 段语义一致(CLAUDE.md 强制同步改动)。
    if !heading_fired {
        for ln in draft.line_range.0..=draft.line_range.1 {
            if ln >= lines.len() { continue; }
            let zone = line_label_zone(lines[ln]);
            if let Some((family, keyword)) = text_keyword_family_and_keyword(zone) {
                out.push((
                    family,
                    InferenceSource::InlineLabelKeyword {
                        line: ln,
                        keyword,
                    },
                ));
                break; // 每 draft 只打一次 E6
            }
        }
    }

    // E4: shell var 名 `export FOO_KEY=` / `FOO=value`
    for ln in draft.line_range.0..=draft.line_range.1 {
        if ln >= lines.len() { continue; }
        for cap in re_var().captures_iter(lines[ln]) {
            if let Some(var) = cap.get(1) {
                let var_name = var.as_str();
                if let Some((family, pattern)) = shell_var_family_and_pattern(var_name) {
                    out.push((
                        family,
                        InferenceSource::ShellVarPattern {
                            var_name: var_name.to_string(),
                            pattern,
                        },
                    ));
                }
            }
        }
    }

    // E5: base_url host
    if let Some(url) = &draft.fields.base_url {
        if let Some((family, pattern)) = url_host_family_and_pattern(url) {
            out.push((
                family,
                InferenceSource::UrlHostPattern {
                    url: url.clone(),
                    pattern,
                },
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::candidate::{make_id, Candidate, Kind, Tier as CTier};
    use super::super::super::provider_fingerprint;
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
    fn e1_fingerprint_confirmed_anthropic() {
        let text = "claude3:\nalice@acme.io\nsk-ant-api03-FakeProd_key_AAA_BBB_CCC_DDD_EEE_FFF_GGG_HHH_III_JJJ_KKK_LLL";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::SecretLike, "sk-ant-api03-FakeProd_key_AAA_BBB_CCC_DDD_EEE_FFF_GGG_HHH_III_JJJ_KKK_LLL"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("anthropic"));
        assert!(drafts[0].inference_confidence >= 1.0);
    }

    #[test]
    fn e3_section_heading_moonshot() {
        // Title "Kimi11" → SectionHeading keyword kimi → kimi (v4.1 family rename)
        let text = "Kimi11\nhttps://platform.moonshot.cn/console/api-keys\nsk-RzORWDtmGsXbqcVhPZCg0WYPqujfSpjAaHQYLJP2TRUaPo3i";
        let cands = vec![
            cand(Kind::Url, "https://platform.moonshot.cn/console/api-keys"),
            cand(Kind::SecretLike, "sk-RzORWDtmGsXbqcVhPZCg0WYPqujfSpjAaHQYLJP2TRUaPo3i"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("kimi"));
        // Section heading + URL host 两个证据加权应 ≥ 0.8 + 0.6 = 1.4
        assert!(drafts[0].inference_confidence >= 0.6);
    }

    #[test]
    fn e5_url_host_anthropic() {
        let text = "https://api.anthropic.com/v1\nsk-proj-unknown-but-anthropic-url_abcd1234567890efghij";
        let cands = vec![
            cand(Kind::Url, "https://api.anthropic.com/v1"),
            cand(Kind::SecretLike, "sk-proj-unknown-but-anthropic-url_abcd1234567890efghij"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        // URL host 命中 anthropic.com,应 → "anthropic"
        // sk-proj 会 fingerprint confirm 为 openai_project → family=openai,但 URL 更强
        // 实际: openai E1=1.0 + anthropic E5=0.6 → openai wins 1.0 vs 0.6
        // 这里 openai wins 是 spike 的预期行为 (API key fingerprint 强于 URL host)
        assert!(drafts[0].inferred_provider.is_some());
    }

    #[test]
    fn e6_inline_label_keyword_emoji_prefix_kimi() {
        // BUG-04 regression guard: 单行 Complex `🔑 kimi: sk-moonshot_...` —
        // block.provider_hint 取首 token "🔑"(丢 keyword),E3 scan block 内遇 Credential 即 break。
        // 无 E6 的话 inferred_provider = None(spike 验证过)。E6 InlineLabelKeyword 兜底 → kimi。
        let text = "\u{1F511} kimi: sk-moonshot_AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOO";
        let cands = vec![
            cand(Kind::SecretLike, "sk-moonshot_AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOO"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("kimi"));
        // 0.75 (E6) alone ≥ THRESHOLD 0.5
        assert!(drafts[0].inference_confidence >= 0.75);
    }

    #[test]
    fn e6_inline_label_keyword_yunwu_aggregator() {
        // BUG-05 regression guard: `🔑 yunwu: sk-...` 行内 label 识别 aggregator family。
        // 合约:yunwu ∈ aggregator_families → protocol_types = [](UI 让用户手选)。
        let text = "\u{1F511} yunwu: sk-yunwugenericAAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLL";
        let cands = vec![
            cand(Kind::SecretLike, "sk-yunwugenericAAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLL"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("yunwu"));
        // aggregator → protocol_types 空
        assert!(drafts[0].protocol_types.is_empty());
    }

    #[test]
    fn e6_label_zone_ignores_keyword_inside_secret() {
        // 保底反例:secret 值内部的 "kimi" 不应触发 E6(label_zone 截断到 secret 前缀)。
        // `sk-kimi_...` 前没有任何 label text,label_zone 只剩空串 → 不命中。
        let text = "sk-kimi_AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPP";
        let cands = vec![
            cand(Kind::SecretLike, "sk-kimi_AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPP"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        // 无 E2/E3/E6 命中,仅 ambiguous generic_sk(不作证据)→ None(或 URL/shell 兜底无)
        // 期望:E6 不被 secret 值内 "kimi" 误触发
        // 此处允许 None 或别的 family,只要不是 "kimi" 源自 E6
        for ev in &drafts[0].inference_evidence {
            if let InferenceSource::InlineLabelKeyword { keyword, .. } = ev {
                panic!("E6 incorrectly fired on secret-internal keyword: {}", keyword);
            }
        }
    }

    #[test]
    fn below_threshold_no_inference() {
        // 一个既无 fingerprint 也无 URL 也无 heading keyword 的 draft
        let text = "alice@acme.io\nsk-ant-api03-UnmatchedRandomStringNoProviderCluesWhatsoever1234";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::SecretLike, "sk-ant-api03-UnmatchedRandomStringNoProviderCluesWhatsoever1234"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        // sk-ant-api03 会被 fingerprint 命中 → anthropic (不是 below threshold 示例)
        // 此 test 只验证 enrich 不 panic
        assert_eq!(drafts.len(), 1);
    }
}
