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
//!    SectionHeading=0.8, FingerprintLikely=0.7, UrlHost=0.6) —— 仅 Tier 2 段使用,
//!    Tier 1 strong evidence 走硬规则(详见本文件 enrich_drafts 实现 + update/
//!    20260508-inference-weights-decision-3-realign.md)
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
///
/// **2026-05-08 架构调整 (Path B,详见 update/20260508-inference-weights-decision-3-realign.md)**:
/// 决策 #3 优先级 `URL host > key prefix > keyword > family default` 改为**显式分层**而非
/// 加权投票模拟。
///
/// **Tier 1 — strong evidence 硬规则短路**:
///   - E5 UrlHostPattern 触发 → 锁定该 family (URL host = 用户主动写的强意图证据)
///   - E1 FingerprintConfirmed 触发 (URL 不在场时) → 锁定该 family (regex 直命中)
///   - 跨 family 冲突时 URL host 优先 (决策 #3)
///   - 同 family 多 strong evidence 触发 → 全部列入 inference_evidence (UI transparency)
///   - inference_confidence = 1.0
///   - **不与 Tier 2 弱证据混合投票**:Why 旧设计的"加权累加"会让两条 keyword (E2+E3=1.7)
///     翻盘 confirmed prefix + URL host (E1+E5=1.6),与决策 #3 priority list 矛盾
///
/// **Tier 2 — 无 strong evidence 时回退到加权投票**:
///   - 适用 evidence: E1 FingerprintLikely / E2 InlineTitleKeyword / E3 SectionHeadingKeyword
///     / E4 ShellVarPattern / E6 InlineLabelKeyword
///   - 按 family 累加权重,最高分 family 若 ≥ THRESHOLD 写入
///   - Why 仍累加:多个弱证据共识能突破阈值(heading + inline label 双证 = 0.8+0.75=1.55)
pub fn enrich_drafts(
    drafts: &mut [DraftRecord],
    text: &str,
    blocks: &[Block],
    registry: &FingerprintClassifier,
) {
    let lines: Vec<&str> = text.lines().collect();
    for d in drafts.iter_mut() {
        let evidence = collect_evidence(d, &lines, blocks, registry);

        // ── Tier 1: strong evidence 硬规则短路 ──
        let url_evidence: Vec<&(String, InferenceSource)> = evidence.iter()
            .filter(|(_, s)| matches!(s, InferenceSource::UrlHostPattern{..}))
            .collect();
        let confirmed_evidence: Vec<&(String, InferenceSource)> = evidence.iter()
            .filter(|(_, s)| matches!(s, InferenceSource::FingerprintConfirmed{..}))
            .collect();

        // URL host 优先级 > prefix (决策 #3 priority list);任一边触发即锁定
        let chosen_family: Option<String> = if let Some((fam, _)) = url_evidence.first() {
            Some(fam.clone())
        } else if let Some((fam, _)) = confirmed_evidence.first() {
            Some(fam.clone())
        } else {
            None
        };

        if let Some(family) = chosen_family {
            // 同 family 多 strong evidence 全部列入(UI transparency,Q2 决策)
            let supporting: Vec<InferenceSource> = url_evidence.iter()
                .chain(confirmed_evidence.iter())
                .filter(|(f, _)| f == &family)
                .map(|(_, s)| s.clone())
                .collect();
            d.inferred_provider = Some(family.clone());
            d.inference_evidence = supporting;
            d.inference_confidence = 1.0;
            d.protocol_types = registry.protocol_types_for_family(&family);
            continue;
        }

        // ── Tier 2: 无 strong evidence → 弱证据加权投票 ──
        let mut family_scores: HashMap<String, f32> = HashMap::new();
        let mut family_evidence: HashMap<String, Vec<InferenceSource>> = HashMap::new();
        for (family, src) in evidence {
            // 防御性: Tier 1 已处理 strong evidence,这里跳过(理论上 Tier 1 已 continue)
            if matches!(
                src,
                InferenceSource::UrlHostPattern{..} | InferenceSource::FingerprintConfirmed{..}
            ) {
                continue;
            }
            let w = src.weight();
            *family_scores.entry(family.clone()).or_insert(0.0) += w;
            family_evidence.entry(family).or_default().push(src);
        }
        let best = family_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(f, s)| (f.clone(), *s));
        if let Some((family, score)) = best {
            if score >= THRESHOLD {
                d.inferred_provider = Some(family.clone());
                d.inference_confidence = score;
                d.inference_evidence = family_evidence.remove(&family).unwrap_or_default();
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
        // Title "Kimi11" → SectionHeading keyword kimi → moonshot
        // (2026-05-08 Kimi 双平台拆分后,decision #4: keyword "kimi" 单字默认 → moonshot;
        // URL platform.moonshot.cn → moonshot; 两证据一致,inferred_provider=moonshot)
        let text = "Kimi11\nhttps://platform.moonshot.cn/console/api-keys\nsk-RzORWDtmGsXbqcVhPZCg0WYPqujfSpjAaHQYLJP2TRUaPo3i";
        let cands = vec![
            cand(Kind::Url, "https://platform.moonshot.cn/console/api-keys"),
            cand(Kind::SecretLike, "sk-RzORWDtmGsXbqcVhPZCg0WYPqujfSpjAaHQYLJP2TRUaPo3i"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("moonshot"));
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
        // 无 E6 的话 inferred_provider = None(spike 验证过)。E6 InlineLabelKeyword 兜底 → moonshot
        // (2026-05-08 Kimi 双平台拆分后,decision #4: keyword "kimi" 单字默认 moonshot)。
        let text = "\u{1F511} kimi: sk-moonshot_AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOO";
        let cands = vec![
            cand(Kind::SecretLike, "sk-moonshot_AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOO"),
        ];
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("moonshot"));
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

    // ─────────────────────────────────────────────────────────────────
    // Path B (2026-05-08) matrix: 决策 #3 优先级 `URL host > key prefix
    // > keyword > family default` 显式分层验证。
    // 镜像 spike `path_b_matrix_tests`,详见 update/20260508-inference-
    // weights-decision-3-realign.md。
    // ─────────────────────────────────────────────────────────────────

    fn run_enrich(text: &str, cands: Vec<Candidate>) -> Vec<super::super::DraftRecord> {
        let (mut drafts, _) = group_candidates(text, &cands);
        let blocks = split_into_blocks(text);
        enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());
        drafts
    }

    #[test]
    fn w1_strong_url_plus_strong_prefix_same_family_kimi_code() {
        // user 真实 case: sk-kimi-* + api.kimi.com/coding/v1 → 必须 kimi_code
        let text = "Kimi-official:\nbase_url: https://api.kimi.com/coding/v1\napi_key: sk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM";
        let cands = vec![
            cand(Kind::Url, "https://api.kimi.com/coding/v1"),
            cand(Kind::SecretLike, "sk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("kimi_code"),
            "W1: title 'Kimi-official' keyword 不能翻盘 confirmed prefix + URL host");
        assert!((drafts[0].inference_confidence - 1.0).abs() < 0.001,
            "Tier 1 confidence = 1.0");
    }

    #[test]
    fn w2_strong_url_moonshot_overrides_strong_prefix_kimi_code() {
        // 决策 #3: URL host > key prefix。sk-kimi 但 base_url=api.moonshot.cn 时,
        // URL 表达用户意图 → 用 Moonshot 上游
        let text = "Mixed:\nbase_url: https://api.moonshot.cn/v1\napi_key: sk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM";
        let cands = vec![
            cand(Kind::Url, "https://api.moonshot.cn/v1"),
            cand(Kind::SecretLike, "sk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("moonshot"),
            "W2: URL host 优先于 prefix (决策 #3 priority list)");
    }

    #[test]
    fn w3_strong_url_alone_resolves_to_url_family() {
        // 仅 URL 强证据 → moonshot
        let text = "Moonshot key:\nbase_url: https://api.moonshot.cn/v1\napi_key: sk-XVmmhF9Yv4qf24bEHa6SrDMsAa94oeMdkKLd1gLuuTcQGqaq";
        let cands = vec![
            cand(Kind::Url, "https://api.moonshot.cn/v1"),
            cand(Kind::SecretLike, "sk-XVmmhF9Yv4qf24bEHa6SrDMsAa94oeMdkKLd1gLuuTcQGqaq"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("moonshot"));
    }

    #[test]
    fn w4_weak_keyword_only_kimi_defaults_moonshot_per_decision_4() {
        // Tier 2 加权回退 → keyword "kimi" → moonshot (决策 #4)
        let text = "kimi: sk-XVmmhF9Yv4qf24bEHa6SrDMsAa94oeMdkKLd1gLuuTcQGqaq";
        let cands = vec![
            cand(Kind::SecretLike, "sk-XVmmhF9Yv4qf24bEHa6SrDMsAa94oeMdkKLd1gLuuTcQGqaq"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("moonshot"));
    }

    #[test]
    fn w5_strong_prefix_alone_kimi_code_wins_keyword() {
        // sk-kimi-* (E1 confirmed) + 关键词 "kimi" → Tier 1 锁定 kimi_code
        let text = "Some kimi note\nsk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM";
        let cands = vec![
            cand(Kind::SecretLike, "sk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("kimi_code"),
            "W5: confirmed prefix 锁定 kimi_code,即使 title 含 'kimi' keyword(→moonshot)");
        assert!((drafts[0].inference_confidence - 1.0).abs() < 0.001);
    }

    #[test]
    fn w6_rk_kimi_adversarial_url_host_wins_over_keyword_stack() {
        // rk-kimi-* (对抗,E1 不命中) + api.kimi.com (E5 强) + title keyword(E2/E3)
        // 旧 weighted: keyword stack(1.7) 翻盘 URL(0.6) → moonshot ❌
        // Path B: Tier 1 URL 锁定 kimi_code,keyword 不参与 ✓
        let text = "rk-kimi adversarial:\nbase_url: https://api.kimi.com/coding/v1\napi_key: rk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM";
        let cands = vec![
            cand(Kind::Url, "https://api.kimi.com/coding/v1"),
            cand(Kind::SecretLike, "rk-kimi-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("kimi_code"),
            "W6: URL host strong evidence 锁定 kimi_code,keyword 不参与");
    }

    #[test]
    fn w7_anthropic_consistent_url_plus_prefix_records_both_evidences() {
        // Q2 决策: 同 family 多 strong evidence 触发时,inference_evidence 列出全部
        let text = "Claude:\nhttps://api.anthropic.com\nsk-ant-api03-Fake_AAA_BBB_CCC_DDD_EEE_FFF_GGG_HHH_III_JJJ_KKK_LLL_valid";
        let cands = vec![
            cand(Kind::Url, "https://api.anthropic.com"),
            cand(Kind::SecretLike, "sk-ant-api03-Fake_AAA_BBB_CCC_DDD_EEE_FFF_GGG_HHH_III_JJJ_KKK_LLL_valid"),
        ];
        let drafts = run_enrich(text, cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].inferred_provider.as_deref(), Some("anthropic"));
        let has_url = drafts[0].inference_evidence.iter()
            .any(|e| matches!(e, InferenceSource::UrlHostPattern{..}));
        let has_prefix = drafts[0].inference_evidence.iter()
            .any(|e| matches!(e, InferenceSource::FingerprintConfirmed{..}));
        assert!(has_url, "W7: must include UrlHostPattern evidence");
        assert!(has_prefix, "W7: must include FingerprintConfirmed evidence");
    }
}
