//! L2 Grouper — 从 V4.1 spike `grouping.rs` 迁移
//!
//! # 模块结构
//!
//! - `types`  — DraftRecord / DraftFields / DraftType / GroupReason / Block
//! - `block`  — `split_into_blocks(text)`,按 LineKind 把文本切成若干 Block
//! - `mod.rs` (本文件) — `group_candidates(text, &[Candidate])`,主入口
//!
//! # 调用合约
//!
//! 上游:`parse::rule::rule_extract(text) + parse::crf::extract(text)` 合并产出
//! `Vec<Candidate>`(扁平候选列表,每条带 kind / value / tier / source_span)。
//!
//! 本 grouper 接收扁平候选 + 原文,按 Block 切分 + Stage 1/2/3 + M4 partition 算法
//! 产出 `Vec<DraftRecord>` + 剩余 orphan `Vec<Candidate>`。
//!
//! # 算法概览 (与 V4.1 spike `grouping.rs::group_candidates` 严格对齐)
//!
//! 1. `split_into_blocks` 切 Block
//! 2. `dedup_candidates` 同 (kind, value) 去重
//! 3. `assign_candidates` 按首匹配行号分派到 block
//! 4. `merge_url_only_preambles` 把 "仅含 URL 的 block" 并到下一个含 secret 的 block
//! 5. 逐 block 跑 3 个 Stage:
//!    - **Stage 1** `SingleLineComplex` — 同行 Complex 展开多 Draft (门槛 ≥2 条)
//!    - **Stage 2** `multi-secret 分发` — ≥2 secret 时 per-secret 成 Draft + 邻行配对 email/pwd/url
//!    - **Stage 3** `Safe fallback` — 剩余字段合成 1 条 Draft,多余 secret 进 extra_secrets
//! 6. **M4 partition**: Stage 3 检测多 valid password,额外 password 展开 MultiPasswordExpand Draft
//!
//! # 设计合约
//!
//! - drafts 顺序: per-block 按 Stage 1 → Stage 2 → Stage 3,跨 block 按 block 顺序
//! - orphan 顺序: dedup 后保持 candidates 原序
//! - `DraftRecord.id` 形如 "d-1" / "d-2" ...,最后统一重编
//! - 输入 candidates slice 只读

pub mod block;
pub mod cluster;
pub mod enrich;
pub mod types;

use super::candidate::{Candidate, Kind};
use super::line_class::{line_class, LineFlags, LineKind};
use super::provider_fingerprint;
use block::split_into_blocks;
use types::{Block, DraftFields, DraftRecord, DraftType, EndpointGroup, GroupReason};

/// 完整 L2+L3 入口:candidates → drafts + groups + orphans
///
/// v4.1 Stage 4 新增 convenience,内部复用 `group_candidates` + `cluster::cluster_endpoints`。
/// 二次切块避免 (`split_into_blocks` 在 group_candidates 内部已调过一次,这里只做 L3 聚类)。
pub fn group_and_cluster(
    text: &str,
    candidates: &[Candidate],
) -> (Vec<DraftRecord>, Vec<EndpointGroup>, Vec<Candidate>) {
    let (drafts, orphans) = group_candidates(text, candidates);
    let blocks = split_into_blocks(text);
    let groups = cluster::cluster_endpoints(text, &drafts, &blocks);
    (drafts, groups, orphans)
}

/// 主入口:扁平 candidates → 分组成 drafts + orphans
pub fn group_candidates(
    text: &str,
    candidates: &[Candidate],
) -> (Vec<DraftRecord>, Vec<Candidate>) {
    let blocks = split_into_blocks(text);
    let cands = dedup_candidates(candidates);
    let (per_block, mut block_orphans) = assign_candidates(text, &blocks, &cands);

    // v4.1 B3: URL-only preamble 并入下一含 secret 的 block
    let (blocks, per_block) = merge_url_only_preambles(text, blocks, per_block);

    let mut drafts: Vec<DraftRecord> = Vec::new();
    let mut cross_orphans: Vec<Candidate> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();

    // v4.1 Stage 3 P1 perf: 预计算 value→line_index 一次,O(|text| + N_cands),
    //   Stage 2 pick / Stage 3 sort 原本各自调 value_to_line(text.find) 呈 O(N×|text|)。
    //   HashMap 键去重:多候选同 value(如重粘贴)只记首匹配,与 dedup_candidates 语义一致。
    let line_index: std::collections::HashMap<String, usize> =
        build_line_index(text, &cands);

    for (bi, block) in blocks.iter().enumerate() {
        let in_block = &per_block[bi];
        if in_block.is_empty() { continue; }

        // 用预计算表查行号;未匹配返回 usize::MAX 作"失败哨兵",下游需显式跳过
        let line_of = |c: &Candidate| {
            line_index.get(&c.value).copied().unwrap_or(usize::MAX)
        };

        let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();

        // ── Stage 1: 行级 Complex (HAS_DASH_RUN + HAS_SECRET 同行) ──
        // 门槛: block 必须 ≥2 条 Complex 行才启用 (单 Complex 走 Stage 3 合并整 block)
        let stage1_range = block.start_line..=block.end_line;
        let complex_line_count = stage1_range.clone()
            .filter(|&li| li < lines.len())
            .filter(|&li| line_class(lines[li]).kind == LineKind::Complex)
            .count();
        let stage1_enabled = complex_line_count >= 2;
        if stage1_enabled {
            for li in stage1_range.clone() {
                if li >= lines.len() { continue; }
                let lc = line_class(lines[li]);
                if lc.kind != LineKind::Complex { continue; }

                let row_cands: Vec<&Candidate> = in_block.iter()
                    .filter(|c| line_of(c) == li)
                    .collect();
                let row_email = row_cands.iter().find(|c| c.kind == Kind::Email).map(|c| c.value.clone());
                let row_pwd   = row_cands.iter().find(|c| c.kind == Kind::PasswordLike).map(|c| c.value.clone());
                let row_key   = row_cands.iter().find(|c| c.kind == Kind::SecretLike).map(|c| c.value.clone());
                let row_url   = row_cands.iter().find(|c| c.kind == Kind::Url).map(|c| c.value.clone());

                if row_email.is_none() && row_pwd.is_none() && row_key.is_none() && row_url.is_none() {
                    continue;
                }
                if let Some(e) = &row_email { consumed.insert(e.clone()); }
                if let Some(p) = &row_pwd   { consumed.insert(p.clone()); }
                if let Some(k) = &row_key   { consumed.insert(k.clone()); }
                if let Some(u) = &row_url   { consumed.insert(u.clone()); }

                let fields = DraftFields {
                    email: row_email, password: row_pwd,
                    api_key: row_key, base_url: row_url,
                    extra_secrets: vec![],
                };
                let draft_type = DraftType::classify(&fields);
                drafts.push(DraftRecord {
                    id: String::new(),
                    provider_hint: block.provider_hint.clone(),
                    fields,
                    line_range: (li, li),
                    reason: GroupReason::SingleLineComplex,
                    draft_type,
                    inferred_provider: None,
                    inference_confidence: 0.0,
                    inference_evidence: Vec::new(),
                    protocol_types: Vec::new(),
                });
            }
        }

        // ── Stage 2: 每 secret 独立成 Draft,≥2 secret 启用 ──
        let remaining_after_s1: Vec<&Candidate> = in_block.iter()
            .filter(|c| !consumed.contains(&c.value))
            .collect();

        let mut rem_secrets: Vec<&Candidate> = remaining_after_s1.iter()
            .copied()
            .filter(|c| c.kind == Kind::SecretLike)
            .collect();
        rem_secrets.sort_by_key(|c| line_of(c));

        let mut stage2_fired = false;
        if rem_secrets.len() >= 2 {
            let line_has_flag = |ln: usize, f: LineFlags| -> bool {
                if ln >= lines.len() { return false; }
                line_class(lines[ln]).flags.contains(f)
            };
            let email_rem: Vec<&Candidate> = remaining_after_s1.iter().copied().filter(|c| c.kind == Kind::Email).collect();
            let pwd_rem:   Vec<&Candidate> = remaining_after_s1.iter().copied().filter(|c| c.kind == Kind::PasswordLike).collect();
            let url_rem:   Vec<&Candidate> = remaining_after_s1.iter().copied().filter(|c| c.kind == Kind::Url).collect();

            let mut used_email: std::collections::HashSet<String> = Default::default();
            let mut used_pwd:   std::collections::HashSet<String> = Default::default();
            let mut used_url:   std::collections::HashSet<String> = Default::default();

            // URL 分发:单 URL 共享 / 多 URL per-secret 对齐
            let shared_base_url: Option<String> = if url_rem.len() == 1 {
                Some(url_rem[0].value.clone())
            } else {
                None
            };

            for sec in &rem_secrets {
                let sec_line = line_of(sec);
                // v4.1 Stage 3 P1 保护:value_to_line 失败时 sec_line=MAX,
                //   下面 `sec_line+1` 会触发 usize 溢出 panic。早退跳过该 secret。
                if sec_line == usize::MAX { continue; }
                let pick = |pool: &[&Candidate], used: &std::collections::HashSet<String>| -> Option<String> {
                    for delta in &[0i64, -1, 1] {
                        let target = sec_line as i64 + delta;
                        if target < 0 { continue; }
                        let target = target as usize;
                        for c in pool {
                            if used.contains(&c.value) { continue; }
                            if line_of(c) == target {
                                return Some(c.value.clone());
                            }
                        }
                    }
                    None
                };
                let pair_email = pick(&email_rem, &used_email);
                let pair_pwd   = pick(&pwd_rem,   &used_pwd);
                let pair_url: Option<String> = if url_rem.len() >= 2 {
                    pick(&url_rem, &used_url)
                } else {
                    shared_base_url.clone()
                };
                if let Some(e) = &pair_email { used_email.insert(e.clone()); }
                if let Some(p) = &pair_pwd   { used_pwd.insert(p.clone()); }
                if let Some(u) = &pair_url   { used_url.insert(u.clone()); }

                // 邻接条件:block 内必须有 Credential / Complex 线索,防对非凭证块误配
                let has_credential_neighbor = (sec_line.saturating_sub(1)..=sec_line+1)
                    .any(|ln| line_has_flag(ln, LineFlags::HAS_SECRET)
                        || line_has_flag(ln, LineFlags::HAS_EMAIL));
                if !has_credential_neighbor { continue; }

                consumed.insert(sec.value.clone());
                let fields = DraftFields {
                    email: pair_email,
                    password: pair_pwd,
                    api_key: Some(sec.value.clone()),
                    base_url: pair_url,
                    extra_secrets: vec![],
                };
                let draft_type = DraftType::classify(&fields);
                drafts.push(DraftRecord {
                    id: String::new(),
                    provider_hint: block.provider_hint.clone(),
                    fields,
                    line_range: (sec_line, sec_line),
                    reason: GroupReason::CredentialBlock,
                    draft_type,
                    inferred_provider: None,
                    inference_confidence: 0.0,
                    inference_evidence: Vec::new(),
                    protocol_types: Vec::new(),
                });
                stage2_fired = true;
            }
            if stage2_fired {
                if let Some(u) = &shared_base_url { consumed.insert(u.clone()); }
                for u in &used_url { consumed.insert(u.clone()); }
            }
        }

        // ── Stage 3: Safe fallback — 剩余字段合并一 Draft + M4 partition ──
        let leftover: Vec<&Candidate> = in_block.iter()
            .filter(|c| !consumed.contains(&c.value))
            .collect();
        if leftover.is_empty() { continue; }

        let mut emails: Vec<&Candidate>  = leftover.iter().copied().filter(|c| c.kind == Kind::Email).collect();
        let mut pwds:   Vec<&Candidate>  = leftover.iter().copied().filter(|c| c.kind == Kind::PasswordLike).collect();
        let mut secrets: Vec<&Candidate> = leftover.iter().copied().filter(|c| c.kind == Kind::SecretLike).collect();
        let mut urls:   Vec<&Candidate>  = leftover.iter().copied().filter(|c| c.kind == Kind::Url).collect();
        emails.sort_by_key(|c| line_of(c));
        pwds.sort_by_key(|c| line_of(c));
        secrets.sort_by_key(|c| line_of(c));
        urls.sort_by_key(|c| line_of(c));

        let email = emails.first().map(|c| c.value.clone());

        // v4.1 M4: password 按 valid/invalid partition;valid 首条主 Draft;额外 valid 展 Draft;invalid → orphan
        let is_valid_pwd = |c: &&Candidate| -> bool {
            let ln = line_of(c);
            if ln >= lines.len() { return false; }
            let lc = line_class(lines[ln]);
            match lc.kind {
                LineKind::Credential | LineKind::Complex => true,
                // Title 行受限接受:必须是 `label: value` / `label= value` 简洁标签 + 单值
                LineKind::Title => {
                    let trimmed = lines[ln].trim();
                    if let Some(pos) = trimmed.find(|c: char| c == ':' || c == '=') {
                        let label = &trimmed[..pos];
                        let value = &trimmed[pos + 1..];
                        let label_ok = !label.is_empty()
                            && label.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');
                        let value_ok = value.chars().any(|c| !c.is_whitespace());
                        label_ok && value_ok
                    } else {
                        false
                    }
                }
                LineKind::Note if lc.flags.contains(LineFlags::IS_SOLO_TOKEN) => {
                    (ln.saturating_sub(1)..=ln+1)
                        .filter(|&i| i != ln && i < lines.len())
                        .any(|i| {
                            let nlc = line_class(lines[i]);
                            matches!(nlc.kind, LineKind::Credential | LineKind::Complex)
                                || nlc.flags.contains(LineFlags::HAS_SECRET)
                                || nlc.flags.contains(LineFlags::HAS_EMAIL)
                        })
                }
                _ => false,
            }
        };
        let (valid_pwds, invalid_pwds): (Vec<&Candidate>, Vec<&Candidate>) = pwds.iter()
            .copied()
            .partition(is_valid_pwd);

        let password = valid_pwds.first().map(|c| c.value.clone());
        let extra_valid_pwds: Vec<&Candidate> = valid_pwds.iter().skip(1).copied().collect();

        for c in invalid_pwds.iter() {
            cross_orphans.push((*c).clone());
        }

        let api_key = secrets.first().map(|c| c.value.clone());
        let extra_secrets: Vec<String> = secrets.iter().skip(1).map(|c| c.value.clone()).collect();
        let base_url = urls.first().map(|c| c.value.clone());

        if email.is_none() && password.is_none() && api_key.is_none() && base_url.is_none() {
            let _ = stage2_fired;
            continue;
        }

        let reason = determine_reason(block);
        let fields = DraftFields {
            email, password, api_key, base_url, extra_secrets,
        };
        let draft_type = DraftType::classify(&fields);
        drafts.push(DraftRecord {
            id: String::new(),
            provider_hint: block.provider_hint.clone(),
            fields,
            line_range: (block.start_line, block.end_line),
            reason,
            draft_type,
            inferred_provider: None,
            inference_confidence: 0.0,
            inference_evidence: Vec::new(),
            protocol_types: Vec::new(),
        });

        // v4.1 M4: 额外合法 password 展开独立 Draft
        for extra in &extra_valid_pwds {
            let extra_ln = line_of(extra);
            // v4.1 P1 保护:行号失败 (value 不在 text) 退化到 block 首行,避免 MAX 进 line_range
            let safe_ln = if extra_ln == usize::MAX { block.start_line } else { extra_ln };
            let extra_fields = DraftFields {
                email: None,
                password: Some(extra.value.clone()),
                api_key: None,
                base_url: None,
                extra_secrets: Vec::new(),
            };
            let extra_type = DraftType::classify(&extra_fields);
            drafts.push(DraftRecord {
                id: String::new(),
                provider_hint: block.provider_hint.clone(),
                fields: extra_fields,
                line_range: (safe_ln, safe_ln),
                reason: GroupReason::MultiPasswordExpand,
                draft_type: extra_type,
                inferred_provider: None,
                inference_confidence: 0.0,
                inference_evidence: Vec::new(),
                protocol_types: Vec::new(),
            });
        }
    }

    // 重编 draft id (统一 d-{N})
    for (i, d) in drafts.iter_mut().enumerate() {
        d.id = format!("d-{}", i + 1);
    }

    // v4.1 Stage 3 L3 enrich: 填 inferred_provider / inference_confidence / evidence
    //   5 证据加权投票 (fingerprint / inline_title / section_heading / shell_var / url_host)
    //   使 UI 的 provider chip / banner / confidence bar 能正确渲染
    enrich::enrich_drafts(&mut drafts, text, &blocks, provider_fingerprint::instance());

    block_orphans.extend(cross_orphans);
    (drafts, block_orphans)
}

/// dedup:同 (kind, value) 只保留首个 Candidate + **secret 子串合并**
///
/// 与 V4.1 spike `grouping.rs::dedup_cands` 第二步对齐:
/// 同 kind=secret 的候选中,若一个是另一个的子串,删短的(长 secret 覆盖短残影)。
///
/// Why: CLI rule.rs 的 `re_hex_long` 会把 `sk-ant-api03-AAAAAAA...` 后的 64 个 A 再抽一次
/// 独立 secret。不去重 → Stage 2 误触发(≥2 secret) → 产生 FP "AAAA..." api_key draft。
fn dedup_candidates(candidates: &[Candidate]) -> Vec<Candidate> {
    // Step 1: 同 (kind, value) 去重 (保首个)
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<Candidate> = Vec::new();
    for c in candidates {
        let key = format!("{}\x00{}", c.kind.as_str(), c.value);
        if seen.insert(key) {
            out.push(c.clone());
        }
    }

    // Step 2: secret 子串合并 — 仅在 kind=SecretLike 间做,长 secret 保留,短的删
    //   按 value 长度降序扫:对每个 "大" secret,后面的更短 secret 若是子串则标删
    let mut secret_idxs: Vec<usize> = out.iter().enumerate()
        .filter(|(_, c)| c.kind == Kind::SecretLike)
        .map(|(i, _)| i)
        .collect();
    secret_idxs.sort_by_key(|&i| std::cmp::Reverse(out[i].value.len()));

    let mut delete: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (k, &big_i) in secret_idxs.iter().enumerate() {
        if delete.contains(&big_i) { continue; }
        for &small_i in secret_idxs.iter().skip(k + 1) {
            if delete.contains(&small_i) { continue; }
            if out[big_i].value.contains(&out[small_i].value) {
                delete.insert(small_i);
            }
        }
    }
    out.into_iter().enumerate()
        .filter(|(i, _)| !delete.contains(i))
        .map(|(_, c)| c)
        .collect()
}

/// 按行号分派 candidates 到各 block
fn assign_candidates(
    text: &str,
    blocks: &[Block],
    cands: &[Candidate],
) -> (Vec<Vec<Candidate>>, Vec<Candidate>) {
    let mut per_block: Vec<Vec<Candidate>> = vec![Vec::new(); blocks.len()];
    let mut orphans: Vec<Candidate> = Vec::new();

    for c in cands {
        let line = match value_to_line(text, &c.value) {
            Some(l) => l,
            None => { orphans.push(c.clone()); continue; }
        };
        let mut placed = false;
        for (bi, block) in blocks.iter().enumerate() {
            if line >= block.start_line && line <= block.end_line {
                per_block[bi].push(c.clone());
                placed = true;
                break;
            }
        }
        if !placed { orphans.push(c.clone()); }
    }
    (per_block, orphans)
}

/// v4.1 B3: 合并 "仅含 URL 的 block" 到紧邻的下一含 secret 的 block
///
/// 用户惯性 "base_url 先声明,下面列若干 KEY"。独立成 Draft 会出现 base_url-only
/// 孤立 Draft。但注意:两 block 之间若有 Separator / IS_COMMENT 则不合并。
fn merge_url_only_preambles(
    text: &str,
    mut blocks: Vec<Block>,
    mut per_block: Vec<Vec<Candidate>>,
) -> (Vec<Block>, Vec<Vec<Candidate>>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i + 1 < blocks.len() {
        let this_is_url_only = !per_block[i].is_empty()
            && per_block[i].iter().all(|c| c.kind == Kind::Url);
        let next_has_secret = per_block[i + 1].iter().any(|c| c.kind == Kind::SecretLike);

        let gap_start = blocks[i].end_line + 1;
        let gap_end = blocks[i + 1].start_line;
        let mut has_hard_boundary = false;
        for ln in gap_start..gap_end {
            if ln >= lines.len() { break; }
            let cls = line_class(lines[ln]);
            if cls.kind == LineKind::Separator
                || cls.flags.contains(LineFlags::IS_COMMENT)
            {
                has_hard_boundary = true;
                break;
            }
        }

        if this_is_url_only && next_has_secret && !has_hard_boundary {
            let urls = std::mem::take(&mut per_block[i]);
            let mut merged = urls;
            merged.extend(std::mem::take(&mut per_block[i + 1]));
            per_block[i + 1] = merged;
            blocks[i + 1].start_line = blocks[i].start_line;
            if blocks[i + 1].provider_hint.is_none() {
                blocks[i + 1].provider_hint = blocks[i].provider_hint.take();
            }
            blocks.remove(i);
            per_block.remove(i);
        } else {
            i += 1;
        }
    }
    (blocks, per_block)
}

/// value → 所在行号 (粗查首次出现)
fn value_to_line(text: &str, value: &str) -> Option<usize> {
    let pos = text.find(value)?;
    Some(text[..pos].matches('\n').count())
}

/// 预计算 value → line_index HashMap (v4.1 P1 优化)
///
/// 避免 Stage 2/3 对每个 candidate 重复调 `text.find(value)` 的 O(|text|) 扫描。
/// 一次性 O(|text| + N_cands) 构建,之后 `line_of(c)` 是 O(1) HashMap lookup。
///
/// 同 value 多次出现只记首匹配 (与 `value_to_line` 语义一致,与 V4.1 spike 对齐)。
fn build_line_index(
    text: &str,
    cands: &[Candidate],
) -> std::collections::HashMap<String, usize> {
    let mut map = std::collections::HashMap::with_capacity(cands.len());
    for c in cands {
        if map.contains_key(&c.value) { continue; }
        if let Some(line) = value_to_line(text, &c.value) {
            map.insert(c.value.clone(), line);
        }
    }
    map
}

fn determine_reason(block: &Block) -> GroupReason {
    if block.kinds.iter().any(|k| *k == LineKind::Complex)
        && block.kinds.len() <= 2
    {
        return GroupReason::SingleLineComplex;
    }
    if block.kinds.first() == Some(&LineKind::Title) {
        return GroupReason::TitleBlock;
    }
    if block.kinds.len() == 1 {
        return GroupReason::Standalone;
    }
    GroupReason::CredentialBlock
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands_internal::parse::candidate::{make_id, Tier};

    fn cand(kind: Kind, value: &str) -> Candidate {
        Candidate {
            id: make_id(kind, 1),
            kind,
            value: value.to_string(),
            tier: Tier::Confirmed,
            source_span: None,
            provider: None,
            source: None,
            status: None,
            suppress_reason: None,
        }
    }

    #[test]
    fn single_block_email_plus_key_is_oauth() {
        // v4.1 Post-Stage4: email + api_key → Oauth (account-first 语义)
        // email 的存在意味着"账号-based",api_key 是 account 颁发的 token
        let text = "claude3:\nalice@acme.io\nsk-ant-api03-AAA_BBB_CCC_ddd_eee";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::SecretLike, "sk-ant-api03-AAA_BBB_CCC_ddd_eee"),
        ];
        let (drafts, orphans) = group_candidates(text, &cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(orphans.len(), 0);
        let d = &drafts[0];
        assert_eq!(d.id, "d-1");
        assert_eq!(d.provider_hint.as_deref(), Some("claude3"));
        assert_eq!(d.fields.email.as_deref(), Some("alice@acme.io"));
        assert_eq!(d.fields.api_key.as_deref(), Some("sk-ant-api03-AAA_BBB_CCC_ddd_eee"));
        assert_eq!(d.draft_type, DraftType::Oauth);
    }

    #[test]
    fn two_blocks_two_drafts() {
        let text = "claude2:\nalice@acme.io\nsk-ant-api03-xxxYYYzzz1234\n\nopenai:\nbob@test.io\nsk-proj-MMM_NNN_KLmnop123";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::SecretLike, "sk-ant-api03-xxxYYYzzz1234"),
            cand(Kind::Email, "bob@test.io"),
            cand(Kind::SecretLike, "sk-proj-MMM_NNN_KLmnop123"),
        ];
        let (drafts, _orphans) = group_candidates(text, &cands);
        assert_eq!(drafts.len(), 2);
        assert_eq!(drafts[0].provider_hint.as_deref(), Some("claude2"));
        assert_eq!(drafts[1].provider_hint.as_deref(), Some("openai"));
    }

    #[test]
    fn stage_1_single_line_complex_multi_draft() {
        // 两条同行 email----pwd----secret,每条独立 Draft
        let text = "alice@acme.io----pwd1----sk-ant-api03-AAA_BBB_CCC_ddd_eee\nbob@test.io----pwd2----sk-proj-MMM_NNN_KLmnop123";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::PasswordLike, "pwd1"),
            cand(Kind::SecretLike, "sk-ant-api03-AAA_BBB_CCC_ddd_eee"),
            cand(Kind::Email, "bob@test.io"),
            cand(Kind::PasswordLike, "pwd2"),
            cand(Kind::SecretLike, "sk-proj-MMM_NNN_KLmnop123"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        assert_eq!(drafts.len(), 2);
        assert_eq!(drafts[0].reason as u8, GroupReason::SingleLineComplex as u8);
        assert_eq!(drafts[0].fields.email.as_deref(), Some("alice@acme.io"));
        assert_eq!(drafts[1].fields.email.as_deref(), Some("bob@test.io"));
    }

    #[test]
    fn oauth_email_password_no_apikey() {
        let text = "claude2:\nalice@acme.io----hunter2";
        let cands = vec![
            cand(Kind::Email, "alice@acme.io"),
            cand(Kind::PasswordLike, "hunter2"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].draft_type, DraftType::Oauth);
    }

    #[test]
    fn multi_password_partition() {
        // M4 canary 风格:1 email + 2 pwd + 1 secret → 主 Draft + extra pwd Draft
        let text = "ops@acme.io\npwd: h4n7er_A\npwd: h4n7er_B\nsk-ant-api03-XYZ_YYY_ZZZ_1234567890abcdef";
        let cands = vec![
            cand(Kind::Email, "ops@acme.io"),
            cand(Kind::PasswordLike, "h4n7er_A"),
            cand(Kind::PasswordLike, "h4n7er_B"),
            cand(Kind::SecretLike, "sk-ant-api03-XYZ_YYY_ZZZ_1234567890abcdef"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        // 主 Draft (email + pwd_A + secret) + MultiPasswordExpand (pwd_B)
        assert!(drafts.len() >= 2, "got {} drafts: {:?}", drafts.len(), drafts);
        let has_expand = drafts.iter().any(|d| matches!(d.reason, GroupReason::MultiPasswordExpand));
        assert!(has_expand, "expected MultiPasswordExpand draft");
    }

    #[test]
    fn empty_input_empty_output() {
        let (d, o) = group_candidates("", &[]);
        assert_eq!(d.len(), 0);
        assert_eq!(o.len(), 0);
    }

    #[test]
    fn url_only_preamble_merges_to_next_secret_block() {
        // block 1: URL only; block 2: secret → 合并
        let text = "https://api.anthropic.com/v1\n\nsk-ant-api03-AAA_BBB_CCC_ddd_eee";
        let cands = vec![
            cand(Kind::Url, "https://api.anthropic.com/v1"),
            cand(Kind::SecretLike, "sk-ant-api03-AAA_BBB_CCC_ddd_eee"),
        ];
        let (drafts, _) = group_candidates(text, &cands);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].fields.base_url.as_deref(), Some("https://api.anthropic.com/v1"));
        assert_eq!(drafts[0].fields.api_key.as_deref(), Some("sk-ant-api03-AAA_BBB_CCC_ddd_eee"));
    }
}
