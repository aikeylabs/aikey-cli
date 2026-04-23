//! `_internal parse`：文本解析入口（三层流水：规则 v2 + CRF + Provider Fingerprint）
//!
//! # Phase 2 （本 revision）
//! - ✅ 规则层 v2：基础 regex + label=value + PEM + 邮箱/secret 锚点（4 层）
//! - ⏸ CRF：Phase 4 接入
//! - ⏸ Fingerprint：Phase 3 接入
//!
//! # 模块结构
//! ```
//! commands_internal/parse.rs    ← 本文件，handle() 入口 + 响应组装
//! commands_internal/parse/
//! ├── candidate.rs   ← Candidate / Kind / Tier / ProviderGuess
//! ├── tokenize.rs    ← tokenize_line 扩展分隔符 + markdown 清理
//! ├── rule.rs        ← Layer 1 协调器 + 基础 regex + dash/pipe/label password 启发式
//! ├── rule_labeled.rs ← Layer 2 label=value 通用提取
//! ├── rule_pem.rs    ← Layer 3 PEM 多行块
//! └── rule_anchored.rs ← Layer 4 邮箱/secret 锚点 password 召回（B 方案）
//! ```
//!
//! # 协议
//! 见 `protocol.rs` StdinEnvelope + 本模块响应 schema（参考 批量导入-最终方案-v2.md §5.3）
//!
//! # 安全
//! parse 对 vault **零操作**（不读不写不解密）。但仍然要求 stdin 包含 vault_key_hex（协议一致性）。
//! 只校验 vault_key_hex 格式合法，不校验是否匹配 vault（parse 不需要解锁）。

pub mod candidate;
pub mod tokenize;
pub mod rule;
pub mod rule_labeled;
pub mod rule_pem;
pub mod rule_anchored;
// v4.2 Layer 5: block-first-line natural-language title extraction.
// Emits Kind::Title candidates which the grouper attaches to the draft owning
// the same block (by line_range overlap). Doesn't touch credential recall —
// see TITLE_ABLATION_REPORT for zero-regression validation on 5 dimensions.
pub mod rule_title;
pub mod provider_fingerprint;
pub mod crf;
// v4.1 spike migration (Stage 1): line_class 基础设施 —— LineKind 6 类 + LineFlags 9 bit
// 现阶段未被 rule/candidate 主干消费；Stage 2-3 并入。
pub mod line_class;
// v4.1 Stage 2a 守门工具集: ISSUE-4 IS_COMMENT / ISSUE-3 CJK / Placeholder denylist
pub mod v41_guards;
// Stage 0 placeholder for v4.1 spike migration (L2 grouper + L3 cluster)
// Actual code lands in Stage 3/4. See tests/fixtures/v41_spike_baseline.json.
pub mod grouping;

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::{decode_vault_key, emit, emit_error};

// ========== payload ==========

#[derive(Debug, Deserialize)]
struct ParsePayload {
    /// 用户粘贴的原文文本
    text: String,
    /// 来源（可选，仅用于日志/审计）："paste" | "file"
    #[serde(default)]
    #[allow(dead_code)]
    source_type: Option<String>,
    /// 批量 provider 提示（可选，Go 侧基于同文档聚合判断）
    #[serde(default)]
    #[allow(dead_code)]
    batch_provider_hint: Option<String>,
    /// 候选数量上限（防止超长文本 DoS）；默认 5000
    #[serde(default = "default_max_candidates")]
    max_candidates: usize,
}

fn default_max_candidates() -> usize { 5000 }

/// 文本字节上限:1 MiB。
///
/// **Why**: `ParsePayload.text` 完整入内存,regex/CRF/grouping 各层按 byte-index 扫描。
/// 无上限时 10 MiB+ 粘贴文本会线性放大到多份 `Vec<&str>` / `Vec<Candidate>`,构成
/// DoS / OOM 面(评审 R-1, 2026-04-22 生产代码评审)。1 MiB 与 Go 端请求体软 cap 对齐,
/// 且远大于真实使用场景(~100 行 .env 文件,典型 3-10 KiB)。
pub const MAX_TEXT_BYTES: usize = 1 << 20;

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    // 协议一致性：vault_key_hex 必须格式合法（但不需要匹配 vault）
    if let Err((c, m)) = decode_vault_key(&env.vault_key_hex) {
        emit_error(req_id, c, m);
        return;
    }

    let payload: ParsePayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("parse payload: {}", e)); return; }
    };
    if payload.text.is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "parse requires non-empty text");
        return;
    }
    if payload.text.len() > MAX_TEXT_BYTES {
        emit_error(
            req_id,
            "I_PARSE_TEXT_TOO_LARGE",
            format!(
                "text exceeds {} bytes (got {}); split the paste into smaller chunks",
                MAX_TEXT_BYTES,
                payload.text.len()
            ),
        );
        return;
    }

    match run_parse_v2_rules(&payload) {
        Ok(result) => emit(&ResultEnvelope::ok(req_id, result)),
        Err((c, m)) => emit_error(req_id, c, m),
    }
}

// ========== v2 rules pipeline (Phase 2) ==========

/// Phase 2 实现：规则层 4 子层全部启用；CRF / Fingerprint 仍 disabled。
///
/// Stage 3 Phase 3/4 会逐步替换：
/// - Phase 3: 对每个 `secret_like` 候选跑 H 层 Fingerprint classifier → 填 `provider` 字段 + 调整 tier
/// - Phase 4: 加 CRF + shape filter 层 → 补 `suggested` tier 候选
fn run_parse_v2_rules(payload: &ParsePayload) -> Result<serde_json::Value, (&'static str, String)> {
    let text = &payload.text;
    let max = payload.max_candidates;

    // === 四层规则 ===
    let mut all = rule::rule_extract(text);

    // === CRF Phase 4 补充层：长尾 shape 候选（suggested tier，UI 默认不勾选）===
    // CRF 对"规则漏检的混合 hex secret"（如 `d853aXYZ999`）有补救作用；
    // 命中 shape filter 才保留，避免 narrative 里 UUID 误判成 key。
    //
    // 去重策略：同 (kind, value) 已被规则抓到则跳过 —— confirmed tier 优先保留。
    let rule_seen: std::collections::HashSet<String> = all.iter()
        .map(|c| format!("{}\x00{}", c.kind.as_str(), c.value))
        .collect();
    for crf_cand in crf::extract(text) {
        let key = format!("{}\x00{}", crf_cand.kind.as_str(), crf_cand.value);
        if rule_seen.contains(&key) { continue; }
        if all.len() >= max { break; }
        all.push(crf_cand);
    }

    // 限流（超大文本 DoS 防护）
    if all.len() > max { all.truncate(max); }

    // 重新编号 id（规则内部的 seq 和最终顺序可能不同，保证 id 稳定）
    for (i, c) in all.iter_mut().enumerate() {
        c.id = candidate::make_id(c.kind, i + 1);
    }

    // === H 层 Provider Fingerprint（Phase 3）===
    // 对每个 secret_like 候选跑分类器，填 provider 字段 + 调整 tier。
    // 用同文档 URL 域名做 ambiguous 消歧（比如 sk-* + moonshot.cn → kimi）。
    let url_domains: Vec<String> = all.iter()
        .filter(|c| c.kind == candidate::Kind::Url)
        .filter_map(|c| extract_url_domain(&c.value))
        .collect();

    let classifier = provider_fingerprint::instance();
    for c in all.iter_mut() {
        if c.kind != candidate::Kind::SecretLike { continue; }
        let (entry, suggest) = classifier.classify_with_context(&c.value, &url_domains);
        if let Some(e) = entry {
            let final_id = suggest.clone().unwrap_or_else(|| e.id.clone());
            // Tier 映射：warn tier 的 secret（UUID / 短 hex）候选升级为 Warn
            // 避免 UI 默认勾选导入一个 UUID 当作凭证
            if e.tier == provider_fingerprint::Tier::Warn {
                c.tier = candidate::Tier::Warn;
            }
            c.provider = Some(candidate::ProviderGuess {
                id: final_id,
                display: e.display.clone(),
                tier: match e.tier {
                    provider_fingerprint::Tier::Confirmed => candidate::ProviderTier::Confirmed,
                    provider_fingerprint::Tier::Likely    => candidate::ProviderTier::Confirmed,
                    provider_fingerprint::Tier::Ambiguous => candidate::ProviderTier::Ambiguous,
                    provider_fingerprint::Tier::Warn      => candidate::ProviderTier::Warn,
                },
                hint: e.hint.clone(),
                siblings: e.siblings.clone(),
            });
        }
        // 未命中 → provider 保持 None，UI 展示 "unknown, 请手动选择"
    }

    let source_hash = {
        let mut h = Sha256::new();
        h.update(text.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    };

    // === Stage 3 Phase D + Stage 4: L2 grouper + L3 endpoint cluster ===
    // L2:扁平 candidates → DraftRecord
    // L3:Draft → EndpointGroup (按 provider+base_url 聚合)
    //
    // 合约:
    //   - drafts[].fields 字段名与 V4.1 spike 对齐 (email/password/api_key/base_url/extra_secrets)
    //   - groups[] 每组含 member_draft_ids[] 指回 drafts。UI 可按 group 分层渲染
    //   - 老客户端不消费 drafts/groups 字段仍工作
    let (mut drafts, groups, orphan_cands) = grouping::group_and_cluster(text, &all);

    // v4.1 Stage 6+ / Stage 8 / Stage 11: 为每个 draft 生成 unique suggested alias
    //
    //   OAuth 类(DraftType::Oauth) 且有 email:
    //     - 直接用 email 作 alias(冲突时加 `-2`/`-3` 后缀)
    //     - Why: done 页 `aikey auth login <p> --alias <email>` 语义自然,
    //       login 成功后 display_identity 就是用户熟悉的 email
    //
    //   其他(KEY 类 或 OAuth 无 email):
    //     模板 `{provider}_{type}_{N}`
    //     provider = inferred_provider / provider_hint / "import"(sanitized)
    //     type     = "oauth" | "key"(对应 DraftType)
    //     N        = 1..  递增直到与 vault 现有 aliases + 本 batch 其他 draft 不冲突
    //     例:`openai_oauth_1`,`anthropic_key_1`,`kimi_key_2`(vault 已有 kimi_key_1)
    //
    // Why 这里做不在 group_and_cluster 里:grouper 层是纯文本算法,不依赖 vault 状态;
    // alias 生成属于"与本机 vault 对齐"的后处理,parse handler 做更合适。
    let mut used: std::collections::HashSet<String> = crate::storage::list_entries()
        .unwrap_or_default()
        .into_iter()
        .collect();
    for d in drafts.iter_mut() {
        let is_oauth = matches!(d.draft_type, grouping::types::DraftType::Oauth);
        let email = d.fields.email.clone();

        let candidate = if is_oauth && email.as_deref().map(|e| !e.is_empty()).unwrap_or(false) {
            // OAuth + email → 用 email(冲突时加 -2/-3 后缀)
            let base = email.unwrap();
            if !used.contains(&base) {
                base
            } else {
                let mut n = 2usize;
                loop {
                    let c = format!("{}-{}", base, n);
                    if !used.contains(&c) { break c; }
                    n += 1;
                }
            }
        } else {
            // 其他:走 {provider}_{type}_{N} 模板
            let prefix = d.inferred_provider.clone()
                .or_else(|| d.provider_hint.clone().map(|s| s.to_lowercase()))
                .unwrap_or_else(|| "import".to_string());
            // sanitize prefix: 仅保留 alnum + _/-,其他替换为 _
            let clean_prefix: String = prefix.chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
                .collect();
            let clean_prefix = clean_prefix.trim_matches(|c| c == '_' || c == '-').to_string();
            let clean_prefix = if clean_prefix.is_empty() { "import".to_string() } else { clean_prefix };
            let type_suffix = if is_oauth { "oauth" } else { "key" };
            let mut n = 1usize;
            loop {
                let c = format!("{}_{}_{}", clean_prefix, type_suffix, n);
                if !used.contains(&c) { break c; }
                n += 1;
            }
        };
        used.insert(candidate.clone());
        d.alias = candidate;

        // v4.1 Stage 10+: 填 login_url (UI "Open login page" 按钮用)
        // v4.2: 同时填 official_base_url (UI "use official" 按钮用)
        if let Some(family) = &d.inferred_provider {
            d.login_url = classifier.login_url_for_family(family);
            d.official_base_url = classifier.base_url_for_family(family);
        }
    }

    // orphans schema: 既保留原 candidate id 列表 (老 UI 兼容),
    // 也暴露候选本身 (每个 orphan 是完整 Candidate JSON 的子集),新 UI 可选择消费。
    let orphan_ids: Vec<String> = orphan_cands.iter().map(|c| c.id.clone()).collect();
    let orphans_json: Vec<serde_json::Value> = orphan_cands.iter()
        .map(|c| json!({ "id": c.id, "kind": c.kind.as_str(), "value": c.value }))
        .collect();

    let candidates_json: Vec<serde_json::Value> = all.iter().map(|c| serde_json::to_value(c).unwrap()).collect();
    let drafts_json: Vec<serde_json::Value> = drafts.iter().map(|d| serde_json::to_value(d).unwrap()).collect();
    let groups_json: Vec<serde_json::Value> = groups.iter().map(|g| serde_json::to_value(g).unwrap()).collect();

    Ok(json!({
        "source_hash": source_hash,
        "candidates": candidates_json,
        "drafts": drafts_json,                 // Stage 3 Phase D: DraftRecord 数组
        "groups": groups_json,                 // Stage 4: EndpointGroup 数组 (按 provider+base_url 聚合)
        "weak_drafts": [],                     // 保留字段,v1.1+ 可装 confidence<0.5 的 Draft
        "orphans": orphan_ids,                 // 向后兼容:老 UI 只用 id 列表
        "orphan_candidates": orphans_json,     // v4.1 新增:完整 orphan cand (kind+value)
        "warnings": ["stage-4-grouping-l2-plus-l3-cluster"],
        "layer_versions": {
            "rules": "2.0-full",       // Phase 2
            "crf": "1.0",              // Phase 4 接入 (shape filter + suggested tier)
            "fingerprint": "1.0",      // Phase 3 接入
            "grouper": "2.1-l3",       // Stage 4: L2 + L3 (sticky + EndpointGroup) 全启用
        },
    }))
}

/// 从 URL 抽 domain（`https://platform.moonshot.cn/x/y` → `platform.moonshot.cn`）
fn extract_url_domain(url: &str) -> Option<String> {
    let after_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let end = after_scheme.find(['/', '?', '#', ':']).unwrap_or(after_scheme.len());
    let domain = &after_scheme[..end];
    if domain.is_empty() { None } else { Some(domain.to_string()) }
}
