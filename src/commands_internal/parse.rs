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
pub mod provider_fingerprint;
pub mod crf;
// v4.1 spike migration (Stage 1): line_class 基础设施 —— LineKind 6 类 + LineFlags 9 bit
// 现阶段未被 rule/candidate 主干消费；Stage 2-3 并入。
pub mod line_class;
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
    // 用同文档 URL 域名做 ambiguous 消歧（比如 sk-* + moonshot.cn → moonshot_kimi）。
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

    // Stage 3 Phase 3：无 grouping → 每个 candidate 单独作为 orphan
    let orphans: Vec<String> = all.iter().map(|c| c.id.clone()).collect();

    let candidates_json: Vec<serde_json::Value> = all.iter().map(|c| serde_json::to_value(c).unwrap()).collect();

    Ok(json!({
        "source_hash": source_hash,
        "candidates": candidates_json,
        "drafts": [],
        "weak_drafts": [],
        "orphans": orphans,
        "warnings": ["stage-3-phase-4-with-crf"],
        "layer_versions": {
            "rules": "2.0-full",       // Phase 2
            "crf": "1.0",              // Phase 4 接入（shape filter + suggested tier）
            "fingerprint": "1.0",      // Phase 3 接入
            "grouper": "disabled",     // Phase 5+ (grouper 尚未规划)
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
