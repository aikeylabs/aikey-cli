//! `_internal parse`：文本解析入口（三层流水：规则 v2 + CRF + Provider Fingerprint）
//!
//! # Stage 2 范围（本 Phase E）
//! - 协议契约定稿（input payload + output schema）
//! - **Layer 1-lite**：仅基础 regex（email / URL / 已知 provider 前缀 / 长 hex）
//! - 不做 CRF / shape filter / H 层 Fingerprint（Stage 3 填充）
//! - 不做 tokenize_line / anchored / label=value / PEM 多层（Stage 3 填充）
//! - 不做 grouper（drafts 为空，候选全部作为 orphans）
//!
//! # Stage 3 迁移点
//! 1. 从 `workflow/CI/research/ablation-spike/src/` 迁移完整 rule_extract + anchored + labeled + PEM
//! 2. 接入 `commands_internal::parse::crf::extract_with_crf` (Stage 3.5 新增模块)
//! 3. 接入 `commands_internal::parse::fingerprint::classify_all` (Stage 3.9 新增模块)
//! 4. 加 `grouper::build_drafts` 做图归组
//!
//! # 协议
//! 见 `protocol.rs` StdinEnvelope + 本模块响应 schema（参考 批量导入-最终方案-v2.md §5.3）
//!
//! # 安全
//! parse 对 vault **零操作**（不读不写不解密）。但仍然要求 stdin 包含 vault_key_hex（协议一致性）。
//! 只校验 vault_key_hex 格式合法，不校验是否匹配 vault（parse 不需要解锁）。

use regex::Regex;
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

/// 从 `text` 用 `re` 抽取匹配，去重后追加到 `candidates`。
fn extract_matches(
    text: &str,
    re: &Regex,
    kind: &str,
    max: usize,
    candidates: &mut Vec<serde_json::Value>,
    seen: &mut std::collections::HashSet<String>,
) {
    for m in re.find_iter(text) {
        if candidates.len() >= max { return; }
        let value = m.as_str();
        let dedup_key = format!("{}\x00{}", kind, value);
        if !seen.insert(dedup_key) { continue; }
        let prefix_char = kind.chars().next().unwrap_or('x');
        let id = format!("c-{}-{}", prefix_char, candidates.len() + 1);
        candidates.push(json!({
            "id": id,
            "kind": kind,
            "value": value,
            "tier": "confirmed",
            "source_span": [m.start(), m.end()],
        }));
    }
}

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

    match run_parse_stage2_lite(&payload) {
        Ok(result) => emit(&ResultEnvelope::ok(req_id, result)),
        Err((c, m)) => emit_error(req_id, c, m),
    }
}

// ========== Layer 1-lite regex extraction (Stage 2 skeleton) ==========

/// Stage 2 简化版三层流水：只跑基础 regex，输出候选列表
///
/// Stage 3 替换点：
/// - 接 rule_extract_anchored (B 方案) / rule_extract_secret_labeled / rule_extract_pem_block
/// - 接 CRF + shape filter → 输出 suggested tier 候选
/// - 接 Fingerprint classifier → 为每个 secret 打 provider tag
/// - 接 grouper → 输出 drafts + weak_drafts
fn run_parse_stage2_lite(payload: &ParsePayload) -> Result<serde_json::Value, (&'static str, String)> {
    let text = &payload.text;

    let re_email = Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
        .map_err(|e| ("I_PARSE_FAILED", format!("email regex: {}", e)))?;
    let re_url = Regex::new(r#"https?://[^\s"',}\])]+"#)
        .map_err(|e| ("I_PARSE_FAILED", format!("url regex: {}", e)))?;
    let re_sk_ant = Regex::new(r"sk-ant-[A-Za-z0-9\-_]{10,}")
        .map_err(|e| ("I_PARSE_FAILED", format!("sk-ant regex: {}", e)))?;
    let re_sk_generic = Regex::new(r"\bsk-[A-Za-z0-9\-_]{10,}\b")
        .map_err(|e| ("I_PARSE_FAILED", format!("sk regex: {}", e)))?;
    let re_xai = Regex::new(r"\bxai-[A-Za-z0-9]{10,}\b")
        .map_err(|e| ("I_PARSE_FAILED", format!("xai regex: {}", e)))?;
    let re_rk = Regex::new(r"\brk-[A-Za-z0-9\-_]{10,}\b")
        .map_err(|e| ("I_PARSE_FAILED", format!("rk regex: {}", e)))?;
    let re_ghp = Regex::new(r"\bghp_[A-Za-z0-9]{16,}\b")
        .map_err(|e| ("I_PARSE_FAILED", format!("ghp regex: {}", e)))?;
    let re_hex_long = Regex::new(r"\b[a-fA-F0-9]{28,}\b")
        .map_err(|e| ("I_PARSE_FAILED", format!("hex regex: {}", e)))?;

    let mut candidates: Vec<serde_json::Value> = Vec::new();
    // 用 HashSet<String> 做"精确值去重"；kind 编进 key 前缀避免跨类碰撞。
    // Why dedup: 同一值可能被多条 regex 同时命中（sk-ant 也匹配 sk-），避免重复候选
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let max = payload.max_candidates;

    // 展开式扫描：每个 regex 独立循环，避免 Rust 对 tuple-of-(&str, &Regex) 的 lifetime 推断困难
    extract_matches(text, &re_email, "email", max, &mut candidates, &mut seen);
    extract_matches(text, &re_url, "url", max, &mut candidates, &mut seen);
    // secret 按优先级：更具体的前缀先插入，dedup 保证不重复
    extract_matches(text, &re_sk_ant, "secret_like", max, &mut candidates, &mut seen);
    extract_matches(text, &re_sk_generic, "secret_like", max, &mut candidates, &mut seen);
    extract_matches(text, &re_xai, "secret_like", max, &mut candidates, &mut seen);
    extract_matches(text, &re_rk, "secret_like", max, &mut candidates, &mut seen);
    extract_matches(text, &re_ghp, "secret_like", max, &mut candidates, &mut seen);
    extract_matches(text, &re_hex_long, "secret_like", max, &mut candidates, &mut seen);

    let source_hash = {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    // Stage 2：每个 candidate 单独作为 orphan（无 grouping）
    let orphans: Vec<String> = candidates.iter()
        .map(|c| c["id"].as_str().unwrap_or("").to_string())
        .collect();

    Ok(json!({
        "source_hash": source_hash,
        "candidates": candidates,
        "drafts": [],             // Stage 3: grouper 输出
        "weak_drafts": [],        // Stage 3
        "orphans": orphans,       // Stage 2 所有候选都作为 orphan
        "warnings": ["stage-2-parse-skeleton"],
        "layer_versions": {
            "rules": "1.0-lite",  // Stage 3 升级到 "2.0-full"
            "crf": "disabled",
            "fingerprint": "disabled",
            "grouper": "disabled",
        },
    }))
}
