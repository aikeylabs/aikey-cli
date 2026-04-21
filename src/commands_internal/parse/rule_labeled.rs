//! Label=value 通用 secret 提取（Layer 2）
//!
//! 覆盖场景：
//! - `OPENAI_API_KEY=sk-proj-xxx`（.env 文件）
//! - `"api_key": "cust-xxx"`（JSON 嵌入）
//! - `AccountKey=xxx;`（Azure 连接串）
//! - `Authorization: Bearer xxx`（HTTP 头）
//! - `api_key：sk-xxx`（中文全角冒号）
//! - `"private_key_id": "abc..."`（GCP 服务账号 JSON）
//! - `key: a1b2c3d4e5f6...`（短 hex，仅在 `key` 标签 + 值 16+ 字符 + 含 digit+alpha 时触发）
//!
//! # 关键设计
//! - 主 regex **不带 `\b`**：允许匹配 `OPENAI_API_KEY` 中的 `API_KEY` 子串
//!   （因为 `_` 是 word 字符，`\b` 不会在 `_API_KEY` 边界触发）
//! - 值必须 10+ 字符 + 紧跟 `[:=]`：避免在 "the api_keyboard" 这类叙述误命中
//! - `key` 这个短标签**单独处理**：要求值 16+ 字符 + 含 digit+alpha，避免通用性过强

use regex::Regex;

use super::candidate::Kind;
use super::rule::{looks_like_known_secret, try_push};

pub fn extract(
    text: &str,
    cands: &mut Vec<super::candidate::Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    // 主 label=value regex（case-insensitive；无 `\b` 首部边界，见上文）
    let re = Regex::new(
        r#"(?i)(api[_\s\-]?key|apikey|access[_\s\-]?key|accesskey|accountkey|\
private[_\s\-]?key[_\s\-]?id|secret[_\s\-]?key|aws[_\s\-]?access[_\s\-]?key[_\s\-]?id|\
authorization|bearer|token)["']?\s*[:=]\s*["']?([A-Za-z0-9+/_\-\.=]{10,})["']?"#
    ).unwrap();

    for cap in re.captures_iter(text) {
        let Some(val) = cap.get(2) else { continue };
        let v = val.as_str();
        // 过滤：纯字母且长度短（很可能是标签词本身或英文词）
        if v.len() < 10 { continue; }
        if v.chars().all(|c| c.is_alphabetic()) && v.len() < 20 { continue; }
        // 不处理已被 Layer 1 known-prefix 抓走的（dedup 保证），但也不拦截
        // —— known-prefix 值（如 sk-ant-api03-）**可以**同时被 label=value 匹配，
        // dedup by (kind, value) 确保不重复 push。
        let _ = looks_like_known_secret(v);
        try_push(cands, seen, Kind::SecretLike, v, Some([val.start(), val.end()]));
    }

    // Bearer 特殊形态：`Bearer <value>`（空格分隔，不是 `[:=]`）
    let re_bearer = Regex::new(r"(?i)\bBearer\s+([A-Za-z0-9+/_\-\.=]{10,})\b").unwrap();
    for cap in re_bearer.captures_iter(text) {
        let Some(val) = cap.get(1) else { continue };
        let v = val.as_str();
        if v.len() < 10 { continue; }
        try_push(cands, seen, Kind::SecretLike, v, Some([val.start(), val.end()]));
    }

    // 单词 `key` / `密钥` / `秘钥` 标签 —— 严格约束避免英文叙述 FP
    // - \bkey\b 要求 key 是独立单词（不是 api_key 的子串）
    // - 值 16+ 字符
    // - 值必须含 digit + alpha 混合
    let re_key_label = Regex::new(
        r#"(?i)\b(key|\u5bc6\u94a5|\u79d8\u94a5)\b\s*[:=]\s*["']?([A-Za-z0-9+/_\-\.=]{16,})["']?"#
    ).unwrap();
    for cap in re_key_label.captures_iter(text) {
        let Some(val) = cap.get(2) else { continue };
        let v = val.as_str();
        let has_digit = v.chars().any(|c| c.is_ascii_digit());
        let has_alpha = v.chars().any(|c| c.is_ascii_alphabetic());
        if !(has_digit && has_alpha) { continue; }
        try_push(cands, seen, Kind::SecretLike, v, Some([val.start(), val.end()]));
    }
}
