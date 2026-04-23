//! 规则引擎 v2 主入口
//!
//! 协调 4 个子规则层：
//! 1. **基础 regex**：email / URL / 已知 provider 前缀（sk-ant / sk- / xai- / rk- / ghp_ / 长 hex）+ 高特异性 shape（AWS AKIA / SendGrid SG. / JWT eyJ.）
//! 2. **`rule_labeled`**（label=value 通用提取）：`api_key` / `bearer` / `accesskey` / `accountkey` / `private_key_id` / `token` / `key` 等
//! 3. **`rule_pem`**（PEM 多行块）：SSH / TLS / PGP 私钥
//! 4. **`rule_anchored`**（B 方案邮箱/secret 锚点）：未被上述覆盖的 OOD 排版下的 password-shape token
//!
//! 调用顺序关键：1 → 2 → 3 → 4。前 3 步产出"已认领"候选，第 4 步用这些作为 anchor 拓展召回。

use regex::Regex;
use std::sync::OnceLock;

use super::candidate::{make_id, Candidate, Kind, Tier};
use super::v41_guards::{is_comment_at_offset, is_in_reject_context, is_placeholder_token};

// R-5 P2-A (2026-04-23): per-call `Regex::new(...)` recompilation removed.
// Each pattern lives in a `OnceLock<Regex>` initialized on first use; subsequent
// `re_*()` calls are O(1) reference lookups. Aligns with the existing
// `crf.rs` / `provider_fingerprint.rs` OnceLock model.

fn re_email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap())
}
fn re_url() -> &'static Regex {
    // URL 停在 " ' , } ] ): 覆盖 JSON 嵌入 / Markdown 链接 [text](url) 场景
    //   v4.1 ISSUE-3: 补全角右括号 `）】」〕` —— 避免桃子中文行
    //   `http://taozi-nas.local:3000/v1）` 把 `）` 吞入 URL 造成畸形 base_url
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"https?://[^\s"',}\])）】」〕]+"#).unwrap())
}
fn re_sk_ant() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"sk-ant-[A-Za-z0-9\-_]{10,}").unwrap())
}
fn re_sk() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bsk-[A-Za-z0-9\-_]{10,}\b").unwrap())
}
fn re_xai() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bxai-[A-Za-z0-9]{10,}\b").unwrap())
}
fn re_rk() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\brk-[A-Za-z0-9\-_]{10,}\b").unwrap())
}
fn re_ghp() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bghp_[A-Za-z0-9]{16,}\b").unwrap())
}
fn re_hex_long() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[a-fA-F0-9]{28,}\b").unwrap())
}
fn re_aws() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap())
}
fn re_sendgrid() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b").unwrap())
}
fn re_jwt() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b").unwrap()
    })
}

/// 从原文抽取所有候选（已 dedup + 合并四层）
pub fn rule_extract(text: &str) -> Vec<Candidate> {

    let mut cands: Vec<Candidate> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Why dedup by (kind, value): 同 value 可能被多条 regex 同时命中（sk-ant-xxx 也匹配 sk-），避免重复

    // === Layer 1a: 基础 email / URL ===
    //   v4.1 ISSUE-4: IS_COMMENT 行的 email / URL 一律不抽（注释掉的邮箱 / curl 示例）
    push_matches_guarded(text, re_email(), Kind::Email, &mut cands, &mut seen);
    push_matches_guarded(text, re_url(), Kind::Url, &mut cands, &mut seen);

    // === Layer 1b: 已知 provider 前缀 → secret ===
    // 优先级：更具体的前缀先
    //   v4.1 ISSUE-4: 注释行废弃 key（// sk-ant-api03-OldKey_rotated）不抽
    //   v4.1 placeholder denylist: `sk-example-xxx` / `sk-ant-api03-your_key` 等占位不抽
    push_matches_guarded(text, re_sk_ant(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_sk(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_xai(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_rk(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_ghp(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_hex_long(), Kind::SecretLike, &mut cands, &mut seen);

    // === Layer 1c: 高特异性 shape（AWS / SendGrid / JWT）===
    push_matches_guarded(text, re_aws(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_sendgrid(), Kind::SecretLike, &mut cands, &mut seen);
    push_matches_guarded(text, re_jwt(), Kind::SecretLike, &mut cands, &mut seen);

    // === Legacy `----` 分隔的 password 启发式 ===
    // Why 保留：in-dist 样本（claude2/claude3 风格）大量使用这种格式
    dash_separated_password_heuristic(text, re_email(), &mut cands, &mut seen);

    // === Legacy `|` 分隔的中段 password 启发式 ===
    pipe_separated_password_heuristic(text, re_email(), &mut cands, &mut seen);

    // === 显式标签启发式（password: / 密码: 等）===
    // 注意：这条负责 password 字段；secret 字段由 Layer 2 label=value 负责
    explicit_label_password_heuristic(text, &mut cands, &mut seen);

    // === Layer 2: label=value 通用提取（api_key / bearer / accesskey / private_key_id 等）===
    super::rule_labeled::extract(text, &mut cands, &mut seen);

    // === Layer 3: PEM 多行块 ===
    super::rule_pem::extract(text, &mut cands, &mut seen);

    // === Layer 4: email/secret 锚点 password 召回（B 方案）===
    super::rule_anchored::extract(text, &mut cands, &mut seen);

    // === Layer 5 (v4.2): block 首行"自然语言"title 抽取 ===
    // Why 放 PEM/锚点之后：title 不是 credential，run 完整 credential 层再跑它，不影响
    // 原有 dedup 次序。emit Kind::Title；grouper 按 line_range 贴到对应 draft。
    // 零回归验证见 workflow/CI/research/ablation-spike-v4.1/TITLE_ABLATION_REPORT.md。
    super::rule_title::extract(text, &mut cands, &mut seen);

    cands
}

/// 把一条 regex 的所有 match 作为 Candidate push 进去，按 (kind, value) dedup
#[allow(dead_code)] // 保留原 API；Stage 2a 之后统一走 push_matches_guarded
fn push_matches(
    text: &str,
    re: &Regex,
    kind: Kind,
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    for m in re.find_iter(text) {
        try_push(cands, seen, kind, m.as_str(), Some([m.start(), m.end()]));
    }
}

/// v4.1 Stage 2a + 2d: push_matches 的守门版 ——
///   - IS_COMMENT 行的 match 跳过（ISSUE-4）
///   - placeholder token 跳过（sk-example / your_key 等诱饵）
///   - context_reject_labels v2 上下文跳过（git commit / docker digest / SHA hash，Stage 2d）
///
/// Why 对所有 provider regex 都守门:
/// CLI 用硬编码 provider regex，commit/docker SHA 可能被 re_hex_long / re_sk 等误认。
/// 统一守门简化 bookkeeping，和 v4.1 spike YAML `context_reject_labels` 效果等价。
fn push_matches_guarded(
    text: &str,
    re: &Regex,
    kind: Kind,
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    for m in re.find_iter(text) {
        if is_comment_at_offset(text, m.start()) { continue; }
        if is_in_reject_context(text, m.start()) { continue; }
        if is_placeholder_token(m.as_str()) { continue; }
        try_push(cands, seen, kind, m.as_str(), Some([m.start(), m.end()]));
    }
}

/// 试着 push 一个候选；已见过则跳过
pub(super) fn try_push(
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
    kind: Kind,
    value: &str,
    span: Option<[usize; 2]>,
) -> bool {
    let dedup_key = format!("{}\x00{}", kind.as_str(), value);
    if !seen.insert(dedup_key) {
        return false;
    }
    cands.push(Candidate {
        id: make_id(kind, cands.len() + 1),
        kind,
        value: value.to_string(),
        tier: Tier::Confirmed,
        source_span: span,
        provider: None,
        // v4.1 Method B 字段 (Stage 2b)：Active 是隐式默认；Stage 2c+ 按路径填 source
        source: None,
        status: None,
        suppress_reason: None,
    });
    true
}

/// 帮助：判断一个字符串是否是"已知 secret-like"（会被 re_sk_ant / re_sk / 等命中）
/// rule_anchored / rule_labeled 用它过滤"已被 Layer 1 抓走"的 token
pub(super) fn looks_like_known_secret(s: &str) -> bool {
    let lc = s.to_lowercase();
    lc.starts_with("sk-") || lc.starts_with("xai-") || lc.starts_with("rk-")
        || lc.starts_with("ghp_") || lc.starts_with("akia")
        || lc.starts_with("sg.") || lc.starts_with("eyj")
}

// ============ `----` 分隔 password 启发式 ============

fn dash_separated_password_heuristic(
    text: &str,
    re_email: &Regex,
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    for line in text.lines() {
        if !line.contains("----") { continue; }
        // v4.1 ISSUE-4: 注释行的 dash_split password 启发式跳过
        if super::line_class::line_class(line).flags.contains(super::line_class::LineFlags::IS_COMMENT) {
            continue;
        }
        let parts: Vec<&str> = line.split("----").map(str::trim).collect();

        // email----password[----secret[----url]]
        for n in &[2usize, 3, 4] {
            if parts.len() == *n && re_email.is_match(parts[0]) {
                let pwd = parts[1];
                if is_plausible_password(pwd) {
                    try_push(cands, seen, Kind::PasswordLike, pwd, None);
                }
            }
        }
    }
}

fn pipe_separated_password_heuristic(
    text: &str,
    re_email: &Regex,
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    for line in text.lines() {
        if !line.contains(" | ") { continue; }
        // v4.1 ISSUE-4: 注释行跳过
        if super::line_class::line_class(line).flags.contains(super::line_class::LineFlags::IS_COMMENT) {
            continue;
        }
        let parts: Vec<&str> = line.split(" | ").map(str::trim).collect();
        if parts.len() < 3 { continue; }
        for (i, p) in parts.iter().enumerate() {
            if re_email.is_match(p) && i + 1 < parts.len() {
                let pwd = parts[i + 1];
                if is_plausible_password(pwd) {
                    try_push(cands, seen, Kind::PasswordLike, pwd, None);
                }
            }
        }
    }
}

fn explicit_label_password_heuristic(
    text: &str,
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    // label 后紧跟冒号 / 等号的形态
    let labels_with_punct: &[&str] = &[
        "\u{5BC6}\u{7801}:", "\u{5BC6}\u{7801}\u{FF1A}",
        "password:", "pass:", "passwd:", "pwd:", "pw:",
        "pw=", "pass=", "password=", "passwd=", "pwd=",
        "login:",
    ];
    // label 后紧跟空格的形态
    let labels_with_space: &[&str] = &[
        "\u{5BC6}\u{7801} ", "password ", "pwd ", "pass ",
    ];

    for line in text.lines() {
        // v4.1 ISSUE-4: 注释行跳过 label password 启发式
        if super::line_class::line_class(line).flags.contains(super::line_class::LineFlags::IS_COMMENT) {
            continue;
        }
        let lower = line.to_lowercase();
        for label in labels_with_punct {
            if let Some(idx) = lower.find(label) {
                let rest = &line[idx + label.len()..];
                if let Some(tok) = first_token_stripped(rest) {
                    if is_plausible_password(&tok) {
                        try_push(cands, seen, Kind::PasswordLike, &tok, None);
                    }
                }
            }
        }
        for label in labels_with_space {
            if let Some(idx) = lower.find(label) {
                let rest = &line[idx + label.len()..];
                if let Some(tok) = first_token_stripped(rest) {
                    if is_plausible_password(&tok) {
                        try_push(cands, seen, Kind::PasswordLike, &tok, None);
                    }
                }
            }
        }
    }
}

/// 取字符串首个非空 token，并剥除两端常见 markdown / csv 边缘符
fn first_token_stripped(s: &str) -> Option<String> {
    let tok = s.trim().split_whitespace().next()?.to_string();
    let tok = tok.trim_matches(|c: char| {
        c == '*' || c == '`' || c == '"' || c == '\''
            || c == ',' || c == '.' || c == ';' || c == '|' || c == ':' || c == '~'
            || c == '[' || c == ']' || c == '(' || c == ')'
    });
    if tok.is_empty() { None } else { Some(tok.to_string()) }
}

/// 判断一个字符串是否形态上像 password（非已知 secret、长度合理、含字母）
fn is_plausible_password(s: &str) -> bool {
    use super::v41_guards::{is_placeholder_token, token_has_cjk_or_fullwidth};
    let len = s.chars().count();
    if len < 3 || len > 64 { return false; }
    if looks_like_known_secret(s) { return false; }
    if s.contains('@') { return false; } // 不是 email
    if s.starts_with("http") { return false; } // 不是 URL
    // v4.1 ISSUE-3: CJK / 全角标点 不是真 password（中文描述文字被误抓的 FP 源头）
    if token_has_cjk_or_fullwidth(s) { return false; }
    // v4.1 placeholder denylist: changeme / your_api_key / sk-example 等占位不算 password
    if is_placeholder_token(s) { return false; }
    // v4.1 ISSUE-3 补丁: `email/password` 类描述性 slash token 不是 password
    if s.contains('/') { return false; }
    // v4.1 M4 post-fix: trailing `_-` 几乎必是 `...truncated_...` ellipsis 截断
    if s.ends_with('_') || s.ends_with('-') { return false; }
    true
}
