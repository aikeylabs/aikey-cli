//! Email/secret 锚点 password 召回（Layer 4，B 方案）
//!
//! # 核心思路
//! 对于 OOD 排版（`~~` / `===` / `::` / 反序 / 后缀标签 / 编号 / 引用块 / 自然语言叙述），
//! 标签词 + `----` 的启发式全部失效。但 email/secret 正则对排版几乎不变性，可以作为
//! "锚点"：在锚点所在行或相邻行的 token 里挑 password-shape 候选。
//!
//! # POC 实证
//! - OOD-apikey 召回率 5.9% → 100%（本规则主力贡献）
//! - OOD-layouts 77.8% → 100%
//!
//! # password-shape 过滤（C2 评审收紧版）
//! - 长度 6-32
//! - 不含 `@` / 不是 http:// URL / 不是已知 secret 前缀
//! - 不在停用词表
//! - 含字母 **AND**（含数字 OR 含特殊字符 AND 长度 ≥ 12）
//!   —— 单纯 alpha+special 短 token（如 `[Moonshot`）一律拒绝，避免 markdown 残留当 password

use regex::Regex;
use std::sync::OnceLock;

// R-5 P2-A (2026-04-23): cached regexes (called per-line over whole text).
fn re_email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap())
}
fn re_any_secret() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(
        r"sk-ant-[A-Za-z0-9\-_]{10,}|\bsk-[A-Za-z0-9\-_]{10,}\b|\bxai-[A-Za-z0-9]{10,}\b|\brk-[A-Za-z0-9\-_]{10,}\b|\bghp_[A-Za-z0-9]{16,}\b|\b[a-fA-F0-9]{28,}\b|\bAKIA[0-9A-Z]{16}\b"
    ).unwrap())
}

use super::candidate::Kind;
use super::line_class::{line_class, LineFlags};
use super::rule::{looks_like_known_secret, try_push};
use super::tokenize::tokenize_line;
use super::v41_guards::{is_in_reject_context, is_label_shape, is_placeholder_token};

pub fn extract(
    text: &str,
    cands: &mut Vec<super::candidate::Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    let stopwords: std::collections::HashSet<&str> = [
        "is", "the", "for", "as", "and", "use", "my", "new", "set",
        "login", "email", "password", "passwd", "pass", "pwd",
        "key", "apikey", "token", "mail", "account", "acct",
        "secret", "api", "claude", "openai",
        // 中文停用词
        "\u{5BC6}\u{7801}", "\u{90AE}\u{7BB1}", "\u{8D26}\u{53F7}",
        "\u{5BC6}\u{94A5}", "\u{8BBE}\u{4E3A}", "\u{4ECA}\u{5929}",
        "\u{65B0}\u{7684}", "\u{8FD8}\u{6709}", "\u{6FC0}\u{6D3B}\u{94FE}\u{63A5}",
        "\u{767B}\u{5F55}", "\u{6CE8}\u{518C}",
    ].iter().copied().collect();

    // === Step 1: 找出所有锚点行（含 email 或 secret）===
    let lines: Vec<&str> = text.lines().collect();
    let mut anchor_lines: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (i, line) in lines.iter().enumerate() {
        let has_email = re_email().is_match(line);
        let has_secret = re_any_secret().is_match(line);
        if has_email || has_secret {
            anchor_lines.insert(i);
            if i > 0 { anchor_lines.insert(i - 1); }
            if i + 1 < lines.len() { anchor_lines.insert(i + 1); }
        }
    }

    let mut idxs: Vec<usize> = anchor_lines.into_iter().collect();
    idxs.sort();

    // 预算行首 byte offset，用于 is_in_reject_context 检查
    let mut line_start_offsets: Vec<usize> = Vec::with_capacity(lines.len());
    let mut cur = 0usize;
    for line in &lines {
        line_start_offsets.push(cur);
        cur += line.len() + 1; // +1 for \n
    }

    // === Step 2: 在锚点行 tokenize，挑 password-shape 或 anchored_secret-shape ===
    for i in idxs {
        // v4.1 ISSUE-6: rule_extract_* 家族最后一处 IS_COMMENT 守门补漏
        //   注释行的 token 不参与 anchored password 召回
        if line_class(lines[i]).flags.contains(LineFlags::IS_COMMENT) {
            continue;
        }
        // v4.1 Stage 2d: context_reject 上下文行整行跳过 ——
        //   `commit f3a8b9c0...` / `docker pull ...@sha256:...` 等 hash-context 行
        //   不产生 anchored_password / anchored_secret 候选
        if is_in_reject_context(text, line_start_offsets[i]) {
            continue;
        }
        let line_text = lines[i];
        let tokens = tokenize_line(line_text);
        for tok in tokens {
            // v4.1 Method B Phase 4: anchored_secret 路径优先级高于 anchored_password
            if is_anchored_secret_shape(&tok) && passes_shape_filters(&tok, line_text, &stopwords) {
                try_push(cands, seen, Kind::SecretLike, &tok, None);
                continue;
            }
            if !is_password_shape(&tok, line_text, &stopwords) { continue; }
            try_push(cands, seen, Kind::PasswordLike, &tok, None);
        }
    }
}

/// v4.1 Method B Phase 4: anchored_secret 形态
///
/// 两种触发条件任一成立：
/// - (a) len ∈ (32, 80]，pure alnum + alpha + digit
/// - (b) len ∈ [28, 32]，pure alnum + alpha + digit，且 hex-ratio ≥ 0.70
///
/// Why 上限 80：远长于 YAML 最长 family（gsk ~56）防无 fence 乱抓
/// Why 下限 28：短于 28 字符的 hex 形 secret 很可能是普通 password / UUID 片段，不走此路径
fn is_anchored_secret_shape(tok: &str) -> bool {
    let len = tok.chars().count();
    if len < 28 || len > 80 { return false; }
    let is_pure_alnum = tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && tok.chars().any(|c| c.is_ascii_alphabetic())
        && tok.chars().any(|c| c.is_ascii_digit());
    if !is_pure_alnum { return false; }
    if len > 32 { return true; }  // 33-80 带内：纯 alnum+alpha+digit 即可
    // 28-32 带内：要求 hex-dominant
    let hex_ratio = tok.chars().filter(|c| c.is_ascii_hexdigit()).count() as f32 / len as f32;
    hex_ratio >= 0.70
}

/// anchored_secret 路径的 shape filter（不查 len / alpha / digit，那些 `is_anchored_secret_shape`
/// 已经校验了；这里只补"共用"的形态拒识：注释/email/provider_prefix/placeholder/slash/truncation）
fn passes_shape_filters(
    tok: &str,
    line: &str,
    stopwords: &std::collections::HashSet<&str>,
) -> bool {
    let lc = tok.to_lowercase();
    // email / URL / 已知 secret 前缀
    if tok.contains('@') { return false; }
    if lc.starts_with("http") { return false; }
    if looks_like_known_secret(tok) { return false; }
    // stopwords
    if stopwords.contains(lc.as_str()) { return false; }
    // v4.1 placeholder denylist
    if is_placeholder_token(tok) { return false; }
    // v4.1 Post-Stage4: label_shape (kebab / token: / provider-prefix+digits)
    if is_label_shape(tok, line) { return false; }
    // v4.1 M4 post-fix: trailing _- 截断
    if tok.ends_with('_') || tok.ends_with('-') { return false; }
    // 全非 ASCII（CJK only）
    if tok.chars().all(|c| !c.is_ascii()) { return false; }
    // contains slash
    if tok.contains('/') { return false; }
    // shell var ref
    if tok.starts_with('$') { return false; }
    true
}

fn is_password_shape(
    tok: &str,
    line: &str,
    stopwords: &std::collections::HashSet<&str>,
) -> bool {
    let lc = tok.to_lowercase();
    let len = tok.chars().count();

    // 长度范围
    if len < 6 || len > 32 { return false; }

    // 排除：email / URL / 已知 secret 前缀
    if tok.contains('@') { return false; }
    if lc.starts_with("http") { return false; }
    if looks_like_known_secret(tok) { return false; }

    // v4.1 anchored path 的 CJK 拒识比 label/dash/pipe 路径宽松 ——
    //   仅拒"纯非 ASCII"（`chars().all(|c| !c.is_ascii())`），
    //   而非任意含 CJK（那是 rule::is_plausible_password 的职责）
    //   Why: CLI 测试用例 H-K-01 有 `CnPwd测试99` 这类 mixed-ASCII-CJK password，
    //   V4.1 spike 在 anchored 层会通过（通过 rule_extract_anchored::non_ascii_only 检查），
    //   只在 label/dash/pipe 路径上严格拒（避免中文描述文字碎片作 password FP）
    if tok.chars().all(|c| !c.is_ascii()) { return false; }
    // v4.1 placeholder denylist
    if is_placeholder_token(tok) { return false; }
    // v4.1 M4 post-fix: trailing `_-` 几乎必是 ellipsis 截断 (`LTAI5t_doubao_` 类 fragment)
    if tok.ends_with('_') || tok.ends_with('-') { return false; }
    // v4.1 ISSUE-3 补丁: `email/password` 类 slash token 不是 password
    if tok.contains('/') { return false; }
    // v4.1 Method B shell var ref: `$OPENAI_API_KEY` / `${VAR}`
    if tok.starts_with('$') { return false; }

    // 停用词
    if stopwords.contains(lc.as_str()) { return false; }

    // v4.1 Post-Stage4: label_shape 拒识 (claude2: SF → claude2 是 label;
    //   kebab-case 别名;provider keyword + 数字/dash 后缀)
    if is_label_shape(tok, line) { return false; }

    // 排除纯 hex 长串（secret 残影，应该已被 Layer 1 hex_long 抓走）
    if len >= 28 && tok.chars().all(|c| c.is_ascii_hexdigit()) { return false; }

    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let has_alpha = tok.chars().any(|c| c.is_alphabetic());
    let has_special = tok.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?/~`".contains(c));

    if !has_alpha { return false; }
    if !has_digit {
        // 无数字：只接受 alpha + special 且长度 ≥ 12
        // Why 12：markdown 残留 `[Moonshot`（len 9）应拒绝，`ProdPass!Strong`（len 15）应接受
        if !has_special || len < 12 { return false; }
    }
    true
}
