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

use super::candidate::Kind;
use super::rule::{looks_like_known_secret, try_push};
use super::tokenize::tokenize_line;

pub fn extract(
    text: &str,
    cands: &mut Vec<super::candidate::Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    let re_email = Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap();
    // 任何可识别 secret 形态（用于标记锚点行；不关心具体值）
    let re_any_secret = Regex::new(
        r"sk-ant-[A-Za-z0-9\-_]{10,}|\bsk-[A-Za-z0-9\-_]{10,}\b|\bxai-[A-Za-z0-9]{10,}\b|\brk-[A-Za-z0-9\-_]{10,}\b|\bghp_[A-Za-z0-9]{16,}\b|\b[a-fA-F0-9]{28,}\b|\bAKIA[0-9A-Z]{16}\b"
    ).unwrap();

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
        let has_email = re_email.is_match(line);
        let has_secret = re_any_secret.is_match(line);
        if has_email || has_secret {
            anchor_lines.insert(i);
            if i > 0 { anchor_lines.insert(i - 1); }
            if i + 1 < lines.len() { anchor_lines.insert(i + 1); }
        }
    }

    let mut idxs: Vec<usize> = anchor_lines.into_iter().collect();
    idxs.sort();

    // === Step 2: 在锚点行 tokenize，挑 password-shape ===
    for i in idxs {
        let tokens = tokenize_line(lines[i]);
        for tok in tokens {
            if !is_password_shape(&tok, &stopwords) { continue; }
            try_push(cands, seen, Kind::PasswordLike, &tok, None);
        }
    }
}

fn is_password_shape(
    tok: &str,
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

    // 停用词
    if stopwords.contains(lc.as_str()) { return false; }

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
