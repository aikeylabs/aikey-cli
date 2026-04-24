//! L1 line classification — 从 V4.1 spike `grouping.rs` 迁移 (Stage 1)
//!
//! # 合约 (必须与 V4.1 spike 一致)
//!
//! 输入一行文本 -> 输出 `LineClass { kind: LineKind, flags: LineFlags }`。
//!
//! - `LineKind` 6 类语义标签: `Empty / Separator / Title / Credential / Complex / Note`
//! - `LineFlags` 9 个属性 bit: `HAS_EMAIL / HAS_SECRET / HAS_URL / HAS_PWD_LABEL /
//!   HAS_DASH_RUN / IS_SOLO_TOKEN / STARTS_BULLET / HAS_LABEL_COLON / IS_COMMENT`
//!
//! # 为什么 kind 和 flags 分两轴
//!
//! 一条 `----hunter2----sk-ant-...` 既是 Complex(语义参与 block 切分),又要带 HAS_SECRET /
//! HAS_DASH_RUN 等属性供 grouper 查询。合并到单 enum 会形成组合爆炸。bitflags 保持属性
//! 独立、正交、可组合。
//!
//! # Banner / Separator 识别 (v3.1 C1-a + v4.1 R3)
//!
//! 三档:
//!   (a) 纯符号行 `---` / `===` / `***`
//!   (b) banner `---- PROD ----` / `=== DEV ===`
//!   (c) 注释包裹 banner `# --- 公司项目 ---`  ← kind 升 Separator, 但保留 IS_COMMENT flag
//!
//! # 对应 V4.1 源码
//!
//! `workflow/CI/research/ablation/ablation-spike-v4.1/src/grouping.rs:41-332`
//! (LineKind enum + LineFlags bitflags + classify_line + line_class)

use bitflags::bitflags;
use regex::Regex;
use std::sync::OnceLock;

// R-5 P2-A (2026-04-23): hot-path regexes cached in OnceLock to skip
// recompilation on every line_class() call (called per-line for whole text).
fn re_email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap())
}
fn re_any_secret() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(
        r"sk-ant-[A-Za-z0-9\-_]{10,}|\bsk-[A-Za-z0-9\-_]{10,}\b|\bxai-[A-Za-z0-9]{10,}\b|\brk-[A-Za-z0-9\-_]{10,}\b|\bghp_[A-Za-z0-9]{16,}\b|\b[a-fA-F0-9]{28,}\b|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_\-]{35}\b|\bgsk_[A-Za-z0-9]{48,64}\b|\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
    ).unwrap())
}
fn re_url() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"https?://[^\s"',}\])]+"#).unwrap())
}
fn re_pure_sep() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[-=#*\s]+$").unwrap())
}
fn re_banner_sep() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[-=#*]{2,}\s+\S[^\n]{0,40}?\S\s+[-=#*]{2,}\s*$").unwrap())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Empty,
    Separator,
    Title,
    Credential,
    Complex,
    Note,
}

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct LineFlags: u16 {
        const HAS_EMAIL       = 0b0000_0000_0001;
        const HAS_SECRET      = 0b0000_0000_0010;
        const HAS_URL         = 0b0000_0000_0100;
        const HAS_PWD_LABEL   = 0b0000_0000_1000;  // `password:` / `pwd:` / `密码:` 标签
        const HAS_DASH_RUN    = 0b0000_0001_0000;  // 含 `----` 区段
        const IS_SOLO_TOKEN   = 0b0000_0010_0000;  // 整行仅 1 个非空白 token（孤立值）
        const STARTS_BULLET   = 0b0000_0100_0000;  // `1)` `-` `*` `•` 项目符号起首
        const HAS_LABEL_COLON = 0b0000_1000_0000;  // 首 token 以 `:` / `：` 结尾
        // v3.1 M1: 注释行（`#` / `//` / `;` / `<!--`）—— grouper 不应用其 candidate 装配 Draft
        const IS_COMMENT      = 0b0001_0000_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineClass {
    pub kind: LineKind,
    pub flags: LineFlags,
}

/// 便捷 API：仅返回 kind（Stage 3/4 block 切分用）
#[allow(dead_code)]
pub fn classify_line(line: &str) -> LineKind {
    line_class(line).kind
}

/// v3.1 B1：同时返回 LineKind（语义）和 LineFlags（属性）
pub fn line_class(line: &str) -> LineClass {
    let t = line.trim();
    let mut flags = LineFlags::empty();
    if t.is_empty() {
        return LineClass { kind: LineKind::Empty, flags };
    }

    let has_email = re_email().is_match(t);
    let has_secret = re_any_secret().is_match(t);
    let has_url = re_url().is_match(t);

    if has_email { flags |= LineFlags::HAS_EMAIL; }
    if has_secret { flags |= LineFlags::HAS_SECRET; }
    if has_url { flags |= LineFlags::HAS_URL; }
    if t.contains("----") { flags |= LineFlags::HAS_DASH_RUN; }

    // v3.1 M1: 注释标记（`#` 含 Markdown heading; `//` 编程; `;` ini/conf; `<!--` HTML）
    //   Heading + 下面 commented-out secret 的粘贴笔记里，用户写 # 就是想"软删除"
    if t.starts_with('#') || t.starts_with("//") || t.starts_with(';') || t.starts_with("<!--") {
        flags |= LineFlags::IS_COMMENT;
    }

    let lower = t.to_lowercase();
    for lbl in &["密码", "password:", "pwd:", "pw:", "pass:"] {
        if lower.contains(lbl) { flags |= LineFlags::HAS_PWD_LABEL; break; }
    }

    // 首 token 以 `:` 结尾？
    let first = t.split_whitespace().next().unwrap_or("");
    if first.len() > 1 && (first.ends_with(':') || first.ends_with('\u{FF1A}')) {
        flags |= LineFlags::HAS_LABEL_COLON;
    }
    // 项目符号
    if first == "-" || first == "*" || first == "\u{2022}"
        || first.ends_with(')') && first.trim_end_matches(')').chars().all(|c| c.is_ascii_digit())
    {
        flags |= LineFlags::STARTS_BULLET;
    }
    // 孤立 token：整行去掉 markdown 包裹后只有 1 个 whitespace-分词
    let stripped_tokens: Vec<&str> = t.split_whitespace().collect();
    if stripped_tokens.len() == 1 {
        flags |= LineFlags::IS_SOLO_TOKEN;
    }

    // Priority 1 — 有凭证内容优先（避免 "----hunter2----sk-..." 被错判为 Separator）
    if t.contains("----") && (has_email || has_secret) {
        return LineClass { kind: LineKind::Complex, flags };
    }
    if has_email || has_secret {
        return LineClass { kind: LineKind::Credential, flags };
    }

    // Priority 2 — 分隔符行
    //   (a) 纯符号 `---` / `===` / `***`
    //   (b) banner `---- PROD ----` / `=== DEV ===`
    //   (c) 注释包裹 banner `# --- 公司项目 ---` —— kind 升 Separator, flags 保留 IS_COMMENT
    if re_pure_sep().is_match(t) {
        return LineClass { kind: LineKind::Separator, flags };
    }
    if re_banner_sep().is_match(t) {
        return LineClass { kind: LineKind::Separator, flags };
    }
    // (c) 注释包裹 banner
    if flags.contains(LineFlags::IS_COMMENT) {
        let body = t.trim_start_matches(|c: char| c == '#' || c == '/' || c == ';').trim();
        if !body.is_empty() {
            if re_pure_sep().is_match(body) || re_banner_sep().is_match(body) {
                return LineClass { kind: LineKind::Separator, flags };
            }
        }
    }

    // Priority 3 — 关键字 label 行
    for lbl in &["密码", "password", "email", "邮箱", "pwd", "pw:", "pass:",
                 "apikey", "api key", "api_key", "token", "key:", "key=",
                 "login:", "密钥", "base_url", "endpoint"] {
        if lower.contains(lbl) {
            return LineClass { kind: LineKind::Credential, flags };
        }
    }

    // Priority 4 — Title：首 token 以 `:` 结尾 或 全行以 `:` 结尾
    if flags.contains(LineFlags::HAS_LABEL_COLON) {
        return LineClass { kind: LineKind::Title, flags };
    }
    if t.ends_with(':') || t.ends_with('\u{FF1A}') {
        return LineClass { kind: LineKind::Title, flags };
    }

    // Priority 4.5 — alias 独行形态（soft Title）
    //   典型 `claude-backup (同事借的号，5/1 前还)` —— 首 token 纯 kebab 别名
    //   Why 要求 kebab: 避免把普通句子首词误抓
    let is_kebab_alias = first.len() >= 5
        && first.contains('-')
        && first.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if is_kebab_alias {
        let rest_start = first.len();
        let rest = t.get(rest_start..).unwrap_or("").trim_start();
        let is_paren_or_empty = rest.is_empty()
            || rest.starts_with('(')
            || rest.starts_with('\u{FF08}');
        if is_paren_or_empty {
            return LineClass { kind: LineKind::Title, flags };
        }
    }

    // Priority 5 — 括号注释（`(pro-04/15)`）
    if t.starts_with('(') || t.starts_with('\u{FF08}') {
        return LineClass { kind: LineKind::Note, flags };
    }

    LineClass { kind: LineKind::Note, flags }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_line() {
        let c = line_class("");
        assert_eq!(c.kind, LineKind::Empty);
        assert!(c.flags.is_empty());
    }

    #[test]
    fn comment_hash() {
        let c = line_class("# password: changeme");
        assert!(c.flags.contains(LineFlags::IS_COMMENT));
    }

    #[test]
    fn comment_slash_slash() {
        let c = line_class("// sk-ant-api03-OldKey_deprecated");
        assert!(c.flags.contains(LineFlags::IS_COMMENT));
    }

    #[test]
    fn banner_separator() {
        let c = line_class("==========================");
        assert_eq!(c.kind, LineKind::Separator);
    }

    #[test]
    fn banner_with_text() {
        let c = line_class("---- PROD ----");
        assert_eq!(c.kind, LineKind::Separator);
    }

    #[test]
    fn commented_banner_is_separator() {
        // v4.1 R3: `# --- 公司项目 ---` kind 升 Separator
        let c = line_class("# --- 公司项目 ---");
        assert_eq!(c.kind, LineKind::Separator);
        assert!(c.flags.contains(LineFlags::IS_COMMENT));
    }

    #[test]
    fn credential_email_plus_dash() {
        let c = line_class("alice@acme.io----hunter2----sk-ant-api03-abcdef_klmn_opqr_stuv_wxyz");
        assert_eq!(c.kind, LineKind::Complex);
        assert!(c.flags.contains(LineFlags::HAS_EMAIL));
        assert!(c.flags.contains(LineFlags::HAS_SECRET));
        assert!(c.flags.contains(LineFlags::HAS_DASH_RUN));
    }

    #[test]
    fn title_colon_suffix() {
        let c = line_class("claude3:");
        assert_eq!(c.kind, LineKind::Title);
        assert!(c.flags.contains(LineFlags::HAS_LABEL_COLON));
    }

    #[test]
    fn solo_token_flag() {
        let c = line_class("Hello_World_123!");
        assert!(c.flags.contains(LineFlags::IS_SOLO_TOKEN));
    }

    #[test]
    fn pwd_label_flag() {
        let c = line_class("password: Str0ng_P@ss!");
        assert!(c.flags.contains(LineFlags::HAS_PWD_LABEL));
    }
}
