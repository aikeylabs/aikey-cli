//! V4.1 守门规则工具集 — 从 V4.1 spike 迁移 (Stage 2a)
//!
//! # 覆盖
//! - ISSUE-4: `is_comment_at_offset(text, byte_off)` —— IS_COMMENT 行守门
//! - ISSUE-3: `token_has_cjk_or_fullwidth(tok)` —— CJK/全角标点 token 拒识
//! - Placeholder denylist: `is_placeholder_token(tok)` —— xxx/demo/changeme 等诱饵拒识
//!
//! # 对应 V4.1 源码
//!
//! `workflow/CI/research/ablation-spike-v4.1/src/main.rs`:
//! - `is_comment_at_offset` / `locate_line_by_offset`: L175-193
//! - `is_placeholder_token`: L558-650
//! - `token_has_cjk_or_fullwidth`: L266-275 (inline in rule_extract)

use super::line_class::{line_class, LineFlags};

/// 定位 byte offset 所在的源行（UTF-8 byte-offset → line content）
pub fn locate_line_by_offset(text: &str, byte_off: usize) -> Option<&str> {
    let mut cur = 0usize;
    for line in text.lines() {
        let line_end = cur + line.len();
        if byte_off >= cur && byte_off <= line_end { return Some(line); }
        cur = line_end + 1; // +1 for \n
    }
    None
}

/// ISSUE-4 守门：指定 offset 的行是否是注释行
pub fn is_comment_at_offset(text: &str, byte_off: usize) -> bool {
    if let Some(line) = locate_line_by_offset(text, byte_off) {
        line_class(line).flags.contains(LineFlags::IS_COMMENT)
    } else {
        false
    }
}

/// ISSUE-3 守门：token 含 CJK 字符或全角标点
/// Why 激进：ASCII password 本身不含 CJK；用户用中文当 password 极罕见
pub fn token_has_cjk_or_fullwidth(s: &str) -> bool {
    s.chars().any(|ch| {
        ('\u{4E00}'..='\u{9FFF}').contains(&ch)   // CJK Unified
            || ('\u{3400}'..='\u{4DBF}').contains(&ch)   // CJK Ext-A
            || ('\u{3000}'..='\u{303F}').contains(&ch)   // CJK punct
            || ('\u{FF00}'..='\u{FFEF}').contains(&ch)   // 全角标点
    })
}

/// Placeholder / 占位符 / 示例诱饵拒识
///
/// 典型:`changeme` / `your_key_here` / `PLEASE-REPLACE-WITH-YOUR-OWN` / `sk-example-xxx`
/// `demo1234` / `????` / `xxxxx` / `...`  / `还没想好` / `<请填入>` 等
///
/// 应用到:secret / password / email 全部 candidates
pub fn is_placeholder_token(tok: &str) -> bool {
    let lc = tok.to_lowercase();
    // 明显占位词（substring 匹配，case-insensitive）
    const PLACEHOLDER_SUBSTR: &[&str] = &[
        "changeme", "change_me", "change-me",
        "placeholder", "place_holder",
        "your_key", "your-key", "yourkey",
        "your_api", "your-api",
        "your_token", "your-token",
        "your_password", "your-password",
        "please_replace", "please-replace",
        "replace_with", "replace-with",
        "replace_this", "replace-this",
        "sk-example", "sk_example",
        "ak-example", "example-key", "example_key",
        "fake_key", "fake-key",
        "todo", "fixme",
        "yourapikey", "your_api_key",
    ];
    for p in PLACEHOLDER_SUBSTR {
        if lc.contains(p) { return true; }
    }
    // 纯重复字符 (xxxx / ????/ ...)
    let first_ch = tok.chars().next().unwrap_or('\0');
    if tok.len() >= 4 && tok.chars().all(|c| c == first_ch) {
        if matches!(first_ch, 'x' | 'X' | '?' | '.' | '*' | '0') { return true; }
    }
    // 中文典型占位
    const CN_PLACEHOLDER: &[&str] = &[
        "\u{8FD8}\u{6CA1}\u{60F3}\u{597D}",  // 还没想好
        "\u{5F85}\u{586B}",                     // 待填
        "\u{5360}\u{4F4D}",                     // 占位
    ];
    for p in CN_PLACEHOLDER {
        if tok.contains(p) { return true; }
    }
    // 角括号包裹（`<your_key>` / `<请填入>`）
    if (tok.starts_with('<') && tok.ends_with('>'))
        || (tok.starts_with('\u{3008}') && tok.ends_with('\u{3009}'))
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_guard_hash() {
        let text = "alice@ok.io\n# comment line\nbob@nope.io";
        // "bob@nope.io" 起点在第 3 行，不是注释
        let bob_off = text.find("bob@").unwrap();
        assert!(!is_comment_at_offset(text, bob_off));
        // "comment" 在 # 注释行
        let comment_off = text.find("comment").unwrap();
        assert!(is_comment_at_offset(text, comment_off));
    }

    #[test]
    fn comment_guard_slash_slash() {
        let text = "// sk-ant-api03-OldKey_rotated";
        assert!(is_comment_at_offset(text, 3));
    }

    #[test]
    fn cjk_rejected() {
        assert!(token_has_cjk_or_fullwidth("\u{5BC6}\u{7801}"));  // 密码
        assert!(token_has_cjk_or_fullwidth("test\u{FF09}"));       // test）
        assert!(!token_has_cjk_or_fullwidth("password"));
        assert!(!token_has_cjk_or_fullwidth("Str0ng_P@ss!"));
    }

    #[test]
    fn placeholder_detected() {
        assert!(is_placeholder_token("changeme"));
        assert!(is_placeholder_token("your_api_key"));
        assert!(is_placeholder_token("sk-example-xxx"));
        assert!(is_placeholder_token("xxxxxxxx"));
        assert!(is_placeholder_token("<your_key>"));
        assert!(!is_placeholder_token("Str0ng_P@ss!"));
        assert!(!is_placeholder_token("sk-ant-api03-realkey_xyz"));
    }
}
