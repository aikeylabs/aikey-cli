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

/// v4.1 Stage 2d · context_reject_labels v2：检查 byte_off 所在行是否是
/// git commit / docker digest / SHA hash 的上下文，是则拒识（防长 hex 被当 api_key）。
///
/// 三种形态任一触发:
///   1. **行首 label + 分隔符**: `commit:` / `sha256=` / `sha-1 : ...`
///   2. **行首 label + 空格 + alnum**: `commit abc123` (git log) / `sha 7a8b...`
///   3. **任意位置 `@label:`**: `openai/gpt-proxy@sha256:7a8b...` (docker digest)
///
/// Why 不绑定 provider:
/// CLI 的 rule.rs 用硬编码 regex（sk-/sk-ant-/ghp_/hex_long 等）而非 YAML-driven
/// 抽取；v4.1 spike 的 context_reject 是 per-provider 的 YAML config。CLI 在这里
/// 做全局拒识，保 `long-hex` / `short-prefix-secret` 两条路都被 cover 到。
/// 完整 YAML-driven 的实现留给 v1.1+ 迁移。
///
/// 对应 V4.1: `provider_fingerprint.rs::is_context_rejected` 实现。
pub fn is_in_reject_context(text: &str, byte_off: usize) -> bool {
    let Some(line) = locate_line_by_offset(text, byte_off) else { return false; };
    let trimmed_lc = line.trim().to_lowercase();

    // 与 v4.1 spike YAML `generic_hex_long.context_reject_labels` 对齐
    const REJECT_LABELS: &[&str] = &[
        "commit", "sha", "sha-1", "sha1",
        "sha-256", "sha256", "sha-512",
    ];

    for lbl in REJECT_LABELS {
        // 形态 1+2: 行首 label
        if let Some(rest) = trimmed_lc.strip_prefix(lbl) {
            let next = rest.chars().next();
            match next {
                Some(':') | Some('=') => return true,
                Some(ch) if ch.is_whitespace() => {
                    let after = rest.trim_start();
                    let nx = after.chars().next();
                    // 形态 1 变体: `label : value` / `label = value`
                    if matches!(nx, Some(':') | Some('=')) { return true; }
                    // 形态 2: `commit abc123` —— 空格后直接 alnum（hash-like）
                    if nx.map(|c| c.is_ascii_alphanumeric()).unwrap_or(false) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        // 形态 3: 任意位置 `@<label>:`（docker digest）
        let needle = format!("@{}:", lbl);
        if trimmed_lc.contains(&needle) {
            return true;
        }
    }
    false
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

/// V4.1 label_shape 拒识 —— token 是"标签"形态 (vs value)
///
/// 典型:`claude2: SF (pro-04/15)` 行里 `claude2` 是标签,不该当 password。
/// V4.1 spike `main.rs::is_label_shape` 迁移 (L722-767)。
///
/// 三档(任一命中即是 label,不该入 password 候选):
/// (a) 纯 kebab-case:全 `[a-z0-9-]` 且 ≥1 `-` (如 `claude-main`)
/// (b) token 紧跟 `:` / `：` / `=` 且长度 < 16 (如 `claude2:` → `claude2` 是 label)
/// (c) provider keyword 前缀 + 纯数字/dash 后缀 (如 `openai-1`, `claude-2`)
///
/// `line` 参数:token 所在完整行,用于查 token 尾部紧跟字符。
pub fn is_label_shape(tok: &str, line: &str) -> bool {
    // (a) 纯 kebab-case
    let is_kebab = tok.contains('-')
        && tok.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if is_kebab { return true; }

    // (b) token + `:` / `=` (短 token)
    if tok.chars().count() < 16 {
        if let Some(tok_start) = line.find(tok) {
            let tok_end = tok_start + tok.len();
            let rest = line[tok_end..].chars().find(|c| !c.is_whitespace());
            if matches!(rest, Some(':') | Some('\u{FF1A}') | Some('=')) {
                return true;
            }
        }
    }

    // (c) provider keyword 前缀 + 数字/dash 后缀
    const PROVIDER_KEYWORDS: &[&str] = &[
        "claude", "anthropic", "openai", "gpt", "kimi", "moonshot",
        "gemini", "groq", "deepseek", "xai", "grok", "zhipu", "glm",
        "doubao", "silicon", "huggingface", "perplexity", "openrouter",
    ];
    let lc = tok.to_lowercase();
    for kw in PROVIDER_KEYWORDS {
        if !lc.starts_with(kw) || lc.len() == kw.len() { continue; }
        let suffix = &lc[kw.len()..];
        let all_digits = !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit());
        let dashed = suffix.starts_with('-');
        if all_digits || dashed { return true; }
    }
    false
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
    fn reject_context_git_commit() {
        // 形态 2: `commit <hash>`
        let text = "commit f3a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6";
        let hash_off = text.find("f3a8").unwrap();
        assert!(is_in_reject_context(text, hash_off));
    }

    #[test]
    fn reject_context_docker_digest() {
        // 形态 3: `@sha256:<hash>` 中间位置
        let text = "docker pull openai/gpt-proxy@sha256:7a8b9c0d1e2f3a4b5c6d7e8f";
        let hash_off = text.find("7a8b").unwrap();
        assert!(is_in_reject_context(text, hash_off));
    }

    #[test]
    fn reject_context_colon_label() {
        // 形态 1: `sha256: <hash>`
        let text = "sha256: abcd1234";
        assert!(is_in_reject_context(text, text.find("abcd").unwrap()));
    }

    #[test]
    fn no_reject_context_for_normal_secret_line() {
        let text = "sk-ant-api03-RealProduction_Key_xyz";
        assert!(!is_in_reject_context(text, 0));
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
