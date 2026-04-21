//! Tokenizer：把一行文本切成候选 token（供 anchored / labeled rules 和 Phase 4 CRF 共用）
//!
//! # 扩展分隔符（相对原方案）
//! 从 `workflow/CI/research/ablation-spike/src/main.rs` 1:1 移植 + 补充真实用户场景验证过的边界：
//! - `----`（dash-separated）/ `|`（pipe-sep）/ `~~`（tilde）/ `===`（triple equals）/ `::`（double colon）
//! - `;`（Azure connection string）
//! - `：`（中文全角冒号，Feishu/Notion 粘贴）
//!
//! # Markdown / CSV 边缘清理
//! 从每个 token 两端剥除：`, . ; | : ~ " ' * ` [ ] ( ) ：`
//!
//! # 不 trim 的字符
//! - `=`：base64 padding（`==` 结尾合法）
//! - `/` `+`：base64 / URL 字符
//!
//! # 为什么不做"值内部" trim
//! 值内部可能真的有这些字符（如 `DevPass!2024`）。trim 只在 token 边缘。

/// 切分一行为 token 列表
pub fn tokenize_line(line: &str) -> Vec<String> {
    // Why 6 个分隔符 + 1 个中文：覆盖 ablation-spike 所有测试集 + 实际用户样本
    let delimiters: &[&str] = &[" | ", "----", "~~", "===", "::", ";", "\u{FF1A}"];
    let mut pieces: Vec<String> = line.split_whitespace().map(String::from).collect();
    for delim in delimiters {
        let mut next = Vec::with_capacity(pieces.len());
        for p in pieces {
            for seg in p.split(delim) {
                next.push(seg.to_string());
            }
        }
        pieces = next;
    }
    pieces
        .into_iter()
        .filter_map(|t| {
            // Why 不 trim '=': base64 padding (==) 是 token 本体一部分（APK-06 access_token）
            // Why trim '"' / "'": JSON 内嵌值 "api_key":"cust-xxx" 外层引号应剥除
            // Why trim '*' / '`': Markdown 粗体 **value** / 代码 `value` 包裹应剥除
            // Why trim '[' ']' '(' ')': Markdown 链接 [text](url) 粘贴残留 `[Moonshot` / `console]`
            let t = t.trim().trim_matches(|c: char| {
                c == ',' || c == '.' || c == ';' || c == '|'
                    || c == ':' || c == '~' || c == '"' || c == '\''
                    || c == '*' || c == '`'
                    || c == '[' || c == ']' || c == '(' || c == ')'
                    || c == '\u{FF1A}'
            });
            if t.is_empty() { None } else { Some(t.to_string()) }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_basic_whitespace() {
        let t = tokenize_line("hello world  foo");
        assert_eq!(t, vec!["hello", "world", "foo"]);
    }

    #[test]
    fn tokenize_dash_separated() {
        let t = tokenize_line("alice@x.com----mypwd----sk-ant-abcdef");
        assert_eq!(t, vec!["alice@x.com", "mypwd", "sk-ant-abcdef"]);
    }

    #[test]
    fn tokenize_tilde_separator() {
        let t = tokenize_line("tilde@waves.io~~WavePass99~~sk-ant-tilde-xyz");
        assert_eq!(t, vec!["tilde@waves.io", "WavePass99", "sk-ant-tilde-xyz"]);
    }

    #[test]
    fn tokenize_triple_equals() {
        let t = tokenize_line("pass === ProdPass!Strong");
        // `===` splits, ` ` also splits → ["pass", "ProdPass!Strong"]
        assert!(t.contains(&"pass".to_string()));
        assert!(t.contains(&"ProdPass!Strong".to_string()));
    }

    #[test]
    fn tokenize_full_width_colon() {
        let t = tokenize_line("\u{5BC6}\u{7801}\u{FF1A}MyFeishuPass!2024");
        assert!(t.contains(&"\u{5BC6}\u{7801}".to_string()));
        assert!(t.contains(&"MyFeishuPass!2024".to_string()));
    }

    #[test]
    fn tokenize_preserves_base64_padding() {
        // base64 padding `==` 是 token 一部分，不应该被 trim
        let t = tokenize_line("access_token: dGVzdA==");
        assert!(t.iter().any(|s| s == "dGVzdA=="), "tokens: {:?}", t);
    }

    #[test]
    fn tokenize_markdown_backticks_stripped() {
        // 反引号应从 token 两端剥除
        let t = tokenize_line("key `sk-xxx`");
        assert!(t.iter().any(|s| s == "sk-xxx"),
            "sk-xxx should survive backtick stripping, got: {:?}", t);
    }

    #[test]
    fn tokenize_markdown_link_does_not_split_mid_token() {
        // 注意：tokenize 不"分"markdown link，但两端的 `[` `)` 会被 trim。
        // 这对 Phase 2 OK —— URL 由 rule.rs 的 re_url 正则独立抽取，不依赖 tokenize。
        let t = tokenize_line("[Moonshot](https://x.io)");
        // 至少剥了两端 `[` 和 `)` —— 中间 `](` 保留
        let joined = t.join(" ");
        assert!(!joined.contains("[Moonshot"), "leading [ not trimmed: {:?}", t);
        assert!(!joined.ends_with(")"), "trailing ) not trimmed: {:?}", t);
    }

    #[test]
    fn tokenize_azure_connection_string() {
        let t = tokenize_line("DefaultEndpointsProtocol=https;AccountKey=xYz==;EndpointSuffix=x");
        // `;` splits 三段
        assert!(t.iter().any(|s| s.starts_with("DefaultEndpointsProtocol")));
        assert!(t.iter().any(|s| s.starts_with("AccountKey")));
        assert!(t.iter().any(|s| s.starts_with("EndpointSuffix")));
    }
}
