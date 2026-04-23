//! Block 切分 — 把文本按 LineKind 分成若干 Block
//!
//! 从 V4.1 spike `grouping.rs::split_into_blocks` (L345-427) 迁移。
//!
//! # 算法
//! 按行扫描,遇到:
//!   - `Empty` / `Separator` → 关闭当前 block
//!   - `IS_COMMENT` flag → 关闭(注释行软删除语义,不进 block)
//!   - `Title` → 关闭前一 block,开启新 block 并填 provider_hint
//!   - 其他 (Credential / Complex / Note) → 延伸当前 block 或新开一个
//!
//! # provider_hint 提取规则
//!   - `claude3:` → "claude3"
//!   - `=== PROD ===` → "PROD"
//!   - `claude-backup (同事借的...)` (Priority 4.5 kebab alias) → "claude-backup"
//!   - Credential 首行 `OpenAI: sk-proj-...` (兜底) → "OpenAI"

use super::super::line_class::{line_class, LineFlags, LineKind};
use super::types::Block;

pub fn split_into_blocks(text: &str) -> Vec<Block> {
    let lines: Vec<&str> = text.lines().collect();
    let mut blocks: Vec<Block> = Vec::new();
    let mut cur: Option<Block> = None;

    for (i, line) in lines.iter().enumerate() {
        let lc = line_class(line);
        // v4.1 M1:注释行视为 block 间隔,不进任何 block
        //   `# dev-old@acme.cn` 被软删除的凭证不应装配成 Draft
        if lc.flags.contains(LineFlags::IS_COMMENT) {
            if let Some(b) = cur.take() { blocks.push(b); }
            continue;
        }
        let k = lc.kind;
        match k {
            LineKind::Empty | LineKind::Separator => {
                if let Some(b) = cur.take() { blocks.push(b); }
            }
            LineKind::Title => {
                if let Some(b) = cur.take() { blocks.push(b); }
                let trimmed = line.trim();
                let first = trimmed.split_whitespace().next().unwrap_or("");
                let is_kebab_alias_first = first.len() >= 5
                    && first.contains('-')
                    && first.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
                let hint_text = if first.len() > 1
                    && (first.ends_with(':') || first.ends_with('\u{FF1A}'))
                {
                    first.trim_end_matches(':').trim_end_matches('\u{FF1A}').to_string()
                } else if is_kebab_alias_first {
                    first.to_string()
                } else {
                    trimmed
                        .trim_end_matches(':')
                        .trim_end_matches('\u{FF1A}')
                        .trim()
                        .trim_matches(|c: char| c == '=' || c == '#' || c == '*')
                        .trim()
                        .to_string()
                };
                cur = Some(Block {
                    start_line: i,
                    end_line: i,
                    provider_hint: Some(hint_text),
                    kinds: vec![LineKind::Title],
                });
            }
            other => {
                match cur {
                    Some(ref mut b) => {
                        b.end_line = i;
                        b.kinds.push(other);
                    }
                    None => {
                        // 兜底:新 block 无 Title 开头,但首行 Credential 且首 token 带 `:` 结尾
                        // (如 `OpenAI: sk-proj-...`),把 token 作 provider_hint
                        let hint = line.trim()
                            .split_whitespace()
                            .next()
                            .and_then(|first| {
                                if first.len() > 1
                                    && (first.ends_with(':') || first.ends_with('\u{FF1A}'))
                                {
                                    Some(
                                        first
                                            .trim_end_matches(':')
                                            .trim_end_matches('\u{FF1A}')
                                            .to_string(),
                                    )
                                } else {
                                    None
                                }
                            });
                        cur = Some(Block {
                            start_line: i,
                            end_line: i,
                            provider_hint: hint,
                            kinds: vec![other],
                        });
                    }
                }
            }
        }
    }
    if let Some(b) = cur { blocks.push(b); }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_no_blocks() {
        assert_eq!(split_into_blocks("").len(), 0);
    }

    #[test]
    fn single_title_plus_credential() {
        let text = "claude3:\nalice@acme.io\nsk-ant-api03-AAA_BBB_CCC_ddd_eee";
        let blocks = split_into_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].provider_hint.as_deref(), Some("claude3"));
        assert_eq!(blocks[0].start_line, 0);
        assert_eq!(blocks[0].end_line, 2);
    }

    #[test]
    fn separator_splits_blocks() {
        let text = "claude2:\nsk-ant-api03-AAA_BBB_CCC_ddd_eee\n===\nopenai:\nsk-proj-XXX_YYY_ZZZ_aaa_bbb_ccc";
        let blocks = split_into_blocks(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].provider_hint.as_deref(), Some("claude2"));
        assert_eq!(blocks[1].provider_hint.as_deref(), Some("openai"));
    }

    #[test]
    fn comment_line_closes_block() {
        let text = "claude2:\nsk-ant-api03-AAA_BBB_CCC_ddd_eee\n# archived\nnext@test.io\n";
        let blocks = split_into_blocks(text);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn inline_title_credential_fallback_hint() {
        // Credential 行本身带 `OpenAI:` 首 token 作兜底 hint
        let text = "OpenAI: sk-proj-AAA_BBB_CCC_ddd_eee";
        let blocks = split_into_blocks(text);
        assert_eq!(blocks.len(), 1);
        // 这种情况 line_class 会把它判成 Credential(因含 sk- secret),所以走 other 分支
        // first token = "OpenAI:",hint = "OpenAI"
        assert_eq!(blocks[0].provider_hint.as_deref(), Some("OpenAI"));
    }

    #[test]
    fn kebab_alias_title() {
        let text = "claude-backup\nalice@test.io\n";
        let blocks = split_into_blocks(text);
        assert_eq!(blocks.len(), 1);
        // "claude-backup" 满足 kebab alias 且后无文本 → Priority 4.5 soft Title
        assert_eq!(blocks[0].provider_hint.as_deref(), Some("claude-backup"));
    }
}
