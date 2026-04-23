//! Layer 5 — block-first-line "title" extraction.
//!
//! Extracts the user-written Draft card title (e.g. `Kimitest8`, `工作号`)
//! from each block's first line when it looks like natural language.
//! The grouper later attaches the matched title to whichever draft
//! occupies the same block by line_range overlap (see
//! `grouping::cluster`).
//!
//! # Why a separate Layer 5 (rather than merging into rule.rs Layer 1)
//! The existing layers (email / url / secret / password / labeled /
//! PEM) all extract **credentials**. A title is metadata ABOUT a
//! credential — it needs its own Kind and its own shape rules. Mixing
//! it in would blur rule.rs's single responsibility and complicate the
//! dedup logic (title values are short English/CJK words that would
//! collide with password-shape heuristics).
//!
//! # Shape rule (see TITLE_ABLATION_REPORT §3 for empirical validation)
//! The first line of each block qualifies as a title when:
//!   1. length ≤ 60 chars (trimmed)
//!   2. not starting with `#` / `//` / `--` / `==` / `(` / `http(s)://`
//!   3. not starting with any known secret prefix
//!      (`sk-` / `sk-ant-` / `sk-proj-` / `gsk_` / `AIza(Sy)` / `AKIA` /
//!       `ghp_` / `github_pat_` / `xai-` / `sess_` / `SG.` / `hf_` /
//!       `glpat-` / `ya29.`)
//!   4. first 10 chars contain none of: `@ = : / \`
//!   5. letter ratio in first 10 chars ≥ 50%
//!      (ASCII letters + CJK + Hiragana / Katakana + Hangul syllables)
//!
//! Emits at most ONE title per block (first line only). Trims the line
//! before emission so `Kimitest8 ` with a trailing space ends up as
//! `Kimitest8`.

use super::candidate::{Candidate, Kind};
use super::rule::try_push;

const SECRET_PREFIXES: &[&str] = &[
    "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-", "sk-",
    "gsk_", "xai-", "sess_", "AIzaSy", "AIza",
    "AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "github_pat_", "hf_", "glpat-", "ya29.", "SG.",
];

/// Returns true if `line` (already trimmed, non-empty) looks like a
/// user-written short title. See module-level docs for the full rule set.
pub(super) fn is_natural_title(line: &str) -> bool {
    let char_len = line.chars().count();
    if char_len > 60 {
        return false;
    }
    if line.starts_with('#')
        || line.starts_with("//")
        || line.starts_with("--")
        || line.starts_with("==")
        || line.starts_with('(')
    {
        return false;
    }
    if line.starts_with("http://") || line.starts_with("https://") {
        return false;
    }
    for p in SECRET_PREFIXES {
        if line.starts_with(p) {
            return false;
        }
    }

    // First-10-chars shape window. Uses char-count (not bytes) so CJK
    // titles sample fairly across their multibyte UTF-8 encoding.
    let first10: String = line.chars().take(10).collect();
    for ch in first10.chars() {
        if ch == '@' || ch == '=' || ch == ':' || ch == '/' || ch == '\\' {
            return false;
        }
    }

    let total = first10.chars().count();
    if total == 0 {
        return false;
    }
    let letters = first10
        .chars()
        .filter(|c| {
            c.is_ascii_alphabetic()
                || (*c >= '\u{4E00}' && *c <= '\u{9FFF}')
                || (*c >= '\u{3040}' && *c <= '\u{30FF}')
                || (*c >= '\u{AC00}' && *c <= '\u{D7AF}')
        })
        .count();
    (letters * 2) >= total
}

/// Scans `text` block-by-block and pushes one `Kind::Title` candidate
/// per block that starts with a natural-language short first line.
///
/// Blocks are separated by blank lines (any line that trims to "").
/// `source_span` records the byte offset range of the title line inside
/// `text` so the grouper can look up the owning block by `line_range`
/// later.
pub fn extract(
    text: &str,
    cands: &mut Vec<Candidate>,
    seen: &mut std::collections::HashSet<String>,
) {
    let mut offset = 0usize;
    let mut in_block = false;
    for line in text.split_inclusive('\n') {
        // Strip the trailing '\n' (if any) for length / content checks.
        let line_no_nl = line.trim_end_matches('\n');
        let line_start = offset;
        let line_end = offset + line_no_nl.len();
        offset += line.len();

        let trimmed = line_no_nl.trim();
        if trimmed.is_empty() {
            in_block = false;
            continue;
        }
        if in_block {
            continue;
        }
        in_block = true;

        if !is_natural_title(trimmed) {
            continue;
        }
        let _ = try_push(
            cands,
            seen,
            Kind::Title,
            trimmed,
            Some([line_start, line_end]),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ascii_short_title() {
        assert!(is_natural_title("Kimitest8"));
        assert!(is_natural_title("Proj2024Main"));
        assert!(is_natural_title("\"Gemini dev\""));
    }

    #[test]
    fn accepts_cjk_title() {
        assert!(is_natural_title("工作号"));
        assert!(is_natural_title("测试号"));
    }

    #[test]
    fn rejects_long_sentence() {
        assert!(!is_natural_title(
            "This is a very long description line that should not be treated as a title because it exceeds sixty characters threshold"
        ));
    }

    #[test]
    fn rejects_url_line() {
        assert!(!is_natural_title("https://platform.moonshot.cn/console/api-keys"));
        assert!(!is_natural_title("http://example.com"));
    }

    #[test]
    fn rejects_secret_prefix() {
        assert!(!is_natural_title("sk-ant-api03-abcdef1234567890"));
        assert!(!is_natural_title("sk-proj-longtokenhere"));
        assert!(!is_natural_title("AIzaSyAbCdEf1234567890"));
        assert!(!is_natural_title("ghp_shortertoken"));
        assert!(!is_natural_title("AKIAEXAMPLEKEYID"));
    }

    #[test]
    fn rejects_label_value_line() {
        assert!(!is_natural_title("email: user@example.com"));
        assert!(!is_natural_title("password=Secret123"));
        assert!(!is_natural_title("token: abc123def"));
    }

    #[test]
    fn rejects_comment_or_heading() {
        assert!(!is_natural_title("# TODO list"));
        assert!(!is_natural_title("// note"));
        assert!(!is_natural_title("-- divider"));
        assert!(!is_natural_title("(optional note)"));
    }

    #[test]
    fn rejects_low_letter_ratio() {
        // "12345 abcd"  → 4 letters / 10 chars = 40% → reject
        assert!(!is_natural_title("12345 abcd"));
        // Pure digits
        assert!(!is_natural_title("1234567890"));
    }

    #[test]
    fn accepts_with_trailing_space_before_call() {
        // The caller is responsible for trimming; is_natural_title
        // only sees trimmed input.
        assert!(is_natural_title("Kimitest8"));
    }

    #[test]
    fn extract_emits_one_per_block() {
        let text = "Kimitest8\nhttps://platform.moonshot.cn/console/api-keys\nsk-Kh8bEwSPBsampleTokenABCD\n\nSecondBlock\nhttps://api.example.com\n";
        let mut cands = Vec::new();
        let mut seen = std::collections::HashSet::new();
        extract(text, &mut cands, &mut seen);
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0].value, "Kimitest8");
        assert_eq!(cands[0].kind, Kind::Title);
        assert_eq!(cands[1].value, "SecondBlock");
    }

    #[test]
    fn extract_trims_whitespace() {
        let text = "Kimitest8 \nhttps://a.b\n";
        let mut cands = Vec::new();
        let mut seen = std::collections::HashSet::new();
        extract(text, &mut cands, &mut seen);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].value, "Kimitest8");
    }

    #[test]
    fn extract_skips_secret_first_line() {
        // First line is a secret → no title emitted for this block.
        let text = "sk-leading-secret-firstline\nSome trailing notes\n";
        let mut cands = Vec::new();
        let mut seen = std::collections::HashSet::new();
        extract(text, &mut cands, &mut seen);
        assert!(cands.is_empty());
    }

    #[test]
    fn extract_skips_url_first_line() {
        let text = "https://api.anthropic.com/v1/messages\nperson@test.co\nPwd!88\n";
        let mut cands = Vec::new();
        let mut seen = std::collections::HashSet::new();
        extract(text, &mut cands, &mut seen);
        assert!(cands.is_empty());
    }
}
