//! Mechanical fence: user-visible Unicode glyphs live ONLY in src/symbols.rs
//! (win10-conhost-compat, 2026-07-15).
//!
//! ## Why
//!
//! Win10 conhost fonts cannot render these glyphs (users see □), so every
//! user-visible symbol must resolve through the Fancy/Safe table in
//! `src/symbols.rs`. A doc rule alone regresses within months — new features
//! re-introduce inline glyphs one println! at a time (see CLAUDE.md: 能写成
//! 守卫的规则就不要只写成文档). This test scans every non-comment line of
//! `src/**/*.rs`; any fenced glyph outside `symbols.rs` is a failure.
//!
//! Comments are stripped (quote-aware `//` + `/* */` handling) because
//! comments legitimately use arrows/box-drawing for diagrams. Whatever
//! survives stripping is code — and glyphs in code can only occur inside
//! string/char literals, i.e. output.
//!
//! If this fence turns red on your change: use `symbols::<CONST>.s()` (add a
//! table row if the glyph is new) instead of writing the glyph inline.
//!
//! Deliberately NOT fenced (verified present in BOTH NSimSun/GBK — the
//! zh-CN conhost font — and Consolas — the en-US conhost font — so they
//! never render as □): `· — … • – → ← ↑ ↓ ●`. On zh-CN conhost some render
//! full-width (East Asian ambiguous width), which wobbles alignment but
//! stays readable — a pre-existing cosmetic issue, out of scope here.
//! Box-drawing IS fenced despite font coverage: frames are alignment-
//! critical and full-width borders visually collapse the box on zh conhost.

use std::fs;
use std::path::{Path, PathBuf};

/// Glyphs that must not appear outside src/symbols.rs: missing from conhost
/// fonts (render as □) or alignment-critical box drawing, plus a blanket
/// ban on emoji/symbol planes.
const FENCED: &[char] = &[
    '\u{2713}', // ✓
    '\u{2717}', // ✗
    '\u{26a0}', // ⚠
    '\u{24d8}', // ⓘ
    '\u{21e1}', // ⇡
    '\u{21e3}', // ⇣
    '\u{21ba}', // ↺
    '\u{2295}', // ⊕
    '\u{276c}', // ❬
    '\u{29bf}', // ⦿
    '\u{276d}', // ❭
    '\u{2611}', // ☑
    '\u{2500}', // ─
    '\u{2502}', // │
    '\u{250c}', // ┌
    '\u{2510}', // ┐
    '\u{2514}', // └
    '\u{2518}', // ┘
];

fn is_fenced(c: char) -> bool {
    FENCED.contains(&c) || (c as u32) >= 0x1F000 // emoji & symbol planes
}

/// Strip `//` line comments and `/* */` block comments, quote-aware:
/// `//` inside a string literal ("http://…") does not start a comment.
/// Returns the code-only remainder of each line, tracking block-comment
/// state across lines via `in_block`.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if *in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                *in_block = false;
            }
            continue;
        }
        if in_string {
            out.push(c);
            if c == '\\' {
                // consume escaped char so \" doesn't close the string
                if let Some(esc) = chars.next() {
                    out.push(esc);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => break, // line comment
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                *in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Raw SGR color/style escapes (`ESC [ … m`) may not appear in string
/// literals outside their three audited homes (win10-conhost-compat
/// follow-up, 2026-07-15):
///
/// - `cli.rs` — clap `help_template` / `after_help` attributes are
///   compile-time strings that cannot call `colored` builders; their
///   rendered output is stripped via `style::paint` at the two
///   `err.to_string()` print sites in `main.rs`.
/// - `style.rs` — the strip/paint implementation and the `cmd_in_dim`
///   dim-resume trick.
/// - `commands_statusline.rs` — an ANSI *parser* (strip_ansi_escapes)
///   plus its test fixtures; it consumes codes, it doesn't emit them.
///
/// Everything else must style through `colored` builders so that the
/// global colorize switch (NO_COLOR / non-tty / `term_caps` conhost
/// degrade) is the single on/off truth. Cursor-control sequences
/// (`ESC[2K`, `ESC[nA`, `ESC[?25l` — no `m` terminator) are function,
/// not decoration, and stay allowed everywhere.
#[test]
fn sgr_literals_only_in_allowed_files() {
    const ALLOWED: &[&str] = &["cli.rs", "style.rs", "commands_statusline.rs"];
    let sgr = |code: &str| -> bool {
        // matches \x1b[<digits/;>m or \u{1b}[<digits/;>m escape spellings
        for pat in ["\\x1b[", "\\u{1b}["] {
            let mut rest = code;
            while let Some(pos) = rest.find(pat) {
                let tail = &rest[pos + pat.len()..];
                let params: usize = tail
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == ';')
                    .count();
                if tail[params..].starts_with('m') {
                    return true;
                }
                rest = &rest[pos + pat.len()..];
            }
        }
        false
    };

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);

    let mut violations = Vec::new();
    for path in files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if ALLOWED.contains(&name) {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable source file");
        let mut in_block = false;
        for (idx, line) in text.lines().enumerate() {
            let code = strip_comments(line, &mut in_block);
            if sgr(&code) {
                violations.push(format!(
                    "{}:{}: raw SGR escape — use `colored` builders (see tests/glyph_fence.rs)",
                    path.strip_prefix(&src).unwrap_or(&path).display(),
                    idx + 1
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "raw SGR escapes must go through `colored`, found {}:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn user_visible_glyphs_only_in_symbols_table() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 20, "sanity: src scan found too few files");

    let mut violations = Vec::new();
    for path in files {
        if path.file_name().is_some_and(|n| n == "symbols.rs") {
            continue; // the single allowed home for these glyphs
        }
        let text = fs::read_to_string(&path).expect("readable source file");
        let mut in_block = false;
        for (idx, line) in text.lines().enumerate() {
            let code = strip_comments(line, &mut in_block);
            if let Some(c) = code.chars().find(|&c| is_fenced(c)) {
                violations.push(format!(
                    "{}:{}: fenced glyph '{}' (U+{:04X}) — route it through src/symbols.rs",
                    path.strip_prefix(&src).unwrap_or(&path).display(),
                    idx + 1,
                    c,
                    c as u32
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "user-visible glyphs must come from src/symbols.rs (Fancy/Safe table), \
         found {} inline use(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
