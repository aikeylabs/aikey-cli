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
//! Deliberately NOT fenced — GDI GetGlyphIndicesW-verified present in BOTH
//! the default Win10 Lucida Console AND Consolas (2026-07-15 probe on a real
//! Win10 19045 conhost): `· — … • – → ← ↑ ↓ ▲`. On zh-CN conhost some render
//! full-width (East Asian ambiguous width), which wobbles alignment but
//! stays readable — a pre-existing cosmetic issue, out of scope here.
//! Box-drawing IS fenced despite font coverage: frames are alignment-
//! critical and full-width borders visually collapse the box on zh conhost.
//!
//! NOTE: `●` was previously in the not-fenced list on the ASSUMPTION it was
//! font-safe; the probe found it MISSING in Lucida Console (the Win10
//! default) → □. It, plus `↗ ↻ ➤ ❌`, are now fenced. Lesson: font coverage
//! is an empirical fact to probe, not assume (there is no default font that
//! covers everything — pick the ASCII fallback).

use std::fs;
use std::path::{Path, PathBuf};

/// Documentation of specific known-offender glyphs and their replacements.
/// NOTE: `is_fenced` no longer consults this list — it blanket-fences the
/// whole `0x2010..=0x2BFF` symbol/arrow/box/dingbat swath (plus emoji) minus
/// `ALLOWED_INLINE`. This allowlist flip is deliberate: the old denylist
/// leaked `●`, then `↳◆ℹ❓`, then `↔◀▶`, across three rounds — each a glyph
/// nobody thought to list. Kept here purely as a "what maps to what" index.
#[allow(dead_code)]
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
    '\u{25cf}', // ● — MISSING in Lucida Console (Win10 default) → □; use RADIO_ON
    '\u{25cb}', // ○ — empty circle, same font risk; use RADIO_OFF
    '\u{2197}', // ↗ — MISSING in Lucida Console + Consolas; use LINK_OUT
    '\u{21bb}', // ↻ — MISSING in Lucida Console + Consolas; use REFRESH
    '\u{27a4}', // ➤ — MISSING in Lucida Console + Consolas; use POINTER
    '\u{274c}', // ❌ — MISSING in every conhost font (emoji); use CROSS
    '\u{21b3}', // ↳ — MISSING in Lucida Console (doctor hints); use HINT_ARROW
    '\u{25c6}', // ◆ — MISSING in Lucida Console (add/auth prompts); use PROMPT
    '\u{2139}', // ℹ — MISSING in Lucida Console; use INFO_I
    '\u{2753}', // ❓ — MISSING in Lucida Console (dialog icons); use QUESTION
    '\u{23f1}', // ⏱ — MISSING in every conhost font (emoji); use STOPWATCH
    '\u{2500}', // ─
    '\u{2502}', // │
    '\u{250c}', // ┌
    '\u{2510}', // ┐
    '\u{2514}', // └
    '\u{2518}', // ┘
];

/// The ONLY non-ASCII glyphs allowed inline in output strings — GDI
/// GetGlyphIndicesW-verified present in ALL THREE conhost fonts a Win10 user
/// might have: Lucida Console (en default), Consolas, and NSimSun (zh-CN
/// default). Everything else in the symbol/arrow/box/dingbat/emoji range is
/// fenced (allowlist, not denylist — denylist leaked ●, ↳◆, then ↔ across
/// three rounds). `·`(00B7) and `×`(00D7) sit below the fenced range so they
/// need no entry here.
const ALLOWED_INLINE: &[char] = &[
    '\u{2192}', // →
    '\u{2190}', // ←
    '\u{2191}', // ↑
    '\u{2193}', // ↓
    '\u{2014}', // —
    '\u{2013}', // –
    '\u{2026}', // …
    '\u{2022}', // •
    '\u{25b2}', // ▲
    '\u{2264}', // ≤ — GDI-ok on Lucida/Consolas/NSimSun (test & error messages)
    '\u{2260}', // ≠ — GDI-ok on all three
    '\u{2265}', // ≥ — GDI-ok on all three
];

fn is_fenced(c: char) -> bool {
    if ALLOWED_INLINE.contains(&c) {
        return false;
    }
    let cp = c as u32;
    // Blanket-fence the Unicode blocks conhost fonts routinely lack a glyph
    // for (arrows, math, misc-technical, box, block, geometric, misc-symbols,
    // dingbats, supplemental arrows) plus the emoji planes. This is the
    // root-cause close: a NEW glyph anywhere in this swath is auto-caught, so
    // it must go through src/symbols.rs (Fancy/Safe) instead of shipping □.
    // FENCED is kept only as documentation of the specific known offenders.
    let _ = FENCED;
    (0x2010..=0x2bff).contains(&cp) || cp >= 0x1f000
}

/// Find the first `\u{XXXX}` escape in `code` whose decoded codepoint is
/// fenced. Catches escaped-form offenders (e.g. `"\u{25c6}"`) that a raw
/// `chars()` scan misses. Returns the offending char, not the escape text.
fn escaped_fenced(code: &str) -> Option<char> {
    let bytes = code.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'\\' && bytes[i + 1] == b'u' && bytes[i + 2] == b'{' {
            let start = i + 3;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if let Ok(cp) = u32::from_str_radix(&code[start..j], 16) {
                if let Some(c) = char::from_u32(cp) {
                    if is_fenced(c) {
                        return Some(c);
                    }
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    None
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
        // cli.rs's only fancy glyphs are the owl banner art, which
        // `print_banner` renders ONLY in Fancy tier (Safe tier prints a plain
        // text banner and returns early) — those literals never reach a
        // glyph-poor conhost. Its help_template is ASCII + SGR (no glyphs).
        let banner_art_file = path.file_name().is_some_and(|n| n == "cli.rs");
        let text = fs::read_to_string(&path).expect("readable source file");
        let mut in_block = false;
        for (idx, line) in text.lines().enumerate() {
            // Lines carrying a Safe-tier-gated art marker (e.g. the connectivity
            // blink animation, whose Fancy frames are swapped for ASCII in Safe
            // tier) are legitimately allowed to hold fenced glyphs inline.
            if banner_art_file || line.contains("glyph-fence-allow") {
                continue;
            }
            let code = strip_comments(line, &mut in_block);
            // Check BOTH raw glyph literals AND `\u{XXXX}` escape spellings —
            // the SGR→colored migration produced escaped forms, and hand-written
            // escapes (e.g. "\u{25c6}") would otherwise evade a raw-char scan.
            let offender = code
                .chars()
                .find(|&c| is_fenced(c))
                .or_else(|| escaped_fenced(&code));
            if let Some(c) = offender {
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
