//! SGR helper for output that CANNOT go through the `colored` builders
//! (win10-conhost-compat follow-up, 2026-07-15).
//!
//! ## Why this module is tiny on purpose
//!
//! Color on/off has exactly one source of truth: `colored`'s global
//! colorize decision (NO_COLOR / CLICOLOR / tty detection / the
//! `set_override(false)` degrade in `term_caps::init()`). All runtime
//! output styles text via the `colored` builders (`.bold()`, `.yellow()`,
//! …), which consult that truth themselves.
//!
//! The single structural exception is clap's `help_template` attribute in
//! `cli.rs`: an attribute string is baked at compile time, so it cannot
//! call builders. Its rendered output is funneled through the two
//! `err.to_string()` print sites in `main.rs`, which wrap it with
//! [`paint`] — stripping the baked SGR codes whenever colored would not
//! colorize. `tests/glyph_fence.rs::sgr_literals_only_in_allowed_files`
//! mechanically keeps every other file free of raw `\x1b[..m` literals.

use std::borrow::Cow;

/// True when `colored` would emit color right now (single source of truth).
pub fn colorize_enabled() -> bool {
    colored::control::SHOULD_COLORIZE.should_colorize()
}

/// Pass text through unchanged when color is on; strip SGR sequences
/// (`ESC [ ... m`) when color is off. Cursor-control sequences (no `m`
/// terminator) are left alone — they are function, not decoration.
pub fn paint(s: &str) -> Cow<'_, str> {
    if colorize_enabled() {
        return Cow::Borrowed(s);
    }
    strip_sgr(s)
}

/// Cyan-bold a command name that sits INSIDE a `.dimmed()`-wrapped hint,
/// then resume the surrounding dim. `colored` has no notion of "nested
/// style context": its reset after the cyan segment would kill the outer
/// dim for the rest of the hint, so the dim-resume byte must be raw. It
/// lives here — gated on the same colorize truth — so no other file needs
/// a raw SGR literal for this trick.
pub fn cmd_in_dim(s: &str) -> String {
    use colored::Colorize;
    if colorize_enabled() {
        format!("{}\u{1b}[2m", s.cyan().bold())
    } else {
        s.to_string()
    }
}

/// Remove every `ESC [ <params> m` sequence from `s`.
pub fn strip_sgr(s: &str) -> Cow<'_, str> {
    if !s.contains('\u{1b}') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            // Collect the candidate sequence; only swallow it when it is
            // SGR (terminated by `m`) — otherwise emit it untouched.
            let mut seq = String::from(c);
            seq.push(chars.next().expect("peeked '['"));
            let mut is_sgr = false;
            while let Some(&n) = chars.peek() {
                if n.is_ascii_digit() || n == ';' {
                    seq.push(chars.next().expect("peeked param"));
                } else {
                    if n == 'm' {
                        chars.next();
                        is_sgr = true;
                    }
                    break;
                }
            }
            if !is_sgr {
                out.push_str(&seq);
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_sgr_only() {
        assert_eq!(strip_sgr("\u{1b}[1madd\u{1b}[0m <alias>"), "add <alias>");
        // Cursor control (no `m`) survives.
        assert_eq!(strip_sgr("\u{1b}[2Kline"), "\u{1b}[2Kline");
        assert_eq!(strip_sgr("plain"), "plain");
        assert_eq!(strip_sgr("\u{1b}[38;5;245m|\u{1b}[0m"), "|");
    }
}
