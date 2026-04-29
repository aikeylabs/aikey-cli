//! Shared box-frame rendering for terminal UI.
//!
//! Provides ANSI-aware width calculation and consistent bordered boxes
//! used by the interactive selector, confirmation dialogs, and list displays.

/// Strip ANSI escape sequences and compute visible display width.
///
/// Accounts for:
/// - ANSI escape sequences (stripped, 0 width)
/// - CJK / emoji characters (2 columns each)
/// - Regular ASCII (1 column each)
pub fn visible_len(s: &str) -> usize {
    let mut len = 0usize;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            len += char_width(c);
        }
    }
    len
}

/// Approximate display width of a single character.
/// Emoji and CJK fullwidth characters occupy 2 terminal columns.
fn char_width(c: char) -> usize {
    let cp = c as u32;
    // Variation selectors and ZWJ — zero width.
    if cp == 0xFE0F || cp == 0x200D { return 0; }

    // Emoji that render as wide (2-column) glyphs in modern terminals.
    // Only include ranges where the glyph is *always* wide (color emoji).
    // Ranges like U+2600–U+27BF contain text-presentation symbols (✓✗→←)
    // that are 1 column wide — do NOT include them here.
    if cp >= 0x1F300 && cp <= 0x1FBFF { return 2; } // Misc Symbols & Pictographs, Emoticons, etc.
    if cp >= 0x2705 && cp == 0x2705 { return 2; }    // ✅ (white heavy check mark — emoji presentation)
    if cp == 0x2753 || cp == 0x2754 || cp == 0x2755 { return 2; } // ❓❔❕
    if cp == 0x2614 || cp == 0x2615 { return 2; }    // ☔☕ (always wide)
    if cp == 0x267F { return 2; }                     // ♿
    if cp == 0x2693 { return 2; }                     // ⚓
    if cp == 0x26A1 { return 2; }                     // ⚡
    if cp == 0x26D4 { return 2; }                     // ⛔
    if cp == 0x2934 || cp == 0x2935 { return 2; }     // ⤴⤵

    // CJK Unified Ideographs.
    if cp >= 0x4E00 && cp <= 0x9FFF { return 2; }
    if cp >= 0x3400 && cp <= 0x4DBF { return 2; }
    // Fullwidth Forms.
    if cp >= 0xFF01 && cp <= 0xFF60 { return 2; }

    // Everything else: ASCII, arrows, check marks, box-drawing, etc. → 1 column.
    1
}

/// Pad a string (which may contain ANSI codes) to exactly `target_vis` visible columns.
pub fn pad_visible(s: &str, target_vis: usize) -> String {
    let vis = visible_len(s);
    if vis >= target_vis {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(target_vis - vis))
    }
}

/// Right margin added to the widest content line so the right border
/// has breathing room and minor measurement errors don't break alignment.
const RIGHT_MARGIN: usize = 6;

/// Detect terminal width. Falls back to 80 if unavailable.
///
/// Shell wrappers like `eval $(aikey activate ...)` capture stdout via command
/// substitution, so `STDOUT_FILENO` is a pipe — ioctl there returns 0 cols.
/// Try stderr and stdin as fallbacks because pickers render to stderr and
/// the controlling terminal is almost always connected there.
pub fn term_width() -> usize {
    // $COLUMNS is set by interactive shells but usually not exported to
    // subprocesses; still worth trying first when it is propagated.
    if let Ok(val) = std::env::var("COLUMNS") {
        if let Ok(w) = val.parse::<usize>() {
            if w > 0 { return w; }
        }
    }
    #[cfg(unix)]
    {
        use std::mem::MaybeUninit;
        #[repr(C)]
        struct Winsize { ws_row: u16, ws_col: u16, ws_xpixel: u16, ws_ypixel: u16 }
        #[cfg(target_os = "macos")]
        const TIOCGWINSZ: libc::c_ulong = 0x40087468;
        #[cfg(not(target_os = "macos"))]
        const TIOCGWINSZ: libc::c_ulong = 0x5413;
        for fd in [libc::STDERR_FILENO, libc::STDOUT_FILENO, libc::STDIN_FILENO] {
            unsafe {
                let mut ws = MaybeUninit::<Winsize>::zeroed();
                if libc::ioctl(fd, TIOCGWINSZ, ws.as_mut_ptr()) == 0 {
                    let ws = ws.assume_init();
                    if ws.ws_col > 0 { return ws.ws_col as usize; }
                }
            }
        }
    }
    // Windows: GetConsoleScreenBufferInfo probe lives in the sibling
    // `ui_frame_windows` module (Strategy A pure — keeps ui_frame.rs
    // Unix macOS-byte-clean). Stage 1.3 extracted 2026-04-29.
    #[cfg(windows)]
    {
        if let Some(cols) = crate::ui_frame_windows::term_width_windows() {
            return cols;
        }
    }
    80
}

/// True when the terminal is too narrow to comfortably fit the boxed layout.
/// `AIKEY_COMPACT` forces the decision: `1`/`true`/`yes` → always narrow,
/// `0`/`false`/`no` → always wide. Otherwise auto-detect below 90 columns.
pub fn is_narrow() -> bool {
    if let Ok(v) = std::env::var("AIKEY_COMPACT") {
        match v.as_str() {
            "1" | "true" | "yes" | "on" => return true,
            "0" | "false" | "no" | "off" => return false,
            _ => {}
        }
    }
    term_width() < 90
}

/// Render a complete box frame to a String.
///
/// - `icon`: leading icon in the title bar (e.g. "🔍", "❓", "📋"), or "" for none
/// - `title`: text shown in the top border
/// - `rows`: content lines (may contain ANSI color codes)
pub fn render_box(icon: &str, title: &str, rows: &[String]) -> String {
    let icon_title = if icon.is_empty() {
        title.to_string()
    } else {
        format!("{} {}", icon, title)
    };

    // Compute inner width from content + margin.
    let content_max = rows.iter()
        .map(|r| visible_len(r))
        .max()
        .unwrap_or(20);
    let title_vis = visible_len(&icon_title);
    // inner_w = widest content + 2 side padding + right margin
    // Cap at terminal width minus box borders and outer margins (│ + 2 spaces each side + │ = 6).
    let max_inner = term_width().saturating_sub(6);
    let inner_w = (content_max.max(title_vis) + 4 + RIGHT_MARGIN).min(max_inner);

    let title_fill = inner_w.saturating_sub(title_vis + 3);
    let border = "\u{2500}".repeat(inner_w);

    // Outer frame glyphs use a mid-gray (256-color 245), noticeably brighter
    // than `\x1b[90m` (which is already used for the inner separator) but
    // still clearly secondary to the content.
    const FRAME: &str = "\x1b[38;5;245m";
    const RESET: &str = "\x1b[0m";

    let mut out = String::new();
    let pad_target = inner_w.saturating_sub(4);

    if is_narrow() {
        // Compact layout: skip the vertical `│` walls and corner glyphs to
        // reclaim ~12 cols on a tight terminal. Title + horizontal rules
        // still fence the section visually.
        let rule = "\u{2500}".repeat(pad_target);
        out.push_str(&format!("  {}\n", icon_title));
        out.push_str(&format!("  {f}{}{r}\n", rule, f = FRAME, r = RESET));
        for row in rows {
            let is_separator = !row.is_empty() && row.chars().all(|c| c == '\u{2500}');
            if is_separator {
                out.push_str(&format!("  \x1b[90m{}\x1b[0m\n", rule));
            } else {
                out.push_str(&format!("  {}\n", row));
            }
        }
        out.push_str(&format!("  {f}{}{r}", rule, f = FRAME, r = RESET));
        return out;
    }

    // Wide layout: full boxed rendering.
    // Top border with title. Only the frame glyphs are colored — the title
    // text keeps whatever color the caller passed in.
    out.push_str(&format!("  {f}\u{250C}\u{2500}{r} {} {f}{}\u{2510}{r}\n",
        icon_title, "\u{2500}".repeat(title_fill),
        f = FRAME, r = RESET));
    // Content rows: format is `│  {content}  │`
    // Left margin = 2 spaces, right margin = 2 spaces → content width = inner_w - 4
    for row in rows {
        // Auto-stretch separator lines (pure ─ characters) to fill the content area.
        let is_separator = !row.is_empty() && row.chars().all(|c| c == '\u{2500}');
        if is_separator {
            out.push_str(&format!("  {f}\u{2502}{r}  \x1b[90m{}\x1b[0m  {f}\u{2502}{r}\n",
                "\u{2500}".repeat(pad_target),
                f = FRAME, r = RESET));
        } else {
            out.push_str(&format!("  {f}\u{2502}{r}  {}  {f}\u{2502}{r}\n",
                pad_visible(row, pad_target),
                f = FRAME, r = RESET));
        }
    }
    // Bottom border.
    out.push_str(&format!("  {f}\u{2514}{}\u{2518}{r}",
        border, f = FRAME, r = RESET));
    out
}

/// Print a box frame to stderr (used by confirmation dialogs).
pub fn eprint_box(icon: &str, title: &str, rows: &[String]) {
    eprintln!("{}", render_box(icon, title, rows));
}

/// Print a box frame to stdout (used by list/info displays).
pub fn print_box(icon: &str, title: &str, rows: &[String]) {
    println!("{}", render_box(icon, title, rows));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// term_width must always return a positive value, even when stdin /
    /// stdout / stderr are all redirected (no console attached). Stage
    /// 1.3 windows-compat regression guard: an earlier draft returned 0
    /// when GetConsoleScreenBufferInfo failed on a piped handle, which
    /// caused divide-by-zero in box renderer width math.
    #[test]
    fn term_width_is_always_positive() {
        let w = term_width();
        assert!(w > 0, "term_width returned 0; box renderer would divide by zero");
    }

    /// Bounded sanity: term_width should never exceed some absurd value.
    /// 4096 cols is wider than any practical terminal; if we see more,
    /// we're returning a garbage value (e.g. negative converted to usize).
    #[test]
    fn term_width_is_bounded() {
        let w = term_width();
        assert!(w <= 4096, "term_width returned absurd value: {w}");
    }

    /// COLUMNS env var must take priority over the OS-specific probe so
    /// CI runners can pin a width for snapshot-style tests. Both Unix
    /// and Windows code paths honour this.
    #[test]
    fn term_width_respects_columns_env() {
        let prev = std::env::var_os("COLUMNS");
        std::env::set_var("COLUMNS", "120");
        let w = term_width();
        // Restore before asserting in case the assertion panics.
        match prev {
            Some(v) => std::env::set_var("COLUMNS", v),
            None => std::env::remove_var("COLUMNS"),
        }
        assert_eq!(w, 120);
    }

    /// is_narrow defaults to true on terminals < 90 cols.
    /// Narrow box layout is the path Windows users hit most often
    /// because the default cmd.exe window is 80 cols.
    #[test]
    fn is_narrow_at_80_cols() {
        let prev = std::env::var_os("COLUMNS");
        std::env::set_var("COLUMNS", "80");
        std::env::remove_var("AIKEY_COMPACT");
        let result = is_narrow();
        match prev {
            Some(v) => std::env::set_var("COLUMNS", v),
            None => std::env::remove_var("COLUMNS"),
        }
        assert!(result, "80-col terminal must select narrow layout");
    }
}
