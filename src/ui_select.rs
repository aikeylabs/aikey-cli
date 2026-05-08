//! Interactive box-framed selector for terminal UI.
//!
//! Renders a bordered list of items with arrow-key navigation.
//! Non-selectable rows (separators, disabled keys) are skipped automatically.
//!
//! # Windows status (Stage 1 windows-compat)
//!
//! The interactive path (`interactive_select` / `interactive_multi_select`
//! / `interactive_provider_tree`) is `#[cfg(unix)]` because it relies on
//! `/dev/tty` + termios for raw input. On Windows the public dispatchers
//! transparently fall through to the `fallback_*` numbered-list path,
//! which works on cmd / PowerShell / Windows Terminal but lacks arrow-key
//! navigation.
//!
//! The full Windows console-mode impl (ReadConsoleInputW + KEY_EVENT
//! parsing, mirroring the Unix raw-key path) is tracked separately in
//! windows-compatibility.md §1.2 and will land in a focused PR with the
//! §7.3 byte-level macOS comparison required for high-risk files. We keep
//! the Stage-1 PR scope small to minimise Unix-side regression risk.

#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};
use crate::ui_frame::{visible_len, pad_visible};

/// Result of `box_select`: chosen index or cancelled.
pub enum SelectResult {
    /// User pressed Enter on a selectable row.
    Selected(usize),
    /// User pressed Esc or Ctrl-C.
    Cancelled,
}

/// Renders an interactive box-framed selector and returns the chosen index.
///
/// Windows: see module-level note — interactive path is Unix-only for now;
/// non-Unix targets fall through to the numbered-list `fallback_select`.
pub fn box_select(
    title: &str,
    header: &str,
    items: &[String],
    selectable: &[bool],
    initial: usize,
) -> Result<SelectResult, Box<dyn std::error::Error>> {
    if items.is_empty() {
        return Err("No items to select from.".into());
    }

    #[cfg(unix)]
    {
        use std::io::IsTerminal;
        if !io::stderr().is_terminal() {
            return fallback_select(items, selectable);
        }
    }

    #[cfg(unix)]
    return interactive_select(title, header, items, selectable, initial);

    // Stage 1.2 (2026-04-29) windows-compat: native Windows console picker
    // (ReadConsoleInputW + VT output). Falls through to fallback_select if
    // RawConsole::open() fails (stdin / stderr redirected → no real console
    // attached, e.g. CI without TTY).
    #[cfg(windows)]
    {
        match crate::ui_select_windows::interactive_select_windows(title, header, items, selectable, initial) {
            Ok(r) => return Ok(r),
            Err(_) => return fallback_select(items, selectable),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (title, header, initial); // suppress unused-variable warnings on the fallback path
        fallback_select(items, selectable)
    }
}

/// Simple numbered-list fallback for non-TTY environments.
fn fallback_select(
    items: &[String],
    selectable: &[bool],
) -> Result<SelectResult, Box<dyn std::error::Error>> {
    eprintln!("Select a key (enter number):");
    for (i, item) in items.iter().enumerate() {
        if selectable[i] {
            eprintln!("  [{}] {}", i + 1, item);
        } else {
            eprintln!("      {}", item);
        }
    }
    eprint!("Choice: ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    match input.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= items.len() && selectable[n - 1] => {
            Ok(SelectResult::Selected(n - 1))
        }
        _ => Ok(SelectResult::Cancelled),
    }
}

/// Compute the inner width for the box based on content.
pub(crate) fn compute_inner_w(title: &str, header: &str, items: &[String]) -> usize {
    let icon_title = format!("\u{1F50D} {}", title);
    let title_vis = visible_len(&icon_title);
    let header_vis = visible_len(header);

    // Each item row: "  " marker + item + padding
    let items_max = items.iter()
        .map(|s| visible_len(s) + 2) // 2 for "> " marker
        .max()
        .unwrap_or(20);

    let content_max = header_vis.max(items_max).max(title_vis);
    // Cap at terminal width minus box borders and outer margins.
    let max_inner = crate::ui_frame::term_width().saturating_sub(6);
    (content_max + 10).min(max_inner) // 2 padding each side + 6 right margin
}

/// Format one row. Wide layout: `│  > item-padded  │` with the vertical
/// walls; narrow layout: drop the walls so content can spread across the
/// reclaimed ~6 columns. Cursor marker + padding stay the same so the
/// interactive redraw math is identical in both modes.
pub(crate) fn format_row(item: &str, is_cursor: bool, inner_w: usize) -> String {
    let marker = if is_cursor { "\x1b[36;1m> \x1b[0m" } else { "  " }; // cyan bold ">"
    let content = format!("{}{}", marker, item);
    let pad_target = inner_w.saturating_sub(4);
    if crate::ui_frame::is_narrow() {
        format!("  {}", content)
    } else {
        format!("  \u{2502}  {}  \u{2502}", pad_visible(&content, pad_target))
    }
}

#[cfg(unix)]
fn interactive_select(
    title: &str,
    header: &str,
    items: &[String],
    selectable: &[bool],
    initial: usize,
) -> Result<SelectResult, Box<dyn std::error::Error>> {
    use std::os::unix::io::AsRawFd;

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();

    // Save and set raw mode.
    let orig = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(tty_fd, &mut t) != 0 {
            return Err("tcgetattr failed".into());
        }
        t
    };
    let mut raw = orig;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    unsafe {
        if libc::tcsetattr(tty_fd, libc::TCSANOW, &raw) != 0 {
            return Err("tcsetattr failed".into());
        }
    }

    struct RawGuard { fd: i32, orig: libc::termios }
    impl Drop for RawGuard {
        fn drop(&mut self) {
            unsafe {
                // Why: TCSADRAIN waits for output to flush before restoring.
                // Also restore stdin (fd 0) — on macOS, /dev/tty and stdin
                // may be separate fds and only restoring /dev/tty can leave
                // stdin missing ICRNL, causing read_line to not see newlines.
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.orig);
                libc::tcsetattr(0, libc::TCSADRAIN, &self.orig);
            }
        }
    }
    let _guard = RawGuard { fd: tty_fd, orig };

    let inner_w = compute_inner_w(title, header, items);
    let border = "\u{2500}".repeat(inner_w);
    let narrow = crate::ui_frame::is_narrow();

    // Title with icon.
    let icon_title = format!("\u{1F50D} {}", title);
    let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
    let title_bar = format!("\u{2500} {} {}", icon_title, "\u{2500}".repeat(title_fill));

    let mut out = io::stderr();

    // Hide cursor.
    write!(out, "\x1b[?25l")?;

    // Header assembly differs only at the box edges — content rows go through
    // `format_row`, which already returns a narrow-aware string.
    let pad_target = inner_w.saturating_sub(4);
    if narrow {
        // Compact header: title on its own line, a thin horizontal rule, then
        // the column labels. No vertical walls, no corner glyphs.
        let rule = "\u{2500}".repeat(pad_target);
        write!(out, "\r\n  {}\r\n", icon_title)?;
        write!(out, "  {}\r\n", rule)?;
        write!(out, "  {}\r\n", header)?;
        write!(out, "  \x1b[90m{}\x1b[0m\r\n", rule)?;
    } else {
        // Top border.
        write!(out, "\r\n  \u{250C}{}\u{2510}\r\n", title_bar)?;
        // Header row — same padding as content rows: inner_w - 4 visible cols.
        write!(out, "  \u{2502}  {}  \u{2502}\r\n",
            pad_visible(header, pad_target))?;
        // Separator.
        let sep = "\u{2500}".repeat(pad_target + 2); // fills content + right margin
        write!(out, "  \u{2502} {} \u{2502}\r\n", sep)?;
    }

    // Cursor init.
    let mut cursor = initial;
    if !selectable.get(cursor).copied().unwrap_or(false) {
        cursor = next_selectable(cursor, selectable, true).unwrap_or(0);
    }

    // Item rows.
    for (i, item) in items.iter().enumerate() {
        write!(out, "{}\r\n", format_row(item, i == cursor, inner_w))?;
    }

    // Bottom border.
    if narrow {
        let rule = "\u{2500}".repeat(pad_target);
        write!(out, "  {}\r\n", rule)?;
    } else {
        write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;
    }

    // Hint line (no trailing newline — cursor stays here).
    write!(out, "  [\u{2191}\u{2193} move, \x1b[1;33mEnter\x1b[0m select, Esc cancel]")?;
    out.flush()?;

    // Layout:
    //   hint line          ← cursor at col 0 (0 up)
    //   └───────┘          ← 1 up
    //   item[last]         ← 2 up
    //   item[last-1]       ← 3 up
    //   item[i]            ← (total - i) + 1 up
    let total = items.len();

    let result = loop {
        match read_key(&tty)? {
            Key::Up => {
                if let Some(new) = next_selectable(cursor, selectable, false) {
                    let old = cursor;
                    cursor = new;
                    redraw_two(&mut out, old, cursor, items, inner_w, total)?;
                }
            }
            Key::Down => {
                if let Some(new) = next_selectable(cursor, selectable, true) {
                    let old = cursor;
                    cursor = new;
                    redraw_two(&mut out, old, cursor, items, inner_w, total)?;
                }
            }
            Key::Enter => break SelectResult::Selected(cursor),
            Key::Escape | Key::CtrlC => break SelectResult::Cancelled,
            _ => {}
        }
    };

    // Show cursor, blank line after the box.
    write!(out, "\x1b[?25h\r\n\r\n")?;
    out.flush()?;

    Ok(result)
}

// Stage 1.2 (2026-04-29) windows-compat: pub(crate) so the sibling
// ui_select_windows module can map ReadConsoleInputW KEY_EVENT records to
// the same enum the Unix render loop already uses. Visibility bump is a
// no-op for macOS / Linux machine code (no public-API surface change;
// the enum stays inside the crate).
pub(crate) enum Key { Up, Down, Enter, Space, Escape, CtrlC, Char(char), Other }

#[cfg(unix)]
fn read_key(tty: &std::fs::File) -> io::Result<Key> {
    use std::os::unix::io::AsRawFd;
    let mut buf = [0u8; 1];
    let mut reader = tty;
    reader.read_exact(&mut buf)?;
    match buf[0] {
        0x0D | 0x0A => Ok(Key::Enter),
        0x20 => Ok(Key::Space),
        0x03 => Ok(Key::CtrlC),
        0x1B => {
            // After ESC, poll 50ms to distinguish standalone Esc from arrow key sequence.
            let fd = tty.as_raw_fd();
            let mut poll_fd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll_fd, 1, 50) };
            if ready <= 0 {
                return Ok(Key::Escape);
            }
            reader.read_exact(&mut buf)?;
            if buf[0] == b'[' {
                reader.read_exact(&mut buf)?;
                match buf[0] {
                    b'A' => Ok(Key::Up),
                    b'B' => Ok(Key::Down),
                    _ => Ok(Key::Other),
                }
            } else {
                Ok(Key::Escape)
            }
        }
        c if c.is_ascii_graphic() => Ok(Key::Char(c as char)),
        _ => Ok(Key::Other),
    }
}

pub(crate) fn next_selectable(current: usize, selectable: &[bool], forward: bool) -> Option<usize> {
    let len = selectable.len();
    let mut i = current;
    loop {
        if forward {
            if i + 1 >= len { return None; }
            i += 1;
        } else {
            if i == 0 { return None; }
            i -= 1;
        }
        if selectable[i] { return Some(i); }
    }
}

/// Redraw old row (remove >) and new row (add >).
/// item[i] is (total - i) + 1 lines above the hint line.
///
/// Stage 1.2 (2026-04-29): de-cfg'd. The function body is purely ANSI
/// escape sequences via `Write` — works on both Unix and Windows once
/// the latter has `ENABLE_VIRTUAL_TERMINAL_PROCESSING` set on the
/// output handle (handled by `ui_select_windows::RawConsole`). The
/// previous `#[cfg(unix)]` attribute was a no-op for macOS / Linux
/// machine code, so removing it is byte-identical there.
pub(crate) fn redraw_two(
    out: &mut impl Write,
    old: usize,
    new: usize,
    items: &[String],
    inner_w: usize,
    total: usize,
) -> io::Result<()> {
    let up = |i: usize| -> usize { (total - i) + 1 };

    // Old row: remove cursor marker.
    let n = up(old);
    write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_row(&items[old], false, inner_w), n)?;

    // New row: add cursor marker.
    let n = up(new);
    write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_row(&items[new], true, inner_w), n)?;

    out.flush()
}

// ============================================================================
// Multi-select (checkbox style) — used by `aikey add` for provider selection
// ============================================================================

pub enum MultiSelectResult {
    Confirmed(Vec<usize>),
    Cancelled,
}

pub fn box_multi_select(
    title: &str, items: &[String], initially_checked: &[bool],
) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::io::IsTerminal;
        if io::stderr().is_terminal() {
            return interactive_multi_select(title, items, initially_checked);
        }
    }
    // Stage 1.2 (2026-04-29) windows-compat: native picker when stderr is a
    // real console; otherwise fallback_multi_select (numbered list).
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        if io::stderr().is_terminal() {
            match crate::ui_select_windows::interactive_multi_select_windows(title, items, initially_checked) {
                Ok(r) => return Ok(r),
                Err(_) => return fallback_multi_select(items),
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (title, initially_checked); // unused on the fallback path (see module note)
    fallback_multi_select(items)
}

fn fallback_multi_select(items: &[String]) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    eprintln!("Select protocol types (comma-separated numbers):");
    for (i, item) in items.iter().enumerate() { eprintln!("  [{}] {}", i + 1, item); }
    eprint!("Choice: "); io::stderr().flush()?;
    let mut input = String::new(); io::stdin().read_line(&mut input)?;
    let indices: Vec<usize> = input.split(',').filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= items.len()).map(|n| n - 1).collect();
    if indices.is_empty() { Ok(MultiSelectResult::Cancelled) } else { Ok(MultiSelectResult::Confirmed(indices)) }
}

pub(crate) fn format_multi_row(item: &str, index: usize, is_cursor: bool, is_checked: bool, inner_w: usize) -> String {
    let cursor_mark = if is_cursor { "\x1b[36;1m> \x1b[0m" } else { "  " };
    let check_mark = if is_checked { "\x1b[32m[\x1b[1m*\x1b[0m\x1b[32m]\x1b[0m" } else { "[ ]" };
    let num = format!("\x1b[90m{}\x1b[0m", index + 1); // dim number
    let label = if is_cursor { format!("\x1b[1m{}\x1b[0m", item) } else { item.to_string() };
    let content = format!("{}{} {} {}", cursor_mark, num, check_mark, label);
    let pad_target = inner_w.saturating_sub(4);
    format!("  \u{2502}  {}  \u{2502}", pad_visible(&content, pad_target))
}

#[cfg(unix)]
fn interactive_multi_select(title: &str, items: &[String], initially_checked: &[bool]) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    use std::os::unix::io::AsRawFd;
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();
    let orig = unsafe { let mut t: libc::termios = std::mem::zeroed(); if libc::tcgetattr(tty_fd, &mut t) != 0 { return Err("tcgetattr".into()); } t };
    let mut raw = orig; raw.c_lflag &= !(libc::ECHO | libc::ICANON); raw.c_cc[libc::VMIN] = 1; raw.c_cc[libc::VTIME] = 0;
    unsafe { if libc::tcsetattr(tty_fd, libc::TCSANOW, &raw) != 0 { return Err("tcsetattr".into()); } }
    struct G { fd: i32, o: libc::termios }
    impl Drop for G {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.o);
                libc::tcsetattr(0, libc::TCSADRAIN, &self.o);
            }
        }
    }
    let _g = G { fd: tty_fd, o: orig };

    let icon_title = format!("\u{2611} {}", title);
    let items_max = items.iter().map(|s| visible_len(s) + 8).max().unwrap_or(20);
    let max_inner = crate::ui_frame::term_width().saturating_sub(6);
    let inner_w = (visible_len(&icon_title) + 4).max(items_max + 10).min(max_inner);
    let border = "\u{2500}".repeat(inner_w);
    let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
    let title_bar = format!("\u{2500} {} {}", icon_title, "\u{2500}".repeat(title_fill));

    let mut out = io::stderr();
    let mut checked: Vec<bool> = initially_checked.to_vec();
    let mut cursor: usize = 0;
    let total = items.len();

    // Hint states:
    //   1. Nothing selected                     → guide first selection
    //   2. Has selection, just selected (no move) → "toggle" (may want to undo)
    //   3. Has selection, cursor on unselected   → "select" (guide adding more)
    //   4. Has selection, cursor on selected     → "toggle" (guide deselect)
    const HINT_INITIAL: &str =
        "  \x1b[1;33mEnter\x1b[0m select \u{2022} \u{2191}\u{2193} move \u{2022} 1\u{2013}9 jump \u{2022} Esc cancel";
    const HINT_TOGGLE: &str =
        "  \x1b[1;33mEnter\x1b[0m to confirm \u{2022} \u{2191}\u{2193} select more \u{2022} Space/1\u{2013}9 toggle \u{2022} Esc cancel";
    const HINT_SELECT_MORE: &str =
        "  \x1b[1;33mEnter\x1b[0m to confirm \u{2022} Space/1\u{2013}9 select \u{2022} \u{2191}\u{2193} select more \u{2022} Esc cancel";

    let mut has_moved = false;
    let pick_hint = |checked: &[bool], cursor: usize, moved: bool| -> &'static str {
        if !checked.iter().any(|&c| c) { return HINT_INITIAL; }
        if !moved { return HINT_TOGGLE; }
        if checked[cursor] { HINT_TOGGLE } else { HINT_SELECT_MORE }
    };

    write!(out, "\x1b[?25l")?;
    write!(out, "\r\n  \u{250C}{}\u{2510}\r\n", title_bar)?;
    for (i, item) in items.iter().enumerate() { write!(out, "{}\r\n", format_multi_row(item, i, i == cursor, checked[i], inner_w))?; }
    write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;
    write!(out, "{}", pick_hint(&checked, cursor, has_moved))?;
    out.flush()?;

    let result = loop {
        match read_key(&tty)? {
            Key::Up => {
                if cursor > 0 {
                    has_moved = true;
                    let old = cursor; cursor -= 1;
                    redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?; out.flush()?;
                }
            }
            Key::Down => {
                if cursor + 1 < total {
                    has_moved = true;
                    let old = cursor; cursor += 1;
                    redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?; out.flush()?;
                }
            }
            Key::Space => {
                checked[cursor] = !checked[cursor];
                redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?; out.flush()?;
            }
            Key::Enter => {
                if checked.iter().any(|&c| c) {
                    break MultiSelectResult::Confirmed(
                        checked.iter().enumerate().filter(|(_, &c)| c).map(|(i, _)| i).collect()
                    );
                } else {
                    // Nothing selected → select current item first.
                    checked[cursor] = true;
                    redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?; out.flush()?;
                }
            }
            // Number keys: toggle item directly (1-9).
            Key::Char(c) if c.is_ascii_digit() && c != '0' => {
                let idx = (c as usize) - ('1' as usize);
                if idx < total {
                    has_moved = true; // number jump counts as move
                    checked[idx] = !checked[idx];
                    if cursor != idx {
                        let old = cursor; cursor = idx;
                        redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    } else {
                        redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                    }
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?; out.flush()?;
                }
            }
            Key::Escape | Key::CtrlC => break MultiSelectResult::Cancelled,
            _ => {}
        }
    };
    write!(out, "\x1b[?25h\r\n\r\n")?; out.flush()?;
    Ok(result)
}

// Stage 1.2 (2026-04-29): de-cfg'd. Same rationale as `redraw_two` —
// pure ANSI via `Write`, no Unix syscall. Byte-identical on macOS / Linux.
pub(crate) fn redraw_multi_two(out: &mut impl Write, old: usize, new: usize, items: &[String], checked: &[bool], inner_w: usize, total: usize) -> io::Result<()> {
    let up = |i: usize| -> usize { (total - i) + 1 };
    let n = up(old); write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_multi_row(&items[old], old, false, checked[old], inner_w), n)?;
    let n = up(new); write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_multi_row(&items[new], new, true, checked[new], inner_w), n)?;
    out.flush()
}

pub(crate) fn redraw_multi_one(out: &mut impl Write, idx: usize, items: &[String], checked: &[bool], inner_w: usize, total: usize) -> io::Result<()> {
    let n = (total - idx) + 1;
    write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_multi_row(&items[idx], idx, true, checked[idx], inner_w), n)?;
    out.flush()
}

// ============================================================================
// Provider-tree select — used by `aikey use` (no args)
// ============================================================================

#[derive(Clone)]
pub struct KeyCandidate {
    pub label: String,
    pub source_type: String,       // DB value: "personal", "team", "personal_oauth_account"
    pub source_ref: String,
    pub display_type: Option<String>, // UI display override (e.g., "oauth(f)"). None → auto from source_type.
}
#[derive(Clone)]
pub struct ProviderGroup { pub provider_code: String, pub candidates: Vec<KeyCandidate>, pub selected: Option<usize>, pub expanded: bool }

pub enum ProviderTreeResult { Confirmed(Vec<ProviderGroup>), Cancelled }

pub fn provider_tree_select(groups: &mut Vec<ProviderGroup>) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    { use std::io::IsTerminal; if io::stderr().is_terminal() { return interactive_provider_tree(groups); } }
    // Stage 1.2 (2026-04-29) windows-compat: native tree picker.
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        if io::stderr().is_terminal() {
            match crate::ui_select_windows::interactive_provider_tree_windows(groups) {
                Ok(r) => return Ok(r),
                Err(_) => return fallback_provider_tree(groups),
            }
        }
    }
    fallback_provider_tree(groups)
}

fn fallback_provider_tree(groups: &mut Vec<ProviderGroup>) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    use std::io::BufRead;
    for g in groups.iter() {
        let cur = g.selected.map(|i| g.candidates[i].label.as_str()).unwrap_or("(none)");
        eprintln!("  {} \u{2192} {}", g.provider_code, cur);
        for (i, c) in g.candidates.iter().enumerate() {
            eprintln!("    {} {} [{}]", if g.selected == Some(i) { "(*)" } else { "( )" }, c.label, c.source_type);
        }
    }
    eprintln!("Enter 'protocol=number' per line, blank to confirm, 'q' to cancel:");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?; let line = line.trim();
        if line.is_empty() { break; } if line == "q" { return Ok(ProviderTreeResult::Cancelled); }
        if let Some((prov, num)) = line.split_once('=') {
            if let Ok(n) = num.trim().parse::<usize>() {
                if let Some(g) = groups.iter_mut().find(|g| g.provider_code == prov.trim()) {
                    if n >= 1 && n <= g.candidates.len() { g.selected = Some(n - 1); }
                }
            }
        }
    }
    Ok(ProviderTreeResult::Confirmed(groups.clone()))
}

#[derive(Clone)]
pub(crate) enum TreeRow { Provider(usize), Candidate(usize, usize), Blank, Separator, Confirm, Cancel }

/// V-layer family-aware: toggle 同 family 全部 group 的 expanded 一起翻转,
/// 确保 picker 视觉合并时折叠/展开状态一致。Caller 是 Space 键 on Provider header。
pub(crate) fn family_aware_toggle_expanded(groups: &mut Vec<ProviderGroup>, gi: usize) {
    let target_fam = crate::provider_registry::family_of(&groups[gi].provider_code);
    let new_state = !groups[gi].expanded;
    for og in groups.iter_mut() {
        if crate::provider_registry::family_of(&og.provider_code) == target_fam {
            og.expanded = new_state;
        }
    }
}

/// V-layer family-aware: 选中 candidate 时清空同 family 其它 group 的 selection,
/// picker 层 family-mutex 视觉一致 (DB 层互斥仍由 set_provider_binding transaction 兜底)。
/// Caller 是 Space 键 on Candidate row。
pub(crate) fn family_aware_select(groups: &mut Vec<ProviderGroup>, gi: usize, ci: usize) {
    let target_fam = crate::provider_registry::family_of(&groups[gi].provider_code);
    for (other_gi, og) in groups.iter_mut().enumerate() {
        if other_gi != gi
            && crate::provider_registry::family_of(&og.provider_code) == target_fam
        {
            og.selected = None;
        }
    }
    groups[gi].selected = Some(ci);
}

pub(crate) fn build_tree_rows(groups: &[ProviderGroup]) -> Vec<TreeRow> {
    // 2026-05-08 显示层 family-grouping (V-layer render-merge,详见 update/
    // 20260508-display-family-grouping.md):同 family 的连续 group 共享一个 header,
    // candidates 按 group 顺序展开在同一 header 下。
    //
    // 前提:caller 已按 family-then-code 排好序 (main.rs run_use_picker 里 sort
    // by (family_of, code)),所以 family 边界与 group 顺序一致。
    //
    // M 层零改动:groups 仍是 N 个 ProviderGroup (每 provider_code 一个),candidates
    // 也保留所属 group 索引;选中绑定时仍读 g.provider_code 写真值 (不是 family)。
    let mut rows = Vec::new();
    let mut prev_family: Option<&'static str> = None;
    for (gi, g) in groups.iter().enumerate() {
        let cur_family = crate::provider_registry::family_of(&g.provider_code);
        let new_family = prev_family != Some(cur_family);
        if new_family {
            if !rows.is_empty() { rows.push(TreeRow::Blank); }
            rows.push(TreeRow::Provider(gi));
        }
        if g.expanded {
            for ci in 0..g.candidates.len() { rows.push(TreeRow::Candidate(gi, ci)); }
        }
        prev_family = Some(cur_family);
    }
    rows
}

pub(crate) fn is_focusable(row: &TreeRow) -> bool { !matches!(row, TreeRow::Separator | TreeRow::Blank) }

/// Compute the maximum visible label width across all candidates in all groups.
pub(crate) fn max_candidate_label_width(groups: &[ProviderGroup]) -> usize {
    groups.iter()
        .flat_map(|g| g.candidates.iter())
        .map(|c| visible_len(&c.label))
        .max()
        .unwrap_or(20)
        .max(20) // minimum 20
}

pub(crate) fn format_tree_row(row: &TreeRow, groups: &[ProviderGroup], is_cursor: bool, inner_w: usize, label_col_w: usize, type_col_w: usize) -> String {
    let cursor_mark = if is_cursor { "\x1b[36;1m> \x1b[0m" } else { "  " };
    let pad_target = inner_w.saturating_sub(4);
    let content = match row {
        TreeRow::Provider(gi) => {
            let g = &groups[*gi];
            let arrow = if g.expanded { "\u{25BC}" } else { "\u{25B6}" };
            // 2026-05-08 V-layer family-grouping: header 文字用 family 而不是 provider_code。
            // 单 platform family family_of(code)==code, 行为不变 (e.g. anthropic / openai)。
            // 多 platform family (kimi: kimi/kimi_code/moonshot 共享) 显示 "kimi"。
            let display_name = crate::provider_registry::family_of(&g.provider_code);
            format!("{}{} \x1b[1m{}\x1b[0m", cursor_mark, arrow, display_name)
        }
        TreeRow::Candidate(gi, ci) => {
            let g = &groups[*gi]; let c = &g.candidates[*ci];
            let radio = if g.selected == Some(*ci) { "\x1b[32m(*)\x1b[0m" } else { "( )" };
            let label_raw = if is_cursor { format!("\x1b[1m{}\x1b[0m", c.label) } else { c.label.clone() };
            let label_padded = pad_visible(&label_raw, label_col_w);
            let display_type = c.display_type.as_deref().unwrap_or_else(|| {
                match c.source_type.as_str() {
                    "personal_oauth_account" => "oauth",
                    other => other,
                }
            });
            // Pad type to fixed width, then append dot for selected items.
            // This ensures the dot column is aligned regardless of type length.
            let type_padded = pad_visible(&format!("\x1b[90m{}\x1b[0m", display_type), type_col_w);
            let dot = if g.selected == Some(*ci) { " \x1b[32m\u{25cf}\x1b[0m" } else { "" };
            format!("{}    {} {} {}{}", cursor_mark, radio, label_padded, type_padded, dot)
        }
        TreeRow::Blank => { String::new() }
        TreeRow::Separator => { format!("  {}", "\u{2500}".repeat(pad_target.saturating_sub(2))) }
        TreeRow::Confirm => {
            if is_cursor {
                format!("{}\x1b[1;32mConfirm\x1b[0m \x1b[90m(press Enter to confirm)\x1b[0m", cursor_mark)
            } else {
                format!("{}\x1b[32mConfirm \x1b[33m(Y)\x1b[0m", cursor_mark)
            }
        }
        TreeRow::Cancel => {
            if is_cursor {
                format!("{}\x1b[1;33mCancel\x1b[0m \x1b[90m(press Enter to cancel)\x1b[0m", cursor_mark)
            } else {
                format!("{}\x1b[33mCancel \x1b[33m(N)\x1b[0m", cursor_mark)
            }
        }
    };
    format!("  \u{2502}  {}  \u{2502}", pad_visible(&content, pad_target))
}

#[cfg(unix)]
fn interactive_provider_tree(groups: &mut Vec<ProviderGroup>) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    use std::os::unix::io::AsRawFd;
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();
    let orig = unsafe { let mut t: libc::termios = std::mem::zeroed(); if libc::tcgetattr(tty_fd, &mut t) != 0 { return Err("tcgetattr".into()); } t };
    let mut raw = orig; raw.c_lflag &= !(libc::ECHO | libc::ICANON); raw.c_cc[libc::VMIN] = 1; raw.c_cc[libc::VTIME] = 0;
    unsafe { if libc::tcsetattr(tty_fd, libc::TCSANOW, &raw) != 0 { return Err("tcsetattr".into()); } }
    struct G { fd: i32, o: libc::termios }
    impl Drop for G {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.o);
                libc::tcsetattr(0, libc::TCSADRAIN, &self.o);
            }
        }
    }
    let _g = G { fd: tty_fd, o: orig };

    let title = "Provider Key Selection";
    let icon_title = format!("\u{1F310} {}", title);
    let mut out = io::stderr();
    let mut cursor: usize = 0;

    loop {
        let rows = build_tree_rows(groups);
        let total = rows.len();
        let max_inner = crate::ui_frame::term_width().saturating_sub(6);
        // Dynamic label column: adapt to longest candidate label + 2 padding
        let label_col_w = max_candidate_label_width(groups) + 2;
        // Candidate row visible width:
        //   cursor(2) + indent(4) + radio+space(4) + label_col_w + space(1) + type(~8) + " ●"(2)
        let max_type_w = groups.iter()
            .flat_map(|g| g.candidates.iter())
            .map(|c| c.display_type.as_deref().unwrap_or(
                if c.source_type == "personal_oauth_account" { "oauth" } else { &c.source_type }
            ).len())
            .max().unwrap_or(8);
        // Candidate content visible width = cursor(2) + indent(4) + radio(4) + label + space(1) + type + " ●"(2) = 13 + L + T
        // pad_target = inner_w - 4, so inner_w needs to be ≥ 13 + L + T + 4 = 17 + L + T
        let content_min_w = 17 + label_col_w + max_type_w;
        let inner_w = (visible_len(&icon_title) + 4).max(content_min_w).min(max_inner);
        let border = "\u{2500}".repeat(inner_w);
        let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
        let title_bar = format!("\u{2500} {} {}", icon_title, "\u{2500}".repeat(title_fill));

        if cursor >= total || !is_focusable(&rows[cursor]) {
            cursor = rows.iter().position(|r| is_focusable(r)).unwrap_or(0);
        }

        write!(out, "\x1b[?25l")?;
        write!(out, "\r\n  \u{250C}{}\u{2510}\r\n", title_bar)?;
        for (i, row) in rows.iter().enumerate() { write!(out, "{}\r\n", format_tree_row(row, groups, i == cursor, inner_w, label_col_w, max_type_w))?; }
        write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;
        write!(out, "  [\u{2191}\u{2193} move \u{2022} \x1b[1;33mSpace\x1b[0m select/expand \u{2022} \x1b[1;33mEnter\x1b[0m confirm \u{2022} \x1b[1;33mEsc\x1b[0m cancel]\r\n")?;
        out.flush()?;

        let key = read_key(&tty)?;

        // Erase: total + 4 lines (blank + top + rows + bottom + hint)
        let erase_lines = total + 4;
        for _ in 0..erase_lines { write!(out, "\x1b[A\r\x1b[2K")?; }
        out.flush()?;

        match key {
            Key::Up => { let mut n = cursor; loop { if n == 0 { break; } n -= 1; if is_focusable(&rows[n]) { cursor = n; break; } } }
            Key::Down => { let mut n = cursor; loop { if n + 1 >= total { break; } n += 1; if is_focusable(&rows[n]) { cursor = n; break; } } }
            Key::Space => {
                // 2026-05-08 V-layer family-grouping: Space 键 family-aware,详见
                // family_aware_toggle_expanded / family_aware_select 单测。
                match &rows[cursor] {
                    TreeRow::Provider(gi) => family_aware_toggle_expanded(groups, *gi),
                    TreeRow::Candidate(gi, ci) => family_aware_select(groups, *gi, *ci),
                    _ => {}
                }
            }
            Key::Enter => {
                // Enter confirms the current selection
                write!(out, "\x1b[?25h")?; out.flush()?;
                return Ok(ProviderTreeResult::Confirmed(groups.clone()));
            }
            Key::Escape | Key::CtrlC => { write!(out, "\x1b[?25h")?; out.flush()?; return Ok(ProviderTreeResult::Cancelled); }
            _ => {}
        }
    }
}

#[cfg(test)]
mod family_grouping_tests {
    use super::*;

    // 2026-05-08 显示层 family-grouping (详见 update/20260508-display-family-grouping.md)
    // 验证 V-layer render-merge 行为:
    //   - 同 family 连续 group 共享 header
    //   - 不同 family 独立 header
    //   - Space 键 family-aware (同步展开 / 同步互斥选中)

    fn group(provider_code: &str, candidate_count: usize, expanded: bool) -> ProviderGroup {
        ProviderGroup {
            provider_code: provider_code.to_string(),
            candidates: (0..candidate_count).map(|i| KeyCandidate {
                label: format!("k{}", i),
                source_type: "personal".to_string(),
                source_ref: format!("k{}", i),
                display_type: None,
            }).collect(),
            selected: None,
            expanded,
        }
    }

    fn count_provider_headers(rows: &[TreeRow]) -> usize {
        rows.iter().filter(|r| matches!(r, TreeRow::Provider(_))).count()
    }

    #[test]
    fn build_tree_rows_single_platform_families_one_header_each() {
        // anthropic / openai 各自单 platform → 各 1 header (与改前行为一致)
        let groups = vec![
            group("anthropic", 2, true),
            group("openai", 1, true),
        ];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_provider_headers(&rows), 2);
    }

    #[test]
    fn build_tree_rows_kimi_family_three_codes_emit_one_combined_header() {
        // kimi family 三个 provider_code 必须共享 1 个 header
        // (caller 已按 family-then-code 排序,所以同 family 相邻)
        let groups = vec![
            group("kimi", 1, true),       // family=kimi
            group("kimi_code", 1, true),  // family=kimi
            group("moonshot", 1, true),   // family=kimi
        ];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_provider_headers(&rows), 1,
            "Kimi family 3 个 code 必须只 emit 1 个 header");
    }

    #[test]
    fn build_tree_rows_kimi_family_candidates_all_under_one_header() {
        // 三个 group 共 6 个 candidate 都应展开在同一 header 下
        let groups = vec![
            group("kimi", 2, true),       // 2 candidates
            group("kimi_code", 1, true),  // 1 candidate
            group("moonshot", 3, true),   // 3 candidates
        ];
        let rows = build_tree_rows(&groups);
        let candidate_count = rows.iter().filter(|r| matches!(r, TreeRow::Candidate(_, _))).count();
        assert_eq!(candidate_count, 6);
    }

    #[test]
    fn build_tree_rows_mixed_families_each_family_has_own_header() {
        // anthropic + kimi family + openai → 3 个 header
        let groups = vec![
            group("anthropic", 1, true),
            group("kimi", 1, true),
            group("kimi_code", 1, true),
            group("moonshot", 1, true),
            group("openai", 1, true),
        ];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_provider_headers(&rows), 3,
            "anthropic / kimi family / openai → 各 1 header");
    }

    #[test]
    fn build_tree_rows_collapsed_group_no_candidates_emitted() {
        // collapsed group 不展开 candidates,但 header 仍显示
        let groups = vec![
            group("anthropic", 3, false),
        ];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_provider_headers(&rows), 1);
        assert_eq!(rows.iter().filter(|r| matches!(r, TreeRow::Candidate(_, _))).count(), 0);
    }

    #[test]
    fn family_aware_toggle_synchronizes_kimi_family_expansion() {
        // toggle 任一 group 必须同步同 family 全部 group
        let mut groups = vec![
            group("anthropic", 1, true),  // 控制组,不应被影响
            group("kimi", 1, true),
            group("kimi_code", 1, true),
            group("moonshot", 1, true),
        ];
        // 折叠 kimi family (toggle index 1 即 kimi group)
        family_aware_toggle_expanded(&mut groups, 1);
        assert_eq!(groups[0].expanded, true,  "anthropic 不受影响");
        assert_eq!(groups[1].expanded, false, "kimi → collapsed");
        assert_eq!(groups[2].expanded, false, "kimi_code → 同 family 跟随");
        assert_eq!(groups[3].expanded, false, "moonshot → 同 family 跟随");
        // 展开回去 (toggle index 2 即 kimi_code group, 应同样同步)
        family_aware_toggle_expanded(&mut groups, 2);
        assert_eq!(groups[1].expanded, true);
        assert_eq!(groups[2].expanded, true);
        assert_eq!(groups[3].expanded, true);
    }

    #[test]
    fn family_aware_select_kimi_family_mutex_clears_other_selections() {
        // 选中 kimi family 内一个 candidate 时,同 family 其它 group 的 selection 清空
        let mut groups = vec![
            group("anthropic", 1, true),
            group("kimi_code", 1, true),
            group("moonshot", 1, true),
        ];
        // 先选中 anthropic 和 moonshot
        groups[0].selected = Some(0);
        groups[2].selected = Some(0);
        // 现在选中 kimi_code candidate
        family_aware_select(&mut groups, 1, 0);
        assert_eq!(groups[0].selected, Some(0), "anthropic 不受影响 (跨 family)");
        assert_eq!(groups[1].selected, Some(0), "kimi_code 选中");
        assert_eq!(groups[2].selected, None,    "moonshot 同 family 互斥被清");
    }

    #[test]
    fn family_aware_select_does_not_clear_self_selection() {
        // 选中本组的 candidate (不清空自己)
        let mut groups = vec![
            group("kimi_code", 2, true),
        ];
        family_aware_select(&mut groups, 0, 1);
        assert_eq!(groups[0].selected, Some(1));
    }

    #[test]
    fn family_aware_toggle_independent_families_unaffected() {
        // 切 anthropic 不影响 kimi family
        let mut groups = vec![
            group("anthropic", 1, true),
            group("kimi", 1, true),
            group("moonshot", 1, true),
        ];
        family_aware_toggle_expanded(&mut groups, 0);
        assert_eq!(groups[0].expanded, false, "anthropic 折叠");
        assert_eq!(groups[1].expanded, true,  "kimi 不受影响");
        assert_eq!(groups[2].expanded, true,  "moonshot 不受影响");
    }
}
