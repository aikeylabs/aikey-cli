//! Interactive box-framed selector for terminal UI.
//!
//! Renders a bordered list of items with arrow-key navigation.
//! Non-selectable rows (separators, disabled keys) are skipped automatically.

use std::io::{self, Read, Write};
use crate::ui_frame::{visible_len, pad_visible};

/// Result of `box_select`: chosen index or cancelled.
pub enum SelectResult {
    /// User pressed Enter on a selectable row.
    Selected(usize),
    /// User pressed Esc or Ctrl-C.
    Cancelled,
}

/// Renders an interactive box-framed selector and returns the chosen index.
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

    #[cfg(not(unix))]
    fallback_select(items, selectable)
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
fn compute_inner_w(title: &str, header: &str, items: &[String]) -> usize {
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

/// Format one row: `│ > item padded │` or `│   item padded │`
/// Layout: `│` + space + content(padded to inner_w-4) + 2 spaces + `│`
fn format_row(item: &str, is_cursor: bool, inner_w: usize) -> String {
    let marker = if is_cursor { "\x1b[36;1m> \x1b[0m" } else { "  " }; // cyan bold ">"
    let content = format!("{}{}", marker, item);
    let pad_target = inner_w.saturating_sub(4);
    format!("  \u{2502}  {}  \u{2502}", pad_visible(&content, pad_target))
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

    // Title with icon.
    let icon_title = format!("\u{1F50D} {}", title);
    let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
    let title_bar = format!("\u{2500} {} {}", icon_title, "\u{2500}".repeat(title_fill));

    let mut out = io::stderr();

    // Hide cursor.
    write!(out, "\x1b[?25l")?;

    // Top border.
    write!(out, "\r\n  \u{250C}{}\u{2510}\r\n", title_bar)?;

    // Header row — same padding as content rows: inner_w - 4 visible cols.
    let pad_target = inner_w.saturating_sub(4);
    write!(out, "  \u{2502}  {}  \u{2502}\r\n",
        pad_visible(header, pad_target))?;

    // Separator.
    let sep = "\u{2500}".repeat(pad_target + 2); // fills content + right margin
    write!(out, "  \u{2502} {} \u{2502}\r\n", sep)?;

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
    write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;

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

enum Key { Up, Down, Enter, Space, Escape, CtrlC, Char(char), Other }

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

fn next_selectable(current: usize, selectable: &[bool], forward: bool) -> Option<usize> {
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
#[cfg(unix)]
fn redraw_two(
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
    fallback_multi_select(items)
}

fn fallback_multi_select(items: &[String]) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    eprintln!("Select provider types (comma-separated numbers):");
    for (i, item) in items.iter().enumerate() { eprintln!("  [{}] {}", i + 1, item); }
    eprint!("Choice: "); io::stderr().flush()?;
    let mut input = String::new(); io::stdin().read_line(&mut input)?;
    let indices: Vec<usize> = input.split(',').filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= items.len()).map(|n| n - 1).collect();
    if indices.is_empty() { Ok(MultiSelectResult::Cancelled) } else { Ok(MultiSelectResult::Confirmed(indices)) }
}

fn format_multi_row(item: &str, index: usize, is_cursor: bool, is_checked: bool, inner_w: usize) -> String {
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

#[cfg(unix)]
fn redraw_multi_two(out: &mut impl Write, old: usize, new: usize, items: &[String], checked: &[bool], inner_w: usize, total: usize) -> io::Result<()> {
    let up = |i: usize| -> usize { (total - i) + 1 };
    let n = up(old); write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_multi_row(&items[old], old, false, checked[old], inner_w), n)?;
    let n = up(new); write!(out, "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r", n, format_multi_row(&items[new], new, true, checked[new], inner_w), n)?;
    out.flush()
}

#[cfg(unix)]
fn redraw_multi_one(out: &mut impl Write, idx: usize, items: &[String], checked: &[bool], inner_w: usize, total: usize) -> io::Result<()> {
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
    eprintln!("Enter 'provider=number' per line, blank to confirm, 'q' to cancel:");
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
enum TreeRow { Provider(usize), Candidate(usize, usize), Blank, Separator, Confirm, Cancel }

fn build_tree_rows(groups: &[ProviderGroup]) -> Vec<TreeRow> {
    let mut rows = Vec::new();
    for (gi, g) in groups.iter().enumerate() {
        if gi > 0 { rows.push(TreeRow::Blank); } // visual spacing between groups
        rows.push(TreeRow::Provider(gi));
        if g.expanded { for ci in 0..g.candidates.len() { rows.push(TreeRow::Candidate(gi, ci)); } }
    }
    rows
}

fn is_focusable(row: &TreeRow) -> bool { !matches!(row, TreeRow::Separator | TreeRow::Blank) }

/// Compute the maximum visible label width across all candidates in all groups.
fn max_candidate_label_width(groups: &[ProviderGroup]) -> usize {
    groups.iter()
        .flat_map(|g| g.candidates.iter())
        .map(|c| visible_len(&c.label))
        .max()
        .unwrap_or(20)
        .max(20) // minimum 20
}

fn format_tree_row(row: &TreeRow, groups: &[ProviderGroup], is_cursor: bool, inner_w: usize, label_col_w: usize, type_col_w: usize) -> String {
    let cursor_mark = if is_cursor { "\x1b[36;1m> \x1b[0m" } else { "  " };
    let pad_target = inner_w.saturating_sub(4);
    let content = match row {
        TreeRow::Provider(gi) => {
            let g = &groups[*gi];
            let arrow = if g.expanded { "\u{25BC}" } else { "\u{25B6}" };
            format!("{}{} \x1b[1m{}\x1b[0m", cursor_mark, arrow, g.provider_code)
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
                match &rows[cursor] {
                    TreeRow::Provider(gi) => { groups[*gi].expanded = !groups[*gi].expanded; }
                    TreeRow::Candidate(gi, ci) => { groups[*gi].selected = Some(*ci); }
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
