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
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig); }
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
    write!(out, "  [\u{2191}\u{2193} move, Enter select, Esc cancel]")?;
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

enum Key { Up, Down, Enter, Escape, CtrlC, Other }

#[cfg(unix)]
fn read_key(tty: &std::fs::File) -> io::Result<Key> {
    let mut buf = [0u8; 1];
    let mut reader = tty;
    reader.read_exact(&mut buf)?;
    match buf[0] {
        0x0D | 0x0A => Ok(Key::Enter),
        0x03 => Ok(Key::CtrlC),
        0x1B => {
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
