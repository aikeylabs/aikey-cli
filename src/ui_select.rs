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

use crate::ui_frame::{pad_visible, visible_len};
#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};

use colored::Colorize;

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
        match crate::ui_select_windows::interactive_select_windows(
            title, header, items, selectable, initial,
        ) {
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
    // No stdin terminal → don't block on read_line (lateral sweep
    // 2026-07-07, same class as the P2-5 login hang): this fallback is
    // reached precisely when stderr is NOT a tty, so an automation-spawned
    // `aikey use` / `aikey auth login` with no explicit argument landed
    // here and hung forever on a silent-but-open stdin. Piped-selection is
    // not a supported contract (all documented automation passes explicit
    // args; interactive pickers are gated on stdin tty elsewhere, see
    // main.rs `aikey add`). Cancelled keeps the callers' existing
    // "nothing chosen" handling.
    {
        use std::io::IsTerminal;
        if !io::stdin().is_terminal() {
            eprintln!("[aikey] non-interactive session: pass the selection explicitly (e.g. an alias / provider argument) instead of the picker");
            return Ok(SelectResult::Cancelled);
        }
    }
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
    let icon_title = format!("{}{}", crate::symbols::ICON_SEARCH.pre(), title);
    let title_vis = visible_len(&icon_title);
    let header_vis = visible_len(header);

    // Each item row: "  " marker + item + padding
    let items_max = items
        .iter()
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
    let marker = if is_cursor {
        "> ".cyan().bold().to_string()
    } else {
        "  ".to_string()
    }; // cyan bold ">"
    let content = format!("{}{}", marker, item);
    let pad_target = inner_w.saturating_sub(4);
    if crate::ui_frame::is_narrow() {
        format!("  {}", content)
    } else {
        format!(
            "  {v}  {}  {v}",
            pad_visible(&content, pad_target),
            v = crate::symbols::BOX_V.s()
        )
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

    struct RawGuard {
        fd: i32,
        orig: libc::termios,
    }
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
    let border = crate::symbols::BOX_H.s().repeat(inner_w);
    let narrow = crate::ui_frame::is_narrow();

    // Title with icon.
    let icon_title = format!("{}{}", crate::symbols::ICON_SEARCH.pre(), title);
    let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
    let title_bar = format!(
        "{} {} {}",
        crate::symbols::BOX_H.s(),
        icon_title,
        crate::symbols::BOX_H.s().repeat(title_fill)
    );

    let mut out = io::stderr();

    // Hide cursor.
    write!(out, "\x1b[?25l")?;

    // Header assembly differs only at the box edges — content rows go through
    // `format_row`, which already returns a narrow-aware string.
    let pad_target = inner_w.saturating_sub(4);
    if narrow {
        // Compact header: title on its own line, a thin horizontal rule, then
        // the column labels. No vertical walls, no corner glyphs.
        let rule = crate::symbols::BOX_H.s().repeat(pad_target);
        write!(out, "\r\n  {}\r\n", icon_title)?;
        write!(out, "  {}\r\n", rule)?;
        write!(out, "  {}\r\n", header)?;
        write!(out, "  {}\r\n", rule.bright_black())?;
    } else {
        // Top border.
        write!(
            out,
            "\r\n  {}{}{}\r\n",
            crate::symbols::BOX_TL.s(),
            title_bar,
            crate::symbols::BOX_TR.s()
        )?;
        // Header row — same padding as content rows: inner_w - 4 visible cols.
        write!(
            out,
            "  {v}  {}  {v}\r\n",
            pad_visible(header, pad_target),
            v = crate::symbols::BOX_V.s()
        )?;
        // Separator.
        let sep = crate::symbols::BOX_H.s().repeat(pad_target + 2); // fills content + right margin
        write!(out, "  {v} {} {v}\r\n", sep, v = crate::symbols::BOX_V.s())?;
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
        let rule = crate::symbols::BOX_H.s().repeat(pad_target);
        write!(out, "  {}\r\n", rule)?;
    } else {
        write!(
            out,
            "  {}{}{}\r\n",
            crate::symbols::BOX_BL.s(),
            border,
            crate::symbols::BOX_BR.s()
        )?;
    }

    // Hint line (no trailing newline — cursor stays here).
    write!(
        out,
        "  [\u{2191}\u{2193} move, {} select, Esc cancel]",
        "Enter".yellow().bold()
    )?;
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
pub(crate) enum Key {
    Up,
    Down,
    Enter,
    Space,
    Escape,
    CtrlC,
    Char(char),
    Other,
}

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
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
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
            if i + 1 >= len {
                return None;
            }
            i += 1;
        } else {
            if i == 0 {
                return None;
            }
            i -= 1;
        }
        if selectable[i] {
            return Some(i);
        }
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
    write!(
        out,
        "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
        n,
        format_row(&items[old], false, inner_w),
        n
    )?;

    // New row: add cursor marker.
    let n = up(new);
    write!(
        out,
        "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
        n,
        format_row(&items[new], true, inner_w),
        n
    )?;

    out.flush()
}

// ============================================================================
// Multi-select (checkbox style) — used by `aikey add` for provider selection
// ============================================================================

pub enum MultiSelectResult {
    Confirmed(Vec<usize>),
    Cancelled,
}

/// `mutex_groups` declares index sets that must hold AT MOST ONE checked item
/// at a time. Toggling an item ON inside a mutex group automatically clears
/// the other members of that same group. Used by `aikey add` to enforce the
/// kimi-family one-upstream constraint at toggle time (matches Web
/// ProviderMultiSelect's add-time mutex).
///
/// Pass `&[]` to opt out — preserves the original generic multi-select.
pub fn box_multi_select(
    title: &str,
    items: &[String],
    initially_checked: &[bool],
    mutex_groups: &[Vec<usize>],
) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::io::IsTerminal;
        if io::stderr().is_terminal() {
            return interactive_multi_select(title, items, initially_checked, mutex_groups);
        }
    }
    // Stage 1.2 (2026-04-29) windows-compat: native picker when stderr is a
    // real console; otherwise fallback_multi_select (numbered list).
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        if io::stderr().is_terminal() {
            match crate::ui_select_windows::interactive_multi_select_windows(
                title,
                items,
                initially_checked,
                mutex_groups,
            ) {
                Ok(r) => return Ok(r),
                Err(_) => return fallback_multi_select(items),
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (title, initially_checked, mutex_groups); // unused on the fallback path (see module note)
    fallback_multi_select(items)
}

/// Apply mutex constraints after toggling `idx` ON: for any group that
/// contains `idx`, clear all other members. No-op when `idx` was just toggled
/// OFF or when no mutex group contains it.
pub(crate) fn apply_mutex_on_toggle(checked: &mut [bool], idx: usize, mutex_groups: &[Vec<usize>]) {
    if !checked[idx] {
        return;
    } // toggled OFF — nothing to enforce
    for group in mutex_groups {
        if group.contains(&idx) {
            for &other in group {
                if other != idx && other < checked.len() {
                    checked[other] = false;
                }
            }
        }
    }
}

fn fallback_multi_select(
    items: &[String],
) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    // Same no-stdin-terminal guard as fallback_select above (2026-07-07
    // lateral sweep) — never block a non-interactive session on read_line.
    {
        use std::io::IsTerminal;
        if !io::stdin().is_terminal() {
            eprintln!(
                "[aikey] non-interactive session: pass protocols explicitly instead of the picker"
            );
            return Ok(MultiSelectResult::Cancelled);
        }
    }
    eprintln!("Select protocol types (comma-separated numbers):");
    for (i, item) in items.iter().enumerate() {
        eprintln!("  [{}] {}", i + 1, item);
    }
    eprint!("Choice: ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let indices: Vec<usize> = input
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= items.len())
        .map(|n| n - 1)
        .collect();
    if indices.is_empty() {
        Ok(MultiSelectResult::Cancelled)
    } else {
        Ok(MultiSelectResult::Confirmed(indices))
    }
}

pub(crate) fn format_multi_row(
    item: &str,
    index: usize,
    is_cursor: bool,
    is_checked: bool,
    inner_w: usize,
) -> String {
    let cursor_mark = if is_cursor {
        "> ".cyan().bold().to_string()
    } else {
        "  ".to_string()
    };
    let check_mark = if is_checked {
        format!("{}{}{}", "[".green(), "*".bold(), "]".green())
    } else {
        "[ ]".to_string()
    };
    let num = (index + 1).to_string().bright_black().to_string(); // dim number
    let label = if is_cursor {
        format!("{}", item.bold())
    } else {
        item.to_string()
    };
    let content = format!("{}{} {} {}", cursor_mark, num, check_mark, label);
    let pad_target = inner_w.saturating_sub(4);
    format!(
        "  {v}  {}  {v}",
        pad_visible(&content, pad_target),
        v = crate::symbols::BOX_V.s()
    )
}

#[cfg(unix)]
fn interactive_multi_select(
    title: &str,
    items: &[String],
    initially_checked: &[bool],
    mutex_groups: &[Vec<usize>],
) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    use std::os::unix::io::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();
    let orig = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(tty_fd, &mut t) != 0 {
            return Err("tcgetattr".into());
        }
        t
    };
    let mut raw = orig;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    unsafe {
        if libc::tcsetattr(tty_fd, libc::TCSANOW, &raw) != 0 {
            return Err("tcsetattr".into());
        }
    }
    struct G {
        fd: i32,
        o: libc::termios,
    }
    impl Drop for G {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.o);
                libc::tcsetattr(0, libc::TCSADRAIN, &self.o);
            }
        }
    }
    let _g = G {
        fd: tty_fd,
        o: orig,
    };

    let icon_title = format!("{}{}", crate::symbols::CHECKBOX_ON.pre(), title);
    let items_max = items.iter().map(|s| visible_len(s) + 8).max().unwrap_or(20);
    let max_inner = crate::ui_frame::term_width().saturating_sub(6);
    let inner_w = (visible_len(&icon_title) + 4)
        .max(items_max + 10)
        .min(max_inner);
    let border = crate::symbols::BOX_H.s().repeat(inner_w);
    let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
    let title_bar = format!(
        "{} {} {}",
        crate::symbols::BOX_H.s(),
        icon_title,
        crate::symbols::BOX_H.s().repeat(title_fill)
    );

    let mut out = io::stderr();
    let mut checked: Vec<bool> = initially_checked.to_vec();
    let mut cursor: usize = 0;
    let total = items.len();

    // Hint states:
    //   1. Nothing selected                     → guide first selection
    //   2. Has selection, just selected (no move) → "toggle" (may want to undo)
    //   3. Has selection, cursor on unselected   → "select" (guide adding more)
    //   4. Has selection, cursor on selected     → "toggle" (guide deselect)
    fn enter_key() -> String {
        "Enter".yellow().bold().to_string()
    }
    let hint_initial = format!(
        "  {} select \u{2022} \u{2191}\u{2193} move \u{2022} 1\u{2013}9 jump \u{2022} Esc cancel",
        enter_key()
    );
    let hint_toggle = format!(
        "  {} to confirm \u{2022} \u{2191}\u{2193} select more \u{2022} Space/1\u{2013}9 toggle \u{2022} Esc cancel",
        enter_key()
    );
    let hint_select_more = format!(
        "  {} to confirm \u{2022} Space/1\u{2013}9 select \u{2022} \u{2191}\u{2193} select more \u{2022} Esc cancel",
        enter_key()
    );

    let mut has_moved = false;
    let pick_hint = |checked: &[bool], cursor: usize, moved: bool| -> &str {
        if !checked.iter().any(|&c| c) {
            return &hint_initial;
        }
        if !moved {
            return &hint_toggle;
        }
        if checked[cursor] {
            &hint_toggle
        } else {
            &hint_select_more
        }
    };

    write!(out, "\x1b[?25l")?;
    write!(
        out,
        "\r\n  {}{}{}\r\n",
        crate::symbols::BOX_TL.s(),
        title_bar,
        crate::symbols::BOX_TR.s()
    )?;
    for (i, item) in items.iter().enumerate() {
        write!(
            out,
            "{}\r\n",
            format_multi_row(item, i, i == cursor, checked[i], inner_w)
        )?;
    }
    write!(
        out,
        "  {}{}{}\r\n",
        crate::symbols::BOX_BL.s(),
        border,
        crate::symbols::BOX_BR.s()
    )?;
    write!(out, "{}", pick_hint(&checked, cursor, has_moved))?;
    out.flush()?;

    let result = loop {
        match read_key(&tty)? {
            Key::Up => {
                if cursor > 0 {
                    has_moved = true;
                    let old = cursor;
                    cursor -= 1;
                    redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            Key::Down => {
                if cursor + 1 < total {
                    has_moved = true;
                    let old = cursor;
                    cursor += 1;
                    redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            Key::Space => {
                let prev = checked.clone();
                checked[cursor] = !checked[cursor];
                apply_mutex_on_toggle(&mut checked, cursor, mutex_groups);
                redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                // Redraw any sibling rows the mutex auto-cleared (non-cursor).
                for i in 0..total {
                    if i != cursor && checked[i] != prev[i] {
                        let n = (total - i) + 1;
                        write!(
                            out,
                            "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
                            n,
                            format_multi_row(&items[i], i, false, checked[i], inner_w),
                            n
                        )?;
                    }
                }
                write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                out.flush()?;
            }
            Key::Enter => {
                if checked.iter().any(|&c| c) {
                    break MultiSelectResult::Confirmed(
                        checked
                            .iter()
                            .enumerate()
                            .filter(|(_, &c)| c)
                            .map(|(i, _)| i)
                            .collect(),
                    );
                } else {
                    // Nothing selected → select current item first.
                    checked[cursor] = true;
                    // Empty -> 1 item, no mutex sibling can have been ON, but call for symmetry.
                    apply_mutex_on_toggle(&mut checked, cursor, mutex_groups);
                    redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            // Number keys: toggle item directly (1-9).
            Key::Char(c) if c.is_ascii_digit() && c != '0' => {
                let idx = (c as usize) - ('1' as usize);
                if idx < total {
                    has_moved = true; // number jump counts as move
                    let prev = checked.clone();
                    checked[idx] = !checked[idx];
                    apply_mutex_on_toggle(&mut checked, idx, mutex_groups);
                    if cursor != idx {
                        let old = cursor;
                        cursor = idx;
                        redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    } else {
                        redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                    }
                    // Redraw mutex-cleared siblings (other than cursor & prior cursor).
                    for i in 0..total {
                        if i != cursor && i != idx && checked[i] != prev[i] {
                            let n = (total - i) + 1;
                            write!(
                                out,
                                "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
                                n,
                                format_multi_row(&items[i], i, false, checked[i], inner_w),
                                n
                            )?;
                        }
                    }
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            Key::Escape | Key::CtrlC => break MultiSelectResult::Cancelled,
            _ => {}
        }
    };
    write!(out, "\x1b[?25h\r\n\r\n")?;
    out.flush()?;
    Ok(result)
}

// Stage 1.2 (2026-04-29): de-cfg'd. Same rationale as `redraw_two` —
// pure ANSI via `Write`, no Unix syscall. Byte-identical on macOS / Linux.
pub(crate) fn redraw_multi_two(
    out: &mut impl Write,
    old: usize,
    new: usize,
    items: &[String],
    checked: &[bool],
    inner_w: usize,
    total: usize,
) -> io::Result<()> {
    let up = |i: usize| -> usize { (total - i) + 1 };
    let n = up(old);
    write!(
        out,
        "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
        n,
        format_multi_row(&items[old], old, false, checked[old], inner_w),
        n
    )?;
    let n = up(new);
    write!(
        out,
        "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
        n,
        format_multi_row(&items[new], new, true, checked[new], inner_w),
        n
    )?;
    out.flush()
}

pub(crate) fn redraw_multi_one(
    out: &mut impl Write,
    idx: usize,
    items: &[String],
    checked: &[bool],
    inner_w: usize,
    total: usize,
) -> io::Result<()> {
    let n = (total - idx) + 1;
    write!(
        out,
        "\x1b[{}A\r\x1b[2K{}\x1b[{}B\r",
        n,
        format_multi_row(&items[idx], idx, true, checked[idx], inner_w),
        n
    )?;
    out.flush()
}

// ============================================================================
// Provider-tree select — used by `aikey use` (no args)
// ============================================================================

#[derive(Clone)]
pub struct KeyCandidate {
    pub label: String,
    pub source_type: String, // DB value: "personal", "team", "personal_oauth_account"
    pub source_ref: String,
    /// Actual upstream supplier selected by this row.
    pub provider_code: String,
    /// Exact wire protocol carried by the credential binding.
    pub protocol_type: String,
    pub display_type: Option<String>, // UI display override (e.g., "oauth(f)"). None → auto from source_type.
    /// Key material not reachable (team VK pending download / not claimed).
    /// Rendered dimmed and NOT selectable — but still VISIBLE, and still shows
    /// the radio/dot when it is the current binding. WHY show instead of hide
    /// (2026-07-06, update/20260706-绑定材料守卫与Web解锁态全量sync.md): hiding
    /// made the picker show "nothing selected" while the web vault showed the
    /// same key as IN USE — two surfaces disagreeing about the active key.
    pub pending: bool,
}
#[derive(Clone)]
pub struct ClientRouteGroup {
    pub client_route: String,
    pub candidates: Vec<KeyCandidate>,
    pub selected: Option<usize>,
    pub expanded: bool,
}

pub enum ProviderTreeResult {
    Confirmed(Vec<ClientRouteGroup>),
    Cancelled,
}

pub fn provider_tree_select(
    groups: &mut Vec<ClientRouteGroup>,
) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::io::IsTerminal;
        if io::stderr().is_terminal() {
            return interactive_provider_tree(groups);
        }
    }
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

fn fallback_provider_tree(
    groups: &mut Vec<ClientRouteGroup>,
) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    use std::io::BufRead;
    for g in groups.iter() {
        let cur = g
            .selected
            .map(|i| g.candidates[i].label.as_str())
            .unwrap_or("(none)");
        eprintln!("  {} \u{2192} {}", g.client_route, cur);
        for (i, c) in g.candidates.iter().enumerate() {
            eprintln!(
                "    {} {} [{}]{}",
                if g.selected == Some(i) { "(*)" } else { "( )" },
                c.label,
                c.source_type,
                if c.pending { " (pending download)" } else { "" }
            );
        }
    }
    eprintln!("Enter 'protocol=number' per line, blank to confirm, 'q' to cancel:");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if line == "q" {
            return Ok(ProviderTreeResult::Cancelled);
        }
        if let Some((prov, num)) = line.split_once('=') {
            if let Ok(n) = num.trim().parse::<usize>() {
                if let Some(g) = groups.iter_mut().find(|g| g.client_route == prov.trim()) {
                    if n >= 1 && n <= g.candidates.len() {
                        if g.candidates[n - 1].pending {
                            eprintln!(
                                "  '{}' is pending download (run `aikey key sync` first).",
                                g.candidates[n - 1].label
                            );
                        } else {
                            g.selected = Some(n - 1);
                        }
                    }
                }
            }
        }
    }
    Ok(ProviderTreeResult::Confirmed(groups.clone()))
}

#[derive(Clone)]
pub(crate) enum TreeRow {
    ClientRoute(usize),
    Candidate(usize, usize),
    Blank,
    Separator,
    Confirm,
    Cancel,
}

/// V-layer family-aware: toggle 同 family 全部 group 的 expanded 一起翻转,
/// 确保 picker 视觉合并时折叠/展开状态一致。Caller 是 Space 键 on Provider header。
pub(crate) fn route_toggle_expanded(groups: &mut Vec<ClientRouteGroup>, gi: usize) {
    groups[gi].expanded = !groups[gi].expanded;
}

/// V-layer family-aware: 选中 candidate 时清空同 family 其它 group 的 selection,
/// picker 层 family-mutex 视觉一致 (DB 层互斥仍由 set_provider_binding transaction 兜底)。
/// Caller 是 Space 键 on Candidate row。
pub(crate) fn route_select(groups: &mut Vec<ClientRouteGroup>, gi: usize, ci: usize) {
    // Pending (material-unreachable) candidates are visible but not selectable —
    // selecting one would recreate the "IN USE but proxy 503s" state the
    // 2026-07-06 binding material guard exists to prevent. Space is a no-op;
    // the row's dim style + "pending" tag tells the user why.
    if groups[gi]
        .candidates
        .get(ci)
        .map(|c| c.pending)
        .unwrap_or(false)
    {
        return;
    }
    groups[gi].selected = Some(ci);
}

pub(crate) fn build_tree_rows(groups: &[ClientRouteGroup]) -> Vec<TreeRow> {
    // One header per client route. Provider is row metadata, never a grouping
    // key, so Mock+anthropic appears under Claude and Mock+openai under Codex.
    let mut rows = Vec::new();
    for (gi, g) in groups.iter().enumerate() {
        if !rows.is_empty() {
            rows.push(TreeRow::Blank);
        }
        rows.push(TreeRow::ClientRoute(gi));
        if g.expanded {
            for ci in 0..g.candidates.len() {
                rows.push(TreeRow::Candidate(gi, ci));
            }
        }
    }
    rows
}

pub(crate) fn is_focusable(row: &TreeRow) -> bool {
    !matches!(row, TreeRow::Separator | TreeRow::Blank)
}

/// Compute the maximum visible label width across all candidates in all groups.
pub(crate) fn max_candidate_label_width(groups: &[ClientRouteGroup]) -> usize {
    groups
        .iter()
        .flat_map(|g| g.candidates.iter())
        .map(|c| visible_len(&c.label))
        .max()
        .unwrap_or(20)
        .max(20) // minimum 20
}

pub(crate) fn format_tree_row(
    row: &TreeRow,
    groups: &[ClientRouteGroup],
    is_cursor: bool,
    inner_w: usize,
    label_col_w: usize,
    type_col_w: usize,
) -> String {
    let cursor_mark = if is_cursor {
        "> ".cyan().bold().to_string()
    } else {
        "  ".to_string()
    };
    let pad_target = inner_w.saturating_sub(4);
    let content = match row {
        TreeRow::ClientRoute(gi) => {
            let g = &groups[*gi];
            let arrow = if g.expanded {
                crate::symbols::TREE_EXPANDED.s()
            } else {
                crate::symbols::TREE_COLLAPSED.s()
            };
            // 2026-05-08 V-layer family-grouping: header 文字用 family 而不是 provider_code。
            // 单 platform family family_of(code)==code, 行为不变 (e.g. anthropic / openai)。
            // 多 platform family (kimi: kimi/kimi_code/moonshot 共享) 显示 "kimi"。
            //
            // 2026-05-12: render brand alias next to the family label in dim
            // styling — e.g. `anthropic (claude)` — for single-platform
            // families where the canonical code isn't the brand users
            // recognize. Multi-platform families (kimi) get no alias at
            // family level (see provider_registry::family_display).
            let (display_name, alias) = crate::provider_registry::family_display(&g.client_route);
            match alias {
                Some(a) => format!(
                    "{}{} {} {}",
                    cursor_mark,
                    arrow,
                    display_name.bold(),
                    format!("({})", a).dimmed(),
                ),
                None => format!("{}{} {}", cursor_mark, arrow, display_name.bold()),
            }
        }
        TreeRow::Candidate(gi, ci) => {
            let g = &groups[*gi];
            let c = &g.candidates[*ci];
            // Pending selected state renders YELLOW, not green: "this IS your
            // current binding but it cannot serve requests yet" (material not
            // downloaded). Green would claim health it doesn't have.
            let radio = if g.selected == Some(*ci) {
                if c.pending {
                    "(*)".yellow().to_string()
                } else {
                    "(*)".green().to_string()
                }
            } else {
                "( )".to_string()
            };
            let label_raw = if is_cursor {
                format!("{}", c.label.bold())
            } else if c.pending {
                format!("{}", c.label.dimmed())
            } else {
                c.label.clone()
            };
            let label_padded = pad_visible(&label_raw, label_col_w);
            let display_type =
                c.display_type
                    .as_deref()
                    .unwrap_or_else(|| match c.source_type.as_str() {
                        "personal_oauth_account" => "oauth",
                        other => other,
                    });
            // Pad type to fixed width, then append dot for selected items.
            // This ensures the dot column is aligned regardless of type length.
            let type_padded = pad_visible(&display_type.bright_black().to_string(), type_col_w);
            let dot = if g.selected == Some(*ci) {
                if c.pending {
                    format!(" {}", format!("{}", crate::symbols::RADIO_ON.s()).yellow())
                } else {
                    format!(" {}", format!("{}", crate::symbols::RADIO_ON.s()).green())
                }
            } else {
                String::new()
            };
            format!(
                "{}    {} {} {}{}",
                cursor_mark, radio, label_padded, type_padded, dot
            )
        }
        TreeRow::Blank => String::new(),
        TreeRow::Separator => {
            format!(
                "  {}",
                crate::symbols::BOX_H
                    .s()
                    .repeat(pad_target.saturating_sub(2))
            )
        }
        TreeRow::Confirm => {
            if is_cursor {
                format!(
                    "{}{} {}",
                    cursor_mark,
                    "Confirm".green().bold(),
                    "(press Enter to confirm)".bright_black()
                )
            } else {
                format!("{}{} {}", cursor_mark, "Confirm".green(), "(Y)".yellow())
            }
        }
        TreeRow::Cancel => {
            if is_cursor {
                format!(
                    "{}{} {}",
                    cursor_mark,
                    "Cancel".yellow().bold(),
                    "(press Enter to cancel)".bright_black()
                )
            } else {
                format!("{}{} {}", cursor_mark, "Cancel".yellow(), "(N)".yellow())
            }
        }
    };
    format!(
        "  {v}  {}  {v}",
        pad_visible(&content, pad_target),
        v = crate::symbols::BOX_V.s()
    )
}

#[cfg(unix)]
fn interactive_provider_tree(
    groups: &mut Vec<ClientRouteGroup>,
) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    use std::os::unix::io::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();
    let orig = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(tty_fd, &mut t) != 0 {
            return Err("tcgetattr".into());
        }
        t
    };
    let mut raw = orig;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    unsafe {
        if libc::tcsetattr(tty_fd, libc::TCSANOW, &raw) != 0 {
            return Err("tcsetattr".into());
        }
    }
    struct G {
        fd: i32,
        o: libc::termios,
    }
    impl Drop for G {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.o);
                libc::tcsetattr(0, libc::TCSADRAIN, &self.o);
            }
        }
    }
    let _g = G {
        fd: tty_fd,
        o: orig,
    };

    let title = "CLI Route Selection";
    let icon_title = format!("{}{}", crate::symbols::ICON_GLOBE.pre(), title);
    let mut out = io::stderr();
    let mut cursor: usize = 0;

    // 2026-05-12 guidance: tell the user up-front what Enter does and which
    // tools the choice affects. Printed once outside the loop so it stays
    // above the box and doesn't re-render with the tree. Style: subdued so
    // the box itself remains the focal element.
    write!(
        out,
        "\r\n  {}\r\n",
        "Pick the default key for each CLI route.".dimmed()
    )?;
    write!(
        out,
        "  {}\r\n",
        "Your CLI tools (claude / codex / kimi …) will route through these keys until you switch again.".dimmed()
    )?;

    loop {
        let rows = build_tree_rows(groups);
        let total = rows.len();
        let max_inner = crate::ui_frame::term_width().saturating_sub(6);
        // Dynamic label column: adapt to longest candidate label + 2 padding
        let label_col_w = max_candidate_label_width(groups) + 2;
        // Candidate row visible width:
        //   cursor(2) + indent(4) + radio+space(4) + label_col_w + space(1) + type(~8) + " ●"(2)
        let max_type_w = groups
            .iter()
            .flat_map(|g| g.candidates.iter())
            .map(|c| {
                c.display_type
                    .as_deref()
                    .unwrap_or(if c.source_type == "personal_oauth_account" {
                        "oauth"
                    } else {
                        &c.source_type
                    })
                    .len()
            })
            .max()
            .unwrap_or(8);
        // Candidate content visible width = cursor(2) + indent(4) + radio(4) + label + space(1) + type + " ●"(2) = 13 + L + T
        // pad_target = inner_w - 4, so inner_w needs to be ≥ 13 + L + T + 4 = 17 + L + T
        let content_min_w = 17 + label_col_w + max_type_w;
        let inner_w = (visible_len(&icon_title) + 4)
            .max(content_min_w)
            .min(max_inner);
        let border = crate::symbols::BOX_H.s().repeat(inner_w);
        let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
        let title_bar = format!(
            "{} {} {}",
            crate::symbols::BOX_H.s(),
            icon_title,
            crate::symbols::BOX_H.s().repeat(title_fill)
        );

        if cursor >= total || !is_focusable(&rows[cursor]) {
            cursor = rows.iter().position(|r| is_focusable(r)).unwrap_or(0);
        }

        write!(out, "\x1b[?25l")?;
        write!(
            out,
            "\r\n  {}{}{}\r\n",
            crate::symbols::BOX_TL.s(),
            title_bar,
            crate::symbols::BOX_TR.s()
        )?;
        for (i, row) in rows.iter().enumerate() {
            write!(
                out,
                "{}\r\n",
                format_tree_row(row, groups, i == cursor, inner_w, label_col_w, max_type_w)
            )?;
        }
        write!(
            out,
            "  {}{}{}\r\n",
            crate::symbols::BOX_BL.s(),
            border,
            crate::symbols::BOX_BR.s()
        )?;
        write!(
            out,
            "  [\u{2191}\u{2193} move \u{2022} {} select/expand \u{2022} {} confirm \u{2022} {} cancel]\r\n",
            "Space".yellow().bold(),
            "Enter".yellow().bold(),
            "Esc".yellow().bold()
        )?;
        out.flush()?;

        let key = read_key(&tty)?;

        // Erase: total + 4 lines (blank + top + rows + bottom + hint)
        let erase_lines = total + 4;
        for _ in 0..erase_lines {
            write!(out, "\x1b[A\r\x1b[2K")?;
        }
        out.flush()?;

        match key {
            Key::Up => {
                let mut n = cursor;
                loop {
                    if n == 0 {
                        break;
                    }
                    n -= 1;
                    if is_focusable(&rows[n]) {
                        cursor = n;
                        break;
                    }
                }
            }
            Key::Down => {
                let mut n = cursor;
                loop {
                    if n + 1 >= total {
                        break;
                    }
                    n += 1;
                    if is_focusable(&rows[n]) {
                        cursor = n;
                        break;
                    }
                }
            }
            Key::Space => {
                // A client route is the selection mutex boundary.
                match &rows[cursor] {
                    TreeRow::ClientRoute(gi) => route_toggle_expanded(groups, *gi),
                    TreeRow::Candidate(gi, ci) => route_select(groups, *gi, *ci),
                    _ => {}
                }
            }
            Key::Enter => {
                // Enter confirms the current selection
                write!(out, "\x1b[?25h")?;
                out.flush()?;
                return Ok(ProviderTreeResult::Confirmed(groups.clone()));
            }
            Key::Escape | Key::CtrlC => {
                write!(out, "\x1b[?25h")?;
                out.flush()?;
                return Ok(ProviderTreeResult::Cancelled);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod client_route_grouping_tests {
    use super::*;

    fn group(client_route: &str, candidate_count: usize, expanded: bool) -> ClientRouteGroup {
        ClientRouteGroup {
            client_route: client_route.to_string(),
            candidates: (0..candidate_count)
                .map(|i| KeyCandidate {
                    label: format!("k{}", i),
                    source_type: "personal".to_string(),
                    source_ref: format!("k{}", i),
                    provider_code: client_route.to_string(),
                    protocol_type: "openai_compatible".to_string(),
                    display_type: None,
                    pending: false,
                })
                .collect(),
            selected: None,
            expanded,
        }
    }

    fn count_route_headers(rows: &[TreeRow]) -> usize {
        rows.iter()
            .filter(|r| matches!(r, TreeRow::ClientRoute(_)))
            .count()
    }

    #[test]
    fn build_tree_rows_single_platform_families_one_header_each() {
        // anthropic / openai 各自单 platform → 各 1 header (与改前行为一致)
        let groups = vec![group("anthropic", 2, true), group("openai", 1, true)];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_route_headers(&rows), 2);
    }

    #[test]
    fn build_tree_rows_one_header_per_client_route() {
        let groups = vec![group("anthropic", 1, true), group("openai", 1, true)];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_route_headers(&rows), 2);
    }

    #[test]
    fn build_tree_rows_candidates_stay_under_their_route() {
        let groups = vec![group("kimi", 6, true)];
        let rows = build_tree_rows(&groups);
        let candidate_count = rows
            .iter()
            .filter(|r| matches!(r, TreeRow::Candidate(_, _)))
            .count();
        assert_eq!(candidate_count, 6);
    }

    #[test]
    fn build_tree_rows_collapsed_group_no_candidates_emitted() {
        // collapsed group 不展开 candidates,但 header 仍显示
        let groups = vec![group("anthropic", 3, false)];
        let rows = build_tree_rows(&groups);
        assert_eq!(count_route_headers(&rows), 1);
        assert_eq!(
            rows.iter()
                .filter(|r| matches!(r, TreeRow::Candidate(_, _)))
                .count(),
            0
        );
    }

    #[test]
    fn route_toggle_only_changes_the_target_route() {
        let mut groups = vec![group("anthropic", 1, true), group("openai", 1, true)];
        route_toggle_expanded(&mut groups, 0);
        assert!(!groups[0].expanded);
        assert!(groups[1].expanded);
    }

    #[test]
    fn route_select_changes_only_that_route() {
        let mut groups = vec![group("anthropic", 2, true), group("openai", 1, true)];
        groups[1].selected = Some(0);
        route_select(&mut groups, 0, 1);
        assert_eq!(groups[0].selected, Some(1));
        assert_eq!(groups[1].selected, Some(0));
    }
}
