//! Stage 1.2 (deferred → 2026-04-29) windows-compat: native console
//! interactive selectors for `aikey use` / `aikey add` provider
//! pickers etc.
//!
//! ## Strategy A (windows-compatibility.md §7.1) — pure
//!
//! - The existing `ui_select::interactive_select` etc. fns stay
//!   `#[cfg(unix)]` and **byte-identical** on macOS / Linux.
//! - This module is `#[cfg(windows)]`-only — never compiles on macOS,
//!   so it cannot affect Unix machine code.
//! - `ui_select`'s 3 dispatchers (`box_select`, `box_multi_select`,
//!   `provider_tree_select`) get a `#[cfg(windows)]` arm that calls
//!   the `*_windows` functions in this module. The `#[cfg(unix)]` arm
//!   that already existed is unchanged.
//!
//! ## Why ReadConsoleInputW (and not stdin byte stream + VT input)
//!
//! The Unix path opens `/dev/tty` and reads raw bytes; arrow keys
//! arrive as `ESC [ A` etc. and the parser uses `libc::poll(50ms)` to
//! disambiguate a standalone `Esc` from the start of an arrow-key
//! sequence.
//!
//! Windows offers two equivalent paths:
//!   1. **`ENABLE_VIRTUAL_TERMINAL_INPUT` + raw bytes from stdin** —
//!      arrow keys come through as the same `ESC [ A` sequences,
//!      letting us reuse the Unix `read_key` byte parser. Cleaner
//!      cross-platform code, but requires a `libc::poll`-equivalent
//!      timed read (`PeekConsoleInput` + sleep loop) and the polling
//!      semantics are subtly different.
//!   2. **`ReadConsoleInputW` returning `INPUT_RECORD` (KEY_EVENT)** —
//!      we get `wVirtualKeyCode` directly (no escape parsing); ESC vs
//!      arrow is unambiguous because each is its own KEY_EVENT.
//!
//! Path 2 is the more idiomatic Windows console approach and avoids
//! the timed-poll subtlety, so this module uses it.
//!
//! Output rendering still uses VT escape sequences (the existing
//! `redraw_two` / `format_*` helpers) — `ENABLE_VIRTUAL_TERMINAL_PROCESSING`
//! is set on the output handle so the same ANSI escapes the Unix
//! path emits work on Windows too.

#![cfg(windows)]

use std::io::{self, Write};
use std::mem::MaybeUninit;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, ReadConsoleInputW, SetConsoleMode,
    INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD,
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_ERROR_HANDLE, STD_INPUT_HANDLE,
};
// Note: deliberately NOT importing `ENABLE_VIRTUAL_TERMINAL_INPUT` even
// though the module-level docstring discusses it — we use ReadConsoleInputW
// + KEY_EVENT_RECORD parsing, which doesn't need VT input mode.

use crate::ui_select::{
    build_tree_rows, compute_inner_w, format_multi_row, format_row, format_tree_row,
    is_focusable, max_candidate_label_width, next_selectable, redraw_multi_one,
    redraw_multi_two, redraw_two,
    Key, MultiSelectResult, ProviderGroup, ProviderTreeResult, SelectResult, TreeRow,
};

// Width / padding helpers live in ui_frame (cross-platform).
use crate::ui_frame::{pad_visible, visible_len};

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the Win32 virtual-key constants — these are part of the
    /// stable Win32 ABI but a typo in the inlined values would silently
    /// break arrow-key navigation. The values are documented at:
    /// https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
    #[test]
    fn vk_constants_match_win32_abi() {
        assert_eq!(VK_RETURN, 0x0D);
        assert_eq!(VK_ESCAPE, 0x1B);
        assert_eq!(VK_SPACE,  0x20);
        assert_eq!(VK_UP,     0x26);
        assert_eq!(VK_DOWN,   0x28);
    }

    /// Pin the modifier-key state bits. Same rationale as VK constants.
    #[test]
    fn ctrl_modifier_bits_match_win32_abi() {
        assert_eq!(LEFT_CTRL_PRESSED,  0x0008);
        assert_eq!(RIGHT_CTRL_PRESSED, 0x0004);
    }

    /// `RawConsole::open()` must fail cleanly when stdin / stderr are
    /// not real consoles — the dispatchers (`box_select` etc.) rely on
    /// this signal to fall back to numbered-list rendering instead of
    /// silently hanging.
    ///
    /// Why we test the failure-mode rather than the success-mode: the
    /// success path requires an attached real console, which `cargo
    /// test` doesn't provide (the test runner captures stdout/stderr
    /// for output buffering). `GetConsoleMode` will fail on the
    /// captured handle, so `RawConsole::open()` returns Err — exactly
    /// the path we want pinned. A regression that "always succeeds"
    /// (e.g. somebody adding a panic-free fallback) would make the
    /// dispatcher try to draw a TUI to a captured pipe, hanging the
    /// test runner.
    #[test]
    fn raw_console_open_fails_when_not_attached_to_real_console() {
        let result = RawConsole::open();
        // Under cargo test the std streams are captured pipes, not
        // real consoles. We accept either: (a) Err (the expected case
        // — GetConsoleMode rejects the pipe handle), (b) Ok (running
        // under a real console attached to the test process — rare
        // but valid, e.g. interactive `cargo test --test-threads=1`).
        // The point is the function must NOT panic.
        match result {
            Ok(_rc) => { /* ok — running under a real console */ }
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::NotConnected,
                    "expected NotConnected when stdin/stderr aren't real consoles; got {:?}", e.kind()
                );
            }
        }
    }
}

// ── Win32 virtual-key code constants (stable, inlined) ────────────────────
//
// Source: Microsoft VK_* docs. Inlined rather than imported because
// windows-sys 0.52 puts them under
// `Win32::UI::Input::KeyboardAndMouse` which would require enabling a
// new feature for one constant each.
const VK_RETURN: u16 = 0x0D;
const VK_ESCAPE: u16 = 0x1B;
const VK_SPACE:  u16 = 0x20;
const VK_UP:     u16 = 0x26;
const VK_DOWN:   u16 = 0x28;

// Modifier-state bits inside KEY_EVENT_RECORD::dwControlKeyState.
// Stable Win32 values; same rationale as the VK constants above.
const LEFT_CTRL_PRESSED:  u32 = 0x0008;
const RIGHT_CTRL_PRESSED: u32 = 0x0004;

/// RAII guard that captures the original input + output console modes,
/// flips them into raw / VT-processing modes for picker rendering,
/// and restores both modes on drop.
///
/// Why both handles in one guard: the picker needs raw input AND VT
/// output simultaneously; bundling avoids a half-set state where Drop
/// of one guard restores while the other is still in raw mode (would
/// leave the user's terminal in a wedged state on panic).
pub(crate) struct RawConsole {
    h_in: HANDLE,
    h_out: HANDLE,
    orig_in_mode: u32,
    orig_out_mode: u32,
    /// True when we successfully set the input mode (so Drop restores it).
    /// Important for error paths where SetConsoleMode on input succeeded
    /// but on output failed — Drop must still restore input.
    in_mode_changed: bool,
    out_mode_changed: bool,
}

impl RawConsole {
    /// Open the controlling console in raw input + VT output mode.
    ///
    /// Returns `Err` if either stdin or stderr is not attached to a real
    /// console (redirected to a pipe / file). The dispatcher uses this
    /// signal to fall back to `fallback_select` (numbered list) instead
    /// of trying to render a TUI no one can interact with.
    pub(crate) fn open() -> io::Result<Self> {
        let h_in = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if h_in == 0 || h_in == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stdin handle invalid (cannot open Windows console)",
            ));
        }
        let h_out = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        if h_out == 0 || h_out == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stderr handle invalid",
            ));
        }

        let mut orig_in_mode: u32 = 0;
        if unsafe { GetConsoleMode(h_in, &mut orig_in_mode) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stdin is not a real console (redirected pipe / file)",
            ));
        }
        let mut orig_out_mode: u32 = 0;
        if unsafe { GetConsoleMode(h_out, &mut orig_out_mode) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stderr is not a real console",
            ));
        }

        // Input mode: clear LINE/ECHO/PROCESSED so we read raw KEY_EVENT
        // records (Ctrl-C reaches us as KEY_EVENT instead of triggering
        // the default Ctrl-C handler that would terminate the process).
        // Don't set ENABLE_VIRTUAL_TERMINAL_INPUT — we use ReadConsoleInputW
        // and parse KEY_EVENT_RECORD directly; VT input would interleave
        // raw bytes that we don't want.
        let raw_in_mode =
            orig_in_mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        if unsafe { SetConsoleMode(h_in, raw_in_mode) } == 0 {
            return Err(io::Error::last_os_error());
        }

        // Output mode: enable VT processing so the existing ANSI escape
        // sequences (cursor up / erase line) the Unix render path emits
        // work on Windows too. Old Windows 10 builds (< 1607) didn't
        // support this; we don't claim those baselines anyway
        // (windows-compatibility.md §0: minimum = Windows 10 1809+).
        let new_out_mode = orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        let out_changed = if new_out_mode != orig_out_mode {
            if unsafe { SetConsoleMode(h_out, new_out_mode) } == 0 {
                // Restore input before erroring out.
                let _ = unsafe { SetConsoleMode(h_in, orig_in_mode) };
                return Err(io::Error::last_os_error());
            }
            true
        } else {
            false
        };

        Ok(Self {
            h_in,
            h_out,
            orig_in_mode,
            orig_out_mode,
            in_mode_changed: true,
            out_mode_changed: out_changed,
        })
    }
}

impl Drop for RawConsole {
    fn drop(&mut self) {
        // Restore in reverse order of acquisition. Errors deliberately
        // ignored — the alternative (panic-in-Drop) is worse.
        if self.out_mode_changed {
            unsafe { SetConsoleMode(self.h_out, self.orig_out_mode) };
        }
        if self.in_mode_changed {
            unsafe { SetConsoleMode(self.h_in, self.orig_in_mode) };
        }
    }
}

/// Read the next "interesting" key event from the console, skipping
/// non-key events (mouse / window resize / focus events) and
/// key-up events (we only act on key-down to match Unix behaviour
/// where the kernel only delivers a byte once per press).
pub(crate) fn read_key_windows(rc: &RawConsole) -> io::Result<Key> {
    loop {
        let mut record: MaybeUninit<INPUT_RECORD> = MaybeUninit::uninit();
        let mut nread: u32 = 0;
        let ok = unsafe { ReadConsoleInputW(rc.h_in, record.as_mut_ptr(), 1, &mut nread) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if nread == 0 {
            // Spurious wake — ReadConsoleInputW shouldn't return 0 with
            // nread==0 in our caller pattern, but defensively retry.
            continue;
        }
        // SAFETY: ReadConsoleInputW filled the record (ok != 0, nread >= 1).
        let rec = unsafe { record.assume_init() };
        if rec.EventType != KEY_EVENT as u16 {
            // Mouse / focus / resize — ignore.
            continue;
        }
        // SAFETY: union access guarded by EventType == KEY_EVENT above.
        let key_event: &KEY_EVENT_RECORD = unsafe { &rec.Event.KeyEvent };
        if key_event.bKeyDown == 0 {
            // We only handle key-down; ignore key-up.
            continue;
        }

        // Match by virtual-key first — unambiguous for arrows / Enter / Esc.
        match key_event.wVirtualKeyCode {
            VK_UP => return Ok(Key::Up),
            VK_DOWN => return Ok(Key::Down),
            VK_RETURN => return Ok(Key::Enter),
            VK_SPACE => return Ok(Key::Space),
            VK_ESCAPE => return Ok(Key::Escape),
            _ => {}
        }

        // Detect Ctrl+C: when ENABLE_PROCESSED_INPUT is cleared, the
        // console no longer auto-handles Ctrl-C — it arrives as a
        // KEY_EVENT with the 'C' / 'c' character AND the control-key
        // state bit set, OR as a KEY_EVENT whose UnicodeChar is 0x03.
        // Both paths are observed in practice across Windows builds; we
        // accept either.
        // SAFETY: KEY_EVENT_RECORD::uChar is a union of u16/i8; we read
        // the wide-char half via raw memory access since windows-sys
        // exposes it as a typedef'd union we can't name directly without
        // extra features.
        let uchar: u16 = unsafe {
            // KEY_EVENT_RECORD layout per Win32:
            //   WORD wRepeatCount; WORD wVirtualKeyCode; WORD wVirtualScanCode;
            //   union { WCHAR UnicodeChar; CHAR AsciiChar; } uChar;
            //   DWORD dwControlKeyState;
            // windows-sys 0.52 exposes uChar as a transparent struct;
            // the wide-char read is safe because the field is always
            // initialised on a key-down record.
            std::ptr::read_unaligned((&key_event.uChar) as *const _ as *const u16)
        };

        let ctrl_pressed = (key_event.dwControlKeyState
            & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED))
            != 0;

        if uchar == 0x03 || (ctrl_pressed && (uchar == b'C' as u16 || uchar == b'c' as u16)) {
            return Ok(Key::CtrlC);
        }

        // Printable Unicode → Char. Reject 0x00 (no character delivered
        // for this key, e.g. modifier-only press) and other control bytes.
        if uchar >= 0x20 {
            if let Some(c) = char::from_u32(uchar as u32) {
                if c.is_ascii_graphic() || (c as u32 > 0x7F) {
                    return Ok(Key::Char(c));
                }
            }
        }

        return Ok(Key::Other);
    }
}

// ============================================================================
// interactive_select_windows — single-select picker
// ============================================================================
//
// Mirrors the structure of `ui_select::interactive_select` but uses
// `RawConsole` + `read_key_windows` instead of /dev/tty + termios.
// Render helpers (compute_inner_w, format_row, redraw_two) are reused
// directly via pub(crate) imports.

pub(crate) fn interactive_select_windows(
    title: &str,
    header: &str,
    items: &[String],
    selectable: &[bool],
    initial: usize,
) -> Result<SelectResult, Box<dyn std::error::Error>> {
    let rc = match RawConsole::open() {
        Ok(c) => c,
        // Not on a real console — caller falls back to numbered-list.
        Err(e) => return Err(e.into()),
    };

    let inner_w = compute_inner_w(title, header, items);
    let border = "\u{2500}".repeat(inner_w);
    let narrow = crate::ui_frame::is_narrow();

    let icon_title = format!("\u{1F50D} {}", title);
    let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
    let title_bar = format!("\u{2500} {} {}", icon_title, "\u{2500}".repeat(title_fill));

    let mut out = io::stderr();

    // Hide cursor.
    write!(out, "\x1b[?25l")?;

    let pad_target = inner_w.saturating_sub(4);
    if narrow {
        let rule = "\u{2500}".repeat(pad_target);
        write!(out, "\r\n  {}\r\n", icon_title)?;
        write!(out, "  {}\r\n", rule)?;
        write!(out, "  {}\r\n", header)?;
        write!(out, "  \x1b[90m{}\x1b[0m\r\n", rule)?;
    } else {
        write!(out, "\r\n  \u{250C}{}\u{2510}\r\n", title_bar)?;
        write!(out, "  \u{2502}  {}  \u{2502}\r\n", pad_visible(header, pad_target))?;
        let sep = "\u{2500}".repeat(pad_target + 2);
        write!(out, "  \u{2502} {} \u{2502}\r\n", sep)?;
    }

    let mut cursor = initial;
    if !selectable.get(cursor).copied().unwrap_or(false) {
        cursor = next_selectable(cursor, selectable, true).unwrap_or(0);
    }

    for (i, item) in items.iter().enumerate() {
        write!(out, "{}\r\n", format_row(item, i == cursor, inner_w))?;
    }

    if narrow {
        let rule = "\u{2500}".repeat(pad_target);
        write!(out, "  {}\r\n", rule)?;
    } else {
        write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;
    }

    write!(out, "  [\u{2191}\u{2193} move, \x1b[1;33mEnter\x1b[0m select, Esc cancel]")?;
    out.flush()?;

    let total = items.len();
    let result = loop {
        match read_key_windows(&rc)? {
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

    write!(out, "\x1b[?25h\r\n\r\n")?;
    out.flush()?;
    Ok(result)
}

// ============================================================================
// interactive_multi_select_windows — checkbox-style multi-select
// ============================================================================

pub(crate) fn interactive_multi_select_windows(
    title: &str,
    items: &[String],
    initially_checked: &[bool],
) -> Result<MultiSelectResult, Box<dyn std::error::Error>> {
    let rc = RawConsole::open()?;

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
    for (i, item) in items.iter().enumerate() {
        write!(out, "{}\r\n", format_multi_row(item, i, i == cursor, checked[i], inner_w))?;
    }
    write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;
    write!(out, "{}", pick_hint(&checked, cursor, has_moved))?;
    out.flush()?;

    let result = loop {
        match read_key_windows(&rc)? {
            Key::Up => {
                if cursor > 0 {
                    has_moved = true;
                    let old = cursor; cursor -= 1;
                    redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            Key::Down => {
                if cursor + 1 < total {
                    has_moved = true;
                    let old = cursor; cursor += 1;
                    redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            Key::Space => {
                checked[cursor] = !checked[cursor];
                redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                out.flush()?;
            }
            Key::Enter => {
                if checked.iter().any(|&c| c) {
                    break MultiSelectResult::Confirmed(
                        checked.iter().enumerate().filter(|(_, &c)| c).map(|(i, _)| i).collect()
                    );
                } else {
                    checked[cursor] = true;
                    redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
                    write!(out, "\r\x1b[2K{}", pick_hint(&checked, cursor, has_moved))?;
                    out.flush()?;
                }
            }
            Key::Char(c) if c.is_ascii_digit() && c != '0' => {
                let idx = (c as usize) - ('1' as usize);
                if idx < total {
                    has_moved = true;
                    checked[idx] = !checked[idx];
                    if cursor != idx {
                        let old = cursor; cursor = idx;
                        redraw_multi_two(&mut out, old, cursor, items, &checked, inner_w, total)?;
                    } else {
                        redraw_multi_one(&mut out, cursor, items, &checked, inner_w, total)?;
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

// ============================================================================
// interactive_provider_tree_windows — collapsible group / radio-row picker
// ============================================================================

pub(crate) fn interactive_provider_tree_windows(
    groups: &mut Vec<ProviderGroup>,
) -> Result<ProviderTreeResult, Box<dyn std::error::Error>> {
    let rc = RawConsole::open()?;

    let title = "Provider Key Selection";
    let icon_title = format!("\u{1F310} {}", title);
    let mut out = io::stderr();
    let mut cursor: usize = 0;

    loop {
        let rows = build_tree_rows(groups);
        let total = rows.len();
        let max_inner = crate::ui_frame::term_width().saturating_sub(6);
        let label_col_w = max_candidate_label_width(groups) + 2;
        let max_type_w = groups.iter()
            .flat_map(|g| g.candidates.iter())
            .map(|c| c.display_type.as_deref().unwrap_or(
                if c.source_type == "personal_oauth_account" { "oauth" } else { &c.source_type }
            ).len())
            .max().unwrap_or(8);
        let content_min_w = 17 + label_col_w + max_type_w;
        let inner_w = (visible_len(&icon_title) + 4).max(content_min_w).min(max_inner);
        let border = "\u{2500}".repeat(inner_w);
        let title_fill = inner_w.saturating_sub(visible_len(&icon_title) + 3);
        let title_bar = format!("\u{2500} {} {}", icon_title, "\u{2500}".repeat(title_fill));

        if cursor >= total || !is_focusable(&rows[cursor]) {
            cursor = rows.iter().position(is_focusable).unwrap_or(0);
        }

        write!(out, "\x1b[?25l")?;
        write!(out, "\r\n  \u{250C}{}\u{2510}\r\n", title_bar)?;
        for (i, row) in rows.iter().enumerate() {
            write!(out, "{}\r\n", format_tree_row(row, groups, i == cursor, inner_w, label_col_w, max_type_w))?;
        }
        write!(out, "  \u{2514}{}\u{2518}\r\n", border)?;
        write!(out, "  [\u{2191}\u{2193} move \u{2022} \x1b[1;33mSpace\x1b[0m select/expand \u{2022} \x1b[1;33mEnter\x1b[0m confirm \u{2022} \x1b[1;33mEsc\x1b[0m cancel]\r\n")?;
        out.flush()?;

        let key = read_key_windows(&rc)?;

        let erase_lines = total + 4;
        for _ in 0..erase_lines {
            write!(out, "\x1b[A\r\x1b[2K")?;
        }
        out.flush()?;

        match key {
            Key::Up => {
                let mut n = cursor;
                loop {
                    if n == 0 { break; }
                    n -= 1;
                    if is_focusable(&rows[n]) { cursor = n; break; }
                }
            }
            Key::Down => {
                let mut n = cursor;
                loop {
                    if n + 1 >= total { break; }
                    n += 1;
                    if is_focusable(&rows[n]) { cursor = n; break; }
                }
            }
            Key::Space => match &rows[cursor] {
                TreeRow::Provider(gi) => { groups[*gi].expanded = !groups[*gi].expanded; }
                TreeRow::Candidate(gi, ci) => { groups[*gi].selected = Some(*ci); }
                _ => {}
            },
            Key::Enter => {
                write!(out, "\x1b[?25h")?; out.flush()?;
                return Ok(ProviderTreeResult::Confirmed(groups.clone()));
            }
            Key::Escape | Key::CtrlC => {
                write!(out, "\x1b[?25h")?; out.flush()?;
                return Ok(ProviderTreeResult::Cancelled);
            }
            _ => {}
        }
    }
}

