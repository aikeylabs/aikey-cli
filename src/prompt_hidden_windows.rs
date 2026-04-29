//! Windows variant of `lib.rs::read_password_with_stars`. Stage 1.1
//! windows-compat, extracted to a sibling module 2026-04-29 to keep
//! `lib.rs` macOS-byte-clean (Strategy A pure — same pattern as
//! `ui_select_windows.rs`).
//!
//! ## What this provides
//!
//! `read_password_with_stars_windows()` reads a password character-by-
//! character from the Windows console input handle, printing `*` for
//! each visible character. Supports backspace and surfaces Ctrl-C as
//! `io::ErrorKind::Interrupted` (mirrors the Unix variant in
//! `lib.rs::read_password_with_stars`).
//!
//! ## Why split out vs inline
//!
//! Pre-2026-04-29 this lived as a `#[cfg(windows)]` block of ~100 LoC
//! inside `lib.rs`. Strategy A pure (windows-compatibility.md §7.1):
//! Windows-only code that doesn't share any logic with the Unix path
//! belongs in a `_windows.rs` sibling so:
//!
//!   1. The macOS byte-level diff for `lib.rs` is genuinely empty when
//!      a Windows-only change happens here. Reviewers can audit the
//!      Unix file knowing it's untouched.
//!   2. cargo's `#[cfg(windows)]` skips this file entirely on macOS /
//!      Linux compilation, so there's zero chance the new code can
//!      affect Unix machine code.
//!   3. Future changes to ReadConsoleW behaviour stay localised — no
//!      need to scroll through 100 lines of unrelated lib code.
//!
//! ## Why ReadConsoleW + console-mode toggle (not `crossterm`)
//!
//! We already take a hard dep on `windows-sys` for proxy_proc / crypto,
//! so adding a second cross-platform layer for this single fn would
//! just duplicate surface area. The mode mask we use
//! (`mode & !(ECHO|LINE|PROCESSED)`) is the documented contract for
//! raw-line console input on Windows.

#![cfg(windows)]

use std::io::Write;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, ENABLE_ECHO_INPUT,
    ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, STD_INPUT_HANDLE,
};

/// Reads a password character-by-character with echo disabled,
/// printing `*` for each visible character. Supports backspace and
/// surfaces Ctrl-C as `io::ErrorKind::Interrupted`.
///
/// Returns `Err` (and the caller falls back to `rpassword::read_password`)
/// when stdin is not a real console — `GetConsoleMode` rejects redirected
/// pipes / files which is exactly the signal we need for "this is not
/// an interactive session, stop trying to do star-feedback".
pub(crate) fn read_password_with_stars_windows() -> std::io::Result<String> {
    let h_in: HANDLE = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if h_in == 0 || h_in == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut orig_mode: u32 = 0;
    if unsafe { GetConsoleMode(h_in, &mut orig_mode) } == 0 {
        // Not a real console (stdin redirected from a pipe / file). Caller
        // falls back to rpassword which handles non-TTY stdin correctly.
        return Err(std::io::Error::last_os_error());
    }

    // Disable echo + line buffering + processed-input so we read raw
    // wide chars one at a time. Clearing PROCESSED gives us Ctrl-C as
    // 0x03 (we map it to Interrupted), matching the Unix branch.
    let raw_mode = orig_mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    if unsafe { SetConsoleMode(h_in, raw_mode) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut password = String::new();
    let mut buf = [0u16; 1];
    let mut chars_read: u32 = 0;
    let result: std::io::Result<()> = loop {
        let ok = unsafe {
            ReadConsoleW(
                h_in,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                1,
                &mut chars_read,
                std::ptr::null(),
            )
        };
        if ok == 0 {
            break Err(std::io::Error::last_os_error());
        }
        if chars_read == 0 {
            // EOF on stdin (rare in interactive console mode).
            break Ok(());
        }
        let unit = buf[0];
        match unit {
            // Enter: CR or LF
            0x0D | 0x0A => break Ok(()),
            // Ctrl-C — restore mode then surface as Interrupted (matches Unix).
            0x03 => {
                unsafe { SetConsoleMode(h_in, orig_mode) };
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "interrupted",
                ));
            }
            // Backspace
            0x08 => {
                if !password.is_empty() {
                    password.pop();
                    eprint!("\x08 \x08");
                    let _ = std::io::stderr().flush();
                }
            }
            // Printable (BMP only — surrogate pairs are exotic in passwords
            // and would require buffering across reads. If they ever matter
            // we extend with a 2-unit lookahead).
            c if c >= 0x20 => {
                if let Some(Ok(decoded)) =
                    std::char::decode_utf16(std::iter::once(c)).next()
                {
                    password.push(decoded);
                    eprint!("*");
                    let _ = std::io::stderr().flush();
                }
            }
            // Silently skip other control units.
            _ => {}
        }
    };

    // Restore original console mode regardless of success/error path.
    unsafe { SetConsoleMode(h_in, orig_mode) };

    result.map(|_| password)
}
