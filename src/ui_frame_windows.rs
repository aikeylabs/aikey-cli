//! Windows variant of `ui_frame::term_width`. Stage 1.3 windows-compat,
//! extracted to a sibling module 2026-04-29 to keep `ui_frame.rs`
//! macOS-byte-clean (Strategy A pure — same pattern as
//! `ui_select_windows.rs` / `prompt_hidden_windows.rs`).
//!
//! ## Why split out vs inline
//!
//! Pre-2026-04-29 the Windows branch was a 30-LoC `#[cfg(windows)]`
//! block inside `ui_frame::term_width`. Strategy A pure (windows-compat
//! §7.1) prefers Windows-only code in `_windows.rs` siblings so:
//!
//!   - The macOS byte-level diff for `ui_frame.rs` is genuinely empty
//!     when a Windows-only width-detection change happens here.
//!   - `windows-sys` Console feature usage stays bounded to a single
//!     file per concern, simplifying the audit trail.
//!   - Future probes (e.g. PowerShell PSReadLine query, OSC 18 terminal
//!     query) can be added here without expanding `ui_frame.rs`.

#![cfg(windows)]

use std::mem::MaybeUninit;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_ERROR_HANDLE,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

/// Probe the Windows console for terminal width via
/// `GetConsoleScreenBufferInfo`. Returns `None` when no console handle
/// exposes a usable width — the caller (`ui_frame::term_width`)
/// continues to its 80-column fallback.
///
/// Mirrors the Unix `ioctl(TIOCGWINSZ)` probe order: stderr → stdout →
/// stdin. Why this order: shell wrappers like `eval $(aikey activate
/// ...)` capture stdout via command substitution, leaving stdout as a
/// pipe (no console behind it). Probing stderr first picks up the
/// real terminal that pickers actually render to. PowerShell flows
/// through the same pattern via `Invoke-Expression $(aikey ...)`.
pub(crate) fn term_width_windows() -> Option<usize> {
    for std_id in [STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, STD_INPUT_HANDLE] {
        let h: HANDLE = unsafe { GetStdHandle(std_id) };
        if h == 0 || h == INVALID_HANDLE_VALUE {
            continue;
        }
        let mut info = MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::zeroed();
        let ok = unsafe { GetConsoleScreenBufferInfo(h, info.as_mut_ptr()) };
        if ok != 0 {
            let info = unsafe { info.assume_init() };
            // srWindow is inclusive on both ends, so width = right - left + 1.
            let cols = (info.srWindow.Right as i32 - info.srWindow.Left as i32 + 1) as i64;
            if cols > 0 {
                return Some(cols as usize);
            }
        }
    }
    None
}
