//! Windows detector for `term_caps` (win10-conhost-compat, 2026-07-15).
//! Sibling module so `windows-sys` Console usage stays bounded to one file
//! per concern and `term_caps.rs` stays macOS-byte-clean (Strategy A pure —
//! windows-compatibility.md §7.1, same pattern as `ui_frame_windows.rs`).

#![cfg(windows)]

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
};

use crate::term_caps::{tier_from_env, TermCaps};

/// Enable VT processing on every std handle that is a real console.
///
/// Why persistent (no restore-on-exit, unlike `ui_select_windows::RawConsole`):
/// the selector toggles *input* modes that would break the parent shell if
/// leaked; output VT processing is exactly the mode Windows Terminal / Win11
/// already run consoles in, and leaving it on after exit is harmless — the
/// next process inherits a console that renders escapes correctly.
///
/// Handle classification:
/// - `GetConsoleMode` fails → the handle is redirected (pipe/file), not a
///   console. Nothing to enable; does not count as a VT failure. Escape
///   bytes written to pipes are pre-existing cross-platform behavior.
/// - `GetConsoleMode` ok but `SetConsoleMode(+VT)` fails → a real console
///   that cannot process VT (pre-1809 host, outside the support baseline)
///   → report `vt_enabled = false` so `term_caps::init()` disables colors.
pub(crate) fn detect_windows() -> TermCaps {
    let mut vt_enabled = true;
    for std_id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle/GetConsoleMode/SetConsoleMode are simple
        // Win32 calls; the handle is process-owned and not closed here.
        unsafe {
            let handle = GetStdHandle(std_id);
            if handle == INVALID_HANDLE_VALUE || handle == 0 {
                continue;
            }
            let mut mode = 0u32;
            if GetConsoleMode(handle, &mut mode) == 0 {
                continue; // redirected, not a console
            }
            if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
                continue; // already on (Windows Terminal / Win11 default)
            }
            if SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
                vt_enabled = false;
            }
        }
    }

    let has = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    TermCaps {
        vt_enabled,
        unicode_tier: tier_from_env(
            true,
            has("WT_SESSION"),
            has("WT_PROFILE_ID"),
            has("TERM_PROGRAM"),
        ),
    }
}
