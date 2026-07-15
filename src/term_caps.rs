//! Process-wide terminal capability snapshot (win10-conhost-compat, 2026-07-15).
//!
//! ## Why this module exists
//!
//! Two rendering capabilities differ per terminal and were previously
//! assumed to always be present:
//!
//! 1. **VT/ANSI escape processing.** Windows 10's legacy console host
//!    (conhost — what a double-clicked "Windows PowerShell" icon opens)
//!    *supports* VT sequences on every release in our support baseline
//!    (Windows 10 1809+, see windows-compatibility.md §0) but does NOT
//!    enable them by default. The `colored` crate (2.x) never calls
//!    `SetConsoleMode`, so without this module every colored line renders
//!    as literal `←[32m` garbage on Win10 conhost. Windows Terminal and
//!    Windows 11 enable VT by default, which masked the bug.
//! 2. **Unicode glyph coverage.** conhost's raster/Consolas/NSimSun fonts
//!    lack many glyphs we print (⇡ ⇣ ⦿ ⓘ, emoji, …) — they render as □.
//!    There is no API to probe font coverage, so this is a heuristic.
//!
//! Both are computed **once at startup** (`init()` from `main`) and are the
//! single source of truth consumed by `symbols.rs` and any cursor-control
//! code. Display and behavior read the same snapshot — never re-derive
//! capability ad hoc at a callsite.
//!
//! On non-Windows targets this module is a constant: VT on, Fancy glyphs.
//! Unix output is byte-identical with and without this module (Strategy A
//! pure — windows-compatibility.md §7.1).

use std::sync::OnceLock;

/// Which glyph repertoire the active terminal can be trusted to render.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnicodeTier {
    /// Modern terminal (macOS/Linux terminals, Windows Terminal, VS Code):
    /// full symbol set including emoji and dingbats.
    Fancy,
    /// Legacy Windows console (conhost) or unknown Windows host: restrict
    /// user-visible output to ASCII via the `symbols` table.
    Safe,
}

#[derive(Clone, Copy, Debug)]
pub struct TermCaps {
    /// True when it is safe to emit VT/ANSI escape sequences to
    /// stdout/stderr. On Windows this is the *result* of attempting
    /// `SetConsoleMode(.. | ENABLE_VIRTUAL_TERMINAL_PROCESSING)` on every
    /// std handle that is a real console. Always true on Unix.
    pub vt_enabled: bool,
    pub unicode_tier: UnicodeTier,
}

static CAPS: OnceLock<TermCaps> = OnceLock::new();

/// Detect capabilities and, when VT could not be enabled on a real console,
/// globally disable `colored` output (plain text beats escape garbage).
///
/// Called once from `main()` right after `observability::init_trace()`,
/// before any user-visible output. Idempotent: later calls are no-ops.
pub fn init() {
    let caps = *CAPS.get_or_init(detect);
    if !caps.vt_enabled {
        // Degrade tier: a console exists but refused VT (host outside the
        // Win10 1809+ baseline, or an exotic embedded host). Colors would
        // render as literal `←[32m` noise — plain text is strictly better.
        colored::control::set_override(false);
    }
}

pub fn caps() -> TermCaps {
    // `get_or_init` (not `.get().expect(..)`) so library consumers and unit
    // tests that never ran `main()` still get a valid snapshot instead of a
    // panic. The colored-override side effect only happens via `init()`.
    *CAPS.get_or_init(detect)
}

pub fn vt_enabled() -> bool {
    caps().vt_enabled
}

pub fn unicode_tier() -> UnicodeTier {
    caps().unicode_tier
}

fn detect() -> TermCaps {
    #[cfg(windows)]
    {
        crate::term_caps_windows::detect_windows()
    }
    #[cfg(not(windows))]
    {
        TermCaps {
            vt_enabled: true,
            unicode_tier: UnicodeTier::Fancy,
        }
    }
}

/// Pure tier heuristic, shared by the Windows detector and unit tests.
///
/// Font coverage cannot be probed, so we trust the *host* instead:
/// - Windows Terminal exports `WT_SESSION` / `WT_PROFILE_ID`
/// - VS Code's integrated terminal exports `TERM_PROGRAM=vscode`
///
/// Anything else on Windows (bare conhost, ssh/ConPTY sessions, scheduled
/// tasks) gets the ASCII-safe tier — ASCII is correct everywhere, so the
/// heuristic only needs to avoid *false Fancy*, never false Safe.
pub(crate) fn tier_from_env(
    is_windows: bool,
    has_wt_session: bool,
    has_wt_profile: bool,
    has_term_program: bool,
) -> UnicodeTier {
    if !is_windows || has_wt_session || has_wt_profile || has_term_program {
        UnicodeTier::Fancy
    } else {
        UnicodeTier::Safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_is_always_fancy() {
        assert_eq!(
            tier_from_env(false, false, false, false),
            UnicodeTier::Fancy
        );
    }

    #[test]
    fn windows_bare_conhost_is_safe() {
        assert_eq!(tier_from_env(true, false, false, false), UnicodeTier::Safe);
    }

    #[test]
    fn windows_terminal_is_fancy() {
        assert_eq!(tier_from_env(true, true, false, false), UnicodeTier::Fancy);
        assert_eq!(tier_from_env(true, false, true, false), UnicodeTier::Fancy);
    }

    #[test]
    fn windows_vscode_is_fancy() {
        assert_eq!(tier_from_env(true, false, false, true), UnicodeTier::Fancy);
    }

    #[test]
    fn caps_snapshot_is_stable_and_unix_default() {
        // On the Unix CI/dev hosts this asserts the byte-identical contract:
        // VT on, Fancy glyphs — i.e. zero behavior change off Windows.
        #[cfg(not(windows))]
        {
            let c = caps();
            assert!(c.vt_enabled);
            assert_eq!(c.unicode_tier, UnicodeTier::Fancy);
        }
    }
}
