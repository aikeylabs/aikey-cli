//! Windows-only PowerShell hook install logic. Stage 3.2 windows-compat,
//! extracted to a sibling module 2026-04-29 to keep
//! `shell_integration.rs` macOS-byte-clean (Strategy A pure — same
//! pattern as `ui_select_windows.rs` / `prompt_hidden_windows.rs` /
//! `ui_frame_windows.rs`).
//!
//! ## What this provides
//!
//! - `v3_rc_block_powershell()` — the marker block that gets spliced
//!   into `$PROFILE.CurrentUserAllHosts` to dot-source `~/.aikey/hook.ps1`
//!   at every PowerShell session start.
//! - `powershell_profile_candidates()` — `$PROFILE.CurrentUserAllHosts`
//!   path resolver (pwsh 7+ / Windows PowerShell 5.1 / pwsh on macOS&Linux).
//! - `ensure_powershell_hook()` — PowerShell sibling of bash / zsh's
//!   `ensure_shell_hook`. Writes hook.ps1 + splices the marker block
//!   (TTY-gated, idempotent rewrite if already wired).
//!
//! ## Why split out vs inline
//!
//! Pre-2026-04-29 these three helpers lived inside `shell_integration.rs`
//! (~150 LoC of cumulatively PowerShell-specific logic). Strategy A pure
//! (windows-compatibility.md §7.1) prefers Windows-only code in
//! `_windows.rs` siblings so:
//!
//!   - shell_integration.rs's macOS byte-level diff stays empty when a
//!     PowerShell-only change happens here.
//!   - PowerShell-related concerns (path resolution, $PROFILE marker
//!     syntax, install prompts) are colocated; a future "kimi-cli on
//!     Windows" follower can find PS plumbing in one file.
//!   - Cross-shell sync semantics live in `shell_integration.rs`
//!     (V3 markers, write_hook_file, replace_between_markers), which
//!     this module imports via pub(super) to avoid duplication.
//!
//! ## Why not also extract `display_path` / `kimi_config_paths` etc.
//!
//! Those have small `#[cfg(windows)]` arms (~5 LoC each). Splitting
//! them would cost more in inter-module hops than it saves in clarity.
//! Strategy A is about WHEN the inline code is substantial enough to
//! warrant splitting — small arms stay inline.
//!
//! ## Why NOT `#![cfg(windows)]` on this file
//!
//! The functions here (`v3_rc_block_powershell`,
//! `powershell_profile_candidates`, `ensure_powershell_hook`) are
//! "PowerShell-specific" in concept but **not** "Windows-only" in
//! compilation: none of them use windows-sys / winapi imports. They
//! just produce PowerShell-syntax strings + paths that happen to
//! describe Windows folder layout. Critically:
//!
//!   - cross-platform tests in `stage3_powershell_hook_tests` reference
//!     `v3_rc_block_powershell` to assert PowerShell-syntax invariants;
//!     they run on macOS / Linux too.
//!   - pwsh 7+ runs on macOS / Linux; if a future user installs aikey
//!     under pwsh-on-macOS, `ensure_powershell_hook` should still work.
//!
//! The `_windows.rs` suffix here reflects "this module is **mainly**
//! relevant to Windows users" — naming convention, not a compilation
//! gate. This differs from `ui_select_windows.rs` /
//! `prompt_hidden_windows.rs` / `ui_frame_windows.rs` which **do** use
//! windows-sys APIs and **must** be `#![cfg(windows)]`.

use std::io;

use super::shell_integration::{
    display_aikey_path, replace_between_markers, resolve_user_home, write_hook_file, HookKind,
    V3_BEGIN, V3_END,
};

/// Stage 3.2: PowerShell variant of the v3 marker block, dot-sources
/// `~/.aikey/hook.ps1` from `$PROFILE.CurrentUserAllHosts`.
///
/// Why a separate helper from `v3_rc_block` (POSIX): PowerShell's
/// `$PROFILE.CurrentUserAllHosts` uses different syntax (Test-Path +
/// `.` for source) than POSIX rc. Same marker tokens (`# aikey shell
/// hook v3 begin/end`) so the same idempotent-rewrite logic in
/// `replace_between_markers` works for both.
pub(super) fn v3_rc_block_powershell() -> String {
    // Use $env:USERPROFILE to land on Windows; on cross-platform PowerShell
    // (pwsh on macOS / Linux) $env:HOME is the standard.
    //
    // The Test-Path probe is the equivalent of bash's `[[ -f ... ]]` —
    // dot-source only when the hook file actually exists, so a stale
    // marker block never errors on shell start.
    format!(
        "{begin}\n$_aikeyHookFile = if ($env:USERPROFILE) {{ Join-Path $env:USERPROFILE '.aikey/hook.ps1' }} else {{ Join-Path $env:HOME '.aikey/hook.ps1' }}\nif (Test-Path $_aikeyHookFile) {{ . $_aikeyHookFile }}\nRemove-Variable -Name _aikeyHookFile -Scope Local -ErrorAction SilentlyContinue\n{end}\n",
        begin = V3_BEGIN,
        end = V3_END,
    )
}

/// Stage 3.2: candidate paths for `$PROFILE.CurrentUserAllHosts`.
///
/// PowerShell's `$PROFILE.CurrentUserAllHosts` resolves to:
///   - PowerShell 7+ (pwsh):   `<HOME>\Documents\PowerShell\profile.ps1`
///   - Windows PowerShell 5.1: `<HOME>\Documents\WindowsPowerShell\profile.ps1`
///   - PowerShell 7+ on macOS / Linux: `~/.config/powershell/profile.ps1`
///
/// We don't spawn a PowerShell subprocess to query the actual value
/// because that costs ~200 ms per `aikey use`. Instead we replicate the
/// path resolution from PowerShell's source (SHGetKnownFolderPath
/// FOLDERID_Documents lookup on Windows; XDG `$HOME/.config/powershell`
/// on Unix-y pwsh 7+).
///
/// Returns the candidates in stable preference order. We don't filter
/// to existing-parent here because the user might be installing pwsh
/// via the same flow that triggered this; the install logic creates
/// the parent dir on demand.
///
/// Cross-platform note: pwsh 7+ runs on macOS / Linux, so this fn must
/// produce a usable candidate on those platforms too. The `_windows.rs`
/// suffix here is a naming convention (PowerShell-specific) — see
/// the module-level "Why NOT `#![cfg(windows)]`" docstring above.
pub(super) fn powershell_profile_candidates() -> Vec<std::path::PathBuf> {
    let home = resolve_user_home();
    let mut out: Vec<std::path::PathBuf> = Vec::new();

    #[cfg(windows)]
    {
        out.push(home.join("Documents").join("PowerShell").join("profile.ps1"));
        out.push(home.join("Documents").join("WindowsPowerShell").join("profile.ps1"));
    }
    #[cfg(not(windows))]
    {
        out.push(home.join(".config").join("powershell").join("profile.ps1"));
    }

    out
}

/// Stage 3.2: PowerShell sibling of `ensure_shell_hook`.
///
/// Mirrors the bash/zsh contract:
///   1. Write `~/.aikey/hook.ps1` (Layer 1 — source of truth for wrappers).
///   2. Find `$PROFILE.CurrentUserAllHosts`; if marker block already
///      present, idempotent rewrite. Else fresh install (TTY-gated by
///      H1.5 — bash/zsh have the same gate; non-interactive callers
///      get a clear hint instead of silent rc rewrite).
///
/// Returns the same `Option<String>` envelope as `ensure_shell_hook`
/// so the caller (`commands_account::mod.rs` `aikey use` flow) can print
/// the status line without conditional branching on shell.
pub(super) fn ensure_powershell_hook() -> Option<String> {
    use std::io::IsTerminal;

    let home = match resolve_user_home().to_str() {
        Some(s) => s.to_string(),
        None => return Some("  Could not resolve home dir for PowerShell hook install.".to_string()),
    };

    // 1. Write hook.ps1 — Layer 1 (refresh always, never asks).
    if let Err(e) = write_hook_file(&home, HookKind::PowerShell) {
        return Some(format!("  Could not write {}: {}", display_aikey_path("hook.ps1"), e));
    }

    let v3_block = v3_rc_block_powershell();

    // 2. Look for an existing marker in any candidate profile path.
    //    Idempotent rewrite when found.
    let candidates = powershell_profile_candidates();
    for profile in &candidates {
        let contents = match std::fs::read_to_string(profile) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if contents.contains(V3_BEGIN) {
            if let Some(updated) = replace_between_markers(&contents, V3_BEGIN, V3_END, &v3_block) {
                if updated != contents {
                    let _ = std::fs::write(profile, updated);
                }
            }
            return None;
        }
    }

    // 3. No marker found — fresh install. Same H1.5 non-TTY hard
    //    constraint as bash/zsh: rc-file mutation requires interactive
    //    confirmation. Without it, piped/CI invocations would silently
    //    rewrite $PROFILE — exactly the contract surprise H1.5 prevents.
    if !io::stderr().is_terminal() || !io::stdin().is_terminal() {
        return Some(format!(
            "  Shell hook file rendered, but {} (rc-file) wiring needs interactive confirmation.\n  \
             Run interactively: \x1b[36maikey hook install\x1b[0m\n  \
             Or silence this hint: \x1b[36mset AIKEY_NO_HOOK=1\x1b[0m (or `$env:AIKEY_NO_HOOK = '1'` in PowerShell)\n  \
             To apply right now without rc wiring: \x1b[36m. {}\x1b[0m",
            candidates
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "$PROFILE.CurrentUserAllHosts".to_string()),
            display_aikey_path("hook.ps1"),
        ));
    }

    // Fresh install: pick the candidate whose PARENT DIR already exists
    // (signal that the user actually has that PowerShell version installed).
    // Falling back to candidates.first() (pwsh 7+) when no parent exists
    // means a fresh-install user gets the modern path — but a PS-5.1-only
    // user (no `Documents\PowerShell\`, only `Documents\WindowsPowerShell\`)
    // gets the 5.1 path, which is what their actual PS sessions read.
    //
    // Without this, PS 5.1-only users would silently get a hook installed
    // to the pwsh 7+ profile path that their sessions never source —
    // hours of "why doesn't aikey use work" debugging.
    let target = candidates
        .iter()
        .find(|p| p.parent().map(|d| d.exists()).unwrap_or(false))
        .cloned()
        .or_else(|| candidates.first().cloned());
    let target = match target {
        Some(p) => p,
        None => {
            return Some(
                "  No PowerShell profile candidate path resolved. Set $PROFILE.CurrentUserAllHosts manually."
                    .to_string(),
            );
        }
    };
    let target_display = target.display().to_string();

    let rows = vec![
        format!("Shell:  PowerShell (CurrentUserAllHosts)"),
        format!("File:   {}", target_display),
        format!("Add:    . {}  (v3)", display_aikey_path("hook.ps1")),
    ];
    crate::ui_frame::eprint_box("\u{2753}", "Install PowerShell Shell Hook", &rows);
    eprint!("  Proceed? [Y/n] (default Y): ");
    {
        use std::io::Write;
        let _ = io::stderr().flush();
    }
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok()
        && matches!(input.trim().to_lowercase().as_str(), "n" | "no")
    {
        return Some(format!(
            "  Skipped. To apply once: . {}",
            display_aikey_path("hook.ps1"),
        ));
    }

    // Create parent dir (pwsh 7+ profile dir is often missing on a
    // freshly-installed pwsh) and append the v3 block. Use OpenOptions
    // append — never overwrite user content already present.
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let block = format!("\n{}", v3_block);
    let write_result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&target)
        .and_then(|mut f| std::io::Write::write_all(&mut f, block.as_bytes()));
    if write_result.is_err() {
        return Some(format!(
            "  Could not write to {}. Source {} manually.",
            target_display,
            display_aikey_path("hook.ps1"),
        ));
    }

    Some(format!("  Shell hook installed in {}", target_display))
}
