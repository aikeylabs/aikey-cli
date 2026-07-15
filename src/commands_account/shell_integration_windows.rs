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
//! compilation: almost none of them use windows-sys / winapi imports
//! (sole exception: `documents_known_folder`, individually gated with
//! `#[cfg(windows)]` — see its docstring). The rest just produce
//! PowerShell-syntax strings + paths that happen to describe Windows
//! folder layout. Critically:
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

use colored::Colorize;

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
    //
    // BR-rc.5-90: also ensure .aikey/bin is on $env:Path. We can't rely on
    // Windows env inheritance because explorer.exe caches the env block at
    // login time, and WM_SETTINGCHANGE broadcasts don't reliably trigger an
    // explorer.exe reload on all Windows builds (Server 2019/2022 in
    // particular). Result: user installs aikey, opens a new PowerShell from
    // the Start menu, types `aikey` → "term not recognized" even though the
    // registry HKCU\Environment.Path has been updated correctly. The
    // user-facing workaround was "log out + log in" or "restart explorer.exe
    // AND open a brand new PS window" — neither acceptable for a
    // first-run experience. This block self-heals: every new PowerShell
    // that loads $PROFILE will check whether .aikey/bin is in $env:Path
    // and prepend it if missing. No-op if explorer already had it.
    //
    // This is in addition to (not replacing) the installer's PATH-update
    // broadcast (BR-rc.5-89) — the broadcast handles all OTHER shells
    // that aren't PowerShell (cmd.exe, third-party terminals), and the
    // V3 block handles PowerShell specifically. Both layers needed.
    // BR-rc.5-90 v2: use literal ';' as PATH separator (Windows-specific).
    // The earlier `[System.IO.Path]::PathSeparator` form trips PS 5.1's
    // parser inside the `-split` context — it tries to parse the `[type]::`
    // expression as a type-literal subscript and reports
    // "Missing closing ')' in expression". $PROFILE.ps1 is Windows-only
    // (CurrentUserAllHosts resolves to Documents\WindowsPowerShell\... on
    // Windows; cross-platform PS 7 users use a different config path that
    // we don't write to from this template). Hardcoding ';' is correct.
    format!(
        "{begin}\n\
         $_aikeyBin = if ($env:USERPROFILE) {{ Join-Path $env:USERPROFILE '.aikey\\bin' }} else {{ Join-Path $env:HOME '.aikey/bin' }}\n\
         if ((Test-Path $_aikeyBin) -and (($env:Path -split ';') -notcontains $_aikeyBin)) {{ $env:Path = \"$_aikeyBin;$env:Path\" }}\n\
         $_aikeyHookFile = if ($env:USERPROFILE) {{ Join-Path $env:USERPROFILE '.aikey/hook.ps1' }} else {{ Join-Path $env:HOME '.aikey/hook.ps1' }}\n\
         if (Test-Path $_aikeyHookFile) {{ . $_aikeyHookFile }}\n\
         Remove-Variable -Name _aikeyBin,_aikeyHookFile -Scope Local -ErrorAction SilentlyContinue\n\
         {end}\n",
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
/// because that costs ~200 ms per `aikey use`. Instead we ask the SAME
/// Win32 API PowerShell's own resolution bottoms out in
/// (SHGetKnownFolderPath FOLDERID_Documents on Windows; XDG
/// `$HOME/.config/powershell` on Unix-y pwsh 7+).
///
/// COMPAT LAYER (2026-07-08, minimal by user decision): the Documents
/// known folder can be REDIRECTED away from `<home>\Documents`
/// (Parallels/VMware shared profiles, OneDrive folder redirection,
/// roaming profiles) and PowerShell follows the redirect. The previous
/// hardcoded `<home>\Documents` wrote the hook into a profile PowerShell
/// never reads on such machines — active.env vars silently never reached
/// any shell, and the post-`aikey use` hint
/// (`. $PROFILE.CurrentUserAllHosts`) died with CommandNotFoundException
/// (Parallels box, 2026-07-08: interactive Documents =
/// `C:\Mac\Home\Documents`). Known-folder candidates therefore come
/// FIRST; the hardcoded paths are KEPT UNCHANGED as fallbacks (API
/// failure + hooks written by older builds must stay findable). On a
/// non-redirected machine the known folder equals `<home>\Documents`,
/// dedup collapses the list to exactly the old one — zero behavior
/// change for machines that already work.
///
/// The known-folder value can be SESSION-DEPENDENT (Parallels:
/// interactive sessions see the Mac-shared path, SSH sessions the local
/// default). Reading it live per-invocation makes the write location
/// agree with the shells the user opens next to this `aikey use`.
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
        if let Some(docs) = documents_known_folder() {
            out.push(docs.join("PowerShell").join("profile.ps1"));
            out.push(docs.join("WindowsPowerShell").join("profile.ps1"));
        }
        for fb in [
            home.join("Documents")
                .join("PowerShell")
                .join("profile.ps1"),
            home.join("Documents")
                .join("WindowsPowerShell")
                .join("profile.ps1"),
        ] {
            if !out.contains(&fb) {
                out.push(fb);
            }
        }
    }
    #[cfg(not(windows))]
    {
        out.push(home.join(".config").join("powershell").join("profile.ps1"));
    }

    out
}

/// Resolve the Documents known folder via `SHGetKnownFolderPath` — the
/// same resolution PowerShell performs for `$PROFILE`, so redirection
/// (Parallels / OneDrive / roaming) is honored identically. `None` on
/// any API failure; callers fall back to `<home>\Documents`.
///
/// This is the module's one windows-sys use — kept behind
/// `#[cfg(windows)]` so the module (and its PowerShell-syntax tests)
/// still compiles and runs on macOS / Linux.
#[cfg(windows)]
fn documents_known_folder() -> Option<std::path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_Documents, SHGetKnownFolderPath};

    unsafe {
        let mut pw: windows_sys::core::PWSTR = std::ptr::null_mut();
        // dwFlags = 0 (KF_FLAG_DEFAULT), hToken = 0 (current user; HANDLE
        // is isize in windows-sys 0.52) — mirrors PowerShell's
        // Environment.GetFolderPath(MyDocuments).
        let hr = SHGetKnownFolderPath(&FOLDERID_Documents, 0, 0, &mut pw);
        if hr != 0 || pw.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *pw.add(len) != 0 {
            len += 1;
        }
        let s = OsString::from_wide(std::slice::from_raw_parts(pw, len));
        CoTaskMemFree(pw as *const core::ffi::c_void);
        if s.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(s))
        }
    }
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
        None => {
            return Some("  Could not resolve home dir for PowerShell hook install.".to_string())
        }
    };

    // 1. Write hook.ps1 — Layer 1 (refresh always, never asks).
    if let Err(e) = write_hook_file(&home, HookKind::PowerShell) {
        return Some(format!(
            "  Could not write {}: {}",
            display_aikey_path("hook.ps1"),
            e
        ));
    }

    let v3_block = v3_rc_block_powershell();

    // 2. 3a (2026-07-12): wire EVERY present PowerShell flavor. pwsh 7 and
    //    PS 5.1 read different profile files; the old "first candidate with
    //    a marker / first parent dir that exists" logic wired exactly one,
    //    leaving the other flavor's sessions hookless while the OR-logic
    //    detectors reported wired. Already-wired targets get an idempotent
    //    in-place rewrite; missing ones need consent below.
    let targets = powershell_wire_targets();
    let mut missing: Vec<std::path::PathBuf> = Vec::new();
    for target in &targets {
        match std::fs::read_to_string(target) {
            Ok(c) if c.contains(V3_BEGIN) => {
                if let Some(updated) = replace_between_markers(&c, V3_BEGIN, V3_END, &v3_block) {
                    if updated != c {
                        let _ = std::fs::write(target, updated);
                    }
                }
            }
            _ => missing.push(target.clone()),
        }
    }
    if missing.is_empty() {
        return None;
    }

    // 3. Unwired flavors remain — fresh install for those. Same H1.5
    //    non-TTY hard constraint as bash/zsh: rc-file mutation requires
    //    interactive confirmation. Without it, piped/CI invocations would
    //    silently rewrite $PROFILE — exactly the contract surprise H1.5
    //    prevents.
    if !io::stderr().is_terminal() || !io::stdin().is_terminal() {
        return Some(format!(
            "  Shell hook file rendered, but {} (rc-file) wiring needs interactive confirmation.\n  \
             Run interactively: {}\n  \
             Or silence this hint: {} (or `$env:AIKEY_NO_HOOK = '1'` in PowerShell)\n  \
             To apply right now without rc wiring: {}",
            missing
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "$PROFILE.CurrentUserAllHosts".to_string()),
            "aikey hook install".cyan(),
            "set AIKEY_NO_HOOK=1".cyan(),
            format!(". {}", display_aikey_path("hook.ps1")).cyan(),
        ));
    }

    let mut rows = vec![format!("Shell:  PowerShell (CurrentUserAllHosts)")];
    for m in &missing {
        rows.push(format!("File:   {}", m.display()));
    }
    rows.push(format!(
        "Add:    . {}  (v3)",
        display_aikey_path("hook.ps1")
    ));
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

    // Consent granted → wire each missing flavor. The shared helper
    // carries the H2 UTF-16 guard (encoding sweep 2026-07-07): NEVER
    // byte-append UTF-8 onto a profile that isn't UTF-8 — PS 5.1 commonly
    // produces UTF-16LE $PROFILE files, and appending corrupts the whole
    // file into per-session parse errors. Failures are reported per file
    // with the conversion recipe; other flavors still get wired.
    let mut failed: Vec<String> = Vec::new();
    for target in &missing {
        if super::shell_integration::wire_one_powershell_profile(target, &v3_block).is_err() {
            failed.push(target.display().to_string());
        }
    }
    if !failed.is_empty() {
        return Some(format!(
            "  Could not wire: {}\n  \
             If the file is UTF-16 (common from PS 5.1 redirection), convert once:\n  \
             {}  then re-run {}.\n  \
             Or source manually: {}",
            failed.join(", "),
            "(Get-Content <file> -Raw) | Set-Content <file> -Encoding utf8".cyan(),
            "aikey hook install".cyan(),
            format!(". {}", display_aikey_path("hook.ps1")).cyan(),
        ));
    }
    let target_display = missing
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    // ExecutionPolicy wired-but-dead guard (2026-07-12, Windows real-machine
    // exploratory testing X2): on default client Windows every policy scope
    // is Undefined → effective Restricted → profile.ps1 REFUSES to load, so
    // the block we just wired never runs and every detector still reports
    // "wired". Surface it at the moment of wiring, with the exact fix.
    let mut done = format!("  Shell hook installed in {}", target_display);
    if let Some(warn) = powershell_profile_load_blocked() {
        done.push_str(&format!("\n{}", warn));
    }
    Some(done)
}

/// pwsh-7 flavor-presence predicate (3a, 2026-07-12): pwsh 7+ keeps its
/// profile in `Documents\PowerShell\` — a DIFFERENT directory from
/// PS 5.1's `Documents\WindowsPowerShell\`. Wiring only one of them leaves
/// the other flavor's sessions hookless while every wired-detector (OR
/// over candidates) reports green. Pure so the decision table is testable
/// cross-platform.
pub(super) fn pwsh7_is_wire_target(profile_dir_exists: bool, pwsh_on_path: bool) -> bool {
    profile_dir_exists || pwsh_on_path
}

/// Is `pwsh` resolvable on PATH? Plain PATH scan (no spawn — this runs on
/// every `aikey use` via ensure_powershell_hook, spawning would add ~100ms).
pub(super) fn pwsh_on_path() -> bool {
    let exe = if cfg!(windows) { "pwsh.exe" } else { "pwsh" };
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(exe).is_file()))
        .unwrap_or(false)
}

/// The profile files each PRESENT PowerShell flavor will actually load —
/// the write-side counterpart of `powershell_profile_candidates()` (which
/// stays permissive OR-logic for read-side detection).
///
/// Windows: PS 5.1 ships with the OS → its profile is always a target;
/// pwsh 7+ only when present (dir or PATH). Unix pwsh uses the single
/// XDG path. Order matters for messages: modern flavor first.
pub(super) fn powershell_wire_targets() -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        let docs =
            documents_known_folder().unwrap_or_else(|| resolve_user_home().join("Documents"));
        let pwsh_dir = docs.join("PowerShell");
        if pwsh7_is_wire_target(pwsh_dir.exists(), pwsh_on_path()) {
            out.push(pwsh_dir.join("profile.ps1"));
        }
        out.push(docs.join("WindowsPowerShell").join("profile.ps1"));
    }
    #[cfg(not(windows))]
    {
        let _ = pwsh_on_path; // referenced so the fn isn't dead on unix builds
        out.push(
            resolve_user_home()
                .join(".config")
                .join("powershell")
                .join("profile.ps1"),
        );
    }
    out
}

/// doctor probe (3a): pwsh 7+ is present but its profile lacks the v3
/// block → pwsh sessions silently run hookless. `None` when fine or on
/// non-Windows.
pub fn pwsh_profile_wiring_gap() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let docs =
            documents_known_folder().unwrap_or_else(|| resolve_user_home().join("Documents"));
        let pwsh_dir = docs.join("PowerShell");
        if !pwsh7_is_wire_target(pwsh_dir.exists(), pwsh_on_path()) {
            return None;
        }
        let profile = pwsh_dir.join("profile.ps1");
        let wired = std::fs::read_to_string(&profile)
            .map(|c| c.contains(V3_BEGIN))
            .unwrap_or(false);
        if wired {
            None
        } else {
            Some(profile)
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(test)]
mod pwsh_dual_profile_tests {
    use super::pwsh7_is_wire_target;

    #[test]
    fn pwsh7_targeted_only_when_present() {
        // dir exists (pwsh ran at least once) → target
        assert!(pwsh7_is_wire_target(true, false));
        // freshly installed pwsh, never launched (no profile dir yet) → PATH wins
        assert!(pwsh7_is_wire_target(false, true));
        // no pwsh anywhere → do NOT create Documents\PowerShell for a
        // flavor the user doesn't have
        assert!(!pwsh7_is_wire_target(false, false));
    }
}

/// Effective ExecutionPolicy a FRESH PowerShell session would see, computed
/// from `Get-ExecutionPolicy -List` scope pairs. Precedence per PowerShell
/// docs: MachinePolicy > UserPolicy > Process > CurrentUser > LocalMachine —
/// but a fresh session has no Process-scope value, so Process is skipped
/// (the CALLING context often runs under `-ExecutionPolicy Bypass`, which
/// must not mask the user's real steady-state). All-Undefined defaults to
/// Restricted on client SKUs — the case that kills profile loading.
pub(super) fn effective_policy_for_new_session(scopes: &[(String, String)]) -> String {
    for wanted in ["MachinePolicy", "UserPolicy", "CurrentUser", "LocalMachine"] {
        if let Some((_, v)) = scopes
            .iter()
            .find(|(s, v)| s == wanted && !v.eq_ignore_ascii_case("Undefined"))
        {
            return v.clone();
        }
    }
    "Restricted".to_string()
}

/// Whether `effective` blocks loading an UNSIGNED profile.ps1 (ours is).
pub(super) fn policy_blocks_profile(effective: &str) -> bool {
    effective.eq_ignore_ascii_case("Restricted") || effective.eq_ignore_ascii_case("AllSigned")
}

/// Windows-only probe: does the current ExecutionPolicy prevent the wired
/// profile (and therefore the aikey hook) from ever loading? Returns a
/// user-facing warning with the scoped fix when blocked, `None` when fine
/// (or on any probe failure — a diagnostics helper must not create noise).
/// GPO-managed scopes (MachinePolicy/UserPolicy) get a "contact IT" variant
/// because `Set-ExecutionPolicy -Scope CurrentUser` cannot override them.
#[cfg(windows)]
pub fn powershell_profile_load_blocked() -> Option<String> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-ExecutionPolicy -List | ForEach-Object { $_.Scope.ToString() + '=' + $_.ExecutionPolicy.ToString() }",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let scopes: Vec<(String, String)> = text
        .lines()
        .filter_map(|l| {
            let (s, v) = l.trim().split_once('=')?;
            Some((s.to_string(), v.to_string()))
        })
        .collect();
    if scopes.is_empty() {
        return None;
    }
    let effective = effective_policy_for_new_session(&scopes);
    if !policy_blocks_profile(&effective) {
        return None;
    }
    let gpo_managed = scopes.iter().any(|(s, v)| {
        (s == "MachinePolicy" || s == "UserPolicy") && !v.eq_ignore_ascii_case("Undefined")
    });
    Some(if gpo_managed {
        format!(
            "  {}",
            format!(
                "\u{25b2} ExecutionPolicy '{}' is enforced by Group Policy \u{2014} PowerShell will NOT load the wired profile, so the aikey hook never runs.\n     Ask your IT admin to allow RemoteSigned for your user.",
                effective
            )
            .yellow()
        )
    } else {
        format!(
            "  {}{}",
            format!(
                "\u{25b2} ExecutionPolicy '{}' blocks profile loading \u{2014} the wired aikey hook will NEVER run in new sessions.\n     Fix once: ",
                effective
            )
            .yellow(),
            "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned".cyan()
        )
    })
}

/// Non-Windows stub — the policy concept doesn't exist for zsh/bash, and
/// pwsh-on-Unix defaults to Unrestricted.
#[cfg(not(windows))]
pub fn powershell_profile_load_blocked() -> Option<String> {
    None
}

#[cfg(test)]
mod execution_policy_tests {
    use super::{effective_policy_for_new_session, policy_blocks_profile};

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn all_undefined_defaults_to_restricted_the_dead_hook_case() {
        // Factory client Windows: every scope Undefined → Restricted →
        // profile never loads. This is exploratory finding X2.
        let p = pairs(&[
            ("MachinePolicy", "Undefined"),
            ("UserPolicy", "Undefined"),
            ("Process", "Undefined"),
            ("CurrentUser", "Undefined"),
            ("LocalMachine", "Undefined"),
        ]);
        let eff = effective_policy_for_new_session(&p);
        assert_eq!(eff, "Restricted");
        assert!(policy_blocks_profile(&eff));
    }

    #[test]
    fn process_scope_bypass_must_not_mask_steady_state() {
        // The probe itself often runs under `-ExecutionPolicy Bypass`
        // (Process scope). A fresh session won't have that — skip it.
        let p = pairs(&[
            ("MachinePolicy", "Undefined"),
            ("UserPolicy", "Undefined"),
            ("Process", "Bypass"),
            ("CurrentUser", "Undefined"),
            ("LocalMachine", "Undefined"),
        ]);
        assert_eq!(effective_policy_for_new_session(&p), "Restricted");
    }

    #[test]
    fn current_user_remotesigned_unblocks() {
        let p = pairs(&[
            ("MachinePolicy", "Undefined"),
            ("UserPolicy", "Undefined"),
            ("Process", "Bypass"),
            ("CurrentUser", "RemoteSigned"),
            ("LocalMachine", "Undefined"),
        ]);
        let eff = effective_policy_for_new_session(&p);
        assert_eq!(eff, "RemoteSigned");
        assert!(!policy_blocks_profile(&eff));
    }

    #[test]
    fn gpo_machine_policy_wins_over_current_user() {
        let p = pairs(&[
            ("MachinePolicy", "Restricted"),
            ("UserPolicy", "Undefined"),
            ("CurrentUser", "RemoteSigned"),
            ("LocalMachine", "Undefined"),
        ]);
        let eff = effective_policy_for_new_session(&p);
        assert_eq!(eff, "Restricted");
        assert!(policy_blocks_profile(&eff));
    }

    #[test]
    fn allsigned_blocks_our_unsigned_profile() {
        assert!(policy_blocks_profile("AllSigned"));
        assert!(!policy_blocks_profile("Unrestricted"));
        assert!(!policy_blocks_profile("Bypass"));
    }
}
