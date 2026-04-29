//! Owner-only file ACL hardening, cross-platform.
//!
//! Why this module exists (Stage 2.4 windows-compat):
//!
//! On Unix, `set_permissions(path, 0o600/0o700)` is the canonical "only
//! the owner can read this" gesture. NTFS silently ignores Unix mode
//! bits — files created with default Windows ACLs typically inherit
//! `Authenticated Users:(R)` from the parent directory, which on a
//! shared workstation makes the encrypted vault world-readable.
//!
//! `enforce_owner_only_*` collapses the per-OS hardening into one call
//! site so vault / session / synapse writers stay platform-agnostic.
//!
//! ## Implementation choices
//!
//! - **Unix**: `chmod 0o600` (files) / `0o700` (dirs). Byte-identical
//!   to the original inline code; this module is just the moved
//!   destination.
//! - **Windows**: spawn `icacls.exe` (a Windows builtin since Vista) to
//!   disable inheritance and grant the current user + SYSTEM +
//!   Administrators. Why icacls and not `windows-sys::SetNamedSecurityInfoW`
//!   directly:
//!   - icacls is Microsoft-tested for the exact "owner-only file" use
//!     case; getting the SID + DACL building right by hand is ~100 LoC
//!     of unsafe FFI with several easy-to-miss security pitfalls.
//!   - The installer scripts (Stage 4 D6/D7) will use icacls anyway,
//!     so this keeps the hardening tool consistent end-to-end.
//!   - Latency: ~50 ms for an icacls call — acceptable because vault
//!     init runs once. For frequently-written files (session cache,
//!     synapse), the strategy is to harden the **parent directory**
//!     once and let NTFS inheritance carry the ACL to new files.
//!
//! ## How to apply
//!
//! - At directory creation: call `enforce_owner_only_dir(&dir)` once.
//!   Subsequent files created inside inherit the owner-only ACL.
//! - For first-time vault.db init: also call `enforce_owner_only_file`
//!   to belt-and-suspender the inheritance.

use std::path::Path;

/// Tighten a file's ACL so only the owner (current user) can read/write.
/// Returns `Err` if the underlying syscall / subprocess fails.
pub fn enforce_owner_only_file(path: &Path) -> std::io::Result<()> {
    enforce_owner_only(path, /* is_dir = */ false)
}

/// Tighten a directory's ACL so only the owner can read/write/list, and
/// disable inheritance so files created inside inherit owner-only.
pub fn enforce_owner_only_dir(path: &Path) -> std::io::Result<()> {
    enforce_owner_only(path, /* is_dir = */ true)
}

#[cfg(unix)]
fn enforce_owner_only(path: &Path, is_dir: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(if is_dir { 0o700 } else { 0o600 });
    std::fs::set_permissions(path, perms)
}

#[cfg(windows)]
fn enforce_owner_only(path: &Path, is_dir: bool) -> std::io::Result<()> {
    use std::process::Command;

    // Why icacls over Win32 FFI: see module-level docs.
    //
    // Steps:
    //   1. /inheritance:r       — strip all inherited ACEs (the source of
    //                              the Authenticated Users readability we
    //                              want to remove).
    //   2. /grant:r %USERNAME%  — full control for current user. ":r"
    //                              replaces any existing grant for that
    //                              principal so re-running the helper is
    //                              idempotent.
    //   3. /grant:r SYSTEM      — SYSTEM is needed for backup APIs and
    //                              system services (Windows Defender,
    //                              shadow copy) that legitimately need
    //                              read access to administrative storage.
    //   4. /grant:r Administrators — needed so an elevated admin (e.g.
    //                              IT support) can recover the vault if
    //                              the user account is locked. Same
    //                              principle as Unix `root` having access
    //                              even with mode 0o600.
    //
    // (OI)(CI)F = object + container inheritance, full control. Only
    // applied on directories; files just get F.

    // Early-out for a non-existent path — matches the Go aikeycompat
    // contract ("returns nil if path doesn't exist; caller's
    // MkdirAll/WriteFile error path will surface the problem"). Without
    // this, icacls fails with a cryptic Windows-locale-dependent error
    // string that's hard to diagnose.
    if !path.exists() {
        return Ok(());
    }

    let path_str = path.as_os_str();

    // Step 1: disable inheritance.
    // Why .output() not .status(): icacls writes a localised success
    // line to stdout ("Successfully processed 1 files") on every call,
    // which pollutes our own stdout when running interactively or in
    // tests. We don't need the output content, just the exit code.
    let result = Command::new("icacls")
        .arg(path_str)
        .arg("/inheritance:r")
        .output()?;
    if !result.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("icacls /inheritance:r failed for {}", path.display()),
        ));
    }

    let inherit_flags = if is_dir { ":(OI)(CI)F" } else { ":F" };

    // USERNAME unset → fall through to SYSTEM + Administrators only,
    // matching the Go aikeycompat behaviour: "more secure than failing
    // open". The path will be unreadable to the current user, which is
    // a hard error the user can see immediately by running `aikey
    // status` — better than a half-applied ACL that looks safe but
    // leaks via the inherited Authenticated Users grant we just left
    // unstripped.
    let username = std::env::var("USERNAME").unwrap_or_default();
    let principals: &[&str] = if username.is_empty() {
        &["SYSTEM", "Administrators"]
    } else {
        // ASCII-only sanity check — usernames with embedded ":" or
        // newlines would corrupt the icacls grant string. Defensive.
        if username.contains(':') || username.contains('\n') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("USERNAME contains forbidden char(s): {username:?}"),
            ));
        }
        // Two-element slice with the dynamic username first.
        return enforce_with_username(path, path_str, &username, inherit_flags);
    };

    for principal in principals {
        let result = Command::new("icacls")
            .arg(path_str)
            .arg("/grant:r")
            .arg(format!("{principal}{inherit_flags}"))
            .output()?;
        if !result.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("icacls /grant:r failed for {} on {}", principal, path.display()),
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn enforce_with_username(
    path: &Path,
    path_str: &std::ffi::OsStr,
    username: &str,
    inherit_flags: &str,
) -> std::io::Result<()> {
    use std::process::Command;
    for principal in [username, "SYSTEM", "Administrators"] {
        let result = Command::new("icacls")
            .arg(path_str)
            .arg("/grant:r")
            .arg(format!("{principal}{inherit_flags}"))
            .output()?;
        if !result.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("icacls /grant:r failed for {} on {}", principal, path.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn enforce_owner_only(_path: &Path, _is_dir: bool) -> std::io::Result<()> {
    // No-op on platforms we don't recognise. Don't fail — caller's
    // intent is "tighten if you can"; an unknown platform is allowed
    // to fall back to OS defaults.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: make a fresh tempdir for each test so they don't collide.
    fn fresh_tempdir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aikey-storage-acl-{}-{}-{}",
            label,
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn nonexistent_path_is_noop_not_error() {
        // Stage 2.4 contract: caller's MkdirAll/WriteFile is the source
        // of truth for "does this path exist". We must not fail merely
        // because the path doesn't exist — that would force every caller
        // into a fragile "stat first, then enforce" pattern.
        let phantom = std::env::temp_dir().join(format!(
            "aikey-storage-acl-no-such-{}",
            rand::random::<u64>()
        ));
        assert!(!phantom.exists(), "test invariant: phantom path must not exist");

        // Both file and dir variants accept a non-existent path cleanly.
        enforce_owner_only_file(&phantom).unwrap_or_else(|e| {
            panic!("expected ok on nonexistent file path; got {e}")
        });
        enforce_owner_only_dir(&phantom).unwrap_or_else(|e| {
            panic!("expected ok on nonexistent dir path; got {e}")
        });
    }

    #[test]
    fn idempotent_repeated_runs_dir() {
        // Re-running enforce on the same dir must succeed every time.
        // Why this matters: vault init is called on every `aikey add` /
        // `aikey use` / etc.; if hardening were non-idempotent, the
        // second call would fail or, worse, append duplicate ACEs that
        // accumulate over time.
        let dir = fresh_tempdir("idempotent");
        for round in 1..=3 {
            enforce_owner_only_dir(&dir).unwrap_or_else(|e| {
                panic!("round {round} failed: {e}")
            });
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn idempotent_repeated_runs_file() {
        let dir = fresh_tempdir("idempotent-file");
        let file = dir.join("vault.db");
        fs::write(&file, b"placeholder").unwrap();
        for round in 1..=3 {
            enforce_owner_only_file(&file).unwrap_or_else(|e| {
                panic!("round {round} failed: {e}")
            });
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_mode_is_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_tempdir("mode-file");
        let file = dir.join("v");
        fs::write(&file, b"x").unwrap();
        enforce_owner_only_file(&file).unwrap();
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600 on Unix, got {:o}", mode);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_dir_mode_is_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_tempdir("mode-dir");
        enforce_owner_only_dir(&dir).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0o700 on Unix, got {:o}", mode);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_smoke_succeeds_on_real_file() {
        // Smoke test: hardening must succeed on a freshly-created file.
        // Verifying the actual ACL contents requires `Get-Acl` (PowerShell
        // not available from cargo test); we leave that to the e2e smoke
        // script. Here we only verify the syscall chain doesn't error.
        let dir = fresh_tempdir("smoke-file");
        let file = dir.join("vault.db");
        fs::write(&file, b"placeholder").unwrap();
        enforce_owner_only_file(&file).unwrap_or_else(|e| {
            panic!("Windows enforce_owner_only_file smoke failed: {e}")
        });
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_smoke_succeeds_on_real_dir() {
        let dir = fresh_tempdir("smoke-dir");
        enforce_owner_only_dir(&dir).unwrap_or_else(|e| {
            panic!("Windows enforce_owner_only_dir smoke failed: {e}")
        });
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_files_inside_protected_dir_inherit_owner_only() {
        // The protection model is: harden the directory once, then
        // files created inside inherit the owner-only DACL. This test
        // exercises that flow end-to-end on a real NTFS path. We can't
        // assert on the resolved DACL from cargo test (no Get-Acl), but
        // we verify that creation + read + write succeed for the owner.
        let dir = fresh_tempdir("inherit");
        enforce_owner_only_dir(&dir).unwrap();
        let file = dir.join("inherited.db");
        fs::write(&file, b"after-acl").unwrap();
        let read_back = fs::read(&file).unwrap();
        assert_eq!(read_back, b"after-acl");
        let _ = fs::remove_dir_all(&dir);
    }
}
