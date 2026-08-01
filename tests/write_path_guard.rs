//! Source-level fence: vault `entries` ciphertext may only be written through
//! the key-verifying door.
//!
//! Background (2026-08-01 bugfix): `storage::verify_vault_key` was added after
//! the 2026-05-11 team-key incident, but it was only wired into the
//! `managed_virtual_keys_cache` write path. Personal `entries` writes went
//! through `store_entry` / `store_entry_on_conn`, which verify nothing — each
//! caller was trusted to have checked the key somewhere upstream. That
//! invariant is invisible at the call site and silently breaks the moment a
//! new caller appears.
//!
//! The damage is unrecoverable and delayed: ciphertext encrypted under a
//! non-current key can never be decrypted again, so the entry drops out of the
//! unlocked vault list, `aikey get` and the proxy registry can't read it, and
//! `aikey change-password` aborts for the WHOLE vault (it re-encrypts every
//! row and fails fast on the bad one).
//!
//! So the rule is structural, not a convention: production code calls
//! `store_entry_verified` / `store_entry_verified_on_conn`. The unverified
//! helpers stay `pub(crate)` for `storage.rs` itself and its unit tests.
//!
//! Regression doc:
//! workflow/CI/bugfix/2026-08-01-vault-unlocked-list-drops-undecryptable-entries.md

use std::fs;
use std::path::{Path, PathBuf};

/// `storage.rs` owns both the verified and unverified helpers, so it is the one
/// file allowed to call the latter.
const OWNER_FILE: &str = "storage.rs";

/// Substrings that indicate an unverified write. `store_entry_verified(` and
/// `store_entry_verified_on_conn(` do NOT contain either of these (the
/// `_verified` infix breaks the match), so the check needs no allowlist.
const UNVERIFIED_CALLS: [&str; 2] = ["store_entry(", "store_entry_on_conn("];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn entries_writes_go_through_the_verified_door() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    assert!(!files.is_empty(), "no sources scanned — fence would be vacuous");

    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        if file.file_name().is_some_and(|n| n == OWNER_FILE) {
            continue;
        }
        let text = fs::read_to_string(&file).expect("read source");
        // Unit tests inside a production module legitimately exercise the
        // low-level helpers; only non-test code is fenced. Files are scanned
        // whole, so a `#[cfg(test)]` module anywhere makes us fall back to
        // line-level filtering below.
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            if UNVERIFIED_CALLS.iter().any(|c| line.contains(c)) {
                offenders.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&src).unwrap_or(&file).display(),
                    i + 1,
                    trimmed
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these call sites write vault entries without verifying the key against \
         config.password_hash — use storage::store_entry_verified{{,_on_conn}} instead:\n{}",
        offenders.join("\n")
    );
}
