//! Mechanical fence: "you need a terminal for the master password" guidance
//! lives ONLY in src/session.rs.
//!
//! ## Why
//!
//! Every refusal meaning "this machine cannot supply the master password right
//! now" must carry ERRCODE_VAULT_LOCKED_NO_CACHED_PASSWORD — GUI consumers
//! (aikey-tray's servicebridge.IsVaultLocked, the panel's act()) match on the
//! CODE to open their in-panel unlock form, never on prose. The 2026-08-22 fix
//! coded only the proxy-start exit of that concept; `aikey key use` kept a
//! hand-rolled sentence ("Set AK_TEST_PASSWORD or run from an interactive
//! terminal"), and a tray user on winpc2 hit a dead-end banner (2026-08-25):
//! the unlock form the panel already had never opened.
//!
//! A concept with no single exit gets re-derived by hand at every new call
//! site, so this fence forces the exit: any non-comment line in `src/**/*.rs`
//! outside `session.rs` that spells the phrase "interactive terminal" is a
//! failure — build the message through `session::password_unavailable_error`
//! (or one of its wrappers) instead.
//!
//! Bugfix: workflow/CI/bugfix/2026-08-25-tray-team-key-switch-locked-vault-dead-end.md
//! Behavior-level companion: tests/e2e_key_use_vault_locked_errcode.rs

use std::fs;
use std::path::{Path, PathBuf};

/// Strip `//` line comments and `/* */` block comments, quote-aware — same
/// approach as tests/glyph_fence.rs, kept local so each fence file stays
/// self-contained.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if *in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                *in_block = false;
            }
            continue;
        }
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(esc) = chars.next() {
                    out.push(esc);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => break,
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                *in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn password_terminal_guidance_only_in_session_rs() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);

    let mut violations = Vec::new();
    for path in files {
        if path.file_name().and_then(|n| n.to_str()) == Some("session.rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable source file");
        let mut in_block = false;
        for (idx, line) in text.lines().enumerate() {
            let code = strip_comments(line, &mut in_block);
            if code.contains("interactive terminal") {
                violations.push(format!(
                    "{}:{}: hand-rolled master-password guidance — build it via \
                     session::password_unavailable_error (or a wrapper) so the \
                     refusal carries VAULT_LOCKED_NO_CACHED_PASSWORD \
                     (see tests/password_guidance_fence.rs)",
                    path.strip_prefix(&src).unwrap_or(&path).display(),
                    idx + 1
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "password guidance outside session.rs:\n{}",
        violations.join("\n")
    );
}
