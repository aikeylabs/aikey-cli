//! Source-level ratchet: third-party config files are written through ONE
//! door, and the text-level heuristics that deleted user lines are gone.
//!
//! spec: R-third-party-config-guard-2.S1 产品代码不许有第二扇写门
//! design: roadmap20260320/技术实现/阶段9-商业化版本/third-party-config-guard/design.md
//!
//! Background (2026-09-04 winpc2). `unconfigure_codex_cli` fell back to
//! deleting every line containing `# managed by aikey` with a bare
//! `fs::write` — no backup, no verification — and `configure_codex_cli`
//! silently skipped an unparseable file. The 04-20 design said backup-first;
//! the implementation had drifted away from it and nothing noticed. This
//! fence makes the drift a compile-time-adjacent failure:
//!
//!   * `commit(` and `backup_versioned(` exist exactly once, in the guard;
//!   * the guard is the only product code that calls `atomic_write` on a
//!     third-party path (one call site);
//!   * raw write / rename / copy / remove calls in the files that touch
//!     third-party configs can only go DOWN (ratchet). Phase 1 leaves kimi
//!     (shell_integration), claude settings (commands_statusline) and Claude
//!     Desktop (claude_desktop) on their old writers — those numbers are the
//!     allowlist, and each later phase lowers them;
//!   * tokens that belong to the removed text-strip / heal paths never come back.
//!
//! "Product region" = everything before the first `#[cfg(test)]` that opens a
//! `mod`. (`#[cfg(test)]` on a single item — the `TP_COMMITS` witness — does
//! not end the region.)
//!
//! What this does NOT prove: that a call site actually goes through the door
//! at runtime. The behavioural suites (`tp_invalid_file_suite`) cover that
//! with the `TP_COMMITS` witness; this file only stops a NEW writer being
//! added without anyone noticing.

use std::path::Path;

const GUARD: &str = "src/commands_account/third_party_config.rs";

/// (file, raw-write-site ceiling, forbidden-literal ceilings)
/// Ratchet DOWN only. Raising a number here is a design regression and needs
/// the design doc updated first.
const RATCHET: &[(&str, usize)] = &[
    ("src/commands_account/shell_integration.rs", 19), // hook/cluster own files (kimi + codex now on the guard)
    ("src/commands_account/claude_desktop.rs", 3), // the restore-note sidecar (aikey's own file); the four Desktop files go through tp::commit
    ("src/commands_statusline.rs", 15), // statusline render cache / WAL (aikey's own files); claude settings on the guard
    ("src/commands_account/mod.rs", 12), // aikey's own file
    (GUARD, 5),                         // commit(write+delete) + backup copy + prune delete
];

const WRITE_CALLS: &[&str] = &[
    "std::fs::write(",
    "fs::write(",
    "std::fs::rename(",
    "fs::rename(",
    "std::fs::copy(",
    "fs::copy(",
    "remove_file(",
    "atomic_write(",
    "write_config_atomic(",
    "write_settings_atomic(",
];

/// Tokens of the removed paths. Zero everywhere in product code.
const GONE_FOR_GOOD: &[&str] = &[
    "CODEX_LINE_MARKER",
    // Phase 2 (kimi, 2026-09-05): the heal-by-guessing parse, the marker
    // region text strip, the private atomic writer and the "skip silently"
    // outcome are gone from product code for good.
    "parse_or_heal_toml(",
    "strip_managed_region(",
    "write_config_atomic(",
    "SkipUnparseable",
    // Phase 3 (claude settings.json, 2026-09-05)
    "write_settings_atomic(",
    "settings.aikey_backup.json",
];

/// Tokens still used by surfaces not yet on the guard — ratchet per file.
const PHASED_OUT: &[(&str, &str, usize)] = &[
    // the legacy marker constant itself (codex residue detection only)
    (
        "src/commands_account/shell_integration.rs",
        "LEGACY_MARKER",
        1,
    ),
    // legacy single-slot backup NAMES (returned by *_config_paths for the
    // --from-backup candidate list; never written any more)
    (
        "src/commands_account/shell_integration.rs",
        ".aikey_backup.",
        3,
    ),
];

/// The user-facing sentences live in `ReasonCode::sentence` only.
/// (`is not valid TOML` is still hand-written once in the kimi writer → Phase 2;
/// the guard renders the format, so the prefix is what both share.)
const SENTENCE_LITERALS: &[(&str, usize)] = &[
    ("activate an OpenAI key first", 0),
    ("is not valid ", 1),
    ("aikey hook repair", 0),
];

fn product_region(path: &str) -> String {
    let full = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    let lines: Vec<&str> = full.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.trim() == "#[cfg(test)]" {
            if let Some(next) = lines.get(i + 1) {
                if next.trim_start().starts_with("mod ") {
                    break;
                }
            }
        }
        // Comments and doc-comments are not code: a `///` line quoting the
        // repair command must not count as a second sentence source.
        if !l.trim_start().starts_with("//") {
            out.push_str(l);
            out.push('\n');
        }
        i += 1;
    }
    out
}

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

#[test]
fn the_guard_owns_the_only_write_door() {
    let g = product_region(GUARD);
    assert_eq!(count(&g, "fn commit("), 1, "exactly one write door");
    assert_eq!(
        count(&g, "fn backup_versioned("),
        1,
        "exactly one versioned backup"
    );
    assert_eq!(
        count(&g, "profile_activation::atomic_write("),
        1,
        "the guard calls atomic_write from `commit` and nowhere else"
    );
    assert_eq!(
        count(&g, "fn strip_owned_text("),
        1,
        "the only text-level mutation"
    );
}

#[test]
fn raw_write_sites_only_go_down() {
    for (file, ceiling) in RATCHET {
        let region = product_region(file);
        let n: usize = WRITE_CALLS.iter().map(|c| count(&region, c)).sum();
        // `fs::write(` is a suffix of `std::fs::write(` — both patterns hit the
        // same site. The ceilings are calibrated with THIS formula (see the
        // recipe in the design doc), not by counting call sites by eye.
        assert!(
            n <= *ceiling,
            "{file}: {n} raw write-call hits > ceiling {ceiling}. \
             A NEW writer for a third-party config must go through third_party_config::apply."
        );
    }
}

#[test]
fn removed_text_strip_paths_never_return() {
    for (file, _) in RATCHET {
        let region = product_region(file);
        for tok in GONE_FOR_GOOD {
            assert_eq!(count(&region, tok), 0, "{file}: `{tok}` came back");
        }
    }
    for (file, tok, ceiling) in PHASED_OUT {
        let n = count(&product_region(file), tok);
        assert!(n <= *ceiling, "{file}: `{tok}` ×{n} > ratchet {ceiling}");
    }
}

#[test]
fn reason_sentences_are_written_once() {
    for (file, _) in RATCHET {
        if *file == GUARD {
            continue;
        }
        let region = product_region(file);
        for (lit, ceiling) in SENTENCE_LITERALS {
            let n = count(&region, lit);
            assert!(
                n <= *ceiling,
                "{file}: sentence literal {lit:?} ×{n} (ceiling {ceiling}) — build it via ReasonCode::sentence"
            );
        }
    }
    let g = product_region(GUARD);
    for (lit, _) in SENTENCE_LITERALS {
        assert!(count(&g, lit) >= 1, "guard no longer emits {lit:?}");
    }
}
