//! Source-level fence: mutating a process-global env var in a unit test
//! requires holding the crate-wide `ENV_MUTATION_LOCK`.
//!
//! Background (2026-08-23 bugfix). `cargo test` runs the lib test binary's
//! tests in parallel THREADS of ONE process, so `HOME` / `SHELL` /
//! `USERPROFILE` / `AIKEY_SHELL_OVERRIDE` are shared mutable state. The crate
//! settled this in `src/test_env_lock.rs`: one process-level mutex, plus a
//! `HomeVaultEnvGuard` RAII wrapper for the common HOME+vault case.
//!
//! The rule was documented in prose and broken twice anyway:
//!
//!   * `commands_internal::unlock::unlock_fences::isolated_vault` moved HOME
//!     while holding only `TEST_VAULT_LOCK` — a DIFFERENT mutex. So it ran
//!     concurrently with `session::tests`, the two stomped each other's HOME,
//!     and `session::tests::test_meta_round_trip` read `vault_seq` 0 instead
//!     of 42. It also never restored HOME, leaving it pointed at an
//!     already-deleted TempDir for every later test in the process — which is
//!     why `optional_read_uses_file_backend` failed on a bare `file_store`.
//!     Reproduced at 1 failure per 25 runs with `--test-threads=8`.
//!
//!   * `connectivity::protocol_addons` moved HOME holding no lock at all.
//!
//! Both were found by hand after a flake, not by a check — hence this file.
//!
//! ## What this fence does and does NOT prove
//!
//! Granularity is the `mod` region, not the individual call. A region that
//! mutates a guarded var must MENTION the lock (directly, through a
//! `ENV_MUTATION_LOCK as X` alias, or through `HomeVaultEnvGuard`). That is
//! deliberately coarse: whether the lock is actually held at the moment of the
//! write is a dataflow question this cannot answer, and helper functions such
//! as `local_server_probe::tests::with_home` are legitimately called by test
//! bodies that took the lock themselves.
//!
//! So it catches the case that actually bit us twice — a NEW test module that
//! is unaware the rule exists — and does not catch a new unlocked test added
//! to a module that already locks elsewhere. Closing that gap needs the
//! single-door refactor (route every mutation through one guard type), which
//! is a larger change and has not been made.
//!
//! 能红: delete the `HomeVaultEnvGuard` call from `unlock.rs::isolated_vault`,
//! or the `ENV_MUTATION_LOCK` line from the `protocol_addons` test. Both were
//! confirmed to turn this test red before they were fixed.
//!
//! Regression doc:
//! workflow/CI/bugfix/20260823-cli-test-home-env-parallel-race.md

use std::fs;
use std::path::{Path, PathBuf};

/// Home of the lock and of `HomeVaultEnvGuard`. Its `Drop` impl restores HOME
/// while holding the guard in a struct field, so it can never satisfy a
/// lexical "mentions the lock" test — and it is the one file that defines the
/// door, so it is exempt by construction.
const OWNER_FILE: &str = "test_env_lock.rs";

/// Process-global env vars that `ENV_MUTATION_LOCK` is documented to guard.
/// `AK_VAULT_PATH` is deliberately absent: it belongs to `TEST_VAULT_LOCK`.
const GUARDED_VARS: [&str; 4] = ["HOME", "USERPROFILE", "SHELL", "AIKEY_SHELL_OVERRIDE"];

/// Evidence that a region is aware of the rule.
const LOCK_MARKERS: [&str; 2] = ["ENV_MUTATION_LOCK", "HomeVaultEnvGuard"];

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

/// True if `line` writes one of the guarded vars, ignoring comments.
fn mutates_guarded_var(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return false;
    }
    if !line.contains("set_var(") && !line.contains("remove_var(") {
        return false;
    }
    GUARDED_VARS
        .iter()
        .any(|v| line.contains(&format!("\"{v}\"")))
}

/// Start-of-line `mod foo` declarations, used to split a file into regions.
fn starts_mod_region(line: &str) -> bool {
    let t = line.trim_start();
    let t = t.strip_prefix("pub ").unwrap_or(t);
    let t = match t.find(')') {
        // `pub(crate) mod ...`
        Some(i) if t.starts_with("pub(") => t[i + 1..].trim_start(),
        _ => t,
    };
    t.starts_with("mod ")
}

/// Local names bound to the crate lock, e.g. `use ... as ENV_LOCK;`.
fn lock_aliases(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_once("ENV_MUTATION_LOCK as "))
        .map(|(_, rest)| {
            rest.trim()
                .trim_end_matches(';')
                .trim_end_matches('}')
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn env_var_mutations_declare_the_crate_lock() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    assert!(
        !files.is_empty(),
        "no sources scanned — fence would be vacuous"
    );

    // Self-check: the fence is worthless if its own detector cannot see a
    // mutation. Keeps a future refactor of `mutates_guarded_var` from
    // silently turning this whole file into a no-op.
    assert!(
        mutates_guarded_var(r#"std::env::set_var("HOME", tmp.path());"#),
        "detector no longer recognises a plain HOME mutation"
    );
    assert!(
        !mutates_guarded_var(r#"// std::env::set_var("HOME", tmp.path());"#),
        "detector must ignore commented-out lines"
    );

    let mut offenders: Vec<String> = Vec::new();
    let mut scanned_regions = 0usize;

    for file in &files {
        if file.file_name().is_some_and(|n| n == OWNER_FILE) {
            continue;
        }
        let text = fs::read_to_string(file).expect("read source");
        let lines: Vec<&str> = text.lines().collect();

        let mut markers: Vec<String> = LOCK_MARKERS.iter().map(|s| s.to_string()).collect();
        markers.extend(lock_aliases(&text));

        let mut starts: Vec<usize> = vec![0];
        starts.extend(
            lines
                .iter()
                .enumerate()
                .filter(|(_, l)| starts_mod_region(l))
                .map(|(i, _)| i),
        );
        starts.push(lines.len());

        for window in starts.windows(2) {
            let (from, to) = (window[0], window[1]);
            let region = &lines[from..to];
            let hits: Vec<usize> = region
                .iter()
                .enumerate()
                .filter(|(_, l)| mutates_guarded_var(l))
                .map(|(j, _)| from + j + 1)
                .collect();
            if hits.is_empty() {
                continue;
            }
            scanned_regions += 1;
            let aware = region
                .iter()
                .any(|l| markers.iter().any(|m| l.contains(m.as_str())));
            if !aware {
                offenders.push(format!(
                    "{} lines {}-{}: mutates {:?} at {:?} without naming the lock",
                    file.strip_prefix(&src).unwrap_or(file).display(),
                    from + 1,
                    to,
                    GUARDED_VARS,
                    hits,
                ));
            }
        }
    }

    // A rename of the env vars would empty the offender list and read as
    // "everything is fine". Fail loudly instead.
    assert!(
        scanned_regions > 0,
        "no region mutates any of {GUARDED_VARS:?} — the fence has stopped \
         watching anything and must be updated or deleted"
    );

    assert!(
        offenders.is_empty(),
        "these test regions mutate a process-global env var without holding \
         crate::test_env_lock::ENV_MUTATION_LOCK. `cargo test` runs the lib \
         tests as parallel THREADS of one process, so an unlocked HOME/SHELL \
         write races every other test that reads or writes it — the failure \
         shows up as an unrelated test flaking. Take the lock for the whole \
         test, or use HomeVaultEnvGuard when you also need a temp vault:\n{}",
        offenders.join("\n")
    );
}
