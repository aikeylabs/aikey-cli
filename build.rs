//! Build script for aikey-cli: injects version metadata at compile time.
//!
//! Priority: environment variables (from Makefile/release.sh) > git commands > defaults.
//! See: roadmap20260320/技术实现/阶段3-增强版KEY管理/统一版本信息方案.md

use std::process::Command;

fn main() {
    // === Declare rerun conditions ===

    // 1. Environment variable dependencies: rerun when make/release.sh values change.
    println!("cargo:rerun-if-env-changed=AIKEY_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=AIKEY_BUILD_REVISION");
    println!("cargo:rerun-if-env-changed=AIKEY_BUILD_ID");
    println!("cargo:rerun-if-env-changed=AIKEY_BUILD_TIME");

    // 2. Git state dependencies: for bare "cargo build", Revision/Dirty come from git.
    //    Watch .git/HEAD (branch switch, commit) and .git/index (git add/commit/stash).
    //    Note: untracked file changes don't update these files — cargo build script
    //    limitation, acceptable as best-effort for bare builds.
    if std::path::Path::new(".git/HEAD").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");
    }
    if std::path::Path::new(".git/index").exists() {
        println!("cargo:rerun-if-changed=.git/index");
    }

    // 3. Shell hook templates: belt-and-suspenders rerun trigger.
    //    `include_str!()` already makes rustc track these as deps so the
    //    enclosing module recompiles when they change. In practice with
    //    RUSTC_WRAPPER=sccache (or other layered caches) that signal can
    //    get lost — observed 2026-04-28: editing src/templates/hook.zsh
    //    didn't propagate to the installed binary's embedded template
    //    until a `cargo clean`. Adding explicit rerun-if-changed + a
    //    fingerprint env var guarantees a recompile when templates change.
    println!("cargo:rerun-if-changed=src/templates/hook.zsh");
    println!("cargo:rerun-if-changed=src/templates/hook.bash");
    let hook_zsh = std::fs::read("src/templates/hook.zsh").unwrap_or_default();
    let hook_bash = std::fs::read("src/templates/hook.bash").unwrap_or_default();
    let hook_fp = fnv1a_64(&hook_zsh).wrapping_mul(0x100000001b3) ^ fnv1a_64(&hook_bash);
    // shell_integration.rs references this via `env!()` so changing it
    // forces that module to recompile.
    println!(
        "cargo:rustc-env=AIKEY_HOOK_TEMPLATES_FINGERPRINT={:016x}",
        hook_fp
    );

    // === Revision ===
    let revision = std::env::var("AIKEY_BUILD_REVISION").unwrap_or_else(|_| {
        let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
        // Dirty detection: git status --porcelain covers modified + untracked
        let dirty = git(&["status", "--porcelain", "--untracked-files=normal"])
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if dirty && sha != "unknown" {
            format!("{}-dirty", sha)
        } else {
            sha
        }
    });

    // === BuildID ===
    // Build-session level ID, must come from the build entry point (make/release.sh).
    // Bare "cargo build" gets "unknown" — honest about not going through build system.
    let build_id = std::env::var("AIKEY_BUILD_ID").unwrap_or_else(|_| "unknown".into());

    // === BuildTime ===
    let build_time = std::env::var("AIKEY_BUILD_TIME").unwrap_or_else(|_| {
        // Cross-platform: try Unix date first, then PowerShell on Windows
        run_cmd("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .or_else(|| {
                run_cmd(
                    "powershell",
                    &[
                        "-NoProfile",
                        "-C",
                        "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')",
                    ],
                )
            })
            .unwrap_or_else(|| "unknown".into())
    });

    // === Version ===
    // AIKEY_BUILD_VERSION overrides CARGO_PKG_VERSION from Cargo.toml.
    // This eliminates the need to sed-edit Cargo.toml during release builds,
    // avoiding data loss when the CLI repo has uncommitted Cargo.toml changes.
    if let Ok(v) = std::env::var("AIKEY_BUILD_VERSION") {
        println!("cargo:rustc-env=CARGO_PKG_VERSION={}", v);
    }

    println!("cargo:rustc-env=AIKEY_BUILD_REVISION={}", revision);
    println!("cargo:rustc-env=AIKEY_BUILD_ID={}", build_id);
    println!("cargo:rustc-env=AIKEY_BUILD_TIME={}", build_time);

    // === BR-rc.5-93 方案 A: per-release TRUSTED_APPS manifest URL+SHA injection ===
    //
    // Avoid the chicken-and-egg of having to manually update install.rs's
    // TRUSTED_APPS (manifest_url + manifest_sha256) on every patch release.
    // Source manifest at launch/manifests/<slug>.manifest.json contains the
    // __RELEASE_TAG__ placeholder; this build step:
    //   1. Reads the source manifest
    //   2. Substitutes __RELEASE_TAG__ → "v" + (AIKEY_BUILD_VERSION or CARGO_PKG_VERSION fallback)
    //   3. Computes SHA-256 of the substituted bytes
    //   4. Emits AIKEY_MANIFEST_URL_<SLUG> and AIKEY_MANIFEST_SHA_<SLUG> as
    //      compile-time env vars consumed by install.rs::TRUSTED_APPS via env!()
    //
    // release.sh performs the SAME substitution at staging time to produce
    // the byte-identical manifest that gets uploaded to GitHub releases.
    // Both substitutions must agree; the placeholder is the contract.
    //
    // If launch/manifests/<slug>.manifest.json is missing (e.g., aikey-cli
    // cloned without sibling launch repo), the build emits a sentinel value
    // ("MISSING") which will cause install to refuse the app at runtime
    // with a clear error — better than silently shipping a broken binary.
    inject_manifest_env_vars(&version_for_url());
}

/// Returns the version string to use in TRUSTED_APPS manifest URL — always
/// prefixed with "v" to match GitHub release tag convention.
fn version_for_url() -> String {
    let bare = std::env::var("AIKEY_BUILD_VERSION")
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());
    format!("v{}", bare)
}

/// BR-rc.5-93 方案 A helper. Hardcoded slug list parallel to install.rs::TRUSTED_APPS;
/// extend together when adding a new first-party app.
fn inject_manifest_env_vars(release_tag: &str) {
    use sha2::{Digest, Sha256};

    const SLUGS: &[&str] = &[
        "degrade-detector",
        "ai-compliance-detector",
        "ai-compliance-deep-scan",
    ];
    // Sibling repo layout: aikeylabs/aikey-cli + aikeylabs/launch
    const MANIFESTS_DIR: &str = "../launch/manifests";

    for slug in SLUGS {
        let env_suffix = slug.to_uppercase().replace('-', "_");
        let manifest_path = format!("{}/{}.manifest.json", MANIFESTS_DIR, slug);
        println!("cargo:rerun-if-changed={}", manifest_path);

        match std::fs::read_to_string(&manifest_path) {
            Ok(src) => {
                let substituted = src.replace("__RELEASE_TAG__", release_tag);
                let sha = format!("{:x}", Sha256::digest(substituted.as_bytes()));
                let url = format!(
                    "https://github.com/aikeylabs/launch/releases/download/{}/{}.manifest.json",
                    release_tag, slug
                );
                println!("cargo:rustc-env=AIKEY_MANIFEST_URL_{}={}", env_suffix, url);
                println!("cargo:rustc-env=AIKEY_MANIFEST_SHA_{}={}", env_suffix, sha);
            }
            Err(e) => {
                // Sibling launch repo missing — emit sentinels that will refuse install at runtime.
                let url = format!(
                    "https://github.com/aikeylabs/launch/releases/download/{}/{}.manifest.json",
                    release_tag, slug
                );
                println!("cargo:rustc-env=AIKEY_MANIFEST_URL_{}={}", env_suffix, url);
                println!(
                    "cargo:rustc-env=AIKEY_MANIFEST_SHA_{}=MISSING_MANIFEST_AT_BUILD_TIME",
                    env_suffix
                );
                println!(
                    "cargo:warning=BR-rc.5-93: {} not found ({}); '{}' app install will refuse at runtime. Clone sibling 'launch' repo to build a working binary.",
                    manifest_path, e, slug
                );
            }
        }
    }
}

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

/// FNV-1a-64. Stable across rustc versions (unlike std's DefaultHasher) so
/// the AIKEY_HOOK_TEMPLATES_FINGERPRINT env var stays comparable across
/// machines / build hosts during diagnostics.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
