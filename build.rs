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
