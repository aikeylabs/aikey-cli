//! Offline CRF trainer (called by `release.sh` before the main CLI build).
//!
//! Reads `tests/testdata/train.jsonl` (embedded at compile time via `include_str!`
//! in `commands_internal::parse::crf`), runs LBFGS training, and writes the
//! serialized model bytes to the path given by `--output` (default:
//! `data/crf-phase1.bin` relative to CWD).
//!
//! Flow:
//!   release.sh → cargo run --release --bin train-crf -- --output data/crf-phase1.bin
//!             → validate-crf compares metrics vs last baseline
//!             → if accepted, cargo build --release --bin aikey embeds the new .bin
//!
//! Why a separate bin (not a test or build.rs):
//!   - Needs explicit invocation (release.sh decides when to re-train)
//!   - Must produce a file at a known path for the downstream build to pick up
//!   - Not coupled to `cargo test` runs (don't want every test run to retrain)

use std::env;
use std::path::PathBuf;
use std::process;

use aikeylabs_aikey_cli::commands_internal::parse::crf;

fn main() {
    let args: Vec<String> = env::args().collect();
    let output = parse_output_flag(&args).unwrap_or_else(|| PathBuf::from("data/crf-phase1.bin"));

    eprintln!("[train-crf] training CRF from embedded tests/testdata/train.jsonl...");
    let start = std::time::Instant::now();
    let bytes = crf::train_from_embedded();
    let elapsed_ms = start.elapsed().as_millis();
    eprintln!("[train-crf] done: {} bytes in {} ms", bytes.len(), elapsed_ms);

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("[train-crf] ERROR: create_dir_all({}): {}", parent.display(), e);
                process::exit(2);
            }
        }
    }
    if let Err(e) = std::fs::write(&output, &bytes) {
        eprintln!("[train-crf] ERROR: write({}): {}", output.display(), e);
        process::exit(2);
    }
    eprintln!("[train-crf] wrote {}", output.display());

    // Emit machine-readable line on stdout for release.sh to grep/jq.
    println!(
        r#"{{"model_path":"{}","bytes":{},"train_ms":{}}}"#,
        output.display(),
        bytes.len(),
        elapsed_ms
    );
}

fn parse_output_flag(args: &[String]) -> Option<PathBuf> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--output" || args[i] == "-o" {
            if i + 1 < args.len() {
                return Some(PathBuf::from(&args[i + 1]));
            }
        } else if let Some(p) = args[i].strip_prefix("--output=") {
            return Some(PathBuf::from(p));
        }
        i += 1;
    }
    None
}
