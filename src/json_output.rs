use crate::error_codes::ErrorCode;
use serde_json::json;
use std::process;

// STREAM CONTRACT (bugfix 2026-08-20 aikey-json-output-on-stderr):
// machine-readable JSON goes to STDOUT; human diagnostics go to stderr.
//
// WHY this had to change: every non-`_stderr` helper below used to eprintln!,
// so `aikey <cmd> --json > file` produced an EMPTY file and any consumer that
// discarded stderr silently saw nothing. Two shipped consumers were already
// broken by it — ai-compliance-detector's install_service.{sh,ps1} test
// `aikey app list --json 2>/dev/null | grep <slug>` for their "already
// registered" fast path, which could never match, so every install re-ran
// register; a previous round even misdiagnosed that as a regex bug and
// "fixed" the regex while the real cause (empty stdout) survived. aikey-tray
// had to carry a per-command `jsonStream` map to record which stream each
// command's JSON lands on — downstream complexity created purely by this
// split.
//
// The `_stderr` variants are NOT redundant: `aikey run` hands stdout to the
// child process, so its own envelope must stay on stderr. Keep that pair
// distinct — making them identical again is what made the distinction inert.

/// Output a raw JSON payload to STDOUT without wrapping or exiting
pub fn print_json(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}

/// Output a raw JSON payload to STDOUT and exit with code
pub fn print_json_exit(value: serde_json::Value, exit_code: i32) -> ! {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
    process::exit(exit_code);
}

/// Output a success JSON response to STDOUT and exit with code 0
pub fn success(data: serde_json::Value) -> ! {
    let mut response = json!({
        "status": "success"
    });

    if let serde_json::Value::Object(map) = data {
        for (key, value) in map {
            response[key] = value;
        }
    }

    println!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(0);
}

/// Output a success JSON response to stderr and exit with code 0
/// Used for commands like `run` where stdout is reserved for child process output
pub fn success_stderr(data: serde_json::Value) -> ! {
    let mut response = json!({
        "status": "success"
    });

    if let serde_json::Value::Object(map) = data {
        for (key, value) in map {
            response[key] = value;
        }
    }

    // Output to stderr to avoid mixing with child process stdout
    eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(0);
}

/// Output an error JSON response to STDOUT and exit with the specified code
pub fn error(message: &str, exit_code: i32) -> ! {
    let response = json!({
        "status": "error",
        "error": message
    });

    println!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}

/// Output an error JSON response to stderr and exit with the specified code
/// Used for commands like `run` where stdout is reserved for child process output
pub fn error_stderr(message: &str, exit_code: i32) -> ! {
    let response = json!({
        "status": "error",
        "error": message
    });

    // Output to stderr to avoid mixing with child process stdout
    eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}

/// Output an error JSON response with additional data to STDOUT and exit
pub fn error_with_data(message: &str, data: serde_json::Value, exit_code: i32) -> ! {
    let mut response = json!({
        "status": "error",
        "error": message
    });

    if let serde_json::Value::Object(map) = data {
        for (key, value) in map {
            response[key] = value;
        }
    }

    println!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}

/// Output an error JSON response with additional data to stderr and exit
/// Used for commands like `run` where stdout is reserved for child process output
pub fn error_with_data_stderr(message: &str, data: serde_json::Value, exit_code: i32) -> ! {
    let mut response = json!({
        "status": "error",
        "error": message
    });

    if let serde_json::Value::Object(map) = data {
        for (key, value) in map {
            response[key] = value;
        }
    }

    // Output to stderr to avoid mixing with child process stdout
    eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}

/// Output an error JSON response with error code to STDOUT (Platform API v0.2)
pub fn error_with_code(message: &str, code: ErrorCode, exit_code: i32) -> ! {
    let response = json!({
        "ok": false,
        "code": code.as_str(),
        "message": message
    });

    println!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}
