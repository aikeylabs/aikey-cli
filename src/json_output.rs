use serde_json::json;
use std::process;

/// Output a success JSON response and exit with code 0
pub fn success(data: serde_json::Value) -> ! {
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

/// Output an error JSON response and exit with the specified code
pub fn error(message: &str, exit_code: i32) -> ! {
    let response = json!({
        "status": "error",
        "error": message
    });

    // Output to stderr to avoid mixing with child process stdout
    eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}

/// Output an error JSON response with additional data and exit
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

    // Output to stderr to avoid mixing with child process stdout
    eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
    process::exit(exit_code);
}
