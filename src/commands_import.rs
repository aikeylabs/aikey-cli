//! `aikey import` — Stage 6 Mode A implementation.
//!
//! The CLI intentionally delegates every vault-touching operation to the
//! Web UI served by local-server. The local-server lifecycle is managed by
//! launchd (macOS) / systemd (Linux), NOT by this CLI — see
//! roadmap20260320/技术实现/update/20260422-批量导入-aikey-serve-命令移除.md
//! for why `aikey serve` / `aikey stop` were removed.
//!
//! Port discovery, health probe, and start-command hints are shared with
//! `aikey status`, `aikey doctor`, and `aikey web` — they live in
//! `local_server_probe`. This module only owns the import-specific UX
//! (browser handoff + headless stub).
//!
//! Flow:
//!   1. Resolve port via `local_server_probe::read_local_server_port`.
//!   2. If a FILE argument is given, validate it can be read.
//!   3. Open the browser to `http://127.0.0.1:<port>/user/import`.
//!   4. If the browser fails to launch (headless / CI), print the URL.
//!
//! `--non-interactive` skips the browser and runs the full
//! parse → confirm flow over HTTP; used for scripts / CI testing.

use std::fs;
use std::path::Path;

use crate::local_server_probe::{probe_health, read_local_server_port};

// CLI-level error codes for the import command.
const ERR_I_NOT_IMPLEMENTED: &str = "I_NOT_IMPLEMENTED";

pub fn handle(
    file: Option<&Path>,
    non_interactive: bool,
    yes: bool,
    provider: Option<&str>,
    as_json: bool,
) -> Result<(), String> {
    let port = read_local_server_port()?;
    let base_url = format!("http://127.0.0.1:{}", port);

    // Probe local-server is alive before anything else; fail fast with a
    // platform-specific start command hint rather than opening a dead URL.
    probe_health(&base_url)?;

    if non_interactive {
        return run_headless(file, &base_url, yes, provider, as_json);
    }

    // Default: optionally pre-parse the file, then open the browser.
    let url = match file {
        Some(p) => {
            let hash = preparse_file(p, &base_url)?;
            format!("{}/user/import?source_hash={}&from_cli=1", base_url, hash)
        }
        None => format!("{}/user/import", base_url),
    };

    open_browser_or_print(&url, as_json)
}

// ── File preparse (optional, happy path) ─────────────────────────────────

fn preparse_file(path: &Path, _base: &str) -> Result<String, String> {
    // For the browser-mode case we currently just validate the file is
    // readable and return a short hash placeholder; the Web UI will re-parse
    // the text after the user pastes/uploads it. True pre-parse via HTTP
    // requires vault unlock on the server, which we don't want to trigger
    // silently from the CLI. Keep this a trivial pass for now.
    fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    Ok("cli".to_string())
}

// ── Browser / headless handoff ──────────────────────────────────────────

fn open_browser_or_print(url: &str, as_json: bool) -> Result<(), String> {
    let opened = try_open_browser(url);
    if opened {
        if as_json {
            println!(r#"{{"status":"ok","url":"{}","browser":"opened"}}"#, url);
        } else {
            println!("Opened {} in your browser.", url);
        }
    } else {
        if as_json {
            println!(r#"{{"status":"ok","url":"{}","browser":"print_only"}}"#, url);
        } else {
            println!(
                "Browser could not be opened. Paste this URL into your browser manually:\n  {}",
                url
            );
        }
    }
    Ok(())
}

fn try_open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        // Stage 3.5 windows-compat: shell out to `rundll32 url.dll,FileProtocolHandler <url>`
        // rather than `Start-Process` or `cmd /c start`.
        //
        // Why rundll32 url.dll:
        //   - Pure Win32 entry point — does not depend on a shell wrapper
        //     that might disable URL launches under ExecutionPolicy lockdown.
        //   - Honors the user's default-browser registry binding.
        //   - Available on every Windows since Win9x; lives in System32.
        //   - cmd `start` would briefly flash a console window; rundll32 does not.
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
        false
    }
}

// ── Headless flow (--non-interactive) ────────────────────────────────────

fn run_headless(
    file: Option<&Path>,
    _base_url: &str,
    _yes: bool,
    _provider: Option<&str>,
    as_json: bool,
) -> Result<(), String> {
    let path = file.ok_or_else(|| {
        "--non-interactive requires a FILE argument".to_string()
    })?;
    let _text = fs::read_to_string(path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;

    // Headless parse+confirm requires an authenticated session cookie plus a
    // pre-unlocked vault. That machinery is a v1.1 item per the
    // implementation plan; for v1.0 we print a clear "not implemented" and
    // exit with a stable code so scripts can detect it.
    let msg = "aikey import --non-interactive is reserved for v1.1 (requires \
               unattended vault unlock). For v1.0 please run `aikey import` \
               without --non-interactive and complete the flow in the browser.";
    if as_json {
        println!(
            r#"{{"status":"error","error_code":"I_NOT_IMPLEMENTED","error_message":"{}"}}"#,
            msg
        );
    } else {
        eprintln!("{}", msg);
    }
    Err(format!("{} headless import not implemented in v1.0", ERR_I_NOT_IMPLEMENTED))
}
