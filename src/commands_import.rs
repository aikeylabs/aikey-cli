//! `aikey import` — Stage 6 Mode A implementation.
//!
//! The CLI intentionally delegates every vault-touching operation to the
//! Web UI served by local-server. The local-server lifecycle is managed by
//! launchd (macOS) / systemd (Linux), NOT by this CLI — see
//! roadmap20260320/技术实现/update/20260422-批量导入-aikey-serve-命令移除.md
//! for why `aikey serve` / `aikey stop` were removed.
//!
//! Port discovery — single source of truth:
//!   The port is read from `~/.aikey/config/control-trial.yaml`'s `listen:`
//!   field — the same file local-server itself reads at startup. Keeping
//!   one source (the yaml) instead of a derived `local-server.port` file
//!   eliminates a class of "installer and binary disagree on port" bugs
//!   and lets the CLI work correctly when the user edits the yaml to
//!   change ports.
//!
//! Edition alignment:
//!   - Personal / Team Trial: yaml exists → port extracted → works.
//!   - Team Production: no local-server is installed on the user's host
//!     (Control Panel is remote Docker), yaml absent → `aikey import`
//!     fails with an edition-aware hint pointing at the remote URL
//!     from `config.json`'s `controlPanelUrl`. This matches the CLAUDE.md
//!     "版型意识" rule: don't fabricate a local component in editions
//!     that don't ship it.
//!
//! Localhost fallback:
//!   If the yaml is missing but `controlPanelUrl` in `config.json` is a
//!   127.0.0.1 / localhost URL, we extract the port from it. Covers the
//!   case where the user deleted the yaml by accident. Remote
//!   `controlPanelUrl` values are NOT accepted — opening the remote
//!   Bulk Import page would operate on the team vault, not the local
//!   vault, and that's a different feature with different semantics.
//!
//! Flow:
//!   1. Resolve port (yaml → localhost-controlPanelUrl → edition-aware error).
//!   2. If a FILE argument is given, POST its contents to
//!      `/api/user/import/parse` so the Web UI shows "parsed from X" on open.
//!   3. Open the browser to `http://127.0.0.1:<port>/user/import`.
//!   4. If the browser fails to launch (headless / CI), print the URL.
//!
//! `--non-interactive` skips the browser and runs the full
//! parse → confirm flow over HTTP; used for scripts / CI testing.

use std::fs;
use std::path::{Path, PathBuf};

// CLI-level error codes for the import command. These are user-facing error
// strings, distinct from the `I_*` IPC codes in error_codes::ErrorCode which
// are internal-protocol. See `docs/VAULT_SPEC.md` for the canonical list.
const ERR_I_CLI_NOT_AVAILABLE: &str = "I_CLI_NOT_AVAILABLE";
const ERR_I_NOT_IMPLEMENTED: &str = "I_NOT_IMPLEMENTED";

const YAML_CONFIG_REL: &str = ".aikey/config/control-trial.yaml";
const JSON_CONFIG_REL: &str = ".aikey/config/config.json";

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

/// `aikey status` extension — local-server section.
/// Returns a one-line summary the main status handler appends to its block.
pub fn local_server_status_line() -> String {
    match read_local_server_port() {
        Err(e) => format!("local-server: NOT CONFIGURED — {}", e),
        Ok(port) => {
            let base = format!("http://127.0.0.1:{}", port);
            match probe_vault_status(&base) {
                Ok(unlocked) => format!(
                    "local-server: running on port {} (vault: {})",
                    port,
                    if unlocked { "unlocked" } else { "locked" }
                ),
                Err(_) => {
                    let hint = start_command_hint();
                    format!(
                        "local-server: NOT RUNNING on port {}\n    Start:  {}",
                        port, hint
                    )
                }
            }
        }
    }
}

// ── Port discovery ───────────────────────────────────────────────────────
//
// Source priority:
//   1. `~/.aikey/config/control-trial.yaml` → `listen: host:port`
//        The authoritative source — this is what local-server itself reads
//        at startup, so any edit here is guaranteed consistent with the
//        running process.
//   2. `~/.aikey/config/config.json` → `controlPanelUrl`
//        Only accepted when the URL's host is 127.0.0.1 / localhost.
//        Covers the "user accidentally deleted the yaml" edge case on
//        Personal/Trial installs. Remote values (Team Production) are
//        rejected: the remote Control Panel's Bulk Import operates on the
//        team vault, not the user's local vault — different feature.
//   3. Edition-aware error
//        Tells the user what happened and suggests the correct next step
//        for their edition (install script for Personal/Trial; "use the
//        remote Control Panel at <url>" for Production).

fn read_local_server_port() -> Result<u16, String> {
    // Stage 2.1 windows-compat: route through the single home-resolver so
    // sandbox tests (HOME-override) and Windows (USERPROFILE-only) take
    // the same code path the rest of the CLI uses. The previous direct
    // `dirs::home_dir()` skipped HOME entirely on Linux/macOS and skipped
    // USERPROFILE on Windows when the user had explicitly redirected.
    let home = crate::commands_account::resolve_user_home();

    // 1. Authoritative: yaml's listen line.
    if let Some(port) = read_yaml_listen_port(&home.join(YAML_CONFIG_REL))? {
        return Ok(port);
    }

    // 2. Fallback: config.json controlPanelUrl, only if localhost.
    if let Some(port) = read_localhost_port_from_config_json(&home.join(JSON_CONFIG_REL)) {
        return Ok(port);
    }

    // 3. Edition-aware error. If controlPanelUrl exists but is remote,
    //    point the user at it — they're on Production and this command
    //    doesn't apply, but the remote page does offer team-scope import.
    let remote_hint = read_remote_control_url(&home.join(JSON_CONFIG_REL));
    Err(build_not_installed_error(remote_hint))
}

/// Parse the yaml's top-level `listen:` field and return its port.
/// Returns `Ok(None)` when the yaml is absent (caller falls through);
/// returns `Err` only for parse / format issues that need operator attention.
fn read_yaml_listen_port(path: &Path) -> Result<Option<u16>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    // Why serde_yaml over regex: the yaml has ~10 fields and users may
    // reformat / reorder freely; a dedicated parser handles that while
    // a regex on "^listen:" is fragile to indentation / multi-line shapes.
    // Dep is already in Cargo.toml for Stage 3 parse.
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let listen = doc.get("listen").and_then(|v| v.as_str()).ok_or_else(|| {
        format!("{} has no `listen:` field", path.display())
    })?;
    // Shape: "127.0.0.1:8090" — split on last ':' so IPv6-style hosts
    // like "[::1]:8090" are also tolerated.
    let port_str = listen.rsplit_once(':').map(|(_, p)| p).ok_or_else(|| {
        format!("listen `{}` is not host:port", listen)
    })?;
    let port: u16 = port_str.parse().map_err(|e| {
        format!("listen port `{}` is not a u16: {}", port_str, e)
    })?;
    Ok(Some(port))
}

/// Extract port from `controlPanelUrl` if and only if its host is localhost.
/// Silently returns None for remote URLs — they don't apply to local Bulk Import.
fn read_localhost_port_from_config_json(path: &Path) -> Option<u16> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let url = parsed["controlPanelUrl"].as_str()?;
    localhost_port_of(url)
}

/// Return `controlPanelUrl` verbatim regardless of host — used only to
/// produce the edition-aware error when we're about to fail. Remote URLs
/// are NOT used as a port source (see `read_localhost_port_from_config_json`).
fn read_remote_control_url(path: &PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed["controlPanelUrl"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// If `url` is of the form `http://127.0.0.1:<port>` or `http://localhost:<port>`,
/// return `<port>`. Otherwise None.
fn localhost_port_of(url: &str) -> Option<u16> {
    // Strip scheme so we can split authority cleanly.
    let after_scheme = url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let (host, port_str) = authority.rsplit_once(':')?;
    let is_localhost = host == "127.0.0.1" || host == "localhost" || host == "[::1]";
    if !is_localhost {
        return None;
    }
    port_str.parse::<u16>().ok()
}

fn build_not_installed_error(remote_hint: Option<String>) -> String {
    match remote_hint {
        Some(url) if !url.starts_with("http://127.0.0.1")
                    && !url.starts_with("http://localhost") => {
            // Production: no local-server, remote Control Panel available.
            format!(
                "{} Local Bulk Import is not available on this host \
                 (Personal/Trial editions only).\n\
                 For team-scope import, use the Control Panel:\n    {}\n\
                 Note: the remote page operates on the team vault, not your \
                 local CLI vault.",
                ERR_I_CLI_NOT_AVAILABLE, url
            )
        }
        _ => format!(
            "{} Local Bulk Import requires aikey-local-server, which is not \
             installed on this host.\n\
             Install (Personal): curl -fsSL .../local-install.sh | sh\n\
             Install (Trial):    curl -fsSL .../trial-install.sh | sh",
            ERR_I_CLI_NOT_AVAILABLE
        ),
    }
}

// ── Health probes (minimal, no async runtime) ────────────────────────────

fn probe_health(base: &str) -> Result<(), String> {
    // 1s timeout. On failure, give the user actionable platform advice.
    let url = format!("{}/health", base);
    match ureq_get_with_timeout(&url, 1) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "{} local-server not reachable at {} ({}). Start it with:\n    {}",
            ERR_I_CLI_NOT_AVAILABLE,
            base,
            e,
            start_command_hint()
        )),
    }
}

fn probe_vault_status(base: &str) -> Result<bool, String> {
    let url = format!("{}/api/user/vault/status", base);
    let body = ureq_get_with_timeout(&url, 1)?;
    Ok(body.contains(r#""unlocked":true"#))
}

/// Minimal blocking HTTP GET — avoids pulling reqwest/ureq just for this.
/// Uses std::net::TcpStream + hand-rolled HTTP/1.0 request so the CLI keeps
/// its small binary size. Local-server is always on 127.0.0.1, so this is
/// safe; never use this for arbitrary URLs.
fn ureq_get_with_timeout(url: &str, timeout_secs: u64) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let (host, port, path) = parse_local_url(url)?;
    if host != "127.0.0.1" && host != "localhost" {
        return Err(format!("refusing non-local URL: {}", url));
    }
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("bad addr: {}", e))?,
        Duration::from_secs(timeout_secs),
    )
    .map_err(|e| format!("connect: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(|e| e.to_string())?;
    // Check status line
    let status_ok = buf.starts_with("HTTP/1.0 2") || buf.starts_with("HTTP/1.1 2");
    if !status_ok {
        let status_line = buf.lines().next().unwrap_or("<empty>");
        return Err(format!("HTTP not OK: {}", status_line));
    }
    // Body after blank line
    let body = buf.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok(body)
}

fn parse_local_url(url: &str) -> Result<(String, u16, String), String> {
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// supported: {}", url))?;
    let (host_port, path) = without_scheme
        .split_once('/')
        .map(|(h, p)| (h, format!("/{}", p)))
        .unwrap_or((without_scheme, "/".to_string()));
    let (host, port) = host_port.split_once(':')
        .ok_or_else(|| format!("URL missing port: {}", url))?;
    let port: u16 = port.parse().map_err(|e| format!("bad port: {}", e))?;
    Ok((host.to_string(), port, path))
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
    // Use the `open` crate if available, else shell out per-platform.
    // Guarded by cfg to keep dependencies minimal.
    let opened = try_open_browser(url);
    if opened {
        if as_json {
            println!(r#"{{"status":"ok","url":"{}","browser":"opened"}}"#, url);
        } else {
            println!("Opened {} in your browser.", url);
        }
    } else {
        // Headless / CI / no browser registered — print URL so the user can
        // paste it manually.
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
        //   - It's a pure Win32 entry point — does not depend on any
        //     shell wrapper that might disable URL launches under
        //     ExecutionPolicy / Group Policy lockdown.
        //   - Honors the user's default-browser registry binding
        //     (HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\...)
        //     same as a click-from-Explorer would.
        //   - Available on every Windows since the Win9x era; no PATH
        //     surprises (it lives in System32, which is always on PATH).
        //   - cmd `start` would briefly flash a console window; rundll32
        //     does not.
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

fn start_command_hint() -> String {
    #[cfg(target_os = "macos")]
    {
        "launchctl start com.aikey.local-server".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "systemctl --user start aikey-local-server".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "~/.aikey/bin/aikey-local-server --config ~/.aikey/config/control-trial.yaml &"
            .to_string()
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
