//! Local-server probe — shared discovery, health, and status helpers.
//!
//! Why this module exists:
//!   Three commands need to know "is aikey-local-server running, on what
//!   port, with what vault state?" — `aikey status`, `aikey doctor`,
//!   `aikey web` (plus `aikey import` as the original consumer). Before
//!   this extraction the helpers lived in `commands_import.rs` and
//!   `doctor` hard-coded port 8090 with a silent-skip on failure. That
//!   drift caused two real bugs: (1) `aikey web` would open a browser
//!   pointing at a dead URL when the service was down, (2) `aikey doctor`
//!   missed a stopped local-server entirely on non-default ports.
//!
//! Port discovery — single source of truth:
//!   `~/.aikey/config/control-trial.yaml`'s `listen:` field is the same
//!   file local-server reads at startup, so any user edit propagates here.
//!   A localhost `controlPanelUrl` in `config.json` is accepted as a
//!   fallback for users who deleted the yaml. Remote URLs are never
//!   accepted as a local port source — that would silently retarget local
//!   probes at a remote team server, a different feature.
//!
//! Edition awareness:
//!   - Personal / Trial: yaml exists → port → probe works.
//!   - Production: no local-server on the user's host, yaml absent →
//!     edition-aware error pointing at the remote Control Panel URL.

use std::fs;
use std::path::{Path, PathBuf};

// Surfaced as part of error messages so scripts can grep for it.
pub const ERR_I_CLI_NOT_AVAILABLE: &str = "I_CLI_NOT_AVAILABLE";

const YAML_CONFIG_REL: &str = ".aikey/config/control-trial.yaml";
const JSON_CONFIG_REL: &str = ".aikey/config/config.json";

// ── Public API ──────────────────────────────────────────────────────────

/// Resolve local-server's listen port from the canonical config file,
/// falling back to a localhost `controlPanelUrl` in `config.json`.
/// Returns an edition-aware error if neither source yields a local port.
pub fn read_local_server_port() -> Result<u16, String> {
    // Stage 2.1 windows-compat: route through the single home-resolver so
    // sandbox tests (HOME-override) and Windows (USERPROFILE-only) take
    // the same code path the rest of the CLI uses.
    let home = crate::commands_account::resolve_user_home();

    if let Some(port) = read_yaml_listen_port(&home.join(YAML_CONFIG_REL))? {
        return Ok(port);
    }
    if let Some(port) = read_localhost_port_from_config_json(&home.join(JSON_CONFIG_REL)) {
        return Ok(port);
    }
    let remote_hint = read_remote_control_url(&home.join(JSON_CONFIG_REL));
    Err(build_not_installed_error(remote_hint))
}

/// HTTP probe of `<base>/health`. Returns Ok(()) on 2xx, Err with an
/// actionable platform-specific start hint otherwise.
pub fn probe_health(base: &str) -> Result<(), String> {
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

/// Probe `<base>/api/user/vault/status` and return whether the vault is
/// unlocked. Err on unreachable / non-2xx — callers that only want
/// reachability can treat any Ok as "running".
pub fn probe_vault_status(base: &str) -> Result<bool, String> {
    let url = format!("{}/api/user/vault/status", base);
    let body = ureq_get_with_timeout(&url, 1)?;
    Ok(body.contains(r#""unlocked":true"#))
}

/// Platform-specific command users can copy-paste to start local-server.
/// Wired to launchd / systemd where available; otherwise a direct
/// background invocation. Never returns an empty string — callers depend
/// on this being non-empty for the NOT-RUNNING hint to be useful.
pub fn start_command_hint() -> String {
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

/// Whether this edition is supposed to have a local-server running on
/// the user's host. Reads `~/.aikey/install-state.json`'s
/// `installed_components`. True for Personal (with console) and Trial;
/// false for Personal CLI-only and Production. Used by callers that
/// need to decide whether a missing local-server is "ok" (Production)
/// or "actionable warning" (Personal/Trial with service stopped).
pub fn is_local_server_installed() -> bool {
    let home = crate::commands_account::resolve_user_home();
    let path = home.join(".aikey/install-state.json");
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed.get("installed_components")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|c| {
            matches!(c.as_str(), Some("local-server") | Some("full-trial"))
        }))
        .unwrap_or(false)
}

/// Block until local-server's vault-status endpoint responds on `port`,
/// or `wait_for` elapses. Polls every 200 ms. Returns Ok on the first
/// successful response, Err with the elapsed time on timeout.
pub fn wait_for_reachable(port: u16, wait_for: std::time::Duration) -> Result<(), String> {
    let base = format!("http://127.0.0.1:{}", port);
    let deadline = std::time::Instant::now() + wait_for;
    while std::time::Instant::now() < deadline {
        if probe_vault_status(&base).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!(
        "local-server did not respond on port {} within {:?}",
        port, wait_for
    ))
}

/// Fire the platform-native start command for local-server (launchd /
/// systemd-user / direct spawn). Returns Ok if the command exited 0,
/// Err with diagnostic otherwise. Does NOT wait for the service to come
/// up — callers should follow with `wait_for_reachable`.
pub fn spawn_start_command() -> Result<(), String> {
    use std::process::Command;

    #[cfg(target_os = "macos")]
    {
        Command::new("launchctl")
            .args(["start", "com.aikey.local-server"])
            .status()
            .map_err(|e| format!("invoke launchctl: {}", e))
            .and_then(|s| if s.success() { Ok(()) } else {
                Err(format!("launchctl start exit {}", s.code().unwrap_or(-1)))
            })
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("systemctl")
            .args(["--user", "start", "aikey-local-server"])
            .status()
            .map_err(|e| format!("invoke systemctl: {}", e))
            .and_then(|s| if s.success() { Ok(()) } else {
                Err(format!("systemctl start exit {}", s.code().unwrap_or(-1)))
            })
    }
    #[cfg(target_os = "windows")]
    {
        // No native service manager wired up for Personal Windows installs
        // yet — spawn the binary directly in the background. Matches the
        // hint from `start_command_hint()` for this platform.
        let home = crate::commands_account::resolve_user_home();
        let bin = home.join(".aikey").join("bin").join("aikey-local-server.exe");
        let cfg = home.join(".aikey").join("config").join("control-trial.yaml");
        Command::new(&bin)
            .arg("--config").arg(&cfg)
            .spawn()
            .map_err(|e| format!("spawn aikey-local-server: {}", e))
            .map(|_| ())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("auto-start not supported on this platform".to_string())
    }
}

/// One-line summary used by `aikey status` — combines port discovery,
/// reachability, and vault state. Returns three distinct shapes:
///   - "local-server: running on port N (vault: locked|unlocked)"
///   - "local-server: NOT RUNNING on port N\n    Start:  <hint>"
///   - "local-server: NOT CONFIGURED — <discovery error>"
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

// ── Port discovery ──────────────────────────────────────────────────────

fn read_yaml_listen_port(path: &Path) -> Result<Option<u16>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    // Why serde_yaml over regex: the yaml has ~10 fields and users may
    // reformat / reorder freely; regex on "^listen:" is fragile to
    // indentation / multi-line shapes.
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| format!("parse {}: {}", path.display(), e))?;
    let listen = doc.get("listen").and_then(|v| v.as_str()).ok_or_else(|| {
        format!("{} has no `listen:` field", path.display())
    })?;
    // Shape: "127.0.0.1:8090" — split on last ':' so IPv6-style hosts
    // like "[::1]:8090" are tolerated.
    let port_str = listen.rsplit_once(':').map(|(_, p)| p).ok_or_else(|| {
        format!("listen `{}` is not host:port", listen)
    })?;
    let port: u16 = port_str.parse().map_err(|e| {
        format!("listen port `{}` is not a u16: {}", port_str, e)
    })?;
    Ok(Some(port))
}

fn read_localhost_port_from_config_json(path: &Path) -> Option<u16> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let url = parsed["controlPanelUrl"].as_str()?;
    localhost_port_of(url)
}

fn read_remote_control_url(path: &PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed["controlPanelUrl"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn localhost_port_of(url: &str) -> Option<u16> {
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

// ── Minimal blocking HTTP/1.0 client ────────────────────────────────────
//
// Why hand-rolled instead of reqwest/ureq: keeps the binary small (these
// probes are the only HTTP calls in this code path). Local-server is
// always on 127.0.0.1 — never use these helpers for arbitrary URLs.

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
    let status_ok = buf.starts_with("HTTP/1.0 2") || buf.starts_with("HTTP/1.1 2");
    if !status_ok {
        let status_line = buf.lines().next().unwrap_or("<empty>");
        return Err(format!("HTTP not OK: {}", status_line));
    }
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

// ── Tests ───────────────────────────────────────────────────────────────
//
// These mirror the safety-net suite that was authored against the old
// location in commands_import.rs. Keeping them here means future edits
// to this module are guarded at the place they need to be guarded.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // ── Pure helpers ─────────────────────────────────────────────────

    #[test]
    fn localhost_port_of_accepts_127() {
        assert_eq!(localhost_port_of("http://127.0.0.1:8090"), Some(8090));
        assert_eq!(localhost_port_of("http://127.0.0.1:8090/"), Some(8090));
        assert_eq!(localhost_port_of("http://127.0.0.1:8090/path"), Some(8090));
    }

    #[test]
    fn localhost_port_of_accepts_localhost_and_ipv6_loopback() {
        assert_eq!(localhost_port_of("http://localhost:9000"), Some(9000));
        assert_eq!(localhost_port_of("http://[::1]:9001"), Some(9001));
    }

    #[test]
    fn localhost_port_of_rejects_remote() {
        assert_eq!(localhost_port_of("https://control.example.com:443"), None);
        assert_eq!(localhost_port_of("http://10.0.0.1:8080"), None);
    }

    #[test]
    fn localhost_port_of_returns_none_without_port() {
        assert_eq!(localhost_port_of("http://127.0.0.1"), None);
        assert_eq!(localhost_port_of("http://localhost"), None);
    }

    #[test]
    fn parse_local_url_happy_path() {
        let (h, p, path) = parse_local_url("http://127.0.0.1:8090/health").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8090);
        assert_eq!(path, "/health");
    }

    #[test]
    fn parse_local_url_defaults_path_to_slash() {
        let (_, _, path) = parse_local_url("http://127.0.0.1:8090").unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_local_url_rejects_https() {
        assert!(parse_local_url("https://127.0.0.1:8090/").is_err());
    }

    #[test]
    fn parse_local_url_requires_port() {
        assert!(parse_local_url("http://127.0.0.1/health").is_err());
    }

    #[test]
    fn start_command_hint_is_nonempty_on_current_platform() {
        let hint = start_command_hint();
        assert!(!hint.trim().is_empty(), "start_command_hint must not be empty");
    }

    #[test]
    fn build_not_installed_error_with_remote_url_mentions_it() {
        let err = build_not_installed_error(Some("https://control.example.com".to_string()));
        assert!(err.contains("https://control.example.com"),
            "remote hint should be embedded verbatim in error: {}", err);
        assert!(err.contains(ERR_I_CLI_NOT_AVAILABLE));
    }

    #[test]
    fn build_not_installed_error_treats_localhost_remote_as_no_remote() {
        let err = build_not_installed_error(Some("http://127.0.0.1:9999".to_string()));
        assert!(!err.contains("team vault"),
            "localhost-as-remote must not trigger production messaging: {}", err);
        assert!(err.contains("aikey-local-server"));
    }

    #[test]
    fn build_not_installed_error_without_remote_suggests_install() {
        let err = build_not_installed_error(None);
        assert!(err.contains("local-install.sh") || err.contains("trial-install.sh"));
    }

    // ── YAML / JSON file fixtures ────────────────────────────────────

    #[test]
    fn read_yaml_listen_port_absent_returns_ok_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nope.yaml");
        assert!(matches!(read_yaml_listen_port(&p), Ok(None)));
    }

    #[test]
    fn read_yaml_listen_port_extracts_port_from_listen() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "listen: 127.0.0.1:8090\nother: x\n").unwrap();
        assert_eq!(read_yaml_listen_port(&p).unwrap(), Some(8090));
    }

    #[test]
    fn read_yaml_listen_port_tolerates_ipv6_listen() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "listen: \"[::1]:8090\"\n").unwrap();
        assert_eq!(read_yaml_listen_port(&p).unwrap(), Some(8090));
    }

    #[test]
    fn read_yaml_listen_port_errors_when_field_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "other: x\n").unwrap();
        let err = read_yaml_listen_port(&p).unwrap_err();
        assert!(err.contains("listen"));
    }

    #[test]
    fn read_yaml_listen_port_errors_when_listen_shape_bad() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.yaml");
        std::fs::write(&p, "listen: not-a-port\n").unwrap();
        let err = read_yaml_listen_port(&p).unwrap_err();
        assert!(err.contains("host:port") || err.contains("u16"));
    }

    #[test]
    fn read_localhost_port_from_config_json_extracts_localhost() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("config.json");
        std::fs::write(&p, r#"{"controlPanelUrl":"http://127.0.0.1:8090"}"#).unwrap();
        assert_eq!(read_localhost_port_from_config_json(&p), Some(8090));
    }

    #[test]
    fn read_localhost_port_from_config_json_rejects_remote_url() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("config.json");
        std::fs::write(&p, r#"{"controlPanelUrl":"https://control.example.com"}"#).unwrap();
        assert_eq!(read_localhost_port_from_config_json(&p), None);
    }

    #[test]
    fn read_localhost_port_from_config_json_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            read_localhost_port_from_config_json(&tmp.path().join("nope.json")),
            None
        );
    }

    // ── Mock-server-backed tests ─────────────────────────────────────

    fn spawn_oneshot(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        port
    }

    fn pick_unused_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[test]
    fn probe_vault_status_detects_unlocked() {
        let port = spawn_oneshot(r#"{"unlocked":true}"#);
        let base = format!("http://127.0.0.1:{}", port);
        assert_eq!(probe_vault_status(&base), Ok(true));
    }

    #[test]
    fn probe_vault_status_detects_locked() {
        let port = spawn_oneshot(r#"{"unlocked":false}"#);
        let base = format!("http://127.0.0.1:{}", port);
        assert_eq!(probe_vault_status(&base), Ok(false));
    }

    #[test]
    fn probe_vault_status_errors_when_unreachable() {
        let port = pick_unused_port();
        let base = format!("http://127.0.0.1:{}", port);
        assert!(probe_vault_status(&base).is_err());
    }

    // ── Integration: local_server_status_line with HOME override ─────

    fn write_yaml_under(home: &std::path::Path, port: u16) {
        let cfg = home.join(".aikey/config");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("control-trial.yaml"),
            format!("listen: 127.0.0.1:{}\n", port)).unwrap();
    }

    #[test]
    fn status_line_running_unlocked() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let port = spawn_oneshot(r#"{"unlocked":true}"#);
        let tmp = tempfile::tempdir().unwrap();
        write_yaml_under(tmp.path(), port);
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home { std::env::set_var("HOME", h); }
        else { std::env::remove_var("HOME"); }

        assert!(line.contains(&format!("port {}", port)), "got: {}", line);
        assert!(line.contains("running"), "got: {}", line);
        assert!(line.contains("unlocked"), "got: {}", line);
    }

    #[test]
    fn status_line_running_locked() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let port = spawn_oneshot(r#"{"unlocked":false}"#);
        let tmp = tempfile::tempdir().unwrap();
        write_yaml_under(tmp.path(), port);
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home { std::env::set_var("HOME", h); }
        else { std::env::remove_var("HOME"); }

        assert!(line.contains("running"), "got: {}", line);
        assert!(line.contains("locked") && !line.contains("unlocked"), "got: {}", line);
    }

    #[test]
    fn status_line_not_running_includes_start_hint() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let port = pick_unused_port();
        let tmp = tempfile::tempdir().unwrap();
        write_yaml_under(tmp.path(), port);
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home { std::env::set_var("HOME", h); }
        else { std::env::remove_var("HOME"); }

        assert!(line.contains("NOT RUNNING"), "got: {}", line);
        assert!(line.contains("Start:"), "got: {}", line);
    }

    // ── wait_for_reachable ───────────────────────────────────────────

    #[test]
    fn wait_for_reachable_returns_ok_when_server_responds() {
        let port = spawn_oneshot(r#"{"unlocked":true}"#);
        let r = wait_for_reachable(port, std::time::Duration::from_secs(2));
        assert!(r.is_ok(), "expected Ok, got {:?}", r);
    }

    #[test]
    fn wait_for_reachable_times_out_when_no_server() {
        let port = pick_unused_port();
        // Short timeout so the test stays fast — covers the deadline path.
        let r = wait_for_reachable(port, std::time::Duration::from_millis(300));
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("did not respond"), "got: {}", msg);
        assert!(msg.contains(&port.to_string()), "got: {}", msg);
    }

    // ── is_local_server_installed ────────────────────────────────────

    fn write_install_state(home: &std::path::Path, body: &str) {
        let d = home.join(".aikey");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("install-state.json"), body).unwrap();
    }

    fn with_home<F: FnOnce()>(home: &std::path::Path, f: F) {
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", home);
        f();
        if let Some(h) = prev { std::env::set_var("HOME", h); }
        else { std::env::remove_var("HOME"); }
    }

    #[test]
    fn is_local_server_installed_true_for_personal_with_console() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(),
            r#"{"installed_components":["aikey-cli","local-server"]}"#);
        with_home(tmp.path(), || {
            assert!(is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_true_for_trial() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(),
            r#"{"installed_components":["full-trial"]}"#);
        with_home(tmp.path(), || {
            assert!(is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_false_for_cli_only() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(),
            r#"{"installed_components":["aikey-cli"]}"#);
        with_home(tmp.path(), || {
            assert!(!is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_false_when_state_missing() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_home(tmp.path(), || {
            assert!(!is_local_server_installed());
        });
    }

    #[test]
    fn is_local_server_installed_false_when_state_malformed() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        write_install_state(tmp.path(), "not-json");
        with_home(tmp.path(), || {
            assert!(!is_local_server_installed());
        });
    }

    #[test]
    fn status_line_not_configured_when_no_yaml_no_config_json() {
        let _g = crate::test_env_lock::ENV_MUTATION_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        let line = local_server_status_line();

        if let Some(h) = prev_home { std::env::set_var("HOME", h); }
        else { std::env::remove_var("HOME"); }

        assert!(line.contains("NOT CONFIGURED"), "got: {}", line);
    }
}
