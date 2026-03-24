//! Proxy lifecycle management commands: start, stop, status, restart.
//!
//! `aikey proxy start` authenticates once with the vault master password,
//! then spawns `aikey-proxy` as a child process with the password injected
//! via `AIKEY_VAULT_PASSWORD` — no second prompt required.

use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

// Default proxy listen address for health checks.
const PROXY_HEALTH_ADDR: &str = "127.0.0.1:27200";
const PID_FILENAME: &str = "proxy.pid";
const DEFAULT_CONFIG_NAME: &str = "aikey-proxy.yaml";

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn handle_start(config: Option<&str>, detach: bool, password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Check if already running.
    if let Some(pid) = read_pid() {
        if process_alive(pid) {
            println!("proxy already running (pid: {})", pid);
            println!("listen: http://{}", PROXY_HEALTH_ADDR);
            return Ok(());
        }
        // Stale PID file — remove it.
        let _ = fs::remove_file(pid_path()?);
    }

    // 2. Locate proxy binary first so its directory is available for config lookup.
    let proxy_bin = find_proxy_binary()?;

    // 3. Resolve config: proxy bin dir → cwd → ~/.aikey/
    let proxy_dir = proxy_bin.parent().map(|p| p.to_path_buf());
    let config_path = resolve_config(config, proxy_dir.as_deref())?;

    eprintln!("Starting aikey-proxy...");
    eprintln!("  config: {}", config_path.display());
    eprintln!("  binary: {}", proxy_bin.display());

    // 4. Build the child command, injecting the password via env.
    let mut cmd = Command::new(&proxy_bin);
    cmd.arg("--config").arg(&config_path);
    cmd.env("AIKEY_VAULT_PASSWORD", password.expose_secret());

    if detach {
        // Background: stdout/stderr go to /dev/null; we just write the PID.
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn()
            .map_err(|e| format!("failed to spawn aikey-proxy: {}", e))?;
        let pid = child.id();
        write_pid(pid)?;
        println!("proxy started (pid: {})", pid);
        println!("listen: http://{}", PROXY_HEALTH_ADDR);
    } else {
        // Foreground: inherit stdio so logs are visible; write PID before waiting.
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        let mut child = cmd.spawn()
            .map_err(|e| format!("failed to spawn aikey-proxy: {}", e))?;
        write_pid(child.id())?;
        let status = child.wait()?;
        let _ = fs::remove_file(pid_path()?);
        if !status.success() {
            return Err(format!("aikey-proxy exited with status: {}", status).into());
        }
    }

    Ok(())
}

pub fn handle_stop() -> Result<(), Box<dyn std::error::Error>> {
    let pid = match read_pid() {
        Some(p) => p,
        None => {
            println!("proxy not running");
            return Ok(());
        }
    };

    if !process_alive(pid) {
        println!("proxy not running (stale pid file cleaned up)");
        let _ = fs::remove_file(pid_path()?);
        return Ok(());
    }

    // Send SIGTERM on Unix, TerminateProcess on Windows.
    terminate_process(pid)?;
    let _ = fs::remove_file(pid_path()?);
    println!("proxy stopped (pid: {})", pid);
    Ok(())
}

pub fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    match read_pid() {
        None => {
            println!("status:  stopped");
        }
        Some(pid) => {
            if !process_alive(pid) {
                println!("status:  stopped (stale pid file)");
                let _ = fs::remove_file(pid_path()?);
            } else {
                let healthy = port_reachable(PROXY_HEALTH_ADDR, Duration::from_millis(500));
                let health_str = if healthy { "healthy" } else { "unreachable" };
                println!("status:  running ({})", health_str);
                println!("pid:     {}", pid);
                println!("listen:  http://{}", PROXY_HEALTH_ADDR);
            }
        }
    }
    Ok(())
}

pub fn handle_restart(config: Option<&str>, password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    // Stop if running, then start again.
    handle_stop()?;
    // Small pause to let the port free up.
    std::thread::sleep(Duration::from_millis(300));
    handle_start(config, true, password)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `~/.aikey/run/proxy.pid`.
fn pid_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("cannot determine home directory")?;
    Ok(home.join(".aikey").join("run").join(PID_FILENAME))
}

fn read_pid() -> Option<u32> {
    let path = pid_path().ok()?;
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

fn write_pid(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let path = pid_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, pid.to_string())?;
    Ok(())
}

/// Check whether a process with the given PID is alive.
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) returns 0 if the process exists.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        ret == 0
    }
    #[cfg(windows)]
    {
        use std::ptr;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 || h == INVALID_HANDLE_VALUE as isize {
            return false;
        }
        unsafe { CloseHandle(h) };
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Send SIGTERM / TerminateProcess to the given PID.
fn terminate_process(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if ret != 0 {
            return Err(format!("kill({}) failed: {}", pid, io::Error::last_os_error()).into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows_sys::Win32::Foundation::CloseHandle;
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if h == 0 {
            return Err(format!("OpenProcess({}) failed", pid).into());
        }
        unsafe { TerminateProcess(h, 1); CloseHandle(h); }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(format!("terminate_process not supported on this platform (pid: {})", pid).into())
    }
}

/// Non-blocking TCP connect to check if the proxy port is reachable.
fn port_reachable(addr: &str, timeout: Duration) -> bool {
    TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| "127.0.0.1:27200".parse().unwrap()),
        timeout,
    ).is_ok()
}

/// Locate the `aikey-proxy` binary:
/// 1. `AIKEY_PROXY_BIN` env var — explicit override for CI / custom installs
/// 2. PATH — standard install via `make install` in the aikey-proxy project
fn find_proxy_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // 1. Explicit override.
    if let Ok(val) = std::env::var("AIKEY_PROXY_BIN") {
        let p = PathBuf::from(val);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("AIKEY_PROXY_BIN is set but binary not found: {}", p.display()).into());
    }

    // 2. PATH lookup.
    let bin_name = if cfg!(windows) { "aikey-proxy.exe" } else { "aikey-proxy" };
    let which_cmd = if cfg!(windows) { "where" } else { "which" };
    if let Ok(out) = Command::new(which_cmd).arg(bin_name).output() {
        if out.status.success() {
            let path_str = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !path_str.is_empty() {
                return Ok(PathBuf::from(path_str));
            }
        }
    }

    Err("aikey-proxy not found in PATH. Run `make install` in the aikey-proxy project, or set AIKEY_PROXY_BIN.".into())
}

/// Resolve the proxy config file path in priority order:
/// 1. Explicit `--config` argument
/// 2. Same directory as the `aikey-proxy` binary
/// 3. Current working directory
/// 4. `~/.aikey/aikey-proxy.yaml`
fn resolve_config(explicit: Option<&str>, proxy_dir: Option<&std::path::Path>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()).into());
        }
        return Ok(path);
    }

    // Same directory as the proxy binary (highest priority after explicit)
    if let Some(dir) = proxy_dir {
        let candidate = dir.join(DEFAULT_CONFIG_NAME);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // Current working directory
    let cwd_cfg = PathBuf::from(DEFAULT_CONFIG_NAME);
    if cwd_cfg.exists() {
        return Ok(cwd_cfg);
    }

    // ~/.aikey/config/aikey-proxy.yaml
    if let Some(home) = dirs::home_dir() {
        let home_cfg = home.join(".aikey").join("config").join(DEFAULT_CONFIG_NAME);
        if home_cfg.exists() {
            return Ok(home_cfg);
        }
    }

    Err(format!(
        "aikey-proxy.yaml not found. Searched: proxy bin dir, current directory, ~/.aikey/config/. Use --config to specify explicitly."
    ).into())
}
