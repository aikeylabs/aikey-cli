//! Proxy lifecycle management commands: start, stop, status, restart, verify.
//!
//! `aikey proxy start` authenticates once with the vault master password,
//! then spawns `aikey-proxy` as a child process with the password injected
//! via `AIKEY_VAULT_PASSWORD` — no second prompt required.
//!
//! A lightweight `proxy_guard` is exported for use by other commands (e.g. `run`)
//! so the proxy is automatically started in the background when needed.

use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

// Fallback proxy listen address when the config cannot be parsed.
const PROXY_HEALTH_ADDR_DEFAULT: &str = "127.0.0.1:27200";
const PID_FILENAME: &str = "proxy.pid";
const DEFAULT_CONFIG_NAME: &str = "aikey-proxy.yaml";

/// Read the `listen.host:port` from the yaml config (best-effort, falls back to default).
fn proxy_listen_addr(config_path: Option<&std::path::Path>) -> String {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => match resolve_config(None) {
            Ok(p) => p,
            Err(_) => return PROXY_HEALTH_ADDR_DEFAULT.to_string(),
        },
    };
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return PROXY_HEALTH_ADDR_DEFAULT.to_string(),
    };
    // Minimal parse: look for `host:` and `port:` lines under `listen:`.
    let mut host = "127.0.0.1".to_string();
    let mut port = 27200u16;
    let mut in_listen = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "listen:" { in_listen = true; continue; }
        if in_listen {
            if trimmed.starts_with("host:") {
                host = trimmed.trim_start_matches("host:").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("port:") {
                if let Ok(p) = trimmed.trim_start_matches("port:").trim().parse::<u16>() {
                    port = p;
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(' ') {
                in_listen = false; // left the listen block
            }
        }
    }
    format!("{}:{}", host, port)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn handle_start(config: Option<&str>, detach: bool, password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Check if already running.
    if let Some(pid) = read_pid() {
        if process_alive(pid) {
            eprintln!("proxy already running (pid: {})", pid);
            eprintln!("listen: http://{}", PROXY_HEALTH_ADDR_DEFAULT);
            return Ok(());
        }
        // Stale PID file — remove it.
        let _ = fs::remove_file(pid_path()?);
    }

    // 2. Locate proxy binary.
    let proxy_bin = find_proxy_binary()?;

    // 3. Resolve config: cwd → ~/.aikey/
    let config_path = resolve_config(config)?;

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
        eprintln!("proxy started (pid: {})", pid);
        eprintln!("listen: http://{}", PROXY_HEALTH_ADDR_DEFAULT);
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
            eprintln!("proxy not running");
            return Ok(());
        }
    };

    if !process_alive(pid) {
        eprintln!("proxy not running (stale pid file cleaned up)");
        let _ = fs::remove_file(pid_path()?);
        return Ok(());
    }

    // Send SIGTERM on Unix, TerminateProcess on Windows.
    terminate_process(pid)?;
    let _ = fs::remove_file(pid_path()?);
    eprintln!("proxy stopped (pid: {})", pid);
    Ok(())
}

pub fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    match read_pid() {
        None => {
            println!("status:  stopped");
            println!("hint:    run `aikey proxy start` to start");
        }
        Some(pid) => {
            if !process_alive(pid) {
                println!("status:  stopped (stale pid file)");
                println!("hint:    run `aikey proxy start` to start");
                let _ = fs::remove_file(pid_path()?);
            } else {
                let healthy = port_reachable(PROXY_HEALTH_ADDR_DEFAULT, Duration::from_millis(500));
                let health_str = if healthy { "healthy" } else { "unreachable" };
                println!("status:  running ({})", health_str);
                println!("pid:     {}", pid);
                println!("listen:  http://{}", PROXY_HEALTH_ADDR_DEFAULT);
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
        &addr.parse().unwrap_or_else(|_| PROXY_HEALTH_ADDR_DEFAULT.parse().unwrap()),
        timeout,
    ).is_ok()
}

/// Locate the `aikey-proxy` binary using the following priority order:
/// 1. `AIKEY_PROXY_BIN` env var — explicit override for CI / custom installs
/// 2. Same directory as the running `aikey` binary — co-installed layout
/// 3. `~/.aikey/bin/aikey-proxy` — user-local install
/// 4. System `PATH` — standard install via `make install`
fn find_proxy_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let bin_name = if cfg!(windows) { "aikey-proxy.exe" } else { "aikey-proxy" };

    // 1. Explicit override via env var.
    if let Ok(val) = std::env::var("AIKEY_PROXY_BIN") {
        let p = PathBuf::from(val);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("AIKEY_PROXY_BIN is set but binary not found: {}", p.display()).into());
    }

    // 2. Same directory as the current `aikey` binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(bin_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // 3. ~/.aikey/bin/aikey-proxy
    if let Some(home) = dirs::home_dir() {
        let candidate = home.join(".aikey").join("bin").join(bin_name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 4. System PATH lookup.
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

    Err("aikey-proxy not found. Searched: same dir as aikey, ~/.aikey/bin/, system PATH. \
         Run `make install` in the aikey-proxy project, or set AIKEY_PROXY_BIN.".into())
}

/// Verify current project / env / provider connectivity end-to-end.
///
/// Checks in order:
/// 1. Vault is accessible (validated by caller before this function is called)
/// 2. Project config discovery
/// 3. Active logical environment
/// 4. Provider resolution from config
/// 5. Proxy health (auto-starts in background if not running)
pub fn handle_verify(password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    let mut failed = false;

    // Step 1: vault already validated by caller.
    println!("vault:    ok");

    // Step 2: project config.
    let config = crate::config::ProjectConfig::discover()
        .ok()
        .flatten()
        .map(|(_, cfg)| cfg);

    let project_name = config.as_ref()
        .map(|c| c.project.name.as_str())
        .unwrap_or("(no project config)");
    println!("project:  {}", project_name);

    // Step 3: current env.
    let current_env = crate::global_config::get_current_env()
        .ok()
        .flatten()
        .unwrap_or_else(|| "dev".to_string());
    println!("env:      {}", current_env);

    // Step 4: provider from config.
    let provider = config.as_ref().and_then(|cfg| {
        // Prefer envMappings for the active env, fall back to providers map.
        if let Some(env_map) = cfg.env_mappings.get(&current_env) {
            env_map.values().next().map(|m| m.provider.clone())
        } else {
            cfg.providers.keys().next().cloned()
        }
    });

    match &provider {
        Some(p) => println!("provider: {}", p),
        None => {
            println!("provider: (not configured)");
            println!("hint:     run `aikey project map` to configure a provider for this env");
        }
    }

    // Step 5: proxy health — auto-start if needed.
    let proxy_up = match read_pid() {
        Some(pid) if process_alive(pid) => {
            port_reachable(PROXY_HEALTH_ADDR_DEFAULT, Duration::from_millis(500))
        }
        _ => false,
    };

    if !proxy_up {
        eprintln!("proxy not running — attempting to start...");
        match handle_start(None, true, password) {
            Ok(_) => {
                std::thread::sleep(Duration::from_millis(800));
                if port_reachable(PROXY_HEALTH_ADDR_DEFAULT, Duration::from_millis(1000)) {
                    println!("proxy:    running (healthy)");
                } else {
                    println!("proxy:    unreachable after start attempt");
                    println!("hint:     run `aikey proxy status` to debug");
                    failed = true;
                }
            }
            Err(e) => {
                println!("proxy:    failed to start ({})", e);
                println!("hint:     run `aikey proxy start` to troubleshoot");
                failed = true;
            }
        }
    } else {
        println!("proxy:    running (healthy)");
    }

    println!();
    if failed {
        println!("result:   failed");
        return Err("verification failed — check hints above".into());
    }

    println!("result:   ok");
    Ok(())
}

/// Lightweight proxy guard for use by `aikey run` and other commands.
///
/// Checks whether `aikey-proxy` is running and reachable. If not, silently
/// starts it in the background using the given vault password. Returns `true`
/// if the proxy is (or becomes) reachable, `false` if startup failed.
///
/// Designed to be transparent to end users: no output on the happy path.
pub fn proxy_guard(password: &SecretString) -> bool {
    let health_addr = proxy_listen_addr(None);

    // Fast path: already running and healthy.
    if let Some(pid) = read_pid() {
        if process_alive(pid) && port_reachable(&health_addr, Duration::from_millis(300)) {
            return true;
        }
    }

    // Proxy not running — start silently in background.
    eprintln!("[aikey] proxy not running, starting in background...");
    match handle_start(None, true, password) {
        Ok(_) => {
            // Poll up to 5 s for the port to open (matches CI test timeout).
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let up = loop {
                if port_reachable(&health_addr, Duration::from_millis(300)) {
                    break true;
                }
                if std::time::Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(300));
            };
            if !up {
                eprintln!("[aikey] warning: proxy started but port {} unreachable", health_addr);
                eprintln!("[aikey] hint:    run `aikey proxy status` to debug");
            }
            up
        }
        Err(e) => {
            eprintln!("[aikey] warning: could not start proxy: {}", e);
            eprintln!("[aikey] hint:    run `aikey proxy start` to troubleshoot");
            false
        }
    }
}

/// Resolve the proxy config file path in priority order:
/// 1. Explicit `--config` argument
/// 2. `AIKEY_PROXY_CONFIG` environment variable
/// 3. Current working directory (`aikey-proxy.yaml`)
/// 4. `~/.aikey/config/aikey-proxy.yaml`
fn resolve_config(explicit: Option<&str>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()).into());
        }
        return Ok(path);
    }

    // AIKEY_PROXY_CONFIG env var.
    if let Ok(env_val) = std::env::var("AIKEY_PROXY_CONFIG") {
        let path = PathBuf::from(&env_val);
        if path.exists() {
            return Ok(path);
        }
        // Warn and fall back instead of failing hard, so the proxy can still start.
        let default_path = dirs::home_dir()
            .map(|h| h.join(".aikey").join("config").join(DEFAULT_CONFIG_NAME).display().to_string())
            .unwrap_or_else(|| format!("~/.aikey/config/{}", DEFAULT_CONFIG_NAME));
        eprintln!("Warning: AIKEY_PROXY_CONFIG not found: {}", path.display());
        eprintln!("         Falling back to default: {}", default_path);
    }

    // Current working directory.
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

    Err("aikey-proxy.yaml not found. Searched: current directory, ~/.aikey/config/. \
         Use --config to specify explicitly.".into())
}
