//! Proxy lifecycle management commands: start, stop, status, restart, verify.
//!
//! `aikey proxy start` authenticates once with the vault master password,
//! then spawns `aikey-proxy` as a child process with the password injected
//! via `AIKEY_MASTER_PASSWORD` — no second prompt required.
//!
//! A lightweight `proxy_guard` is exported for use by other commands (e.g. `run`)
//! so the proxy is automatically started in the background when needed.

use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

// Fallback proxy listen address when the config cannot be parsed.
const PROXY_HEALTH_ADDR_DEFAULT: &str = "127.0.0.1:27200";
const PID_FILENAME: &str = "proxy.pid";
const DEFAULT_CONFIG_NAME: &str = "aikey-proxy.yaml";

// ---------------------------------------------------------------------------
// Vault change-sequence state helpers
// ---------------------------------------------------------------------------

/// Whether the running proxy's vault snapshot is up-to-date.
#[derive(Debug, PartialEq)]
pub enum ProxyVaultState {
    /// Proxy has loaded the latest vault snapshot.
    Current,
    /// Vault has been written since the proxy last loaded it.
    Stale,
    /// Sequence numbers are unavailable (vault not initialised, proxy never
    /// recorded its loaded seq, etc.).
    Unknown,
}

/// Returns the vault snapshot state of the currently running proxy.
/// Does NOT check whether the proxy process is alive; call `is_proxy_running`
/// before this if you only want to inspect a live proxy.
pub fn proxy_vault_state() -> ProxyVaultState {
    let vault_seq = match crate::storage::get_vault_change_seq() {
        Ok(s) => s,
        Err(_) => return ProxyVaultState::Unknown,
    };
    let proxy_seq = match crate::storage::get_proxy_loaded_seq() {
        Ok(s) => s,
        Err(_) => return ProxyVaultState::Unknown,
    };
    if vault_seq > proxy_seq {
        ProxyVaultState::Stale
    } else {
        ProxyVaultState::Current
    }
}

/// Returns true if the proxy process is running.
pub fn is_proxy_running() -> bool {
    read_pid().map_or(false, |pid| process_alive(pid))
}

/// Sends `POST /admin/reload` to the proxy if it is currently running.
///
/// Called by `aikey use` after updating the active key config so the proxy
/// picks up the new route without a full restart.  Errors are suppressed —
/// the proxy remains reachable even if the reload HTTP call fails.
pub fn try_reload_proxy() {
    if is_proxy_running() {
        if let Err(e) = post_admin_reload() {
            let msg = e.to_string();
            // Why: after `aikey change-password`, the proxy process still has
            // the old AIKEY_MASTER_PASSWORD in its env; reload then fails with
            // "invalid master password" from aikey-proxy/vault.go and users
            // have no actionable hint. Detect that specific path and tell them
            // to restart the proxy so the new password is picked up.
            if msg.contains("invalid master password") {
                eprintln!("[aikey] proxy reload failed: vault password mismatch.");
                eprintln!("        The proxy is still holding the old AIKEY_MASTER_PASSWORD.");
                eprintln!("        Run `aikey proxy restart` to pick up the new password.");
            } else {
                eprintln!("[aikey] proxy reload hint failed (non-fatal): {}", msg);
            }
        }
    }
}

/// Silently start the proxy in the background using the given password.
///
/// Unlike `proxy_guard`, this function produces no output on the happy path —
/// it is intended for fully transparent auto-start triggered by other commands.
/// Returns `true` if the proxy is up after the call, `false` otherwise.
fn silently_start_proxy(password: &SecretString) -> bool {
    // Already running — nothing to do.
    if is_proxy_running() {
        return true;
    }

    let proxy_bin = match find_proxy_binary() {
        Ok(b) => b,
        Err(_) => return false, // binary not installed — skip silently
    };
    let config_path = match resolve_config(None) {
        Ok(p) => p,
        Err(_) => return false, // no config — skip silently
    };

    let mut cmd = std::process::Command::new(&proxy_bin);
    cmd.arg("--config").arg(&config_path);
    // Load proxy.env entries — warn on parse failure but don't block auto-start.
    match crate::proxy_env::read_proxy_env() {
        Ok(env_map) => {
            for (k, v) in &env_map {
                cmd.env(k, v);
            }
        }
        Err(e) => {
            eprintln!("[aikey] warning: failed to parse ~/.aikey/proxy.env: {}", e);
            eprintln!("[aikey] proxy will start without proxy.env settings");
        }
    }
    cmd.env("AIKEY_MASTER_PASSWORD", password.expose_secret());
    cmd.stdout(std::process::Stdio::null())
       .stderr(std::process::Stdio::null());

    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            let _ = write_pid(pid);
            if let Ok(seq) = crate::storage::get_vault_change_seq() {
                let _ = crate::storage::set_proxy_loaded_seq(seq);
            }
            // Poll up to 4 s for proxy to become reachable.
            let health_addr = proxy_listen_addr(None);
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                if port_reachable(&health_addr, Duration::from_millis(300)) {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        }
        Err(_) => false,
    }
}

/// Try to auto-start the proxy silently using `AIKEY_MASTER_PASSWORD` or
/// `AK_TEST_PASSWORD` environment variables.
///
/// Called at the top of every command dispatch so that the proxy is running
/// whenever a master password is pre-injected (e.g. CI / scripted sessions).
/// No-ops completely when neither env var is set — no prompt, no output.
pub fn try_auto_start_from_env() {
    if is_proxy_running() {
        return;
    }
    let pw = std::env::var("AIKEY_MASTER_PASSWORD")
        .or_else(|_| std::env::var("AK_TEST_PASSWORD"));
    if let Ok(pw_val) = pw {
        let _ = silently_start_proxy(&SecretString::new(pw_val));
    }
}

/// Ensure the proxy is running, prompting for the master password when needed.
///
/// Called by `aikey use` / `aikey key use` so that the proxy is always started
/// after activating a key.  Priority:
///   1. Already running → no-op
///   2. `AIKEY_MASTER_PASSWORD` / `AK_TEST_PASSWORD` env var → silent start
///   3. Interactive TTY → prompt once for master password, then start
///   4. Non-TTY without env var → print a hint but don't block
pub fn ensure_proxy_for_use(password_stdin: bool) {
    if is_proxy_running() {
        return;
    }

    // 1. Try env var (fully silent).
    {
        let pw = std::env::var("AIKEY_MASTER_PASSWORD")
            .or_else(|_| std::env::var("AK_TEST_PASSWORD"));
        if let Ok(pw_val) = pw {
            let started = silently_start_proxy(&SecretString::new(pw_val));
            if started {
                eprintln!("[aikey] proxy started in background");
            }
            return;
        }
    }

    // 2. Interactive: prompt once.
    use std::io::IsTerminal;
    if io::stderr().is_terminal() || password_stdin {
        eprintln!();
        eprintln!("  Proxy not running — starting it now.");
        let pw = if password_stdin {
            eprint!("  \u{1F512} Enter Master Password: ");
            let _ = io::stderr().flush();
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            eprintln!("***");
            SecretString::new(line.trim().to_string())
        } else {
            match crate::prompt_hidden("  \u{1F512} Enter Master Password: ") {
                Ok(p) => SecretString::new(p),
                Err(_) => {
                    eprintln!("  [aikey] Could not read password — run `aikey proxy start` manually.");
                    return;
                }
            }
        };
        let started = silently_start_proxy(&pw);
        if started {
            eprintln!("  [aikey] proxy started in background");
        } else {
            // Why: show actionable reason instead of a generic "failed" message.
            let bin_ok = find_proxy_binary().is_ok();
            let cfg_ok = resolve_config(None).is_ok();
            if !bin_ok {
                eprintln!("  [aikey] proxy binary not found — reinstall with: aikey proxy install");
            } else if !cfg_ok {
                eprintln!("  [aikey] proxy config not found — run: aikey proxy start");
            } else {
                eprintln!("  [aikey] proxy failed to start — check port conflict or run: aikey proxy start --foreground");
            }
        }
    } else {
        // Non-interactive, no env var — print a one-line hint.
        eprintln!("[aikey] proxy not running — run `aikey proxy start` to enable routing");
    }
}

/// Auto-restarts the proxy if it is running and its vault snapshot is stale.
/// Restart is needed (not just reload) because personal keys require a fresh
/// vault open with the master password to decrypt entries.
/// Call this after any vault-write operation (add, delete, update, etc.).
pub fn maybe_warn_stale() {
    if is_proxy_running() && proxy_vault_state() == ProxyVaultState::Stale {
        if let Some(pw) = crate::session::try_get() {
            match handle_restart(None, &pw) {
                Ok(_) => eprintln!("  Proxy restarted with new keys."),
                Err(_) => eprintln!("  Run 'aikey proxy restart' to apply new keys."),
            }
        } else {
            eprintln!("  Run 'aikey proxy restart' to apply new keys.");
        }
    }
}

/// Sends `POST /admin/reload` to the running proxy and waits for the response.
/// Injects the current trace context via the W3C `traceparent` header so the
/// reload operation can be correlated with CLI log records by trace_id.
/// Returns Ok(()) when the proxy confirms a successful graceful reload.
pub fn post_admin_reload() -> Result<(), Box<dyn std::error::Error>> {
    // Why: use configured listen address instead of hardcoded default, so reload
    // works when the user/deployment overrides the proxy port in config YAML.
    let addr = proxy_listen_addr(None);
    let stream = TcpStream::connect(&addr)
        .map_err(|e| format!("cannot connect to proxy at {}: {}", addr, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Inject traceparent so the proxy's reload logs share the same trace_id.
    let traceparent_header = crate::observability::trace()
        .map(|tc| format!("traceparent: {}\r\n", tc.traceparent))
        .unwrap_or_default();

    let request = format!(
        "POST /admin/reload HTTP/1.0\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n{}\r\n",
        addr, traceparent_header
    );
    {
        let mut w = stream.try_clone()?;
        w.write_all(request.as_bytes())?;
    }

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    // Read and check the HTTP status line.
    let status_line = lines
        .next()
        .ok_or("proxy closed connection without response")??;
    if !status_line.contains("200") {
        // Drain the rest of the body for the error message.
        let mut body = String::new();
        let mut in_body = false;
        for line in lines.flatten() {
            if in_body { body.push_str(&line); body.push('\n'); }
            else if line.is_empty() { in_body = true; }
        }
        return Err(format!("proxy reload failed: {} — {}", status_line.trim(), body.trim()).into());
    }
    Ok(())
}

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

    // 4. Build the child command, injecting proxy.env + password via env.
    let mut cmd = Command::new(&proxy_bin);
    cmd.arg("--config").arg(&config_path);

    // Load proxy.env entries into child process environment.
    // Order: parent env (inherited) → proxy.env → CLI internal vars.
    match crate::proxy_env::read_proxy_env() {
        Ok(env_map) if !env_map.is_empty() => {
            let keys: Vec<&str> = env_map.keys().map(|k| k.as_str()).collect();
            eprintln!("  proxy.env: {} entries [{}]", env_map.len(), keys.join(", "));
            for (k, v) in &env_map {
                cmd.env(k, v);
            }
        }
        Ok(_) => {} // empty or no file — fine
        Err(e) => {
            return Err(format!(
                "Failed to parse ~/.aikey/proxy.env: {}\n\
                 Fix the file or remove it, then retry.",
                e
            ).into());
        }
    }

    // AIKEY_MASTER_PASSWORD always set last (cannot be overridden by proxy.env).
    cmd.env("AIKEY_MASTER_PASSWORD", password.expose_secret());

    if detach {
        // Background: stdout/stderr go to log file; terminal is not blocked.
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn()
            .map_err(|e| format!("failed to spawn aikey-proxy: {}", e))?;
        let pid = child.id();
        write_pid(pid)?;

        // Wait for proxy to become healthy before returning (max 3s).
        let addr = proxy_listen_addr(config.map(std::path::Path::new));
        let mut healthy = false;
        for _ in 0..6 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if port_reachable(&addr, std::time::Duration::from_millis(300)) {
                healthy = true;
                break;
            }
        }
        if healthy {
            eprintln!("\x1b[32m✓\x1b[0m aikey-proxy running (pid: {}, http://{})", pid, addr);
        } else {
            eprintln!("aikey-proxy spawned (pid: {}) but not yet reachable at http://{}", pid, addr);
            eprintln!("  check logs: ~/.aikey/logs/");
        }

        // Quick connectivity check for overseas providers after proxy starts.
        // Only warn when a provider is unreachable — no noise when all is fine.
        std::thread::spawn(|| {
            check_overseas_connectivity();
        });

        // Record the vault snapshot that this proxy generation was started with.
        if let Ok(seq) = crate::storage::get_vault_change_seq() {
            let _ = crate::storage::set_proxy_loaded_seq(seq);
        }
    } else {
        // Foreground: inherit stdio so logs are visible; write PID before waiting.
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        let mut child = cmd.spawn()
            .map_err(|e| format!("failed to spawn aikey-proxy: {}", e))?;
        let pid = child.id();
        write_pid(pid)?;

        // Record vault snapshot seq for the foreground process too.
        if let Ok(seq) = crate::storage::get_vault_change_seq() {
            let _ = crate::storage::set_proxy_loaded_seq(seq);
        }

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
    for line in status_rows() {
        println!("{}", line);
    }
    Ok(())
}

/// Returns the Gateway status as a list of display rows (no box frame).
/// Used by both `aikey proxy status` (plain) and `aikey status` (boxed overview).
pub fn status_rows() -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    match read_pid() {
        None => {
            rows.push("status:  stopped".to_string());
            rows.push("hint:    run `aikey proxy start` to start".to_string());
        }
        Some(pid) => {
            if !process_alive(pid) {
                rows.push("status:  stopped (stale pid file)".to_string());
                rows.push("hint:    run `aikey proxy start` to start".to_string());
                if let Ok(p) = pid_path() { let _ = fs::remove_file(p); }
            } else {
                let healthy = port_reachable(PROXY_HEALTH_ADDR_DEFAULT, Duration::from_millis(500));
                let health_str = if healthy { "healthy" } else { "unreachable" };
                rows.push(format!("status:  running ({})", health_str));
                rows.push(format!("pid:     {}", pid));
                rows.push(format!("listen:  http://{}", PROXY_HEALTH_ADDR_DEFAULT));
                match proxy_vault_state() {
                    ProxyVaultState::Current => rows.push("vault sync: current".to_string()),
                    ProxyVaultState::Stale => {
                        rows.push("vault sync: stale".to_string());
                        rows.push("hint:    restart proxy to apply new keys: aikey proxy restart".to_string());
                    }
                    ProxyVaultState::Unknown => {}
                }
            }
        }
    }
    rows
}

pub fn handle_restart(config: Option<&str>, password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    // Why hard restart instead of graceful reload: restart must reload proxy.env
    // (process environment variables), which can only take effect via a new process.
    // Graceful reload only re-reads vault/YAML config within the existing process.
    handle_stop()?;
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

/// Quick connectivity check for overseas AI providers.
/// Called in a background thread after proxy start. Only prints warnings
/// for providers that are unreachable — no output when all is fine.
fn check_overseas_connectivity() {
    const PROVIDERS: &[(&str, &str)] = &[
        ("OpenAI",    "api.openai.com:443"),
        ("Anthropic", "api.anthropic.com:443"),
    ];
    let timeout = Duration::from_secs(5);
    let mut unreachable = Vec::new();
    for &(name, addr) in PROVIDERS {
        if let Ok(sock_addr) = addr.to_socket_addrs().and_then(|mut it| {
            it.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no addr"))
        }) {
            if TcpStream::connect_timeout(&sock_addr, timeout).is_err() {
                unreachable.push(name);
            }
        } else {
            unreachable.push(name);
        }
    }
    if !unreachable.is_empty() {
        eprintln!();
        eprintln!("  \x1b[33m[warn]\x1b[0m  Cannot reach: {}",
            unreachable.join(", "));
        eprintln!("  \x1b[33m[warn]\x1b[0m  If you use these providers, configure HTTP_PROXY / HTTPS_PROXY");
        eprintln!("          and restart the proxy: aikey proxy restart");
    }
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
/// 1. Vault snapshot staleness (bail early if stale — results would be misleading)
/// 2. Vault is accessible (validated by caller before this function is called)
/// 3. Project config discovery
/// 4. Active logical environment
/// 5. Provider resolution from config
/// 6. Proxy health (auto-starts in background if not running)
pub fn handle_verify(password: &SecretString) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: bail early if the proxy is running on a stale vault snapshot.
    if is_proxy_running() && proxy_vault_state() == ProxyVaultState::Stale {
        eprintln!("proxy is using an outdated vault snapshot.");
        eprintln!("restart proxy to apply new keys: aikey proxy restart");
        eprintln!("Then re-run: aikey proxy verify");
        return Err("verify aborted: proxy vault snapshot is stale".into());
    }

    let mut failed = false;

    // Step 2: vault already validated by caller.
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
/// starts it in the background using the given master password. Returns `true`
/// if the proxy is (or becomes) reachable, `false` if startup failed.
///
/// Designed to be transparent to end users: no output on the happy path.
pub fn proxy_guard(password: &SecretString) -> bool {
    let health_addr = proxy_listen_addr(None);

    // Fast path: already running and healthy.
    if let Some(pid) = read_pid() {
        if process_alive(pid) && port_reachable(&health_addr, Duration::from_millis(300)) {
            // Warn once if the proxy is serving from a stale vault snapshot.
            if proxy_vault_state() == ProxyVaultState::Stale {
                eprintln!("[aikey] proxy is using an outdated vault snapshot.");
                eprintln!("[aikey] restart proxy to apply new keys: aikey proxy restart");
            }
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

// ---------------------------------------------------------------------------
// Public diagnostic helpers (used by `aikey doctor`)
// ---------------------------------------------------------------------------

/// Returns the proxy listen address (e.g. `127.0.0.1:27200`).
pub fn doctor_proxy_addr() -> String {
    proxy_listen_addr(None)
}

/// Returns the proxy listen port from config, falling back to 27200.
pub fn proxy_port() -> u16 {
    let addr = proxy_listen_addr(None);
    addr.rsplit(':').next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(27200)
}

/// Lightweight post-operation check: prints a warning if the proxy is not
/// reachable.  Does NOT attempt to auto-start — just informs the user.
///
/// Intended to be called at the end of commands that depend on the proxy
/// (`list`, `use`, `run`, `exec`) so the user knows why requests may fail
/// after an unexpected proxy termination (e.g. `kill -9`).
pub fn warn_if_proxy_down() {
    let addr = proxy_listen_addr(None);
    if !port_reachable(&addr, Duration::from_millis(400)) {
        eprintln!();
        eprintln!("  \x1b[33m\u{26A0}\x1b[0m  Proxy is not running. Start it with: aikey proxy start");
    }
}

/// Returns `(is_running, pid)` — checks PID file + process alive + port reachable.
pub fn doctor_proxy_status() -> (bool, Option<u32>) {
    let addr = proxy_listen_addr(None);
    match read_pid() {
        Some(pid) if process_alive(pid) && port_reachable(&addr, Duration::from_millis(500)) => {
            (true, Some(pid))
        }
        Some(pid) if process_alive(pid) => (false, Some(pid)), // alive but port not open yet
        _ => (false, None),
    }
}
