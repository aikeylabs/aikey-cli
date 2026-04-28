//! Cross-platform OS process introspection for the proxy lifecycle Layer 1.
//!
//! Two helpers, both intentionally low-level and side-effect-free:
//!
//! - [`process_identity`] — read the executable path of a running PID,
//!   used to verify "this PID is an `aikey-proxy` process" (invariant
//!   I-7a).
//! - [`process_birth_token`] — read a platform-specific *opaque* string
//!   that uniquely identifies a process incarnation (kernel-level start
//!   marker), used to verify "this PID is the *same* aikey-proxy instance
//!   our sidecar meta refers to" (invariant I-7b).
//!
//! See lifecycle 方案 doc § Round 5 评审采纳记录 for why birth_token is
//! kept as a per-platform opaque string rather than abstracted into a
//! `start_time_ms` (avoids Linux jiffies → ms conversion pitfalls:
//! boot_time resolution, container/sandbox differences, jiffies
//! granularity, NTP-related drift).

use std::path::PathBuf;

/// True if a process with the given PID is currently running.
///
/// This is the cheapest possible liveness check — no metadata, just
/// "does the kernel still have a process table entry for this PID?".
/// Per the Layer 1 invariants, this is the **first** gate; identity
/// + ownership checks come AFTER, never before.
///
/// On Unix uses `kill(pid, 0)` (no signal sent, just a permission
/// check). On Windows uses `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`.
///
/// Note: a `true` here does NOT mean the process is *ours* — kernel
/// PID recycling is exactly what makes the rest of the decision tree
/// (identity, ownership) necessary.
pub fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) is a no-op signal that probes existence + perm.
        //   ret == 0   → process exists AND we can signal it
        //   errno=EPERM → process exists, BUT we lack permission (e.g.
        //                 unprivileged user probing launchd / init).
        //                 Process is still alive — counts as alive.
        //   errno=ESRCH → process does not exist. Counts as dead.
        // SAFETY: kill with sig 0 is the documented existence-probe
        // pattern; errno is read via libc::__errno_location-equivalent
        // wrapped by std::io::Error::last_os_error.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if ret == 0 {
            return true;
        }
        // ret == -1 — distinguish EPERM (alive but unprivileged) from
        // ESRCH (truly gone). Anything else (rare) treat as dead to be
        // safe — start_proxy / stop_proxy will then attempt clean
        // recovery via Crashed branch.
        let err = std::io::Error::last_os_error();
        matches!(err.raw_os_error(), Some(libc::EPERM))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess returns 0 / INVALID_HANDLE_VALUE on
        // failure; we check before CloseHandle.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 || h == INVALID_HANDLE_VALUE as isize {
            return false;
        }
        unsafe { CloseHandle(h) };
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Read the executable path of the given PID.
///
/// Returns `None` when:
/// - the PID is not running,
/// - we lack permission to introspect (Linux non-self process before
///   ptrace_scope changes, macOS SIP-protected proc, Windows insufficient
///   handle access), or
/// - the platform call returns an error we cannot meaningfully recover.
///
/// The Layer 1 decision tree treats `None` as "identity unverifiable" →
/// the safe path is `OrphanedPort` (read-only, never killed). Identity
/// failures never escalate to "definitely not aikey-proxy" — they
/// escalate to "we don't know, so don't touch".
pub fn process_identity(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // /proc/PID/exe is a symlink to the executable. read_link works
        // for *self* unconditionally; for other PIDs it requires
        // ptrace_may_access permission (root or matching uid). We are
        // typically inspecting a child we ourselves spawned, so this
        // succeeds in the dominant case.
        let path = format!("/proc/{}/exe", pid);
        std::fs::read_link(&path).ok()
    }
    #[cfg(target_os = "macos")]
    {
        // proc_pidpath fills a fixed-size buffer with the full path.
        // PROC_PIDPATHINFO_MAXSIZE is 4 * MAXPATHLEN = 4096 (libc 0.2).
        const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
        let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
        // SAFETY: buf has the documented size, libc::proc_pidpath writes
        // up to bufsize bytes and returns the number written or -1.
        let n = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr() as *mut libc::c_void,
                PROC_PIDPATHINFO_MAXSIZE as u32,
            )
        };
        if n <= 0 {
            return None;
        }
        let n = n as usize;
        // proc_pidpath does not null-terminate; n is the byte count.
        let s = std::str::from_utf8(&buf[..n]).ok()?;
        Some(PathBuf::from(s))
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess returns 0 on failure; we check before use
        // and close via CloseHandle.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 {
            return None;
        }
        // QueryFullProcessImageNameW returns the Win32 path (DOS-style).
        // 32_768 chars is the max possible NT path length — generous but
        // correct.
        let mut buf: Vec<u16> = vec![0u16; 32_768];
        let mut size: u32 = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size) };
        unsafe { CloseHandle(h) };
        if ok == 0 {
            return None;
        }
        let s = String::from_utf16(&buf[..size as usize]).ok()?;
        Some(PathBuf::from(s))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = pid;
        None
    }
}

/// Convenience: is this PID an `aikey-proxy` process?
///
/// Returns:
/// - `true` only if `process_identity(pid)` returns Some path whose
///   filename (basename) equals `"aikey-proxy"` (or `"aikey-proxy.exe"`
///   on Windows).
/// - `false` if identity could not be read OR the basename does not match.
///
/// This is the invariant I-7a check. Note it does **not** prove
/// ownership — that's invariant I-7b's job
/// ([`process_birth_token`] + sidecar meta). A `true` here means "this is
/// some aikey-proxy"; combined with ownership it means "this is **our**
/// aikey-proxy".
pub fn is_aikey_proxy(pid: u32) -> bool {
    let Some(path) = process_identity(pid) else {
        return false;
    };
    let Some(stem) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    // Accept both Unix ("aikey-proxy") and Windows ("aikey-proxy.exe")
    // basenames without dragging in cfg gating — matching strings is
    // cheaper than splitting build paths.
    stem == "aikey-proxy" || stem == "aikey-proxy.exe"
}

/// Read an *opaque* platform-specific string that uniquely identifies a
/// process incarnation (= a "birth token"). Two distinct processes —
/// even if they have the same PID due to kernel PID recycling — will
/// always have different birth tokens, because the token incorporates a
/// kernel-level start marker that only changes across `fork`/`exec`.
///
/// Format is platform-specific and intentionally **opaque to the caller**:
/// CLI may only do `==` string comparison against a previously-recorded
/// value (in the sidecar meta file). We never parse, never convert, never
/// translate to a unified time format.
///
/// - **Linux**: `linux:jiffies:<n>` where n is field 22 of
///   `/proc/PID/stat` ("starttime", clock ticks since boot).
/// - **macOS**: `darwin:starttime:<sec>:<usec>` where sec/usec come from
///   `proc_pidinfo` PROC_PIDTBSDINFO `pbi_start_tvsec` /
///   `pbi_start_tvusec`.
/// - **Windows**: `windows:filetime:<u64>` where u64 is the FILETIME
///   value returned by `GetProcessTimes` (lpCreationTime).
///
/// **Why platform-opaque vs unified `start_time_ms`** (Round 5 evaluation
///采纳): converting Linux jiffies to ms would require (a) reading the
/// boot timestamp, (b) reading `CLK_TCK` to know jiffy resolution, (c)
/// handling container vs host boot-time differences, (d) handling jiffy
/// precision boundaries. Each of those is a separate failure mode that
/// would silently degrade ownership verification accuracy. String compare
/// of the raw kernel value sidesteps all of it.
///
/// Returns `Err` when the PID is gone, permission denies the read, or
/// the file/syscall is malformed. The Layer 1 decision tree treats `Err`
/// as "ownership unverifiable" → safe path is `OrphanedPort`.
pub fn process_birth_token(pid: u32) -> Result<String, BirthTokenError> {
    #[cfg(target_os = "linux")]
    {
        // /proc/PID/stat layout: see proc(5). Field 22 ("starttime") is
        // the start time in clock ticks since boot. Parsing is non-trivial
        // because field 2 (comm) is "(name)" and may contain spaces or
        // parens — we must split on the *last* ')' character first.
        let path = format!("/proc/{}/stat", pid);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| BirthTokenError::Read(format!("/proc/{pid}/stat: {e}")))?;
        // Find last ')', everything after the following space is field 3
        // onward (space-separated). starttime = field 22 → after the ')'
        // we want the 19th space-separated token (field 3 is the first).
        let split_at = content.rfind(')').ok_or_else(|| {
            BirthTokenError::Parse(format!("/proc/{pid}/stat missing ')' in comm field"))
        })?;
        let after = &content[split_at + 1..]; // starts with " S " typically
        let fields: Vec<&str> = after.split_whitespace().collect();
        // After the ')', field 3 onward — so starttime (field 22) is
        // index 22 - 3 = 19 in the post-')' fields list.
        let starttime = fields.get(19).ok_or_else(|| {
            BirthTokenError::Parse(format!(
                "/proc/{pid}/stat has only {} post-comm fields, need ≥20",
                fields.len()
            ))
        })?;
        // Sanity: must be a non-negative integer string.
        starttime
            .parse::<u64>()
            .map_err(|_| BirthTokenError::Parse(format!("starttime '{starttime}' not u64")))?;
        Ok(format!("linux:jiffies:{starttime}"))
    }
    #[cfg(target_os = "macos")]
    {
        // proc_pidinfo with PROC_PIDTBSDINFO returns a proc_bsdinfo
        // struct that includes pbi_start_tvsec / pbi_start_tvusec.
        // SAFETY: zeroed struct is the documented init pattern; the
        // libc call writes pbi_* fields when PROC_PIDTBSDINFO is set.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
            )
        };
        if n <= 0 {
            return Err(BirthTokenError::Read(format!(
                "proc_pidinfo({pid}, PROC_PIDTBSDINFO) returned {n}"
            )));
        }
        Ok(format!(
            "darwin:starttime:{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: zeroed FILETIME, OpenProcess returns 0 on failure.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 {
            return Err(BirthTokenError::Read(format!(
                "OpenProcess({pid}) failed"
            )));
        }
        let mut creation: FILETIME = unsafe { std::mem::zeroed() };
        let mut exit: FILETIME = unsafe { std::mem::zeroed() };
        let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
        let mut user: FILETIME = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user) };
        unsafe { CloseHandle(h) };
        if ok == 0 {
            return Err(BirthTokenError::Read(format!(
                "GetProcessTimes({pid}) failed"
            )));
        }
        // Combine high/low 32-bit halves into a u64 — the raw value is
        // 100-nanosecond intervals since 1601-01-01 UTC. We do NOT
        // convert; just stringify.
        let raw = ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);
        Ok(format!("windows:filetime:{raw}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = pid;
        Err(BirthTokenError::Read(
            "process_birth_token unsupported on this platform".into(),
        ))
    }
}

/// Find the PID of whatever process is listening on `tcp_port` on
/// localhost.
///
/// Used by Layer 1 decision tree to compare against our pidfile's PID
/// — if they differ, the port is held by an external process and we
/// must demote to `OrphanedPort` (never kill).
///
/// Returns:
/// - `Ok(Some(pid))` when exactly one PID owns the port (the dominant
///   case — TCP LISTEN sockets are 1:1 with PID).
/// - `Ok(None)` when no process is listening (port is free).
/// - `Ok(Some(first_pid))` when multiple PIDs are reported (unusual —
///   typically a forked listener; we pick the first reported and let
///   the caller treat it as the canonical owner).
/// - `Err(...)` when the platform tool is missing / fails to spawn /
///   produces unparseable output. Layer 1 maps `Err` to "owner unknown"
///   → conservative `OrphanedPort` with `owner_pid: None` (don't claim
///   a PID we can't verify).
///
/// Implementation: shells out to `lsof` on Unix (macOS / Linux) and to
/// PowerShell `Get-NetTCPConnection` on Windows. Both are present by
/// default on supported platforms — we deliberately do NOT depend on
/// netstat (deprecated on modern Windows, formatting varies on Linux).
pub fn port_owner_pid(tcp_port: u16) -> Result<Option<u32>, PortOwnerError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // `lsof -ti :<port> -sTCP:LISTEN` outputs PIDs (one per line)
        // for processes holding a LISTEN socket on that port. Empty
        // output (and exit 1) means no listener — that is the normal
        // "port is free" case, NOT an error.
        let out = std::process::Command::new("lsof")
            .arg("-ti")
            .arg(format!(":{tcp_port}"))
            .arg("-sTCP:LISTEN")
            .output()
            .map_err(|e| PortOwnerError::Spawn(format!("lsof: {e}")))?;
        // lsof returns 1 when no match — distinguish from a real failure.
        // Exit code 0 with empty stdout is also "no match" in some
        // environments; rely on stdout, not status.
        let stdout = std::str::from_utf8(&out.stdout)
            .map_err(|e| PortOwnerError::Parse(format!("lsof stdout not utf8: {e}")))?;
        let first = stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .next();
        match first {
            None => Ok(None),
            Some(s) => s
                .parse::<u32>()
                .map(Some)
                .map_err(|_| PortOwnerError::Parse(format!("lsof returned non-pid line: {s:?}"))),
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Get-NetTCPConnection is the canonical Windows API for this.
        // We call PowerShell with -Command for a one-shot query;
        // -OwningProcess is the PID column. Filter on LocalPort and
        // State Listen to mirror lsof's `-sTCP:LISTEN`.
        let script = format!(
            "(Get-NetTCPConnection -LocalPort {} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess)",
            tcp_port
        );
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(|e| PortOwnerError::Spawn(format!("powershell: {e}")))?;
        let stdout = std::str::from_utf8(&out.stdout)
            .map_err(|e| PortOwnerError::Parse(format!("powershell stdout not utf8: {e}")))?;
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        trimmed
            .parse::<u32>()
            .map(Some)
            .map_err(|_| PortOwnerError::Parse(format!("powershell returned non-pid: {trimmed:?}")))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = tcp_port;
        Err(PortOwnerError::Spawn(
            "port_owner_pid unsupported on this platform".into(),
        ))
    }
}

/// **Strong liveness probe** — sends `GET /health` to `127.0.0.1:<port>`
/// and reports whether the admin handler responded with HTTP 200.
///
/// **Important: this is a LIVENESS probe, not a READINESS probe.** A
/// `true` here means "the proxy's HTTP server is up and the admin
/// router handler responded" — it does NOT mean "the proxy has fully
/// applied the latest vault snapshot, the supervisor has built a
/// healthy generation, the upstream pool is warm, etc.". Real
/// readiness lives in the ProxyRuntimeState scheme's
/// `/internal/status` endpoint and is out of scope for this Layer 1
/// decision tree.
///
/// Why this is "stronger" than a plain TCP connect: bare TCP succeeds
/// the moment the kernel binds the port, even if the Go HTTP server
/// hasn't installed its routes yet. `/health` only succeeds after the
/// admin handler has been mounted — catching the "port-bound but not
/// yet serving" gap that the original `is_proxy_listening` ran into.
///
/// Returns `true` only on HTTP 200. Anything else (timeout, network
/// error, non-200 status) returns `false` — Layer 1 maps that to
/// `Unresponsive` (not `Running`), which is correct: Layer 2 will then
/// kill+respawn rather than trust a half-started proxy.
///
/// `timeout` caps both the connect and the response read. 500ms is a
/// good default for localhost — anything slower than that is almost
/// certainly a hung proxy, not network latency.
pub fn http_health_ok(port: u16, timeout: std::time::Duration) -> bool {
    let url = format!("http://127.0.0.1:{port}/health");
    // ureq agent with both connect and read timeouts. We do NOT honor
    // user proxy.env here — /health is a localhost loopback call and
    // should never be routed through an outbound HTTP proxy (would
    // produce confusing failures on networks that filter localhost via
    // proxy autoconfig).
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    match agent.get(&url).call() {
        Ok(resp) => resp.status() == 200,
        Err(_) => false,
    }
}

/// Errors from [`port_owner_pid`]. Layer 1 maps both variants to
/// "owner unknown" (= `OrphanedPort` with `owner_pid: None`).
#[derive(Debug)]
pub enum PortOwnerError {
    /// The lookup tool (lsof / powershell) could not be spawned.
    Spawn(String),
    /// The tool ran but its output did not parse as expected (typically
    /// a tooling-version skew).
    Parse(String),
}

impl std::fmt::Display for PortOwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortOwnerError::Spawn(s) => write!(f, "port owner lookup spawn: {s}"),
            PortOwnerError::Parse(s) => write!(f, "port owner lookup parse: {s}"),
        }
    }
}

impl std::error::Error for PortOwnerError {}

/// Error categories from [`process_birth_token`]. Layer 1 maps both
/// variants to "ownership unverifiable" (= demoted to `OrphanedPort`).
/// We split them so log messages can be more specific.
///
/// `#[allow(dead_code)]`: `Parse` is only constructed on Linux (where
/// /proc/PID/stat parsing can fail in non-trivial ways); macOS and
/// Windows code paths only ever return `Read` on failure. Keeping the
/// variant in the enum so callers' exhaustive matches stay correct
/// across platforms.
#[allow(dead_code)]
#[derive(Debug)]
pub enum BirthTokenError {
    /// The OS call / file read failed (process gone, permission denied,
    /// file system error).
    Read(String),
    /// The platform data layout did not parse as expected (typically a
    /// kernel/proc-ABI mismatch).
    Parse(String),
}

impl std::fmt::Display for BirthTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BirthTokenError::Read(s) => write!(f, "birth_token read failed: {s}"),
            BirthTokenError::Parse(s) => write!(f, "birth_token parse failed: {s}"),
        }
    }
}

impl std::error::Error for BirthTokenError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Unix `process_identity(self_pid)` should return our test
    /// binary's exe path. Catches a regression where the platform call
    /// silently returns Err / None due to a libc binding change.
    #[test]
    fn process_identity_works_for_self() {
        let me = std::process::id();
        let path = process_identity(me);
        assert!(
            path.is_some(),
            "process_identity must succeed for self-PID"
        );
        let p = path.unwrap();
        // The basename is the cargo test binary, *not* aikey-proxy —
        // confirms the call is reading the actual exe path, not a hard-
        // coded sentinel.
        assert!(p.is_absolute(), "expected absolute path, got {p:?}");
    }

    /// Self-PID is definitely not aikey-proxy (we are the test runner).
    /// Pinning so a future regression that always returns true would be
    /// caught immediately.
    #[test]
    fn is_aikey_proxy_false_for_self() {
        assert!(!is_aikey_proxy(std::process::id()));
    }

    /// PID 0 / 1 (init / launchd / SYSTEM) are guaranteed not to be
    /// aikey-proxy. Picks PID 1 because it always exists; PID 0 is
    /// kernel-only on Linux and identity reads typically fail there too.
    #[test]
    fn is_aikey_proxy_false_for_pid1() {
        assert!(
            !is_aikey_proxy(1),
            "init/launchd/System should never be classified as aikey-proxy"
        );
    }

    /// Non-existent PID should return false, not panic. We pick a high
    /// PID unlikely to be in use; on the off-chance it *is* in use, the
    /// test still passes because that arbitrary process is not
    /// aikey-proxy either.
    #[test]
    fn is_aikey_proxy_false_for_unlikely_pid() {
        assert!(!is_aikey_proxy(999_999_999));
    }

    /// Self-PID always has a birth_token. Pinning that the platform
    /// call returns Ok for the dominant case.
    #[test]
    fn process_birth_token_works_for_self() {
        let token = process_birth_token(std::process::id()).expect("self birth_token must succeed");
        // Must start with the platform tag — sanity-check the format
        // contract documented in the function comment, since the rest of
        // Layer 1/2 only treats it as opaque.
        assert!(
            token.starts_with("linux:jiffies:")
                || token.starts_with("darwin:starttime:")
                || token.starts_with("windows:filetime:"),
            "unexpected token format: {token}"
        );
    }

    /// Two consecutive calls for the same self-PID must produce the
    /// **identical** token string. This is the load-bearing guarantee
    /// for ownership verification — if the token drifted across calls
    /// even for the same process, ownership check would always fail.
    #[test]
    fn process_birth_token_stable_across_calls() {
        let a = process_birth_token(std::process::id()).unwrap();
        let b = process_birth_token(std::process::id()).unwrap();
        assert_eq!(
            a, b,
            "birth_token must be stable across calls for same PID — \
             ownership verification depends on this invariant"
        );
    }

    /// Birth token for an unlikely / dead PID returns Err, not panic.
    #[test]
    fn process_birth_token_errs_for_dead_pid() {
        let r = process_birth_token(999_999_999);
        assert!(r.is_err(), "expected Err for dead PID, got {r:?}");
    }

    /// Free port → port_owner_pid returns Ok(None). Pinned because Layer
    /// 1's "Stopped" branch depends on this signal.
    #[test]
    fn port_owner_pid_none_for_free_port() {
        // Bind+drop to obtain a port the OS just released. Race-prone in
        // theory (something else could grab it before our check), but
        // for a 1-microsecond gap on localhost this is functionally
        // reliable in CI.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        // Tiny sleep to let the kernel release the LISTEN socket fully.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let r = port_owner_pid(port);
        // We accept both Ok(None) and Err (lsof not on PATH / permission)
        // — what we MUST NOT see is Ok(Some(pid)) for a port we know is
        // free (would mean false-attribution → wrong OrphanedPort
        // diagnostic). On macOS/Linux dev machines lsof is present.
        match r {
            Ok(None) => {}
            Ok(Some(pid)) => panic!("free port {port} reported as owned by pid {pid}"),
            Err(_) => {} // lsof missing / permission — acceptable
        }
    }

    /// Bound port on this process → port_owner_pid (when it works) must
    /// return our PID. Pinned so a future regression that pulls the
    /// wrong column out of lsof output is caught.
    #[test]
    fn port_owner_pid_self_when_we_hold_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = std::process::id();
        match port_owner_pid(port) {
            Ok(Some(pid)) => {
                assert_eq!(
                    pid, me,
                    "port_owner_pid returned {pid} but we are {me} and we hold the port"
                );
            }
            Ok(None) => panic!("port {port} reported free but we hold its listener"),
            Err(e) => {
                // lsof missing on this machine — log and skip rather than fail,
                // because the helper itself is correct in design and the only
                // remaining failure mode is environment.
                eprintln!("[skip] port_owner_pid_self_when_we_hold_port: {e}");
            }
        }
        drop(listener);
    }

    // ── HTTP /health probe tests ───────────────────────────────────────
    //
    // We spin up a minimal blocking std::net::TcpListener that speaks
    // HTTP/1.0 by hand — keeps the test self-contained (no extra dev
    // dep) and lets us inject specific responses (200 vs 503 vs hang)
    // to verify Layer 1 only treats 200 as healthy.

    use std::io::{Read, Write};

    /// Spawn a one-shot fake HTTP server on `127.0.0.1:0` that answers
    /// the FIRST incoming request with `status_line` (e.g.
    /// "200 OK" / "503 Service Unavailable") and an empty body, then
    /// closes the connection. Returns the bound port.
    ///
    /// Used by /health probe tests — kept inline rather than abstracted
    /// because the surrounding tests are the only callers and the
    /// inline version makes the request/response shape obvious.
    fn spawn_fake_http_once(status_line: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf); // discard the request line
                let resp = format!(
                    "HTTP/1.0 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        // Tiny grace so the accept loop is ready before the test
        // probes — the listener is bound (so port_reachable would be
        // true) but the response side races with our probe otherwise.
        std::thread::sleep(std::time::Duration::from_millis(20));
        port
    }

    /// Happy path: a server that returns 200 → http_health_ok = true.
    /// Pinned because Layer 1's `Running` branch depends on this signal.
    #[test]
    fn http_health_ok_true_on_200() {
        let port = spawn_fake_http_once("200 OK");
        assert!(http_health_ok(port, std::time::Duration::from_millis(500)));
    }

    /// Non-200 response → false. Caught a class of regressions where
    /// future ureq versions might treat 503 as a "completed call" and
    /// return Ok — we strictly require status == 200.
    #[test]
    fn http_health_ok_false_on_503() {
        let port = spawn_fake_http_once("503 Service Unavailable");
        assert!(!http_health_ok(port, std::time::Duration::from_millis(500)));
    }

    /// Free port (no listener at all) → false within timeout. Caught a
    /// regression where a connect refused error would be (mis)mapped
    /// to "true" by an over-eager error handler.
    #[test]
    fn http_health_ok_false_when_nobody_listening() {
        // Bind+drop to obtain a port we know is free.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let start = std::time::Instant::now();
        let ok = http_health_ok(port, std::time::Duration::from_millis(300));
        let elapsed = start.elapsed();
        assert!(!ok, "unexpected ok response from a free port");
        // Sanity-check the timeout actually applies — within 1s.
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "probe should respect timeout, took {elapsed:?}"
        );
    }
}
