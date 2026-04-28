//! Proxy lifecycle Layer 2: state-machine **write** path.
//!
//! Three public APIs — [`start_proxy`], [`stop_proxy`], [`restart_proxy`]
//! — implement the only sanctioned ways to mutate proxy process state.
//! Direct `Command::spawn` / `kill` / pidfile writes from anywhere else
//! in the CLI is a violation of the design (and removed in Stage 3 cut-over).
//!
//! # Invariants enforced here
//!
//! - **I-1**: every kill action targets exclusively the PID that
//!   ownership-verifies against our sidecar meta. Layer 1's
//!   [`ProxyState`] enum is the bridge — only `Running` /
//!   `Unresponsive` instances are eligible, and Layer 1 guarantees
//!   those are identity + ownership verified.
//! - **I-2**: every spawn-to-healthy-or-fail sequence is wrapped in a
//!   RAII [`StartCleanupGuard`] so panics, early returns, and CLI
//!   `?`-bubble-ups all clean up child + pidfile + sidecar without
//!   leaving stale on-disk state.
//! - **I-4**: stop_proxy waits up to 30s for `srv.Shutdown(30s)`
//!   graceful drain in the proxy before escalating to SIGKILL.
//! - **Concurrency**: every API acquires
//!   `~/.aikey/run/proxy.lock` (fs2 advisory) at entry, blocking
//!   concurrent CLI invocations from racing the same proxy slot.
//!
//! See lifecycle 方案 § Layer 2 for full design rationale.

use secrecy::{ExposeSecret, SecretString};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;

use crate::proxy_proc;
use crate::proxy_state::{
    self, MetaV1, OrphanReason, ProxyState, StateInputs, META_SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Filename of the lifecycle lock file. Lives next to pidfile + sidecar
/// under `~/.aikey/run/`. Empty content; presence + fs2 lock semantics
/// is what matters.
pub const LIFECYCLE_LOCK_FILENAME: &str = "proxy.lock";

/// How long to wait for the lifecycle lock at the start of a Layer 2
/// API. Most operations finish in <1s; 5s is generous for normal use
/// and short enough that interactive callers don't get a "hung" feel.
const LIFECYCLE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Polling interval for the lock acquisition loop. fs2's `try_lock_exclusive`
/// is non-blocking; we busy-wait between attempts.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Default timeout for `start_proxy` to consider the spawned child
/// "healthy" (process_alive + HTTP /health 200). 5s is enough for cold
/// starts on most laptops; longer than that almost always means the
/// proxy crashed silently.
pub const DEFAULT_HEALTHY_DEADLINE: Duration = Duration::from_secs(5);

/// Polling interval inside the healthy-poll loop. 250ms balances "user
/// doesn't notice" with "child has time to bind the port".
const HEALTHY_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Default timeout for `stop_proxy` SIGTERM phase. Aligned with
/// aikey-proxy's own `srv.Shutdown(30 * time.Second)` graceful drain
/// contract so streaming SSE responses, token usage uploads, and WAL
/// flushes have time to finish before SIGKILL escalation.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum extra wait after SIGKILL escalation (in `stop_proxy`).
/// Real processes die almost immediately on SIGKILL — 5s is a wide
/// safety margin that should never actually be hit.
const SIGKILL_GRACE: Duration = Duration::from_secs(5);

/// How often `stop_proxy` polls during the SIGTERM wait.
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How often `stop_proxy` emits a "still stopping" progress line.
/// Conservative — we don't claim to know what proxy is doing internally.
const STOP_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes from [`start_proxy`].
///
/// Each variant carries enough context for the CLI shell (Layer 3) to
/// render an actionable error message — the user should never see a
/// bare "start failed" string.
///
/// `#[allow(dead_code)]` on the enum: a few variants
/// (`VaultPasswordRejected`, `BirthTokenRead`) are defined as part of
/// the public error contract but not currently constructed by
/// `start_proxy_locked` — caller is expected to verify password before
/// calling Layer 2 (Layer 2 doesn't run vault operations itself).
/// Keeping them in the enum so future expansion (e.g., Layer 2-side
/// password verification mode) doesn't need a SemVer bump.
#[allow(dead_code)]
#[derive(Debug)]
pub enum StartError {
    /// Could not acquire the lifecycle lock within
    /// `LIFECYCLE_LOCK_TIMEOUT`. Another `aikey proxy *` invocation
    /// is in flight; retry once it finishes.
    LockBusy,

    /// Layer 1 reported `Unresponsive` (our previous instance is
    /// stuck) and the SIGTERM → SIGKILL escalation could not get the
    /// PID to die or the port to release within the bounded deadline.
    /// We refuse to spawn a replacement in this state because doing so
    /// risks a double-instance window AND we cannot safely delete the
    /// ownership anchor (pidfile + sidecar) — those two would then point
    /// at a still-live process. User should investigate manually.
    /// (Round 7 review fix: previously the CLI would silently delete
    /// pidfile + sidecar even if the old process was still alive.)
    UnresponsiveStuck { pid: u32, port: u16 },

    /// Vault password could not be verified before spawn (rate limiter
    /// counted this as a failed attempt). Caller should re-prompt.
    VaultPasswordRejected(String),

    /// Configured listen port is held by something we cannot prove is
    /// our own aikey-proxy (external program, different aikey-proxy
    /// instance, legacy pidfile from before sidecar mechanism).
    OrphanedPort {
        port: u16,
        owner_pid: Option<u32>,
        reason: OrphanReason,
    },

    /// `aikey-proxy` binary not found on disk.
    BinaryMissing(String),

    /// `aikey-proxy.yaml` config not found / unreadable.
    ConfigMissing(String),

    /// `process_birth_token(pid)` failed for a freshly-spawned child —
    /// extremely rare (would indicate the child died between spawn and
    /// the immediate token read).
    BirthTokenRead(String),

    /// Sidecar meta or pidfile write failed (typically a filesystem
    /// permission / disk-full issue).
    PersistFailed(String),

    /// `Command::spawn` itself failed (ENOEXEC, EACCES, etc.).
    SpawnFailed(String),

    /// Child spawned but did not become healthy within
    /// `healthy_deadline`. Drop guard already cleaned up child +
    /// pidfile + sidecar; the embedded path points to the proxy's own
    /// stderr log so the user can investigate.
    HealthyTimeout { stderr_log: PathBuf },

    /// Child exited shortly after spawn (e.g., vault decrypt failure
    /// inside the proxy — usually means env var smuggling went wrong).
    /// Drop guard cleaned up; stderr_log points to proxy's own log.
    ChildDiedAtStartup { stderr_log: PathBuf },
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::LockBusy => write!(
                f,
                "another aikey proxy command is in flight ({}s timeout exceeded); retry shortly",
                LIFECYCLE_LOCK_TIMEOUT.as_secs()
            ),
            StartError::VaultPasswordRejected(s) => write!(f, "vault password rejected: {s}"),
            StartError::OrphanedPort { port, owner_pid, reason } => {
                write!(f, "port {port} not owned by us: {}", reason.hint(*port, *owner_pid))
            }
            StartError::BinaryMissing(s) => write!(
                f,
                "aikey-proxy binary not found: {s}; reinstall via `aikey proxy install`"
            ),
            StartError::ConfigMissing(s) => write!(
                f,
                "aikey-proxy config not found: {s}"
            ),
            StartError::BirthTokenRead(s) => write!(
                f,
                "could not read process_birth_token for spawned child: {s} (rare; retry once)"
            ),
            StartError::PersistFailed(s) => write!(f, "failed to persist pidfile/sidecar: {s}"),
            StartError::SpawnFailed(s) => write!(f, "failed to spawn aikey-proxy: {s}"),
            StartError::HealthyTimeout { stderr_log } => write!(
                f,
                "aikey-proxy did not become healthy in {:?}; check {}",
                DEFAULT_HEALTHY_DEADLINE,
                stderr_log.display()
            ),
            StartError::ChildDiedAtStartup { stderr_log } => write!(
                f,
                "aikey-proxy exited shortly after starting; check {}",
                stderr_log.display()
            ),
            StartError::UnresponsiveStuck { pid, port } => write!(
                f,
                "previous aikey-proxy (pid: {pid}) is unresponsive and did not exit \
                 after SIGTERM/SIGKILL; refusing to start a replacement (would risk \
                 double instances). Investigate with: \
                 lsof -nP -iTCP:{port} -sTCP:LISTEN; kill -9 {pid} (manual)"
            ),
        }
    }
}

impl std::error::Error for StartError {}

/// Failure modes from [`stop_proxy`].
#[derive(Debug)]
pub enum StopError {
    /// Could not acquire the lifecycle lock.
    LockBusy,

    /// Layer 1 reported `OrphanedPort` — the port is held by something
    /// we cannot prove ownership of, so we MUST NOT signal the owner
    /// PID (invariant I-1). Caller should print the diagnostic and
    /// instruct the user to investigate manually.
    NotOurs {
        port: u16,
        owner_pid: Option<u32>,
        reason: OrphanReason,
    },

    /// SIGTERM was sent but the PID neither died nor released the
    /// port within `timeout + SIGKILL_GRACE`. Should be impossible
    /// in practice (SIGKILL is uncatchable on Unix; Windows
    /// TerminateProcess is similarly final).
    StuckAfterKill { pid: u32, port: u16 },

    /// OS-level `kill` syscall failed (e.g., permission denied —
    /// would only happen if the proxy elevated mid-run, which we
    /// don't support).
    KillFailed(String),
}

impl std::fmt::Display for StopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopError::LockBusy => write!(
                f,
                "another aikey proxy command is in flight; retry shortly"
            ),
            StopError::NotOurs { port, owner_pid, reason } => {
                write!(f, "port {port} not owned by us: {}", reason.hint(*port, *owner_pid))
            }
            StopError::StuckAfterKill { pid, port } => write!(
                f,
                "PID {pid} or port {port} still active after SIGKILL — investigate with `lsof -nP -iTCP:{port} -sTCP:LISTEN`"
            ),
            StopError::KillFailed(s) => write!(f, "kill failed: {s}"),
        }
    }
}

impl std::error::Error for StopError {}

// ---------------------------------------------------------------------------
// Path resolution + atomic IO
// ---------------------------------------------------------------------------

/// Resolve `~/.aikey/run/` (creating it if needed). All three lifecycle
/// files (proxy.pid, proxy-meta.json, proxy.lock) live here.
fn run_dir() -> std::io::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine home directory for ~/.aikey/run",
        )
    })?;
    let dir = home.join(".aikey").join("run");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Resolve canonical pidfile path.
pub fn pid_path() -> std::io::Result<PathBuf> {
    Ok(run_dir()?.join("proxy.pid"))
}

/// Resolve canonical sidecar meta path.
pub fn meta_path() -> std::io::Result<PathBuf> {
    Ok(run_dir()?.join(crate::proxy_state::SIDECAR_META_FILENAME))
}

/// Resolve canonical lock-file path.
pub fn lock_path() -> std::io::Result<PathBuf> {
    Ok(run_dir()?.join(LIFECYCLE_LOCK_FILENAME))
}

/// Atomic write: write to `<path>.tmp`, then rename to `<path>`.
/// Reader never observes a half-written byte sequence.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Best-effort delete. Missing file is not an error.
pub fn best_effort_remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Persist the ownership anchor files (sidecar meta first, pidfile
/// second) for a freshly-spawned aikey-proxy child. Returns the
/// `birth_token` so callers can include it in any further bookkeeping.
///
/// **Round 7 review fix (Finding 2)**: extracted from
/// `start_proxy_locked_inner` so the foreground start path can use the
/// same atomic write order. Without this, `aikey proxy start
/// --foreground` writes only the pidfile and Layer 1 classifies the
/// running proxy as `OrphanedPort + LegacyPidfileNoSidecar` — meaning
/// `aikey proxy stop / restart` from another shell refuses to manage
/// it.
///
/// Caller is responsible for installing a Drop guard / equivalent
/// cleanup that removes both files in REVERSE order (pidfile first,
/// sidecar second) on failure paths — see [`StartCleanupGuard`] for
/// the canonical pattern.
pub fn persist_ownership_files(
    child_pid: u32,
    binary_path: &Path,
    config_path: &Path,
    listen_addr: &str,
) -> Result<String, StartError> {
    let birth_token = match proxy_proc::process_birth_token(child_pid) {
        Ok(t) => t,
        Err(crate::proxy_proc::BirthTokenError::Read(_)) => {
            // Most likely the child already exited (race with vault
            // decrypt failure / panic during init). Surface as a
            // distinct error so callers can render the proxy's stderr
            // log path instead of a generic "persist failed".
            return Err(StartError::ChildDiedAtStartup {
                stderr_log: PathBuf::from("/dev/null"),
            });
        }
        Err(crate::proxy_proc::BirthTokenError::Parse(detail)) => {
            return Err(StartError::BirthTokenRead(detail));
        }
    };
    let meta = MetaV1 {
        schema_version: META_SCHEMA_VERSION,
        pid: child_pid,
        birth_token: birth_token.clone(),
        binary_path: binary_path.to_path_buf(),
        config_path: config_path.to_path_buf(),
        listen_addr: listen_addr.to_string(),
        written_at: chrono_now_rfc3339(),
    };
    let meta_p = meta_path()
        .map_err(|e| StartError::PersistFailed(format!("meta_path: {e}")))?;
    let pid_p = pid_path()
        .map_err(|e| StartError::PersistFailed(format!("pid_path: {e}")))?;
    let meta_bytes = serde_json::to_vec_pretty(&meta)
        .map_err(|e| StartError::PersistFailed(format!("meta serialize: {e}")))?;
    // Write order matters: sidecar first so a CLI crash between the
    // two writes leaves us with "sidecar but no pidfile" (= Stopped per
    // Layer 1, harmless) rather than "pidfile but no sidecar"
    // (= LegacyPidfileNoSidecar, which blocks subsequent management).
    atomic_write(&meta_p, &meta_bytes)
        .map_err(|e| StartError::PersistFailed(format!("sidecar write: {e}")))?;
    atomic_write(&pid_p, child_pid.to_string().as_bytes())
        .map_err(|e| StartError::PersistFailed(format!("pidfile write: {e}")))?;
    Ok(birth_token)
}

// ---------------------------------------------------------------------------
// Lifecycle lock (T2-2)
// ---------------------------------------------------------------------------

/// RAII guard wrapping the held lifecycle lock. Drop releases.
pub struct LifecycleLock {
    _file: File, // dropping closes fd which auto-releases the fs2 lock
}

/// Acquire the lifecycle lock with a bounded retry loop.
///
/// Returns `Ok(LifecycleLock)` on success — the returned guard MUST
/// be held for the entire critical section (start/stop/restart).
/// Drop releases the lock; this happens automatically on function
/// return / panic / early `?` propagation.
///
/// Returns `Err(())` (caller maps to `StartError::LockBusy` /
/// `StopError::LockBusy`) when `LIFECYCLE_LOCK_TIMEOUT` is exceeded.
pub fn acquire_lifecycle_lock() -> Result<LifecycleLock, ()> {
    let path = lock_path().map_err(|_| ())?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|_| ())?;
    let deadline = Instant::now() + LIFECYCLE_LOCK_TIMEOUT;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(LifecycleLock { _file: file }),
            Err(_) => {
                if Instant::now() >= deadline {
                    return Err(());
                }
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Drop guard (T2-3 / I-2)
// ---------------------------------------------------------------------------

/// RAII cleanup for an in-progress `start_proxy`.
///
/// Captures (a) the PID we just spawned, (b) the pidfile path, (c) the
/// sidecar meta path. On Drop without a prior `commit()`:
///
/// 1. SIGTERM the captured PID (best-effort — it may already be dead).
/// 2. Delete pidfile (if present).
/// 3. Delete sidecar meta (if present).
///
/// `commit()` cancels the cleanup — call only after the proxy is
/// confirmed healthy and we want to keep the on-disk state.
///
/// **Invariant I-2**: this is the single failure-cleanup path.
/// `start_proxy` MUST NOT call `kill` / `delete pidfile` / `delete
/// sidecar` outside of guard.commit() / guard drop. Anywhere it does
/// risks leaking child or pidfile state on early-return / panic paths.
struct StartCleanupGuard {
    pid: u32,
    pid_path: PathBuf,
    meta_path: PathBuf,
    /// `Some` while we own the handle (until commit consumes it via
    /// take()). On Drop, `Some` means we must reap the child to avoid
    /// zombies (Round-6 review fix #1).
    child: Option<std::process::Child>,
    committed: bool,
}

impl StartCleanupGuard {
    fn new(
        pid: u32,
        pid_path: PathBuf,
        meta_path: PathBuf,
        child: Option<std::process::Child>,
    ) -> Self {
        Self {
            pid,
            pid_path,
            meta_path,
            child,
            committed: false,
        }
    }

    /// Cancel cleanup. Call only after the proxy is healthy and the
    /// on-disk state should be kept.
    ///
    /// We `take()` the child handle and forget it — the proxy is
    /// expected to outlive the CLI process, so detaching the handle
    /// is correct. On Unix the kernel will reap when the proxy
    /// eventually exits (it has no parent to wait, so init takes over).
    fn commit(mut self) {
        if let Some(c) = self.child.take() {
            std::mem::forget(c);
        }
        self.committed = true;
    }
}

impl Drop for StartCleanupGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Best-effort kill of the child. process is probably already
        // dying (that's why we're cleaning up), but a SIGTERM is cheap
        // insurance for the "still stuck mid-init" subset.
        let _ = kill_pid_signal(self.pid, /* sigkill = */ false);

        // Reap the child to prevent zombies. Wait briefly — the child
        // should exit quickly after SIGTERM; if it's stuck, escalate
        // to SIGKILL and try again. This is bounded so a misbehaving
        // proxy can't make a panic recovery hang forever.
        if let Some(mut child) = self.child.take() {
            // Try non-blocking wait first — if child already exited
            // (the dominant case for spawn-time failures), reap and
            // move on.
            let mut reaped = matches!(child.try_wait(), Ok(Some(_)));
            if !reaped {
                std::thread::sleep(Duration::from_millis(200));
                reaped = matches!(child.try_wait(), Ok(Some(_)));
            }
            if !reaped {
                let _ = kill_pid_signal(self.pid, /* sigkill = */ true);
                std::thread::sleep(Duration::from_millis(200));
                let _ = child.try_wait();
            }
        }

        // Delete pidfile + sidecar in REVERSE order from how
        // start_proxy wrote them (sidecar first, pidfile second).
        // Reverse cleanup avoids the read-path window where pidfile
        // exists but sidecar does not — that path triggers the
        // OrphanedPort/LegacyPidfileNoSidecar branch, which is the
        // worst classification we could leave for the next caller.
        best_effort_remove(&self.pid_path);
        best_effort_remove(&self.meta_path);
    }
}

// ---------------------------------------------------------------------------
// Cross-platform signal helpers
// ---------------------------------------------------------------------------

/// Send a signal (SIGTERM or SIGKILL) to a PID. On Windows
/// `TerminateProcess` is always equivalent to SIGKILL.
fn kill_pid_signal(pid: u32, sigkill: bool) -> Result<(), StopError> {
    #[cfg(unix)]
    {
        let signal = if sigkill { libc::SIGKILL } else { libc::SIGTERM };
        // SAFETY: kill is safe — invalid pid simply returns -1 with errno.
        let ret = unsafe { libc::kill(pid as libc::pid_t, signal) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // ESRCH = process already gone, treat as success.
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(StopError::KillFailed(format!("kill({pid}, {signal}): {err}")));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        let _ = sigkill; // Windows: TerminateProcess is always equivalent to SIGKILL
        // SAFETY: OpenProcess returns 0 on failure; TerminateProcess
        // accepts the handle; we close after.
        let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if h == 0 {
            return Err(StopError::KillFailed(format!("OpenProcess({pid}) failed")));
        }
        let ok = unsafe { TerminateProcess(h, 1) };
        unsafe { CloseHandle(h); }
        if ok == 0 {
            return Err(StopError::KillFailed(format!("TerminateProcess({pid}) failed")));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, sigkill);
        Err(StopError::KillFailed("unsupported platform".into()))
    }
}

// ---------------------------------------------------------------------------
// start_proxy() — T2-3
// ---------------------------------------------------------------------------

/// Options for [`start_proxy`].
pub struct StartOptions {
    /// `aikey-proxy.yaml` path. Used for sidecar meta `config_path`
    /// + spawn `--config` arg + listen address resolution.
    pub config_path: PathBuf,

    /// Path to the `aikey-proxy` binary.
    pub binary_path: PathBuf,

    /// Listen address from the config (`host:port`). Used for
    /// the healthy-poll loop's HTTP probe + sidecar meta.
    pub listen_addr: String,

    /// Maximum time to wait for the spawned child to become healthy
    /// (process_alive + HTTP /health 200). Default
    /// [`DEFAULT_HEALTHY_DEADLINE`].
    pub healthy_deadline: Duration,

    /// Where to redirect the proxy child's stderr. Typically the
    /// startup log (`~/.aikey/logs/aikey-proxy-startup.log`); can be
    /// `Inherit` for foreground mode or `Null` for tests.
    pub stderr_target: StderrTarget,

    /// Extra environment vars to inject (typically `AIKEY_*` from
    /// proxy.env).  `AIKEY_MASTER_PASSWORD` is always set separately
    /// from the password parameter.
    pub extra_env: Vec<(String, String)>,
}

/// Where to direct the spawned child's stderr.
///
/// `#[allow(dead_code)]`: `Null` and `Inherit` variants are part of the
/// public StartOptions surface for future foreground / silent-test
/// callers, but Stage 3 callers all use `Log` (the canonical startup
/// log path). Keeping the variants for API completeness — caller can
/// pick whichever fits their context without forcing API churn later.
#[allow(dead_code)]
pub enum StderrTarget {
    /// Discard (`/dev/null`).
    Null,
    /// Inherit from CLI (foreground mode shows logs).
    Inherit,
    /// Append to the named file (typical startup log path).
    Log(PathBuf),
}

impl StderrTarget {
    fn into_stdio(self) -> std::process::Stdio {
        match self {
            StderrTarget::Null => std::process::Stdio::null(),
            StderrTarget::Inherit => std::process::Stdio::inherit(),
            StderrTarget::Log(p) => OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .map(std::process::Stdio::from)
                .unwrap_or_else(|_| std::process::Stdio::null()),
        }
    }
}

/// Result of a successful `start_proxy`.
///
/// `#[allow(dead_code)]` on `port`: the Stage 3 CLI shells render
/// `listen_addr` (which contains both host:port) and don't need the
/// numeric port separately. Kept for callers that need port-only access
/// without re-parsing.
#[derive(Debug, Clone)]
pub struct RunningState {
    pub pid: u32,
    #[allow(dead_code)]
    pub port: u16,
    pub listen_addr: String,
}

/// Start the proxy, blocking until it's healthy or fails.
///
/// **Atomicity contract** (invariant I-2): on `Ok`, the on-disk state
/// (pidfile + sidecar meta) is consistent and the proxy is responding
/// on `/health`. On `Err`, the spawned child (if any) is killed and
/// pidfile + sidecar are cleaned — no half-state survives.
///
/// Caller is responsible for: vault password validation (do it before
/// calling this — `executor::list_secrets` is the standard helper),
/// resolving config + binary paths.
///
/// Acquires the lifecycle lock for the whole operation; `restart_proxy`
/// uses [`start_proxy_locked`] directly to avoid double-acquire.
pub fn start_proxy(
    password: &SecretString,
    opts: StartOptions,
) -> Result<RunningState, StartError> {
    let _lock = acquire_lifecycle_lock().map_err(|_| StartError::LockBusy)?;
    start_proxy_locked(password, opts)
}

// ---------------------------------------------------------------------------
// stop_proxy() — T2-4
// ---------------------------------------------------------------------------

/// Stop the proxy, blocking until the PID is dead AND the port is free.
/// Defaults to a 30s graceful drain (aligned with proxy's
/// `srv.Shutdown(30s)`) followed by a 5s SIGKILL fallback.
///
/// **Safety contract** (invariants I-1 + I-7a + I-7b): only PIDs that
/// Layer 1 classifies as `Running` or `Unresponsive` are signalled.
/// `OrphanedPort` (PID recycled to non-proxy / different aikey-proxy
/// instance / external port holder) returns `Err(StopError::NotOurs)`
/// without sending any signal — caller surfaces the diagnostic.
///
/// `timeout` controls the SIGTERM-wait phase. If the PID hasn't died
/// by then we escalate to SIGKILL with a hard `SIGKILL_GRACE` cap.
///
/// `progress` is called every 5s during the wait with a single-line
/// status message — keeps the user informed without claiming to know
/// what proxy is doing internally.
/// Stop the proxy, blocking until the PID is dead AND the port is free.
///
/// See [`stop_proxy_locked`] for the full contract — this wrapper just
/// adds the lifecycle-lock acquisition. Use [`stop_proxy_locked`]
/// directly when you already hold the lock (e.g., inside `restart_proxy`).
///
/// `listen_addr` is the configured listen address from `aikey-proxy.yaml`
/// — used to probe the right port + interface for the "is the port
/// released yet" check. Caller (Layer 3 shell) is responsible for
/// providing it; sidecar meta is consulted as a *secondary* source
/// when the user's CLI invocation doesn't have access to the live
/// config (e.g., during `aikey proxy stop` when the proxy was started
/// with a different config file). See Round-6 review fix #3.
pub fn stop_proxy(
    listen_addr: &str,
    timeout: Duration,
    progress: impl FnMut(&str),
) -> Result<(), StopError> {
    let _lock = acquire_lifecycle_lock().map_err(|_| StopError::LockBusy)?;
    stop_proxy_locked(listen_addr, timeout, progress)
}

// ---------------------------------------------------------------------------
// restart_proxy() — T2-5
// ---------------------------------------------------------------------------

/// Stop then start, all under a single lifecycle-lock acquisition.
///
/// Holding the lock across both phases prevents another CLI invocation
/// from racing in and starting a different proxy in the gap.
pub fn restart_proxy(
    password: &SecretString,
    opts: StartOptions,
    stop_timeout: Duration,
    progress: impl FnMut(&str),
) -> Result<RunningState, RestartError> {
    // Acquire lock once for the whole compound operation.
    let _lock = acquire_lifecycle_lock().map_err(|_| RestartError::LockBusy)?;
    // Phase 1: stop. Drop the lock-acquire wrapping by calling the
    // private "no-lock" variants to avoid double-acquire deadlock.
    // listen_addr passed explicitly (Round-6 review fix #3): use the
    // address from `opts` so phase-1 stop probes the same port as
    // phase-2 start will bind.
    let listen_addr = opts.listen_addr.clone();
    stop_proxy_locked(&listen_addr, stop_timeout, progress).map_err(RestartError::Stop)?;
    // Phase 2: start.
    start_proxy_locked(password, opts).map_err(RestartError::Start)
}

/// Failure modes from [`restart_proxy`]. Distinguishes which phase
/// failed so the user-facing error message can be precise.
#[derive(Debug)]
pub enum RestartError {
    LockBusy,
    Stop(StopError),
    Start(StartError),
}

impl std::fmt::Display for RestartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestartError::LockBusy => write!(f, "another aikey proxy command is in flight"),
            RestartError::Stop(e) => write!(f, "stop phase: {e}"),
            RestartError::Start(e) => write!(f, "start phase: {e}"),
        }
    }
}

impl std::error::Error for RestartError {}

/// **Canonical stop implementation** — caller is responsible for
/// holding the lifecycle lock.
///
/// Use [`stop_proxy`] (which acquires the lock for you) unless you
/// already hold the lock (e.g., inside `restart_proxy`'s compound
/// stop+start).
///
/// **Safety contract** (invariants I-1 + I-7a + I-7b): only PIDs
/// that Layer 1 classifies as `Running` or `Unresponsive` are
/// signalled. `OrphanedPort` (PID recycled to non-proxy / different
/// aikey-proxy instance / external port holder) returns
/// `Err(StopError::NotOurs)` without sending any signal — caller
/// surfaces the diagnostic.
///
/// `timeout` controls the SIGTERM-wait phase (typically
/// [`DEFAULT_STOP_TIMEOUT`] = 30s, aligned with proxy's own
/// `srv.Shutdown(30s)`). On timeout we escalate to SIGKILL with a
/// hard `SIGKILL_GRACE` cap.
///
/// `progress` is called every [`STOP_PROGRESS_INTERVAL`] during the
/// wait with a single-line status message — keeps the user informed
/// without claiming to know what proxy is doing internally.
///
/// Records a [`crate::proxy_events::TransitionEvent`] on entry/exit so
/// the events log captures every stop attempt with its outcome.
pub fn stop_proxy_locked(
    listen_addr: &str,
    timeout: Duration,
    progress: impl FnMut(&str),
) -> Result<(), StopError> {
    let start_ts = Instant::now();
    // Round-6 review fix #6: capture the entry state and the affected
    // PID so the events log records real forensic data instead of
    // "*" + None.
    let mut entry_state_label = String::from("?");
    let mut entry_pid: Option<u32> = None;
    let mut entry_port: Option<u16> = None;
    let result = stop_proxy_locked_inner(
        listen_addr,
        timeout,
        progress,
        &mut entry_state_label,
        &mut entry_pid,
        &mut entry_port,
    );
    let duration_ms = start_ts.elapsed().as_millis();
    let (event, reason) = match &result {
        Ok(()) => ("proxy.state.transition", None),
        Err(e) => ("proxy.state.transition_failed", Some(format!("{e}"))),
    };
    crate::proxy_events::record(&crate::proxy_events::TransitionEvent {
        ts: crate::proxy_events::now_ts(),
        event,
        from: &entry_state_label,
        to: "Stopped",
        trigger: "stop_proxy_locked",
        duration_ms,
        pid: entry_pid,
        port: entry_port,
        reason,
    });
    result
}

fn stop_proxy_locked_inner(
    listen_addr: &str,
    timeout: Duration,
    mut progress: impl FnMut(&str),
    entry_state_label: &mut String,
    entry_pid: &mut Option<u32>,
    entry_port: &mut Option<u16>,
) -> Result<(), StopError> {
    let pid_p = pid_path().map_err(|e| StopError::KillFailed(format!("pid_path: {e}")))?;
    let meta_p = meta_path().map_err(|e| StopError::KillFailed(format!("meta_path: {e}")))?;
    // Round-6 review fix #3: caller-supplied listen_addr is the
    // PRIMARY source. Sidecar meta is read only to cross-check (and is
    // already the source of ownership in compute_proxy_state). The old
    // hardcoded "127.0.0.1:27200" fallback caused wrong-port lsof
    // lookups when the user ran on a non-default port + lost the
    // sidecar (e.g., manual cleanup).
    let inputs = StateInputs {
        pid_path: pid_p.clone(),
        meta_path: meta_p.clone(),
        listen_addr: listen_addr.to_string(),
    };
    let (pid, port) = match proxy_state::compute_proxy_state(&inputs) {
        ProxyState::Stopped => {
            *entry_state_label = "Stopped".into();
            return Ok(());
        }
        ProxyState::Crashed { stale_pid } => {
            *entry_state_label = "Crashed".into();
            *entry_pid = Some(stale_pid);
            best_effort_remove(&pid_p);
            best_effort_remove(&meta_p);
            return Ok(());
        }
        ProxyState::Running { pid, port, .. } => {
            *entry_state_label = "Running".into();
            *entry_pid = Some(pid);
            *entry_port = Some(port);
            (pid, port)
        }
        ProxyState::Unresponsive { pid, port } => {
            *entry_state_label = "Unresponsive".into();
            *entry_pid = Some(pid);
            *entry_port = Some(port);
            (pid, port)
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            *entry_state_label = "OrphanedPort".into();
            *entry_pid = owner_pid;
            *entry_port = Some(port);
            return Err(StopError::NotOurs { port, owner_pid, reason });
        }
    };
    kill_pid_signal(pid, false)?;
    let deadline = Instant::now() + timeout;
    let mut last_progress = Instant::now();
    loop {
        if !proxy_proc::process_alive(pid) && !port_is_bound(port) {
            best_effort_remove(&pid_p);
            best_effort_remove(&meta_p);
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        if last_progress.elapsed() >= STOP_PROGRESS_INTERVAL {
            progress("[aikey] proxy still stopping... waiting up to 30s for graceful shutdown");
            last_progress = Instant::now();
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }
    let _ = kill_pid_signal(pid, true);
    let kill_deadline = Instant::now() + SIGKILL_GRACE;
    loop {
        if !proxy_proc::process_alive(pid) && !port_is_bound(port) {
            best_effort_remove(&pid_p);
            best_effort_remove(&meta_p);
            return Ok(());
        }
        if Instant::now() >= kill_deadline {
            return Err(StopError::StuckAfterKill { pid, port });
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }
}

/// **Canonical start implementation** — caller is responsible for
/// holding the lifecycle lock.
///
/// Use [`start_proxy`] (which acquires the lock for you) unless you
/// already hold the lock (e.g., inside `restart_proxy`'s compound
/// stop+start).
///
/// **Atomicity contract** (invariant I-2): on `Ok`, the on-disk state
/// (pidfile + sidecar meta) is consistent and the proxy is responding
/// on `/health`. On `Err`, the spawned child (if any) is killed and
/// pidfile + sidecar are cleaned via [`StartCleanupGuard`] — no
/// half-state survives, even on panic / `?` propagation.
///
/// Caller is responsible for: vault password validation (do it before
/// calling this — `executor::list_secrets` is the standard helper),
/// resolving config + binary paths.
///
/// Records a [`crate::proxy_events::TransitionEvent`] on entry/exit
/// (success or failure) so `~/.aikey/logs/proxy-state-events.jsonl`
/// has a forensic record of every spawn attempt.
pub fn start_proxy_locked(
    password: &SecretString,
    opts: StartOptions,
) -> Result<RunningState, StartError> {
    let trigger = "start_proxy_locked";
    let start_ts = Instant::now();
    // Round-6 review fix #6: capture the entry state observed by Layer 1
    // before spawn so the events log records what we *transitioned from*
    // (e.g., Stopped, Crashed, Unresponsive) rather than the meaningless
    // "*" wildcard. Inner sets these via out-params before mutating
    // anything.
    let mut entry_state_label = String::from("?");
    let result = start_proxy_locked_inner(password, opts, &mut entry_state_label);
    let duration_ms = start_ts.elapsed().as_millis();
    let port = match &result {
        Ok(s) => Some(s.port),
        Err(_) => None,
    };
    let pid = match &result {
        Ok(s) => Some(s.pid),
        Err(_) => None,
    };
    let (event, to, reason) = match &result {
        Ok(_) => ("proxy.state.transition", "Running", None),
        Err(e) => (
            "proxy.state.transition_failed",
            "Running",
            Some(format!("{e}")),
        ),
    };
    crate::proxy_events::record(&crate::proxy_events::TransitionEvent {
        ts: crate::proxy_events::now_ts(),
        event,
        from: &entry_state_label,
        to,
        trigger,
        duration_ms,
        pid,
        port,
        reason,
    });
    result
}

fn start_proxy_locked_inner(
    password: &SecretString,
    opts: StartOptions,
    entry_state_label: &mut String,
) -> Result<RunningState, StartError> {
    let pid_p = pid_path().map_err(|e| StartError::PersistFailed(format!("pid_path: {e}")))?;
    let meta_p = meta_path().map_err(|e| StartError::PersistFailed(format!("meta_path: {e}")))?;
    let inputs = StateInputs {
        pid_path: pid_p.clone(),
        meta_path: meta_p.clone(),
        listen_addr: opts.listen_addr.clone(),
    };
    match proxy_state::compute_proxy_state(&inputs) {
        ProxyState::Running { pid, port, listen_addr } => {
            *entry_state_label = "Running".into();
            return Ok(RunningState { pid, port, listen_addr });
        }
        ProxyState::Crashed { .. } => {
            *entry_state_label = "Crashed".into();
            best_effort_remove(&pid_p);
            best_effort_remove(&meta_p);
        }
        ProxyState::Unresponsive { pid, port } => {
            *entry_state_label = "Unresponsive".into();
            // **Round 7 review fix (HIGH)**: previously a best-effort
            // SIGTERM + 5s wait + unconditional file delete. If the old
            // proxy was still alive (e.g., handling a long-running
            // request) we'd remove the ownership anchor while the
            // process kept running → double-instance window or false
            // OrphanedPort on the next caller. Now we use the same
            // SIGTERM(30s) → SIGKILL(5s) escalation as `stop_proxy`
            // and refuse to proceed if it's stuck.
            //
            // Files are only deleted AFTER PID confirmed dead + port
            // confirmed released (invariant I-1 / I-2 cleanup ordering).
            if let Err((stuck_pid, stuck_port)) = terminate_unresponsive(pid, port) {
                return Err(StartError::UnresponsiveStuck {
                    pid: stuck_pid,
                    port: stuck_port,
                });
            }
            best_effort_remove(&pid_p);
            best_effort_remove(&meta_p);
        }
        ProxyState::OrphanedPort { port, owner_pid, reason } => {
            *entry_state_label = "OrphanedPort".into();
            return Err(StartError::OrphanedPort { port, owner_pid, reason });
        }
        ProxyState::Stopped => {
            *entry_state_label = "Stopped".into();
        }
    }
    // Round-6 review fix #2 (BLOCKING): NO defensive port_is_bound /
    // http_health_ok pre-check here. On macOS the port may sit briefly
    // in TIME_WAIT after our own `aikey proxy stop` released it, and
    // `TcpListener::bind` (used inside `port_is_bound`) treats
    // TIME_WAIT as EADDRINUSE for several seconds → spurious
    // OrphanedPort returned even though Layer 1 just classified
    // Stopped. Layer 1 is the source of truth; if it returned Stopped
    // we trust it and let the proxy's own bind() surface real
    // failures (which become ChildDiedAtStartup with the proxy's
    // stderr log path).
    let port = parse_port(&opts.listen_addr);
    if !opts.binary_path.exists() {
        return Err(StartError::BinaryMissing(opts.binary_path.display().to_string()));
    }
    if !opts.config_path.exists() {
        return Err(StartError::ConfigMissing(opts.config_path.display().to_string()));
    }
    let mut cmd = std::process::Command::new(&opts.binary_path);
    cmd.arg("--config").arg(&opts.config_path);
    for (k, v) in &opts.extra_env {
        cmd.env(k, v);
    }
    cmd.env("AIKEY_MASTER_PASSWORD", password.expose_secret());
    cmd.stdout(std::process::Stdio::null());
    let stderr_log_path = match &opts.stderr_target {
        StderrTarget::Log(p) => p.clone(),
        StderrTarget::Null | StderrTarget::Inherit => PathBuf::from("/dev/null"),
    };
    cmd.stderr(opts.stderr_target.into_stdio());
    let child = cmd.spawn()
        .map_err(|e| StartError::SpawnFailed(format!("{e}")))?;
    let child_pid = child.id();

    // **Round-6 review fix #1 (BLOCKING)**: Install Drop guard
    // IMMEDIATELY after spawn — *before* any operation that can early-
    // return (process_birth_token, MetaV1 build, atomic_write). The
    // guard's `best_effort_remove` handles paths that don't yet exist,
    // so it's safe to install before the sidecar/pidfile writes.
    //
    // We move the Child handle INTO the guard so its Drop also waits
    // for the child to be reaped (zombie prevention). Child.wait() is
    // called inside the guard's Drop after SIGTERM.
    let guard = StartCleanupGuard::new(child_pid, pid_p.clone(), meta_p.clone(), Some(child));

    // Centralized in `persist_ownership_files` so foreground / detached
    // paths share one implementation (Round 7 review fix #2).
    if let Err(e) = persist_ownership_files(
        child_pid,
        &opts.binary_path,
        &opts.config_path,
        &opts.listen_addr,
    ) {
        // Map the helper's generic ChildDiedAtStartup (with /dev/null
        // placeholder) to one carrying THIS caller's real stderr log.
        return Err(match e {
            StartError::ChildDiedAtStartup { .. } => {
                StartError::ChildDiedAtStartup { stderr_log: stderr_log_path }
            }
            other => other,
        });
    }
    let deadline = Instant::now() + opts.healthy_deadline;
    loop {
        if !proxy_proc::process_alive(child_pid) {
            return Err(StartError::ChildDiedAtStartup { stderr_log: stderr_log_path });
        }
        if proxy_proc::http_health_ok(port, Duration::from_millis(500)) {
            guard.commit();
            return Ok(RunningState {
                pid: child_pid,
                port,
                listen_addr: opts.listen_addr,
            });
        }
        if Instant::now() >= deadline {
            return Err(StartError::HealthyTimeout { stderr_log: stderr_log_path });
        }
        std::thread::sleep(HEALTHY_POLL_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse `host:port` → port. Defaults to 27200 if malformed.
fn parse_port(listen_addr: &str) -> u16 {
    listen_addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(27200)
}

/// **Fast** port-busy probe via `TcpListener::bind`. Microsecond-level
/// vs `port_owner_pid`'s ~10-20ms lsof spawn — the difference matters
/// in `stop_proxy`'s 30s poll loop (300 iterations).
///
/// Returns `true` when bind fails with `EADDRINUSE` (= port held by
/// somebody on ANY interface) and `false` when bind succeeds (= port
/// is free on ALL interfaces, we immediately drop the listener so we
/// don't actually take it).
///
/// **Round-6 review fix #7**: probes `0.0.0.0:port` instead of
/// `127.0.0.1:port`. `0.0.0.0` bind fails if ANY interface — loopback
/// OR LAN IP — has the port held. The previous `127.0.0.1`-only
/// probe gave false negatives for `0.0.0.0` / `192.168.x.y`
/// configurations: stop_proxy could return "port released" while the
/// proxy was actually still bound to the LAN IP.
///
/// `port_owner_pid` is reserved for the case where we need the OWNER
/// PID for user-facing diagnostics (e.g., `OrphanedPort` error).
fn port_is_bound(port: u16) -> bool {
    match std::net::TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => {
            drop(listener);
            false
        }
        // EADDRINUSE / EACCES / etc. — anything that prevents bind is
        // "port not available to us", which is what callers care about.
        Err(_) => true,
    }
}

/// Reuse the same SIGTERM-then-SIGKILL escalation that `stop_proxy`
/// uses, returning `Ok(())` only when the PID is confirmed dead AND
/// the port is confirmed released. Used by `start_proxy_locked_inner`
/// when the entry state is `Unresponsive` (= our previous instance
/// stuck) and we need to terminate it before spawning a replacement.
///
/// **Round 7 review fix**: the previous helper was best-effort with no
/// error path, so callers would proceed to delete pidfile + sidecar
/// even if the old process was still alive — a fast path to a
/// double-instance window. This version uses the same bounded
/// deadlines as `stop_proxy_locked_inner` (default 30s SIGTERM + 5s
/// SIGKILL grace) and propagates `Err` on stuck.
fn terminate_unresponsive(pid: u32, port: u16) -> Result<(), (u32, u16)> {
    let _ = kill_pid_signal(pid, false);
    let deadline = Instant::now() + DEFAULT_STOP_TIMEOUT;
    loop {
        if !proxy_proc::process_alive(pid) && !port_is_bound(port) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }
    let _ = kill_pid_signal(pid, true);
    let kill_deadline = Instant::now() + SIGKILL_GRACE;
    loop {
        if !proxy_proc::process_alive(pid) && !port_is_bound(port) {
            return Ok(());
        }
        if Instant::now() >= kill_deadline {
            return Err((pid, port));
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }
}

/// RFC3339 UTC timestamp without pulling in `chrono`. Format matches
/// the standard subset used in our other JSON fields. Truncates
/// fractional seconds for stability across platforms.
fn chrono_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86_400;
    let day_secs = secs % 86_400;
    let h = day_secs / 3_600;
    let m = (day_secs % 3_600) / 60;
    let s = day_secs % 60;
    // Compute Y-M-D from days-since-epoch using Howard Hinnant's
    // civil_from_days algorithm (small, MIT, no deps).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as u32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z",
        y = y, mo = mo, d = d, h = h, m = m, s = s
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC3339 formatter sanity: format roundtrips through manual
    /// parse without exotic substrings. Pinned because the manual
    /// civil_from_days arithmetic is the kind of code that fails
    /// silently when wrong.
    #[test]
    fn rfc3339_format_is_well_formed() {
        let s = chrono_now_rfc3339();
        // Shape: YYYY-MM-DDTHH:MM:SSZ — exactly 20 chars.
        assert_eq!(s.len(), 20, "unexpected length: {s:?}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
    }

    /// parse_port handles `host:port` and falls back gracefully.
    #[test]
    fn parse_port_handles_host_port_and_garbage() {
        assert_eq!(parse_port("127.0.0.1:27200"), 27200);
        assert_eq!(parse_port("0.0.0.0:8080"), 8080);
        assert_eq!(parse_port("garbage"), 27200, "fallback default");
        assert_eq!(parse_port(""), 27200, "fallback default for empty");
    }

    /// Lifecycle lock can be acquired then released by Drop. Pinned
    /// because everything else in Stage 2 depends on this primitive.
    #[test]
    fn lifecycle_lock_acquire_and_release() {
        // First acquire succeeds.
        let g1 = acquire_lifecycle_lock().expect("first acquire");
        // Second acquire from THIS thread would also succeed in fs2's
        // model (advisory lock semantics) — fs2 lock is per-file-handle,
        // not per-process, BUT we open a NEW handle in the helper. So
        // the second acquire SHOULD fail with LockBusy after timeout.
        // To keep test fast, we do not actually verify timeout
        // behaviour here (it would take 5s). Just verify drop works.
        drop(g1);
        // After drop, fresh acquire works again.
        let g2 = acquire_lifecycle_lock().expect("re-acquire after drop");
        drop(g2);
    }

    /// `atomic_write` writes the exact bytes and overwrites cleanly.
    #[test]
    fn atomic_write_overwrites_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.txt");
        atomic_write(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        atomic_write(&path, b"world").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"world");
    }

    /// `best_effort_remove` is a no-op for missing files — pinned
    /// because Drop guard / Crashed cleanup paths call it without
    /// pre-checking existence.
    #[test]
    fn best_effort_remove_silent_on_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does_not_exist");
        best_effort_remove(&path);
        // No assertion — we just want this to NOT panic.
    }
}
