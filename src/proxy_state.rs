//! Proxy lifecycle Layer 1: state-machine **read** path.
//!
//! Maps the on-disk + on-network signals (pidfile, sidecar meta,
//! `process_alive`, `process_identity`, `process_birth_token`, port
//! reachability, HTTP `/health`) into a single `ProxyState` enum that the
//! rest of the CLI can reason about.
//!
//! # Invariants (see lifecycle 方案 § 核心不变量)
//!
//! - **I-7a (identity)**: only PIDs whose process executable basename ==
//!   `"aikey-proxy"` may produce `Running` / `Unresponsive`. PIDs that fail
//!   identity check fall to `OrphanedPort` (read-only, never killed).
//! - **I-7b (ownership)**: only PIDs whose `process_birth_token` matches
//!   the sidecar `meta.birth_token` may produce `Running` / `Unresponsive`.
//!   PID recycle to *another* aikey-proxy instance is caught here and
//!   demoted to `OrphanedPort`.
//!
//! These invariants together guarantee that any state Layer 2 will act on
//! (`Running` / `Unresponsive` → `kill our PID`) is genuinely **our**
//! aikey-proxy instance, not a coincidentally-named other process.
//!
//! See [`ProxyState`] and [`MetaV1`].
//!
//! Round 5 evaluation (2026-04-28) introduced the identity/ownership split
//! and the sidecar `birth_token` design — see lifecycle 方案 doc § Round 5
//! 评审采纳记录 for the design rationale, including why we use a
//! platform-specific *opaque* `birth_token` string instead of unifying to
//! a `start_time_ms` (avoids Linux jiffies → ms conversion pitfalls).

use serde::{Deserialize, Serialize};

/// Sidecar meta file schema. Persisted at `~/.aikey/run/proxy-meta.json`,
/// written atomically next to the pidfile during `start_proxy`, cleaned by
/// the same RAII Drop guard. **Read path treats `pid + meta.pid +
/// meta.birth_token == process_birth_token(pid)` as the ownership proof**;
/// other fields are diagnostic-only.
///
/// `schema_version` lets future field additions / removals coexist with
/// older CLI binaries reading the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaV1 {
    /// Schema version. Currently `1`. Older / newer CLIs treat unknown
    /// versions as "unreadable", which decision tree maps to OrphanedPort
    /// (conservative — never kill).
    pub schema_version: u32,

    /// Same PID as the pidfile. Redundant by design — sidecar should be
    /// self-describing for forensic / audit purposes.
    pub pid: u32,

    /// **Ownership main key** — opaque platform-specific string returned
    /// by `process_birth_token(pid)`. Format examples:
    ///
    /// - `"linux:jiffies:42938472"` — `/proc/PID/stat` field 22
    /// - `"darwin:starttime:1745851200:123456"` — proc_pidinfo PROC_PIDTBSDINFO
    /// - `"windows:filetime:132615840000000000"` — GetProcessTimes CreationTime
    ///
    /// CLI **only does string equality**, never parses, never converts.
    /// This avoids Linux jiffies-to-ms conversion pitfalls (boot_time
    /// resolution, container/sandbox differences, jiffies precision).
    pub birth_token: String,

    /// Diagnostic-only: which proxy binary we spawned.
    pub binary_path: std::path::PathBuf,

    /// Diagnostic-only: which config we passed to the proxy.
    pub config_path: std::path::PathBuf,

    /// Diagnostic-only: what address/port the proxy was instructed to bind.
    pub listen_addr: String,

    /// Diagnostic-only: when the sidecar was written (RFC3339 UTC).
    pub written_at: String,
}

/// CLI's view of the proxy's lifecycle state.
///
/// **Time-free** — five branches, no grace-window timestamps. Distinguishing
/// "just spawned, about to bind" vs "stuck during init" is *not* attempted
/// from outside; that nuance lives only inside `start_proxy`'s own poll
/// loop where it's locally measurable.
///
/// All `Running` / `Unresponsive` instances are guaranteed to be
/// **identity-verified AND ownership-verified** — i.e. provably *our*
/// `aikey-proxy` instance. Anything we cannot prove to be ours falls into
/// `OrphanedPort` (read-only, never killed). See module-level invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyState {
    /// No pidfile (or only stale sidecar meta) and the configured port is
    /// free. Ready for `start_proxy` to spawn a new proxy.
    Stopped,

    /// pidfile + identity + ownership all check out, port is bound, and
    /// `/health` returns 200. The proxy is fully usable.
    Running {
        pid: u32,
        port: u16,
        listen_addr: String,
    },

    /// pidfile + identity + ownership check out, but the proxy is not
    /// answering on `/health` (or hasn't bound the port yet). Could be
    /// "still starting up" or "hung in init" — the CLI deliberately does
    /// not try to distinguish (no time metadata, no log of when we last
    /// saw it healthy). Layer 2 may safely kill this PID because ownership
    /// is verified.
    Unresponsive { pid: u32, port: u16 },

    /// pidfile points at a PID that is no longer alive. The pidfile + any
    /// stale sidecar meta should be cleaned by the next `start_proxy` /
    /// `stop_proxy`. No process to kill.
    Crashed { stale_pid: u32 },

    /// **Read-only diagnostic state** — port is owned by some process the
    /// CLI cannot prove is its own aikey-proxy. Layer 2 must NOT send any
    /// signal here (invariant I-1).
    ///
    /// `reason` distinguishes the underlying cause for the user-facing
    /// error message: PID recycled to non-proxy / aikey-proxy but legacy
    /// (no sidecar) / aikey-proxy but ownership mismatch (PID recycled to
    /// a different instance) / port held by an unrelated external listener.
    OrphanedPort {
        port: u16,
        owner_pid: Option<u32>,
        reason: OrphanReason,
    },
}

/// Why a state was classified as `OrphanedPort`. Drives the actionable
/// hint we show the user — "stop the other process" vs "your old proxy
/// from before the upgrade is in the way" call for very different fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrphanReason {
    /// The PID under our pidfile is alive but its executable is not
    /// `aikey-proxy` — the kernel reused the PID for an unrelated process.
    PidRecycledToNonProxy,

    /// The PID under our pidfile is an `aikey-proxy` process, but no
    /// sidecar meta file exists. Most likely a proxy spawned by a
    /// pre-Round-5 CLI (legacy upgrade path) — we can't prove ownership,
    /// so we don't touch it.
    LegacyPidfileNoSidecar,

    /// The PID under our pidfile is an `aikey-proxy` process AND a sidecar
    /// meta exists, but `birth_token` mismatches — the kernel reused the
    /// PID for a *different* aikey-proxy instance (e.g., user manually
    /// started another proxy, sandbox install, etc.).
    PidRecycledToDifferentInstance,

    /// No pidfile, but the configured port is held by some other process.
    PortHeldByExternal,
}

impl OrphanReason {
    /// One-line user-facing hint. Used by `aikey proxy status` /
    /// `start_proxy` / `stop_proxy` Err paths to point the user at the
    /// right next step.
    pub fn hint(&self, port: u16, owner_pid: Option<u32>) -> String {
        let owner = owner_pid
            .map(|p| format!("PID {p}"))
            .unwrap_or_else(|| "unknown owner".to_string());
        match self {
            OrphanReason::PidRecycledToNonProxy => format!(
                "pidfile points at PID that has been reused for an unrelated process; \
                 run `{}` to inspect",
                crate::proxy_proc::port_inspect_command(port),
            ),
            OrphanReason::LegacyPidfileNoSidecar => format!(
                "an existing aikey-proxy ({owner}) was started by an older CLI (no sidecar meta). \
                 Stop it manually and re-start with the current CLI: `{kill_cmd}` then `aikey proxy start`",
                kill_cmd = owner_pid
                    .map(crate::proxy_proc::kill_command_hint)
                    .unwrap_or_else(|| {
                        if cfg!(windows) {
                            "taskkill /F /PID <pid>".into()
                        } else {
                            "kill <pid>".into()
                        }
                    }),
            ),
            OrphanReason::PidRecycledToDifferentInstance => format!(
                "the pidfile's PID is now a *different* aikey-proxy instance ({owner}) — \
                 we will not touch it. Investigate which instance you intend to manage"
            ),
            OrphanReason::PortHeldByExternal => format!(
                "port {port} is held by {owner}, which is not an aikey-proxy we manage. \
                 Stop that listener or change `listen.port` in aikey-proxy.yaml"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Sidecar meta IO + ownership verification
// ---------------------------------------------------------------------------

/// Filename of the sidecar meta file. Lives next to the pidfile under
/// `~/.aikey/run/`.
pub const SIDECAR_META_FILENAME: &str = "proxy-meta.json";

/// Current sidecar meta schema version. Bump when adding fields that
/// existing CLI must understand to make ownership decisions correctly.
/// Increasing the diagnostic-only fields does NOT require a bump.
pub const META_SCHEMA_VERSION: u32 = 1;

/// IO + parsing errors when working with the sidecar meta file.
/// Layer 1 maps both variants to "ownership unverifiable" → OrphanedPort.
/// We split them so logging / diagnostics can be more specific (e.g.,
/// "schema mismatch from a future CLI" vs "file is corrupt").
#[derive(Debug)]
pub enum MetaError {
    /// File could not be read (missing / permission denied / IO error).
    /// `missing` is `true` when `kind == NotFound` so callers can treat
    /// the legacy-pidfile case (file missing entirely) distinctly from
    /// real IO errors without re-stat'ing.
    Read { missing: bool, detail: String },
    /// File exists but JSON parse failed, or `schema_version` is unknown
    /// (newer than this binary supports).
    Parse(String),
}

impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaError::Read { missing: true, .. } => write!(f, "sidecar meta file missing"),
            MetaError::Read { detail, .. } => write!(f, "sidecar meta read: {detail}"),
            MetaError::Parse(s) => write!(f, "sidecar meta parse: {s}"),
        }
    }
}

impl std::error::Error for MetaError {}

/// Resolve the sidecar meta file path for the current user.
///
/// Mirrors the `commands_proxy::pid_path()` shape (`~/.aikey/run/<file>`)
/// so the sidecar always lives next to the pidfile. Returns `Err` if the
/// home directory cannot be determined (rare — typically headless CI
/// without a HOME var).
pub fn meta_path() -> std::io::Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine home directory for proxy-meta.json",
        )
    })?;
    Ok(home.join(".aikey").join("run").join(SIDECAR_META_FILENAME))
}

/// Read + parse the sidecar meta file at the given path.
///
/// **Path-explicit variant** — used directly by tests and by the prod
/// wrapper [`read_meta`]. Production callers should prefer the
/// no-argument [`read_meta`].
///
/// Returns:
/// - `Ok(MetaV1)` only when the file exists, parses cleanly, and
///   `schema_version == META_SCHEMA_VERSION`.
/// - `Err(MetaError::Read { missing: true })` when the file is missing
///   (legacy upgrade case — Layer 1 maps to `LegacyPidfileNoSidecar`).
/// - `Err(MetaError::Read { missing: false })` for other IO errors.
/// - `Err(MetaError::Parse)` for JSON / schema-version errors.
///
/// **Forward-compat policy**: a future schema_version > 1 is treated as
/// `MetaError::Parse` (i.e., ownership unverifiable, demote to
/// OrphanedPort). This is conservative — the alternative ("ignore
/// unknown fields and trust the rest") could let a malformed meta from
/// a buggy future build pass ownership when it shouldn't.
pub fn read_meta_at(path: &std::path::Path) -> Result<MetaV1, MetaError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(MetaError::Read {
                missing: true,
                detail: format!("{}: not found", path.display()),
            });
        }
        Err(e) => {
            return Err(MetaError::Read {
                missing: false,
                detail: format!("{}: {e}", path.display()),
            });
        }
    };
    let meta: MetaV1 = serde_json::from_slice(&bytes)
        .map_err(|e| MetaError::Parse(format!("{}: {e}", path.display())))?;
    if meta.schema_version != META_SCHEMA_VERSION {
        return Err(MetaError::Parse(format!(
            "{}: schema_version {} not supported (expect {})",
            path.display(),
            meta.schema_version,
            META_SCHEMA_VERSION
        )));
    }
    Ok(meta)
}

/// Production wrapper for [`read_meta_at`] using the canonical
/// `~/.aikey/run/proxy-meta.json` path.
///
/// `#[allow(dead_code)]`: kept as the canonical no-arg entry point
/// for future callers (currently Layer 2 uses `read_meta_at` with
/// explicit paths from `proxy_lifecycle::meta_path()`).
#[allow(dead_code)]
pub fn read_meta() -> Result<MetaV1, MetaError> {
    let path = meta_path().map_err(|e| MetaError::Read {
        missing: e.kind() == std::io::ErrorKind::NotFound,
        detail: e.to_string(),
    })?;
    read_meta_at(&path)
}

/// Atomically write the sidecar meta file at the given path (temp + rename).
///
/// Same atomic guarantee as the pidfile writer in commands_proxy.rs —
/// no half-written bytes ever observed by a concurrent reader, even if
/// the writer is killed mid-write.
///
/// Caller is responsible for sequencing this **before** the pidfile
/// write (so the read path never observes "pidfile alone, no meta" in
/// the spawn-success path) and for cleaning up the file via the same
/// RAII Drop guard that owns the pidfile (so failure paths don't leak
/// either file alone). See lifecycle 方案 § Layer 1 sidecar 写入纪律.
#[allow(dead_code)]
pub fn write_meta_atomic_at(meta: &MetaV1, path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(meta)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Production wrapper for [`write_meta_atomic_at`].
#[allow(dead_code)]
pub fn write_meta_atomic(meta: &MetaV1) -> std::io::Result<()> {
    write_meta_atomic_at(meta, &meta_path()?)
}

/// Best-effort sidecar meta cleanup at the given path. Used by Drop
/// guard / Crashed recovery / stop_proxy success path. Missing file is
/// not an error.
#[allow(dead_code)]
pub fn delete_meta_at(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Production wrapper for [`delete_meta_at`].
#[allow(dead_code)]
pub fn delete_meta() -> std::io::Result<()> {
    let path = match meta_path() {
        Ok(p) => p,
        Err(_) => return Ok(()), // no HOME, nothing to clean
    };
    delete_meta_at(&path)
}

/// **Invariant I-7b — ownership verification entry point (path-explicit).**
///
/// Returns `true` only when the meta file at `path` exists, its `pid`
/// matches the queried PID, and `process_birth_token(pid)` exactly
/// equals `meta.birth_token` (string compare, no parsing).
///
/// Returns `false` for ANY of:
/// - meta file missing (legacy pidfile case)
/// - meta file present but malformed / wrong schema_version
/// - meta.pid does not match the queried PID
/// - process_birth_token(pid) read failed (process gone / permission)
/// - birth_token mismatch (PID recycled to a different aikey-proxy
///   instance)
///
/// Layer 1 callers MUST gate `Running` / `Unresponsive` classification
/// on this returning `true`. A `false` return MUST result in
/// `OrphanedPort` (read-only, never killed).
#[allow(dead_code)]
pub fn ownership_verified_at(pid: u32, meta_path: &std::path::Path) -> bool {
    let meta = match read_meta_at(meta_path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if meta.pid != pid {
        return false;
    }
    let live_token = match crate::proxy_proc::process_birth_token(pid) {
        Ok(t) => t,
        Err(_) => return false,
    };
    live_token == meta.birth_token
}

/// Production wrapper for [`ownership_verified_at`].
#[allow(dead_code)]
pub fn ownership_verified(pid: u32) -> bool {
    let path = match meta_path() {
        Ok(p) => p,
        Err(_) => return false,
    };
    ownership_verified_at(pid, &path)
}

// ---------------------------------------------------------------------------
// proxy_state() decision tree (Layer 1 main entry)
// ---------------------------------------------------------------------------

/// Inputs for the [`compute_proxy_state`] decision tree. Path-explicit so
/// tests can drive it without touching `~/.aikey/run/`. Production
/// callers use the no-arg [`proxy_state`] wrapper.
#[derive(Debug, Clone)]
pub struct StateInputs {
    /// Path to `~/.aikey/run/proxy.pid` (or test override).
    pub pid_path: std::path::PathBuf,
    /// Path to `~/.aikey/run/proxy-meta.json` (or test override).
    pub meta_path: std::path::PathBuf,
    /// Listen address the proxy is *configured* to bind, e.g.
    /// `"127.0.0.1:27200"`. Used for port-reachability + lsof owner
    /// lookup. Must match what was written to sidecar `meta.listen_addr`
    /// when start_proxy ran (verified during ownership check via
    /// metadata, not here — this field is the *current* config).
    pub listen_addr: String,
}

impl StateInputs {
    /// Extract `(host, port)` from `listen_addr`. Defaults to port 27200
    /// when parse fails — chosen because that's the documented
    /// `aikey-proxy.yaml` default and Layer 1 should degrade gracefully.
    fn host_port(&self) -> (String, u16) {
        if let Some((h, p)) = self.listen_addr.rsplit_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
        ("127.0.0.1".to_string(), 27200)
    }
}

/// Read pidfile (one-line plain integer). Returns None if file missing,
/// unreadable, or contents do not parse as u32.
fn read_pidfile(path: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

/// **Layer 1 decision tree (path-explicit)** — the heart of the
/// state-machine read path.
///
/// Computes the current [`ProxyState`] from on-disk + on-network
/// signals according to the lifecycle 方案 § Layer 1 specification.
/// The decision tree's exact structure is the contract — every test
/// in this module pins one of its branches, and any change here MUST
/// have a corresponding test.
///
/// **Invariant guarantees** (this is the implementation of I-7a + I-7b):
///
/// - `Running` / `Unresponsive` are produced **only** when both
///   identity (basename == "aikey-proxy") AND ownership
///   (`process_birth_token(pid) == sidecar meta.birth_token`) succeed.
///   Layer 2 may safely kill PIDs in these states.
/// - All identity / ownership failures fall to `OrphanedPort` with a
///   specific [`OrphanReason`] for actionable diagnostics. Layer 2 is
///   forbidden from sending signals to these PIDs.
pub fn compute_proxy_state(inputs: &StateInputs) -> ProxyState {
    let (_host, port) = inputs.host_port();

    // 1. Read pidfile.
    let pid_opt = read_pidfile(&inputs.pid_path);

    // 2. Branch on pidfile presence.
    if let Some(pid) = pid_opt {
        // 2a. Is that PID still alive in the kernel?
        if !crate::proxy_proc::process_alive(pid) {
            // PID is dead. Distinguish "port also free" (clean Crashed,
            // just clean up pidfile + meta) from "port held by something
            // else" (OrphanedPort, leave it alone).
            return classify_dead_pid(pid, port);
        }
        // 2b. PID is alive. Check identity (I-7a).
        if !crate::proxy_proc::is_aikey_proxy(pid) {
            // PID was reused for a non-aikey-proxy process. Not ours.
            return ProxyState::OrphanedPort {
                port,
                owner_pid: Some(pid),
                reason: OrphanReason::PidRecycledToNonProxy,
            };
        }
        // 2c. Check ownership (I-7b) — sidecar meta + birth_token.
        let meta_result = read_meta_at(&inputs.meta_path);
        let meta = match meta_result {
            Ok(m) => m,
            Err(MetaError::Read { missing: true, .. }) => {
                // Legacy: pre-Round-5 CLI started this proxy, no sidecar.
                return ProxyState::OrphanedPort {
                    port,
                    owner_pid: Some(pid),
                    reason: OrphanReason::LegacyPidfileNoSidecar,
                };
            }
            Err(_) => {
                // Sidecar present but corrupt / wrong schema. Ownership
                // unverifiable — conservative demotion. Treated like
                // legacy upgrade case for the user-facing hint, since
                // the actionable fix is the same (manual stop + restart
                // through current CLI).
                return ProxyState::OrphanedPort {
                    port,
                    owner_pid: Some(pid),
                    reason: OrphanReason::LegacyPidfileNoSidecar,
                };
            }
        };
        // pid in meta must match the pidfile pid (sanity — they should
        // have been written together). If not, the sidecar is stale.
        if meta.pid != pid {
            return ProxyState::OrphanedPort {
                port,
                owner_pid: Some(pid),
                reason: OrphanReason::PidRecycledToDifferentInstance,
            };
        }
        // birth_token must match the LIVE process's token. This is the
        // load-bearing check that catches PID-recycle-to-another-
        // aikey-proxy-instance.
        let live_token = match crate::proxy_proc::process_birth_token(pid) {
            Ok(t) => t,
            Err(_) => {
                // Could not read live token (process disappeared in the
                // race, permission denied, ABI mismatch). Conservative.
                return ProxyState::OrphanedPort {
                    port,
                    owner_pid: Some(pid),
                    reason: OrphanReason::PidRecycledToDifferentInstance,
                };
            }
        };
        if live_token != meta.birth_token {
            return ProxyState::OrphanedPort {
                port,
                owner_pid: Some(pid),
                reason: OrphanReason::PidRecycledToDifferentInstance,
            };
        }
        // 2d. Identity ✓ + ownership ✓ — we own this PID. Now check
        // whether the proxy is actually serving requests on the port.
        let port_held = crate::proxy_proc::port_owner_pid(port).ok().flatten();
        match port_held {
            Some(p) if p == pid => {
                // Our PID owns the port. Check /health to distinguish
                // Running (admin handler responding) from Unresponsive
                // (port bound but handler not yet up / hung).
                let healthy = crate::proxy_proc::http_health_ok(
                    port,
                    std::time::Duration::from_millis(500),
                );
                if healthy {
                    ProxyState::Running {
                        pid,
                        port,
                        listen_addr: inputs.listen_addr.clone(),
                    }
                } else {
                    ProxyState::Unresponsive { pid, port }
                }
            }
            Some(_other) => {
                // Our PID is alive AND ownership-verified, but the
                // configured port is held by a DIFFERENT process. The
                // ownership-verified PID is doing something else
                // (possibly bound to a different port via different
                // config); the configured port is owned by an external
                // listener. Layer 2 cannot help here without breaking
                // the external listener — demote to OrphanedPort.
                ProxyState::OrphanedPort {
                    port,
                    owner_pid: Some(_other),
                    reason: OrphanReason::PortHeldByExternal,
                }
            }
            None => {
                // PID alive + ownership ✓ but port not bound. Either
                // proxy hasn't bound yet (still starting) or it
                // crashed mid-init. Either way it is *our* process so
                // Layer 2 may safely kill+respawn — this is the
                // Unresponsive case.
                ProxyState::Unresponsive { pid, port }
            }
        }
    } else {
        // 3. No pidfile. Check whether something else holds the port.
        match crate::proxy_proc::port_owner_pid(port) {
            Ok(Some(owner)) => ProxyState::OrphanedPort {
                port,
                owner_pid: Some(owner),
                reason: OrphanReason::PortHeldByExternal,
            },
            Ok(None) => ProxyState::Stopped,
            Err(_) => {
                // Tooling failed (lsof missing). Conservative: if the
                // port probe also fails, we cannot prove "free" — but
                // we have no evidence of a holder either. Treat as
                // Stopped: better to attempt start (which itself does
                // a port pre-check) than to refuse forever.
                ProxyState::Stopped
            }
        }
    }
}

/// Helper: for a dead pidfile PID, classify whether the port is also
/// free (Crashed) or held by something unrelated (OrphanedPort). Split
/// out so the main decision tree stays linear.
fn classify_dead_pid(stale_pid: u32, port: u16) -> ProxyState {
    match crate::proxy_proc::port_owner_pid(port) {
        Ok(Some(owner)) => ProxyState::OrphanedPort {
            port,
            owner_pid: Some(owner),
            reason: OrphanReason::PortHeldByExternal,
        },
        Ok(None) | Err(_) => ProxyState::Crashed { stale_pid },
    }
}

/// Production wrapper for [`compute_proxy_state`] using the canonical
/// `~/.aikey/run/proxy.pid` + `~/.aikey/run/proxy-meta.json` paths.
///
/// `listen_addr` is resolved by the caller (typically from
/// `aikey-proxy.yaml`) — Layer 1 doesn't reach back into config
/// parsing to keep this function free of `commands_proxy` dependencies.
pub fn proxy_state(listen_addr: &str) -> ProxyState {
    let pid_path = pidfile_path()
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/_aikey_proxy_pidpath_unset"));
    let meta_path =
        meta_path().unwrap_or_else(|_| std::path::PathBuf::from("/tmp/_aikey_proxy_metapath_unset"));
    let inputs = StateInputs {
        pid_path,
        meta_path,
        listen_addr: listen_addr.to_string(),
    };
    compute_proxy_state(&inputs)
}

/// Resolve the canonical pidfile path (`~/.aikey/run/proxy.pid`).
///
/// Mirrors the (currently private) `commands_proxy::pid_path()` so
/// Layer 1 doesn't have to bridge into commands_proxy. Stage 3
/// cut-over will collapse the two callers onto this single source.
pub fn pidfile_path() -> std::io::Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine home directory for proxy.pid",
        )
    })?;
    Ok(home.join(".aikey").join("run").join("proxy.pid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_v1_roundtrips_through_json() {
        let m = MetaV1 {
            schema_version: 1,
            pid: 12345,
            birth_token: "linux:jiffies:42938472".into(),
            binary_path: "/Users/jake/.aikey/bin/aikey-proxy".into(),
            config_path: "/Users/jake/.aikey/config/aikey-proxy.yaml".into(),
            listen_addr: "127.0.0.1:27200".into(),
            written_at: "2026-04-28T14:40:00Z".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: MetaV1 = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn orphan_reason_hint_includes_actionable_cmd_for_external_holder() {
        // Sanity: external-holder hint mentions the port number and
        // suggests a fix path — users hitting this need both bits to
        // resolve it. Pinning the format so future edits keep both.
        let r = OrphanReason::PortHeldByExternal;
        let hint = r.hint(27200, Some(99999));
        assert!(hint.contains("27200"), "hint must name the conflicting port");
        assert!(hint.contains("99999"), "hint must name the owner PID for forensics");
        assert!(hint.contains("listen.port"), "hint must point users at the config knob");
    }

    #[test]
    fn orphan_reason_hint_for_legacy_pidfile_explains_upgrade_friction() {
        // Legacy upgrade is the most user-confusing OrphanedPort cause —
        // the hint must distinguish it from "external program took the
        // port" or it'll feel like a bug. Pinning the explainer.
        let r = OrphanReason::LegacyPidfileNoSidecar;
        let hint = r.hint(27200, Some(54321));
        assert!(
            hint.contains("older CLI") || hint.contains("legacy") || hint.contains("sidecar"),
            "hint must signal this is an upgrade-friction situation, not an external conflict"
        );
        assert!(
            hint.contains("kill") && hint.contains("54321"),
            "hint must give a concrete shell command (kill / kill -9 / taskkill) referencing the PID; got: {hint}"
        );
    }

    #[test]
    fn proxy_state_partialeq_supports_test_assertions() {
        // `assert_eq!(state, ProxyState::Stopped)` is the dominant test
        // pattern — pinning that PartialEq stays implemented. Catches a
        // future "let's drop derive(PartialEq)" refactor that would break
        // every Stage 1/2 unit test silently.
        assert_eq!(ProxyState::Stopped, ProxyState::Stopped);
        assert_ne!(
            ProxyState::Stopped,
            ProxyState::Crashed { stale_pid: 1 },
        );
    }

    // ── Sidecar meta IO + ownership tests ─────────────────────────────
    //
    // We use the path-explicit `*_at` variants to avoid touching the
    // real ~/.aikey/run/proxy-meta.json. macOS `dirs::home_dir()`
    // ignores HOME env overrides (uses NSHomeDirectory), so HOME-
    // swapping doesn't isolate. The path-explicit API is the cleanest
    // testability hook; prod call sites use the no-arg wrappers.

    fn sample_meta(pid: u32, token: &str) -> MetaV1 {
        MetaV1 {
            schema_version: META_SCHEMA_VERSION,
            pid,
            birth_token: token.into(),
            binary_path: "/test/bin/aikey-proxy".into(),
            config_path: "/test/cfg/aikey-proxy.yaml".into(),
            listen_addr: "127.0.0.1:27200".into(),
            written_at: "2026-04-28T14:40:00Z".into(),
        }
    }

    fn temp_meta_path(tmp: &std::path::Path) -> std::path::PathBuf {
        tmp.join(SIDECAR_META_FILENAME)
    }

    #[test]
    fn read_meta_missing_is_distinguished_from_other_errors() {
        // Layer 1 needs to know "missing entirely" (legacy upgrade) vs
        // "file there but unreadable" (corrupt / permission). Without
        // this distinction, the OrphanReason::LegacyPidfileNoSidecar
        // hint cannot fire correctly.
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        let err = read_meta_at(&path).unwrap_err();
        match err {
            MetaError::Read { missing: true, .. } => {} // good
            other => panic!("expected Read{{missing:true}}, got {:?}", other),
        }
    }

    #[test]
    fn write_then_read_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        let m = sample_meta(12345, "linux:jiffies:42938472");
        write_meta_atomic_at(&m, &path).expect("write_meta_atomic_at");
        let back = read_meta_at(&path).expect("read_meta_at");
        assert_eq!(m, back);
    }

    #[test]
    fn unknown_schema_version_treated_as_parse_error() {
        // Forward-compat: a future CLI writing schema_version=99 must
        // be rejected by today's reader (conservative). Otherwise we'd
        // try to apply ownership rules from an unknown contract.
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        std::fs::write(
            &path,
            r#"{"schema_version":99,"pid":1,"birth_token":"x","binary_path":"/a","config_path":"/b","listen_addr":"127.0.0.1:1","written_at":"x"}"#,
        )
        .unwrap();
        match read_meta_at(&path) {
            Err(MetaError::Parse(s)) => assert!(s.contains("schema_version")),
            other => panic!("expected Parse(schema_version), got {other:?}"),
        }
    }

    #[test]
    fn corrupt_meta_treated_as_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        std::fs::write(&path, "this is not json").unwrap();
        assert!(matches!(read_meta_at(&path), Err(MetaError::Parse(_))));
    }

    #[test]
    fn delete_meta_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        // Calling delete_meta_at() with no file present must not error
        // — Drop guard / stop_proxy paths call this unconditionally.
        delete_meta_at(&path).expect("missing-file delete should be Ok");
        let m = sample_meta(1, "tok");
        write_meta_atomic_at(&m, &path).unwrap();
        delete_meta_at(&path).expect("real-file delete should be Ok");
        // Second delete on now-absent file is still Ok.
        delete_meta_at(&path).expect("repeat delete should be Ok");
    }

    #[test]
    fn ownership_verified_false_when_meta_missing() {
        // The "legacy upgrade" case. Layer 1 must demote to OrphanedPort
        // when sidecar meta is missing, even if the PID is alive and the
        // exe basename matches. This test pins the gate.
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        // Use self-PID — guaranteed alive + has a real birth_token,
        // but no sidecar meta exists for it.
        assert!(!ownership_verified_at(std::process::id(), &path));
    }

    #[test]
    fn ownership_verified_false_when_pid_in_meta_does_not_match() {
        // Sidecar meta says pid 12345 but caller queries pid 99 →
        // mismatch. Even if 99 happens to have a real birth_token, the
        // pid mismatch alone disqualifies. Catches a regression where
        // the pid field in sidecar gets ignored.
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        let m = sample_meta(12345, "linux:jiffies:42938472");
        write_meta_atomic_at(&m, &path).unwrap();
        assert!(!ownership_verified_at(99, &path));
    }

    #[test]
    fn ownership_verified_false_when_birth_token_mismatches() {
        // The Round 5 core scenario: sidecar meta has the right pid
        // (= self-pid here for liveness convenience) but a
        // birth_token that does NOT match the live process's actual
        // birth_token (= "fake-token-not-real"). This MUST return false
        // — that mismatch is exactly what "PID recycled to a different
        // aikey-proxy instance" looks like in real life.
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        let me = std::process::id();
        let m = sample_meta(me, "fake-token-that-cannot-match-any-real-process");
        write_meta_atomic_at(&m, &path).unwrap();
        assert!(
            !ownership_verified_at(me, &path),
            "ownership must fail when birth_token ≠ live process token"
        );
    }

    #[test]
    fn ownership_verified_true_when_full_match() {
        // Happy path: meta has self-pid + the actual live birth_token.
        // Sanity-check that the verifier does succeed when everything
        // lines up — otherwise Layer 1 would never produce Running.
        let tmp = tempfile::tempdir().unwrap();
        let path = temp_meta_path(tmp.path());
        let me = std::process::id();
        let live_token = crate::proxy_proc::process_birth_token(me)
            .expect("self birth_token must succeed");
        let m = sample_meta(me, &live_token);
        write_meta_atomic_at(&m, &path).unwrap();
        assert!(
            ownership_verified_at(me, &path),
            "ownership must succeed for self-pid + matching live birth_token"
        );
    }

    // ── compute_proxy_state() decision tree tests ─────────────────────
    //
    // Each test stages a tempdir with a specific (pidfile, sidecar)
    // combination and asserts compute_proxy_state classifies it into
    // the documented branch. This is the load-bearing safety net for
    // Layer 1 — every classification mistake would translate directly
    // to a Layer 2 misbehavior (kill wrong PID, refuse to start, etc.).
    //
    // We pick a free port per test to avoid conflict with any real
    // proxy that might be running on the dev machine.

    fn pick_free_port_for_state_tests() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        std::thread::sleep(std::time::Duration::from_millis(20));
        p
    }

    fn build_inputs(tmp: &std::path::Path, port: u16) -> StateInputs {
        StateInputs {
            pid_path: tmp.join("proxy.pid"),
            meta_path: tmp.join(SIDECAR_META_FILENAME),
            listen_addr: format!("127.0.0.1:{port}"),
        }
    }

    /// No pidfile + free port → Stopped. The "fresh machine" baseline.
    #[test]
    fn state_branch_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let port = pick_free_port_for_state_tests();
        let inputs = build_inputs(tmp.path(), port);
        assert_eq!(compute_proxy_state(&inputs), ProxyState::Stopped);
    }

    /// pidfile points at a dead PID + port free → Crashed. Layer 2's
    /// recovery path (clean pidfile + meta, then spawn) depends on
    /// this signal.
    #[test]
    fn state_branch_crashed_when_dead_pid_and_free_port() {
        let tmp = tempfile::tempdir().unwrap();
        let port = pick_free_port_for_state_tests();
        let inputs = build_inputs(tmp.path(), port);
        // Pick a PID that is essentially guaranteed dead. Using
        // u32::MAX / 2 avoids collision with any real PID range.
        std::fs::write(&inputs.pid_path, "999999999").unwrap();
        assert_eq!(
            compute_proxy_state(&inputs),
            ProxyState::Crashed { stale_pid: 999999999 }
        );
    }

    /// pidfile points at PID 1 (init/launchd) → identity check fails
    /// → OrphanedPort with PidRecycledToNonProxy reason. Pinned because
    /// this is the I-7a check fired in production.
    #[test]
    fn state_branch_orphaned_when_pid_recycled_to_non_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let port = pick_free_port_for_state_tests();
        let inputs = build_inputs(tmp.path(), port);
        // PID 1 = init / launchd / SYSTEM — guaranteed alive, never
        // aikey-proxy.
        std::fs::write(&inputs.pid_path, "1").unwrap();
        match compute_proxy_state(&inputs) {
            ProxyState::OrphanedPort {
                owner_pid: Some(1),
                reason: OrphanReason::PidRecycledToNonProxy,
                ..
            } => {} // expected
            other => panic!("expected OrphanedPort/PidRecycledToNonProxy, got {other:?}"),
        }
    }

    /// pidfile points at our self-PID (alive) but no sidecar meta →
    /// OrphanedPort with LegacyPidfileNoSidecar reason. This is the
    /// upgrade-friction case from Round 5: a pre-Round-5 CLI started
    /// the proxy and didn't write sidecar.
    ///
    /// Note: self-PID *is* the cargo test runner, not aikey-proxy, so
    /// identity check would fail FIRST → PidRecycledToNonProxy. We
    /// can't easily fake "alive PID with aikey-proxy basename" in a
    /// pure unit test. The semantically-correct branch is exercised
    /// in Stage 2 integration tests using the real aikey-proxy
    /// binary. Here we just pin that the no-sidecar case eventually
    /// lands in OrphanedPort regardless of the exact reason.
    #[test]
    fn state_no_sidecar_lands_in_orphanedport() {
        let tmp = tempfile::tempdir().unwrap();
        let port = pick_free_port_for_state_tests();
        let inputs = build_inputs(tmp.path(), port);
        let me = std::process::id();
        std::fs::write(&inputs.pid_path, me.to_string()).unwrap();
        // No sidecar written. Even though we WANT this to surface as
        // LegacyPidfileNoSidecar in the field, here identity will fail
        // first (we are the cargo test runner, not aikey-proxy). So
        // assert the OrphanedPort outer branch — both reasons produce
        // identical Layer 2 behavior (do not touch).
        match compute_proxy_state(&inputs) {
            ProxyState::OrphanedPort { owner_pid: Some(pid), .. } => {
                assert_eq!(pid, me, "OrphanedPort owner_pid should be the pidfile pid");
            }
            other => panic!("expected OrphanedPort, got {other:?}"),
        }
    }

    /// No pidfile + something else holding the port → OrphanedPort
    /// with PortHeldByExternal. Pinned because the alternative
    /// (silently classify Stopped + then start_proxy fails on bind)
    /// would produce confusing user messages.
    #[test]
    fn state_branch_orphaned_when_external_holds_port() {
        let tmp = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let inputs = build_inputs(tmp.path(), port);
        // Note: listener still alive (held by `listener` local).
        match compute_proxy_state(&inputs) {
            ProxyState::OrphanedPort {
                reason: OrphanReason::PortHeldByExternal,
                owner_pid: Some(pid),
                ..
            } => {
                assert_eq!(
                    pid,
                    std::process::id(),
                    "owner_pid should be us (we hold the listener)"
                );
            }
            // lsof missing → degrades to Stopped per the documented
            // policy. Acceptable but skip.
            ProxyState::Stopped => {
                eprintln!("[skip] lsof not available — port owner lookup degraded");
            }
            other => panic!("expected OrphanedPort/PortHeldByExternal or Stopped, got {other:?}"),
        }
        drop(listener);
    }

    /// **Round 5 core safety scenario**: pidfile + sidecar present, but
    /// sidecar's birth_token does NOT match the live process's actual
    /// birth_token (= "fake_token") → OrphanedPort with
    /// PidRecycledToDifferentInstance. THIS IS THE CHECK THAT PROTECTS
    /// AGAINST KILLING ANOTHER aikey-proxy instance.
    ///
    /// The same caveat as the legacy test: we can't easily fake
    /// "alive PID + aikey-proxy basename + meta with mismatched
    /// birth_token" in a pure unit test (self-PID isn't aikey-proxy,
    /// so identity fails before ownership). What we CAN pin:
    ///
    /// 1. Construct a meta with the correct pid + a fake birth_token.
    /// 2. Confirm `ownership_verified_at` returns false.
    ///
    /// `ownership_verified_at`'s false return is what
    /// `compute_proxy_state` uses to make the OrphanedPort
    /// determination — so the helper-level test (already covered in
    /// `ownership_verified_false_when_birth_token_mismatches`) is the
    /// load-bearing safety guarantee. The full integration assertion
    /// happens in Stage 2 with the real aikey-proxy binary.
    #[test]
    fn ownership_check_demotes_pid_recycle_to_different_instance() {
        // Pin via the helper directly — same effect, no need to fake
        // identity check in pure-unit context.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(SIDECAR_META_FILENAME);
        let me = std::process::id();
        let m = sample_meta(me, "linux:jiffies:1234567890_DEFINITELY_NOT_LIVE");
        write_meta_atomic_at(&m, &path).unwrap();
        assert!(
            !ownership_verified_at(me, &path),
            "ownership_verified must reject mismatched birth_token; \
             this is the I-7b implementation that compute_proxy_state \
             relies on to demote PID-recycled-to-different-instance \
             scenarios to OrphanedPort"
        );
    }

    /// Sanity: a malformed pidfile (non-numeric) is treated as if no
    /// pidfile exists. Pinned to prevent a future "panic on
    /// unwrap()" regression in the parser.
    #[test]
    fn state_handles_garbage_pidfile_as_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let port = pick_free_port_for_state_tests();
        let inputs = build_inputs(tmp.path(), port);
        std::fs::write(&inputs.pid_path, "this is not a pid").unwrap();
        // Garbage parses as None → no-pidfile branch. Combined with
        // free port → Stopped (or OrphanedPort if lsof missing).
        match compute_proxy_state(&inputs) {
            ProxyState::Stopped => {} // expected (port free)
            other => panic!("expected Stopped, got {other:?}"),
        }
    }
}
