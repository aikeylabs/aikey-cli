//! Probe primitives + suite runner + table renderer.
//!
//! Contents:
//!   - `tcp_ping` / HTTP probe agent / provider-specific helpers (`probe_auth`,
//!     `probe_suffix`, `chat_suffix`, `chat_body`, `probe_model`)
//!   - `test_provider_connectivity` — the ping→API→chat primitive with
//!     built-in short-circuit (ping fail → skip API; API fail → skip chat)
//!   - `test_proxy_connectivity` — the proxy-row probe
//!   - `run_connectivity_suite` — the single entry point every command uses
//!   - `render_cannot_test_block` — "cannot test" explanations beneath the table
//!
//! `test_provider_connectivity` runs `oauth_provider_to_canonical` on its input
//! as a second line of defense — even if a regressed caller hands it a broker
//! code (`"claude"` / `"codex"`), the persona-tweak `match` still fires.

use std::io::{self, Write};

use super::{BuildTargetError, CredentialKind, SuiteOptions, SuiteOutcome, TestTarget};

pub fn tcp_ping(host: &str, port: u16, timeout_secs: u64) -> (bool, u128) {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    let addr_str = format!("{}:{}", host, port);
    let start = Instant::now();

    // Resolve hostname to socket address (includes DNS lookup).
    let resolved = match addr_str.to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(_) => return (false, start.elapsed().as_millis()),
    };
    let sock_addr = match resolved {
        Some(a) => a,
        None => return (false, start.elapsed().as_millis()),
    };

    let ok = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(timeout_secs)).is_ok();
    (ok, start.elapsed().as_millis())
}

/// Result of a provider connectivity test.
///
/// Four phases since 2026-04-22:
///
///   - **Ping(DIRECT)**: CLI → upstream host. Independent baseline — does
///     NOT gate downstream phases. Appears as the "Ping(D)" column.
///   - **Ping(PROXY) → API → Chat**: cascaded through aikey-proxy, each
///     short-circuits on failure. Protects against hammering upstream with
///     invalid auth when the route is down.
///
/// `Clone + Default` (added 2026-04-27): the per-column animation pipeline
/// (`test_provider_connectivity_with_progress` → `animate_blinking_while`)
/// builds this struct incrementally and ships a snapshot through an mpsc
/// channel on every phase boundary, so the renderer can paint each column
/// the instant its phase completes (instead of waiting for all 4 phases to
/// finish). Channels move owned values, so a snapshot must be cloneable;
/// the initial empty struct (before any phase finishes) needs Default.
#[derive(Debug, Clone, Default)]
pub struct ConnectivityResult {
    /// Ping(DIRECT): CLI measures upstream reachability from its own network
    /// context. Does not affect API/Chat — informational column only.
    pub ping_direct_ok: bool,
    pub ping_direct_ms: u128,

    /// Ping(PROXY): aikey-proxy measures upstream reachability from ITS
    /// network context (the one real traffic uses at runtime). Gates API+Chat.
    pub ping_ok: bool,
    pub ping_ms: u128,
    pub api_ok: bool,
    pub api_ms: u128,
    pub api_status: Option<u16>,
    pub chat_ok: bool,
    pub chat_ms: u128,
    pub chat_status: Option<u16>,
    /// First ~512 chars of the API response body when the probe got an HTTP
    /// status (success or error). Used by api_status_hint to disambiguate
    /// "upstream rejected the key" from "local proxy didn't recognize the
    /// bearer" — both are 401, but the operator action differs (reissue key
    /// vs. restart proxy / sync). None when the probe never reached HTTP
    /// (TCP fail, agent error, etc.).
    pub api_body_snippet: Option<String>,
    /// First ~512 chars of the Chat response body when the probe got an HTTP
    /// status. Same role as `api_body_snippet`, fed into chat_status_hint.
    pub chat_body_snippet: Option<String>,
}

/// Default base URLs for known providers — always use the official recommended URL.
/// chat_suffix() / probe_suffix() detect trailing /v1 to avoid double /v1/v1.
///
/// Backed by `provider_registry::entries()` as of 2026-04-24. Callers that
/// previously iterated `PROVIDER_DEFAULTS.iter()` now iterate this lazily-
/// materialized slice; the registry's YAML-declared order is preserved.
pub fn provider_defaults() -> &'static [(&'static str, &'static str)] {
    use std::sync::OnceLock;
    static CACHED: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    CACHED.get_or_init(|| {
        crate::provider_registry::entries()
            .iter()
            .map(|e| (e.code, e.default_base_url))
            .collect()
    })
}

/// Resolve the default base URL for a provider code. Handles OAuth aliases
/// via the registry (claude → anthropic, codex → openai, etc.).
pub fn default_base_url(provider_code: &str) -> Option<&'static str> {
    crate::provider_registry::lookup(provider_code).map(|e| e.default_base_url)
}

/// Test connectivity to a provider: first TCP ping, then API probe.
///
/// - **Ping**: TCP connect to the provider host on port 443 (fast, no auth).
/// - **API**: HTTP GET with the real key (validates both network and key).
///   Any HTTP response (including 401/403) is treated as "reachable".
///   Only connection errors count as failure.
/// Build a ureq agent that respects proxy.env (https_proxy / http_proxy).
/// Why: in China and other restricted networks, direct connections to
/// api.openai.com etc. are blocked. The user's proxy.env configures an
/// outbound proxy (e.g., socks5://127.0.0.1:7890) that the connectivity
/// test must use — otherwise TCP ping and HTTP probes time out.
/// Build a ureq agent that respects proxy.env (https_proxy / http_proxy).
/// Reads from `~/.aikey/proxy.env` first, then falls back to the process
/// env (lowercase `https_proxy` / `http_proxy` / `all_proxy`). Critical
/// for Mac users running Clash / V2Ray etc. that export lowercase env
/// only — ureq's default `ureq::get()` does NOT consult any env on its
/// own. Bugfix: 20260525-aikey-cli-install-bypasses-proxy-aware-agent.md.
pub fn build_proxy_aware_agent(timeout: std::time::Duration) -> ureq::Agent {
    let mut builder = ureq::AgentBuilder::new().timeout(timeout);

    // Try https_proxy, then http_proxy, then all_proxy from proxy.env or env.
    let proxy_url = crate::proxy_env::read_proxy_env_var("https_proxy")
        .or_else(|| crate::proxy_env::read_proxy_env_var("http_proxy"))
        .or_else(|| crate::proxy_env::read_proxy_env_var("all_proxy"))
        .or_else(|| std::env::var("https_proxy").ok())
        .or_else(|| std::env::var("http_proxy").ok())
        .or_else(|| std::env::var("all_proxy").ok());

    if let Some(url) = proxy_url {
        if let Ok(proxy) = ureq::Proxy::new(&url) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build()
}

// ── Probe progress callbacks (2026-04-27) ────────────────────────────────
//
// Plan A from the "blinking eyes column animation" thread: every connectivity
// test surface (`aikey test`, `aikey doctor`, `aikey add` post-add probe, the
// claude/codex wrapper preflight that calls `aikey test <id>`, and the
// proxy-row probe at the bottom of the suite table) runs through one of two
// primitives:
//
//   1. test_provider_connectivity_with_progress  — 4-phase per-target probe
//   2. test_proxy_connectivity                   — 1-shot probe (proxy row)
//
// Both are wrapped at the rendering call site by `animate_blinking_while`,
// which hides the synchronous network blocking under a per-column blink. The
// reusability invariant: NEW connectivity probes only need to emit Started /
// Finished events — the animation primitive handles cursor management,
// terminal detection, and frame timing identically across surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePhase {
    PingDirect,
    PingProxy,
    Api,
    Chat,
}

impl ProbePhase {
    /// Map a phase to its column index in the per-target row.
    /// Centralised so the 4-column layout in `run_connectivity_suite` and
    /// the animation helper agree on ordering without each site hard-coding it.
    pub fn column_index(self) -> usize {
        match self {
            ProbePhase::PingDirect => 0,
            ProbePhase::PingProxy => 1,
            ProbePhase::Api => 2,
            ProbePhase::Chat => 3,
        }
    }
}

/// Lifecycle event for a single probe phase.
///
/// `Finished` carries a borrowed snapshot of the cumulative
/// `ConnectivityResult` so the rendering layer can format the just-completed
/// column without waiting for the rest of the probe to run. The borrow is
/// the probe function's local accumulator — callers that need to ferry it
/// across threads (e.g. an mpsc channel) must `.clone()` it before sending.
#[derive(Debug)]
pub enum ProbeStage<'a> {
    Started,
    Finished(&'a ConnectivityResult),
}

/// 4-frame blinking-eyes animation matching the user-supplied storyboard
/// (2026-04-27): a 1.5-second resting gaze followed by a quick double-blink
/// (sharp / brief reopen / sharp). The asymmetric 130/180/130 ms cadence
/// reads as alive rather than mechanical — short enough that probe-level
/// jitter (typical Ping-D / Ping-PROXY ~500 ms) catches the user mid-frame
/// instead of leaving them staring at a frozen open-eye glyph.
const BLINK_FRAMES: &[(&str, u64)] = &[
    ("\u{276C}\u{29BF}\u{B7}\u{29BF}\u{276D}", 1500), // ❬⦿·⦿❭
    ("\u{276C}-\u{B7}-\u{276D}", 130),                // ❬-·-❭
    ("\u{276C}\u{29BF}\u{B7}\u{29BF}\u{276D}", 180),  // ❬⦿·⦿❭
    ("\u{276C}-\u{B7}-\u{276D}", 130),                // ❬-·-❭
];

/// Internal animation event — `Started(col)` moves the blink, `Finished(col, S)`
/// freezes the just-completed column to its formatted result and the blink
/// advances to the next column on the NEXT `Started` event. Generic over the
/// snapshot type `S` so the same primitive serves the 4-phase provider probe
/// (snapshot = `ConnectivityResult`) and the 1-phase proxy probe (snapshot =
/// `ProxyProbeResult`).
enum AnimEvent<S> {
    Started,
    Finished(S),
}

/// Run `work` on a background thread while animating a "blinking eyes" cell
/// across the row's columns. As each phase finishes the helper invokes
/// `cell_formatter(col, &snapshot)` to PIN that column to its real value;
/// subsequent frames keep the finalized cells visible while the blink
/// continues into the next un-finished column. The whole row stays
/// painted at function exit — the caller only needs to print `eprintln!()`
/// to advance to the next line.
///
/// Cursor protocol:
///   Caller positions cursor at the first column's start before calling.
///   `ESC 7` saves on entry; each redraw uses `ESC 8` (restore) + `ESC [K`
///   (erase to end of line) + paint(rendered cells, blink in current col).
///   The exit paint leaves rendered cells visible — caller prints `\n`.
///
/// Non-TTY fallback: when stderr is not a terminal (CI / piped output) we
/// skip animation entirely (escape codes would pollute logs) AND skip the
/// final paint — caller is expected to render the result row itself in
/// that path. Helper just runs `work` synchronously and returns its value.
///
/// Reusability:
///   * Multi-phase probe → caller maps phase enum to column index. Each
///     `Finished(snapshot)` pins a single column. `S = ConnectivityResult`.
///   * Single-phase probe → caller sends Started(0) + Finished(0, snap).
///     `S = ProxyProbeResult`.
///   * Future probes only declare column widths + a per-column formatter;
///     the helper owns terminal manipulation, threading, frame timing.
fn animate_blinking_while<S, F, FFmt, R>(col_widths: &[usize], cell_formatter: FFmt, work: F) -> R
where
    S: Send + 'static,
    F: FnOnce(std::sync::mpsc::Sender<(usize, AnimEvent<S>)>) -> R + Send + 'static,
    FFmt: Fn(usize, &S) -> String,
    R: Send + 'static,
{
    use std::io::IsTerminal;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    // Non-TTY: pass a Sender that drops events silently. Caller's render
    // path is responsible for printing the row when it doesn't get column-
    // by-column callbacks back from us.
    if !io::stderr().is_terminal() || col_widths.is_empty() {
        let (tx, _rx) = mpsc::channel::<(usize, AnimEvent<S>)>();
        return work(tx);
    }

    let (tx, rx) = mpsc::channel::<(usize, AnimEvent<S>)>();
    let widths = col_widths.to_vec();
    let total_cols = widths.len();
    let handle = thread::spawn(move || work(tx));

    eprint!("\x1b7"); // save cursor at columns area entry
    let _ = io::stderr().flush();

    // Per-column rendered text — set when a phase completes. Stays painted
    // for every subsequent redraw so columns fill in left-to-right exactly
    // when their phase finishes (rather than all-at-once at the end).
    let mut rendered: Vec<Option<String>> = (0..total_cols).map(|_| None).collect();
    let mut current_col: Option<usize> = None;
    let mut frame_idx: usize = 0;
    let mut frame_start = Instant::now();
    let mut all_done = false;

    let paint = |rendered: &Vec<Option<String>>, current_col: Option<usize>, frame_idx: usize| {
        let (frame_text, _) = BLINK_FRAMES[frame_idx % BLINK_FRAMES.len()];
        eprint!("\x1b8\x1b[K");
        for (i, &w) in widths.iter().enumerate() {
            if let Some(s) = &rendered[i] {
                // Already finalized: keep the real result on screen.
                eprint!("{} ", s);
            } else if Some(i) == current_col {
                // Active phase: draw the blink frame.
                eprint!("{:<w$} ", frame_text, w = w);
            } else {
                // Pending phase: empty cell, padded to width.
                eprint!("{:<w$} ", "", w = w);
            }
        }
        let _ = io::stderr().flush();
    };

    while !all_done {
        let mut state_changed = false;

        // Drain any queued events. `Finished(col, snap)` finalises that
        // column via the formatter; advancing the blink is implicit — it
        // moves on the NEXT `Started` event.
        loop {
            match rx.try_recv() {
                Ok((col, AnimEvent::Started)) => {
                    current_col = Some(col);
                    state_changed = true;
                }
                Ok((col, AnimEvent::Finished(snapshot))) => {
                    if col < total_cols {
                        rendered[col] = Some(cell_formatter(col, &snapshot));
                    }
                    if col + 1 >= total_cols {
                        all_done = true;
                        break;
                    }
                    state_changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    all_done = true;
                    break;
                }
            }
        }

        // Advance frame on dwell timeout.
        let (_, frame_dur) = BLINK_FRAMES[frame_idx % BLINK_FRAMES.len()];
        if frame_start.elapsed() >= Duration::from_millis(frame_dur) {
            frame_idx += 1;
            frame_start = Instant::now();
            state_changed = true;
        }

        // Skip the in-loop paint when the loop is about to exit (all_done).
        // The unconditional final paint below will draw the same finalized
        // state once. Why: when every phase finishes inside a single drain
        // iteration (fast-failing rows like a key-rejected chat that returns
        // 0ms), painting both here AND at the final-paint site fires two
        // \x1b8 cursor restores back-to-back. If the row is wider than the
        // terminal and soft-wraps, the second restore lands at a stale
        // position on some terminals, visibly duplicating the row.
        // Bugfix record: 2026-04-27 — qwen row duplicated in `aikey doctor`.
        if state_changed && !all_done {
            paint(&rendered, current_col, frame_idx);
        }

        if !all_done {
            thread::sleep(Duration::from_millis(50));
        }
    }

    // Drain stragglers — including the LAST `Finished` if the work fn
    // pushed it after we set all_done.
    while let Ok((col, ev)) = rx.try_recv() {
        if let AnimEvent::Finished(snapshot) = ev {
            if col < total_cols {
                rendered[col] = Some(cell_formatter(col, &snapshot));
            }
        }
    }

    // Final paint — every finalised column shows its real value; any phase
    // that didn't fire Finished (panic / disconnected work) is left empty.
    // Cursor lands just after the last cell so caller can `eprintln!()`.
    paint(&rendered, None, frame_idx);

    match handle.join() {
        Ok(r) => r,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Backward-compatible wrapper: the original synchronous probe with no
/// progress callback, used by callers (tests, `aikey doctor` JSON path,
/// any non-rendering caller) that don't need per-phase events.
pub fn test_provider_connectivity(
    provider_code: &str,
    base_url: &str,
    api_key: &str,
    kind: CredentialKind,
) -> ConnectivityResult {
    test_provider_connectivity_with_progress(provider_code, base_url, api_key, kind, |_, _| {})
}

/// Same probe pipeline as `test_provider_connectivity` but emits a
/// (`ProbePhase`, `ProbeStage`) event on every phase boundary — including
/// instant Started→Finished pairs for phases that are SKIPPED by the early
/// short-circuit logic (Ping-PROXY fail → no API/Chat; API fail → no Chat).
/// Why: the per-column animation needs to "step through" all 4 columns
/// even when a probe short-circuits, otherwise the blink would freeze on
/// the column where the failure happened. Emitting trivial Started/Finished
/// pairs for skipped phases lets the renderer immediately move on and
/// land the cursor cleanly.
pub fn test_provider_connectivity_with_progress<F>(
    provider_code: &str,
    base_url: &str,
    api_key: &str,
    kind: CredentialKind,
    mut on_phase: F,
) -> ConnectivityResult
where
    F: FnMut(ProbePhase, ProbeStage),
{
    use std::time::{Duration, Instant};

    // Defense-in-depth canonicalization.
    //
    // The factories in `commands_project` already hand us canonical codes
    // ("anthropic"/"openai"/"kimi"). This line is a second line of defense:
    // if any *future* caller passes a broker code ("claude"/"codex") — e.g. a
    // new resolver, a test fixture, a caller that reconstructs TestTarget
    // manually — the persona-tweak matches below must still trigger. Without
    // this shadow, such a regression would manifest as a silent chat 404 on
    // OAuth probes (exactly the 2026-04-21 "claude vs anthropic" incident).
    // `oauth_provider_to_canonical` is idempotent on already-canonical codes.
    let provider_code = crate::commands_account::oauth_provider_to_canonical(provider_code);

    // Check if user has a network proxy configured (proxy.env or env vars).
    // Used by Ping(DIRECT) to decide TCP vs HTTP-HEAD-through-proxy.
    let has_proxy = crate::proxy_env::read_proxy_env_var("https_proxy").is_some()
        || crate::proxy_env::read_proxy_env_var("http_proxy").is_some()
        || crate::proxy_env::read_proxy_env_var("all_proxy").is_some()
        || std::env::var("https_proxy").is_ok()
        || std::env::var("http_proxy").is_ok()
        || std::env::var("all_proxy").is_ok();

    // Determine the REAL upstream host for Ping(DIRECT). If base_url is a
    // localhost URL (team/OAuth TestTargets routed via aikey-proxy), fall
    // back to the provider's canonical upstream so we still measure what
    // the user intuitively expects ("can my laptop reach anthropic?").
    let ping_target_url: String =
        if base_url.contains("127.0.0.1") || base_url.contains("localhost") {
            default_base_url(provider_code)
                .unwrap_or("https://unknown")
                .to_string()
        } else {
            base_url.to_string()
        };
    let (upstream_host, upstream_port) = parse_host_port(&ping_target_url);

    // Cumulative result that grows as each phase completes. We pass `&result`
    // back through the `Finished` callback so renderers can format the cell
    // for the just-completed phase before the next phase even starts.
    let mut result = ConnectivityResult::default();

    // ── Phase 1: Ping(DIRECT) — CLI → upstream. Independent. ─────────────
    // Never short-circuits the other phases. Surfaces as the "Ping(D)"
    // column and gives users a "my laptop's path to upstream" baseline.
    on_phase(ProbePhase::PingDirect, ProbeStage::Started);
    let (ping_direct_ok, ping_direct_ms) = if has_proxy {
        // With a network proxy, TCP won't work — use HTTP HEAD through the
        // same proxy the CLI uses for real requests. Any response (incl.
        // 4xx/5xx) proves reachability.
        probe_http_head_direct(&ping_target_url, Duration::from_secs(3))
    } else {
        tcp_ping(&upstream_host, upstream_port, 3)
    };
    result.ping_direct_ok = ping_direct_ok;
    result.ping_direct_ms = ping_direct_ms;
    on_phase(ProbePhase::PingDirect, ProbeStage::Finished(&result));

    // ── Phase 2: Ping(PROXY) — CLI → aikey-proxy → upstream. ─────────────
    // Uses the new POST /admin/probe/ping endpoint. aikey-proxy handles
    // its own HTTPS_PROXY / NO_PROXY semantics internally.
    on_phase(ProbePhase::PingProxy, ProbeStage::Started);
    let (ping_ok, ping_ms) = probe_via_aikey_proxy_ping(provider_code, &ping_target_url);
    result.ping_ok = ping_ok;
    result.ping_ms = ping_ms;
    on_phase(ProbePhase::PingProxy, ProbeStage::Finished(&result));

    // Short-circuit: if proxy can't reach upstream, skip API + Chat.
    // Critical: probing auth against a known-unreachable upstream wastes
    // the user's rate-limit budget (and inflates OAuth error counters
    // server-side, which can trigger refresh-loop anomalies).
    //
    // Why we still fire trivial Started/Finished for the skipped phases:
    // the per-column animation walks col-by-col; without these events
    // the blink would stay frozen on the failing column instead of
    // landing on the line so caller can render the "—" placeholders.
    if !ping_ok {
        on_phase(ProbePhase::Api, ProbeStage::Started);
        on_phase(ProbePhase::Api, ProbeStage::Finished(&result));
        on_phase(ProbePhase::Chat, ProbeStage::Started);
        on_phase(ProbePhase::Chat, ProbeStage::Finished(&result));
        return result;
    }

    // Note (2026-04-29): Earlier draft of fix C added an OAuth probe
    // short-circuit here. After fix A (proxy.go Tier2Probe OAuth branch)
    // landed and was verified working, C became redundant and was actively
    // hiding A's success — cells went empty in the panel because the
    // short-circuit returned api_status=999 before the real probe ran.
    // Removed in same PR. See bugfix/2026-04-29-oauth-probe-tier2-503.md.

    let agent = build_proxy_aware_agent(Duration::from_secs(10));

    // Is this probe flowing through our own local aikey-proxy? If so the
    // X-Aikey-Probe header suppresses usage-event logging on the proxy side
    // (see proxy/middleware.go::isAikeyProbe). Tagging the header for
    // upstream-direct probes would be harmless but misleading, so gate it.
    let via_aikey_proxy = base_url.contains("127.0.0.1") || base_url.contains("localhost");

    // ── Phase 3: API probe ───────────────────────────────────────────────
    // GET — lightweight, no side effects. Treats ANY HTTP response
    // (incl. 401/403) as "reachable" since the question here is auth
    // transport, not auth success.
    let test_url = if provider_code == "google" {
        format!(
            "{}{}?key={}",
            base_url.trim_end_matches('/'),
            probe_suffix(provider_code, base_url),
            api_key
        )
    } else {
        format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            probe_suffix(provider_code, base_url)
        )
    };
    let (auth_key, auth_val) = probe_auth(provider_code, api_key);

    on_phase(ProbePhase::Api, ProbeStage::Started);
    let api_start = Instant::now();
    let mut api_req = agent.get(&test_url);
    if provider_code != "google" {
        api_req = api_req.set(auth_key, &auth_val);
    }
    if via_aikey_proxy {
        api_req = api_req.set("X-Aikey-Probe", "1");
    }
    let api_result = api_req.call();
    let api_ms = api_start.elapsed().as_millis();

    // Capture body snippet so api_status_hint can distinguish proxy-side
    // registry miss ("Route token not found in registry") from upstream-side
    // key rejection. Both surface as 401 but mean different things and
    // require different operator actions. Cap at ~512 chars to keep the
    // ConnectivityResult cheap to clone / serialize.
    let (api_ok, api_status, api_body_snippet) = match api_result {
        Ok(r) => {
            let s = r.status();
            let body = r.into_string().ok().map(truncate_body_snippet);
            (true, Some(s), body)
        }
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().ok().map(truncate_body_snippet);
            // Local proxy registry miss is reported via 401 + a specific
            // body shape (proxy.go writeJSONError TOKEN_INVALID). It is NOT
            // "reachable from upstream's perspective" — it never left the
            // local proxy. Demote api_ok to false so the table cell renders
            // red and points the operator at the actual fix.
            let is_local_registry_miss = code == 401
                && body
                    .as_deref()
                    .map(body_indicates_registry_miss)
                    .unwrap_or(false);
            // 404 handling — TWO subclasses, treated differently:
            //
            //   (a) Upstream-business 404: JSON envelope like
            //       `{"error":{"type":"not_found_error",...}}` — the upstream
            //       reached us but the resource (model/route/etc.) is gone.
            //       Surfaces as a genuine misconfiguration (e.g. wrong
            //       base_url, deleted upstream route). Vault page used to
            //       paint "API OK ✓" here behind a green chip; the 5/22
            //       guard correctly turns this into red fail.
            //
            //   (b) Gateway-layer 404: plain "404 page not found" body from
            //       Go's net/http when the gateway doesn't register that
            //       specific path. The gateway IS alive — it just only
            //       proxies POST /v1/messages, not GET /v1/models. Aicoding
            //       and other anthropic-compatible byok proxies fall here.
            //       This is transport-OK; keep it green so user isn't
            //       misled into thinking the credential is broken.
            //
            // Bugfix 20260523 round-2 (strict-allowlist version):
            // keep the 5/22 main-path guard intact, but exempt a small
            // explicit allowlist of literal gateway-layer 404 bodies
            // (see `is_known_benign_gateway_404` above). This is a
            // **special case**, not a generalization — DO NOT inline,
            // DO NOT broaden the match.
            let is_path_missing =
                code == 404 && !is_known_benign_gateway_404(code, body.as_deref());
            (
                !(is_local_registry_miss || is_path_missing),
                Some(code),
                body,
            )
        }
        Err(_) => (false, None, None),
    };
    result.api_ok = api_ok;
    result.api_ms = api_ms;
    result.api_status = api_status;
    result.api_body_snippet = api_body_snippet;
    on_phase(ProbePhase::Api, ProbeStage::Finished(&result));

    if !api_ok {
        // Same skip-phase bookkeeping as the Ping(PROXY) early return: emit
        // a trivial Chat Started/Finished pair so the column animation can
        // step out of the API column and land on the line cleanly.
        on_phase(ProbePhase::Chat, ProbeStage::Started);
        on_phase(ProbePhase::Chat, ProbeStage::Finished(&result));
        return result;
    }

    // ── Phase 4: Chat probe ──────────────────────────────────────────────
    // Minimal completion request (max_tokens=1). Short-circuit on API
    // failure prevents this from hammering an upstream that just rejected
    // our auth — some providers count that against rate limits.
    //
    // Bugfix 20260523: previously this branch used `is_via_proxy` (a
    // proxy-variable that's TRUE for ANY credential routed through
    // aikey-proxy) as a stand-in for "is OAuth flow". That misjudged
    // personal API keys whose base_url legitimately points at the local
    // proxy (e.g. routed to a custom anthropic gateway like aicoding) —
    // they got the OAuth-only `?beta=true` query and the gateway returned
    // 404. Fix: drive protocol addons off `kind == OAuth` via a config
    // table (see protocol_addons.rs), kept as the single source of truth
    // for future proxy outbound-transform middleware too.
    let (chat_url, body) = build_chat_probe(provider_code, base_url, api_key, kind);
    let (chat_auth_key, chat_auth_val) = probe_auth(provider_code, api_key);

    let chat_agent = build_proxy_aware_agent(Duration::from_secs(15));
    let chat_start = Instant::now();
    let mut req = chat_agent
        .post(&chat_url)
        .set("Content-Type", "application/json");
    // Google uses ?key= in URL; skip header auth. Others use header.
    if provider_code != "google" {
        req = req.set(chat_auth_key, &chat_auth_val);
    }
    if provider_code == "anthropic" {
        req = req.set("anthropic-version", "2023-06-01");
    }
    if via_aikey_proxy {
        req = req.set("X-Aikey-Probe", "1");
    }
    // Why: KIMI Coding API (api.kimi.com/coding/v1) requires a User-Agent
    // matching its coding-agent whitelist (e.g. "claude-code", "kimi-cli").
    // Without it, KIMI returns access_terminated_error (HTTP 403).
    // We use "claude-code/1.0 (aikey)" to satisfy the whitelist while
    // identifying ourselves. This only affects the connectivity probe.
    //
    // 2026-05-08 Kimi 双平台拆分: 'kimi_code' 是新 canonical code (api.kimi.com
    // 上游),沿用同样的 coding-agent whitelist 要求;'kimi' 是 deprecated alias
    // 仍兼容老 vault 数据 / 任何残留的 'kimi' 字面值。Moonshot (api.moonshot.cn)
    // 不在 whitelist 范围内,**不**注入此 header,避免污染请求形态。
    if provider_code == "kimi_code" || provider_code == "kimi" {
        req = req.set("User-Agent", "claude-code/1.0");
    }
    on_phase(ProbePhase::Chat, ProbeStage::Started);
    let chat_result = req.send_string(&body.to_string());
    let chat_ms = chat_start.elapsed().as_millis();

    let (chat_ok, chat_status, chat_body_snippet) = match chat_result {
        Ok(r) => {
            let s = r.status();
            let body = r.into_string().ok().map(truncate_body_snippet);
            (s >= 200 && s < 300, Some(s), body)
        }
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().ok().map(truncate_body_snippet);
            // 429 = auth passed but rate limited → connectivity OK.
            //   Claude OAuth returns 429 as business rejection when persona
            //   headers are incomplete, but also for genuine rate limits.
            //   Either way, the key is valid and the provider is reachable.
            //
            // 404 = endpoint reachable, content-level rejection → also OK.
            //   Reported in the wild 2026-04-25:
            //     - Anthropic personal: probe model `claude-haiku-4-5-20251001`
            //       isn't available on every account tier → 404 "Model not
            //       found", but auth itself succeeded (otherwise we'd see 401).
            //     - Kimi Coding API at `/coding/v1/chat/completions`: probe
            //       model `moonshot-v1-8k` isn't a coding-tier model → 404,
            //       same shape.
            //     - OpenAI OAuth via Codex proxy: `/v1/chat/completions`
            //       doesn't exist there (Codex uses Responses API) → 404,
            //       same shape — actual usage works regardless.
            //   In all three the request reached the upstream and the upstream
            //   answered authoritatively; flagging this as red "fail" with
            //   `chat HTTP 404 — unexpected` (the previous behavior) misled
            //   users into thinking their key was broken when it wasn't.
            //   Treating 404 as OK with a "reachable, model unavailable" hint
            //   keeps the column green and points at the real fix (use a
            //   different model name) without falsely signalling auth failure.
            let ok = code == 429 || code == 404;
            (ok, Some(code), body)
        }
        Err(_) => (false, None, None),
    };
    result.chat_ok = chat_ok;
    result.chat_ms = chat_ms;
    result.chat_status = chat_status;
    result.chat_body_snippet = chat_body_snippet;
    on_phase(ProbePhase::Chat, ProbeStage::Finished(&result));

    result
}

/// Parse an "https://host:port/…" or "host:port" string into (host, port).
/// Defaults to 443 (https) / 80 (http).
fn parse_host_port(url_or_authority: &str) -> (String, u16) {
    let is_http = url_or_authority.starts_with("http://");
    let stripped = url_or_authority
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    if let Some(idx) = host_port.rfind(':') {
        let host = host_port[..idx].to_string();
        let port = host_port[idx + 1..]
            .parse::<u16>()
            .unwrap_or(if is_http { 80 } else { 443 });
        (host, port)
    } else {
        (host_port.to_string(), if is_http { 80 } else { 443 })
    }
}

/// Ping(DIRECT) when a network proxy is configured: HTTP HEAD to the
/// upstream URL via the same proxy-aware agent used for everything else.
/// Any response (including 4xx/5xx) proves reachability.
///
/// Why the thread + mpsc::recv_timeout dance: ureq 2.x's `AgentBuilder::timeout`
/// does not reliably cap DNS resolution, TCP connect, or TLS handshake on the
/// outbound proxy hop. Field reports show 60+ second hangs with a 5s setting
/// when HTTPS_PROXY points at an unreachable upstream. Running the call in a
/// detached thread with `recv_timeout` enforces a hard wall-clock cap; the
/// orphaned thread eventually unwinds via the agent's own (looser) timeout.
fn probe_http_head_direct(target_url: &str, timeout: std::time::Duration) -> (bool, u128) {
    use std::sync::mpsc;
    use std::time::Instant;
    let start = Instant::now();
    let url = target_url.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let agent = build_proxy_aware_agent(timeout);
        let ok = match agent.head(&url).call() {
            Ok(_) => true,
            Err(ureq::Error::Status(_, _)) => true, // HEAD may 405; still reached upstream
            Err(_) => false,
        };
        let _ = tx.send(ok);
    });
    let ok = rx.recv_timeout(timeout).unwrap_or(false);
    (ok, start.elapsed().as_millis())
}

/// Ping(PROXY): ask the local aikey-proxy to TCP-ping (or HTTP-HEAD via
/// its own outbound proxy) the upstream on our behalf. This is what tells
/// us "can the proxy itself reach upstream" — the question the CLI
/// actually cares about for runtime traffic.
///
/// Returns `(false, elapsed_ms)` on any transport error, unknown provider,
/// or aikey-proxy unreachability. Short-circuits the rest of the suite.
fn probe_via_aikey_proxy_ping(provider_code: &str, upstream_url: &str) -> (bool, u128) {
    use std::time::Instant;
    let proxy_port = crate::commands_proxy::proxy_port();
    let endpoint = format!("http://127.0.0.1:{}/admin/probe/ping", proxy_port);
    let body = serde_json::json!({
        "provider": provider_code,
        "base_url": upstream_url,
    });
    // 4s cap — the proxy itself uses 3s internally so we allow a bit of
    // slack for request overhead.
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(4))
        .build();
    let start = Instant::now();
    let resp = match agent
        .post(&endpoint)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(r) => r,
        Err(_) => return (false, start.elapsed().as_millis()),
    };
    // Proxy always returns 200 with a structured JSON body — even on
    // upstream failure. If the proxy says ok:false, we propagate that.
    let parsed: serde_json::Value = match resp.into_json() {
        Ok(v) => v,
        Err(_) => return (false, start.elapsed().as_millis()),
    };
    let proxy_ok = parsed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let proxy_ms = parsed
        .get("latency_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u128;
    // Report proxy's own measured latency (host → upstream), not our RTT
    // to localhost (which is ~0ms and meaningless).
    (proxy_ok, proxy_ms)
}

/// Result of a proxy connectivity probe.
///
/// `Clone` (added 2026-04-27): proxy-row rendering pipes the result through
/// `animate_blinking_while`'s mpsc channel for the per-column finalisation
/// callback. Owned snapshots are required by the channel, so the work
/// closure clones before sending.
#[derive(Debug, Clone)]
pub struct ProxyProbeResult {
    pub ok: bool,
    pub ms: u128,
    pub status: Option<u16>,
    /// 2026-05-26 (spec: 20260526-pre-save-proxy-probe-raw.md §5.3): when set,
    /// carries a stable error_code categorizing the proxy's response so callers
    /// can render specific user-actionable hints. Set only in probe_raw mode
    /// (when bearer_override was Some). Variants today:
    ///
    /// - `"PROXY_TOO_OLD_NO_PROBE_RAW"` — proxy returned 401 + TOKEN_INVALID
    ///   body. Means proxy hasn't been upgraded to a version that understands
    ///   `aikey_probe_raw_*`. NO fallback per user decision 2026-05-26 (the
    ///   legacy `aikey_active_*` path tests the wrong key, so silently falling
    ///   back would just produce a different misleading result). User must
    ///   `aikey service restart proxy` after upgrading aikey.
    ///
    /// - `"PROBE_RAW_DISABLED"` — new proxy with AIKEY_PROBE_RAW_DISABLED=1.
    ///   Operator turned the feature off (defense rollback flag).
    ///
    /// - `"PROBE_HEADER_REQUIRED"` — defense; proxy says we sent the token
    ///   without `X-Aikey-Probe: 1`. Indicates a caller bug (we always send
    ///   it) — surface so we can find regressions early.
    ///
    /// `None` for: post-save legacy active-sentinel mode (always), or
    /// probe_raw mode where proxy returned an unsurprising status.
    pub error_code: Option<String>,
}

/// Test the proxy → provider chain. Two modes selected by `bearer_override`:
///
/// **Mode 1 — Active sentinel (post-save, `bearer_override = None`)**:
///   Sends `aikey_active_<provider>` Tier3 sentinel. Proxy resolves
///   `GetProviderBinding(canonical)` and forwards using whatever key is
///   CURRENTLY ACTIVE for that provider. Used by `aikey test [<alias>]`,
///   `aikey doctor`, web "Test connection" (post-save). Tests "what `aikey use`
///   would route to right now". The probe row does NOT test the alias the
///   caller named — that's a known semantic for post-save where active
///   binding IS what matters operationally.
///
/// **Mode 2 — Pre-save probe_raw (`bearer_override = Some(plaintext_key)`)**:
///   Sends `aikey_probe_raw_<provider>` Tier2ProbeRaw token + the plaintext
///   key in `X-Aikey-Probe-Bearer` header. Proxy skips vault entirely and uses
///   the header bearer directly. Used by `aikey add` + web Add Key Test
///   connectivity — tests "does THIS specific key the user is adding work
///   through this machine's proxy?". Spec:
///   roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md
///
/// **Mode 3 — OAuth account probe (`oauth_account_id = Some(account_id)`)**:
///   Sends `aikey_probe_<account_id>` Tier2Probe token. Proxy's existing
///   OAuth Tier2Probe path (proxy.go::handlePathPrefixRoute Tier2Probe
///   branch) recognizes the account_id via `broker.GetAccountStatus`,
///   refreshes the token via `broker.EnsureFresh`, resolves the credential
///   via `broker.ResolveCredential`, and forwards. Used by web Add Key
///   OAuth Test connectivity (post-save by id) so the proxy row tests
///   THIS SPECIFIC OAuth account instead of falling back to active
///   sentinel which may resolve to a different (older) binding because
///   Web OAuth add doesn't propagate lifecycle (Phase A.1 deferred).
///
/// `bearer_override` and `oauth_account_id` are MUTUALLY EXCLUSIVE.
/// Caller violation (both `Some`) panics in debug; in release the
/// probe_raw mode (bearer_override) wins for safety.
///
/// Common: `X-Aikey-Probe: 1` suppresses usage-event emission in all modes
/// (see aikey-proxy middleware.go::isAikeyProbe).
///
/// 2026-04-22 regression history (do not silently drop `.set_proxy(None)` —
/// see workflow/CI/bugfix/2026-04-22-connectivity-probe-through-proxy.md):
/// must NOT use `ureq::get()` shortcut, which inherits `https_proxy` env and
/// routes localhost through Clash → bogus failures.
pub fn test_proxy_connectivity(
    proxy_addr: &str,
    provider_code: &str,
    bearer_override: Option<&str>,
    base_url_override: Option<&str>,
    oauth_account_id: Option<&str>,
) -> ProxyProbeResult {
    use std::time::{Duration, Instant};

    debug_assert!(
        !(bearer_override.is_some() && oauth_account_id.is_some()),
        "test_proxy_connectivity: bearer_override and oauth_account_id are mutually exclusive — caller bug"
    );

    // Proxy strips the provider prefix and forwards to the real provider.
    // The proxy's upstream base_url never ends with /v1, so use full /v1/... paths.
    let proxy_base = format!("http://{}/{}", proxy_addr, provider_code);
    let proxy_url = format!("{}{}", proxy_base, probe_suffix(provider_code, &proxy_base));

    // Token form differs by mode (see fn docstring). Mode precedence in case
    // a caller bug passes both: probe_raw wins (release-mode defense — the
    // header bearer is safer than implicitly trusting vault state).
    let (bearer, extra_headers) = match (bearer_override, oauth_account_id) {
        (Some(raw), _) => {
            // Mode 2 — probe_raw. Token suffix is canonical provider code.
            // Plaintext key rides in X-Aikey-Probe-Bearer (NOT Authorization);
            // proxy reads the header to use as upstream credential.
            let mut headers: Vec<(&'static str, String)> =
                vec![("X-Aikey-Probe-Bearer", raw.to_string())];
            if let Some(base) = base_url_override {
                if !base.is_empty() {
                    headers.push(("X-Aikey-Probe-BaseURL", base.to_string()));
                }
            }
            (format!("aikey_probe_raw_{}", provider_code), headers)
        }
        (None, Some(account_id)) => {
            // Mode 3 — OAuth account probe (Tier2Probe). Proxy resolves the
            // account_id via broker; no plaintext bearer needed (broker holds
            // the refreshed OAuth token). No extra headers.
            (format!("aikey_probe_{}", account_id), Vec::new())
        }
        (None, None) => {
            // Mode 1 — active sentinel (legacy / post-save). No extra headers.
            // _active_cfg read kept for compatibility — call site relied on it
            // historically as a vault-presence probe; preserved for byte-equivalent
            // behavior with pre-2026-05-26 callers.
            let _active_cfg = crate::storage::get_active_key_config().ok().flatten();
            (format!("aikey_active_{}", provider_code), Vec::new())
        }
    };

    let (auth_key, auth_val) = probe_auth(provider_code, &bearer);
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let start = Instant::now();
    let mut req = agent
        .get(&proxy_url)
        .set(auth_key, &auth_val)
        .set("X-Aikey-Probe", "1");
    // Anthropic requires anthropic-version header on /v1/models too — without
    // it, even valid keys get 400 ("anthropic-version: header is required"),
    // which probe_status_hint renders as a non-specific "routing ok".
    // Sending the header lets a valid key produce a clean 200 (or 401 for
    // bad keys), giving the user a precise verdict. Mirrors the existing
    // chat-probe path (runtime.rs:640). Allowlisted on proxy side.
    if provider_code == "anthropic" {
        req = req.set("anthropic-version", "2023-06-01");
    }
    for (k, v) in &extra_headers {
        req = req.set(k, v);
    }
    let result = req.call();
    let ms = start.elapsed().as_millis();

    // Body inspection differs by mode (spec 20260526-pre-save-proxy-probe-raw.md §2.4):
    //   - Active sentinel mode (None): proxy is a pass-through; r.status() IS
    //     the upstream status. No body parse needed.
    //   - probe_raw mode (Some): proxy ALWAYS returns 200 when its chain
    //     succeeded, putting upstream's real status in body {"upstream_status":...}.
    //     Client MUST extract this to give caller the right signal ("key valid"
    //     vs "key rejected"). Without this, status_hint would always read
    //     "routing ok, key valid" even for 401-rejected keys.
    //
    // Error path: also peek body to distinguish old-proxy TOKEN_INVALID,
    // flag-disabled, etc. — same body shape, different fields read.
    let is_probe_raw = bearer_override.is_some();
    let (ok, status, error_code) = match result {
        Ok(r) => {
            // Happy path. In probe_raw mode, body carries upstream_status.
            if is_probe_raw {
                let upstream = extract_probe_raw_upstream_status(r);
                // upstream None → proxy chain worked but body parse failed
                // (defensive). Fall back to outer status (200) so caller
                // still sees ok-but-unknown.
                (true, upstream.or(Some(200)), None)
            } else {
                (true, Some(r.status()), None)
            }
        }
        Err(ureq::Error::Status(code, response)) => {
            let err_code = if is_probe_raw {
                classify_probe_raw_error(code, response)
            } else {
                None
            };
            (true, Some(code), err_code)
        }
        Err(_) => (false, None, None),
    };
    ProxyProbeResult {
        ok,
        ms,
        status,
        error_code,
    }
}

/// 2026-05-26 — extract `upstream_status` field from proxy's probe_raw
/// success response body. Returns None when body parse fails (defensive).
///
/// Body shape per spec §2.4:
/// ```json
/// {"probe_ok": true, "upstream_status": 200, "latency_ms": 187, ...}
/// ```
fn extract_probe_raw_upstream_status(response: ureq::Response) -> Option<u16> {
    let body = response.into_string().ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    json.get("upstream_status")
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
}

/// 2026-05-26 — classify a non-2xx response from the proxy when in probe_raw
/// mode. Reads up to 1KB of body, parses the proxy's standard JSON error
/// shape (`{"error":{"code":"..."}}`), returns a stable error_code string.
///
/// Returns None when the body doesn't conform to the proxy error shape
/// (defensive — proxy returns this shape consistently per middleware.go,
/// but we don't want to crash on edge cases like proxy bug / network mid-stream
/// truncation).
fn classify_probe_raw_error(status: u16, response: ureq::Response) -> Option<String> {
    // Bounded body read: error payloads are < 1KB. Limit defends against
    // a malicious / buggy proxy streaming an unbounded body.
    let body = response
        .into_string()
        .ok()
        .map(|s| s.chars().take(2048).collect::<String>())
        .unwrap_or_default();

    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let proxy_code = json
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())?;

    match (status, proxy_code) {
        // Old proxy (no probe_raw support): classifies aikey_probe_raw_* as
        // TokenInvalid → 401 + TOKEN_INVALID. This is the most common Phase 2
        // failure mode (user updated aikey CLI but didn't restart proxy).
        (401, "TOKEN_INVALID") => Some("PROXY_TOO_OLD_NO_PROBE_RAW".to_string()),
        // New proxy with operator-disabled flag (defense rollback).
        (503, "PROBE_RAW_DISABLED") => Some("PROBE_RAW_DISABLED".to_string()),
        // Defense: we always send X-Aikey-Probe: 1; this should never fire.
        // If it does, it's a caller-side bug worth surfacing loud.
        (401, "PROBE_HEADER_REQUIRED") => Some("PROBE_HEADER_REQUIRED".to_string()),
        // Other recognized proxy error codes pass through as-is (lets CLI
        // / web display them verbatim instead of swallowing).
        (_, code) if code.starts_with("PROBE_") => Some(code.to_string()),
        _ => None,
    }
}

/// Format a proxy probe status code into a human-readable hint.
pub fn proxy_status_hint(status: u16) -> String {
    match status {
        200 => "routing ok, key valid".to_string(),
        400 | 404 | 405 => "routing ok".to_string(),
        401 | 403 => "routing ok, key rejected by provider".to_string(),
        503 => "proxy has no active key for this provider".to_string(),
        _ => format!("HTTP {}", status),
    }
}

/// 2026-05-26 — full-result hint that takes precedence of `error_code` over
/// raw status mapping. Use this from probe_raw call sites; legacy callers
/// that only have `status: u16` can keep using `proxy_status_hint`.
///
/// When `error_code` is `Some`, returns a user-actionable string explaining
/// what to do next (no automatic fallback — per spec §5.3 user decision
/// 2026-05-26: silently retrying with `aikey_active_*` would mask the issue
/// and produce a misleading result. Surface loud + tell user what to do.).
pub fn proxy_probe_full_hint(r: &ProxyProbeResult) -> String {
    if let Some(code) = &r.error_code {
        return match code.as_str() {
            "PROXY_TOO_OLD_NO_PROBE_RAW" => {
                "aikey-proxy too old for pre-save probe — run `aikey service restart proxy`"
                    .to_string()
            }
            "PROBE_RAW_DISABLED" => {
                "pre-save probe disabled by operator (AIKEY_PROBE_RAW_DISABLED=1)".to_string()
            }
            "PROBE_HEADER_REQUIRED" => {
                "BUG: client missed X-Aikey-Probe header — please report".to_string()
            }
            other => format!("proxy error: {}", other),
        };
    }
    match r.status {
        Some(s) => proxy_status_hint(s),
        None => "unreachable".to_string(),
    }
}

/// Build the probe URL suffix for a provider.
/// Checks if base_url already ends with /v1 to avoid double /v1/v1.
///
/// Why anthropic falls through to `/v1/models` (was `/v1/messages`):
/// `/v1/messages` is POST-only, so a GET probe always returned 405. That's
/// semantically "reachable but wrong method" — technically fine, but the
/// user-visible `HTTP 405` read as a bug ("is 405 normal?", 2026-04-22).
/// `/v1/models` accepts GET and returns 200 (with a valid key) or 401
/// (rejected), mapping cleanly onto api_status_hint's existing cases.
/// Verified live via the aikey-proxy OAuth route: 200 with full models
/// list. The proxy auto-injects `anthropic-version`, so the header we set
/// below is only load-bearing for direct-to-api.anthropic.com probes.
/// Third-party gateways that don't implement `/v1/models` still land in
/// the 404/405 → "reachable" safety net, so no regression.
fn probe_suffix(provider_code: &str, base_url: &str) -> String {
    let base_has_v1 = base_url.trim_end_matches('/').ends_with("/v1");
    match provider_code {
        "google" => "/v1beta/models".to_string(),
        "custom" => String::new(),
        _ if base_has_v1 => "/models".to_string(),
        _ => "/v1/models".to_string(),
    }
}

/// Build the chat completion URL suffix for a provider.
/// Checks if base_url already ends with /v1 to avoid double /v1/v1.
/// Build the (URL, body) tuple for the chat probe.
///
/// **OAuth credentials**: look up `oauth_addons_for(provider)` to apply protocol
/// addons (e.g. anthropic `?beta=true` + metadata.user_id, Codex `/responses`
/// path + Responses API body). Personal API keys and managed-team credentials
/// always take the clean path — they MUST NOT inherit OAuth-only protocol
/// quirks, since a personal API key routed via aikey-proxy may forward to a
/// custom anthropic gateway (e.g. aicoding) that doesn't implement the OAuth
/// variant (bugfix 20260523).
///
/// **Google special case**: personal-API uses `?key=<api_key>` URL auth (not a
/// protocol addon, an alternative auth scheme). Kept inline because it depends
/// on `api_key` runtime value, not provider-static config.
///
/// Extracted as a standalone fn so unit tests can pin the URL/body shape per
/// (provider × kind) combination without spinning up a real HTTP probe.
pub(crate) fn build_chat_probe(
    provider_code: &str,
    base_url: &str,
    api_key: &str,
    kind: CredentialKind,
) -> (String, serde_json::Value) {
    // OAuth: consult the protocol-addons registry (single source of truth).
    if matches!(kind, CredentialKind::OAuth) {
        if let Some(addons) = super::protocol_addons::oauth_addons_for(provider_code) {
            let default_path = chat_suffix(provider_code, base_url);
            let url = addons.url(base_url, &default_path);
            let body = addons.body(chat_body(provider_code));
            return (url, body);
        }
        // OAuth provider not in registry yet — fall through to default path.
        // The probe will likely 4xx, but we don't crash. Adding a new OAuth
        // provider = adding one entry in `oauth_addons_for`.
    }

    // Google personal-API: ?key= query auth, no other addons.
    if provider_code == "google" {
        let url = format!(
            "{}{}?key={}",
            base_url.trim_end_matches('/'),
            chat_suffix(provider_code, base_url),
            api_key,
        );
        return (url, chat_body(provider_code));
    }

    // Default: clean URL + standard chat body. Covers PersonalApi / ManagedTeam
    // for all providers, and any OAuth provider not yet in the addons registry.
    let url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        chat_suffix(provider_code, base_url),
    );
    (url, chat_body(provider_code))
}

fn chat_suffix(provider_code: &str, base_url: &str) -> String {
    let base_has_v1 = base_url.trim_end_matches('/').ends_with("/v1");
    match provider_code {
        "anthropic" if base_has_v1 => "/messages".to_string(),
        "anthropic" => "/v1/messages".to_string(),
        "google" => "/v1beta/models/gemini-2.0-flash:generateContent".to_string(),
        _ if base_has_v1 => "/chat/completions".to_string(),
        _ => "/v1/chat/completions".to_string(),
    }
}

/// Default model name per provider for the chat probe.
fn probe_model(provider_code: &str) -> &'static str {
    match provider_code {
        // Why haiku: sonnet/opus hit rate limits on OAuth accounts (429 business rejection).
        // Haiku is lighter and skips stricter quota checks. Verified in research.
        "anthropic" => "claude-haiku-4-5-20251001",
        "openai" => "gpt-4o-mini",
        "deepseek" => "deepseek-chat",
        // 2026-05-08 Kimi 双平台拆分: 三个 code 都属 Kimi family,但默认探针 model
        // 各自独立 (kimi-cli upstream 不同模型集):
        //   - kimi_code (api.kimi.com/coding) → kimi-k2.5 (Kimi Coding 默认)
        //   - moonshot (api.moonshot.cn) → moonshot-v1-8k (Moonshot 平台)
        //   - kimi (deprecated alias) → 与 kimi_code 一致
        // pre-fix 只有 "kimi" case,kimi_code/moonshot 跑到 fallback gpt-4o-mini,
        // api.kimi.com 探针被 reject (model not found),结果 doctor 报错误诊断。
        "kimi_code" | "kimi" => "kimi-k2.5",
        "moonshot" => "moonshot-v1-8k",
        "google" => "gemini-2.0-flash",
        "glm" | "zhipu" => "glm-4-flash",
        "yi" => "yi-lightning",
        "qwen" | "dashscope" => "qwen-turbo",
        "mistral" => "mistral-small-latest",
        _ => "gpt-4o-mini", // fallback: most gateways understand this
    }
}

/// Build a minimal chat request body for a provider.
fn chat_body(provider_code: &str) -> serde_json::Value {
    let model = probe_model(provider_code);
    match provider_code {
        "anthropic" => serde_json::json!({
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        }),
        "google" => serde_json::json!({
            "contents": [{"parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 1}
        }),
        _ => serde_json::json!({
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        }),
    }
}

/// Build the auth header (key, value) for a provider probe.
fn probe_auth(provider_code: &str, api_key: &str) -> (&'static str, String) {
    match provider_code {
        "anthropic" => ("x-api-key", api_key.to_string()),
        // Google uses ?key= query param, but we pass it as header too for proxy compatibility.
        // The actual URL builder appends ?key= for direct calls.
        "google" => ("x-goog-api-key", api_key.to_string()),
        _ => ("Authorization", format!("Bearer {}", api_key)),
    }
}

/// Format a chat probe status code into a human-readable hint.
/// Cap a response body to ~512 chars; safe to embed in display + JSON.
/// Uses `chars().take` so multi-byte UTF-8 isn't sliced mid-codepoint.
pub fn truncate_body_snippet(s: String) -> String {
    if s.chars().count() <= 512 {
        s
    } else {
        s.chars().take(512).collect()
    }
}

/// Returns true when a proxy 401 body indicates the local Tier1 registry
/// didn't recognize the bearer (post-2026-05-09 fix scope: stale
/// vault/proxy state, not an actual upstream auth failure).
///
/// Substring matched against `proxy.go::writeJSONError` payload for the
/// "Route token not found in registry" case. Stays as a substring check —
/// don't JSON-parse here; the proxy's exact JSON shape evolves and we want
/// the detector to survive shape changes as long as the message text holds.
pub fn body_indicates_registry_miss(body: &str) -> bool {
    body.contains("not found in registry") || body.contains("TOKEN_INVALID")
}

// ───────────────────────────────────────────────────────────────────────────
// SPECIAL CASE — known-benign gateway 404 allowlist.
//
// DO NOT MERGE INTO `api_ok` MAIN PATH.  DO NOT GENERALIZE THIS LIST.
// DO NOT CONVERT TO substring / regex / HTML detection.
//
// Why this exists:
//   The 2026-05-22 "code == 404 → api_ok=false" guard was added to catch
//   vault-page false positives where a misconfigured base_url silently
//   showed "API OK ✓". That guard is correct for the vast majority of
//   404s (upstream-business "resource not found" JSON envelopes).
//
//   BUT it accidentally fails legitimate anthropic-compatible byok
//   gateways (e.g. aicoding) that only proxy `POST /v1/messages` and
//   return Go's `net/http` default `"404 page not found"` on the probe's
//   `GET /v1/models`. The gateway is alive, the credential is valid,
//   Chat probe succeeds — but the API column lights up red and exit
//   code is 2. See bugfix 20260523 round-2 and the failed R2 attempt
//   that over-generalized this match.
//
// Why a separate, *strict-equality* allowlist:
//   The first attempt (R2) used a fuzzy heuristic — empty body /
//   leading-char inspection / lowercase substring match. Within hours
//   the design reviewer (user) flagged it as "patch-style, will be
//   over-fitted again". The lesson: every generalization here is a
//   re-opening of the original vault-page hole.
//
//   This allowlist keeps two properties intact:
//     1. Main path is untouched — every other 404 still fails as 5/22
//        intended; vault-page false-positive fix remains in force.
//     2. Each entry is a literal string, traceable to a specific
//        observed gateway. To add a new one you must:
//          (a) capture the exact body bytes from a real reproduction
//          (b) append a new `#[test]` case asserting the literal
//          (c) keep the list short — if it grows past ~5 entries the
//              right fix is no longer this allowlist but a redesign
//              of the API probe (drop /v1/models entirely; see the
//              "Future direction" note in the bugfix doc).
//
// Removal rule:
//   When the API probe path is redesigned to not depend on /v1/models
//   (the proper systemic fix), delete this entire section together with
//   its callsite. Until then DO NOT touch the main path; touch this
//   section.
// ───────────────────────────────────────────────────────────────────────────

/// Literal 404 bodies known to be returned by **legitimate** anthropic /
/// openai-compatible byok gateways that only proxy chat completions and
/// don't implement `/v1/models`. Adding to this list is an explicit
/// per-gateway opt-in; never generalize.
const KNOWN_BENIGN_GATEWAY_404_BODIES: &[&str] = &[
    // Go `net/http` default 404 — covers aicoding (aicoding.2233.ai) and
    // most byok proxies built on Go. The trailing newline is what
    // ServeMux::serveError actually writes; the trimmed form covers the
    // case where the body reader stripped trailing whitespace.
    "404 page not found",
    "404 page not found\n",
];

/// Is this (status, body) pair a known-benign gateway-layer 404 that
/// should bypass the 2026-05-22 "404 → fail" guard?
///
/// Strict equality only — see the section comment above for why no
/// substring / regex / shape inference is allowed here.
pub fn is_known_benign_gateway_404(status: u16, body: Option<&str>) -> bool {
    if status != 404 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    KNOWN_BENIGN_GATEWAY_404_BODIES
        .iter()
        .any(|exact| body == *exact || body.trim_end() == exact.trim_end())
}

pub fn chat_status_hint(status: u16, body: Option<&str>) -> String {
    // Disambiguate "local proxy didn't recognize the bearer" from "upstream
    // says key is invalid" — both surface as 401 but the operator action is
    // very different (sync/restart proxy vs. reissue/check upstream key).
    if status == 401 && body.map(body_indicates_registry_miss).unwrap_or(false) {
        // 2026-05-11: two-cause guidance. Registry miss can mean (a) a
        // recent `aikey use` whose seq the proxy's 5-second poller has not
        // picked up yet, or (b) a vault_key inconsistency where managed
        // key ciphertext was written under a different key than the proxy
        // now derives — see workflow/CI/bugfix/2026-05-11-team-key-decrypt-inconsistent.md.
        // The proxy doesn't surface the reason in the 401 body, so we
        // print both recovery paths and let the user pick.
        return "proxy has no route for this key. Causes: (a) just ran `aikey use`? proxy reloads within 5s — retry or `aikey proxy reload`; (b) vault decrypt mismatch — `aikey key sync --force-reencrypt`".to_string();
    }
    match status {
        200 => "valid".to_string(),
        400 => "bad request".to_string(),
        401 => "invalid key".to_string(),
        403 => "forbidden".to_string(),
        // 404 paired with `chat_ok = true` per the match arm in
        // `test_provider_connectivity_with_progress`: route + auth worked,
        // upstream rejected the specific (model, endpoint) combination.
        // Most often a probe-time model-name mismatch — the user's key is
        // fine, real usage with their own model name will succeed.
        404 => "reachable, model unavailable".to_string(),
        422 => "invalid request".to_string(),
        429 => "rate limited, key valid".to_string(),
        _ if status >= 500 => format!("server error ({})", status),
        _ => format!("HTTP {}", status),
    }
}

/// Format an API probe status code into a human-readable hint.
pub fn api_status_hint(status: u16, body: Option<&str>) -> String {
    // Same registry-miss disambiguation as chat_status_hint — without it,
    // the API column rendered "ok (reachable, key rejected)" for a local
    // proxy registry miss, which actively misleads the operator into
    // checking their upstream key when the real fix is local.
    if status == 401 && body.map(body_indicates_registry_miss).unwrap_or(false) {
        // 2026-05-11: two-cause guidance. Registry miss can mean (a) a
        // recent `aikey use` whose seq the proxy's 5-second poller has not
        // picked up yet, or (b) a vault_key inconsistency where managed
        // key ciphertext was written under a different key than the proxy
        // now derives — see workflow/CI/bugfix/2026-05-11-team-key-decrypt-inconsistent.md.
        // The proxy doesn't surface the reason in the 401 body, so we
        // print both recovery paths and let the user pick.
        return "proxy has no route for this key. Causes: (a) just ran `aikey use`? proxy reloads within 5s — retry or `aikey proxy reload`; (b) vault decrypt mismatch — `aikey key sync --force-reencrypt`".to_string();
    }
    match status {
        200 => "valid key".to_string(),
        401 | 403 => "reachable, key rejected".to_string(),
        // 405: API probe is GET, but Anthropic /v1/messages is POST-only,
        // so 405 here = "endpoint exists and rejected our verb" = reachable.
        405 => "reachable".to_string(),
        // 404 — split between the strict-allowlist benign case (e.g.
        // aicoding-class byok proxies that only forward POST /v1/messages)
        // and everything else (treated as upstream-business misconfig, the
        // 5/22 vault-page false-positive case). See SPECIAL CASE comment
        // above `KNOWN_BENIGN_GATEWAY_404_BODIES`.
        404 => {
            if is_known_benign_gateway_404(status, body) {
                "reachable (gateway alive, /v1/models not implemented)".to_string()
            } else {
                "HTTP 404 — upstream resource missing (check base_url / model availability)"
                    .to_string()
            }
        }
        _ => format!("HTTP {}", status),
    }
}

// ---------------------------------------------------------------------------
// Unified connectivity suite (2026-04-21)
//
// One entry point used by `aikey add`, `aikey doctor`, `aikey test`, and
// `aikey test <alias>`. Each caller supplies pre-built TestTargets plus a
// SuiteOptions; this function handles short-circuit (delegated to
// test_provider_connectivity), table rendering, proxy row, and JSON output.
//
// The low-level per-probe short-circuit behaviour — ping fail stops API,
// API fail stops chat — is unchanged: it lives inside
// test_provider_connectivity and is therefore shared automatically.
// ---------------------------------------------------------------------------

/// Run the full suite: probe each target in order, render the table (or
/// JSON payload), optionally append the proxy row, and collect outcomes.
pub fn run_connectivity_suite(
    targets: Vec<TestTarget>,
    opts: SuiteOptions,
    json_mode: bool,
) -> SuiteOutcome {
    use colored::Colorize;

    let mut rows: Vec<(TestTarget, ConnectivityResult)> = Vec::with_capacity(targets.len());
    let mut json_results: Vec<serde_json::Value> = Vec::new();
    let mut any_reachable = false;
    let mut any_chat_ok = false;

    // ── JSON mode: probe all, collect, return; no stderr output. ─────────
    if json_mode {
        for t in &targets {
            let r = test_provider_connectivity(&t.provider_code, &t.base_url, &t.bearer, t.kind);
            if r.chat_ok {
                any_chat_ok = true;
            }
            if r.ping_ok {
                any_reachable = true;
            }
            // Truncate body snippets to 400 chars per row before serialising.
            // The probe layer already caps at ~512, but the Web popup
            // only needs enough to read upstream error JSON ({"error":
            // {"message": "...", "type": "invalid_request_error"}})
            // — a longer paste pushes the table off-screen on small
            // viewports. We surface BOTH api_body_snippet and
            // chat_body_snippet so a 200/401 mix (API auth OK, Chat
            // rejected) shows the exact reason at each stage.
            let trunc = |opt: &Option<String>| -> Option<String> {
                opt.as_ref()
                    .map(|s| s.chars().take(400).collect::<String>())
            };
            json_results.push(serde_json::json!({
                "provider":           t.provider_code,
                "kind":               match t.kind {
                    CredentialKind::PersonalApi  => "personal_api",
                    CredentialKind::ManagedTeam  => "managed_team",
                    CredentialKind::OAuth        => "oauth",
                },
                "source_ref":         t.source_ref,
                "base_url":           t.base_url,
                "via_proxy":          t.kind.via_proxy(),
                "ping_ok":            r.ping_ok,
                "ping_ms":            r.ping_ms,
                "api_ok":             r.api_ok,
                "api_ms":             r.api_ms,
                "api_status":         r.api_status,
                "api_body_snippet":   trunc(&r.api_body_snippet),
                "chat_ok":            r.chat_ok,
                "chat_ms":            r.chat_ms,
                "chat_status":        r.chat_status,
                "chat_body_snippet":  trunc(&r.chat_body_snippet),
            }));
            rows.push((t.clone(), r));
        }

        // Round 9 fix #1: was is_proxy_running (PID-only); now uses
        // proxy_is_running_managed (Layer 1 identity + ownership +
        // /health) so the proxy row only appears when we actually own
        // the running instance.
        let proxy_result = if opts.show_proxy_row
            && any_reachable
            && crate::commands_proxy::proxy_is_running_managed()
        {
            let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
            let prov = targets
                .iter()
                .find(|t| t.provider_code != "custom")
                .map(|t| t.provider_code.as_str());
            prov.map(|p| {
                let r = test_proxy_connectivity(
                    &proxy_addr,
                    p,
                    opts.probe_raw_bearer.as_deref(),
                    opts.probe_raw_base_url.as_deref(),
                    opts.probe_oauth_account_id.as_deref(),
                );
                json_results.push(serde_json::json!({
                    "provider":   "proxy",
                    "proxy_addr": proxy_addr,
                    "ok":         r.ok,
                    "ms":         r.ms,
                    "status":     r.status,
                }));
                r
            })
        } else {
            None
        };

        return SuiteOutcome {
            rows,
            proxy: proxy_result,
            build_errors: Vec::new(),
            any_chat_ok,
            json_results,
        };
    }

    // ── Interactive mode: streaming table to stderr. ─────────────────────
    // Dynamic width: account for the longest display_label + kind suffix so
    // "anthropic (oauth)" never truncates. Pad +2 for breathing room.
    let label_w = targets
        .iter()
        .map(|t| t.display_label().len())
        .max()
        .unwrap_or(12)
        .max("Protocol".len())
        + 2;
    // 2026-05-09: optional Key column for `aikey test --all`. Uses
    // `key_display()` rather than the raw `source_ref` so team rows surface
    // their human alias (`key-335923591-0011-1`) and OAuth rows surface the
    // email / local_alias instead of the bearer-form id (vk_id /
    // provider_account_id). source_ref must stay routing-stable; the
    // friendly label lives in the parallel `display_alias` field that
    // `targets_from_all_keys` populates.
    //
    // Off by default — single-alias / Primary-binding modes have one row per
    // provider so the protocol column already disambiguates. When --all
    // surfaces multiple rows for the same provider (e.g. team + oauth both
    // Anthropic), the Key column is the only way to tell which row goes
    // with which credential.
    // Hard cap Key column width: the row already carries ~92 chars of fixed
    // columns (Protocol + Ping(D) + Ping + API + Chat + padding); adding an
    // unbounded Key column makes the row wrap on standard 120-col terminals,
    // which breaks `animate_blinking_while`'s `\x1b7`/`\x1b8` cursor restore
    // (the wrap scrolls past the saved position, leaving a trail of blink
    // frames instead of overwriting in place — visible on long OAuth emails).
    // 22 covers `key-335923591-0011-1` (20 chars) intact and forces mid-
    // ellipsis truncation on emails — runtime renderer already implements
    // `head…tail` shortening below.
    const KEY_W_CAP: usize = 22;
    let key_w = if opts.show_key_column {
        let raw = targets
            .iter()
            .map(|t| t.key_display().chars().count())
            .max()
            .unwrap_or(8)
            .max("Key".len())
            + 2;
        raw.min(KEY_W_CAP)
    } else {
        0
    };
    // 5/6 columns: [Key] | Protocol | Ping(D) | Ping | API | Chat
    //   Ping(D) = CLI → upstream (independent baseline).
    //   Ping    = CLI → aikey-proxy → upstream (gates API+Chat).
    const W_PD: usize = 14; // "Ping(D)" column, short latency (+" (Xms)")
    const W_PING: usize = 14; // Ping(PROXY)
    const W_API: usize = 34;

    if let Some(header) = opts.header_label {
        eprintln!();
        eprintln!("  \u{1F50C} {}", header.bold());
    }
    if opts.show_key_column {
        eprintln!(
            "  {:<wk$} {:<wp$} {:<wpd$} {:<wpi$} {:<wap$} {}",
            "Key".dimmed(),
            "Protocol".dimmed(),
            "Ping(D)".dimmed(),
            "Ping".dimmed(),
            "API".dimmed(),
            "Chat".dimmed(),
            wk = key_w,
            wp = label_w,
            wpd = W_PD,
            wpi = W_PING,
            wap = W_API
        );
        eprintln!(
            "  {}",
            "\u{2500}"
                .repeat(key_w + label_w + W_PD + W_PING + W_API + 22)
                .dimmed()
        );
    } else {
        eprintln!(
            "  {:<wp$} {:<wpd$} {:<wpi$} {:<wap$} {}",
            "Protocol".dimmed(),
            "Ping(D)".dimmed(),
            "Ping".dimmed(),
            "API".dimmed(),
            "Chat".dimmed(),
            wp = label_w,
            wpd = W_PD,
            wpi = W_PING,
            wap = W_API
        );
        eprintln!(
            "  {}",
            "\u{2500}"
                .repeat(label_w + W_PD + W_PING + W_API + 22)
                .dimmed()
        );
    }

    let mut failed_hints: Vec<String> = Vec::new();
    // Animation column widths must match the printed-result widths so each
    // cell's blink frame occupies the exact slot the formatted result will
    // pin. W_CHAT_ANIM keeps the blink frame compact while the chat result
    // is allowed to bleed past — it's the last column.
    const W_CHAT_ANIM: usize = 10;
    for t in &targets {
        let display = t.display_label();
        if opts.show_key_column {
            // Truncate over-long key labels with a mid-ellipsis so the row
            // doesn't blow out. `key_w` is sized to the longest key_display
            // already, so this only kicks in if a credential's identifier
            // exceeds the column budget after column-cap clamping (rare —
            // mostly OAuth account_id or very long emails).
            let key_src = t.key_display();
            let key_disp = if key_src.chars().count() > key_w.saturating_sub(2) {
                let take = key_w.saturating_sub(3);
                let head: String = key_src.chars().take(take * 2 / 3).collect();
                let tail: String = key_src
                    .chars()
                    .skip(key_src.chars().count() - (take - take * 2 / 3))
                    .collect();
                format!("{head}…{tail}")
            } else {
                key_src.to_string()
            };
            eprint!(
                "  {:<wk$} {:<wp$} ",
                key_disp.dimmed(),
                display.bold(),
                wk = key_w,
                wp = label_w
            );
        } else {
            eprint!("  {:<wp$} ", display.bold(), wp = label_w);
        }
        let _ = io::stderr().flush();

        // Per-column formatter: invoked by `animate_blinking_while` the
        // moment each phase finishes, so the just-completed cell takes its
        // real value while the blink advances to the next column. Centralised
        // here (instead of post-hoc after the probe returns) is what makes
        // "results land left-to-right as phases complete" work.
        let format_cell = |col: usize, r: &ConnectivityResult| -> String {
            match col {
                0 => {
                    // Ping(DIRECT) — dimmed on fail (not a hard error: the
                    // proxy may still reach upstream when the laptop can't).
                    let raw = if r.ping_direct_ok {
                        format!("ok ({}ms)", r.ping_direct_ms)
                    } else {
                        format!("fail ({}ms)", r.ping_direct_ms)
                    };
                    if r.ping_direct_ok {
                        format!("{:<w$}", raw, w = W_PD).green().to_string()
                    } else {
                        format!("{:<w$}", raw, w = W_PD).dimmed().to_string()
                    }
                }
                1 => {
                    // Ping(PROXY) — red on fail (gates API + Chat).
                    let raw = if r.ping_ok {
                        format!("ok ({}ms)", r.ping_ms)
                    } else {
                        format!("fail ({}ms)", r.ping_ms)
                    };
                    if r.ping_ok {
                        format!("{:<w$}", raw, w = W_PING).green().to_string()
                    } else {
                        format!("{:<w$}", raw, w = W_PING).red().to_string()
                    }
                }
                2 => {
                    // API — em-dash placeholder when ping short-circuited;
                    // otherwise normal ok/fail with status hint.
                    if !r.ping_ok {
                        format!("{:<w$}", "\u{2014}", w = W_API)
                            .dimmed()
                            .to_string()
                    } else {
                        let raw = if r.api_ok {
                            let h = r
                                .api_status
                                .map(|s| api_status_hint(s, r.api_body_snippet.as_deref()))
                                .unwrap_or_default();
                            format!("ok ({}ms, {})", r.api_ms, h)
                        } else {
                            // Surface registry-miss reason in the fail cell too
                            // — without it, the operator sees a bare "fail (1ms)"
                            // and has no clue why. Same disambiguation as Chat
                            // column below.
                            let hint = r
                                .api_status
                                .map(|s| {
                                    format!(
                                        ", HTTP {}: {}",
                                        s,
                                        api_status_hint(s, r.api_body_snippet.as_deref())
                                    )
                                })
                                .unwrap_or_default();
                            format!("fail ({}ms{})", r.api_ms, hint)
                        };
                        if r.api_ok {
                            format!("{:<w$}", raw, w = W_API).green().to_string()
                        } else {
                            format!("{:<w$}", raw, w = W_API).red().to_string()
                        }
                    }
                }
                3 => {
                    // Chat — em-dash if ping or api failed; otherwise green
                    // ok with chat hint or red fail with HTTP-status hint.
                    if !r.ping_ok || !r.api_ok {
                        "\u{2014}".dimmed().to_string()
                    } else if r.chat_ok {
                        let h = r
                            .chat_status
                            .map(|s| chat_status_hint(s, r.chat_body_snippet.as_deref()))
                            .unwrap_or_default();
                        format!("ok ({}ms, {})", r.chat_ms, h).green().to_string()
                    } else {
                        let hint = r
                            .chat_status
                            .map(|s| {
                                format!(
                                    ", HTTP {}: {}",
                                    s,
                                    chat_status_hint(s, r.chat_body_snippet.as_deref())
                                )
                            })
                            .unwrap_or_default();
                        format!("fail ({}ms{})", r.chat_ms, hint).red().to_string()
                    }
                }
                _ => String::new(),
            }
        };

        let provider_code = t.provider_code.clone();
        let base_url = t.base_url.clone();
        let bearer = t.bearer.clone();
        let kind = t.kind;
        let r = animate_blinking_while(
            &[W_PD, W_PING, W_API, W_CHAT_ANIM],
            format_cell,
            move |tx| {
                test_provider_connectivity_with_progress(
                    &provider_code,
                    &base_url,
                    &bearer,
                    kind,
                    |phase, stage| {
                        let col = phase.column_index();
                        match stage {
                            ProbeStage::Started => {
                                let _ = tx.send((col, AnimEvent::Started));
                            }
                            ProbeStage::Finished(snap) => {
                                // Clone the borrowed snapshot so it can move
                                // through the channel. ConnectivityResult is
                                // small (5 bools / u128 / Option<u16>) — the
                                // copy cost is negligible vs. the network I/O
                                // each phase already paid for.
                                let _ = tx.send((col, AnimEvent::Finished(snap.clone())));
                            }
                        }
                    },
                )
            },
        );

        // Helper has painted the entire row. End the line so the next
        // target (or the trailing hints / proxy row) starts cleanly.
        eprintln!();

        // Side-effects that drive aggregate state and the failed-hints list.
        // These can't live in `format_cell` (which is called per-column on
        // the rendering thread); they need the full result and the target's
        // metadata (`display`, `t.kind`, etc.).
        if r.ping_ok {
            any_reachable = true;
        }
        if r.chat_ok {
            any_chat_ok = true;
        }

        if !r.ping_ok {
            // If Ping(DIRECT) passed while Ping(PROXY) failed, the proxy
            // itself (not the network) is the problem — actionable hint.
            let hint = if r.ping_direct_ok {
                format!(
                    "{}: proxy can't reach upstream (but your laptop can). \
                         Is `aikey proxy` configured with HTTPS_PROXY / \
                         config.upstream_proxy if your network requires it?",
                    display
                )
            } else {
                format!(
                    "{}: both paths failed — check network / VPN / firewall",
                    display
                )
            };
            failed_hints.push(hint);
        } else if !r.api_ok {
            failed_hints.push(format!(
                "{}: API unreachable — check base URL or provider status",
                display
            ));
        } else if !r.chat_ok {
            // Actionable hint tailored to credential kind + status.
            let suggestion = match (r.chat_status, t.kind, t.provider_code.as_str()) {
                (Some(404), CredentialKind::OAuth, "openai") =>
                    format!("{}: Codex uses Responses API (not Chat Completions) — probe limitation; actual usage works", display),
                (Some(400), _, _) => format!("{}: chat 400 — bad body / missing header", display),
                (Some(401), CredentialKind::OAuth, _) =>
                    format!("{}: chat 401 — token expired. Run: aikey auth login {}", display, t.provider_code),
                (Some(401), _, _) =>
                    format!("{}: chat 401 — invalid key", display),
                (Some(403), _, _) => format!("{}: chat 403 — access denied (subscription?)", display),
                (Some(429), _, _) => format!("{}: chat 429 — rate limited (key is valid)", display),
                (Some(s), _, _) if s >= 500 => format!("{}: chat {} — provider server error", display, s),
                (None, _, _) => format!("{}: chat failed — check ~/.aikey/logs/aikey-proxy/current.jsonl", display),
                (Some(s), _, _) => format!("{}: chat HTTP {} — unexpected", display, s),
            };
            failed_hints.push(suggestion);
        }
        rows.push((t.clone(), r));
    }

    // Closing rule — visually terminates the provider table so the
    // subsequent "failed hints" block and "proxy" row don't look like
    // more table data. Uses the same width + character as the header
    // underline; keep them in lockstep.
    if !rows.is_empty() {
        eprintln!(
            "  {}",
            "\u{2500}"
                .repeat(label_w + W_PD + W_PING + W_API + 22)
                .dimmed()
        );
    }

    if !failed_hints.is_empty() {
        eprintln!();
        for hint in &failed_hints {
            eprintln!("  {} {}", "\u{2192}".dimmed(), hint.dimmed());
        }
    }

    // ── Proxy row. ────────────────────────────────────────────────────────
    let proxy_result = if opts.show_proxy_row {
        eprintln!();
        if !any_reachable {
            eprintln!(
                "  {:<12} {}",
                "proxy".bold(),
                "skipped (all providers unreachable)".dimmed()
            );
            None
        } else if crate::commands_proxy::proxy_is_running_managed() {
            // Round 9 fix #1: was is_proxy_running (PID-only); see top of fn.
            let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
            let prov = targets
                .iter()
                .find(|t| t.provider_code != "custom")
                .map(|t| t.provider_code.as_str());
            if let Some(p) = prov {
                eprint!("  {:<12} ", "proxy".bold());
                let _ = io::stderr().flush();
                // Single-column animation reusing the same primitive. The
                // proxy probe is one HTTP call (~200 ms) — wrapping it as a
                // 1-phase event keeps every connectivity surface painted with
                // the same blinking-eyes affordance instead of a frozen line.
                // The cell formatter renders ok/fail with status hint inline,
                // so the helper paints the result the moment the probe ends.
                let proxy_addr_owned = proxy_addr.clone();
                let prov_owned = p.to_string();
                // Move bearer/base_url options into closure as owned values
                // (animate_blinking_while runs the worker fn on a worker thread).
                let probe_bearer_owned = opts.probe_raw_bearer.clone();
                let probe_base_url_owned = opts.probe_raw_base_url.clone();
                let probe_oauth_owned = opts.probe_oauth_account_id.clone();
                let format_proxy_cell = |_col: usize, r: &ProxyProbeResult| -> String {
                    // 2026-05-26 — use proxy_probe_full_hint so probe_raw
                    // error_codes (PROXY_TOO_OLD_NO_PROBE_RAW etc) surface
                    // as user-actionable text instead of opaque "HTTP 401".
                    let h = proxy_probe_full_hint(r);
                    if r.ok {
                        // For probe_raw mode with PROXY_TOO_OLD_NO_PROBE_RAW the
                        // status comes back as 401 (TokenInvalid) — ok=true is
                        // misleading (proxy returned, but with the wrong verdict).
                        // Render as "failed" when error_code is set.
                        if r.error_code.is_some() {
                            format!("{} ({} ms, {})", "failed".red(), r.ms, h)
                        } else {
                            format!("{} ({} ms, {})", "ok".green(), r.ms, h)
                        }
                    } else {
                        format!("{} ({} ms)", "failed".red(), r.ms)
                    }
                };
                let r = animate_blinking_while(&[12], format_proxy_cell, move |tx| {
                    let _ = tx.send((0, AnimEvent::Started));
                    let r = test_proxy_connectivity(
                        &proxy_addr_owned,
                        &prov_owned,
                        probe_bearer_owned.as_deref(),
                        probe_base_url_owned.as_deref(),
                        probe_oauth_owned.as_deref(),
                    );
                    let _ = tx.send((0, AnimEvent::Finished(r.clone())));
                    r
                });
                // Helper has painted the cell. Just close the line.
                eprintln!();
                Some(r)
            } else {
                eprintln!(
                    "  {:<12} {}",
                    "proxy".bold(),
                    "skipped — no testable provider".dimmed()
                );
                None
            }
        } else {
            eprintln!("  {:<12} {}", "proxy".bold(), "not running".dimmed());
            None
        }
    } else {
        None
    };

    SuiteOutcome {
        rows,
        proxy: proxy_result,
        build_errors: Vec::new(),
        any_chat_ok,
        json_results,
    }
}

/// Render the "cannot test" block beneath the suite output.
///
/// Each entry explains why the target could not be constructed (proxy down,
/// missing password, team key not yet synced, etc.) along with an
/// actionable next step.  No-op when `errors` is empty.
pub fn render_cannot_test_block(errors: &[BuildTargetError], json_mode: bool) {
    use colored::Colorize;
    if errors.is_empty() {
        return;
    }
    if json_mode {
        return;
    } // JSON already captures this via callsite metadata.

    eprintln!();
    eprintln!("  {}", "Cannot test:".yellow());
    let w = errors
        .iter()
        .map(|e| e.label().len())
        .max()
        .unwrap_or(0)
        .max(12);
    for e in errors {
        eprintln!("  {:<w$}  {}", e.label().bold(), e.reason().dimmed(), w = w);
    }
}

#[cfg(test)]
mod build_chat_probe_tests {
    //! Regression guard for bugfix
    //! 20260523-aikey-test-anthropic-via-proxy-misadds-beta-query.md.
    //!
    //! Before the fix, the OAuth-only `?beta=true` + metadata.user_id addons
    //! were applied to ANY anthropic request via aikey-proxy — including
    //! personal API keys whose base_url happens to point at the proxy. That
    //! made `aikey test claude` fail with 404 against custom anthropic
    //! gateways (e.g. aicoding) which don't implement the OAuth variant.
    //!
    //! Post-fix: protocol addons are driven by `kind == OAuth` via the
    //! `protocol_addons` config table. These tests pin three load-bearing
    //! cases.
    use super::*;

    #[test]
    fn anthropic_oauth_via_proxy_gets_beta_query_and_metadata() {
        let (url, body) = build_chat_probe(
            "anthropic",
            "http://127.0.0.1:27200/anthropic",
            "aikey_probe_some-account-id",
            CredentialKind::OAuth,
        );
        assert!(
            url.contains("?beta=true"),
            "anthropic OAuth must add ?beta=true; got: {}",
            url
        );
        let meta = body
            .get("metadata")
            .expect("OAuth body must inject metadata.user_id");
        assert_eq!(meta["user_id"], "aikey_doctor_probe");
    }

    /// **Bug 1 regression**: a personal API key whose vault entry happens to
    /// have base_url forwarded through aikey-proxy (e.g. user-defined
    /// `https://aicoding.example.com/anthropic/v1` exposed as a personal
    /// alias) MUST NOT get the OAuth-only `?beta=true` addon. Aicoding-class
    /// gateways do not implement the OAuth variant and return 404.
    #[test]
    fn anthropic_personal_via_proxy_does_not_add_beta_query() {
        let (url, body) = build_chat_probe(
            "anthropic",
            "http://127.0.0.1:27200/anthropic",
            "aikey_probe_my-claude",
            CredentialKind::PersonalApi,
        );
        assert!(
            !url.contains("beta=true"),
            "personal API key MUST NOT add OAuth-only ?beta=true; got: {}",
            url
        );
        assert!(
            body.get("metadata").is_none(),
            "personal API key MUST NOT inject metadata.user_id; got body: {}",
            body
        );
        // body still carries the normal anthropic chat shape
        assert!(body.get("messages").is_some());
        assert_eq!(body.get("max_tokens").and_then(|v| v.as_i64()), Some(1));
    }

    #[test]
    fn anthropic_personal_direct_does_not_add_beta_query() {
        // Even when base_url is the official Anthropic API host directly (not via proxy),
        // personal API keys still take the clean path.
        let (url, body) = build_chat_probe(
            "anthropic",
            "https://api.anthropic.com",
            "sk-ant-api03-real-key",
            CredentialKind::PersonalApi,
        );
        assert!(
            !url.contains("beta=true"),
            "personal-direct anthropic MUST NOT add ?beta=true; got: {}",
            url
        );
        assert!(body.get("metadata").is_none());
    }

    #[test]
    fn codex_oauth_uses_responses_path_and_responses_body() {
        let (url, body) = build_chat_probe(
            "openai",
            "http://127.0.0.1:27200/openai",
            "aikey_probe_chatgpt-account",
            CredentialKind::OAuth,
        );
        assert!(
            url.ends_with("/responses"),
            "Codex OAuth must use /responses; got: {}",
            url
        );
        assert_eq!(body["model"], "gpt-5.4");
        assert_eq!(body["store"], false);
        assert_eq!(body["stream"], true);
    }

    #[test]
    fn openai_personal_via_proxy_uses_chat_completions_clean() {
        // Symmetric of the anthropic case: openai personal API key
        // must NOT take the Codex Responses-API path.
        let (url, body) = build_chat_probe(
            "openai",
            "http://127.0.0.1:27200/openai",
            "aikey_probe_my-openai",
            CredentialKind::PersonalApi,
        );
        assert!(
            !url.contains("/responses"),
            "personal openai MUST NOT use Codex /responses path; got: {}",
            url
        );
        assert!(
            url.ends_with("/chat/completions") || url.ends_with("/v1/chat/completions"),
            "personal openai must hit chat/completions; got: {}",
            url
        );
        // standard chat body — not Responses API
        assert!(body.get("messages").is_some());
        assert!(body.get("input").is_none());
    }

    #[test]
    fn google_personal_appends_key_query_param() {
        let (url, _body) = build_chat_probe(
            "google",
            "https://generativelanguage.googleapis.com",
            "AIzaSy-fake-key",
            CredentialKind::PersonalApi,
        );
        assert!(
            url.contains("?key=AIzaSy-fake-key"),
            "google personal must use ?key= auth query; got: {}",
            url
        );
    }

    // ── 404 special-case allowlist (bugfix 20260523 round-2, revised) ──
    //
    // Strict-equality allowlist. Each entry MUST be a literal body
    // observed from a real byok gateway. DO NOT add substring / shape
    // checks here — see the SPECIAL CASE comment above
    // `KNOWN_BENIGN_GATEWAY_404_BODIES`.

    #[test]
    fn allowlist_exempts_exact_go_default_404() {
        // Both forms (with and without trailing newline) — Go ServeMux's
        // serveError writes "...\n", the body reader may or may not strip it.
        assert!(is_known_benign_gateway_404(404, Some("404 page not found")));
        assert!(is_known_benign_gateway_404(
            404,
            Some("404 page not found\n")
        ));
    }

    #[test]
    fn allowlist_rejects_anything_not_an_exact_literal_match() {
        // Other 404 body shapes — even if they look "404-ish" — MUST stay
        // on the main fail path, preserving the 2026-05-22 vault-page
        // false-positive guard.
        let cases = [
            // JSON business envelope
            r#"{"error":{"type":"not_found_error","message":"model not found"}}"#,
            // HTML page (nginx default etc.)
            "<html><title>404 Not Found</title></html>",
            // Plain text variations — explicitly NOT exempted, because
            // any unconfirmed "looks like Go" body could be a real
            // upstream business message.
            "Not Found",
            "404 not found",
            "Page Not Found",
            // Empty body — explicitly NOT exempted.
            "",
            "   ",
        ];
        for body in cases {
            assert!(
                !is_known_benign_gateway_404(404, Some(body)),
                "unallowlisted body must NOT be exempted (kept on main fail path): {:?}",
                body
            );
        }
    }

    #[test]
    fn allowlist_only_applies_to_404_status() {
        // The allowlist is gated on 404. Same body text on other status
        // codes is irrelevant to the gateway-404 exception.
        for status in [200, 401, 403, 405, 500] {
            assert!(
                !is_known_benign_gateway_404(status, Some("404 page not found")),
                "allowlist must not bypass non-404 statuses (got status={})",
                status
            );
        }
    }

    #[test]
    fn api_status_hint_404_differentiates_allowlisted_vs_other() {
        // Allowlisted gateway-default body — hint reads as reachable.
        let gateway = api_status_hint(404, Some("404 page not found"));
        assert!(
            gateway.contains("reachable"),
            "allowlisted gateway 404 must read as reachable, got: {}",
            gateway
        );
        assert!(
            gateway.contains("not implemented") || gateway.contains("gateway alive"),
            "allowlisted gateway 404 hint must explain why, got: {}",
            gateway
        );

        // Non-allowlisted body — falls through to the upstream-business hint.
        let upstream = api_status_hint(404, Some(r#"{"error":{"type":"not_found_error"}}"#));
        assert!(
            upstream.starts_with("HTTP 404"),
            "non-allowlisted 404 must surface as visible HTTP 404, got: {}",
            upstream
        );
        assert!(
            upstream.contains("base_url") || upstream.contains("model"),
            "non-allowlisted 404 hint must guide operator to check config, got: {}",
            upstream
        );
    }

    #[test]
    fn managed_team_credential_takes_clean_anthropic_path() {
        // Team-managed virtual keys are not OAuth — they MUST take the same
        // clean URL as personal API keys, regardless of proxy routing.
        let (url, body) = build_chat_probe(
            "anthropic",
            "http://127.0.0.1:27200/anthropic",
            "aikey_team_vk_xxx",
            CredentialKind::ManagedTeam,
        );
        assert!(
            !url.contains("beta=true"),
            "ManagedTeam MUST NOT add OAuth-only ?beta=true; got: {}",
            url
        );
        assert!(body.get("metadata").is_none());
    }
}

#[cfg(test)]
mod proxy_probe_regression_tests {
    //! Regression guard for 2026-04-22 test_proxy_connectivity fix.
    //!
    //! The original bug: `ureq::get()` shortcut was inheriting the user's
    //! `http_proxy` / `https_proxy` env vars, which routed every 127.0.0.1
    //! probe through Clash / a corporate proxy and reported "failed (10 ms)"
    //! even though the local aikey-proxy was running. Additionally the probe
    //! did not set `X-Aikey-Probe: 1`, so every invocation polluted the
    //! collector with a synthetic usage event.
    //!
    //! We can't test the real function end-to-end without standing up a full
    //! proxy, but we can stand up a minimal mock HTTP server on 127.0.0.1
    //! that records the incoming request headers, then verify (a) the probe
    //! reaches it even when `HTTPS_PROXY` env points at a black hole and
    //! (b) it carries the `X-Aikey-Probe: 1` header. Both assertions must
    //! hold or the user-facing "failed bottom row" / "collector polluted"
    //! regressions return.
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    /// Minimal one-shot HTTP/1.1 server on 127.0.0.1:<random>. Captures the
    /// raw request bytes so the test can assert on headers, then replies
    /// with a 200. Returns (port, captured-request handle, join handle).
    fn spawn_capture_server() -> (u16, Arc<Mutex<Vec<u8>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_cl = Arc::clone(&captured);
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = [0u8; 4096];
                // One read is enough for HEAD-sized requests; good enough
                // for the assertions we need.
                if let Ok(n) = stream.read(&mut buf) {
                    captured_cl.lock().unwrap().extend_from_slice(&buf[..n]);
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        });
        (port, captured, handle)
    }

    #[test]
    fn probe_sets_x_aikey_probe_header() {
        let (port, captured, handle) = spawn_capture_server();
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(2))
            .build();
        let url = format!("http://127.0.0.1:{}/anthropic/v1/models", port);
        let _ = agent.get(&url).set("X-Aikey-Probe", "1").call();
        handle.join().ok();

        let req = captured.lock().unwrap();
        let text = String::from_utf8_lossy(&req);
        assert!(
            text.to_lowercase().contains("x-aikey-probe: 1"),
            "probe must set X-Aikey-Probe: 1 to suppress collector usage events; \
             got request: {}",
            text
        );
    }

    #[test]
    fn probe_agent_ignores_https_proxy_env() {
        // Point HTTPS_PROXY at a port nobody is listening on. If the probe
        // agent inherits env, it tries to tunnel through this dead port and
        // fails. With an explicit no-proxy agent it connects straight to
        // our 127.0.0.1 capture server and succeeds.
        //
        // `std::env::set_var` mutates process-global state, so this test
        // cannot run in parallel with anything else touching HTTPS_PROXY.
        // cargo test runs tests within the same binary in parallel by
        // default — we accept that risk here because (a) this binary's other
        // tests don't touch HTTPS_PROXY and (b) the capture-server URL is
        // unique per test so we won't collide on the port either.
        //
        // SAFETY: set_var is unsafe in Rust edition 2024 because non-test
        // threads may read env concurrently. In this cfg(test) context only
        // the test thread exists meaningfully.
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
        }
        unsafe {
            std::env::set_var("https_proxy", "http://127.0.0.1:1");
        }

        let (port, _captured, handle) = spawn_capture_server();
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(2))
            .build();
        let url = format!("http://127.0.0.1:{}/anthropic/v1/models", port);
        let result = agent.get(&url).call();
        handle.join().ok();

        unsafe {
            std::env::remove_var("HTTPS_PROXY");
        }
        unsafe {
            std::env::remove_var("https_proxy");
        }

        // If env-proxy was inherited, the call goes to 127.0.0.1:1 (dead)
        // and errors out. Explicit no-proxy agent must reach our capture
        // server and get the 200.
        assert!(
            result.is_ok(),
            "probe agent must NOT inherit HTTPS_PROXY env var — the runtime \
             proxy is on 127.0.0.1 and routing that through Clash/corporate \
             proxies produces bogus 'failed (10 ms)' bottom row"
        );
    }
}

#[cfg(test)]
mod probe_model_kimi_split_tests {
    //! 2026-05-08 Kimi 双平台拆分 review feedback (medium): probe_model 此前
    //! 只有 "kimi" case (返回 moonshot-v1-8k),拆分后 kimi_code/moonshot 都
    //! fallback 到 gpt-4o-mini → api.kimi.com 探针被 reject (model not found),
    //! aikey doctor 报错误诊断。下面锁定每条 family 内 provider_code 的 model:

    use super::probe_model;

    #[test]
    fn probe_model_kimi_code_uses_kimi_k2_5() {
        assert_eq!(probe_model("kimi_code"), "kimi-k2.5");
    }

    #[test]
    fn probe_model_moonshot_uses_moonshot_v1_8k() {
        assert_eq!(probe_model("moonshot"), "moonshot-v1-8k");
    }

    #[test]
    fn probe_model_kimi_deprecated_alias_matches_kimi_code() {
        // Defense:老 vault 数据 / 手工构造的 'kimi' 字面值仍能跑探针。
        assert_eq!(probe_model("kimi"), "kimi-k2.5");
    }

    #[test]
    fn probe_model_unknown_falls_back_to_gpt_4o_mini() {
        // 未知 provider 走 fallback,大多数 OpenAI-compat gateway 都接受 gpt-4o-mini。
        assert_eq!(probe_model("some-new-aggregator"), "gpt-4o-mini");
    }
}

#[cfg(test)]
mod probe_raw_request_shape_tests {
    //! 2026-05-26 — Pin the on-wire request shape of `test_proxy_connectivity`
    //! in both modes. These tests use a mock HTTP server to capture exactly
    //! what header set the function sends, validating the contract from
    //! roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md §5.1
    //! without depending on a running aikey-proxy.
    //!
    //! Two invariants pinned:
    //!
    //! (A) **None mode = byte-equivalent legacy**: `bearer_override = None`
    //!     emits the exact wire shape that pre-2026-05-26 code did —
    //!     `Authorization: Bearer aikey_active_<provider>` + `X-Aikey-Probe: 1`
    //!     and NO X-Aikey-Probe-Bearer / -BaseURL headers. Regression-locks
    //!     the 5 post-save call sites (aikey test, doctor, vault-op test).
    //!
    //! (B) **Some mode emits probe_raw shape**: `bearer_override = Some(raw)`
    //!     emits `Authorization: Bearer aikey_probe_raw_<provider>` (NOT
    //!     active) + `X-Aikey-Probe: 1` + `X-Aikey-Probe-Bearer: <raw>` +
    //!     optionally `X-Aikey-Probe-BaseURL: <base>`. Regression-locks
    //!     the 2 pre-save call sites (aikey add, vault-op test_raw).

    use super::test_proxy_connectivity;
    use std::sync::{Arc, Mutex};

    // Mini HTTP server that captures the first request's headers + path,
    // returns a canned 200 response, then closes. No external deps (re-uses
    // std::net so we don't pull in hyper/tokio for fence tests).
    fn capture_one_request() -> (String, Arc<Mutex<Option<CapturedRequest>>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr").to_string();
        let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Set read timeout so test doesn't hang on hung client.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));

                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line);

                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    let n = reader.read_line(&mut h).unwrap_or(0);
                    if n == 0 || h == "\r\n" || h == "\n" {
                        break;
                    }
                    headers.push(h.trim_end_matches(['\r', '\n']).to_string());
                }
                // Drain any body so the client's write completes (we don't care
                // about body content for these tests).
                let mut buf = [0u8; 1024];
                let _ = reader
                    .get_mut()
                    .set_read_timeout(Some(std::time::Duration::from_millis(50)));
                let _ = reader.get_mut().read(&mut buf);

                let captured_req = CapturedRequest {
                    request_line: req_line.trim_end_matches(['\r', '\n']).to_string(),
                    headers,
                };
                *captured_clone.lock().unwrap() = Some(captured_req);

                // Reply 200 OK with a minimal body.
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                );
                let _ = stream.flush();
            }
        });

        (addr, captured)
    }

    #[derive(Debug)]
    struct CapturedRequest {
        request_line: String,
        headers: Vec<String>,
    }

    impl CapturedRequest {
        fn header_value(&self, name: &str) -> Option<String> {
            let target = name.to_ascii_lowercase();
            self.headers.iter().find_map(|h| {
                let mut parts = h.splitn(2, ':');
                let k = parts.next()?.trim().to_ascii_lowercase();
                let v = parts.next()?.trim().to_string();
                if k == target {
                    Some(v)
                } else {
                    None
                }
            })
        }

        fn has_header(&self, name: &str) -> bool {
            self.header_value(name).is_some()
        }
    }

    // Helper: poll captured until set, with timeout (probe call is sync from
    // the test thread's perspective so this typically returns immediately).
    fn wait_for_capture(captured: &Arc<Mutex<Option<CapturedRequest>>>) -> CapturedRequest {
        for _ in 0..50 {
            if let Some(c) = captured.lock().unwrap().take() {
                return c;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("mock server did not capture any request within timeout");
    }

    // ───── Invariant (A): None mode = legacy aikey_active_* shape ─────

    #[test]
    fn none_mode_emits_legacy_active_sentinel_shape() {
        let (addr, captured) = capture_one_request();

        // Run probe in None mode (mirrors all 5 post-save call sites).
        let _ = test_proxy_connectivity(&addr, "anthropic", None, None, None);

        let req = wait_for_capture(&captured);

        // Path goes /anthropic/v1/messages (or whatever probe_suffix picks
        // for anthropic). Critical part is the URL has /anthropic/ prefix.
        assert!(
            req.request_line.contains("/anthropic/"),
            "request path missing /anthropic/ prefix: {}",
            req.request_line
        );

        // X-Aikey-Probe: 1 ALWAYS present (suppresses reporter on proxy side).
        assert_eq!(
            req.header_value("X-Aikey-Probe").as_deref(),
            Some("1"),
            "X-Aikey-Probe: 1 missing — would let probe traffic hit reporter"
        );

        // Anthropic uses x-api-key; bearer value MUST be the active sentinel.
        let key = req.header_value("x-api-key").expect("x-api-key missing");
        assert_eq!(
            key, "aikey_active_anthropic",
            "None mode must emit aikey_active_<provider>, got: {}",
            key
        );

        // Critical regression fence: NO probe_raw headers must appear in None mode.
        // If these leak, the 5 post-save call sites silently change semantics.
        assert!(
            !req.has_header("X-Aikey-Probe-Bearer"),
            "X-Aikey-Probe-Bearer leaked into None-mode request (silent regression of 5 post-save call sites)"
        );
        assert!(
            !req.has_header("X-Aikey-Probe-BaseURL"),
            "X-Aikey-Probe-BaseURL leaked into None-mode request"
        );
    }

    #[test]
    fn none_mode_openai_emits_authorization_bearer_active() {
        let (addr, captured) = capture_one_request();

        let _ = test_proxy_connectivity(&addr, "openai", None, None, None);

        let req = wait_for_capture(&captured);

        // OpenAI uses Authorization: Bearer <token>.
        let auth = req
            .header_value("Authorization")
            .expect("Authorization missing");
        assert_eq!(
            auth, "Bearer aikey_active_openai",
            "openai None mode must emit Bearer aikey_active_<provider>, got: {}",
            auth
        );

        assert!(!req.has_header("X-Aikey-Probe-Bearer"));
        assert!(!req.has_header("X-Aikey-Probe-BaseURL"));
    }

    // ───── Invariant (B): Some mode emits probe_raw shape ─────

    #[test]
    fn some_mode_emits_probe_raw_token_and_bearer_header() {
        let (addr, captured) = capture_one_request();
        let plaintext_key = "sk-ant-PRE-SAVE-PROBE-KEY";

        // Mirrors `aikey add` / `vault-op test_raw` call site after Phase 2.B/C.
        let _ = test_proxy_connectivity(&addr, "anthropic", Some(plaintext_key), None, None);

        let req = wait_for_capture(&captured);

        // Bearer is probe_raw token, NOT active sentinel.
        let key = req.header_value("x-api-key").expect("x-api-key missing");
        assert_eq!(
            key, "aikey_probe_raw_anthropic",
            "Some mode must emit aikey_probe_raw_<provider>, got: {}",
            key
        );

        // X-Aikey-Probe: 1 still present.
        assert_eq!(req.header_value("X-Aikey-Probe").as_deref(), Some("1"));

        // X-Aikey-Probe-Bearer carries the plaintext key (proxy uses this
        // value to authenticate to upstream; never falls to vault).
        assert_eq!(
            req.header_value("X-Aikey-Probe-Bearer").as_deref(),
            Some(plaintext_key),
            "X-Aikey-Probe-Bearer missing or wrong value"
        );

        // base_url_override = None → no BaseURL header.
        assert!(
            !req.has_header("X-Aikey-Probe-BaseURL"),
            "BaseURL header set despite None override"
        );
    }

    #[test]
    fn some_mode_with_base_url_emits_baseurl_header() {
        let (addr, captured) = capture_one_request();
        let plaintext_key = "sk-test";
        let custom_base = "https://my-enterprise-gateway.example.com/v1";

        let _ = test_proxy_connectivity(
            &addr,
            "anthropic",
            Some(plaintext_key),
            Some(custom_base),
            None,
        );

        let req = wait_for_capture(&captured);

        assert_eq!(
            req.header_value("X-Aikey-Probe-BaseURL").as_deref(),
            Some(custom_base),
            "X-Aikey-Probe-BaseURL not set when base_url_override is Some"
        );
    }

    #[test]
    fn some_mode_empty_base_url_does_not_send_baseurl_header() {
        // Defense: pre-trimmed empty string should NOT emit empty BaseURL header
        // (would confuse proxy's empty-vs-missing check). vault_op.rs::handle_test_raw
        // pre-filters this with `if .is_empty() { None }` but defense-in-depth.
        let (addr, captured) = capture_one_request();
        let _ = test_proxy_connectivity(&addr, "anthropic", Some("sk-test"), Some(""), None);

        let req = wait_for_capture(&captured);
        assert!(
            !req.has_header("X-Aikey-Probe-BaseURL"),
            "empty base_url override leaked as empty BaseURL header — proxy should not see empty values"
        );
    }

    #[test]
    fn probe_raw_anthropic_always_sends_anthropic_version_header() {
        // E2E finding 2026-05-26 (run #2): without anthropic-version header,
        // Anthropic returns 400 "anthropic-version: header is required" even
        // for valid keys. Send the header in both modes so probe_raw can
        // distinguish "valid key + endpoint happy (200)" from "key rejected
        // (401)". Allowlisted on proxy side (probe_raw.go::outboundHeaderAllowlist).
        let (addr, captured) = capture_one_request();
        let _ = test_proxy_connectivity(&addr, "anthropic", Some("sk-ant-test"), None, None);
        let req = wait_for_capture(&captured);
        assert_eq!(
            req.header_value("anthropic-version").as_deref(),
            Some("2023-06-01"),
            "anthropic probe_raw must send anthropic-version header so upstream returns clear verdict (200 valid / 401 rejected) instead of 400 'header required'"
        );
    }

    #[test]
    fn probe_raw_anthropic_sends_anthropic_version_in_none_mode_too() {
        // Defense: the header is sent regardless of mode (matches behavior in
        // existing chat probe path runtime.rs:640). post-save active sentinel
        // mode also benefits — but we mainly care that no regression here.
        let (addr, captured) = capture_one_request();
        let _ = test_proxy_connectivity(&addr, "anthropic", None, None, None);
        let req = wait_for_capture(&captured);
        assert_eq!(
            req.header_value("anthropic-version").as_deref(),
            Some("2023-06-01"),
        );
    }

    #[test]
    fn probe_raw_non_anthropic_provider_does_not_send_anthropic_version() {
        // openai etc shouldn't receive an Anthropic-specific header — would
        // be ignored but pollutes the wire. Pin per-provider exclusivity.
        let (addr, captured) = capture_one_request();
        let _ = test_proxy_connectivity(&addr, "openai", Some("sk-test"), None, None);
        let req = wait_for_capture(&captured);
        assert!(
            !req.has_header("anthropic-version"),
            "non-anthropic provider must not send anthropic-version header"
        );
    }

    #[test]
    fn some_mode_openai_provider_emits_authorization_bearer_probe_raw() {
        let (addr, captured) = capture_one_request();
        let _ = test_proxy_connectivity(&addr, "openai", Some("sk-openai-test"), None, None);

        let req = wait_for_capture(&captured);

        let auth = req
            .header_value("Authorization")
            .expect("Authorization missing");
        assert_eq!(
            auth, "Bearer aikey_probe_raw_openai",
            "openai Some mode must emit Bearer aikey_probe_raw_<provider>, got: {}",
            auth
        );
        assert_eq!(
            req.header_value("X-Aikey-Probe-Bearer").as_deref(),
            Some("sk-openai-test")
        );
    }
}

#[cfg(test)]
mod probe_raw_error_classification_tests {
    //! 2026-05-26 — Phase 2.D: pin the user-experience contract for the
    //! "no fallback" decision. When proxy returns specific errors, CLI must
    //! produce stable `error_code` strings that downstream (UI / CLI hints)
    //! can render as user-actionable text.
    //!
    //! No-fallback fence: the test for `PROXY_TOO_OLD_NO_PROBE_RAW` is
    //! particularly important — it pins that we DO NOT silently retry with
    //! `aikey_active_*` per user decision 2026-05-26 (silent fallback would
    //! mask "test the wrong key" with another wrong-key test).

    use super::{proxy_probe_full_hint, test_proxy_connectivity, ProxyProbeResult};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Mock proxy returning a single canned JSON-error response.
    /// Used to simulate (a) old proxy returning TOKEN_INVALID,
    /// (b) new proxy with flag off returning PROBE_RAW_DISABLED,
    /// (c) defensive 401 PROBE_HEADER_REQUIRED.
    fn mock_proxy_returning(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr").to_string();
        let body_owned = body.to_string();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                // Drain request line + headers.
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                loop {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).unwrap_or(0);
                    if n == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let reason = match status {
                    401 => "Unauthorized",
                    503 => "Service Unavailable",
                    _ => "Error",
                };
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    status,
                    reason,
                    body_owned.len(),
                    body_owned
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        addr
    }

    // ───── Old proxy: 401 + TOKEN_INVALID → PROXY_TOO_OLD_NO_PROBE_RAW ─────
    //
    // CRITICAL FENCE per user decision 2026-05-26: no silent fallback.
    // Old proxy treats aikey_probe_raw_* as TokenInvalid. We must surface
    // PROXY_TOO_OLD_NO_PROBE_RAW so user knows to restart proxy, NOT silently
    // re-call with aikey_active_* (which tests the wrong key).

    #[test]
    fn old_proxy_returns_token_invalid_classified_as_too_old() {
        let addr = mock_proxy_returning(
            401,
            r#"{"error":{"code":"TOKEN_INVALID","message":"unknown token form","type":"authentication_error"}}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-pre-save"), None, None);

        assert_eq!(
            r.error_code.as_deref(),
            Some("PROXY_TOO_OLD_NO_PROBE_RAW"),
            "401 + TOKEN_INVALID in probe_raw mode must classify as PROXY_TOO_OLD_NO_PROBE_RAW"
        );
        assert_eq!(r.status, Some(401));
    }

    #[test]
    fn proxy_too_old_hint_tells_user_to_restart_proxy() {
        // proxy_probe_full_hint must render this in actionable text — not
        // just regurgitate the error code.
        let r = ProxyProbeResult {
            ok: true,
            ms: 50,
            status: Some(401),
            error_code: Some("PROXY_TOO_OLD_NO_PROBE_RAW".to_string()),
        };
        let hint = proxy_probe_full_hint(&r);
        assert!(
            hint.contains("aikey service restart proxy"),
            "hint must include the recovery action, got: {}",
            hint
        );
        assert!(
            hint.contains("too old"),
            "hint must explain why (proxy too old), got: {}",
            hint
        );
    }

    // ───── PROBE_RAW_DISABLED: defense rollback flag ─────

    #[test]
    fn flag_disabled_503_classified_as_probe_raw_disabled() {
        let addr = mock_proxy_returning(
            503,
            r#"{"error":{"code":"PROBE_RAW_DISABLED","message":"flag off","type":"server_error"}}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-test"), None, None);

        assert_eq!(
            r.error_code.as_deref(),
            Some("PROBE_RAW_DISABLED"),
            "503 + PROBE_RAW_DISABLED must classify as PROBE_RAW_DISABLED"
        );
    }

    // ───── PROBE_HEADER_REQUIRED: caller-side bug defense ─────

    #[test]
    fn missing_probe_header_401_classified_as_probe_header_required() {
        // We always send X-Aikey-Probe: 1 — this fence catches regression where
        // a future code change accidentally strips it. proxy_probe_full_hint
        // surfaces this as a BUG indicator, not a user-actionable error.
        let addr = mock_proxy_returning(
            401,
            r#"{"error":{"code":"PROBE_HEADER_REQUIRED","message":"missing X-Aikey-Probe","type":"authentication_error"}}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-test"), None, None);

        assert_eq!(r.error_code.as_deref(), Some("PROBE_HEADER_REQUIRED"),);
        let hint = proxy_probe_full_hint(&r);
        assert!(
            hint.contains("BUG"),
            "PROBE_HEADER_REQUIRED hint must signal client bug, got: {}",
            hint
        );
    }

    // ───── None mode (post-save) — error_code NEVER set ─────
    //
    // Critical fence: we only classify probe_raw errors. The 5 post-save
    // call sites (aikey test [<alias>], doctor, vault-op test) must not
    // suddenly start getting error_code populated — that would change
    // their existing UX.

    #[test]
    fn none_mode_never_sets_error_code_even_on_401() {
        let addr = mock_proxy_returning(
            401,
            r#"{"error":{"code":"TOKEN_INVALID","message":"x","type":"y"}}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", None, None, None);

        assert_eq!(
            r.error_code, None,
            "None mode (post-save) must NEVER set error_code — would change existing UX of 5 call sites"
        );
    }

    // ───── Unknown error code in probe_raw mode: pass through PROBE_* prefix ─────

    #[test]
    fn unknown_probe_error_code_passes_through_when_prefixed() {
        // Defense: if proxy adds a new PROBE_* error code in a future version,
        // it should still surface (not be swallowed). Our `proxy_probe_full_hint`
        // renders "proxy error: <code>" so even unknown codes get displayed.
        let addr = mock_proxy_returning(
            400,
            r#"{"error":{"code":"PROBE_FUTURE_ERROR","message":"x","type":"y"}}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-test"), None, None);

        assert_eq!(r.error_code.as_deref(), Some("PROBE_FUTURE_ERROR"));
    }

    // ───── Non-PROBE_ error codes in probe_raw mode: do NOT capture (no false matches) ─────

    #[test]
    fn non_probe_error_codes_not_captured() {
        // Vault errors, provider errors etc shouldn't be mistakenly classified.
        // Only PROBE_* prefix and the specific (401, TOKEN_INVALID) case match.
        let addr = mock_proxy_returning(
            500,
            r#"{"error":{"code":"VAULT_ERROR","message":"x","type":"server_error"}}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-test"), None, None);

        assert_eq!(
            r.error_code, None,
            "VAULT_ERROR must not be captured as probe_raw error"
        );
        assert_eq!(r.status, Some(500), "but raw status should still surface");
    }

    // ───── proxy_status_hint legacy callers unaffected ─────

    #[test]
    fn legacy_proxy_status_hint_unchanged() {
        // 5 post-save call sites still use proxy_status_hint(s) via the
        // closure's `r.status.map(...)` path when error_code is None.
        // Pin existing return strings.
        use super::proxy_status_hint;
        assert_eq!(proxy_status_hint(200), "routing ok, key valid");
        assert_eq!(
            proxy_status_hint(401),
            "routing ok, key rejected by provider"
        );
        assert_eq!(
            proxy_status_hint(503),
            "proxy has no active key for this provider"
        );
    }

    // ───── probe_raw upstream_status extraction (E2E-2 finding fix) ─────
    //
    // Pin spec §2.4 contract:proxy ALWAYS returns 200 on chain success,
    // putting upstream's real status in body {"upstream_status":...}. Client
    // MUST extract this; otherwise status_hint always reads "key valid" even
    // for 401-rejected keys. Caught live during E2E-2 (real Anthropic 401
    // for bad key was being hidden by proxy's 200 outer status).

    #[test]
    fn probe_raw_extracts_upstream_status_401_from_body() {
        // Mock proxy returns 200 (chain ok) + body says upstream rejected with 401.
        let addr = mock_proxy_returning(
            200,
            r#"{"probe_ok":true,"upstream_status":401,"latency_ms":150,"provider":"anthropic","status_hint":"routing ok, key rejected by upstream"}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-ant-fake"), None, None);

        // Outer was 200 but client surfaces upstream (401) so caller sees real verdict.
        assert_eq!(
            r.status,
            Some(401),
            "probe_raw mode must surface upstream_status (401), not proxy outer status (200). Bug from E2E-2: real upstream rejection was being hidden as 'key valid'."
        );
        assert!(
            r.error_code.is_none(),
            "401 from upstream is NOT an error_code situation"
        );
    }

    #[test]
    fn probe_raw_extracts_upstream_status_200_happy_path() {
        let addr = mock_proxy_returning(
            200,
            r#"{"probe_ok":true,"upstream_status":200,"latency_ms":420,"provider":"anthropic","status_hint":"routing ok, key valid"}"#,
        );

        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-ant-valid"), None, None);

        assert_eq!(
            r.status,
            Some(200),
            "happy path: upstream_status=200 surfaces"
        );
        assert!(r.error_code.is_none());
    }

    #[test]
    fn probe_raw_falls_back_to_200_when_body_missing_upstream_status() {
        // Defense: proxy returns 200 but body parse fails / field missing.
        // Client must not panic; fall back to outer status so caller sees ok signal.
        let addr = mock_proxy_returning(200, r#"{}"#);
        let r = test_proxy_connectivity(&addr, "anthropic", Some("sk-test"), None, None);
        assert_eq!(
            r.status,
            Some(200),
            "missing upstream_status field → fall back to outer 200 (still signals proxy chain ok)"
        );
    }

    #[test]
    fn none_mode_unaffected_by_upstream_status_extraction() {
        // CRITICAL: extraction only happens in probe_raw mode (bearer_override Some).
        // 5 post-save call sites use None → path returns r.status() unchanged.
        // Mock returns 200 + body that LOOKS like probe_raw shape — None mode
        // must NOT parse it.
        let addr = mock_proxy_returning(
            200,
            r#"{"probe_ok":true,"upstream_status":401}"#, // would mislead a confused parser
        );

        // Notice: bearer_override is None here.
        let r = test_proxy_connectivity(&addr, "anthropic", None, None, None);

        assert_eq!(
            r.status,
            Some(200),
            "None mode (post-save) must NOT extract upstream_status — would change UX of 5 post-save call sites silently"
        );
    }
}
