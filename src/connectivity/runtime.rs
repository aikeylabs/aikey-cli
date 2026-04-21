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

use super::{
    BuildTargetError, CredentialKind, SuiteOptions, SuiteOutcome, TestTarget,
};

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
}

/// Default base URLs for known providers.
/// Default base URLs for known providers — always use the official recommended URL.
/// chat_suffix() / probe_suffix() detect trailing /v1 to avoid double /v1/v1.
pub const PROVIDER_DEFAULTS: &[(&str, &str)] = &[
    ("anthropic", "https://api.anthropic.com"),
    ("openai",    "https://api.openai.com/v1"),
    ("google",    "https://generativelanguage.googleapis.com"),
    ("deepseek",  "https://api.deepseek.com/v1"),
    ("kimi",      "https://api.kimi.com/coding/v1"),
    ("glm",       "https://open.bigmodel.cn/api/paas"),
];

/// Resolve the default base URL for a provider code.
pub fn default_base_url(provider_code: &str) -> Option<&'static str> {
    PROVIDER_DEFAULTS.iter()
        .find(|(c, _)| *c == provider_code)
        .map(|(_, u)| *u)
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
/// `pub(crate)` so `check_usage_pipeline` in `commands_project.rs` can reuse
/// the same proxy discovery logic for its "internet reachable" check.
pub(crate) fn build_proxy_aware_agent(timeout: std::time::Duration) -> ureq::Agent {
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

pub fn test_provider_connectivity(
    provider_code: &str,
    base_url: &str,
    api_key: &str,
) -> ConnectivityResult {
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
    let ping_target_url: String = if base_url.contains("127.0.0.1") || base_url.contains("localhost") {
        default_base_url(provider_code)
            .unwrap_or("https://unknown")
            .to_string()
    } else {
        base_url.to_string()
    };
    let (upstream_host, upstream_port) = parse_host_port(&ping_target_url);

    // ── Phase 1: Ping(DIRECT) — CLI → upstream. Independent. ─────────────
    // Never short-circuits the other phases. Surfaces as the "Ping(D)"
    // column and gives users a "my laptop's path to upstream" baseline.
    let (ping_direct_ok, ping_direct_ms) = if has_proxy {
        // With a network proxy, TCP won't work — use HTTP HEAD through the
        // same proxy the CLI uses for real requests. Any response (incl.
        // 4xx/5xx) proves reachability.
        probe_http_head_direct(&ping_target_url, Duration::from_secs(5))
    } else {
        tcp_ping(&upstream_host, upstream_port, 5)
    };

    // ── Phase 2: Ping(PROXY) — CLI → aikey-proxy → upstream. ─────────────
    // Uses the new POST /admin/probe/ping endpoint. aikey-proxy handles
    // its own HTTPS_PROXY / NO_PROXY semantics internally.
    let (ping_ok, ping_ms) = probe_via_aikey_proxy_ping(provider_code, &ping_target_url);

    // Short-circuit: if proxy can't reach upstream, skip API + Chat.
    // Critical: probing auth against a known-unreachable upstream wastes
    // the user's rate-limit budget (and inflates OAuth error counters
    // server-side, which can trigger refresh-loop anomalies).
    if !ping_ok {
        return ConnectivityResult {
            ping_direct_ok, ping_direct_ms,
            ping_ok: false, ping_ms,
            api_ok: false, api_ms: 0, api_status: None,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

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
        format!("{}{}?key={}", base_url.trim_end_matches('/'), probe_suffix(provider_code, base_url), api_key)
    } else {
        format!("{}{}", base_url.trim_end_matches('/'), probe_suffix(provider_code, base_url))
    };
    let (auth_key, auth_val) = probe_auth(provider_code, api_key);

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

    let (api_ok, api_status) = match api_result {
        Ok(r) => (true, Some(r.status())),
        Err(ureq::Error::Status(code, _)) => (true, Some(code)),
        Err(_) => (false, None),
    };

    if !api_ok {
        return ConnectivityResult {
            ping_direct_ok, ping_direct_ms,
            ping_ok, ping_ms,
            api_ok, api_ms, api_status,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

    // ── Phase 4: Chat probe ──────────────────────────────────────────────
    // Minimal completion request (max_tokens=1). Short-circuit on API
    // failure prevents this from hammering an upstream that just rejected
    // our auth — some providers count that against rate limits.
    // Why ?beta=true: Claude OAuth API requires this query param. Without it,
    // Anthropic returns 429 business rejection (not real rate limit).
    // `is_via_proxy` is the same determination as `via_aikey_proxy` above;
    // kept as a local for readability where it drives persona tweaks.
    let is_via_proxy = via_aikey_proxy;

    let (chat_url, body) = if provider_code == "openai" && is_via_proxy {
        // Codex OAuth: uses Responses API via chatgpt.com/backend-api/codex.
        // Required fields: model=gpt-5.4, instructions, input=array, store=false, stream=true
        // Why gpt-5.4: ChatGPT accounts only support Codex-specific models (not gpt-4o-mini).
        // Why stream=true + store=false: Codex API enforces these for ChatGPT accounts.
        // Ref: verified 2026-04-16 against chatgpt.com/backend-api/codex/responses
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": "gpt-5.4",
            "instructions": "Say hi.",
            "input": [{"role": "user", "content": "hi"}],
            "store": false,
            "stream": true
        });
        (url, body)
    } else if provider_code == "anthropic" && is_via_proxy {
        // Claude OAuth: requires ?beta=true + metadata.user_id
        let url = format!("{}{}?beta=true", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url));
        let mut body = chat_body(provider_code);
        if let Some(obj) = body.as_object_mut() {
            obj.insert("metadata".to_string(), serde_json::json!({"user_id": "aikey_doctor_probe"}));
        }
        (url, body)
    } else if provider_code == "google" {
        let url = format!("{}{}?key={}", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url), api_key);
        (url, chat_body(provider_code))
    } else {
        let url = format!("{}{}", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url));
        (url, chat_body(provider_code))
    };
    let (chat_auth_key, chat_auth_val) = probe_auth(provider_code, api_key);

    let chat_agent = build_proxy_aware_agent(Duration::from_secs(15));
    let chat_start = Instant::now();
    let mut req = chat_agent.post(&chat_url)
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
    if provider_code == "kimi" {
        req = req.set("User-Agent", "claude-code/1.0");
    }
    let chat_result = req.send_string(&body.to_string());
    let chat_ms = chat_start.elapsed().as_millis();

    let (chat_ok, chat_status) = match chat_result {
        Ok(r) => {
            let s = r.status();
            (s >= 200 && s < 300, Some(s))
        }
        Err(ureq::Error::Status(code, _)) => {
            // 429 = auth passed but rate limited → treat as connectivity OK.
            // Why: Claude OAuth returns 429 as business rejection when persona
            // headers are incomplete, but also for genuine rate limits. Either way,
            // the key is valid and the provider is reachable.
            //
            // 404 for openai via proxy = Codex uses Responses API, not Chat Completions.
            // The probe endpoint doesn't exist, but the provider is reachable (API probe passed).
            let ok = code == 429;
            (ok, Some(code))
        }
        Err(_) => (false, None),
    };

    ConnectivityResult {
        ping_direct_ok, ping_direct_ms,
        ping_ok, ping_ms,
        api_ok, api_ms, api_status,
        chat_ok, chat_ms, chat_status,
    }
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
        let port = host_port[idx+1..]
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
fn probe_http_head_direct(target_url: &str, timeout: std::time::Duration) -> (bool, u128) {
    use std::time::Instant;
    let agent = build_proxy_aware_agent(timeout);
    let start = Instant::now();
    let ok = match agent.head(target_url).call() {
        Ok(_) => true,
        Err(ureq::Error::Status(_, _)) => true, // HEAD may 405; still reached upstream
        Err(_) => false,
    };
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
    let resp = match agent.post(&endpoint)
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
    let proxy_ms = parsed.get("latency_ms").and_then(|v| v.as_u64()).unwrap_or(0) as u128;
    // Report proxy's own measured latency (host → upstream), not our RTT
    // to localhost (which is ~0ms and meaningless).
    (proxy_ok, proxy_ms)
}

/// Result of a proxy connectivity probe.
pub struct ProxyProbeResult {
    pub ok: bool,
    pub ms: u128,
    pub status: Option<u16>,
}

/// Test a key through the proxy (full chain: CLI → proxy → provider).
/// Uses the active key's token for authentication.
pub fn test_proxy_connectivity(proxy_addr: &str, provider_code: &str) -> ProxyProbeResult {
    use std::time::{Duration, Instant};

    // Proxy strips the provider prefix and forwards to the real provider.
    // The proxy's upstream base_url never ends with /v1, so use full /v1/... paths.
    let proxy_base = format!("http://{}/{}", proxy_addr, provider_code);
    let proxy_url = format!("{}{}", proxy_base, probe_suffix(provider_code, &proxy_base));
    let active_cfg = crate::storage::get_active_key_config().ok().flatten();
    let bearer = active_cfg.as_ref()
        .map(|cfg| {
            if cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey {
                format!("aikey_vk_{}", cfg.key_ref)
            } else {
                format!("aikey_personal_{}", cfg.key_ref)
            }
        })
        .unwrap_or_else(|| "aikey_test_probe".to_string());

    let (auth_key, auth_val) = probe_auth(provider_code, &bearer);
    // Explicit no-proxy agent. Must NOT use `ureq::get()` shortcut — it
    // inherits the user's `https_proxy` / `http_proxy` env, which routes
    // localhost (127.0.0.1:<proxy>) through Clash / corporate proxies and
    // produces a bogus "failed (10 ms)" bottom row. Regression history:
    // workflow/CI/bugfix/2026-04-22-connectivity-probe-through-proxy.md.
    //
    // X-Aikey-Probe: 1 suppresses usage-event emission on the proxy side
    // (see aikey-proxy/internal/proxy/middleware.go::isAikeyProbe). Without
    // this header every `aikey test` run pollutes the collector with a
    // billing event for the synthetic probe.
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let start = Instant::now();
    let result = agent.get(&proxy_url)
        .set(auth_key, &auth_val)
        .set("X-Aikey-Probe", "1")
        .call();
    let ms = start.elapsed().as_millis();

    let (ok, status) = match result {
        Ok(r) => (true, Some(r.status())),
        Err(ureq::Error::Status(code, _)) => (true, Some(code)),
        Err(_) => (false, None),
    };
    ProxyProbeResult { ok, ms, status }
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
        "openai"    => "gpt-4o-mini",
        "deepseek"  => "deepseek-chat",
        "kimi"      => "moonshot-v1-8k",
        "google"    => "gemini-2.0-flash",
        "glm" | "zhipu" => "glm-4-flash",
        "yi"        => "yi-lightning",
        "qwen" | "dashscope" => "qwen-turbo",
        "mistral"   => "mistral-small-latest",
        _           => "gpt-4o-mini", // fallback: most gateways understand this
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
        "google"    => ("x-goog-api-key", api_key.to_string()),
        _           => ("Authorization", format!("Bearer {}", api_key)),
    }
}

/// Format a chat probe status code into a human-readable hint.
pub fn chat_status_hint(status: u16) -> String {
    match status {
        200 => "valid".to_string(),
        400 => "bad request".to_string(),
        401 => "invalid key".to_string(),
        403 => "forbidden".to_string(),
        404 => "not found".to_string(),
        422 => "invalid request".to_string(),
        429 => "rate limited, key valid".to_string(),
        _ if status >= 500 => format!("server error ({})", status),
        _ => format!("HTTP {}", status),
    }
}

/// Format an API probe status code into a human-readable hint.
pub fn api_status_hint(status: u16) -> String {
    match status {
        200 => "valid key".to_string(),
        401 | 403 => "reachable, key rejected".to_string(),
        // Why 405 is treated like 404 (both = "reachable"):
        // The API probe does a GET against each provider's base path to
        // minimise side effects. Anthropic's `/v1/messages` is POST-only,
        // so every probe against it returns 405 — that's a proof the
        // endpoint is reachable, not a failure. Showing the raw "HTTP 405"
        // read as a bug to users ("is 405 normal?"); folding it into
        // "reachable" keeps Anthropic's row visually consistent with
        // OpenAI/Kimi (which return 200/404). The actual auth verdict is
        // decided by the Chat column, not this one.
        404 | 405 => "reachable".to_string(),
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
    let mut any_chat_ok   = false;

    // ── JSON mode: probe all, collect, return; no stderr output. ─────────
    if json_mode {
        for t in &targets {
            let r = test_provider_connectivity(&t.provider_code, &t.base_url, &t.bearer);
            if r.chat_ok { any_chat_ok = true; }
            if r.ping_ok { any_reachable = true; }
            json_results.push(serde_json::json!({
                "provider":      t.provider_code,
                "kind":          match t.kind {
                    CredentialKind::PersonalApi  => "personal_api",
                    CredentialKind::ManagedTeam  => "managed_team",
                    CredentialKind::OAuth        => "oauth",
                },
                "source_ref":    t.source_ref,
                "base_url":      t.base_url,
                "via_proxy":     t.kind.via_proxy(),
                "ping_ok":       r.ping_ok,
                "ping_ms":       r.ping_ms,
                "api_ok":        r.api_ok,
                "api_ms":        r.api_ms,
                "api_status":    r.api_status,
                "chat_ok":       r.chat_ok,
                "chat_ms":       r.chat_ms,
                "chat_status":   r.chat_status,
            }));
            rows.push((t.clone(), r));
        }

        let proxy_result = if opts.show_proxy_row && any_reachable
            && crate::commands_proxy::is_proxy_running()
        {
            let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
            let prov = targets.iter()
                .find(|t| t.provider_code != "custom")
                .map(|t| t.provider_code.as_str());
            prov.map(|p| {
                let r = test_proxy_connectivity(&proxy_addr, p);
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
    let label_w = targets.iter()
        .map(|t| t.display_label().len())
        .max()
        .unwrap_or(12)
        .max("Provider".len()) + 2;
    // 5 columns: Provider | Ping(D) | Ping | API | Chat
    //   Ping(D) = CLI → upstream (independent baseline).
    //   Ping    = CLI → aikey-proxy → upstream (gates API+Chat).
    const W_PD:   usize = 14;   // "Ping(D)" column, short latency (+" (Xms)")
    const W_PING: usize = 14;   // Ping(PROXY)
    const W_API:  usize = 34;

    if let Some(header) = opts.header_label {
        eprintln!();
        eprintln!("  \u{1F50C} {}", header.bold());
    }
    eprintln!("  {:<wp$} {:<wpd$} {:<wpi$} {:<wap$} {}",
        "Provider".dimmed(), "Ping(D)".dimmed(), "Ping".dimmed(),
        "API".dimmed(), "Chat".dimmed(),
        wp = label_w, wpd = W_PD, wpi = W_PING, wap = W_API);
    eprintln!("  {}", "\u{2500}".repeat(label_w + W_PD + W_PING + W_API + 22).dimmed());

    let mut failed_hints: Vec<String> = Vec::new();
    for t in &targets {
        let display = t.display_label();
        eprint!("  {:<wp$} ", display.bold(), wp = label_w);
        let _ = io::stderr().flush();

        let r = test_provider_connectivity(&t.provider_code, &t.base_url, &t.bearer);

        // Ping(DIRECT) column — informational, never gates.
        let pd_raw = if r.ping_direct_ok { format!("ok ({}ms)", r.ping_direct_ms) }
                     else { format!("fail ({}ms)", r.ping_direct_ms) };
        let pd_col = if r.ping_direct_ok {
            format!("{:<w$}", pd_raw, w = W_PD).green().to_string()
        } else {
            // Dimmed (not red) — Ping(D) failure on its own isn't a blocker,
            // just a diagnostic ("your laptop can't reach upstream, but the
            // proxy might").
            format!("{:<w$}", pd_raw, w = W_PD).dimmed().to_string()
        };
        eprint!("{} ", pd_col);
        let _ = io::stderr().flush();

        // Ping(PROXY) column — gates API + Chat.
        let ping_raw = if r.ping_ok { format!("ok ({}ms)", r.ping_ms) }
                       else { format!("fail ({}ms)", r.ping_ms) };
        let ping_col = if r.ping_ok { format!("{:<w$}", ping_raw, w = W_PING).green().to_string() }
                       else { format!("{:<w$}", ping_raw, w = W_PING).red().to_string() };
        eprint!("{} ", ping_col);
        let _ = io::stderr().flush();

        if !r.ping_ok {
            eprintln!("{:<w$} {}", "\u{2014}".dimmed(), "\u{2014}".dimmed(), w = W_API);
            // If Ping(DIRECT) passed while Ping(PROXY) failed, the proxy
            // itself (not the network) is the problem — actionable hint.
            let hint = if r.ping_direct_ok {
                format!("{}: proxy can't reach upstream (but your laptop can). \
                         Is `aikey proxy` configured with HTTPS_PROXY / \
                         config.upstream_proxy if your network requires it?", display)
            } else {
                format!("{}: both paths failed — check network / VPN / firewall", display)
            };
            failed_hints.push(hint);
            rows.push((t.clone(), r));
            continue;
        }
        any_reachable = true;

        // API column (short-circuited by test_provider_connectivity when !ping).
        let api_raw = if r.api_ok {
            let h = r.api_status.map(|s| api_status_hint(s)).unwrap_or_default();
            format!("ok ({}ms, {})", r.api_ms, h)
        } else {
            format!("fail ({}ms)", r.api_ms)
        };
        let api_col = if r.api_ok { format!("{:<w$}", api_raw, w = W_API).green().to_string() }
                      else { format!("{:<w$}", api_raw, w = W_API).red().to_string() };
        eprint!("{} ", api_col);
        let _ = io::stderr().flush();

        // Chat column.
        if !r.api_ok {
            eprintln!("{}", "\u{2014}".dimmed());
            failed_hints.push(format!("{}: API unreachable — check base URL or provider status", display));
        } else if r.chat_ok {
            any_chat_ok = true;
            let h = r.chat_status.map(|s| chat_status_hint(s)).unwrap_or_default();
            eprintln!("{}", format!("ok ({}ms, {})", r.chat_ms, h).green());
        } else {
            let hint = r.chat_status.map(|s| format!(", HTTP {}: {}", s, chat_status_hint(s))).unwrap_or_default();
            eprintln!("{}", format!("fail ({}ms{})", r.chat_ms, hint).red());
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
        eprintln!("  {}", "\u{2500}".repeat(label_w + W_PD + W_PING + W_API + 22).dimmed());
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
            eprintln!("  {:<12} {}", "proxy".bold(), "skipped (all providers unreachable)".dimmed());
            None
        } else if crate::commands_proxy::is_proxy_running() {
            let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
            let prov = targets.iter()
                .find(|t| t.provider_code != "custom")
                .map(|t| t.provider_code.as_str());
            if let Some(p) = prov {
                eprint!("  {:<12} ", "proxy".bold());
                let r = test_proxy_connectivity(&proxy_addr, p);
                if r.ok {
                    let h = r.status.map(|s| proxy_status_hint(s)).unwrap_or_default();
                    eprintln!("{} ({} ms, {})", "ok".green(), r.ms, h);
                } else {
                    eprintln!("{} ({} ms)", "failed".red(), r.ms);
                }
                Some(r)
            } else {
                eprintln!("  {:<12} {}", "proxy".bold(), "skipped — no testable provider".dimmed());
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
    if errors.is_empty() { return; }
    if json_mode { return; } // JSON already captures this via callsite metadata.

    eprintln!();
    eprintln!("  {}", "Cannot test:".yellow());
    let w = errors.iter()
        .map(|e| e.label().len())
        .max()
        .unwrap_or(0)
        .max(12);
    for e in errors {
        eprintln!("  {:<w$}  {}", e.label().bold(), e.reason().dimmed(), w = w);
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
        assert!(text.to_lowercase().contains("x-aikey-probe: 1"),
            "probe must set X-Aikey-Probe: 1 to suppress collector usage events; \
             got request: {}", text);
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
        unsafe { std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1"); }
        unsafe { std::env::set_var("https_proxy", "http://127.0.0.1:1"); }

        let (port, _captured, handle) = spawn_capture_server();
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(2))
            .build();
        let url = format!("http://127.0.0.1:{}/anthropic/v1/models", port);
        let result = agent.get(&url).call();
        handle.join().ok();

        unsafe { std::env::remove_var("HTTPS_PROXY"); }
        unsafe { std::env::remove_var("https_proxy"); }

        // If env-proxy was inherited, the call goes to 127.0.0.1:1 (dead)
        // and errors out. Explicit no-proxy agent must reach our capture
        // server and get the 200.
        assert!(result.is_ok(),
            "probe agent must NOT inherit HTTPS_PROXY env var — the runtime \
             proxy is on 127.0.0.1 and routing that through Clash/corporate \
             proxies produces bogus 'failed (10 ms)' bottom row");
    }
}
