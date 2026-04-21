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
pub struct ConnectivityResult {
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
    let has_proxy = crate::proxy_env::read_proxy_env_var("https_proxy").is_some()
        || crate::proxy_env::read_proxy_env_var("http_proxy").is_some()
        || crate::proxy_env::read_proxy_env_var("all_proxy").is_some()
        || std::env::var("https_proxy").is_ok()
        || std::env::var("http_proxy").is_ok()
        || std::env::var("all_proxy").is_ok();

    // 1. TCP ping — extract host and port from base_url
    // Why: skip TCP ping when a network proxy is configured, because direct
    // TCP connect to the provider host will fail in restricted networks even
    // though HTTP requests through the proxy succeed fine.
    let is_http = base_url.starts_with("http://");
    let host_port = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(base_url);
    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        let h = &host_port[..idx];
        let p = host_port[idx+1..].parse::<u16>().unwrap_or(if is_http { 80 } else { 443 });
        (h, p)
    } else {
        (host_port, if is_http { 80 } else { 443 })
    };

    let (ping_ok, ping_ms) = if has_proxy {
        // With a proxy, skip TCP ping and go straight to HTTP probe.
        (true, 0)
    } else {
        tcp_ping(host, port, 5)
    };

    if !ping_ok {
        return ConnectivityResult {
            ping_ok: false, ping_ms,
            api_ok: false, api_ms: 0, api_status: None,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

    let agent = build_proxy_aware_agent(Duration::from_secs(10));

    // 2. API probe with real key (GET — lightweight, no side effects)
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
    let api_result = api_req.call();
    let api_ms = api_start.elapsed().as_millis();

    let (api_ok, api_status) = match api_result {
        Ok(r) => (true, Some(r.status())),
        Err(ureq::Error::Status(code, _)) => (true, Some(code)),
        Err(_) => (false, None),
    };

    if !api_ok {
        return ConnectivityResult {
            ping_ok, ping_ms,
            api_ok, api_ms, api_status,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

    // 3. Chat probe — send a minimal completion request with max_tokens=1
    // Why ?beta=true: Claude OAuth API requires this query param. Without it,
    // Anthropic returns 429 business rejection (not real rate limit).
    // When going through proxy, the proxy forwards the query params to upstream.
    // OAuth accounts go through the proxy (base_url is localhost).
    // Provider-specific adjustments are needed for OAuth persona requirements.
    let is_via_proxy = base_url.contains("127.0.0.1") || base_url.contains("localhost");

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
        ping_ok, ping_ms,
        api_ok, api_ms, api_status,
        chat_ok, chat_ms, chat_status,
    }
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
    let start = Instant::now();
    let result = ureq::get(&proxy_url)
        .set(auth_key, &auth_val)
        .timeout(Duration::from_secs(10))
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
fn probe_suffix(provider_code: &str, base_url: &str) -> String {
    let base_has_v1 = base_url.trim_end_matches('/').ends_with("/v1");
    match provider_code {
        "anthropic" if base_has_v1 => "/messages".to_string(),
        "anthropic" => "/v1/messages".to_string(),
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
        404 => "reachable".to_string(),
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
    const W_PING: usize = 16;
    const W_API:  usize = 34;

    if let Some(header) = opts.header_label {
        eprintln!();
        eprintln!("  \u{1F50C} {}", header.bold());
    }
    eprintln!("  {:<wp$} {:<wpi$} {:<wap$} {}",
        "Provider".dimmed(), "Ping".dimmed(), "API".dimmed(), "Chat".dimmed(),
        wp = label_w, wpi = W_PING, wap = W_API);
    eprintln!("  {}", "\u{2500}".repeat(label_w + W_PING + W_API + 20).dimmed());

    let mut failed_hints: Vec<String> = Vec::new();
    for t in &targets {
        let display = t.display_label();
        eprint!("  {:<wp$} ", display.bold(), wp = label_w);
        let _ = io::stderr().flush();

        let r = test_provider_connectivity(&t.provider_code, &t.base_url, &t.bearer);

        // Ping column.
        let ping_raw = if r.ping_ok { format!("ok ({}ms)", r.ping_ms) }
                       else { format!("fail ({}ms)", r.ping_ms) };
        let ping_col = if r.ping_ok { format!("{:<w$}", ping_raw, w = W_PING).green().to_string() }
                       else { format!("{:<w$}", ping_raw, w = W_PING).red().to_string() };
        eprint!("{} ", ping_col);
        let _ = io::stderr().flush();

        if !r.ping_ok {
            eprintln!("{:<w$} {}", "\u{2014}".dimmed(), "\u{2014}".dimmed(), w = W_API);
            failed_hints.push(format!("{}: ping failed — check network / VPN / firewall", display));
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

