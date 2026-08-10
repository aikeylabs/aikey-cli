//! `--from-url` against a REAL socket (P4, tasks 4.2 / 4.2b / 4.3).
//!
//! Against a local HTTP server rather than a mocked agent, for the reason
//! probe-runner's own suite gives: the thing under test is what the HTTP
//! client actually does with a redirect and a body, and a mock of the client
//! is a mock of exactly that.
//!
//! 🔴 THIS SUITE NEEDS NO GATE-LOOSENING SHIM, AND THAT IS ITSELF THE POINT.
//! The equivalent Python suite on the check site has to monkey-patch
//! `_is_forbidden_ip` before it can talk to 127.0.0.1, because that gate
//! refuses loopback. This one dials loopback straight through — which is the
//! enterprise case (R-3b) working, demonstrated rather than asserted.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use aikeylabs_aikey_cli::provider_selfdesc as selfdesc;

const V1_DOC: &str = r#"{
  "aikey_provider_version": 1,
  "display_name": "Example Relay",
  "base_url": "https://api.example-relay.com",
  "protocols": ["anthropic", "openai"],
  "models": ["claude-sonnet-4-5"],
  "region_hint": "a field this build has never heard of"
}"#;

/// HOME and the proxy variables are process-global; these tests share a
/// binary and run in parallel threads.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Point the CLI's declared egress lane at "no proxy configured".
///
/// 🔴 Necessary because the lane is real: `build_proxy_aware_agent*` reads
/// `~/.aikey/proxy.env` and then the process environment, and a developer
/// laptop usually has one exported — which would route a request for
/// 127.0.0.1 through Clash and fail for a reason that has nothing to do with
/// the code under test. Clearing it here is the same discipline the DMZ suite
/// applies from the other direction.
struct NoProxyEnv {
    _guard: MutexGuard<'static, ()>,
    previous: Vec<(&'static str, Option<String>)>,
    _home: tempfile::TempDir,
    previous_home: Option<String>,
}

impl NoProxyEnv {
    fn set() -> Self {
        let guard = env_lock();
        const VARS: [&str; 6] = [
            "https_proxy",
            "http_proxy",
            "all_proxy",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
        ];
        let previous = VARS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect::<Vec<_>>();
        for k in VARS {
            std::env::remove_var(k);
        }
        // A temp HOME so `~/.aikey/proxy.env` cannot be the developer's.
        let home = tempfile::tempdir().expect("tempdir");
        let previous_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", home.path());
        Self {
            _guard: guard,
            previous,
            _home: home,
            previous_home,
        }
    }
}

impl Drop for NoProxyEnv {
    fn drop(&mut self) {
        for (k, v) in &self.previous {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        match &self.previous_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}

/// A one-request-at-a-time HTTP server. `routes` maps path → (status, body,
/// optional Location).
fn serve(routes: Vec<(&'static str, u16, &'static str, Option<String>)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    serve_with(listener, port, routes)
}

/// Same server, on a port the caller already knows — needed when a route's
/// Location header has to name the server's own address.
fn serve_on(port: u16, routes: Vec<(&'static str, u16, &'static str, Option<String>)>) -> String {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    serve_with(listener, port, routes)
}

fn serve_with(
    listener: TcpListener,
    port: u16,
    routes: Vec<(&'static str, u16, &'static str, Option<String>)>,
) -> String {
    thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut stream) = stream else { continue };
            let path = read_request_path(&stream).unwrap_or_default();
            let route = routes
                .iter()
                .find(|(p, _, _, _)| path.starts_with(p))
                .cloned();
            let (status, body, location) = match route {
                Some((_, s, b, l)) => (s, b.to_string(), l),
                None => (404, "not found".to_string(), None),
            };
            let mut head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
            if let Some(loc) = location {
                head.push_str(&format!("Location: {loc}\r\n"));
            }
            head.push_str("Connection: close\r\n\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn read_request_path(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    line.split_whitespace().nth(1).map(|s| s.to_string())
}

#[test]
fn a_real_document_over_a_real_socket_parses_and_warns_about_http() {
    let _env = NoProxyEnv::set();
    let base = serve(vec![(
        "/.well-known/aikey-provider.json",
        200,
        V1_DOC,
        None,
    )]);

    let fetched = selfdesc::fetch(&base).expect("a v1 document must fetch and parse");

    assert_eq!(fetched.desc.display_name, "Example Relay");
    assert_eq!(fetched.desc.protocols, vec!["anthropic", "openai"]);
    // 🔴 The unknown field survived contact with a real body (§2 semantic 3).
    assert_eq!(fetched.desc.models, vec!["claude-sonnet-4-5"]);
    // 🔴 http:// warned rather than refused, and the warning names the
    // consequence — the credential travels to this address in cleartext later.
    assert_eq!(fetched.warnings.len(), 1, "warnings: {:?}", fetched.warnings);
    assert!(fetched.warnings[0].contains("cleartext"));
}

#[test]
fn the_url_can_be_the_root_or_the_document_itself() {
    // Somebody who pasted the full path off our own claim-completion page must
    // not be told they did it wrong.
    let _env = NoProxyEnv::set();
    let base = serve(vec![(
        "/.well-known/aikey-provider.json",
        200,
        V1_DOC,
        None,
    )]);
    let full = format!("{base}/.well-known/aikey-provider.json");

    selfdesc::fetch(&full).expect("the full document URL must work too");
}

#[test]
fn a_redirect_into_the_metadata_service_is_refused_on_the_second_hop() {
    // 🔴 THE REASON THE GATE RE-RUNS PER HOP. Hop 1 is a host the user typed;
    // hop 2 is a URL that host chose after we approved hop 1. A gate that only
    // checked the first looks identical in review and stops nothing.
    let _env = NoProxyEnv::set();
    let base = serve(vec![(
        "/.well-known/aikey-provider.json",
        302,
        "",
        Some("http://169.254.169.254/latest/meta-data/".to_string()),
    )]);

    match selfdesc::fetch(&base) {
        Err(selfdesc::FetchError::Gate(msg)) => {
            assert!(
                msg.contains("metadata"),
                "refused for the wrong reason: {msg}"
            );
        }
        other => panic!("a redirect to the metadata service produced {other:?}"),
    }
}

#[test]
fn a_legitimate_redirect_is_followed() {
    // The other half of the redirect fix: apex -> www and http -> https are
    // ordinary relay configurations, and refusing them would make this flag
    // fail on sites that are working correctly. The gate re-runs on the new
    // URL; it does not stop us going there.
    let _env = NoProxyEnv::set();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let target = format!("http://127.0.0.1:{port}/moved/aikey-provider.json");
    let base = serve_on(
        port,
        vec![
            (
                "/.well-known/aikey-provider.json",
                302,
                "",
                Some(target.clone()),
            ),
            ("/moved/aikey-provider.json", 200, V1_DOC, None),
        ],
    );

    let fetched = selfdesc::fetch(&base).expect("a normal redirect must be followed");
    assert_eq!(fetched.desc.display_name, "Example Relay");
    assert_eq!(fetched.final_url, target, "the final URL was not recorded");
}

#[test]
fn a_higher_version_over_the_wire_is_refused_with_an_upgrade_hint() {
    let _env = NoProxyEnv::set();
    let base = serve(vec![(
        "/.well-known/aikey-provider.json",
        200,
        r#"{"aikey_provider_version": 2, "base_url": "https://x", "protocols": ["anthropic"]}"#,
        None,
    )]);

    match selfdesc::fetch(&base) {
        Err(e @ selfdesc::FetchError::UnsupportedVersion { .. }) => {
            let msg = e.to_string();
            assert!(msg.contains("aikey upgrade"), "no way forward: {msg}");
        }
        other => panic!("v2 produced {other:?}"),
    }
}

#[test]
fn a_missing_document_says_what_to_do_instead() {
    let _env = NoProxyEnv::set();
    let base = serve(vec![("/nothing-here", 200, "{}", None)]);

    match selfdesc::fetch(&base) {
        Err(e @ selfdesc::FetchError::Http { .. }) => {
            let msg = e.to_string();
            assert!(msg.contains("404"), "{msg}");
            // 🔴 Every refusal on this path ends somewhere the user can go.
            // This is the flow the primary goal runs through; "failed" loses
            // people at exactly the wrong moment.
            assert!(msg.contains("--providers"), "no manual path offered: {msg}");
        }
        other => panic!("a missing document produced {other:?}"),
    }
}

#[test]
fn an_unreachable_host_names_the_air_gapped_case_and_the_way_round_it() {
    // 🔴 TASK 4.7. On a machine with no outbound network this flag cannot
    // work by definition, and the message has to say so and hand over the
    // manual three-axis command — 🚫 not fail silently, and 🚫 not read as
    // "the relay is down" when the relay is fine and we are the ones boxed in.
    let _env = NoProxyEnv::set();

    // Port 1 on loopback: nothing listens, and the gate allows loopback, so
    // this reaches the connect attempt exactly as an air-gapped host would.
    match selfdesc::fetch("http://127.0.0.1:1") {
        Err(e @ selfdesc::FetchError::Unreachable(_)) => {
            let msg = e.to_string();
            assert!(msg.contains("air-gapped"), "{msg}");
            assert!(msg.contains("aikey add"), "no manual path offered: {msg}");
        }
        other => panic!("an unreachable host produced {other:?}"),
    }
}
