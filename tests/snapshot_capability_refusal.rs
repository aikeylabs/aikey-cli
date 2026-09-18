//! Fence: `aikey key sync` must be able to tell a REFUSAL apart from an
//! account that honestly holds no team keys.
//!
//! # What went wrong
//!
//! When the control plane cannot run `routing.snapshot.compile` it still
//! answers 200 and serves the LAST PUBLISHED projection — deliberately, so a
//! licensing problem never becomes a delivery outage (D3.1/R8). Where nothing
//! was ever published, "the last published projection" is the EMPTY SET, and
//! `{"keys": []}` with a 200 is byte-for-byte what a healthy plane sends an
//! account with no team keys.
//!
//! The server distinguishes them in two response headers. Until 2026-09-07
//! nothing read them: `get_managed_keys_snapshot` called `into_json()` and the
//! headers went in the bin, so `aikey key sync` printed "Sync complete: 0
//! key(s) downloaded.", exited 0, and `--json` emitted `{"ok": true,
//! "downloaded": 0}` to the unattended form-② daemon.
//!
//! Bug: workflow/CI/bugfix/20260907-team-key-delivery-is-silent-without-the-protected-module.md

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use aikeylabs_aikey_cli::platform_client::PlatformClient;

/// The body is IDENTICAL in both arms below. That is the whole point: if the
/// fence ever passes because the bodies differ, it has stopped testing the
/// thing that actually went wrong.
const EMPTY_SNAPSHOT_BODY: &str = r#"{"sync_version":7,"keys":[],"key_delivery_form":"local"}"#;

/// One-shot HTTP server that replies with `extra_headers` + EMPTY_SNAPSHOT_BODY.
fn serve_once(extra_headers: &'static [(&'static str, &'static str)]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let mut resp = String::from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
            for (k, v) in extra_headers {
                resp.push_str(&format!("{k}: {v}\r\n"));
            }
            resp.push_str(&format!(
                "Content-Length: {}\r\n\r\n{}",
                EMPTY_SNAPSHOT_BODY.len(),
                EMPTY_SNAPSHOT_BODY
            ));
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// 🔴 A refused snapshot must arrive carrying the refusal.
#[test]
fn a_refused_snapshot_names_the_capability() {
    let base = serve_once(&[
        ("X-AiKey-Capability-Refused", "routing.snapshot.compile"),
        ("X-AiKey-Capability-Refusal-Code", "capability_unavailable"),
    ]);
    let snap = PlatformClient::new(&base, "test-jwt")
        .get_managed_keys_snapshot()
        .expect("snapshot request");

    assert!(
        snap.keys.is_empty(),
        "fixture sanity: the refused arm must return an empty key list, \
         which is exactly why the body cannot carry the signal"
    );

    let refusal = snap.capability_refused.expect(
        "the refusal headers were dropped. Without them this response is \
         indistinguishable from a healthy plane telling the user they have no \
         team keys — the 20260907 bug, exactly.",
    );
    assert_eq!(refusal.capability, "routing.snapshot.compile");
    assert_eq!(refusal.code, "capability_unavailable");
    assert!(
        !refusal.next_step().is_empty(),
        "a refusal with no next step is a dead end for the operator"
    );
}

/// The paired arm. Without it the test above could be satisfied by fabricating
/// a refusal on every empty snapshot, which would make the signal a constant
/// rather than a discriminator — and would then cry wolf at every healthy user
/// who simply has no team keys yet.
#[test]
fn a_healthy_empty_snapshot_carries_no_refusal() {
    let base = serve_once(&[]);
    let snap = PlatformClient::new(&base, "test-jwt")
        .get_managed_keys_snapshot()
        .expect("snapshot request");

    assert!(snap.keys.is_empty(), "fixture sanity");
    assert!(
        snap.capability_refused.is_none(),
        "a healthy control plane sent no refusal headers, but one was reported. \
         The signal must discriminate, not decorate every empty snapshot."
    );
}

/// Each refusal code the server can emit reaches the user with its OWN next
/// step. The three are never collapsed server-side (pkg/snapshot), so the
/// client must not collapse them either: "never activated" and "the module
/// trapped once" call for different actions.
#[test]
fn every_refusal_code_carries_its_own_next_step() {
    let mut steps = Vec::new();
    for code in ["capability_unavailable", "module_fault", "rejected_input"] {
        let base = serve_once(&[("X-AiKey-Capability-Refused", "routing.snapshot.compile")]);
        let snap = PlatformClient::new(&base, "test-jwt")
            .get_managed_keys_snapshot()
            .expect("snapshot request");
        let mut refusal = snap.capability_refused.expect("refusal");
        refusal.code = code.to_string();
        let step = refusal.next_step();
        assert!(!step.is_empty(), "{code} has no next step");
        steps.push(step);
    }
    steps.sort_unstable();
    steps.dedup();
    assert_eq!(
        steps.len(),
        3,
        "two refusal codes share a next step — they have been collapsed into \
         advice that is wrong for at least one of them"
    );
}
