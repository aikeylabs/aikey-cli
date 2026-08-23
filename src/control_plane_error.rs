//! Actionable diagnosis for control-service transport failures.
//!
//! WHY THIS EXISTS (2026-08-21)
//! ============================
//! Every control-plane call in `platform_client` ends in
//! `.map_err(|e| format!("<op> failed: {}", e))`, which renders `ureq`'s raw
//! error chain. For a transport failure that chain is written for the person
//! who wrote the TLS stack, not for the person running the CLI. A real report:
//!
//!     Error: Login failed: login init failed: https://120.24.220.105:3000/...:
//!     Connection Failed: tls connection init failed: received corrupt message
//!     of type InvalidContentType
//!
//! That text names no cause the user can act on, yet the cause was simple and
//! certain: the URL said `https://` and the server answered in plain HTTP, so
//! rustls read an HTTP response where a TLS record should have been. The user
//! could not know that; the CLI could.
//!
//! WHAT THIS DOES, AND WHAT IT REFUSES TO DO
//! =========================================
//! `explain()` ENRICHES a failure it recognises and returns the raw text
//! UNCHANGED otherwise. It never replaces, summarises or swallows the original
//! error — an unrecognised failure must stay exactly as loud and as complete as
//! it is today (project rule: 失败要显眼，不要沉默). The recognised set is a
//! closed table (`SIGNATURES`), not a chain of heuristics, so adding a case is
//! a table row and the match order is reviewable in one place.
//!
//! WHY THE CLASSIFIER IS PURE
//! ==========================
//! `ureq`'s error constructors (`ErrorKind::msg` / `.src`) are `pub(crate)`, so
//! a unit test cannot fabricate a `ureq::Error`. Classification therefore takes
//! three primitives — url, kind, full error text — and `explain()` is a thin
//! adapter that extracts them. Every branch below is directly testable, and the
//! adapter is covered end-to-end against a real local listener (see tests).
//!
//! NOT COVERED, DELIBERATELY: the mirror case (`http://` against a TLS-only
//! port). Measured 2026-08-21 against a live TLS endpoint: the server answers
//! `HTTP/1.1 400 Bad Request` in plaintext, i.e. it surfaces as
//! `ureq::Error::Status(400)` with a server-specific body, never as a transport
//! failure. Diagnosing it belongs to the status layer and would have to guess at
//! nginx/cloudflare body text, so it is left alone rather than guessed at.

/// Transport failure classes we map from `ureq::ErrorKind`.
///
/// Deliberately coarser than `ureq::ErrorKind`: the classifier keys off the
/// error TEXT for everything except DNS, because the interesting distinctions
/// (plaintext server vs untrusted cert vs refused) all arrive under the single
/// `ConnectionFailed` kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    ConnectionFailed,
    Dns,
    Io,
    Other,
}

/// One diagnosed cause. Mirrors `local_server_diagnose::Finding` on purpose so
/// the two diagnostics read identically to the user (same vocabulary: Cause /
/// Evidence / To fix). Kept separate rather than shared because that type is
/// owned by the local-server domain; if a THIRD consumer appears, extract then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// Conclusion — what is wrong, one line, in the user's terms.
    pub cause: String,
    /// Why we concluded it — quoted from the underlying error so the user can
    /// verify the reasoning instead of trusting it.
    pub evidence: String,
    /// Paste-ready steps, in order.
    pub fix: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    PlaintextServer,
    HostnameMismatch,
    ExpiredCert,
    UntrustedCert,
    ConnectionRefused,
    Timeout,
}

/// Ordered signature table: (cause, kinds it may be concluded from, needles).
///
/// FIRST match wins, so the specific certificate failures must precede the
/// generic "invalid peer certificate" catch. Needles are lowercase; the
/// haystack is lowercased once before matching.
///
/// WHY THE KINDS COLUMN EXISTS: matching on text alone misdiagnoses. A
/// corporate-proxy failure (`ErrorKind::ProxyConnect`) can carry the words
/// "connection refused", and concluding "nothing is listening on the control
/// URL port" from it points the user at the wrong machine entirely. A cause is
/// only concluded from a kind where it is actually sound; every other kind
/// falls through and the raw error is preserved.
const SIGNATURES: &[(Cause, &[TransportKind], &[&str])] = &[
    // rustls says this when the peer's first bytes are not a TLS record at all.
    // "InvalidContentType" is the definitive marker; the wording around it has
    // changed between rustls releases, so the looser phrase is kept as a second
    // needle rather than relying on one exact sentence.
    (
        Cause::PlaintextServer,
        &[TransportKind::ConnectionFailed],
        &["invalidcontenttype", "received corrupt message"],
    ),
    (
        Cause::HostnameMismatch,
        &[TransportKind::ConnectionFailed],
        &["notvalidforname"],
    ),
    (
        Cause::ExpiredCert,
        &[TransportKind::ConnectionFailed],
        &["certexpired", "certificate has expired"],
    ),
    (
        Cause::UntrustedCert,
        &[TransportKind::ConnectionFailed],
        &["unknownissuer", "invalid peer certificate"],
    ),
    (
        Cause::ConnectionRefused,
        &[TransportKind::ConnectionFailed, TransportKind::Io],
        &[
            "connection refused",
            // Same condition, three platforms. errno is in the text because
            // ureq passes std::io::Error through verbatim and its Display is
            // localised on Windows — matching the number survives translation.
            "os error 61",    // macOS / BSD  ECONNREFUSED
            "os error 111",   // Linux        ECONNREFUSED
            "os error 10061", // Windows      WSAECONNREFUSED
        ],
    ),
    (
        Cause::Timeout,
        &[TransportKind::ConnectionFailed, TransportKind::Io],
        &[
            "timed out",
            "os error 60",    // macOS / BSD  ETIMEDOUT
            "os error 110",   // Linux        ETIMEDOUT
            "os error 10060", // Windows      WSAETIMEDOUT
        ],
    ),
];

/// Classify a control-service transport failure.
///
/// `base_url` is the control URL as the user configured it (not the endpoint
/// path) so the remedies can be pasted back verbatim. `detail` is the FULL
/// error text including the source chain — the rustls reason lives in the
/// chain, not in `ureq`'s own message.
///
/// Returns `None` when the failure is not one we can speak to; the caller must
/// then keep the raw text.
pub fn classify(base_url: &str, kind: TransportKind, detail: &str) -> Option<Diagnosis> {
    let hay = detail.to_ascii_lowercase();

    // DNS is the one class ureq labels reliably, and its text carries no
    // signature worth matching.
    if kind == TransportKind::Dns {
        return Some(Diagnosis {
            cause: format!("The host in {} could not be resolved.", base_url),
            evidence: trimmed(detail),
            fix: vec![
                "Check the host name for typos.".to_string(),
                "Confirm this machine can resolve it (nslookup / dig), and that \
                 you are on the network or VPN where the control service lives."
                    .to_string(),
            ],
        });
    }

    let cause = SIGNATURES
        .iter()
        .find(|(_, kinds, needles)| {
            kinds.contains(&kind) && needles.iter().any(|n| hay.contains(n))
        })
        .map(|(c, _, _)| *c)?;

    Some(build(cause, base_url, detail))
}

fn build(cause: Cause, base_url: &str, detail: &str) -> Diagnosis {
    let evidence = trimmed(detail);
    match cause {
        Cause::PlaintextServer => Diagnosis {
            cause: format!(
                "{} uses https://, but the server answered in plain HTTP — it is \
                 not serving TLS on that port.",
                base_url
            ),
            evidence: format!(
                "{} — the TLS handshake failed because the reply was not a TLS \
                 record at all.",
                evidence
            ),
            fix: vec![
                format!(
                    "If the server is meant to be plain HTTP, re-run login with \
                     the http:// form:\n       aikey login --control-url {}",
                    to_http(base_url)
                ),
                "If it is meant to serve HTTPS, terminate TLS on that port \
                 (nginx / ingress / load balancer) and keep the https:// URL."
                    .to_string(),
            ],
        },
        Cause::HostnameMismatch => Diagnosis {
            cause: format!(
                "The TLS certificate presented by {} is not valid for that host \
                 name.",
                base_url
            ),
            evidence,
            fix: vec![
                "Use the host name the certificate was issued for (an IP address \
                 will not match a name-only certificate)."
                    .to_string(),
                "Or re-issue the server certificate with this host in its \
                 Subject Alternative Names."
                    .to_string(),
            ],
        },
        Cause::ExpiredCert => Diagnosis {
            cause: format!("The TLS certificate presented by {} has expired.", base_url),
            evidence,
            fix: vec![
                "Renew the certificate on the control service and reload it.".to_string(),
                "If the certificate looks current, check this machine's clock — \
                 a skewed clock reports a valid certificate as expired."
                    .to_string(),
            ],
        },
        Cause::UntrustedCert => Diagnosis {
            cause: format!(
                "The TLS certificate presented by {} is not trusted by this \
                 machine (self-signed, or issued by a private CA).",
                base_url
            ),
            evidence,
            fix: vec![
                "Install the issuing CA certificate in this machine's trust \
                 store, then retry."
                    .to_string(),
                "Do not work around this by disabling verification — the \
                 control service carries your credentials."
                    .to_string(),
            ],
        },
        Cause::ConnectionRefused => Diagnosis {
            cause: format!(
                "Nothing is listening on the port in {} — the host is reachable \
                 but refused the connection.",
                base_url
            ),
            evidence,
            fix: vec![
                "Check the port number in the control URL.".to_string(),
                "Confirm the control service is running on that host.".to_string(),
            ],
        },
        Cause::Timeout => Diagnosis {
            cause: format!("Connecting to {} timed out.", base_url),
            evidence,
            fix: vec![
                "Check that you are on the network or VPN where the control \
                 service is reachable."
                    .to_string(),
                "A firewall or security group silently dropping the port looks \
                 exactly like this — verify the port is open from this machine."
                    .to_string(),
            ],
        },
    }
}

/// Rewrite an `https://` URL to `http://`, leaving anything else untouched.
fn to_http(url: &str) -> String {
    match url.strip_prefix("https://") {
        Some(rest) => format!("http://{}", rest),
        None => url.to_string(),
    }
}

fn trimmed(detail: &str) -> String {
    detail.trim().to_string()
}

/// Render a diagnosis using the same Cause / Evidence / To fix vocabulary as
/// `local_server_diagnose::render_findings`, so the CLI speaks one dialect.
pub fn render(base_url: &str, diag: &Diagnosis) -> String {
    let mut out = format!("cannot reach the control service at {}\n", base_url);
    out.push_str(&format!("\n  Cause:    {}\n", diag.cause));
    out.push_str(&format!("  Evidence: {}\n", diag.evidence));
    if !diag.fix.is_empty() {
        out.push_str("\n  To fix:\n");
        for (i, step) in diag.fix.iter().enumerate() {
            out.push_str(&format!("    {}. {}\n", i + 1, step));
        }
    }
    out
}

/// Adapter: turn a `ureq` failure against `base_url` into user-facing text.
///
/// Recognised transport failures are enriched; everything else — including
/// every HTTP status error, which is a business outcome and not ours to
/// interpret — is returned exactly as `ureq` rendered it.
pub fn explain(base_url: &str, err: &ureq::Error) -> String {
    let raw = err.to_string();
    let kind = match err {
        ureq::Error::Status(_, _) => return raw,
        ureq::Error::Transport(t) => match t.kind() {
            ureq::ErrorKind::ConnectionFailed => TransportKind::ConnectionFailed,
            ureq::ErrorKind::Dns => TransportKind::Dns,
            ureq::ErrorKind::Io => TransportKind::Io,
            // Everything else — proxy failures, redirect loops, malformed
            // headers — is Other, which no table row accepts. We have no advice
            // we can stand behind for those, and a wrong diagnosis costs the
            // user more than the raw error does.
            _ => TransportKind::Other,
        },
    };
    match classify(base_url, kind, &raw) {
        Some(d) => render(base_url, &d),
        None => raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    // ── Pure classifier: one test per table row, plus the fall-through ───────

    /// The exact text a user reported on 2026-08-21 against a plaintext
    /// control service on port 3000.
    const REAL_PLAINTEXT_ERROR: &str = "https://120.24.220.105:3000/v1/auth/cli/login/init: \
         Connection Failed: tls connection init failed: received corrupt message of type \
         InvalidContentType";

    fn classify_cf(detail: &str) -> Option<Diagnosis> {
        classify(
            "https://120.24.220.105:3000",
            TransportKind::ConnectionFailed,
            detail,
        )
    }

    #[test]
    fn plaintext_server_names_the_cause_and_offers_the_http_url() {
        let d = classify_cf(REAL_PLAINTEXT_ERROR).expect("must be recognised");
        assert!(
            d.cause.contains("answered in plain HTTP"),
            "cause must say what is wrong in the user's terms: {}",
            d.cause
        );
        // The remedy must be paste-ready, with the scheme actually rewritten.
        let joined = d.fix.join("\n");
        assert!(
            joined.contains("aikey login --control-url http://120.24.220.105:3000"),
            "fix must contain the corrected, paste-ready command: {}",
            joined
        );
        assert!(
            !joined.contains("--control-url https://"),
            "the remedy must not repeat the broken https:// URL: {}",
            joined
        );
        // Evidence must quote the original so the user can check the reasoning.
        assert!(d.evidence.contains("InvalidContentType"));
    }

    #[test]
    fn plaintext_server_also_matches_the_looser_rustls_wording() {
        // Guards against a rustls release that drops the type name.
        let d = classify_cf("Connection Failed: received corrupt message").unwrap();
        assert!(d.cause.contains("plain HTTP"));
    }

    #[test]
    fn hostname_mismatch_wins_over_the_generic_certificate_signature() {
        // Real rustls text carries BOTH phrases; the ordered table must pick
        // the specific one or the user gets useless advice.
        let d = classify_cf("invalid peer certificate: NotValidForName").unwrap();
        assert!(
            d.cause.contains("not valid for that host name"),
            "ordered match failed, got: {}",
            d.cause
        );
    }

    #[test]
    fn expired_cert_wins_over_the_generic_certificate_signature() {
        let d = classify_cf("invalid peer certificate: CertExpired").unwrap();
        assert!(d.cause.contains("has expired"), "got: {}", d.cause);
        // Clock skew is the non-obvious half of this diagnosis.
        assert!(d.fix.join("\n").contains("clock"));
    }

    #[test]
    fn untrusted_cert_is_recognised_and_refuses_to_suggest_disabling_verification() {
        let d = classify_cf("invalid peer certificate: UnknownIssuer").unwrap();
        assert!(d.cause.contains("not trusted"));
        let joined = d.fix.join("\n").to_ascii_lowercase();
        assert!(joined.contains("install the issuing ca"));
        assert!(
            !joined.contains("--insecure") && !joined.contains("skip verification"),
            "must never hand the user a verification bypass: {}",
            joined
        );
    }

    #[test]
    fn connection_refused_is_recognised_on_every_platform_errno() {
        for detail in [
            "Connection refused",
            "tcp connect error: os error 61",
            "tcp connect error: os error 111",
            "tcp connect error: os error 10061",
        ] {
            let d = classify_cf(detail).unwrap_or_else(|| panic!("not matched: {}", detail));
            assert!(d.cause.contains("Nothing is listening"), "{}", detail);
        }
    }

    #[test]
    fn timeout_is_recognised_on_every_platform_errno() {
        for detail in ["timed out", "os error 60", "os error 110", "os error 10060"] {
            let d = classify("https://h:1", TransportKind::Io, detail)
                .unwrap_or_else(|| panic!("not matched: {}", detail));
            assert!(d.cause.contains("timed out"), "{}", detail);
        }
    }

    #[test]
    fn dns_is_keyed_off_the_kind_not_the_text() {
        let d = classify("https://nope.invalid", TransportKind::Dns, "whatever").unwrap();
        assert!(d.cause.contains("could not be resolved"));
    }

    #[test]
    fn a_needle_under_a_non_diagnosable_kind_is_left_alone() {
        // The kinds column is the load-bearing guard against misdiagnosis.
        // A corporate-proxy failure carries "connection refused" too, and
        // concluding "nothing is listening on the control URL port" from it
        // sends the user to inspect the wrong machine.
        assert!(
            classify(
                "https://h:3000",
                TransportKind::Other,
                "Proxy failed to connect: connection refused",
            )
            .is_none(),
            "a proxy failure must not be read as a control-service failure"
        );
        // TLS conclusions are only sound from a handshake failure.
        for detail in [
            "invalid peer certificate: UnknownIssuer",
            "received corrupt message of type InvalidContentType",
        ] {
            assert!(
                classify("https://h:3000", TransportKind::Io, detail).is_none(),
                "TLS text under a non-handshake kind must not be diagnosed: {}",
                detail
            );
        }
    }

    #[test]
    fn an_unrecognised_failure_is_left_alone() {
        assert!(
            classify_cf("some entirely novel transport failure").is_none(),
            "must not invent a diagnosis it cannot support"
        );
    }

    #[test]
    fn to_http_only_rewrites_the_scheme() {
        assert_eq!(to_http("https://h:3000"), "http://h:3000");
        // Already-plain and non-URL inputs must pass through untouched, so the
        // remedy never fabricates a scheme that was not there.
        assert_eq!(to_http("http://h:3000"), "http://h:3000");
        assert_eq!(to_http("h:3000"), "h:3000");
    }

    #[test]
    fn render_uses_the_same_vocabulary_as_local_server_diagnose() {
        let d = classify_cf(REAL_PLAINTEXT_ERROR).unwrap();
        let out = render("https://120.24.220.105:3000", &d);
        assert!(out.contains("Cause:"));
        assert!(out.contains("Evidence:"));
        assert!(out.contains("To fix:"));
        assert!(out.contains("1. "));
    }

    // ── Adapter, against REAL ureq errors from REAL sockets ─────────────────
    //
    // ureq's error constructors are pub(crate), so these cannot be faked. A
    // local listener is the only way to prove the kind/text mapping actually
    // holds — without it the table above would be a fence over an input shape
    // nobody has confirmed ureq produces.

    /// A socket that speaks plain HTTP, i.e. exactly the server the user hit.
    fn spawn_plaintext_http_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Reply immediately: rustls is waiting for a ServerHello and
                // will get an HTTP status line instead.
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\n\r\n{}",
                );
                let _ = sock.flush();
                let mut sink = [0u8; 64];
                let _ = sock.read(&mut sink);
            }
        });
        port
    }

    #[test]
    fn explain_reproduces_and_diagnoses_the_real_https_to_plaintext_failure() {
        let port = spawn_plaintext_http_server();
        let base = format!("https://127.0.0.1:{}", port);
        let err = ureq::post(&format!("{}/v1/auth/cli/login/init", base))
            .send_json(&serde_json::json!({}))
            .expect_err("an https request to a plaintext port must fail");

        // First: the bug as reported really is a ConnectionFailed transport
        // error. If ureq ever reclassifies it, this assertion is the alarm.
        match &err {
            ureq::Error::Transport(t) => {
                assert_eq!(t.kind(), ureq::ErrorKind::ConnectionFailed)
            }
            other => panic!("expected a transport error, got {:?}", other),
        }

        let out = explain(&base, &err);
        assert!(
            out.contains("answered in plain HTTP"),
            "the real failure must be diagnosed, got:\n{}",
            out
        );
        assert!(
            out.contains(&format!("--control-url http://127.0.0.1:{}", port)),
            "the real failure must yield a paste-ready remedy, got:\n{}",
            out
        );
    }

    #[test]
    fn explain_diagnoses_a_real_refused_connection() {
        // Bind then drop: the port is now guaranteed free and refusing.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let base = format!("http://127.0.0.1:{}", port);
        let err = ureq::get(&format!("{}/accounts/me", base))
            .call()
            .expect_err("a closed port must refuse");
        let out = explain(&base, &err);
        assert!(out.contains("Nothing is listening"), "got:\n{}", out);
    }

    /// Contract test, NOT a fence. Verified by mutation on 2026-08-21: routing
    /// `Error::Status` through the classifier instead of returning early does
    /// not change the output, because `TransportKind::Other` matches no table
    /// row. The early return is structural (a `Status` error has no `kind()` to
    /// read at all), and the kinds column is what actually prevents
    /// misdiagnosis — see `a_needle_under_a_non_diagnosable_kind_is_left_alone`,
    /// which does go red. Recorded here so a future reader does not mistake
    /// this test for proof the early return is load-bearing.
    #[test]
    fn explain_never_touches_an_http_status_error() {
        // Business errors are not ours to interpret: a 401 must reach the user
        // exactly as ureq rendered it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
                let _ = sock.flush();
            }
        });
        let base = format!("http://127.0.0.1:{}", port);
        let err = ureq::get(&format!("{}/accounts/me", base))
            .call()
            .expect_err("401 must be an error");
        let out = explain(&base, &err);
        assert_eq!(out, err.to_string());
        assert!(
            !out.contains("Cause:") && !out.contains("To fix:"),
            "no diagnosis vocabulary may leak into a status error: {}",
            out
        );
    }

    /// Keeps the unused-import warning honest if the helper above changes.
    #[allow(dead_code)]
    fn _assert_tcpstream_in_scope(_s: Option<TcpStream>) {}
}
