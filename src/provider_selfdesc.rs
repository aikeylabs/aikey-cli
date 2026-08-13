//! `.well-known/aikey-provider.json` — a relay's own description of itself.
//!
//! Tasks 4.2 / 4.2b / 4.2c / 4.3. The wire format is frozen in
//! `contract-freeze.md §2` and this module does not get to improve on it.
//!
//! # 🔴 THIS FILE IS A CLAIM, NOT A FACT
//!
//! Everything in it was written by the operator of the relay we are about to
//! send a credential to. It is used to PRE-FILL a form and for nothing else:
//! the provider, the protocols and the model list that get written to the
//! vault come from a real probe (`aikey add --from-url`, step "measured").
//!
//! Writing a declared value straight through is not a hypothetical mistake —
//! the three-axis linkage already shipped it once (D-3) and the symptom is a
//! credential that exists, looks configured, and cannot route.
//!
//! # 🔴 WHY THIS GATE IS WEAKER THAN THE ONE ON check.aikeylabs.com
//!
//! The public check site refuses private addresses and refuses `http://`
//! outright. Copying that here would be wrong, and R-3b says so explicitly.
//! Three questions decide how strong a gate has to be:
//!
//!   whose machine is dialling?  — there: OUR server, on the same network
//!                                  segment as our database. here: the USER'S
//!                                  laptop, on their own network.
//!   whose address is it?        — there: one a stranger submitted about a
//!                                  third party. here: one the user typed.
//!   whose key is being spent?   — there: a stranger's. here: their own.
//!
//! AiKey is a to-B product and enterprise customers run their relay INSIDE
//! their own network. `aikey add --from-url http://10.4.2.9:8443` is the
//! normal case, not the attack. A gate that refused it would delete a
//! legitimate Production-edition workflow to defend a boundary that does not
//! exist on this side.
//!
//! 🚫 So: do NOT "make the two gates consistent". `T-EDN-3b` in
//! `from_url_gate_tests` asserts the enterprise case still works, and exists
//! to fail for the next person who tries.
//!
//! What does NOT relax: cloud metadata endpoints. `169.254.169.254` is not a
//! valid relay address under any trust boundary, on anybody's machine.

use serde::Deserialize;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// The only version this build understands.
pub const SUPPORTED_VERSION: u64 = 1;

/// Path appended to the URL the user gives us.
pub const WELL_KNOWN_PATH: &str = "/.well-known/aikey-provider.json";

/// 🔴 Three hops, not "follow until it settles". A relay that needs more than
/// a couple of redirects to serve a static JSON file is either misconfigured
/// or leading us somewhere, and an unbounded follower is a denial-of-service
/// primitive against ourselves.
const MAX_HOPS: usize = 3;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Cloud instance-metadata endpoints. 🔴 Refused under EVERY trust boundary.
///
/// `100.100.100.200` (Alibaba Cloud) is named explicitly because it is not
/// private and not link-local: every generic classification says it is an
/// ordinary public address. A checklist that only lists 169.254.169.254 — the
/// AWS/GCP convention, and what most of them list — protects nothing on the
/// cloud a large share of our customers actually run on.
const METADATA_LITERALS: &[&str] = &[
    "169.254.169.254",  // AWS / GCP / Azure / OpenStack
    "100.100.100.200",  // Alibaba Cloud
    "fd00:ec2::254",    // AWS IMDS over IPv6
    "metadata.google.internal",
];

/// A relay's self-description, per contract-freeze.md §2.
///
/// 🔴 UNKNOWN FIELDS ARE IGNORED, NOT REJECTED (§2 semantic 3). A v2 relay
/// that adds a field must not break every v1 CLI in the field — those CLIs
/// are on other people's laptops and we cannot upgrade them. This is the
/// serde default and it is load-bearing; `unknown_fields_are_ignored` fails
/// if somebody adds `deny_unknown_fields` for tidiness.
#[derive(Debug, Clone, Deserialize)]
pub struct SelfDescription {
    /// 🔴 An integer, and the ONLY field this module refuses on. See `parse`.
    pub aikey_provider_version: u64,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub base_url: String,
    /// The three-axis "protocol" axis. Declared only — the probe decides.
    #[serde(default)]
    pub protocols: Vec<String>,
    /// 🔴 Optional, and declared-only even when present. §2 semantic 1.
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub docs_url: String,
    #[serde(default)]
    pub key_signup_url: String,
}

/// What the gate decided about a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    /// Dial it.
    Allow,
    /// Dial it, but the user has to be told something first.
    ///
    /// 🔴 A WARNING, NOT A REFUSAL, and the difference is the whole of R-3b.
    /// The user is told what the consequence is and then decides — on their
    /// own machine, about their own network, with their own key.
    Warn(String),
    /// Do not dial it, with a reason the user can act on.
    Refuse(String),
}

/// Why a fetch did not produce a description.
#[derive(Debug)]
pub enum FetchError {
    /// The gate said no.
    Gate(String),
    /// We never got an HTTP response. 🔴 Distinct from every other variant
    /// because it is the air-gapped case (task 4.7), which needs its own
    /// message and its own way forward rather than "it failed".
    Unreachable(String),
    /// The host answered, but not with a description.
    Http { status: u16, url: String },
    /// It answered 200 with something that is not the frozen shape.
    Body(String),
    /// 🔴 A version we do not understand. See `parse`.
    UnsupportedVersion { found: u64 },
    TooManyHops(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Gate(m) => write!(f, "{}", m),
            FetchError::Unreachable(m) => write!(
                f,
                "could not reach that address: {m}\n  \
                 If this machine has no outbound network — an air-gapped or \
                 restricted install — `--from-url` cannot work here by \
                 definition. Add the relay by hand instead:\n    \
                 aikey add <alias> --providers <protocol[,protocol]> --base-url <url>\n  \
                 That is the same write path this flag uses; the only thing \
                 you lose is the pre-fill."
            ),
            FetchError::Http { status, url } => write!(
                f,
                "{url} answered {status}, not a provider description.\n  \
                 Ask the operator whether they publish {WELL_KNOWN_PATH}, or \
                 add the relay by hand with --providers and --base-url."
            ),
            FetchError::Body(m) => write!(
                f,
                "that file is not an AiKey provider description: {m}\n  \
                 Expected the shape documented at \
                 https://check.aikeylabs.com/api"
            ),
            FetchError::UnsupportedVersion { found } => write!(
                f,
                "this description declares aikey_provider_version {found}; \
                 this CLI understands {SUPPORTED_VERSION}.\n  \
                 Upgrade with `aikey upgrade` and try again.\n  \
                 We refuse rather than guessing: reading a v{found} file \
                 under v{SUPPORTED_VERSION} rules would mis-map fields \
                 silently, and the result is a credential that looks \
                 configured and cannot route."
            ),
            FetchError::TooManyHops(m) => write!(f, "{}", m),
        }
    }
}

impl std::error::Error for FetchError {}

/// Decide whether the CLI may dial a URL (tasks 4.2b / 4.2c).
pub fn gate_url(raw: &str) -> GateVerdict {
    let parsed = match url_parts(raw) {
        Some(p) => p,
        None => {
            return GateVerdict::Refuse(format!(
                "{raw} does not look like a URL. It should look like \
                 https://relay.example.com"
            ))
        }
    };
    let (scheme, host) = parsed;

    if scheme != "http" && scheme != "https" {
        return GateVerdict::Refuse(format!(
            "we only fetch over http or https; {scheme:?} is not one of them"
        ));
    }

    // 🔴 Metadata check FIRST, and on the literal host before any resolution:
    // the literal is the case we can always decide, and it is the one an
    // attacker would use if they could get a URL in front of the user.
    if is_metadata_host(&host) {
        return GateVerdict::Refuse(format!(
            "{host} is a cloud instance-metadata endpoint, not a relay.\n  \
             This is the ONE address this command refuses on every kind of \
             network, including your own — there is no deployment in which it \
             is a legitimate provider."
        ));
    }
    // Best-effort resolution, so a NAME pointing at the metadata service is
    // caught too. 🔴 Deliberately best-effort: if resolution fails we do not
    // refuse, because ureq is about to fail with a clearer message than we
    // could invent, and because this is not a TOCTOU boundary — the machine
    // doing the dialling belongs to the person who typed the URL.
    if let Some(addrs) = resolve_best_effort(&host) {
        if let Some(bad) = addrs.iter().find(|a| is_metadata_addr(a)) {
            return GateVerdict::Refuse(format!(
                "{host} resolves to {bad}, a cloud instance-metadata endpoint."
            ));
        }
    }

    if scheme == "http" {
        // 🔴 WARNED, NOT REFUSED (R-3b). dgcheck refuses http outright because
        // it would be putting a STRANGER'S key on the wire in cleartext across
        // the public internet. Here the key is the user's own and the hop is
        // very often a switch in their own rack. Telling them the consequence
        // and letting them decide is the correct strength for this boundary.
        return GateVerdict::Warn(format!(
            "{raw} is plain http. The description itself is public, but the \
             credential you store for this relay will travel to it in \
             cleartext later — anyone on the path can read it. That is fine \
             inside your own network and not fine across the internet."
        ));
    }

    GateVerdict::Allow
}

/// Split a URL into (scheme, host) without pulling in a URL crate.
///
/// 🔴 Deliberately strict about what it accepts rather than clever about
/// what it repairs: a parser that guesses is a parser that disagrees with
/// whatever ureq does a moment later, and the two disagreeing is how a gate
/// approves one address while the client connects to another.
fn url_parts(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@') // strip any userinfo
        .next()
        .unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6, or host[:port].
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("").to_string()
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

fn is_metadata_host(host: &str) -> bool {
    if METADATA_LITERALS.contains(&host) {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(addr) => is_metadata_addr(&addr),
        Err(_) => false,
    }
}

/// 🔴 The whole of 169.254.0.0/16 and fe80::/10, not just the well-known
/// literals. Nobody runs a relay on a link-local address, so refusing the
/// range costs nothing legitimate and closes the variants (169.254.169.253,
/// the IPv6 forms) that a literal list keeps missing.
fn is_metadata_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local() || METADATA_LITERALS.contains(&v4.to_string().as_str()),
        IpAddr::V6(v6) => {
            let s = v6.to_string();
            METADATA_LITERALS.contains(&s.as_str())
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .map(|m| is_metadata_addr(&IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}

fn resolve_best_effort(host: &str) -> Option<Vec<IpAddr>> {
    if host.parse::<IpAddr>().is_ok() {
        return None; // already checked as a literal
    }
    let addrs: Vec<IpAddr> = (host, 443u16)
        .to_socket_addrs()
        .ok()?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        None
    } else {
        Some(addrs)
    }
}

/// Parse a description body (task 4.3).
///
/// 🔴 THE VERSION IS CHECKED BEFORE ANY FIELD IS READ, and a higher version
/// is refused outright — 🚫 no best-effort parse. §2 semantic 2: reading a v2
/// file under v1 rules is a SILENT mis-mapping, and what comes out the other
/// end is a credential that looks configured and cannot route. A loud refusal
/// costs the user one `aikey upgrade`.
pub fn parse(body: &str) -> Result<SelfDescription, FetchError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| FetchError::Body(format!("not valid JSON ({e})")))?;
    let version = value
        .get("aikey_provider_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            FetchError::Body(
                "it has no integer `aikey_provider_version` field, so it is not \
                 one of these files at all"
                    .to_string(),
            )
        })?;
    if version != SUPPORTED_VERSION {
        return Err(FetchError::UnsupportedVersion { found: version });
    }
    let desc: SelfDescription = serde_json::from_value(value)
        .map_err(|e| FetchError::Body(format!("{e}")))?;
    if desc.protocols.is_empty() && desc.base_url.trim().is_empty() {
        return Err(FetchError::Body(
            "it declares neither `protocols` nor `base_url`, so there is \
             nothing to pre-fill from"
                .to_string(),
        ));
    }
    Ok(desc)
}

/// Where the description was read from, and anything the user must be told.
#[derive(Debug)]
pub struct Fetched {
    pub desc: SelfDescription,
    /// Warnings raised by the gate — printed before anything is stored.
    pub warnings: Vec<String>,
    /// The URL that finally answered, after redirects.
    pub final_url: String,
}

/// Build the document URL from what the user typed.
///
/// Accepts either the relay's root (`https://api.example.com`) or the full
/// path to the file, so a user who pasted the URL out of our own completion
/// page does not get told they did it wrong.
pub fn document_url(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.ends_with(WELL_KNOWN_PATH) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{WELL_KNOWN_PATH}")
    }
}

/// Fetch and parse a relay's self-description.
///
/// 🔴 THE EGRESS LANE IS DECLARED (task 4.2): this goes through
/// `build_proxy_aware_agent_no_redirect`, i.e. the SAME outbound path every
/// other CLI network call uses, including the user's own `proxy.env`. That
/// is the opposite call from probe-runner, which refuses to start under a
/// proxy — and the difference is the point. There, a proxy resolves the name
/// itself and defeats the IP pinning the SSRF gate depends on. Here there is
/// no pinning to defeat, and the proxy is frequently the only way the user's
/// machine reaches anything at all.
pub fn fetch(input: &str) -> Result<Fetched, FetchError> {
    let mut warnings = Vec::new();
    let mut current = document_url(input);

    for hop in 0..=MAX_HOPS {
        if hop == MAX_HOPS {
            return Err(FetchError::TooManyHops(format!(
                "that URL redirected more than {MAX_HOPS} times; refusing to \
                 follow further (last: {current})"
            )));
        }
        // 🔴 THE GATE RUNS ON EVERY HOP, not just the first. The second hop is
        // a URL the far end chose after we approved the first one, which is
        // exactly the shape of a redirect-to-metadata attack. Cheap to do,
        // and the version that only checks hop 1 looks identical in review.
        match gate_url(&current) {
            GateVerdict::Allow => {}
            GateVerdict::Warn(w) => {
                if !warnings.contains(&w) {
                    warnings.push(w)
                }
            }
            GateVerdict::Refuse(r) => return Err(FetchError::Gate(r)),
        }

        let agent = crate::connectivity::build_proxy_aware_agent_no_redirect(FETCH_TIMEOUT);
        let response = agent.get(&current).call();
        match response {
            Ok(resp) => {
                // 🔴 A 3xx ARRIVES HERE, NOT IN THE `Err(Status)` ARM.
                // With following disabled, ureq hands a redirect back as an
                // ordinary success — so the version of this loop that only
                // looked for redirects under `Err` did not follow them and
                // did not re-gate them either: it fed an empty body to the
                // JSON parser and told the user their relay serves invalid
                // JSON. Found by a live socket test; no amount of unit
                // testing the gate would have shown it.
                let status = resp.status();
                if (300..400).contains(&status) {
                    match resp.header("location") {
                        Some(loc) => {
                            current = join_redirect(&current, loc);
                            continue;
                        }
                        None => {
                            return Err(FetchError::Http {
                                status,
                                url: current,
                            })
                        }
                    }
                }
                let body = resp
                    .into_string()
                    .map_err(|e| FetchError::Body(format!("could not read the body ({e})")))?;
                let desc = parse(&body)?;
                return Ok(Fetched {
                    desc,
                    warnings,
                    final_url: current,
                });
            }
            Err(ureq::Error::Status(status, resp)) => {
                if (300..400).contains(&status) {
                    match resp.header("location") {
                        Some(loc) => {
                            current = join_redirect(&current, loc);
                            continue;
                        }
                        None => {
                            return Err(FetchError::Http {
                                status,
                                url: current,
                            })
                        }
                    }
                }
                return Err(FetchError::Http {
                    status,
                    url: current,
                });
            }
            Err(e) => return Err(FetchError::Unreachable(format!("{e}"))),
        }
    }
    unreachable!("the hop loop returns on its last iteration")
}

/// Resolve a Location header against the URL that produced it.
fn join_redirect(base: &str, location: &str) -> String {
    let loc = location.trim();
    if loc.contains("://") {
        return loc.to_string();
    }
    let origin = match base.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            format!("{scheme}://{authority}")
        }
        None => return loc.to_string(),
    };
    if loc.starts_with('/') {
        format!("{origin}{loc}")
    } else {
        format!("{origin}/{loc}")
    }
}

#[cfg(test)]
mod from_url_gate_tests {
    use super::*;

    /// 🔴 T-EDN-3b — THE REVERSE FENCE. It guards the FUTURE, not the code.
    ///
    /// The tempting change is "make the CLI gate consistent with the check
    /// site's". That change deletes the Production edition's normal case:
    /// an enterprise customer's relay lives inside their own network, and
    /// `--from-url http://10.4.2.9:8443` is what onboarding looks like there.
    /// Whoever tightens this will see every other test stay green.
    #[test]
    fn a_private_address_is_allowed_because_enterprise_relays_live_there() {
        for url in [
            "http://10.4.2.9:8443/v1",
            "https://192.168.1.20",
            "https://172.16.0.7/anthropic",
            "http://127.0.0.1:8080",
            "http://relay.internal:8443",
        ] {
            match gate_url(url) {
                GateVerdict::Refuse(r) => panic!(
                    "the CLI refused {url}: {r}\n\
                     R-3b: an enterprise customer's relay is INSIDE their \
                     network. Refusing this deletes the Production edition's \
                     normal onboarding path to defend a boundary that does not \
                     exist on the user's own machine."
                ),
                _ => {}
            }
        }
    }

    #[test]
    fn plain_http_warns_and_says_what_the_consequence_is() {
        match gate_url("http://relay.example.com") {
            GateVerdict::Warn(w) => {
                assert!(
                    w.contains("cleartext"),
                    "the warning does not say what goes wrong: {w}"
                );
            }
            other => panic!("http:// produced {other:?}, want a warning"),
        }
    }

    #[test]
    fn cloud_metadata_is_refused_on_every_boundary() {
        // 🔴 The one rule that does NOT relax between the two gates.
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/",
            "http://[fd00:ec2::254]/",
            "http://metadata.google.internal/",
            "http://169.254.169.253/",
        ] {
            match gate_url(url) {
                GateVerdict::Refuse(_) => {}
                other => panic!("{url} produced {other:?}, want a refusal"),
            }
        }
    }

    #[test]
    fn a_non_http_scheme_is_refused() {
        assert!(matches!(
            gate_url("file:///etc/passwd"),
            GateVerdict::Refuse(_)
        ));
        assert!(matches!(gate_url("not a url"), GateVerdict::Refuse(_)));
    }

    #[test]
    fn userinfo_cannot_smuggle_a_different_host_past_the_gate() {
        // `http://169.254.169.254@evil.example/` and its mirror image: the
        // host is what follows the LAST '@', which is what every client uses.
        match gate_url("http://evil.example@169.254.169.254/") {
            GateVerdict::Refuse(_) => {}
            other => panic!("userinfo smuggled a metadata host through: {other:?}"),
        }
    }
}

#[cfg(test)]
mod selfdesc_parse_tests {
    use super::*;

    const V1: &str = r#"{
        "aikey_provider_version": 1,
        "display_name": "Example Relay",
        "base_url": "https://api.example.com",
        "protocols": ["anthropic", "openai"],
        "models": ["claude-sonnet-4-5"],
        "docs_url": "https://example.com/docs"
    }"#;

    #[test]
    fn a_v1_document_parses() {
        let d = parse(V1).expect("v1 must parse");
        assert_eq!(d.display_name, "Example Relay");
        assert_eq!(d.protocols, vec!["anthropic", "openai"]);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // 🔴 §2 semantic 3. A v2 relay that adds a field must not break every
        // v1 CLI in the field — and those CLIs are on other people's laptops.
        let with_extra = r#"{
            "aikey_provider_version": 1,
            "base_url": "https://api.example.com",
            "protocols": ["anthropic"],
            "region_hint": "cn-north",
            "future_thing": {"nested": true}
        }"#;
        parse(with_extra).expect("unknown fields must be ignored, not rejected");
    }

    #[test]
    fn a_higher_version_is_refused_rather_than_guessed() {
        // 🔴 §2 semantic 2. Best-effort parsing means reading a v2 file under
        // v1 rules, which mis-maps silently.
        match parse(&V1.replace("\"aikey_provider_version\": 1", "\"aikey_provider_version\": 2")) {
            Err(FetchError::UnsupportedVersion { found }) => assert_eq!(found, 2),
            other => panic!("v2 gave {other:?}, want an explicit refusal"),
        }
    }

    #[test]
    fn a_file_without_the_version_field_is_not_one_of_ours() {
        match parse(r#"{"base_url":"https://x.example","protocols":["anthropic"]}"#) {
            Err(FetchError::Body(m)) => assert!(m.contains("aikey_provider_version")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_document_url_is_built_once_and_accepts_either_form() {
        assert_eq!(
            document_url("https://api.example.com"),
            "https://api.example.com/.well-known/aikey-provider.json"
        );
        assert_eq!(
            document_url("https://api.example.com/"),
            "https://api.example.com/.well-known/aikey-provider.json"
        );
        // A user who pasted the full path off our own completion page must not
        // get `/.well-known/...` appended twice.
        assert_eq!(
            document_url("https://api.example.com/.well-known/aikey-provider.json"),
            "https://api.example.com/.well-known/aikey-provider.json"
        );
    }

    #[test]
    fn a_redirect_is_resolved_against_the_url_that_produced_it() {
        assert_eq!(
            join_redirect("https://a.example/.well-known/x.json", "/b.json"),
            "https://a.example/b.json"
        );
        assert_eq!(
            join_redirect("https://a.example/x", "https://b.example/y"),
            "https://b.example/y"
        );
    }
}

// ── Declared vs measured (tasks 4.5 / 4.6) ───────────────────────────────
//
// 🔴 THE POINT OF SHOWING BOTH IS THAT THE USER SEES US DISAGREE WITH THE
// OPERATOR. A flow that quietly kept the measurement would be correct and
// unhelpful: the person onboarding needs to know that the relay's own file
// says it serves `openai` and that it does not, because that is a fact about
// the service they are about to depend on, and they are the one who can go
// ask about it.

/// One row of the comparison table.
#[derive(Debug, Clone)]
pub struct ComparisonRow {
    pub field: &'static str,
    pub declared: String,
    pub measured: String,
    /// False when we are about to store something other than what was
    /// declared. 🔴 Rendered, not just computed.
    pub agrees: bool,
}

/// What actually answered, gathered from the connectivity probe.
pub struct Measured {
    /// Protocols whose probe reached the upstream with this credential.
    pub protocols: Vec<String>,
    /// Model ids the relay listed. Empty means WE DID NOT SEE A LIST — many
    /// gateways serve chat and no `/models` — never "it has no models".
    pub models: Vec<String>,
    /// True when at least one protocol answered.
    pub any_ok: bool,
}

fn fmt_list(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_string()
    } else {
        items.join(", ")
    }
}

/// Build the side-by-side view (task 4.5).
pub fn compare(desc: &SelfDescription, measured: &Measured, effective_base_url: &str) -> Vec<ComparisonRow> {
    let mut rows = Vec::new();

    if !desc.display_name.trim().is_empty() {
        rows.push(ComparisonRow {
            field: "name",
            declared: desc.display_name.trim().to_string(),
            // 🔴 There is nothing to measure here and the column says so
            // rather than echoing the declaration into both sides, which
            // would read as confirmation.
            measured: "not checked".to_string(),
            agrees: true,
        });
    }

    let declared_base = if desc.base_url.trim().is_empty() {
        "—".to_string()
    } else {
        desc.base_url.trim().trim_end_matches('/').to_string()
    };
    let effective = effective_base_url.trim_end_matches('/').to_string();
    rows.push(ComparisonRow {
        field: "base URL",
        agrees: declared_base == effective || declared_base == "—",
        declared: declared_base,
        measured: effective,
    });

    let declared_protocols: Vec<String> = desc
        .protocols
        .iter()
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    rows.push(ComparisonRow {
        field: "protocols",
        agrees: same_set(&declared_protocols, &measured.protocols),
        declared: fmt_list(&declared_protocols),
        measured: fmt_list(&measured.protocols),
    });

    // 🔴 Models are COMPARED and shown, and then go nowhere: the vault entry
    // has no model column (the axes it stores are provider / protocol /
    // base_url / credential). Saying so here is better than implying we
    // stored a list we did not — the value of the row is that the user can
    // see the relay's file is out of date and go ask about it.
    let declared_models: Vec<String> = desc
        .models
        .iter()
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect();
    if !declared_models.is_empty() || !measured.models.is_empty() {
        rows.push(ComparisonRow {
            field: "models",
            agrees: same_set(&declared_models, &measured.models)
                || measured.models.is_empty(),
            declared: fmt_list(&declared_models),
            measured: if measured.models.is_empty() {
                "not listed by this relay".to_string()
            } else {
                fmt_list(&measured.models)
            },
        });
    }

    rows
}

fn same_set(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().all(|x| b.iter().any(|y| y.eq_ignore_ascii_case(x)))
}

#[cfg(test)]
mod comparison_tests {
    use super::*;

    fn desc(protocols: &[&str], models: &[&str]) -> SelfDescription {
        SelfDescription {
            aikey_provider_version: 1,
            display_name: "Example Relay".into(),
            base_url: "https://api.example.com".into(),
            protocols: protocols.iter().map(|s| s.to_string()).collect(),
            models: models.iter().map(|s| s.to_string()).collect(),
            docs_url: String::new(),
            key_signup_url: String::new(),
        }
    }

    #[test]
    fn a_protocol_that_was_declared_and_did_not_answer_is_shown_as_a_disagreement() {
        // 🔴 Task 4.5. The relay's file says it speaks two protocols; only one
        // answered. The user has to SEE that, because it is a fact about the
        // service they are about to depend on and they are the one who can go
        // ask about it.
        let d = desc(&["anthropic", "openai"], &[]);
        let m = Measured {
            protocols: vec!["anthropic".into()],
            models: vec![],
            any_ok: true,
        };
        let rows = compare(&d, &m, "https://api.example.com");
        let protocols = rows.iter().find(|r| r.field == "protocols").unwrap();
        assert!(!protocols.agrees, "a mismatch was rendered as agreement");
        assert_eq!(protocols.declared, "anthropic, openai");
        assert_eq!(protocols.measured, "anthropic");
    }

    #[test]
    fn agreement_is_agreement() {
        let d = desc(&["anthropic"], &[]);
        let m = Measured {
            protocols: vec!["anthropic".into()],
            models: vec![],
            any_ok: true,
        };
        let rows = compare(&d, &m, "https://api.example.com/");
        assert!(rows.iter().all(|r| r.agrees), "a matching pair disagreed");
    }

    #[test]
    fn no_model_list_is_not_reported_as_an_empty_model_list() {
        // 🔴 Plenty of gateways serve chat and no /models. "not listed by this
        // relay" and "this relay has no models" are different statements, and
        // only one of them is ours to make.
        let d = desc(&["anthropic"], &["claude-sonnet-4-5"]);
        let m = Measured {
            protocols: vec!["anthropic".into()],
            models: vec![],
            any_ok: true,
        };
        let rows = compare(&d, &m, "https://api.example.com");
        let models = rows.iter().find(|r| r.field == "models").unwrap();
        assert_eq!(models.measured, "not listed by this relay");
        assert!(
            models.agrees,
            "not having a /models endpoint was reported as the relay contradicting itself"
        );
    }

    #[test]
    fn the_name_column_does_not_echo_the_declaration_into_both_sides() {
        let d = desc(&["anthropic"], &[]);
        let m = Measured {
            protocols: vec!["anthropic".into()],
            models: vec![],
            any_ok: true,
        };
        let rows = compare(&d, &m, "https://api.example.com");
        let name = rows.iter().find(|r| r.field == "name").unwrap();
        assert_eq!(name.measured, "not checked");
    }
}
