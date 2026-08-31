//! The "Licensed to" row on `aikey status` and `aikey doctor`.
//!
//! # Why this module exists
//!
//! `specs/license-identity` (ID-02) requires the licensed company name to render
//! **byte-identically** on four surfaces: the web sign-in page, the web settings
//! page, `aikey status` and `aikey doctor`. Two of those are this binary, and
//! until now neither rendered anything at all — the CLI half of ID-02 was
//! satisfied by `aikeylic status`/`doctor`, a *different* binary that customers
//! do not receive. This module is the real CLI half.
//!
//! # The three states, and why they may never collapse into two
//!
//! 需求变更 2026-08-18: every surface now renders this row always, and an
//! unlicensed Personal install says so. That splits "no company name" into two
//! situations a reader must be able to tell apart:
//!
//! * **unlicensed** — this install has no licence and is not supposed to have
//!   one. A legitimate resting state. 🚫 NOT a warning: the open-source Personal
//!   user would otherwise get a warning on every `aikey status` forever.
//! * **error** — a licensed deployment whose identity could not be established
//!   (control plane unreachable, not activated yet, defective artifact). 🔴 This
//!   *is* a warning.
//!
//! Collapsing error into unlicensed would render a Cluster with a downed control
//! plane as a Personal install: the operator is told there is no licence here,
//! which is false and sends them the wrong way.
//!
//! # Why the strings are duplicated from Go rather than shared
//!
//! The four surfaces span Go (control-master), TypeScript (three SPAs) and Rust
//! (this CLI). No shared implementation can span them, so the authority is
//! `aikey-license-core/identity` and every other language copies the literals.
//! `aikey-license-core/crossrepo` is the fence that fails when a copy drifts —
//! 🚫 do not "tidy" these constants; the Go package is the source of truth.

use serde::Deserialize;
use std::time::Duration;

/// Prefixes the rendered row in every state.
/// Mirrors `identity.LicensedToLabel`.
pub const LICENSED_TO_LABEL: &str = "Licensed to: ";

/// Mirrors `identity.UnlicensedLine`.
pub const UNLICENSED_LINE: &str = "Licensed to: Personal edition (not commercially licensed)";

/// Mirrors `identity.ErrorLine`.
///
/// 🚫 It names no cause on purpose: the same constant is rendered on a sign-in
/// page, and the three causes need three different next actions. The cause is
/// carried by the warning this module emits alongside it.
pub const ERROR_LINE: &str = "Licensed to: unavailable";

/// Which of the three answers this install is giving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// A licensed deployment answered with its company name.
    Licensed(String),
    /// This install has no licence and is not supposed to have one.
    Unlicensed,
    /// A licensed deployment whose identity could not be established. The string
    /// is the operator-facing cause, and it is what makes the warning useful —
    /// 每个错误都要有原因和可行修复方法.
    Error(String),
}

/// The one renderer, in every state.
///
/// Mirrors `identity.LineFor`. A caller prints what comes back and 🚫 never
/// branches on the state itself — that branch, written twice, is how the console
/// and the CLI end up wording "Personal" differently.
///
/// 🚫 The blank-name guard maps to [`ERROR_LINE`], never [`UNLICENSED_LINE`]: a
/// licensed deployment that answered with an empty name is defective, and
/// rendering it as "Personal edition" hides a defect behind a legitimate state.
/// The one line the thirty-day ramp wants `aikey status` and `aikey doctor` to
/// trail with, or None when there is nothing to say.
///
/// # Why this exists
///
/// `Reminder.CLITrailingLine` has been produced by the control plane and asserted
/// on every single day of the ramp since commercial-licensing landed, and until
/// now **no CLI rendered it**. The release register said so in as many words —
/// "🚫 This is a PRODUCT gap, not a test gap: the assertion cannot be written
/// until something renders the line." This is the thing that renders it, so that
/// assertion can now be written.
///
/// # Three properties this must not break
///
/// * 🚫 **It never changes an exit code.** PRD §6.3: the ramp is a reminder, not
///   a degradation. `expiring` has planes identical to `active`; a CLI that
///   started failing during the ramp would be inventing an outage the licence
///   state explicitly does not describe.
/// * 🚫 **It never composes its own text.** The wording, the day count and the
///   locale all come from the control plane, which is the same producer the
///   console banner reads. A CLI that wrote "expires in {n} days" itself would be
///   a second producer, and two producers of one sentence disagree eventually —
///   the exact failure `line()` above exists to prevent for the identity row.
/// * 🔴 **Authenticated, unlike `identity`.** The reminder names a date and a day
///   count, which the sign-in page has no business showing to someone who has not
///   signed in. `/v1/license/identity` is deliberately unauthenticated because a
///   sign-in page renders it; this is not that, so it goes through the session.
///
/// Best effort and never blocking, like `resolve`: every failure path returns
/// None. A control plane that is down must not stop `aikey status` reporting
/// local state — 主链路不能被旁路拖累.
pub fn reminder() -> Option<String> {
    let account = match crate::storage::get_platform_account() {
        Ok(Some(account)) => account,
        // Not logged in, or the record is unreadable. Either way there is no
        // deployment whose term we could be counting down, and a CLI that guessed
        // would be the second producer this must not become.
        _ => return None,
    };
    let base = account.control_url.trim_end_matches('/');
    if base.is_empty() || account.jwt_token.is_empty() {
        return None;
    }

    fetch_reminder(base, &account.jwt_token)
}

/// The wire half of `reminder`, split out so it can be tested without a logged-in
/// account — the same split `resolve`/`fetch` already uses in this module.
fn fetch_reminder(base: &str, token: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build();
    let resp = agent
        .get(&format!("{base}/v1/license/status"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .ok()?;
    let dto = resp.into_json::<StatusDto>().ok()?;
    let line = dto.reminder?.cli_trailing_line?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        // An absent line and an empty one mean the same thing: this deployment is
        // healthy and the ramp has nothing to say. `omitempty` on the Go side means
        // both shapes reach us.
        return None;
    }
    Some(trimmed.to_string())
}

/// The slice of `GET /v1/license/status` this module reads.
///
/// 🚫 Deliberately not the whole Status. Deserialising every field would make this
/// CLI fail to parse a response from a NEWER control plane that added one, and the
/// reminder would go dark at exactly the moment someone upgraded the server first.
#[derive(Deserialize)]
struct StatusDto {
    reminder: Option<ReminderDto>,
}

#[derive(Deserialize)]
struct ReminderDto {
    cli_trailing_line: Option<String>,
}

pub fn line(state: &State) -> String {
    match state {
        // Verbatim. 🚫 No trimming, no case folding, no width folding, no
        // truncation — the same prohibition `identity.Line()` carries, and for
        // the same reason: a surface that trims and one that does not are two
        // surfaces that disagree while both believe they are right.
        State::Licensed(name) if !name.trim().is_empty() => format!("{LICENSED_TO_LABEL}{name}"),
        State::Licensed(_) => ERROR_LINE.to_string(),
        State::Unlicensed => UNLICENSED_LINE.to_string(),
        State::Error(_) => ERROR_LINE.to_string(),
    }
}

/// The operator-facing warning for `state`, or `None` when there is nothing
/// wrong.
///
/// 🔴 Split from the printing so the "does this state warn?" question has an
/// answer a test can read. A `warn_if_error` that only wrote to stderr could be
/// changed to warn on every Personal run and no unit test would notice — and
/// that regression is invisible in review precisely because the code reads as
/// helpful.
///
/// 🚫 Returns `None` for [`State::Unlicensed`]. That is the whole reason the two
/// states are separate: a Personal user is not experiencing a fault, and a
/// warning they see forever is a warning they learn to ignore.
pub fn warning_for(state: &State) -> Option<String> {
    match state {
        State::Error(cause) => Some(format!("the licensed identity is unavailable — {cause}")),
        State::Licensed(_) | State::Unlicensed => None,
    }
}

/// Prints [`warning_for`] to stderr, if there is one.
pub fn warn_if_error(state: &State) {
    if let Some(warning) = warning_for(state) {
        eprintln!("[aikey] warning: {warning}");
    }
}

/// The one-field shape `GET /v1/license/identity` returns.
///
/// 🔴 One field, deliberately. The server sends `license.MemberStatus` — a
/// separate type from the administrator DTO — so that expiry dates, ceilings and
/// enforcement mode cannot reach a member surface. Parsing it into a one-field
/// struct here keeps that property on this side of the wire too.
#[derive(Debug, Deserialize)]
struct IdentityDto {
    #[serde(default)]
    company_name: String,
}

/// Establishes which state this install is in.
///
/// Best effort by design and never blocking: every failure path returns a state,
/// none propagates an error to the caller. 主链路不能被旁路拖累 — `aikey status`
/// must finish and exit 0 whether or not a control plane answered.
pub fn resolve() -> State {
    let account = match crate::storage::get_platform_account() {
        Ok(Some(account)) => account,
        // Not logged in: a standalone Personal install. The resting state, not a
        // fault — this is the open-source user, and they get no warning.
        Ok(None) => return State::Unlicensed,
        // We could not even find out whether a deployment is configured. 🚫 The
        // resting state is the wrong answer for "I do not know": it reads as a
        // fact, and no fact was established.
        Err(err) => {
            return State::Error(format!(
                "the local login record could not be read ({err}); \
                 run `aikey doctor` to check the local state"
            ))
        }
    };
    fetch(&account.control_url)
}

/// Asks a deployment who it is licensed to.
///
/// 🔴 Unauthenticated on purpose. `/v1/license/identity` is the surface a
/// *sign-in page* renders, so it carries no session — which means this row still
/// works when the CLI's token has expired. That matters: an expired token is
/// exactly when someone runs `aikey status` to find out what is wrong, and a row
/// that needed a token would go dark at the moment it was wanted.
/// Maps "this control plane serves no licensing routes" to a state.
///
/// Split out so the decision is testable without install state or a server: the
/// caller establishes the fact, this decides what it means.
fn licensing_absent(base: &str, own_local_server: bool) -> State {
    if own_local_server {
        // The resting state, and the one D9 describes: our own Personal
        // local-server, which mounts no licensing surface by design. 🚫 No
        // warning — this is the open-source user and nothing is wrong.
        return State::Unlicensed;
    }
    State::Error(format!(
        "{base} serves no licence identity; it is a control plane built before \
         licensing shipped, so this deployment's licence cannot be read here. \
         Upgrade the control plane to see it"
    ))
}

/// Is `base` the local-server this install manages?
///
/// Loopback AND the port install state records. Both halves matter: a team
/// deployment reached over the network is not ours however it answers, and a
/// different service on loopback is not our local-server either.
fn points_at_own_local_server(base: &str) -> bool {
    let Ok(port) = crate::local_server_probe::read_local_server_port_or_default() else {
        // No local-server installed, so nothing here can be ours. 🚫 Not "assume
        // Personal": that is the guess this whole change removes.
        return false;
    };
    let authority = base
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let authority = authority.split('/').next().unwrap_or("");
    let (host, got_port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (authority, None),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
    loopback && got_port == Some(port)
}

fn fetch(control_url: &str) -> State {
    let base = control_url.trim_end_matches('/');
    if base.is_empty() {
        return State::Error(
            "the login record carries no control-plane URL; \
             run `aikey account set-url <url>` to point this install at its server"
                .to_string(),
        );
    }
    let url = format!("{base}/v1/license/identity");

    // Short, because this row is a side quest on a command whose job is to
    // report local state. A slow control plane must not hold up `aikey status`.
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build();

    match agent.get(&url).call() {
        Ok(resp) => match resp.into_json::<IdentityDto>() {
            Ok(dto) if !dto.company_name.trim().is_empty() => State::Licensed(dto.company_name),
            // 200 with no name: the deployment mounts licensing but holds no
            // activated licence yet. 🚫 Not "Personal" — it is a licensed edition
            // that has not been activated, and saying "no licence here" would
            // stop the operator doing the one thing that fixes it.
            Ok(_) => State::Error(format!(
                "{base} is a licensed deployment with no activated licence yet; \
                 import or activate one in the control console"
            )),
            Err(err) => State::Error(format!(
                "{base} answered with a body this build cannot read ({err}); \
                 the server may be a newer version than this CLI"
            )),
        },
        // 404 is design D9 speaking: a Personal-mode control plane mounts no
        // licensing route at all, so its absence IS the answer "not licensed".
        //
        // 🔴 …but ONLY when the plane on the other end is a Personal one, and a
        // 404 alone does not establish that (2026-08-26). A Production or Cluster
        // control plane built before licensing shipped answers 404 for exactly the
        // same reason a Personal one does — the route is not there — and reading
        // that as "Personal edition (not commercially licensed)" tells the
        // operator of a licensed deployment that no licence applies to them. That
        // is the collapse the three states at the top of this file exist to
        // prevent, arriving through a door D9 left open.
        //
        // Measured: 120.24.220.105:3000 serves a master console and answers 404
        // for every /v1/license/* route, and this row called it Personal.
        //
        // 🚫 Two other discriminators were tried and are wrong, so do not
        // reintroduce them:
        //   * probing /master/* — these deployments serve the SPA's index.html
        //     for ANY unknown path, so every edition answers 200;
        //   * "a platform account implies a team deployment" — a Personal
        //     local-server mounts the CLI login routes too, so Personal installs
        //     have one as well. Flipping on that would warn every Personal user
        //     on every `aikey status`, forever.
        //
        // What IS direct evidence: whether the control plane we are pointed at is
        // the local-server THIS install manages. That comes from install state we
        // already read, needs nothing from the server, and leaves D9 untouched —
        // Personal still mounts no licensing surface.
        Err(ureq::Error::Status(404, _)) => {
            licensing_absent(base, points_at_own_local_server(base))
        }
        Err(ureq::Error::Status(code, _)) => State::Error(format!(
            "{base} answered {code} for the licence identity; \
             check the control-plane logs"
        )),
        Err(err) => State::Error(format!(
            "{base} is unreachable ({err}); \
             check the network and that the control plane is running"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A one-shot control plane. 🔴 The tests below drive `fetch` over real
    /// HTTP through the real ureq agent rather than stubbing the parse, because
    /// the branches that matter — 404 vs 500, 200-with-empty-name — are
    /// *transport* distinctions. A stub that returned a pre-parsed value would
    /// assert nothing about the mapping this module actually performs.
    fn mock_control(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "X",
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    reason,
                    body.len(),
                    body
                );
            }
        });
        format!("http://{}", addr)
    }

    // The awkward name is the point. 🔴 A name that survives an ASCII round trip
    // proves nothing about 逐字节相同: the ways two surfaces diverge in practice
    // are case folding, whitespace trimming and full-width normalisation, and
    // every one of them needs a name that can show it. Same literal as the Go
    // side's `legalName`.
    const LEGAL_NAME: &str = "深圳示例科技有限公司  (Shenzhen Example Ltd.)　";

    #[test]
    fn the_name_is_not_touched_on_its_way_to_a_screen() {
        let rendered = line(&State::Licensed(LEGAL_NAME.to_string()));
        assert_eq!(
            rendered.strip_prefix(LICENSED_TO_LABEL),
            Some(LEGAL_NAME),
            "the CLI altered the signed name; ID-02 requires the bytes the \
             issuance desk typed, unchanged"
        );
    }

    #[test]
    fn the_three_states_render_three_distinct_lines() {
        let licensed = line(&State::Licensed(LEGAL_NAME.to_string()));
        let unlicensed = line(&State::Unlicensed);
        let failed = line(&State::Error("cause".into()));
        assert_ne!(licensed, unlicensed);
        assert_ne!(licensed, failed);
        assert_ne!(
            unlicensed, failed,
            "「no licence here」 and 「could not find out」 must be \
             distinguishable; they call for opposite next actions"
        );
        for row in [&licensed, &unlicensed, &failed] {
            assert!(row.starts_with(LICENSED_TO_LABEL), "{row:?} lost the label");
        }
    }

    /// 🔴 The fence for the failure the three-state model exists to prevent.
    ///
    /// 能红: change the `State::Licensed(_)` arm in `line` to return
    /// `UNLICENSED_LINE`.
    #[test]
    fn a_licensed_deployment_with_no_name_is_an_error_not_personal() {
        for empty in ["", "  　"] {
            let rendered = line(&State::Licensed(empty.to_string()));
            assert_ne!(
                rendered, UNLICENSED_LINE,
                "a licensed deployment that answered with {empty:?} rendered as the \
                 UNLICENSED line — that reports a broken licensed deployment as a \
                 Personal install"
            );
            assert_eq!(rendered, ERROR_LINE);
        }
    }

    /// 🔴 The warning must fire for errors and stay silent for the resting state.
    ///
    /// The open-source Personal user runs `aikey status` forever; a warning there
    /// is noise that trains people to ignore warnings — and once ignored, the
    /// error-state warning that actually matters is ignored with it.
    ///
    /// 能红: return `Some(..)` for `State::Unlicensed` in `warning_for`.
    #[test]
    fn only_the_error_state_is_worth_a_warning() {
        assert_eq!(
            warning_for(&State::Unlicensed),
            None,
            "a Personal install was warned at; it is not experiencing a fault"
        );
        assert_eq!(warning_for(&State::Licensed(LEGAL_NAME.into())), None);

        let warning = warning_for(&State::Error("the control plane is on fire".into()))
            .expect("an error state must produce a warning");
        assert!(
            warning.contains("the control plane is on fire"),
            "the warning {warning:?} dropped the cause, so it tells the operator \
             nothing they can act on"
        );
    }

    #[test]
    fn a_deployment_with_no_url_is_an_error_not_personal() {
        assert!(
            matches!(fetch(""), State::Error(_)),
            "a login record with no control URL is a broken install, not a \
             Personal one"
        );
    }

    /// The literals must match `aikey-license-core/identity` exactly. This is the
    /// local half; `crossrepo` is the half that reads both repos.
    #[test]
    fn the_constants_are_composed_from_the_one_label() {
        assert!(UNLICENSED_LINE.starts_with(LICENSED_TO_LABEL));
        assert!(ERROR_LINE.starts_with(LICENSED_TO_LABEL));
        assert_eq!(LICENSED_TO_LABEL, "Licensed to: ");
        assert_eq!(
            UNLICENSED_LINE,
            "Licensed to: Personal edition (not commercially licensed)"
        );
        assert_eq!(ERROR_LINE, "Licensed to: unavailable");
    }

    #[test]
    fn a_licensed_deployment_answers_with_its_name() {
        let base = mock_control(
            200,
            r#"{"schema_version":1,"company_name":"深圳示例科技有限公司  (Shenzhen Example Ltd.)　"}"#,
        );
        match fetch(&base) {
            State::Licensed(name) => assert_eq!(
                name, LEGAL_NAME,
                "the name was altered between the wire and the state"
            ),
            other => panic!("expected Licensed, got {other:?}"),
        }
    }

    /// 🔴 404 from OUR OWN local-server is design D9 speaking, not a fault.
    ///
    /// A Personal-mode control plane mounts no licensing route at all, so the
    /// route's absence IS the answer. Mapping it to an error would warn every
    /// Personal user on every run — that is still the reason this state exists.
    ///
    /// 🔴 Refined 2026-08-26: the 404 ALONE used to carry this, and it cannot.
    /// A Production or Cluster plane built before licensing answers 404 for the
    /// same reason, and this row then called a licensed deployment "Personal".
    /// The quiet answer is now conditioned on evidence that the plane is ours;
    /// the sibling test below pins the other half.
    ///
    /// 能红: map our own local-server's absent route to `State::Error`.
    #[test]
    fn an_absent_licensing_route_on_our_own_local_server_is_unlicensed_not_an_error() {
        assert_eq!(
            licensing_absent("http://127.0.0.1:8090", true),
            State::Unlicensed
        );
    }

    /// 🔴 The mirror-image fence, and the more dangerous direction.
    ///
    /// A deployment that mounts licensing but holds no activated licence answers
    /// 200 with an empty name. Reporting that as "Personal edition" tells the
    /// operator there is no licence to install — which stops them doing the one
    /// thing that fixes it.
    ///
    /// 能红: map the empty-name arm to `State::Unlicensed`.
    #[test]
    fn a_licensed_deployment_with_no_activation_is_an_error_not_unlicensed() {
        let got = fetch(&mock_control(
            200,
            r#"{"schema_version":1,"company_name":""}"#,
        ));
        assert_ne!(
            got,
            State::Unlicensed,
            "an unactivated licensed deployment was reported as a Personal install"
        );
        match got {
            State::Error(cause) => assert!(
                cause.contains("activate") || cause.contains("activated"),
                "the cause {cause:?} does not tell the operator what to do next"
            ),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn a_server_side_failure_is_an_error_not_unlicensed() {
        let got = fetch(&mock_control(500, r#"{"error":"boom"}"#));
        assert_ne!(got, State::Unlicensed);
        assert!(matches!(got, State::Error(_)));
    }

    /// An unreachable control plane must not read as "no licence here" — that is
    /// the Cluster-with-a-downed-control-plane failure this model exists for.
    #[test]
    fn an_unreachable_deployment_is_an_error_not_unlicensed() {
        // Port 0 is never listening.
        let got = fetch("http://127.0.0.1:0");
        assert_ne!(got, State::Unlicensed);
        match got {
            State::Error(cause) => assert!(
                cause.contains("unreachable"),
                "the cause {cause:?} does not say what went wrong"
            ),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// 🔴 The DTO in this test is the VERBATIM body the live cluster produced on
    /// 2026-08-19 for serial bb69cad4a32f, sixteen days from its term end. It is
    /// pasted rather than hand-written so that this asserts against what the
    /// control plane actually sends, not against what this CLI hopes it sends.
    #[test]
    fn the_ramp_line_is_rendered_verbatim_from_the_control_plane() {
        let base = mock_control(
            200,
            r#"{"schema_version":1,"applicable":true,"edition":"cluster","state":"expiring","reminder":{"active":true,"severity":"warn","dismissible":false,"headline":"The commercial licence ends on 2026-09-04 (16 days left).","days_remaining":16,"cli_trailing_line":"! The AiKey licence ends in 16 days. Ask your administrator to renew it.","email_stage":"T-30"}}"#,
        );
        assert_eq!(
            fetch_reminder(&base, "token"),
            Some(
                "! The AiKey licence ends in 16 days. Ask your administrator to renew it."
                    .to_string()
            ),
            "the CLI must print the control plane's sentence verbatim; composing its own \
             would make it a second producer of one sentence"
        );
    }

    /// A healthy deployment says nothing. 🚫 Non-empty assertion for the test
    /// above: if `fetch_reminder` returned None unconditionally, that test would
    /// fail — so these two together cannot both pass for the wrong reason.
    #[test]
    fn a_healthy_deployment_has_no_ramp_line() {
        let base = mock_control(
            200,
            r#"{"schema_version":1,"state":"active","reminder":{"active":false}}"#,
        );
        assert_eq!(fetch_reminder(&base, "token"), None);
    }

    /// An unreachable or unreadable control plane must not stop `aikey status`.
    #[test]
    fn the_ramp_line_never_breaks_the_command() {
        assert_eq!(fetch_reminder("http://127.0.0.1:0", "token"), None);
        let garbage = mock_control(200, "not json");
        assert_eq!(fetch_reminder(&garbage, "token"), None);
    }

    /// A NEWER control plane that adds fields must still be readable — the reason
    /// StatusDto deserialises a slice rather than the whole Status.
    #[test]
    fn an_unknown_field_from_a_newer_server_is_ignored() {
        let base = mock_control(
            200,
            r#"{"state":"expiring","some_future_field":{"a":1},"reminder":{"cli_trailing_line":"! x","another_new_one":true}}"#,
        );
        assert_eq!(fetch_reminder(&base, "token"), Some("! x".to_string()));
    }

    /// The rendered row for a live response must be byte-identical with what the
    /// Go renderer produces for the same name.
    #[test]
    fn the_rendered_row_survives_the_wire() {
        let base = mock_control(
            200,
            r#"{"schema_version":1,"company_name":"深圳示例科技有限公司  (Shenzhen Example Ltd.)　"}"#,
        );
        assert_eq!(
            line(&fetch(&base)),
            format!("{LICENSED_TO_LABEL}{LEGAL_NAME}")
        );
    }

    /// A 404 from a plane that is NOT our own local-server must not be read as
    /// "Personal edition".
    ///
    /// 🔴 The regression this pins shipped: 120.24.220.105:3000 serves a master
    /// console and 404s every /v1/license/* route because it was built before
    /// licensing, and this row told its operator "not commercially licensed".
    /// The header of this file forbids exactly that collapse; D9's "404 means
    /// Personal" is only true when the plane on the other end is Personal, and a
    /// 404 alone never established that.
    #[test]
    fn a_404_from_someone_elses_control_plane_is_an_error_not_personal() {
        // Through the real agent, not the pure helper: 404-vs-500-vs-unreachable
        // is a TRANSPORT distinction, and the mock's random loopback port is not
        // the local-server this install manages — which is exactly the foreign
        // plane this pins.
        let state = fetch(&mock_control(404, r#"{"error":"not found"}"#));
        match &state {
            State::Error(cause) => {
                // Actionable, or the operator learns nothing they can use.
                assert!(
                    cause.contains("before"),
                    "the cause must say the plane predates licensing: {cause}"
                );
                assert!(
                    cause.contains("Upgrade"),
                    "the cause must name the fix: {cause}"
                );
            }
            other => panic!("a foreign 404 became {other:?}; that is the collapse this guards"),
        }
        // And it must not claim Personal anywhere in what a user sees.
        let rendered = line(&state);
        assert!(
            !rendered.contains("Personal"),
            "rendered line claims Personal for a foreign control plane: {rendered}"
        );
    }

    /// The resting state still rests. A Personal user must not be warned on
    /// every `aikey status` forever — that is why this is decided by evidence
    /// about OUR local-server rather than by flipping the 404 wholesale.
    #[test]
    fn a_404_from_our_own_local_server_is_the_quiet_unlicensed_state() {
        let state = licensing_absent("http://127.0.0.1:8090", true);
        assert!(matches!(state, State::Unlicensed), "got {state:?}");
        assert!(warning_for(&State::Unlicensed).is_none());
    }

    /// The Personal path must keep working, and only a machine that actually
    /// has a local-server can prove it.
    ///
    /// 🔴 This is the half that is easy to break while "fixing" the foreign-404
    /// case: tighten the ownership test a little too far and every Personal user
    /// starts getting a warning on every `aikey status` — the regression the
    /// state above exists to prevent. Skipped where no local-server is
    /// installed rather than asserted-away, because a green run on a machine
    /// that could not have checked is worse than a skip that says so.
    #[test]
    fn our_own_local_server_is_recognised_when_one_is_installed() {
        let Ok(port) = crate::local_server_probe::read_local_server_port_or_default() else {
            eprintln!("skipped: no local-server installed on this machine");
            return;
        };
        for base in [
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
            format!("http://127.0.0.1:{port}/"),
        ] {
            assert!(
                points_at_own_local_server(&base),
                "{base} is this install's own local-server (port {port}) and was not \
                 recognised; a Personal user would now be warned on every status"
            );
            assert_eq!(
                licensing_absent(&base, points_at_own_local_server(&base)),
                State::Unlicensed
            );
        }
    }

    /// Both halves of "ours" are load-bearing.
    #[test]
    fn only_loopback_on_the_recorded_port_counts_as_our_local_server() {
        // A team deployment that happens to use the same port is not ours.
        assert!(!points_at_own_local_server(
            "http://control.corp.example:8090"
        ));
        // Nor is an arbitrary loopback service on some other port.
        assert!(!points_at_own_local_server("http://127.0.0.1:65533"));
    }

    /// 🚫 The 404 decision must not become "ask the server a second question".
    ///
    /// Two discriminators were measured and rejected: probing /master/* (these
    /// deployments serve the SPA's index.html for ANY unknown path, so every
    /// edition answers 200) and "a platform account implies a team deployment"
    /// (Personal local-servers mount the CLI login routes too). Both would have
    /// been extra requests answering nothing.
    ///
    /// So this pins the SHAPE rather than grepping for path literals — a fence
    /// that searches for "/master/" matches its own needle and can never be
    /// green. What it asserts is that the function deciding "is this ours" does
    /// no I/O at all: it reads install state, and nothing else.
    ///
    /// 能红: make points_at_own_local_server issue an HTTP request.
    #[test]
    fn the_ownership_decision_does_no_io() {
        let src = include_str!("license_identity.rs");
        let start = src.find("fn points_at_own_local_server").expect(
            "the ownership decision was renamed; update this fence rather than deleting it",
        );
        let body = &src[start..];
        let end = body.find("\nfn ").unwrap_or(body.len());
        let body = &body[..end];
        for io in ["ureq", "AgentBuilder", "agent.get", "TcpStream"] {
            assert!(
                !body.contains(io),
                "points_at_own_local_server now performs I/O ({io}); the whole point is \
                 that ownership is decided from install state we already have, so the row \
                 cannot get slower or start depending on a second endpoint"
            );
        }
    }
}
