//! Fences for `aikey mcp try` (task 8.7 · R23).
//!
//! 🔴 These run against the real functions. The two that matter most are
//! negative: what this command must NOT do.
use super::*;
use serde_json::json;

fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path":    { "type": "string"  },
            "limit":   { "type": "integer" },
            "ratio":   { "type": "number"  },
            "dry_run": { "type": "boolean" },
            "tags":    { "type": "array"   }
        }
    })
}

fn arg(s: &str) -> Vec<String> {
    vec![s.to_string()]
}

// ---------------------------------------------------------------------------
// 8.F5' — the self-check is a LABEL, never a capability
// ---------------------------------------------------------------------------

/// 🔴 R23's whole point: the try surface must not be a second permission face.
///
/// The gateway-side half of this is fence 8.F5 (`originFor` labels the row and
/// nothing branches on it). This is the client-side half: the command must send
/// exactly ONE thing that is not what an ordinary MCP client sends — the label
/// — and it must carry the operator's own bearer, not an admin credential.
///
/// 能红: add any second `X-Aikey-*` header to `post_raw`, or swap the bearer
/// for something that is not the operator's own route token.
#[test]
fn the_only_extra_header_is_the_audit_label() {
    let src = include_str!("../mcp_try.rs");
    let extras: Vec<&str> = src
        .match_indices("X-Aikey-")
        .map(|(i, _)| {
            let rest = &src[i..];
            let end = rest.find('"').unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    // The constant's definition and nothing else.
    assert_eq!(
        extras,
        vec!["X-Aikey-Mcp-Origin-Console-Test"],
        "this command may send exactly one internal header, and only to label the audit row"
    );
    assert!(
        src.contains("Authorization\", &format!(\"Bearer {}\", self.bearer)"),
        "the call must carry the operator's OWN bearer — R23 forbids an elevated identity"
    );
}

/// 🔴 There is no local authorisation decision to be made, and none is made.
///
/// The command must never decide a call is not allowed and skip it: that would
/// be a second implementation of the ACL, and the two would drift. It asks, and
/// prints whatever comes back.
///
/// 能红: add a permission check before `call_tool`.
#[test]
fn the_command_makes_no_authorisation_decision_of_its_own() {
    let src = include_str!("../mcp_try.rs");
    for forbidden in ["is_granted", "has_permission", "allowed_tools", "is_admin"] {
        assert!(
            !src.contains(forbidden),
            "'{forbidden}' suggests a local authorisation decision; the gateway decides (R23)"
        );
    }
}

// ---------------------------------------------------------------------------
// Argument coercion — by schema, never by appearance
// ---------------------------------------------------------------------------

/// 🔴 The defect this prevents: `1.0` and `0012` are both valid JSON, and both
/// mean something else once parsed. A version string becomes `1`; an account id
/// becomes `12`. The tool accepts them, because the TYPE is right.
///
/// 能红: coerce by `serde_json::from_str` first and fall back to string.
#[test]
fn a_string_argument_that_looks_like_a_number_stays_a_string() {
    let out = build_arguments(&arg("path=1.0"), None, &schema()).unwrap();
    assert_eq!(out["path"], json!("1.0"));

    let out = build_arguments(&arg("path=0012"), None, &schema()).unwrap();
    assert_eq!(out["path"], json!("0012"));

    let out = build_arguments(&arg("path=true"), None, &schema()).unwrap();
    assert_eq!(out["path"], json!("true"));
}

#[test]
fn declared_types_are_honoured() {
    let out = build_arguments(
        &["limit=10".into(), "ratio=0.5".into(), "dry_run=true".into()],
        None,
        &schema(),
    )
    .unwrap();
    assert_eq!(out["limit"], json!(10));
    assert_eq!(out["ratio"], json!(0.5));
    assert_eq!(out["dry_run"], json!(true));
}

/// An undeclared property is passed through as a string rather than guessed at.
/// The gateway validates against the same schema and names the field.
#[test]
fn an_undeclared_property_is_passed_through_as_a_string() {
    let out = build_arguments(&arg("nope=7"), None, &schema()).unwrap();
    assert_eq!(out["nope"], json!("7"));
}

/// Structure has no unambiguous shell spelling, so it is read as JSON — and a
/// parse failure is reported as one instead of silently becoming a string.
#[test]
fn array_and_object_arguments_are_read_as_json() {
    let out = build_arguments(&arg(r#"tags=["a","b"]"#), None, &schema()).unwrap();
    assert_eq!(out["tags"], json!(["a", "b"]));

    let err = build_arguments(&arg("tags=a,b"), None, &schema()).unwrap_err();
    assert!(err.contains("array or object"), "got: {err}");
}

#[test]
fn a_wrong_type_is_refused_before_the_call_and_says_where_the_type_came_from() {
    let err = build_arguments(&arg("limit=many"), None, &schema()).unwrap_err();
    assert!(err.contains("an integer"), "got: {err}");
    assert!(
        err.contains("published schema"),
        "the operator must know the type is the tool's claim, not ours: {err}"
    );
}

#[test]
fn a_malformed_arg_pair_says_how_to_write_one() {
    let err = build_arguments(&arg("justaword"), None, &schema()).unwrap_err();
    assert!(err.contains("NAME=VALUE"), "got: {err}");

    // A value containing '=' is kept whole rather than split twice.
    let out = build_arguments(&arg("path=a=b"), None, &schema()).unwrap();
    assert_eq!(out["path"], json!("a=b"));
}

#[test]
fn args_json_replaces_the_object_and_refuses_to_be_mixed() {
    let out = build_arguments(&[], Some(r#"{"limit":3}"#), &schema()).unwrap();
    assert_eq!(out["limit"], json!(3));

    let err = build_arguments(&arg("limit=1"), Some("{}"), &schema()).unwrap_err();
    assert!(err.contains("not both"), "got: {err}");

    let err = build_arguments(&[], Some("[1,2]"), &schema()).unwrap_err();
    assert!(err.contains("OBJECT"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Rendering — a refusal is an answer, and a tool error is not a success
// ---------------------------------------------------------------------------

/// 🔴 MCP puts TOOL-level failures inside a successful JSON-RPC result
/// (`isError: true`). Reading only the protocol layer prints a tick beside a
/// tool that just said it could not do the thing.
///
/// 能红: drop the `isError` branch from `render_result`.
#[test]
fn a_tool_that_reports_its_own_error_is_not_rendered_as_success() {
    let body = json!({
        "jsonrpc": "2.0", "id": 3,
        "result": { "isError": true, "content": [{ "type": "text", "text": "table not found" }] }
    })
    .to_string();
    let out = render_result(&body, "query", "local", "work", Duration::from_millis(12));
    assert!(out.contains("reported an error"), "got: {out}");
    assert!(!out.contains("succeeded"), "got: {out}");
    assert!(out.contains("table not found"), "got: {out}");
}

#[test]
fn a_successful_call_shows_the_content_and_where_it_was_recorded() {
    let body = json!({
        "jsonrpc": "2.0", "id": 3,
        "result": { "content": [{ "type": "text", "text": "main\ndevelop" }] }
    })
    .to_string();
    let out = render_result(
        &body,
        "list_branches",
        "local",
        "work",
        Duration::from_millis(7),
    );
    assert!(out.contains("succeeded"), "got: {out}");
    assert!(out.contains("develop"), "got: {out}");
    assert!(out.contains("aikey mcp calls"), "got: {out}");
    // 🔴 The user-facing wording is "self-check", never "console test" — the
    // stored value keeps its published name, the human sentence does not.
    assert!(out.contains("self-check"), "got: {out}");
    assert!(!out.to_lowercase().contains("console"), "got: {out}");
}

/// 🔴 A refusal is the system working. It must carry the gateway's own sentence
/// through, and must still say the call was recorded — an operator who thinks a
/// refusal left no trace will not go looking for it.
///
/// 能红: replace the carried message with a generic "request failed".
#[test]
fn a_refusal_carries_the_gateways_own_words_and_says_it_was_recorded() {
    let body = json!({
        "jsonrpc": "2.0", "id": 3,
        "error": {
            "code": "MCP_TOOL_FORBIDDEN",
            "message": "This seat is not granted 'delete_branch'. Ask an administrator."
        }
    })
    .to_string();
    let out = render_result(
        &body,
        "delete_branch",
        "local",
        "work",
        Duration::from_millis(3),
    );
    assert!(out.contains("not granted"), "got: {out}");
    assert!(out.contains("Ask an administrator"), "got: {out}");
    assert!(out.contains("MCP_TOOL_FORBIDDEN"), "got: {out}");
    assert!(out.contains("recorded call"), "got: {out}");
}

/// 🔴 Binary content is described, not dumped: an image is megabytes of base64
/// and tells the operator nothing they can read.
#[test]
fn non_text_content_is_described_rather_than_dumped() {
    let body = json!({
        "jsonrpc": "2.0", "id": 3,
        "result": { "content": [{ "type": "image", "data": "AAAABBBBCCCC", "mimeType": "image/png" }] }
    })
    .to_string();
    let out = render_result(
        &body,
        "screenshot",
        "local",
        "work",
        Duration::from_millis(9),
    );
    assert!(out.contains("[image content, not shown]"), "got: {out}");
    assert!(!out.contains("AAAABBBBCCCC"), "got: {out}");
}

// ---------------------------------------------------------------------------
// Unknown tool
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_tool_lists_what_is_actually_available() {
    let tools = vec![
        ToolDesc {
            name: "query".into(),
            description: String::new(),
            input_schema: json!({}),
        },
        ToolDesc {
            name: "list_tables".into(),
            description: String::new(),
            input_schema: json!({}),
        },
    ];
    let msg = unknown_tool_message("qeury", &tools, "local");
    assert!(
        msg.contains("list_tables, query"),
        "sorted and named: {msg}"
    );
    // A tool held for review is missing from tools/list on purpose (R3), and
    // that is the single most likely reason a name the operator expects is not
    // there — so the message says where to look.
    assert!(msg.contains("aikey mcp review"), "got: {msg}");
}

#[test]
fn an_empty_toolset_says_so_and_differs_by_edition() {
    let msg = unknown_tool_message("query", &[], "local");
    assert!(msg.contains("exposes no tools"), "got: {msg}");
    assert!(msg.contains("aikey mcp add"), "Personal's next step: {msg}");
    assert!(
        msg.contains("administrator"),
        "Production's next step: {msg}"
    );
}

// ---------------------------------------------------------------------------
// The verdict must reach the shell
// ---------------------------------------------------------------------------

/// 🔴 The defect this fence holds shut: the first version of this command
/// printed a refusal perfectly and **exited 0**. A self-check that cannot fail
/// a script is not a check. Found by running the real binary against a gateway
/// stub, not by reading the code — every unit test still passed.
///
/// 能红: make `Outcome::exit_code` return 0 for `Refused`.
#[test]
fn a_refusal_and_a_tool_error_both_exit_non_zero() {
    assert_eq!(Outcome::Succeeded.exit_code(), 0);
    assert_ne!(Outcome::Refused.exit_code(), 0);
    assert_ne!(Outcome::ToolReportedError.exit_code(), 0);
}

/// 🔴 2, not 1, and the difference is load-bearing: 1 means "could not run"
/// (no gateway, no key, unknown tool) and 2 means "ran, and the answer is no".
/// A caller that cannot tell them apart retries the one that will never work.
/// Same split as `aikey env check`.
#[test]
fn a_negative_answer_is_distinguishable_from_a_broken_command() {
    assert_eq!(Outcome::Refused.exit_code(), 2);
    assert_eq!(Outcome::ToolReportedError.exit_code(), 2);
}

/// What is printed and what is exited with come from ONE classifier, so they
/// cannot disagree — the failure mode being a tick on screen beside exit 2.
#[test]
fn the_printed_verdict_and_the_exit_code_come_from_the_same_decision() {
    let cases = [
        (
            json!({"jsonrpc":"2.0","id":3,"result":{"content":[]}}),
            Outcome::Succeeded,
            "succeeded",
        ),
        (
            json!({"jsonrpc":"2.0","id":3,"result":{"isError":true,"content":[]}}),
            Outcome::ToolReportedError,
            "reported an error",
        ),
        (
            json!({"jsonrpc":"2.0","id":3,"error":{"code":"MCP_TOOL_FORBIDDEN","message":"no"}}),
            Outcome::Refused,
            "was refused",
        ),
    ];
    for (body, want, phrase) in cases {
        let raw = body.to_string();
        assert_eq!(classify(&raw), want, "classify disagreed for {raw}");
        let shown = render_result(&raw, "t", "local", "k", Duration::from_millis(1));
        assert!(
            shown.contains(phrase),
            "render said something else: {shown}"
        );
    }
}
