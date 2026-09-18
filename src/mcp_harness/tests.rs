//! Fences for the harness adaptation layer (P15 · K4 · 15.23–15.25).
//!
//! # What these protect
//!
//! The adapter is the ONLY place that knows a harness's dialect. Two failure
//! shapes matter, and both are silent:
//!
//!   1. a dispatch that stops being a table — an `if name == "claude"` somewhere
//!      means the second harness gets added in two places and one of them is
//!      forgotten;
//!   2. a parse that stops being lenient — the vendor adds a field, strict
//!      decoding refuses it, and every developer's sub-agents stop at once.
//!
//! Neither breaks a type or another test.

use super::*;

#[test]
fn the_registry_dispatches_by_name_and_refuses_what_it_does_not_know() {
    // 🔴 A lookup, not a chain of ifs. 能红: replace `adapter_for` with a match
    // on a literal, or make it fall back to the default.
    assert_eq!(adapter_for("claude").map(|a| a.name()), Some("claude"));

    // 🚫 An unknown harness must be None, never the default. Silently adapting
    // to the wrong harness installs a hook into a file that harness never reads
    // — which looks exactly like a working install.
    assert!(
        adapter_for("codex").is_none(),
        "an unknown harness resolved to an adapter; a wrong adapter produces a gate that is \
         installed, green and inert"
    );
    assert!(adapter_for("").is_none());
}

#[test]
fn exactly_one_harness_is_claimed() {
    // 🔴 15.24: `claude` is the only harness whose identity shape has been
    // measured. Shipping an adapter for one we have not verified is a claim to
    // the customer that we support it.
    // 能红: add a second entry to REGISTRY without measuring it.
    assert_eq!(
        known_harnesses(),
        vec!["claude"],
        "a harness was added to the registry. Codex / Hermes / OpenClaw have not been verified \
         in a single field (15.24); an adapter written from vendor docs is a support claim we \
         cannot back."
    );
    assert_eq!(default_adapter().name(), "claude");
}

#[test]
fn both_spawn_tool_names_are_recognised() {
    // 🔴 Measured: the hook event says `Agent`, the run summary says `Task`,
    // for the SAME tool. Matching one leaves a gate that looks installed and
    // stops nothing. 能红: drop either arm.
    let a = default_adapter();
    assert!(a.is_spawn_tool("Agent"));
    assert!(a.is_spawn_tool("Task"));
    assert!(!a.is_spawn_tool("Bash"));
    assert!(!a.is_spawn_tool("agent"), "the harness sends exact-case names");
}

#[test]
fn an_unknown_field_does_not_break_the_parse() {
    // 🔴 15.25 / 15.X7. The hook contract belongs to a third party and gains
    // fields between releases. 能红: add `#[serde(deny_unknown_fields)]`.
    let raw = r#"{
        "tool_name":"Agent",
        "agent_id":"sub-1",
        "tool_input":{"subagent_type":"Explore","description":"look","prompt":"hi"},
        "brand_new_field_from_the_vendor": {"nested": [1,2,3]},
        "another_one": "whatever"
    }"#;
    let req = default_adapter().read_spawn(raw).expect("must parse");
    assert_eq!(req.agent_type, "Explore");
    assert!(!req.is_main_actor);
    assert!(
        req.warnings.is_empty(),
        "a complete event produced warnings: {:?}",
        req.warnings
    );
}

#[test]
fn a_missing_subagent_type_defaults_and_warns() {
    // 🔴 15.25's other half: a defaulted field must not be SILENT. An empty
    // agent type matches no tier, so the spawn is allowed — and "no tier
    // matched" looks identical to "the harness stopped telling us the type",
    // while the two have completely different fixes.
    // 能红: drop the warning, or make the empty type an error.
    let req = default_adapter()
        .read_spawn(r#"{"tool_name":"Agent","tool_input":{}}"#)
        .expect("a missing optional field must not fail the parse");
    assert_eq!(req.agent_type, "");
    assert_eq!(
        req.warnings.len(),
        1,
        "an empty agent type was defaulted silently; a spawn evaluated against no type is \
         indistinguishable from a spawn that matched no tier"
    );
    assert!(
        req.warnings[0].contains("subagent_type"),
        "the warning must name the field that was missing so the reader can check the vendor's \
         contract, got: {}",
        req.warnings[0]
    );
}

#[test]
fn main_actor_is_field_absence_not_an_empty_string() {
    // 🔴 Measured: a main-agent event carries NO `agent_id` key; a sub-agent
    // event carries one. Folding "absent" together with "present but empty"
    // would make a broken hook contract read as "everything is the main agent",
    // and every depth limit would stop biting — silently.
    // 能红: change `evt.agent_id.is_none()` to a string comparison.
    let a = default_adapter();

    let main = a.read_spawn(r#"{"tool_name":"Agent","tool_input":{"subagent_type":"x"}}"#).unwrap();
    assert!(main.is_main_actor, "no agent_id key at all means the main agent");

    let empty = a
        .read_spawn(r#"{"tool_name":"Agent","agent_id":"","tool_input":{"subagent_type":"x"}}"#)
        .unwrap();
    assert!(
        !empty.is_main_actor,
        "an agent_id that is PRESENT but empty is a broken contract, not the main agent — \
         collapsing the two makes every depth limit stop biting with no symptom"
    );

    let sub = a
        .read_spawn(r#"{"tool_name":"Agent","agent_id":"sub-7","tool_input":{"subagent_type":"x"}}"#)
        .unwrap();
    assert!(!sub.is_main_actor);
}

#[test]
fn an_unparseable_payload_is_an_error_the_caller_can_fail_open_on() {
    // 🔴 The adapter REPORTS the failure; it does not decide what to do about
    // it. Failing open is the caller's rule (D-29) and belongs at the hook, not
    // here — an adapter that silently returned a default would take that
    // decision away from the one place that documents it.
    let err = default_adapter()
        .read_spawn("this is not json")
        .expect_err("malformed input must be reported, not defaulted");
    assert!(err.contains("did not parse"), "got: {err}");
}

#[test]
fn the_adapter_states_the_harness_facts_the_installer_writes() {
    // 🔴 These two strings end up in the user's settings.json. They live here so
    // there is ONE copy — mcp_guard.rs used to hold a second, and "what Claude
    // Code calls its spawn tool" in two files is the drift this layer exists to
    // remove. 能红: hard-code either value back into mcp_guard.rs.
    let a = default_adapter();
    assert_eq!(a.hook_event(), "PreToolUse");
    assert_eq!(a.matcher(), "Agent|Task");
}
