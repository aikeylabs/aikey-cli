//! Fences for the delegation gate's CLI half (checklist §D D-91 / D-93 / D-94 /
//! D-95, tasks 15.F12 / 15.F13).
//!
//! Every test names the mutation it must catch. A fence whose breaking change is
//! not written down is a fence nobody can drill.

use super::*;

fn settings_with(v: serde_json::Value) -> serde_json::Value {
    v
}

fn third_party_group() -> serde_json::Value {
    serde_json::json!({
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "/usr/local/bin/somebody-elses-linter"}],
    })
}

// ---------------------------------------------------------------------------
// D-91 / 15.F12 — we are a guest in settings.json
// ---------------------------------------------------------------------------

/// Mutation: make `apply_install` replace `hooks.PreToolUse` instead of pushing
/// onto it.
///
/// Rationale: `settings.json` is the user's file. Replacing the array deletes
/// whatever else lives there, and the loss is silent — the other tool simply
/// stops running one day.
#[test]
fn install_preserves_a_third_party_hook() {
    let mut s = settings_with(serde_json::json!({
        "statusLine": {"type": "command", "command": "/somewhere/aikey statusline"},
        "theme": "dark",
        "hooks": {"PreToolUse": [third_party_group()]},
    }));

    assert_eq!(apply_install(&mut s), GuardAction::Installed);

    let list = s["hooks"]["PreToolUse"].as_array().expect("array");
    assert_eq!(list.len(), 2, "ours must be APPENDED, not swapped in");
    assert!(
        list.contains(&third_party_group()),
        "a third party's PreToolUse entry disappeared; settings.json is not ours to overwrite"
    );
    assert_eq!(s["theme"], "dark", "unrelated keys must survive");
    assert_eq!(
        s["statusLine"]["command"], "/somewhere/aikey statusline",
        "statusLine belongs to another feature and must not be touched"
    );
}

/// Mutation: have `apply_uninstall` clear the array / remove `hooks` wholesale.
///
/// Rationale: same file, same guests. Uninstalling our gate must not uninstall
/// somebody else's hook.
#[test]
fn uninstall_removes_only_ours() {
    let mut s = settings_with(serde_json::json!({
        "statusLine": {"type": "command", "command": "/somewhere/aikey statusline"},
        "hooks": {"PreToolUse": [third_party_group()]},
    }));
    apply_install(&mut s);
    assert!(apply_uninstall(&mut s));

    let list = s["hooks"]["PreToolUse"].as_array().expect("array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0], third_party_group());
    assert!(
        s.get("statusLine").is_some(),
        "statusLine must survive our uninstall"
    );
}

/// 🔴 The round trip must leave the document EXACTLY as it was.
///
/// Mutation: stop pruning the emptied `PreToolUse` array / `hooks` object.
///
/// Rationale: an install/uninstall cycle that leaves `"hooks": {"PreToolUse": []}`
/// behind has not restored anything — and residue like that is how a file
/// accumulates junk from every tool that ever touched it. The checklist's
/// "byte-for-byte" claim is only true if the containers we created are the
/// containers we remove.
#[test]
fn install_then_uninstall_restores_the_document() {
    let original = serde_json::json!({
        "statusLine": {"type": "command", "command": "/somewhere/aikey statusline"},
        "theme": "dark",
    });
    let mut s = original.clone();
    apply_install(&mut s);
    assert_ne!(s, original, "install must actually change something");
    assert!(apply_uninstall(&mut s));
    assert_eq!(
        s, original,
        "install → uninstall left residue behind; the containers we created must be the containers we remove"
    );
}

/// The same round trip when we were NOT the only hook: the third party's
/// container must stay, because we did not create it.
#[test]
fn uninstall_keeps_a_container_it_did_not_create() {
    let original = serde_json::json!({"hooks": {"PreToolUse": [third_party_group()]}});
    let mut s = original.clone();
    apply_install(&mut s);
    assert!(apply_uninstall(&mut s));
    assert_eq!(s, original);
}

/// Re-running install is a no-op, and re-running it after the binary moved
/// refreshes the path rather than adding a second copy.
///
/// Mutation: drop the `is_ours` lookup so every install pushes another group.
/// Rationale: a user who runs `aikey mcp guard install` twice would get the hook
/// invoked twice per spawn — two subprocesses, two decisions, one of them wrong
/// after an upgrade moved the binary.
#[test]
fn install_is_idempotent_and_refreshes_a_moved_binary() {
    let mut s = serde_json::json!({});
    assert_eq!(apply_install(&mut s), GuardAction::Installed);
    assert_eq!(apply_install(&mut s), GuardAction::AlreadyCurrent);
    assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);

    // Simulate the binary having moved.
    s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
        serde_json::json!("/old/path/aikey _internal mcp-guard-hook");
    assert_eq!(apply_install(&mut s), GuardAction::Refreshed);
    assert_eq!(
        s["hooks"]["PreToolUse"].as_array().unwrap().len(),
        1,
        "a moved binary must be UPDATED in place, never duplicated"
    );
}

// ---------------------------------------------------------------------------
// D-93 / 15.F13 — refuse a shape we do not understand
// ---------------------------------------------------------------------------

/// Mutation: coerce `hooks.PreToolUse` into an array when it is not one.
///
/// Rationale: if the vendor changes the shape, or the user hand-wrote something
/// else there, overwriting it destroys their configuration. Refusing is
/// recoverable; overwriting is not.
#[test]
fn install_refuses_a_shape_it_does_not_understand() {
    let mut s = serde_json::json!({"hooks": {"PreToolUse": "not-an-array"}});
    assert_eq!(apply_install(&mut s), GuardAction::RefusedForeignShape);
    assert_eq!(
        s["hooks"]["PreToolUse"], "not-an-array",
        "a shape we refused must be left exactly as it was"
    );

    let mut s2 = serde_json::json!({"hooks": 42});
    assert_eq!(apply_install(&mut s2), GuardAction::RefusedForeignShape);
    assert_eq!(s2["hooks"], 42);
}

// ---------------------------------------------------------------------------
// D-94 — the same tool has two names
// ---------------------------------------------------------------------------

/// Mutation: compare against one constant only, or narrow the matcher.
///
/// Rationale: measured on Claude Code 2.1.247 — the hook event says `Agent`
/// while the run summary says `Task`. Recognising one leaves a gate that looks
/// installed and stops nothing.
#[test]
fn both_spawn_tool_names_are_recognised() {
    assert!(is_delegation_tool("Agent"));
    assert!(is_delegation_tool("Task"));
    assert!(
        !is_delegation_tool("Bash"),
        "the gate must not fire on ordinary tools"
    );

    // The registered matcher must cover both names too — recognising them in
    // code is useless if the harness never invokes us.
    // 🔴 The matcher is the HARNESS's fact and now lives in one place (the
    // adapter). This assertion follows it there rather than keeping a second
    // copy of the string alive in the test.
    let matcher = crate::mcp_harness::default_adapter().matcher();
    assert!(matcher.contains("Agent"), "matcher must cover Agent");
    assert!(matcher.contains("Task"), "matcher must cover Task");
}

// ---------------------------------------------------------------------------
// D-95 — the main agent is FIELD ABSENCE
// ---------------------------------------------------------------------------

/// Mutation: treat `agent_id: ""` as the main agent.
///
/// Rationale: measured — a main-agent event carries no `agent_id` key at all.
/// Folding absence together with an empty value merges "this is the main agent"
/// with "the field decoded empty", i.e. with a broken hook contract.
#[test]
fn depth_distinguishes_absence_from_an_empty_agent_id() {
    // 🔴 Now asserted END TO END, through the adapter that reads the payload and
    // the arithmetic that turns it into a depth. The local event struct this
    // test used to decode moved to `mcp_harness` (P15 · K4); keeping a copy here
    // to test against would have re-created the duplication that layer removed.
    let a = crate::mcp_harness::default_adapter();

    let main = a.read_spawn(r#"{"tool_name":"Agent"}"#).unwrap();
    assert!(main.is_main_actor);
    assert_eq!(
        child_depth_of(&main),
        1,
        "a child of the main agent sits at depth 1"
    );

    let empty = a.read_spawn(r#"{"agent_id":""}"#).unwrap();
    assert!(
        !empty.is_main_actor,
        "a present-but-empty agent_id is a decode problem, not the main agent"
    );
    assert_eq!(child_depth_of(&empty), 2);

    let sub = a.read_spawn(r#"{"agent_id":"a06ce40d"}"#).unwrap();
    assert_eq!(child_depth_of(&sub), 2);
}

/// The event decoder must tolerate fields it has never seen.
///
/// Mutation: add `#[serde(deny_unknown_fields)]`.
/// Rationale: the hook contract belongs to a third party and gains fields
/// between releases. Strict decoding turns "the vendor added a field" into "the
/// user's agent will not start" — a failure we would have manufactured.
#[test]
fn unknown_event_fields_are_tolerated() {
    // Retargeted at the adapter for the same reason as the test above. The
    // property is unchanged: a field the vendor added must not stop anybody's
    // sub-agents.
    let raw = r#"{"tool_name":"Agent","brand_new_field":{"x":1},"permission_mode":"bypassPermissions",
                  "tool_input":{"subagent_type":"Explore","run_in_background":false,"future":"x"}}"#;
    let req = crate::mcp_harness::default_adapter()
        .read_spawn(raw)
        .expect("a new vendor field must not break decoding");
    assert_eq!(req.agent_type, "Explore");
}

// ---------------------------------------------------------------------------
// R66 / I37 — the reply cannot rewrite the parent's task
// ---------------------------------------------------------------------------

/// Mutation: add an `updated_input` field to `HookSpecific`.
///
/// Rationale: measured — extra fields never reach the child, so the only thing
/// modifiable is the task prompt, which is prompt injection; and the parent
/// agent noticed when the probe did it.
///
/// 🔴 THIS FENCE WAS VACUOUS TWICE BEFORE IT WORKED, and the second time is the
/// interesting one.
///
/// v1 scanned the keys of a serialised reply. A field added the way anybody
/// would add it — `skip_serializing_if = "Option::is_none"`, left `None` — is
/// ABSENT from that JSON, so the mutation produced identical output. Same trap
/// the Go side hit; there it was solved with reflection over the type.
///
/// v2 could not do that: Rust has no runtime reflection. The drill still went
/// red, but only because the mutation no longer COMPILED (a missing field at the
/// construction site) — which proves the compiler works, not that this test
/// does. A drill that is red for the wrong reason is the same class of lie as
/// one that is green for the wrong reason.
///
/// v3 asserts on the SOURCE TEXT of the struct, which is the nearest thing Rust
/// has to inspecting the shape, and is the same technique the Go side uses for
/// "this file imports no network package". `include_str!` binds it at compile
/// time, so the fence cannot drift from the file it claims to guard.
#[test]
fn the_reply_has_nowhere_to_put_a_rewritten_input() {
    const SRC: &str = include_str!("../mcp_guard.rs");

    let body = SRC
        .split_once("pub struct HookSpecific {")
        .expect("HookSpecific must exist — this fence is reading the wrong file")
        .1
        .split_once("\n}")
        .expect("HookSpecific must be closed")
        .0;
    assert!(
        !body.is_empty(),
        "read an empty struct body — the fence would pass vacuously"
    );
    for line in body.lines() {
        let l = line.trim();
        if l.starts_with("//") {
            continue;
        }
        assert!(
            !l.to_lowercase().contains("input"),
            "HookSpecific declares `{l}`. The delegation gate must be \
             STRUCTURALLY unable to rewrite the parent's task (R66/I37): a field \
             that only fails a runtime check is one line away from working."
        );
    }

    // Second layer, on the wire this time: the three keys are a third-party
    // contract, and an extra one would be a protocol extension we never agreed.
    let deny = render_reply(&Decision {
        verdict: "deny".into(),
        reason: "AiKey refused this delegation".into(),
        ..Default::default()
    });
    let v = serde_json::to_value(&deny).unwrap();
    let inner = v["hookSpecificOutput"].as_object().expect("object");
    let keys: Vec<&str> = inner.keys().map(|s| s.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "hookEventName",
            "permissionDecision",
            "permissionDecisionReason"
        ],
        "the reply's wire shape changed"
    );
}

/// 🔴 A narrowed delegation still ALLOWS at the harness.
///
/// Mutation: render narrow as deny.
/// Rationale: narrowing is not an interruption — the child starts with fewer
/// toolsets. Surfacing it as a refusal trains the developer to read the gate as
/// breakage, and the narrowing is already recorded for the administrator.
#[test]
fn narrow_allows_and_deny_carries_its_reason() {
    let narrow = render_reply(&Decision {
        verdict: "narrow".into(),
        ..Default::default()
    });
    assert_eq!(narrow.specific.permission_decision, "allow");
    assert!(narrow.specific.permission_decision_reason.is_none());

    let allow = render_reply(&Decision {
        verdict: "allow".into(),
        ..Default::default()
    });
    assert_eq!(allow.specific.permission_decision, "allow");

    let deny = render_reply(&Decision {
        verdict: "deny".into(),
        reason: "AiKey refused this delegation under tier \"read-only\"".into(),
        ..Default::default()
    });
    assert_eq!(deny.specific.permission_decision, "deny");
    assert_eq!(
        deny.specific.permission_decision_reason.as_deref(),
        Some("AiKey refused this delegation under tier \"read-only\""),
        "the gateway's sentence must reach the developer verbatim — it is the only place the fix is stated"
    );
}

/// The reply's event name must match the hook we register for, or the harness
/// ignores our decision.
#[test]
fn the_reply_names_the_event_we_registered_for() {
    let r = render_reply(&Decision {
        verdict: "deny".into(),
        ..Default::default()
    });
    let hook_event = crate::mcp_harness::default_adapter().hook_event();
    assert_eq!(r.specific.hook_event_name, hook_event);
    assert_eq!(hook_event, "PreToolUse");
}

/// The hook command we register must be the one the binary actually answers.
///
/// Mutation: rename the subcommand on one side only.
/// Rationale: a rename that misses one side leaves an installed hook invoking a
/// subcommand that does not exist — the harness gets a non-zero exit on every
/// spawn, which is the loudest possible version of this failure but still one
/// nobody tests for.
#[test]
fn the_registered_command_matches_the_marker_we_recognise() {
    let cmd = hook_command();
    assert!(
        cmd.contains(OWNED_MARKER),
        "we must be able to recognise our own entry"
    );
    assert!(
        cmd.contains("_mcp-guard-hook"),
        "the hook entry is the top-level hidden subcommand"
    );
    let group = our_group();
    assert!(is_ours(&group), "our own group must be recognised as ours");
    assert!(
        !is_ours(&third_party_group()),
        "a third party's group must not be claimed as ours"
    );
}

// ---------------------------------------------------------------------------
// A newer CLI against an older gateway (observed live, 2026-09-03)
// ---------------------------------------------------------------------------

/// Mutation: print the bare status code instead of classifying the body shape.
///
/// Rationale: this is not hypothetical. Running `aikey mcp guard status` against
/// a gateway that predates the delegation route produced `status code 401` —
/// because the unknown path fell through to the proxy's DATA plane, which wanted
/// a virtual key. The user is then hunting a credential problem they do not
/// have, while every spawn is being allowed.
///
/// The shape of `error` is the tell: admin routes answer with a STRING, the data
/// plane with an OBJECT.
#[test]
fn an_old_gateway_is_named_as_an_old_gateway() {
    // Exactly the body observed from the running proxy.
    let data_plane = serde_json::json!({
        "error": {"code": "TOKEN_MISSING", "message": "AiKey: Missing virtual key.", "type": "authentication_error"},
        "origin": "local-proxy.TOKEN_MISSING"
    })
    .to_string();
    let msg = explain_body(401, &data_plane);
    assert!(
        msg.contains("older than this CLI"),
        "a 401 whose body is the DATA PLANE shape means the route is missing, not that \
         the user lacks a credential. got: {msg}"
    );
    assert!(
        msg.contains("aikey proxy restart"),
        "the message must carry the next step, not just the diagnosis. got: {msg}"
    );

    // An admin route answering with its own sentence must be passed through, not
    // relabelled as a version problem.
    let admin = serde_json::json!({"error": "this node follows a control plane"}).to_string();
    let msg2 = explain_body(503, &admin);
    assert!(
        msg2.contains("this node follows a control plane"),
        "the gateway's own sentence must survive — replacing it with ours sends the \
         user to look for the wrong fault. got: {msg2}"
    );
    assert!(!msg2.contains("older than this CLI"));
}

// ---------------------------------------------------------------------------
// Cross-language contract with the gateway (Go side:
// aikey-proxy/internal/admin/mcp_delegation_test.go)
// ---------------------------------------------------------------------------

/// Mutation: rename the route, a request field, or a verdict string on ONE side.
///
/// Rationale: this repo has been bitten twice by exactly this — the `mcp.json`
/// field set and the health document. Both times one side kept working while the
/// other silently read nothing, and every test on each side stayed green. A
/// contract that spans a language boundary needs a fence on both ends or it has
/// none.
#[test]
fn the_gateway_contract_is_the_one_the_proxy_serves() {
    assert_eq!(DELEGATION_ROUTE, "/admin/mcp/delegation");
    assert_eq!(FIELD_AGENT_TYPE, "agent_type");
    assert_eq!(FIELD_DEPTH, "depth");

    // The response fields we read by name. A rename on the Go side would leave
    // these at their serde defaults — "" and false — which is a silent ALLOW.
    let d: Decision = serde_json::from_str(
        r#"{"verdict":"deny","tier":"ro","reason":"AiKey refused","stale":true}"#,
    )
    .expect("the gateway's Decision must decode here");
    assert_eq!(d.verdict, "deny");
    assert_eq!(d.tier, "ro");
    assert_eq!(d.reason, "AiKey refused");
    assert!(d.stale);

    // 🔴 The verdict STRING is contract too: `render_reply` compares against the
    // literal "deny". If Go renamed it, every refusal would become an allow and
    // nothing would fail — the loudest possible bug with the quietest symptom.
    assert_eq!(
        render_reply(&d).specific.permission_decision,
        "deny",
        "the verdict literal drifted; a renamed verdict turns refusals into allows"
    );
}

// ---------------------------------------------------------------------------
// 15.26 — the preview is READ-ONLY and does not decide anything
// ---------------------------------------------------------------------------

/// The source of the module under test, read at COMPILE time.
///
/// 🔴 `include_str!` rather than a runtime path: a path that drifts turns these
/// assertions into a test that reads the wrong file and passes, which is the
/// vacuous-fence shape this repo keeps re-discovering.
const GUARD_SRC: &str = include_str!("../mcp_guard.rs");

/// Just the body of `cmd_preview`, comments stripped.
///
/// 🔴 Comments are removed because this function's own doc block EXPLAINS the
/// bans below (it names `settings.json` and the word "advisory"). Scanning the
/// raw text would let a fence pass on its own rationale, and the only way to
/// green it would be to delete the sentence saying why the rule exists.
fn preview_body() -> String {
    let start = GUARD_SRC
        .find("pub fn cmd_preview(")
        .expect("cmd_preview not found — this fence is reading the wrong file");
    let rest = &GUARD_SRC[start..];
    let end = rest
        .find("\nfn say(")
        .expect("could not find the end of cmd_preview");
    rest[..end]
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Mutation: make `cmd_preview` write the rendered whitelist to a file.
///
/// Rationale: 15.26's write half is deliberately NOT built. Those are the user's
/// agent definitions, and a `tools:` line we put there is advisory — it looks
/// like a whitelist and enforces nothing, which is the §0.7 failure with nothing
/// to stop somebody selling it as a gate. The preview exists so the information
/// is available without that risk; the moment it writes, the risk is back.
#[test]
fn the_preview_writes_nothing() {
    let body = preview_body();
    // 🔴 These must name the write door as it is TODAY. `write_settings_atomic`
    // and `backup_settings` were RETIRED on 2026-09-05 (settings.json moved
    // behind `third_party_config`), and a list that bans names which no longer
    // exist bans nothing — the fence would have gone vacuous while still
    // reading green. See tests/third_party_write_guard_fence.rs.
    for banned in [
        "tp::apply",
        "tp::commit",
        "fs::write",
        "File::create",
        "OpenOptions",
        "backup_versioned",
    ] {
        assert!(
            !body.contains(banned),
            "cmd_preview calls `{banned}`. The preview is read-only on purpose: 15.26's write \
             half would put an ADVISORY line into the user's own agent definitions, which looks \
             like a whitelist and enforces nothing."
        );
    }
}

/// Mutation: compute the verdict locally instead of asking the gateway.
///
/// Rationale: a preview that disagrees with the gate is worse than no preview.
/// This is the CLI-side twin of `TestConsolePreviewAndHookShareTheEvaluator`.
#[test]
fn the_preview_asks_the_gateway_rather_than_deciding() {
    let body = preview_body();
    assert!(
        body.contains("ask_gateway(agent_type, depth)"),
        "cmd_preview no longer asks the gateway. The tiers are evaluated in ONE place \
         (aikey-proxy/internal/mcp/delegation.go); a second implementation here would \
         eventually tell the user something the gate will not do."
    );
    // 🔴 It may RENDER the verdict, but it must not DERIVE one. The three
    // literals appear in the match that colours the output; a derivation would
    // need a comparison against the tier list, which needs the tiers — and the
    // preview never fetches them.
    for banned in ["tiers", "toolset_slugs", "max_depth"] {
        assert!(
            !body.contains(banned),
            "cmd_preview reads `{banned}`; that is the raw material of a second evaluator."
        );
    }
}

/// Mutation: report "unknown" when the gateway does not answer.
///
/// Rationale: the gate FAILS OPEN (D-29). A preview that says "unknown" there
/// describes a stricter product than the one that ships, and an administrator
/// reading it would believe spawns are being held when they are being allowed.
#[test]
fn an_unreachable_gateway_previews_as_allowed_not_as_unknown() {
    let body = preview_body();
    assert!(
        body.contains(r#""verdict": "allow""#),
        "the gateway-unreachable branch no longer previews as `allow`. The gate fails open \
         there, so anything else describes a product we do not ship."
    );
    assert!(
        body.contains("ALLOWED"),
        "the human-readable unreachable branch must say the spawn is ALLOWED"
    );
}

/// Mutation: drop the sentence that calls the `tools:` line advisory.
///
/// Rationale: this is the same class as the §0.7 banner on the console page —
/// the limitation is the whole reason the write half was not built, and a later
/// tidy-up that removes it leaves a feature that reads as a whitelist.
#[test]
fn the_whitelist_is_labelled_advisory_where_the_user_can_see_it() {
    // 🔴 Scoped to the HUMAN-READABLE branch, not to the whole function.
    //
    // The first version scanned the entire body for the word "advisory" and was
    // VACUOUS: the word also appears in the JSON key
    // `harness_tools_line_is_advisory`, so deleting the sentence the user
    // actually reads left the fence green. The drill caught it. The property is
    // "the user is told", so the assertion has to look at what the user is
    // shown — everything after the JSON early-return.
    let body = preview_body();
    let human = &body[body
        .find("let verdict = match")
        .expect("the human-readable branch moved; this fence is reading the wrong region")..];

    assert!(
        human.contains("advisory"),
        "the human-readable output no longer tells the user the `tools:` line is advisory. \
         Something that looks like a whitelist and enforces nothing is worse than nothing, \
         because it gets relied on."
    );
    assert!(
        human.contains("mcp__aikey__"),
        "the output no longer states how the harness actually names AiKey's tools; without it \
         the reader cannot tell why a per-toolset whitelist is not expressible"
    );
}

// ─── the gate writes through the ONE door (Phase 3b, 2026-09-09) ─────────────
// spec: R-third-party-config-guard-2.S1 产品代码不许有第二扇写门

use crate::commands_account::tp_invalid_file_suite::Sandbox;
use crate::commands_account::third_party_config as tp;

// ── the MCP delegation gate shares this same file (Phase 3b, 2026-09-09) ──
// spec: R-third-party-config-guard-2.S1 — one write door.
//
// 🔴 Written when `aikey mcp guard` was ported off `commands_statusline`'s
// retired `read_settings` / `backup_settings` / `write_settings_atomic`.
// The port is only half done if the hook lands but the guarantees the door
// exists to provide do not: a versioned backup, never the retired
// single-slot name, a third party's entry preserved, and an unparseable
// file left alone. `TP_COMMITS` is the runtime witness that it really is
// the door and not a second one that happens to produce the same bytes.

#[test]
fn mcp_guard_writes_through_the_one_door_and_leaves_the_statusline_alone() {
    let event = crate::mcp_harness::default_adapter().hook_event();
    let pre = format!(
        "{{\n  \"statusLine\": {{ \"type\": \"command\", \"command\": \"/usr/local/bin/starship status\" }},\n  \"hooks\": {{ \"{event}\": [ {{ \"matcher\": \"Bash\", \"hooks\": [ {{ \"type\": \"command\", \"command\": \"/opt/other/tool\" }} ] }} ] }}\n}}"
    );
    let sb = Sandbox::with_claude(Some(&pre));
    let commits = tp::TP_COMMITS.load(std::sync::atomic::Ordering::SeqCst);

    cmd_install(true).unwrap();

    assert_eq!(
        tp::TP_COMMITS.load(std::sync::atomic::Ordering::SeqCst),
        commits + 1,
        "install went through third_party_config::commit exactly once"
    );
    assert_eq!(tp::list_backups(&sb.cfg).len(), 1, "one versioned backup");
    assert!(
        !sb.cfg.with_file_name("settings.aikey_backup.json").exists(),
        "the retired single-slot backup name is never written again"
    );

    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sb.cfg).unwrap()).unwrap();
    let list = doc["hooks"][event].as_array().unwrap();
    assert_eq!(list.len(), 2, "the third party's entry survived the merge");
    assert!(list
        .iter()
        .any(|g| g["hooks"][0]["command"] == "/opt/other/tool"));
    assert!(list.iter().any(|g| g["hooks"][0]["command"]
        == serde_json::Value::String(hook_command())));
    assert_eq!(
        doc["statusLine"]["command"], "/usr/local/bin/starship status",
        "the status line belongs to another feature and is not ours to touch"
    );

    // Idempotent: a second install is a byte no-op, so it must not commit.
    cmd_install(true).unwrap();
    assert_eq!(
        tp::TP_COMMITS.load(std::sync::atomic::Ordering::SeqCst),
        commits + 1
    );

    cmd_uninstall(true).unwrap();
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sb.cfg).unwrap()).unwrap();
    let list = doc["hooks"][event].as_array().unwrap();
    assert_eq!(list.len(), 1, "uninstall took ours and only ours");
    assert_eq!(list[0]["hooks"][0]["command"], "/opt/other/tool");
    assert_eq!(doc["statusLine"]["command"], "/usr/local/bin/starship status");
}

#[test]
fn mcp_guard_refuses_an_unparseable_settings_file_without_touching_it() {
    let sb = Sandbox::with_claude(Some("{ \"hooks\": { "));
    let before = std::fs::read(&sb.cfg).unwrap();
    let commits = tp::TP_COMMITS.load(std::sync::atomic::Ordering::SeqCst);

    cmd_install(true).unwrap();
    cmd_uninstall(true).unwrap();

    assert_eq!(
        std::fs::read(&sb.cfg).unwrap(),
        before,
        "an unparseable settings.json is diagnosed, never rewritten"
    );
    assert_eq!(
        tp::TP_COMMITS.load(std::sync::atomic::Ordering::SeqCst),
        commits,
        "a refusal must not reach the write door"
    );
    assert!(tp::list_backups(&sb.cfg).is_empty());
}
