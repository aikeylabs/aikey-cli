//! `aikey mcp guard` — install, inspect and remove the delegation boundary
//! hook (P15 · tasks 15.5 / 15.6).
//!
//! # What this is
//!
//! Claude Code raises a hook before it creates a sub-agent. This module puts
//! `aikey` on that hook, so the local gateway gets to say allow / narrow / deny
//! before a parent agent spawns a child. The decision itself is NOT here — see
//! "the shell holds no policy" below.
//!
//! # 🔴 The shell holds no policy
//!
//! Everything this module does on the hook path is: decode the harness event,
//! ask the running gateway, encode the answer back. The tier rules live in one
//! place (`aikey-proxy/internal/mcp/delegation.go`) and the console preview and
//! this hook reach the same evaluator. That is the repo's
//! `internal-command-reuses-public-core` rule applied to a hook: a second copy
//! of the rules written in Rust would drift, and the user would have no way to
//! tell which of the two refused them.
//!
//! # 🔴 We are a guest in `settings.json`
//!
//! That file is the user's, and other tools write to it — `aikey statusline`
//! among them. So:
//!   - install MERGES, never replaces; a third party's PreToolUse entry survives
//!   - install backs up first, and writes atomically
//!   - uninstall removes OUR entry only, and never touches `statusLine`
//!
//! All of that machinery already exists, and this module reuses it rather than
//! growing a second copy (technical design §8.6). Concretely: every read and
//! every write below goes through `third_party_config` — the ONE write door
//! (spec: R-third-party-config-guard-2.S1 产品代码不许有第二扇写门). This module
//! contributes a `Surface`, not a writer.
//!
//! 🔴 It used to call `commands_statusline`'s own `read_settings` /
//! `backup_settings` / `write_settings_atomic` instead. Those were RETIRED on
//! 2026-09-05 when Claude's settings.json moved behind the guard, and
//! `tests/third_party_write_guard_fence.rs` lists them in `GONE_FOR_GOOD`.
//! 🚫 Do not reintroduce them here to save a few lines: a second write door is
//! the exact defect that fence was written for.
//!
//! # Measured facts this module depends on (2026-09-03, Claude Code 2.1.247)
//!
//!   - `matcher: "Agent|Task"` fires for the spawn tool and NOT for `Bash`.
//!   - The spawn tool is reported as `Agent` in the hook event and as `Task` in
//!     the run summary — so both names must be recognised.
//!   - A main-agent event has NO `agent_id` key at all; a sub-agent event has one.
//!
//! Evidence: `openspec/changes/aikey-mcp-gateway/evidence/15.0-*.jsonl`.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use crate::commands_account::third_party_config as tp;
use crate::commands_statusline::{aikey_bin_quoted, claude_settings_path, parse_claude_settings};

// 🔴 The hook event name and the matcher are the HARNESS's, not ours, so they
// come from the adapter (P15 · K4 · task 15.23) rather than from constants here.
// Two copies of "what Claude Code calls its spawn tool" is exactly the drift the
// registry exists to prevent — and this file used to be the second copy.
// 🚫 Do not re-introduce a literal here; use `harness()`.
fn harness() -> &'static dyn crate::mcp_harness::HarnessAdapter {
    crate::mcp_harness::default_adapter()
}

/// Substring that identifies a hook entry as ours.
///
/// 🔴 Matched on the COMMAND, the way the status-line installer identifies its
/// own `statusLine`. The binary path varies per machine, so the stable part is
/// the subcommand name.
const OWNED_MARKER: &str = "mcp-guard-hook";

/// Env escape hatch (D-28: default on, but the user can turn it off).
const DISABLE_ENV: &str = "AIKEY_NO_MCP_GUARD";

/// The gateway route we ask, and the two request fields we send.
///
/// 🔴 Constants with a fence on BOTH sides of the language boundary. This repo
/// has been bitten twice by a CLI↔proxy shape drifting silently — the `mcp.json`
/// field set, then the health document — and both times one side kept working
/// while the other quietly read nothing, with every test on each side green.
/// The Go half is `TestDelegationWireMatchesTheCLIContract`.
const DELEGATION_ROUTE: &str = "/admin/mcp/delegation";
const FIELD_AGENT_TYPE: &str = "agent_type";
const FIELD_DEPTH: &str = "depth";

// ---------------------------------------------------------------------------
// The harness wire
// ---------------------------------------------------------------------------

// 🔴 The event type used to live here. It moved to `mcp_harness::ClaudeCode`
// (P15 · K4) because it is a description of ONE HARNESS's payload, and a second
// copy of "what Claude Code's hook event looks like" is exactly the drift the
// adapter layer exists to remove. 🚫 Do not re-add a local event struct; call
// `harness().read_spawn(raw)`.

/// What we write back to the harness.
///
/// 🔴 THERE IS NO `updatedInput` FIELD, AND THAT IS THE FEATURE (R66 / I37).
/// The gate must not be able to rewrite the parent's task. Enforcing that with a
/// runtime check would leave the capability one line away; leaving the field out
/// of the type makes the refusal structural — serde cannot emit what the struct
/// cannot hold.
///
/// Measured justification for the ban: extra fields never reach the child at all
/// (it is handed only `prompt`), so the only thing modifiable is the task prompt
/// — which is prompt injection — and when the probe did it, the parent agent
/// noticed and said so in its answer.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HookReply {
    #[serde(rename = "hookSpecificOutput")]
    pub specific: HookSpecific,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HookSpecific {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
}

/// The gateway's answer. Mirrors `mcpwire.Decision`.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Decision {
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub stale: bool,
}

pub fn is_delegation_tool(tool: &str) -> bool {
    harness().is_spawn_tool(tool)
}

/// Where the CHILD would sit, computed by US.
///
/// 🔴 NEVER read from the event. A client that reports its own depth reports 0
/// forever and walks past every limit — the same trust rule that keeps
/// `app_slug` and `session_id` out of authorisation. The adapter deliberately
/// reports the FACT ("this came from the top-level agent") and not the number,
/// so a harness that one day starts sending a depth field cannot have it
/// believed by accident.
///
/// The human is 0 and the main agent is 1, so a child of the main agent is 1 and
/// a child of a sub-agent is 2. Claude Code does not allow the second case today
/// (measured: `spawned_by_subagents: 0`), but the arithmetic does not depend on
/// that staying true.
pub fn child_depth_of(req: &crate::mcp_harness::SpawnRequest) -> i64 {
    if req.is_main_actor {
        1
    } else {
        2
    }
}

/// Map a gateway decision onto the harness's expected reply.
///
/// 🔴 `narrow` renders as ALLOW. Narrowing is not an interruption — the child
/// still starts, it just carries fewer toolsets. Showing it to the developer as
/// a refusal would train them to read the gate as breakage; the narrowing is
/// recorded as an event for the administrator instead.
pub fn render_reply(d: &Decision) -> HookReply {
    let deny = d.verdict == "deny";
    HookReply {
        specific: HookSpecific {
            hook_event_name: harness().hook_event().to_string(),
            permission_decision: if deny { "deny" } else { "allow" }.to_string(),
            permission_decision_reason: if deny && !d.reason.is_empty() {
                Some(d.reason.clone())
            } else {
                None
            },
        },
    }
}

// ---------------------------------------------------------------------------
// The hook entry point (task 15.6)
// ---------------------------------------------------------------------------

/// `aikey _internal mcp-guard-hook <event>` — reads the harness event on stdin,
/// writes the reply on stdout.
///
/// 🔴 FAIL-OPEN on every path where we cannot get an answer, and say so on
/// stderr. D-29 ratified that direction explicitly rather than arriving at it by
/// default: spawning is on the path a developer walks every time they ask their
/// agent to do anything, and a gate that blocks them when the gateway is
/// restarting gets uninstalled — leaving the organisation with no control AND no
/// signal that it lost one.
///
/// ⚠️ **Honest limitation**: on a zero exit the harness does not surface this
/// stderr to the user, so the durable record of a fail-open is the gateway's own
/// `proxy.mcp.delegation_policy_stale` event, not this line. When the gateway is
/// unreachable there is no event either — which is precisely why `aikey mcp
/// guard status` reports whether the gateway is answering.
pub fn cmd_hook() -> Result<(), String> {
    let mut raw = String::new();
    if io::stdin().read_to_string(&mut raw).is_err() {
        return allow_out("could not read the hook event from stdin");
    }

    // 🔴 The tool check reads the RAW event, before the adapter, because "is
    // this even the spawn hop" must stay answerable for a payload whose shape we
    // do not otherwise understand. Anything else is not our business and must
    // not be turned into a decision.
    let tool = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("tool_name").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_default();
    if !tool.is_empty() && !is_delegation_tool(&tool) {
        // Not the spawn hop. Stay neutral — an empty object adds no decision.
        return print_neutral();
    }

    // 🔴 A payload we cannot parse is ALLOWED, not refused. Any change the
    // vendor makes to the event shape would otherwise stop every sub-agent on
    // every machine at once.
    let req = match harness().read_spawn(&raw) {
        Ok(r) => r,
        Err(e) => return allow_out(&e),
    };
    if tool.is_empty() && !req.agent_type.is_empty() {
        // Defensive: a harness that stopped sending `tool_name` but still names
        // a sub-agent type is still the spawn hop. 🚫 Falling through to
        // print_neutral() there would silently stop gating every spawn.
        eprintln!("[aikey] the harness event carried no tool_name; treating it as the spawn hop because it names a sub-agent type");
    }

    // 🔴 Defaulted fields are never silent (15.25): an empty agent type matches
    // no tier, and "no tier matched" and "the harness stopped telling us the
    // type" are the same allow with completely different fixes.
    for w in &req.warnings {
        eprintln!("[aikey] {w}");
    }

    let decision = match ask_gateway(&req.agent_type, child_depth_of(&req)) {
        Ok(d) => d,
        Err(e) => return allow_out(&format!("gateway did not answer: {e}")),
    };
    if decision.stale {
        eprintln!(
            "[aikey] delegation allowed on a stale policy — the gateway could not refresh it ({})",
            if decision.tier.is_empty() {
                "no tier matched"
            } else {
                &decision.tier
            }
        );
    }
    print_reply(&render_reply(&decision))
}

fn ask_gateway(agent_type: &str, depth: i64) -> Result<Decision, String> {
    let url = format!(
        "http://127.0.0.1:{}{DELEGATION_ROUTE}",
        crate::commands_proxy::proxy_port()
    );
    // 🔴 A SHORT timeout. This sits between the model deciding to delegate and
    // the sub-agent starting; a slow gate is a slow product. Failing open after
    // two seconds is better than a developer watching a spinner.
    match ureq::post(&url)
        .timeout(std::time::Duration::from_secs(2))
        .send_json(serde_json::json!({FIELD_AGENT_TYPE: agent_type, FIELD_DEPTH: depth}))
    {
        Ok(resp) => {
            let body = resp.into_string().map_err(|e| format!("{e}"))?;
            serde_json::from_str::<Decision>(&body).map_err(|e| format!("{e}"))
        }
        Err(ureq::Error::Status(code, resp)) => Err(explain_status(code, resp)),
        Err(e) => Err(format!("{e}")),
    }
}

/// Turn a status code from the gateway into a sentence with a next step.
///
/// 🔴 This exists because of a real observation, not a hypothetical. A CLI that
/// is newer than the RUNNING gateway asks for a route that binary does not have;
/// the request falls through to the proxy's DATA plane, which answers 401
/// `TOKEN_MISSING` because it wanted a virtual key. So the user upgrades, the
/// hook installs fine, and `status` reports `status code 401` — a message that
/// sends them hunting for a credential problem they do not have.
///
/// The give-away is the SHAPE of the body: admin routes answer
/// `{"error":"<sentence>"}`, the data plane answers `{"error":{"code":...}}`.
/// The same distinction is already documented in `commands_mcp::admin_status_error`.
///
/// ⚠️ Why this matters more than a nicer message: while the gateway is old,
/// EVERY spawn is allowed. That is the correct fail-open behaviour, but a user
/// who cannot tell why will conclude the gate works.
fn explain_status(code: u16, resp: ureq::Response) -> String {
    explain_body(code, &resp.into_string().unwrap_or_default())
}

/// The pure half of [`explain_status`], split out because `ureq::Response` cannot
/// be constructed in a test — and a classification rule that no test can reach
/// is a rule that will be wrong the next time the wire changes.
fn explain_body(code: u16, body: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let data_plane_shape = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .is_some_and(|e| e.is_object());

    if data_plane_shape {
        return format!(
            "the running gateway does not have the delegation route (HTTP {code}) — \
             it is older than this CLI. Next: restart it with `aikey proxy restart`, \
             then re-run `aikey mcp guard status`."
        );
    }
    let msg = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string();
    if msg.is_empty() {
        format!("gateway answered HTTP {code}")
    } else {
        format!("{msg} (HTTP {code})")
    }
}

fn allow_out(why: &str) -> Result<(), String> {
    eprintln!("[aikey] delegation gate failed open: {why}");
    print_neutral()
}

fn print_neutral() -> Result<(), String> {
    let mut out = io::stdout();
    out.write_all(b"{}").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn print_reply(r: &HookReply) -> Result<(), String> {
    let body = serde_json::to_vec(r).map_err(|e| e.to_string())?;
    let mut out = io::stdout();
    out.write_all(&body).map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// install / status / uninstall (task 15.5)
// ---------------------------------------------------------------------------

/// The command string we register.
///
/// 🔴 A TOP-LEVEL hidden command, not a member of the `_internal` group. That
/// group requires `--stdin-json` on every member, and the harness invokes what
/// we register with no arguments at all — so a member there would fail to parse
/// on the very first spawn. `_hook-hash` and `_refresh-active-env` are the
/// existing precedent for a hidden command that is not part of the local-server
/// IPC envelope.
pub fn hook_command() -> String {
    format!("{} _{OWNED_MARKER}", aikey_bin_quoted())
}

fn is_ours(group: &serde_json::Value) -> bool {
    group
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|entries| {
            entries.iter().any(|e| {
                e.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c.contains(OWNED_MARKER))
            })
        })
        .unwrap_or(false)
}

fn our_group() -> serde_json::Value {
    serde_json::json!({
        "matcher": harness().matcher(),
        "hooks": [{"type": "command", "command": hook_command()}],
    })
}

/// What `apply_install` did.
#[derive(Debug, PartialEq, Eq)]
pub enum GuardAction {
    Installed,
    /// Already present with the same command — nothing written.
    AlreadyCurrent,
    /// Present but pointing at a different path (the binary moved).
    Refreshed,
    /// 🔴 `hooks.PreToolUse` exists but is not an array. We do not know what it
    /// is, so we do not touch it.
    RefusedForeignShape,
}

/// Merge our hook into a settings document.
///
/// 🔴 MERGE, never replace. Third-party `PreToolUse` groups are preserved
/// untouched — `settings.json` is the user's file and other tools live in it.
/// Replacing the array is the one mutation that would silently delete somebody
/// else's hook, which is why it has its own fence.
pub fn apply_install(settings: &mut serde_json::Value) -> GuardAction {
    if !settings.is_object() {
        *settings = serde_json::json!({});
    }
    let root = settings.as_object_mut().expect("object");

    let hooks = root.entry("hooks").or_insert_with(|| serde_json::json!({}));
    if !hooks.is_object() {
        return GuardAction::RefusedForeignShape;
    }
    let hooks = hooks.as_object_mut().expect("object");

    let list = hooks
        .entry(harness().hook_event())
        .or_insert_with(|| serde_json::json!([]));
    let Some(list) = list.as_array_mut() else {
        return GuardAction::RefusedForeignShape;
    };

    let want = our_group();
    let existing = list.iter().position(is_ours);
    match existing {
        Some(i) if list[i] == want => GuardAction::AlreadyCurrent,
        Some(i) => {
            list[i] = want;
            GuardAction::Refreshed
        }
        None => {
            list.push(want);
            GuardAction::Installed
        }
    }
}

/// Remove our hook. Returns whether anything changed.
///
/// 🔴 SURGICAL. It removes our group and nothing else — in particular it never
/// touches `statusLine`, which `aikey statusline` owns. The two features share
/// this file and one uninstalling the other would be a silent regression that no
/// test of either feature alone would catch.
///
/// 🔴 It also prunes containers it emptied, so an install/uninstall round trip
/// leaves no `"hooks": {"PreToolUse": []}` residue behind. That residue is what
/// makes "byte-for-byte restored" false.
pub fn apply_uninstall(settings: &mut serde_json::Value) -> bool {
    let Some(root) = settings.as_object_mut() else {
        return false;
    };
    let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return false;
    };
    let Some(list) = hooks.get_mut(harness().hook_event()).and_then(|l| l.as_array_mut()) else {
        return false;
    };
    let before = list.len();
    list.retain(|g| !is_ours(g));
    if list.len() == before {
        return false;
    }
    if list.is_empty() {
        hooks.remove(harness().hook_event());
    }
    if hooks.is_empty() {
        root.remove("hooks");
    }
    true
}

// ─────────────────────────── the settings.json surface ───────────────────────

/// The delegation hook's face to the one write door.
///
/// 🔴 It reports `SurfaceId::Claude` — the SAME id the status line reports —
/// because that id names the TOOL whose file is being written (Claude Code's
/// `settings.json`), not the concern doing the writing. Two concerns share this
/// one file. A third id invented for the second concern would grow the
/// serialized vocabulary that `SurfaceOutcome`, `status --json` and
/// `hook repair --json` all carry, and would tell a reader the guard had
/// touched some other file.
pub struct McpGuardSurface;

/// Where our hook stands in a parsed settings document.
///
/// 🔴 `Foreign` here means a SHAPE we cannot read (`hooks` is not an object,
/// `hooks.<event>` is not an array) — NOT "somebody else holds the slot".
/// `PreToolUse` is an additive list: a third party's entry there is normal and
/// must survive. The unreadable shape is the only case we refuse on, and it is
/// the same case `apply_install` reported as `RefusedForeignShape`.
fn guard_state(doc: &serde_json::Value) -> tp::TpConfigState {
    let Some(hooks) = doc.get("hooks") else {
        return tp::TpConfigState::PresentNoAikey;
    };
    let Some(hooks) = hooks.as_object() else {
        return tp::TpConfigState::Foreign {
            owner: "hooks is not an object".into(),
        };
    };
    let event = harness().hook_event();
    let Some(list) = hooks.get(event) else {
        return tp::TpConfigState::PresentNoAikey;
    };
    let Some(list) = list.as_array() else {
        return tp::TpConfigState::Foreign {
            owner: format!("hooks.{event} is not an array"),
        };
    };
    match list.iter().find(|g| is_ours(g)) {
        // Present, and identical to what we would write now.
        Some(g) if *g == our_group() => tp::TpConfigState::OursActive,
        // Present but stale — typically the binary moved. `OurResidue` still
        // answers has_ours(), which is what lets uninstall strip it and what
        // makes `status` say "registered" for a gate that really is registered.
        Some(_) => tp::TpConfigState::OurResidue,
        None => tp::TpConfigState::PresentNoAikey,
    }
}

impl tp::Surface for McpGuardSurface {
    type Doc = serde_json::Value;
    /// Install takes no parameters: the hook command is derived from THIS
    /// binary's own path, never chosen by the caller.
    type Input = ();

    const ID: tp::SurfaceId = tp::SurfaceId::Claude;
    const FORMAT: tp::Format = tp::Format::Json;
    // Never conjure ~/.claude on a machine that has never run Claude Code —
    // the same rule the status-line installer follows, for the same reason.
    const CREATE: tp::CreatePolicy = tp::CreatePolicy::RequireParentDir;
    // See `guard_state`: there is no exclusive slot here, so there is nothing
    // to claim and no consent to ask for.
    const FOREIGN: tp::ForeignPolicy = tp::ForeignPolicy::NotApplicable;
    // JSON: there is no line-level "ours" to strip; repair is --from-backup.
    const OWNED_GRAMMAR: Option<&'static tp::OwnedTomlGrammar> = None;

    fn path(&self) -> PathBuf {
        claude_settings_path().unwrap_or_else(|| PathBuf::from("settings.json"))
    }
    fn load(&self, text: &str) -> Result<Self::Doc, tp::ParseFailure> {
        // 🔴 The SAME parse the status line uses. Two surfaces disagreeing about
        // what "parses" means would let one refuse a file the other just wrote.
        parse_claude_settings(text)
    }
    fn empty_doc(&self) -> Self::Doc {
        serde_json::json!({})
    }
    fn detect(&self, doc: &Self::Doc) -> tp::Detection {
        tp::Detection::of(guard_state(doc))
    }
    fn refuse_merge(
        &self,
        det: &tp::Detection,
        _input: &Self::Input,
    ) -> Option<(tp::ReasonCode, tp::ReasonCtx)> {
        match &det.state {
            tp::TpConfigState::Foreign { owner } => Some((
                tp::ReasonCode::TpConfigForeign,
                tp::ReasonCtx {
                    surface: Some(tp::SurfaceId::Claude),
                    path_display: tp::display_for(&self.path()),
                    format: Some(tp::Format::Json),
                    owner: Some(owner.clone()),
                    ..Default::default()
                },
            )),
            _ => None,
        }
    }
    fn merge(&self, mut doc: Self::Doc, _input: &Self::Input) -> Result<Self::Doc, String> {
        // The pure core, unchanged. `RefusedForeignShape` is already caught by
        // `refuse_merge` above; keeping the arm means a future shape the
        // detector misses still fails loudly instead of writing something odd.
        match apply_install(&mut doc) {
            GuardAction::RefusedForeignShape => {
                Err("settings.json has a hooks.PreToolUse of an unexpected shape".into())
            }
            _ => Ok(doc),
        }
    }
    fn remove(&self, mut doc: Self::Doc) -> Self::Doc {
        apply_uninstall(&mut doc);
        doc
    }
    fn render(&self, doc: &Self::Doc) -> String {
        // An empty object renders EMPTY, so the guard deletes a settings.json
        // that holds nothing but what we just removed — it never looked like
        // user state. Byte-identical to the status line's rule for this file;
        // the two must agree, because they render the SAME document.
        if doc.as_object().map(|o| o.is_empty()).unwrap_or(false) {
            return String::new();
        }
        serde_json::to_string_pretty(doc).unwrap_or_default()
    }
    fn expected_after_merge(&self, det: &tp::Detection, _input: &Self::Input) -> bool {
        det.state == tp::TpConfigState::OursActive
    }
}

/// `aikey mcp guard install`
pub fn cmd_install(json: bool) -> Result<(), String> {
    use colored::Colorize;
    let Some(path) = claude_settings_path() else {
        return say(
            json,
            "not-applicable",
            "no Claude Code config directory on this machine",
        );
    };

    // 🔴 ONE call now does what this function used to spell out by hand: read,
    // strict parse, detect, merge, verify the post-state, back up, then write
    // atomically — and on every branch that can stop it stops WITHOUT touching
    // the file. The branches are the same ones as before (no ~/.claude, an
    // unparseable settings.json, a hooks shape we cannot read); they are just
    // no longer a second implementation of them.
    let out = tp::apply(&McpGuardSurface, tp::TpOp::Merge(()));

    // The guard has already printed its sentence to stderr and logged the
    // structured event, so the refusal paths owe only the --json envelope.
    if matches!(out.reason_code, Some(tp::ReasonCode::TpNotApplicable)) {
        return say_after_guard(
            json,
            "not-applicable",
            out.sentence.as_deref().unwrap_or(
                "Claude Code config directory not found — open Claude Code once, then re-run",
            ),
        );
    }
    if matches!(out.action, tp::TpAction::Refused | tp::TpAction::Failed) {
        return say_after_guard(
            json,
            "refused",
            out.sentence
                .as_deref()
                .unwrap_or("refusing to touch settings.json"),
        );
    }
    if matches!(out.action, tp::TpAction::Unchanged) {
        return say(
            json,
            "already-installed",
            "the delegation gate is already installed",
        );
    }

    if !json {
        eprintln!(
            "  {} Delegation gate installed.",
            crate::symbols::CHECK.s().green()
        );
        eprintln!("    {} {}", "file:".dimmed(), path.display());
        eprintln!("    {} {}", "command:".dimmed(), hook_command());
        if let Some(b) = &out.backup_path {
            eprintln!("    {} {}", "backup:".dimmed(), b.display());
        }
        eprintln!(
            "    {} it decides whether an agent may spawn a sub-agent. It does NOT restrict what an already-running sub-agent may call.",
            "note:".dimmed()
        );
    }
    say(json, "installed", "the delegation gate is installed")
}

/// `aikey mcp guard uninstall`
pub fn cmd_uninstall(json: bool) -> Result<(), String> {
    use colored::Colorize;
    let Some(path) = claude_settings_path() else {
        return say(
            json,
            "not-applicable",
            "no Claude Code config directory on this machine",
        );
    };

    let out = tp::apply(&McpGuardSurface, tp::TpOp::Remove);

    if matches!(out.action, tp::TpAction::Refused | tp::TpAction::Failed) {
        return say_after_guard(
            json,
            "refused",
            out.sentence
                .as_deref()
                .unwrap_or("refusing to touch settings.json"),
        );
    }
    // 🔴 "Nothing happened" has two causes and the user needs to tell them
    // apart: there is no file at all, versus a file that never had our hook.
    if matches!(out.action, tp::TpAction::Unchanged) {
        return if out.state_before == tp::TpConfigState::Missing {
            say(json, "not-installed", "there is no settings.json")
        } else {
            say(
                json,
                "not-installed",
                "the delegation gate was not installed",
            )
        };
    }

    if !json {
        eprintln!(
            "  {} Delegation gate removed.",
            crate::symbols::CHECK.s().green()
        );
        eprintln!("    {} {}", "file:".dimmed(), path.display());
        if let Some(b) = &out.backup_path {
            eprintln!("    {} {}", "backup:".dimmed(), b.display());
        }
        // The guard deletes a settings.json that held nothing but our hook,
        // rather than leaving an empty `{}` behind. Say so — a file quietly
        // disappearing is worse than a file quietly emptied.
        if matches!(out.action, tp::TpAction::Deleted) {
            eprintln!(
                "    {} the file held nothing else, so it was removed rather than left empty",
                "note:".dimmed()
            );
        }
    }
    say(json, "uninstalled", "the delegation gate is removed")
}

/// `aikey mcp guard status`
///
/// 🔴 Reports TWO things, because either alone is misleading: whether the hook
/// is registered, and whether the gateway is actually answering. A registered
/// hook whose gateway is unreachable fails open on every spawn — from the
/// outside that is indistinguishable from a working gate, and this command is
/// the only place a user can tell the difference.
pub fn cmd_status(json: bool) -> Result<(), String> {
    use colored::Colorize;
    // Read-only, through the same detector the install path verifies with, so
    // "registered" here cannot drift from what install/uninstall believe.
    // A stale command (OurResidue) still counts as registered: the gate really
    // is wired, it just points at a binary that moved.
    let installed = tp::inspect(&McpGuardSurface).detection.state.has_ours();
    let disabled = std::env::var_os(DISABLE_ENV).is_some_and(|v| !v.is_empty());
    let gateway = ask_gateway("Explore", 1);

    if json {
        let doc = serde_json::json!({
            "installed": installed,
            "disabled_by_env": disabled,
            "gateway_answering": gateway.is_ok(),
            "gateway_error": gateway.as_ref().err(),
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return Ok(());
    }

    let mark = |ok: bool| {
        if ok {
            crate::symbols::CHECK.s().green()
        } else {
            crate::symbols::CROSS.s().red()
        }
    };
    println!("  {} hook registered in settings.json", mark(installed));
    match &gateway {
        Ok(_) => println!("  {} gateway is answering delegation questions", mark(true)),
        Err(e) => {
            println!(
                "  {} gateway is NOT answering — every spawn is allowed",
                mark(false)
            );
            println!("    {} {}", "reason:".dimmed(), e);
        }
    }
    if disabled {
        println!(
            "  {} {DISABLE_ENV} is set — the gate is turned off for this shell",
            crate::symbols::INFO.s().cyan()
        );
    }
    Ok(())
}

/// `aikey mcp guard preview <agent-type>` — what the gate would decide, and what
/// a harness-side `tools:` whitelist could say about it (P15 · task 15.26).
///
/// # 🔴 READ-ONLY, and that is the whole design
///
/// 15.26 originally proposed WRITING the delegation tiers into the harness's own
/// agent definitions as a `tools:` line. That half is deliberately not built:
/// those are the user's files, and a line we wrote there is **advisory** — the
/// user can edit it, and nothing enforces it. Something that looks like a
/// whitelist and is not one is the §0.7 failure again, except this time nothing
/// stops a salesperson describing it as a gate.
///
/// So this command shows the same information and writes nothing.
///
/// # 🔴 It asks the gateway rather than deciding anything
///
/// Same endpoint the live hook asks, so what this prints IS what the gate will
/// do. A local re-implementation would be the two-evaluator failure fence
/// `TestConsolePreviewAndHookShareTheEvaluator` exists to prevent — a preview
/// that says "allowed" while the gate refuses is worse than no preview.
///
/// # 🔴 What the `tools:` rendering can and cannot say
///
/// Measured while building this: AiKey occupies **one** entry in the client's
/// `mcpServers` map (named `aikey`), so every tool it serves reaches Claude Code
/// as `mcp__aikey__<tool>`. A harness-side whitelist therefore cannot express
/// "this toolset but not that one" by prefix — it would have to list individual
/// tool names, and on a node that follows a control plane the CLI cannot
/// enumerate them (`/admin/mcp/local-manifest` answers 503 there, by design:
/// tool review is the console's job).
///
/// ⇒ The advisory line is printed as the honest thing it is. 🚫 Do not "fix"
/// this by guessing tool names — that is the same class of error as guessing an
/// actor id.
pub fn cmd_preview(agent_type: &str, depth: i64, json: bool) -> Result<(), String> {
    use colored::Colorize;

    let agent_type = agent_type.trim();
    if agent_type.is_empty() {
        return Err("give a sub-agent type, e.g. `aikey mcp guard preview Explore`. \
                    Use * to see what the catch-all tier would do."
            .to_string());
    }

    let decision = ask_gateway(agent_type, depth);

    if json {
        let doc = match &decision {
            Ok(d) => serde_json::json!({
                "agent_type": agent_type,
                "depth": depth,
                "verdict": d.verdict,
                "tier": d.tier,
                "reason": d.reason,
                "stale": d.stale,
                // 🔴 Stated in the payload too, so a script that renders this
                // cannot present it as an enforced whitelist.
                "harness_tools_line_is_advisory": true,
            }),
            Err(e) => serde_json::json!({
                "agent_type": agent_type,
                "depth": depth,
                "gateway_error": e,
                // 🔴 The gate FAILS OPEN when it cannot answer (D-29), so the
                // preview must say "allowed", not "unknown" — otherwise it
                // describes a stricter product than the one that ships.
                "verdict": "allow",
                "reason": "the gateway did not answer; every spawn is allowed while that is true",
            }),
        };
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return Ok(());
    }

    let d = match decision {
        Ok(d) => d,
        Err(e) => {
            println!(
                "  {} the gateway did not answer — every spawn is ALLOWED while that is true",
                crate::symbols::CROSS.s().red()
            );
            println!("    {} {}", "reason:".dimmed(), e);
            return Ok(());
        }
    };

    let verdict = match d.verdict.as_str() {
        "deny" => "DENY".red(),
        "narrow" => "NARROW".yellow(),
        _ => "ALLOW".green(),
    };
    println!("  spawning {} at depth {} → {}", agent_type.bold(), depth, verdict);
    if d.tier.is_empty() {
        println!(
            "    {} no tier matched; the organisation's default rule decided",
            "tier:".dimmed()
        );
    } else {
        println!("    {} {}", "tier:".dimmed(), d.tier);
    }
    if !d.reason.is_empty() {
        println!("    {} {}", "reason:".dimmed(), d.reason);
    }
    if d.stale {
        println!(
            "  {} decided from a policy snapshot that could not be refreshed — the real answer may differ",
            crate::symbols::INFO.s().cyan()
        );
    }

    // 🔴 The advisory half, labelled as advisory on the line itself.
    println!();
    println!("  {}", "harness-side `tools:` whitelist".dimmed());
    println!(
        "    {} AiKey serves every tool through ONE entry in your client config (`aikey`), so the",
        crate::symbols::INFO.s().cyan()
    );
    println!("      harness sees them all as `mcp__aikey__<tool>`. A `tools:` line can therefore only");
    println!("      say \"all AiKey tools\" or name individual tools — it cannot express a toolset.");
    println!(
        "    {} And whatever it says is {}: it lives in a file you can edit, and AiKey does not",
        crate::symbols::INFO.s().cyan(),
        "advisory".yellow()
    );
    println!("      enforce it. The decision printed above is the part that is enforced.");
    Ok(())
}

/// Like `say`, for outcomes `third_party_config` has ALREADY reported.
///
/// 🔴 `tp::apply` prints its refusal sentence to stderr and emits the
/// structured event itself. Routing those through `say` would print the same
/// sentence twice in the human path, so this only owes the `--json` envelope.
fn say_after_guard(json: bool, state: &str, message: &str) -> Result<(), String> {
    if json {
        return say(true, state, message);
    }
    Ok(())
}

fn say(json: bool, state: &str, message: &str) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::json!({"state": state, "message": message})
        );
    } else if state != "installed" && state != "uninstalled" {
        eprintln!("  {}", message);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
