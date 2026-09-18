//! Harness adaptation for the delegation boundary (P15 · K4 · tasks 15.23–15.25).
//!
//! # What varies between harnesses, and what does not
//!
//! The delegation boundary is one hop: a parent agent asks its harness to spawn
//! a child, and AiKey gets to answer. Everything AiKey *decides* is harness-
//! neutral — the tiers, the evaluator, the verdict — and lives in the gateway.
//! Everything about *how the question arrives and how the answer is phrased* is
//! the harness's own, and lives here:
//!
//!   · the hook event name it raises        (Claude Code: `PreToolUse`)
//!   · what its spawn tool is called        (`Agent` in the event, `Task` in the
//!                                           run summary — the SAME tool)
//!   · where the requested sub-agent type sits in the payload
//!   · how it signals "this event came from the main agent"
//!   · the shape of the reply it expects
//!
//! # 🔴 Why this is in the CLI and not in the gateway
//!
//! Task 15.23 as written asks for `internal/mcp/harness/` in Go. Measured on
//! 2026-09-03, that is the wrong address: the CLI hook shell already reduces the
//! harness event to `{agent_type, depth}` before it ever calls the gateway, so a
//! Go registry would dispatch on a payload that never reaches Go — a table with
//! no consumer, which this repo bans outright. And `pkg/mcpwire.HookEvent` (Go)
//! has zero non-test consumers; it is a contract mirror, not a parser.
//!
//! Putting the adapter where the variability actually lives means adding a
//! second harness is one entry in `REGISTRY` rather than an `if` in two
//! languages. User decision, same date. 🚫 Do not "restore symmetry" by adding
//! a Go half — harness knowledge in two places is the split-truth-source failure.
//!
//! # 🔴 Exactly ONE implementation, on purpose
//!
//! `claude` is the only adapter, because it is the only harness whose identity
//! shape has been measured (evidence: `15.0-*.jsonl`). Codex / Hermes / OpenClaw
//! have not been verified in a single field. Writing their branches from a
//! vendor's docs is how you get an abstraction shaped around three guesses and
//! one fact — so the registry exists (adding the second one is cheap) and is
//! deliberately not populated (15.24).

use serde::Deserialize;

/// What the harness event boils down to, once a harness-specific adapter has
/// read it.
///
/// 🔴 `is_main_actor` rather than a depth: computing depth is OUR job, and a
/// harness that started reporting one would not be believed (a client that
/// reports its own depth reports 0 forever and walks past every limit). The
/// adapter answers only "did this come from the top-level agent", which is a
/// fact about the payload, and the caller turns that into a depth.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SpawnRequest {
    /// The sub-agent type the parent asked for. Empty when the harness did not
    /// say — see `warnings`.
    pub agent_type: String,
    /// Whether the event came from the top-level agent.
    pub is_main_actor: bool,
    /// Fields that were missing and were defaulted.
    ///
    /// 🔴 Carried out rather than logged in here, so the caller decides where
    /// they go. The hook writes to stderr; a test reads them directly. What
    /// matters is that a defaulted field is never SILENT (15.25) — a spawn we
    /// evaluated against an empty agent type looks exactly like a spawn that
    /// matched no tier, and the two have completely different fixes.
    pub warnings: Vec<String>,
}

/// One harness's dialect of the spawn hop.
pub trait HarnessAdapter: Sync {
    /// Registry key. Stable — it goes in config and in messages.
    fn name(&self) -> &'static str;

    /// The hook event this harness raises before a spawn.
    fn hook_event(&self) -> &'static str;

    /// The matcher expression to register in the harness's settings file.
    fn matcher(&self) -> &'static str;

    /// Whether a tool name from this harness is the spawn hop.
    ///
    /// 🔴 A method, not a constant list, because a harness may name the same
    /// tool differently in different documents — Claude Code does exactly that
    /// (`Agent` in the hook event, `Task` in `permission_denials`), and matching
    /// only one leaves a gate that LOOKS installed and stops nothing.
    fn is_spawn_tool(&self, tool: &str) -> bool;

    /// Read one raw event.
    ///
    /// 🔴 LENIENT (15.25): unknown fields are ignored and missing fields fall
    /// back to a default plus a warning. Strict decoding would turn "the vendor
    /// added a field" into "nobody's agent starts any more" — a failure we would
    /// have manufactured ourselves, on every machine at once.
    fn read_spawn(&self, raw: &str) -> Result<SpawnRequest, String>;
}

// ---------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------

/// Claude Code, measured against 2.1.247.
///
/// Evidence: `roadmap20260320/技术实现/阶段8-平台化/MCP网关/openspec/changes/aikey-mcp-gateway/evidence/15.0-*.jsonl`
pub struct ClaudeCode;

/// The event subset this adapter reads.
///
/// Every field is `#[serde(default)]` — that is the lenient contract, not
/// laziness. 🚫 Do not add `#[serde(deny_unknown_fields)]`.
#[derive(Debug, Deserialize, Default)]
struct ClaudeHookEvent {
    #[serde(default)]
    tool_name: Option<String>,
    /// 🔴 An `Option` because ABSENCE is the signal: a main-agent event carries
    /// no `agent_id` key at all; a sub-agent event carries one. Testing
    /// `agent_id == ""` instead would fold "this is the main agent" together
    /// with "the field decoded empty", i.e. with a broken hook contract.
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    tool_input: Option<ClaudeToolInput>,
}

#[derive(Debug, Deserialize, Default)]
struct ClaudeToolInput {
    #[serde(default)]
    subagent_type: Option<String>,
}

impl HarnessAdapter for ClaudeCode {
    fn name(&self) -> &'static str {
        "claude"
    }

    fn hook_event(&self) -> &'static str {
        "PreToolUse"
    }

    fn matcher(&self) -> &'static str {
        "Agent|Task"
    }

    fn is_spawn_tool(&self, tool: &str) -> bool {
        // 🔴 Both names of the SAME tool. Measured: the hook event says
        // `"tool_name": "Agent"` while the run summary's `permission_denials`
        // says `"tool_name": "Task"`. The failure mode of matching one is
        // silent, which is why there is a fence on it.
        tool == "Agent" || tool == "Task"
    }

    fn read_spawn(&self, raw: &str) -> Result<SpawnRequest, String> {
        let evt: ClaudeHookEvent =
            serde_json::from_str(raw).map_err(|e| format!("hook event did not parse: {e}"))?;

        let mut warnings = Vec::new();
        let agent_type = evt
            .tool_input
            .as_ref()
            .and_then(|t| t.subagent_type.clone())
            .unwrap_or_default();

        // 🔴 A spawn event that names no sub-agent type is worth saying out loud
        // (15.25 / 15.X8's observable half). We still evaluate — failing open is
        // the rule — but an empty agent type matches no tier, and "no tier
        // matched" and "the harness stopped telling us the type" produce the
        // SAME allow with completely different fixes.
        if agent_type.is_empty() {
            warnings.push(format!(
                "the harness event named no sub-agent type (expected tool_input.subagent_type); \
                 evaluating with an empty type, which will match no tier. If this persists, the \
                 {} hook contract has changed and the delegation tiers are no longer being \
                 applied to this spawn.",
                self.name()
            ));
        }

        // 🔴 There is deliberately NO warning for a missing `agent_id`, and the
        // reason is worth writing down because task 15.X8 asks for one: absence
        // IS the main-agent signal here, so "the harness removed the field" and
        // "this event came from the main agent" are the same bytes. A warning
        // would have to fire on every main-agent event — i.e. on the common
        // case — which trains the reader to ignore it.
        //
        // The property is therefore unobservable PER EVENT and is caught
        // statistically instead: a fleet that never records a single depth-2
        // spawn while its tiers set a depth limit is the signal, and that lives
        // in the gateway's events, not here. Recorded rather than faked (R53).
        Ok(SpawnRequest {
            agent_type,
            is_main_actor: evt.agent_id.is_none(),
            warnings,
        })
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Every harness AiKey can adapt to.
///
/// 🔴 A TABLE, not a chain of `if harness == "…"`. The dispatch below is the
/// whole point of the interface: adding a harness is one line here and one impl
/// block, with no call site to remember to update. Same shape as the provider
/// registry and the discovery sources.
static REGISTRY: &[&(dyn HarnessAdapter + 'static)] = &[&ClaudeCode];

/// The harness AiKey assumes when nothing says otherwise.
///
/// 🔴 Claude Code, because it is the only measured one. When a second adapter
/// lands this must become an explicit selection rather than a silent default —
/// a wrong default would install a hook into a file the harness does not read,
/// which looks exactly like a working install.
pub fn default_adapter() -> &'static dyn HarnessAdapter {
    REGISTRY[0]
}

/// Look one up by name. `None` for a harness AiKey does not adapt to.
///
/// 🚫 Never fall back to the default on an unknown name: silently adapting to
/// the wrong harness produces a gate that is installed, green, and inert.
pub fn adapter_for(name: &str) -> Option<&'static dyn HarnessAdapter> {
    REGISTRY.iter().copied().find(|a| a.name() == name)
}

/// The names AiKey can adapt to, for messages and for `--help`.
pub fn known_harnesses() -> Vec<&'static str> {
    REGISTRY.iter().map(|a| a.name()).collect()
}

#[cfg(test)]
mod tests;
