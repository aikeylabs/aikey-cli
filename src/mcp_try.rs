//! `aikey mcp try <tool>` — call one tool through the gateway, as yourself.
//!
//! # What this is for, and why it is a CLI command and not a console panel
//!
//! R23 asked for a "try it" panel in the console: the operator invokes a tool
//! with their own seat and their own key, through the gateway's own
//! `/mcp/{slug}`, so the call walks the identical chain a real Agent walks —
//! authorisation, manifest state, schema validation, rate gate, compliance —
//! with no step skipped.
//!
//! 🔴 **The panel could not exist in Production.** A console-initiated call
//! requires the control plane to reach the MCP surface, and in Production that
//! surface is the proxy on an employee's laptop. The control plane is a server;
//! it cannot reach it. The panel would therefore have worked on Trial and
//! Cluster only — and "a capability that exists in one edition only" is a
//! defect by this project's own rule. Ruling A-1 (2026-09-04) moved the
//! capability to where the surface actually is: this machine.
//!
//! Everything R23 demanded survives the move, and some of it improves:
//!
//! | R23 demands | how this satisfies it |
//! |---|---|
//! | operator's own seat + own key | it sends the operator's own route token — the same one their MCP client carries |
//! | through `/mcp/{slug}` | literally the same URL, port and handler |
//! | no step skipped | there is no second code path to skip steps in |
//! | not authorised → 403, never a silent pass | the gateway answers; this command only prints |
//! | recorded, and it costs quota | recorded by the gateway's own recorder — this command cannot opt out |
//!
//! > R23's one-line test: **anything the try surface can do, the operator could
//! > already do with their own Agent.** Here that is true by construction: this
//! > command *is* an MCP client, holding no more than one.
//!
//! # 🔴 Why it does the whole handshake instead of posting `tools/call`
//!
//! The gateway accepts a bare `tools/call` with no session (an absent
//! `Mcp-Session-Id` is allowed). Posting one directly would be shorter and
//! would still exercise every gate R23 lists. It is still wrong for this
//! command: a self-check exists to answer "would my client work", and a client
//! opens with `initialize`, then sends `MCP-Protocol-Version` on every later
//! request — where an unsupported value is a 400 by the transport spec. A probe
//! that skips negotiation reports success on a gateway a real client cannot
//! finish a handshake with.
//!
//! # Naming
//!
//! `try`, because `aikey mcp test` and `aikey mcp calls` were both already
//! taken and mean other things — `test` asks the gateway how each hosted server
//! is doing, `calls` reads this machine's history. Reusing either would give
//! one word two jobs.
//!
//! spec: `workflow/CI/requirements/2026-08-20-mcp-gateway.md` R23
//! tasks: 8.7 (A-1 ruling) · fences 8.F5 / 8.F6
use std::time::Duration;

use serde_json::{json, Map, Value};

/// The header that labels the row this call leaves in the audit.
///
/// 🔴 It LABELS, it does not authorise. The gateway reads it in `originFor`
/// only to choose between `agent` and `console_test` when writing the record;
/// nothing branches on it, and fence 8.F5 exists so nothing learns to.
///
/// 🔴 The name still says "console" and the stored value is still
/// `console_test`, even though the only sender is this CLI. That is deliberate:
/// `mcp_call_event.origin`'s value domain is a published CHECK constraint, so
/// the value cannot be renamed without a migration — and renaming only the
/// header would leave one concept with two internal names, which is worse than
/// one slightly historical name. **In every user-facing string, in both
/// languages, it is a "self-check call".**
const SELF_CHECK_HEADER: &str = "X-Aikey-Mcp-Origin-Console-Test";

/// Personal's single toolset. Production developers pass `--slug`.
const DEFAULT_SLUG: &str = "local";

/// What the operator asked for.
pub struct TryRequest<'a> {
    pub tool: &'a str,
    pub slug: &'a str,
    pub key: Option<&'a str>,
    pub args: &'a [String],
    pub args_json: Option<&'a str>,
    pub json: bool,
}

/// One tool as `tools/list` describes it. Only the parts this command uses.
#[derive(Debug, serde::Deserialize)]
pub struct ToolDesc {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
}

/// Build the `arguments` object for `tools/call`.
///
/// 🔴 Values are coerced **by the tool's published `inputSchema`**, not by
/// guessing from how they look. The tempting shortcut is "if it parses as JSON,
/// send JSON" — which silently turns the version string `1.0` into the number
/// `1`, and the account id `0012` into `12`. Both are valid JSON and both are
/// the wrong value, and the tool receives them without complaint because they
/// are the right *type*.
///
/// The schema is the same one R23 said the console form would be generated
/// from, so this command and that form agree by construction.
///
/// A property the schema does not declare is passed through as a string and
/// left for the gateway to reject: 🚫 this function does not decide what is
/// valid, it only decides what a shell word MEANT.
pub fn build_arguments(
    pairs: &[String],
    args_json: Option<&str>,
    schema: &Value,
) -> Result<Map<String, Value>, String> {
    if let Some(raw) = args_json {
        if !pairs.is_empty() {
            return Err("use either --arg or --args-json, not both. \
                        --args-json replaces the whole arguments object, so mixing the two \
                        leaves it ambiguous which one wins."
                .to_string());
        }
        let parsed: Value =
            serde_json::from_str(raw).map_err(|e| format!("--args-json is not valid JSON: {e}"))?;
        return match parsed {
            Value::Object(m) => Ok(m),
            _ => Err("--args-json must be a JSON OBJECT of arguments, \
                      e.g. '{\"path\":\"/tmp\",\"limit\":10}'."
                .to_string()),
        };
    }

    let props = schema.get("properties");
    let mut out = Map::new();
    for pair in pairs {
        let (k, v) = pair.split_once('=').ok_or_else(|| {
            format!(
                "--arg must be written NAME=VALUE, got '{pair}'.\n  \
                 For a value containing '=', quote the whole pair: --arg 'q=a=b'."
            )
        })?;
        if k.is_empty() {
            return Err(format!("--arg '{pair}' has an empty name."));
        }
        let declared = props
            .and_then(|p| p.get(k))
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str);
        out.insert(k.to_string(), coerce(v, declared)?);
    }
    Ok(out)
}

/// Turn one shell word into the JSON type the schema declares for it.
///
/// 🔴 An undeclared or unknown type yields a STRING rather than a guess. The
/// gateway validates against the same schema and will say precisely which field
/// is wrong — a far better outcome than this function inventing a number the
/// operator did not type.
fn coerce(raw: &str, declared: Option<&str>) -> Result<Value, String> {
    let bad = |want: &str| {
        Err(format!(
            "the tool declares this argument as {want}, and '{raw}' is not one.\n  \
             (Types come from the tool's published schema, so this is the same check \
             the gateway will run.)"
        ))
    };
    match declared {
        Some("number") => raw
            .parse::<f64>()
            .map(|n| json!(n))
            .or_else(|_| bad("a number")),
        Some("integer") => raw
            .parse::<i64>()
            .map(|n| json!(n))
            .or_else(|_| bad("an integer")),
        Some("boolean") => match raw {
            "true" => Ok(json!(true)),
            "false" => Ok(json!(false)),
            _ => bad("a boolean (write true or false)"),
        },
        // 🔴 Arrays and objects have no shell spelling that is not a guess, so
        // they are taken as JSON and the parse error is reported as one. This
        // is the one place a JSON parse is correct: the schema ASKED for
        // structure, so the operator cannot have meant a bare string.
        Some("array") | Some("object") => serde_json::from_str(raw).map_err(|e| {
            format!(
                "the tool declares this argument as a JSON array or object, \
                 and '{raw}' does not parse as one: {e}"
            )
        }),
        Some("null") => Ok(Value::Null),
        _ => Ok(Value::String(raw.to_string())),
    }
}

/// The message shown when the named tool is not in this toolset.
///
/// 🔴 It lists what IS there. "Unknown tool" alone leaves the operator with no
/// next step, and the list is already in hand — this command fetched it to read
/// the schemas.
pub fn unknown_tool_message(tool: &str, available: &[ToolDesc], slug: &str) -> String {
    if available.is_empty() {
        return format!(
            "the toolset '{slug}' exposes no tools, so '{tool}' cannot be called.\n  \
             On Personal: register a server with `aikey mcp add`, then accept it with \
             `aikey mcp review --accept <server>`.\n  \
             On Production: ask an administrator to grant you a toolset."
        );
    }
    let mut names: Vec<&str> = available.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    format!(
        "'{tool}' is not a tool in the toolset '{slug}'.\n  Available here: {}\n  \
         (This is the same list your MCP client sees — if a tool you expect is missing, \
         it may be held for review: run `aikey mcp review`.)",
        names.join(", ")
    )
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

fn base_url() -> String {
    format!("http://127.0.0.1:{}", crate::commands_proxy::proxy_port())
}

fn not_running(url: &str) -> String {
    format!(
        "the local gateway is not answering on {url}.\n  \
         Start it with `aikey proxy start`, then run this again.\n  \
         (This command deliberately goes through the running gateway rather than talking to \
         your MCP server directly — that is what makes the result mean anything: it is the \
         same path, the same authorisation and the same record as a real call.)"
    )
}

/// Carry the gateway's own sentence through rather than inventing one.
///
/// 🔴 A refusal here is usually the CORRECT answer — "you are not granted this
/// tool" is the system working — and the gateway's wording already tells the
/// operator what to do. Replacing it with "request failed" would turn a clear
/// instruction into a mystery.
fn rpc_error_message(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let e = v.get("error")?;
    let msg = e
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the gateway refused the call");
    let code = e.get("code").and_then(Value::as_str);
    Some(match code {
        Some(c) => format!("{msg}\n  (error code: {c})"),
        None => msg.to_string(),
    })
}

pub fn cmd_try(req: TryRequest<'_>) -> Result<(), String> {
    let (key_alias, bearer) = crate::mcp_adopt::pick_bearer(req.key)?;
    let url = format!("{}/mcp/{}", base_url(), req.slug);

    let mut client = Session::open(&url, &bearer, req.slug)?;
    let tools = client.list_tools()?;

    let Some(desc) = tools.iter().find(|t| t.name == req.tool) else {
        return Err(unknown_tool_message(req.tool, &tools, req.slug));
    };
    let arguments = build_arguments(req.args, req.args_json, &desc.input_schema)?;

    let started = std::time::Instant::now();
    let body = client.call_tool(req.tool, arguments)?;
    let elapsed = started.elapsed();

    let outcome = classify(&body);
    if req.json {
        println!("{body}");
    } else {
        print!(
            "{}",
            render_result(&body, req.tool, req.slug, &key_alias, elapsed)
        );
    }
    // 🔴 The verdict reaches the shell, not just the terminal. See
    // `Outcome::exit_code` for why a refusal is 2 and not 0.
    if outcome != Outcome::Succeeded {
        std::process::exit(outcome.exit_code());
    }
    Ok(())
}

/// One MCP session against the local gateway.
///
/// 🔴 Holds the negotiated protocol version and the session id, because both
/// are required on every later request: the transport spec makes an unsupported
/// `MCP-Protocol-Version` a 400, and a stale `Mcp-Session-Id` a 404.
struct Session {
    url: String,
    bearer: String,
    slug: String,
    protocol: String,
    session_id: Option<String>,
}

impl Session {
    fn open(url: &str, bearer: &str, slug: &str) -> Result<Self, String> {
        let mut s = Session {
            url: url.to_string(),
            bearer: bearer.to_string(),
            slug: slug.to_string(),
            // Asked for on the way in; replaced below by whatever the gateway
            // answers with. 🔴 The gateway is allowed to answer with a
            // different revision (that is negotiation, not failure), and the
            // one it names is the one every later request must carry.
            protocol: "2025-06-18".to_string(),
            session_id: None,
        };
        let (body, session_id) = s.post_raw(
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": s.protocol,
                    "capabilities": {},
                    "clientInfo": { "name": "aikey-cli (aikey mcp try)", "version": env!("CARGO_PKG_VERSION") }
                }
            }),
            true,
        )?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| format!("the gateway's handshake reply could not be read: {e}"))?;
        if let Some(msg) = rpc_error_message(&body) {
            return Err(format!("the gateway refused the handshake: {msg}"));
        }
        if let Some(agreed) = v.pointer("/result/protocolVersion").and_then(Value::as_str) {
            s.protocol = agreed.to_string();
        }
        s.session_id = session_id;
        // The spec's post-handshake notification. 🔴 Sent, and its reply
        // ignored on purpose: a notification has no id and the gateway answers
        // 202 with no body. Skipping it would leave the session half-open by
        // the spec's own lifecycle even though this gateway tolerates it.
        let _ = s.post_raw(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            false,
        );
        Ok(s)
    }

    fn list_tools(&mut self) -> Result<Vec<ToolDesc>, String> {
        let (body, _) = self.post_raw(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
            false,
        )?;
        if let Some(msg) = rpc_error_message(&body) {
            return Err(msg);
        }
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| format!("the gateway's tool list could not be read: {e}"))?;
        let tools = v.pointer("/result/tools").cloned().unwrap_or(json!([]));
        serde_json::from_value(tools)
            .map_err(|e| format!("the gateway's tool list has an unexpected shape: {e}"))
    }

    fn call_tool(&mut self, tool: &str, arguments: Map<String, Value>) -> Result<String, String> {
        let (body, _) = self.post_raw(
            &json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            }),
            false,
        )?;
        Ok(body)
    }

    /// POST one JSON-RPC message, returning the body and any session header.
    ///
    /// 🔴 An HTTP error status is NOT turned into a transport failure here:
    /// 403 (not granted) and 400 (bad protocol version) both carry a JSON-RPC
    /// body written for the operator, and that body is the answer they need.
    fn post_raw(
        &self,
        msg: &Value,
        is_handshake: bool,
    ) -> Result<(String, Option<String>), String> {
        let mut req = ureq::post(&self.url)
            .timeout(Duration::from_secs(30))
            .set("Authorization", &format!("Bearer {}", self.bearer))
            .set("Content-Type", "application/json")
            // The spec's required Accept for Streamable HTTP: a server may reply
            // with either a JSON body or an SSE stream.
            .set("Accept", "application/json, text/event-stream")
            // 🔴 Labels the audit row as a self-check. See SELF_CHECK_HEADER.
            .set(SELF_CHECK_HEADER, "1");
        if !is_handshake {
            req = req.set("MCP-Protocol-Version", &self.protocol);
        }
        if let Some(sid) = &self.session_id {
            req = req.set("Mcp-Session-Id", sid);
        }
        match req.send_json(msg.clone()) {
            Ok(resp) => {
                let sid = resp.header("Mcp-Session-Id").map(str::to_string);
                let body = resp
                    .into_string()
                    .map_err(|e| format!("cannot read the gateway's response: {e}"))?;
                Ok((body, sid))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                if let Some(msg) = rpc_error_message(&body) {
                    return Err(msg);
                }
                if code == 404 {
                    return Err(format!(
                        "the gateway has no toolset called '{}'.\n  \
                         On Personal the toolset is '{DEFAULT_SLUG}' (the default).\n  \
                         On Production, use the slug from your MCP client's config — \
                         the same one in the endpoint your administrator gave you: /mcp/<slug>.",
                        self.slug
                    ));
                }
                Err(format!("the gateway refused the request (HTTP {code})"))
            }
            Err(_) => Err(not_running(&self.url)),
        }
    }
}

/// What the gateway's reply says happened.
///
/// 🔴 Three states, not two, and the middle one is why: MCP puts TOOL-level
/// failures inside a SUCCESSFUL JSON-RPC result (`isError: true`), so reading
/// only the protocol layer reports success for a tool that just said it could
/// not do the thing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Outcome {
    /// The tool ran and reported success.
    Succeeded,
    /// The call reached the tool, and the tool reported a failure.
    ToolReportedError,
    /// The gateway refused before the tool ran — not granted, frozen, invalid
    /// arguments, backend unreachable. 🔴 Usually the system working correctly.
    Refused,
}

impl Outcome {
    /// The process exit code.
    ///
    /// 🔴 A refusal exits NON-ZERO, and this is the whole reason the enum
    /// exists. The first version printed the refusal beautifully and exited 0
    /// — which makes the command useless for the job it was built for: a
    /// self-check that cannot fail a script is not a check, it is a paragraph.
    /// Caught by running the real binary, not by reading it.
    ///
    /// 2 rather than 1, matching `aikey env check`: 1 means "the command could
    /// not run" (no gateway, no key, unknown tool), 2 means "the command ran
    /// and the answer is no". A caller that cannot tell those apart will
    /// retry the one that will never succeed.
    pub fn exit_code(self) -> i32 {
        match self {
            Outcome::Succeeded => 0,
            Outcome::ToolReportedError | Outcome::Refused => 2,
        }
    }
}

/// Classify one `tools/call` reply. The ONE place the verdict is decided, so
/// what is printed and what is exited with cannot disagree.
pub fn classify(body: &str) -> Outcome {
    if rpc_error_message(body).is_some() {
        return Outcome::Refused;
    }
    let is_error = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/result/isError").and_then(Value::as_bool))
        .unwrap_or(false);
    if is_error {
        Outcome::ToolReportedError
    } else {
        Outcome::Succeeded
    }
}

/// Render one `tools/call` reply for a human.
///
/// 🔴 A tool that reports failure IN a successful JSON-RPC reply (`isError`) is
/// shown as a failure. MCP puts tool-level errors in the result rather than in
/// the protocol error, so reading only the JSON-RPC layer would print a tick
/// beside a tool that just said it could not do the thing.
pub fn render_result(
    body: &str,
    tool: &str,
    slug: &str,
    key_alias: &str,
    elapsed: Duration,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(
                out,
                "The gateway answered with something this build cannot read: {e}"
            );
            return out;
        }
    };

    if let Some(msg) = rpc_error_message(body) {
        let _ = writeln!(out, "  {} {tool} was refused", crate::symbols::CROSS.s());
        let _ = writeln!(out, "  {msg}");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "  A refusal is still a recorded call — see `aikey mcp calls`."
        );
        return out;
    }

    let is_error = classify(body) == Outcome::ToolReportedError;
    let mark = if is_error {
        crate::symbols::CROSS.s()
    } else {
        crate::symbols::CHECK.s()
    };
    let verdict = if is_error {
        "reported an error"
    } else {
        "succeeded"
    };
    let _ = writeln!(
        out,
        "  {mark} {tool} {verdict}  ({} ms, toolset '{slug}', key '{key_alias}')",
        elapsed.as_millis()
    );
    let _ = writeln!(out);

    match v.pointer("/result/content").and_then(Value::as_array) {
        Some(items) if !items.is_empty() => {
            for item in items {
                match item.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
                        for line in text.lines() {
                            let _ = writeln!(out, "  {line}");
                        }
                    }
                    // 🔴 Non-text content is DESCRIBED, not dumped. An image or
                    // an audio blob is megabytes of base64; printing it floods
                    // the terminal and tells the operator nothing they can read.
                    Some(kind) => {
                        let _ = writeln!(out, "  [{kind} content, not shown]");
                    }
                    None => {
                        let _ = writeln!(out, "  [content of an unnamed type, not shown]");
                    }
                }
            }
        }
        _ => {
            let _ = writeln!(out, "  (the tool returned no content)");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  Recorded as a self-check call — see `aikey mcp calls`."
    );
    out
}

#[cfg(test)]
mod tests;
