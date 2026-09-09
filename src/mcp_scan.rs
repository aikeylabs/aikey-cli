//! `aikey mcp scan` — read the MCP servers a developer already has, and say
//! which of them are carrying a credential in cleartext.
//!
//! 阶段8-平台化 · MCP 网关 · P14 tasks 14.1a–14.1f
//! spec: `workflow/CI/requirements/2026-08-20-mcp-gateway.md` (R19, I22)
//! design: `roadmap20260320/技术实现/阶段8-平台化/MCP网关/20260820-MCP网关-技术方案.md` §5.6
//!
//! # What this is for
//!
//! The whole gateway exists because of secrets that are **already** sitting in
//! a developer's home directory — a GitHub PAT, a production database password,
//! a Jira token, each one written in plain text into a client config file that
//! anything running as that user can read. A gateway that only helps people who
//! set up MCP *after* installing it does not address that.
//!
//! `scan` is the first half of the answer and, deliberately, a whole product on
//! its own: one command that says "this machine has 3 MCP servers, 2 of them
//! carry a cleartext credential, and one of those points at prod".
//!
//! # 🔴 This module is READ-ONLY, structurally
//!
//! Not as a promise — as a property somebody can check. Users run `scan`
//! expecting "just a look", and the day it writes something is the day they
//! stop running it. The fence `scan_module_makes_no_write_calls` allowlists the
//! `std::fs` functions this file may name; anything else — `File::create`,
//! `OpenOptions`, `remove_file`, `atomic_write`, a `save()` — goes red.
//!
//! # 🔴 Credentials are masked, always
//!
//! The report gets screenshotted into a group chat. That is not a hypothetical:
//! it is the single most likely thing to happen to a screen that says "you have
//! a problem here". So a suspected secret is only ever rendered as first four /
//! last four characters (`ghp_****…****3a91`), and the raw value never leaves
//! this module's [`SuspectedSecret`] — which does not implement `Display` and
//! redacts itself in `Debug`.
//!
//! # 🔴 What a miss looks like
//!
//! [`credential_hints`] recognises variable names and vendor token shapes. It
//! will miss a secret in a variable called `X`. That is a permanent property of
//! pattern matching, so the report **says so** rather than implying the machine
//! is clean afterwards (14.C5). The same honesty applies to files: only the
//! clients in `data/mcp_clients.yaml` are looked at, and a copy of the same
//! secret in a file nobody listed is not found (R19 boundary 1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// the shape table (task 14.1e)
// ---------------------------------------------------------------------------

/// The client shape table, bundled at compile time exactly as
/// `provider_registry.yaml` is — the CLI stays a single self-contained binary
/// with no data directory to lose.
const CLIENTS_YAML: &str = include_str!("../data/mcp_clients.yaml");

#[derive(Debug, Deserialize)]
struct ClientTable {
    entry_shape: EntryShape,
    clients: Vec<ClientShape>,
    credential_hints: CredentialHints,
    managed_entry_name: String,
}

/// Field names inside one server entry.
#[derive(Debug, Clone, Deserialize)]
struct EntryShape {
    command: String,
    args: String,
    env: String,
    url: String,
    headers: String,
    transport: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientShape {
    id: String,
    display: String,
    locations: Vec<LocationShape>,
    /// Per-client override of the file-level shape. Absent today, on purpose —
    /// see the YAML's field reference for when to start using it.
    #[serde(default)]
    entry_shape: Option<EntryShape>,
}

#[derive(Debug, Clone, Deserialize)]
struct LocationShape {
    id: String,
    source: PathSource,
    #[serde(default)]
    path: Option<String>,
    server_maps: Vec<Vec<String>>,
}

/// How a config file's location is resolved.
///
/// 🔴 `ClaudeDesktopConfig` deliberately carries no path. Claude Desktop's
/// config lives under LocalAppData on Windows (not Roaming, which is where the
/// well-known MCP docs point) and behind an MSIX package registration when it
/// was installed from the Store. That knowledge already exists once, in
/// `commands_account::claude_desktop`; spelling a path here would be a second
/// copy that is wrong on exactly the platform this developer does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PathSource {
    HomeRelative,
    CwdRelative,
    ClaudeDesktopConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialHints {
    key_patterns: Vec<String>,
    value_patterns: Vec<String>,
}

fn table() -> &'static ClientTable {
    static TABLE: OnceLock<ClientTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        // A parse failure here is a build-time authoring error in a file that
        // ships inside the binary, so it cannot be a user's problem at runtime
        // and it cannot be recovered from — the table IS the feature.
        serde_yaml::from_str(CLIENTS_YAML).expect("data/mcp_clients.yaml is not valid YAML")
    })
}

/// The server-map pointers declared for whichever location owns `path`.
///
/// 🔴 `adopt` must remove entries from the SAME places `scan` found them,
/// including the `*` wildcard that reaches Claude Code's per-project maps.
/// Re-deriving the shape in the adoption code would be a second table that
/// drifts from this one — and the drift would show up as "adopt says it removed
/// nothing" on exactly the machines that most needed it.
///
/// Matched by FILE NAME rather than by full path, because the same client's
/// config lives at a different absolute path on every machine and in every test.
pub fn server_maps_for(path: &Path) -> Vec<Vec<String>> {
    let want = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let mut out: Vec<Vec<String>> = Vec::new();
    for c in &table().clients {
        for l in &c.locations {
            let declared = match l.source {
                PathSource::HomeRelative | PathSource::CwdRelative => {
                    l.path.as_deref().unwrap_or_default()
                }
                // The desktop config's name is not spelled in the table; it
                // comes from the resolver that owns it.
                PathSource::ClaudeDesktopConfig => "claude_desktop_config.json",
            };
            let leaf = declared.rsplit('/').next().unwrap_or(declared);
            if leaf == want {
                for m in &l.server_maps {
                    if !out.contains(m) {
                        out.push(m.clone());
                    }
                }
            }
        }
    }
    out
}

/// The clients this build knows how to read, for the report's honesty footer
/// (task 14.1f) and for the user documentation.
pub fn known_clients() -> Vec<(String, String)> {
    table()
        .clients
        .iter()
        .map(|c| (c.id.clone(), c.display.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// what a scan produces
// ---------------------------------------------------------------------------

/// How a server is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// A child process on this machine. The overwhelming majority.
    Stdio { command: String, args: Vec<String> },
    /// A remote endpoint. `kind` is whatever the client wrote in its transport
    /// field ("http", "sse", …), or "http" when it wrote nothing.
    Remote { url: String, kind: String },
    /// 🔴 We read the entry and could not tell. Reported as its own outcome and
    /// never dropped: a silently skipped server is one the user will keep
    /// believing has been dealt with (14.1f).
    Unrecognised { reason: String },
}

/// The name `adopt` files its own gateway entry under.
pub fn managed_entry_name() -> &'static str {
    &table().managed_entry_name
}

/// Where a suspected secret was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// An `env` entry handed to a stdio child.
    Env,
    /// An HTTP header on a remote server.
    Header,
}

/// Why we suspect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintReason {
    /// The variable name matched (e.g. `GITHUB_TOKEN`).
    KeyPattern(String),
    /// The value matched a vendor-issued shape (e.g. `ghp_…`).
    ValuePattern(String),
}

/// One suspected credential.
///
/// 🔴 Holds the raw value because `adopt` has to move it into the vault, and
/// re-reading the file there would be a second parse that could disagree with
/// the one the user just confirmed. Everything else about this type exists to
/// make sure that value is only ever *moved*, never *shown*: no `Display`, and
/// a hand-written `Debug` that redacts — because the day this ends up in a
/// panic message or a `dbg!` is the day the feature does the opposite of its
/// job.
#[derive(Clone, PartialEq, Eq)]
pub struct SuspectedSecret {
    pub key: String,
    pub carrier: Carrier,
    pub reason: HintReason,
    value: String,
}

impl SuspectedSecret {
    /// The only rendering that exists (task 14.1c).
    pub fn masked(&self) -> String {
        mask_secret(&self.value)
    }
    /// The raw value, for the one caller that must have it: `adopt`, putting it
    /// into the vault. Named so that it cannot be reached by accident.
    pub fn reveal_for_vault(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for SuspectedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuspectedSecret")
            .field("key", &self.key)
            .field("carrier", &self.carrier)
            .field("reason", &self.reason)
            .field("value", &self.masked())
            .finish()
    }
}

/// One MCP server found in one config file.
#[derive(Debug, Clone)]
pub struct FoundServer {
    pub client_id: String,
    pub client_display: String,
    /// The location within that client — "user", "project", or the project
    /// directory a `*` in the server map matched.
    pub scope: String,
    pub path: PathBuf,
    /// The key the client filed it under. Also its identity to the user.
    pub name: String,
    pub transport: Transport,
    /// 🔴 True when this entry is the gateway entry `adopt` wrote. Its bearer is
    /// a credential and the patterns DO match it — correctly — so without this
    /// flag `scan` would report our own work as a finding and `adopt` would
    /// re-adopt an already-adopted machine (14.C6).
    pub managed_by_aikey: bool,
    pub secrets: Vec<SuspectedSecret>,
    /// Env entries we did NOT flag. Carried so `adopt` can hand them to the
    /// hosted server unchanged, and so the report can say how many values it
    /// looked at without moving.
    pub other_env: BTreeMap<String, String>,
}

impl FoundServer {
    pub fn has_cleartext_credential(&self) -> bool {
        !self.secrets.is_empty()
    }
}

/// Every place we looked, whether or not anything was there.
///
/// 🔴 Absent files are reported too. "We found nothing" and "we did not look"
/// are different sentences, and only one of them means the machine is clean.
#[derive(Debug, Clone)]
pub struct ScannedSource {
    pub client_id: String,
    pub client_display: String,
    pub location_id: String,
    pub path: Option<PathBuf>,
    pub status: SourceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceStatus {
    /// Read and parsed. `servers` counts what came out of it.
    Read { servers: usize },
    /// The file is not there. The normal case for a client that is not installed.
    Absent,
    /// 🔴 The path itself could not be resolved (no home directory, Claude
    /// Desktop not installed). Reported, not skipped.
    Unresolvable { reason: String },
    /// 🔴 The file exists and could not be read or parsed. Carries the reason —
    /// including the line and column, because a hand-written JSON comment or a
    /// trailing comma is the single most common cause and the only actionable
    /// answer is where it is (14.C1).
    Unusable { reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    pub sources: Vec<ScannedSource>,
    pub servers: Vec<FoundServer>,
}

impl ScanReport {
    pub fn with_cleartext(&self) -> impl Iterator<Item = &FoundServer> {
        self.servers.iter().filter(|s| s.has_cleartext_credential())
    }
    pub fn unusable(&self) -> impl Iterator<Item = &ScannedSource> {
        self.sources
            .iter()
            .filter(|s| matches!(s.status, SourceStatus::Unusable { .. }))
    }
}

// ---------------------------------------------------------------------------
// where to look
// ---------------------------------------------------------------------------

/// The roots a scan resolves paths against.
///
/// Passed in rather than read from the process so the whole scan is drivable
/// from a test with a temporary directory — the alternative, overriding `HOME`,
/// races with every other test in the binary.
#[derive(Debug, Clone)]
pub struct ScanRoots {
    pub home: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    /// Claude Desktop's config file, already resolved by the module that owns
    /// that knowledge. `None` when Desktop is not installed on this machine.
    pub claude_desktop_config: Option<PathBuf>,
}

impl ScanRoots {
    /// The real machine.
    pub fn for_this_machine() -> ScanRoots {
        ScanRoots {
            home: Some(crate::commands_account::resolve_user_home()),
            cwd: std::env::current_dir().ok(),
            claude_desktop_config: crate::commands_account::claude_desktop::desktop_paths()
                .map(|p| p.normal_config),
        }
    }

    fn resolve(&self, loc: &LocationShape) -> Result<PathBuf, String> {
        match loc.source {
            PathSource::HomeRelative => {
                let rel = loc.path.as_deref().ok_or_else(|| {
                    "the client table declares home_relative without a path".to_string()
                })?;
                self.home
                    .as_ref()
                    .map(|h| h.join(rel))
                    .ok_or_else(|| "this account has no resolvable home directory".to_string())
            }
            PathSource::CwdRelative => {
                let rel = loc.path.as_deref().ok_or_else(|| {
                    "the client table declares cwd_relative without a path".to_string()
                })?;
                self.cwd
                    .as_ref()
                    .map(|c| c.join(rel))
                    .ok_or_else(|| "the current directory could not be read".to_string())
            }
            PathSource::ClaudeDesktopConfig => self
                .claude_desktop_config
                .clone()
                .ok_or_else(|| "Claude Desktop is not installed on this machine".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// the scan
// ---------------------------------------------------------------------------

/// Read every known client config and report what is in them.
///
/// 🔴 The only I/O in this module, and it is `read_to_string`. See the module
/// header for the fence that keeps it that way.
pub fn scan(roots: &ScanRoots) -> ScanReport {
    let t = table();
    let mut report = ScanReport::default();

    for client in &t.clients {
        let shape = client.entry_shape.as_ref().unwrap_or(&t.entry_shape);
        for loc in &client.locations {
            let path = match roots.resolve(loc) {
                Ok(p) => p,
                Err(reason) => {
                    report.sources.push(ScannedSource {
                        client_id: client.id.clone(),
                        client_display: client.display.clone(),
                        location_id: loc.id.clone(),
                        path: None,
                        status: SourceStatus::Unresolvable { reason },
                    });
                    continue;
                }
            };
            let (status, mut found) = read_and_scan(
                &path,
                client,
                shape,
                loc,
                &t.credential_hints,
                &t.managed_entry_name,
            );
            report.sources.push(ScannedSource {
                client_id: client.id.clone(),
                client_display: client.display.clone(),
                location_id: loc.id.clone(),
                path: Some(path),
                status,
            });
            report.servers.append(&mut found);
        }
    }
    report
}

fn read_and_scan(
    path: &Path,
    client: &ClientShape,
    shape: &EntryShape,
    loc: &LocationShape,
    hints: &CredentialHints,
    managed: &str,
) -> (SourceStatus, Vec<FoundServer>) {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (SourceStatus::Absent, vec![])
        }
        Err(e) => {
            return (
                SourceStatus::Unusable {
                    reason: format!("cannot read this file: {e}"),
                },
                vec![],
            )
        }
    };
    if raw.trim().is_empty() {
        return (SourceStatus::Read { servers: 0 }, vec![]);
    }
    // 🔴 The parse error is passed through verbatim. serde_json says "expected
    // value at line 7 column 3", and for the two overwhelmingly common causes —
    // a `//` comment someone added by hand, a trailing comma — that line number
    // IS the fix. 🚫 Never rewrite this into "invalid config": that turns a
    // 10-second edit into a support ticket (14.C1).
    let doc: Value = match serde_json::from_str(crate::strip_bom(&raw)) {
        Ok(v) => v,
        Err(e) => {
            return (
                SourceStatus::Unusable {
                    reason: format!(
                        "this file is not valid JSON: {e}. \
                         MCP client configs are strict JSON — comments and trailing commas are \
                         not allowed. Fix that line and run `aikey mcp scan` again."
                    ),
                },
                vec![],
            )
        }
    };

    let mut out = Vec::new();
    for pointer in &loc.server_maps {
        for (scope, map) in resolve_pointer(&doc, pointer, loc.id.as_str()) {
            let Some(entries) = map.as_object() else {
                continue;
            };
            for (name, entry) in entries {
                out.push(read_entry(
                    client, shape, hints, managed, path, &scope, name, entry,
                ));
            }
        }
    }
    (SourceStatus::Read { servers: out.len() }, out)
}

/// Walk a `["projects", "*", "mcpServers"]` style pointer, yielding
/// (scope-label, value) for every match.
///
/// A `*` matches every key at that level and the matched key becomes the scope
/// the report prints, so the user sees WHICH project a server belongs to
/// without this code knowing any project's name.
fn resolve_pointer<'a>(
    doc: &'a Value,
    pointer: &[String],
    default_scope: &str,
) -> Vec<(String, &'a Value)> {
    let mut frontier: Vec<(String, &Value)> = vec![(default_scope.to_string(), doc)];
    for seg in pointer {
        let mut next = Vec::new();
        for (scope, node) in frontier {
            let Some(obj) = node.as_object() else {
                continue;
            };
            if seg == "*" {
                for (k, v) in obj {
                    next.push((k.clone(), v));
                }
            } else if let Some(v) = obj.get(seg) {
                next.push((scope, v));
            }
        }
        frontier = next;
    }
    frontier
}

fn read_entry(
    client: &ClientShape,
    shape: &EntryShape,
    hints: &CredentialHints,
    managed: &str,
    path: &Path,
    scope: &str,
    name: &str,
    entry: &Value,
) -> FoundServer {
    let obj = entry.as_object();
    let get_str = |k: &str| -> Option<String> {
        obj.and_then(|o| o.get(k))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let get_map = |k: &str| -> BTreeMap<String, String> {
        obj.and_then(|o| o.get(k))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };

    let command = get_str(&shape.command);
    let url = get_str(&shape.url);
    let declared = get_str(&shape.transport);

    let transport = match (command.as_deref(), url.as_deref()) {
        (Some(cmd), _) if !cmd.trim().is_empty() => Transport::Stdio {
            command: cmd.to_string(),
            args: obj
                .and_then(|o| o.get(&shape.args))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        },
        (_, Some(u)) if !u.trim().is_empty() => Transport::Remote {
            url: u.to_string(),
            // No `type` at all is how the oldest configs in the wild are
            // written, and they mean HTTP.
            kind: declared.unwrap_or_else(|| "http".to_string()),
        },
        _ => Transport::Unrecognised {
            // 🔴 Says what it looked for. "Unrecognised" on its own sends the
            // user to read our source code.
            reason: format!(
                "this entry has neither a `{}` nor a `{}`, so this build cannot tell how it is \
                 reached. It is left exactly as it is; nothing about it was changed.",
                shape.command, shape.url
            ),
        },
    };

    let mut secrets = Vec::new();
    let mut other_env = BTreeMap::new();
    // 🔴 The gateway entry we wrote ourselves is not a finding. Its bearer IS a
    // credential and the patterns match it correctly — but reporting it would
    // tell the user that adopting made things worse, and `adopt` would then try
    // to adopt it (14.C6). 🚫 Do not "fix" this by loosening the patterns; the
    // patterns are right, this entry is just ours.
    let is_managed = name == managed;
    for (carrier, field) in [
        (Carrier::Env, shape.env.as_str()),
        (Carrier::Header, shape.headers.as_str()),
    ] {
        if is_managed {
            break;
        }
        for (k, v) in get_map(field) {
            match classify(&k, &v, hints) {
                Some(reason) => secrets.push(SuspectedSecret {
                    key: k,
                    carrier,
                    reason,
                    value: v,
                }),
                None => {
                    if carrier == Carrier::Env {
                        other_env.insert(k, v);
                    }
                }
            }
        }
    }

    FoundServer {
        managed_by_aikey: is_managed,
        client_id: client.id.clone(),
        client_display: client.display.clone(),
        scope: scope.to_string(),
        path: path.to_path_buf(),
        name: name.to_string(),
        transport,
        secrets,
        other_env,
    }
}

// ---------------------------------------------------------------------------
// credential suspicion + masking (tasks 14.1b / 14.1c)
// ---------------------------------------------------------------------------

/// Decide whether one key/value pair looks like a credential.
///
/// 🔴 A SUSPICION, not a verdict. `adopt` asks the user about every hit, which
/// is what keeps `LOG_LEVEL=debug` from being swept into the vault if somebody
/// ever adds a pattern loose enough to catch it (14.C4) — and what keeps the
/// cost of a loose pattern at "one extra question" instead of "we moved a
/// setting and the server stopped working".
fn classify(key: &str, value: &str, hints: &CredentialHints) -> Option<HintReason> {
    if value.trim().is_empty() {
        // An empty value is not a secret, whatever it is called. Flagging it
        // would produce a finding a user cannot act on.
        return None;
    }
    let upper = key.to_ascii_uppercase();
    for p in &hints.key_patterns {
        if glob_match(p, &upper) {
            return Some(HintReason::KeyPattern(p.clone()));
        }
    }
    for p in &hints.value_patterns {
        if glob_match(p, value) {
            return Some(HintReason::ValuePattern(p.clone()));
        }
    }
    None
}

/// `*`-only glob. Case-sensitive; callers upper-case the key first.
///
/// 🔴 Hand-written rather than a glob crate: the patterns are ours, they use
/// exactly one metacharacter, and a dependency that also understands `?`, `[]`
/// and `**` would silently give the table a bigger language than its author
/// tested against.
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    // A pattern not starting with `*` must match at the very front.
    if let Some(first) = parts.first() {
        if !first.is_empty() {
            match rest.strip_prefix(first) {
                Some(r) => rest = r,
                None => return false,
            }
        }
    }
    // ...and one not ending with `*` must reach the very end.
    if let Some(last) = parts.last() {
        if !last.is_empty() {
            match rest.strip_suffix(last) {
                Some(r) => rest = r,
                None => return false,
            }
        }
    }
    for mid in &parts[1..parts.len().saturating_sub(1)] {
        if mid.is_empty() {
            continue;
        }
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

/// Render a secret for a report that will be screenshotted (task 14.1c, I22).
///
/// First four and last four characters, nothing in between. 🔴 The middle is a
/// FIXED-width run of asterisks, not one per hidden character: a proportional
/// mask leaks the length, and length is most of what an attacker needs to tell
/// a 40-character PAT from a 6-character staging password.
///
/// A connection string is masked differently, and that is the point rather than
/// a special case — see [`mask_connection_string`].
pub fn mask_secret(value: &str) -> String {
    if let Some(masked) = mask_connection_string(value) {
        return masked;
    }
    let chars: Vec<char> = value.chars().collect();
    // Below thirteen characters, showing eight of them shows nearly all of it.
    if chars.len() < 13 {
        return "*".repeat(8);
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}****…****{tail}")
}

/// `postgres://app:hunter2@prod-db:5432/app?sslmode=require`
///   → `postgres://app:****@prod-db:5432/app?…`
///
/// 🔴 Why this is worth the extra code: the single most valuable line the
/// report prints is "this one points at **prod-db**". Masking the whole value
/// throws that away and the finding stops landing. So the password is removed
/// and the host is kept — and the query string is dropped whole, because
/// tokens hide in query strings and no rule here could promise otherwise.
fn mask_connection_string(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    if scheme.is_empty() || scheme.contains(char::is_whitespace) {
        return None;
    }
    let (authority, tail) = match rest.split_once('/') {
        Some((a, t)) => (a, Some(t)),
        None => (rest, None),
    };
    let (userinfo, host) = authority.split_once('@')?;
    let (user, _password) = userinfo.split_once(':')?;
    let mut out = format!("{scheme}://{user}:****@{host}");
    if let Some(tail) = tail {
        let path = tail.split(['?', '#']).next().unwrap_or("");
        out.push('/');
        out.push_str(path);
        if tail.contains('?') || tail.contains('#') {
            out.push_str("?…");
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// the command (task 14.1d) — 🔴 deliberately IN THIS FILE
// ---------------------------------------------------------------------------
//
// The renderer lives beside the reader rather than in `commands_mcp.rs`, and
// the reason is the fence: `scan_module_makes_no_write_calls` allowlists what
// this WHOLE FILE may name, so "the scan path is read-only" is a property of a
// file boundary instead of a hand-drawn list of function names somebody has to
// remember to extend. A helper added six months from now is covered because it
// is here; one added in `commands_mcp.rs` would not be, which is exactly why
// nothing about scanning is there.

/// `aikey mcp scan` — inventory the MCP servers this machine already has.
///
/// 🔴 READ-ONLY, and that is a checked property, not a promise: everything this
/// function does beyond printing happens inside `crate::mcp_scan`, whose one
/// filesystem call is `read_to_string`. The fence
/// `scan_command_makes_no_write_calls` allowlists what either may name.
///
/// Why read-only matters more here than the code cost of proving it: this is
/// the command a customer runs first, often on a machine they have not decided
/// to trust us with yet, and they run it expecting nothing to change. One
/// surprise write and they never run the second command.
///
/// 🔴 Zero password. It never opens the vault — there is nothing to decrypt,
/// because everything it reads is already in cleartext. That is the finding.
pub fn cmd_scan(json: bool) -> Result<(), String> {
    let report = scan(&ScanRoots::for_this_machine());

    if json {
        // `success` exits the process, so nothing after this runs in JSON mode.
        crate::json_output::success(scan_report_json(&report));
    }
    print!("{}", render_scan(&report));
    Ok(())
}

/// The machine-readable form.
///
/// 🔴 Masked here too. A JSON mode that printed raw secrets would be the
/// obvious way to get them back — and it is the mode that ends up piped into a
/// log file or a CI artifact, which is worse than a screenshot.
fn scan_report_json(report: &ScanReport) -> serde_json::Value {
    let sources: Vec<serde_json::Value> = report
        .sources
        .iter()
        .map(|s| {
            let (status, detail) = match &s.status {
                SourceStatus::Read { servers } => ("read", format!("{servers} server(s)")),
                SourceStatus::Absent => ("absent", String::new()),
                SourceStatus::Unresolvable { reason } => ("unresolvable", reason.clone()),
                SourceStatus::Unusable { reason } => ("unusable", reason.clone()),
            };
            serde_json::json!({
                "client": s.client_id,
                "location": s.location_id,
                "path": s.path.as_ref().map(|p| p.display().to_string()),
                "status": status,
                "detail": detail,
            })
        })
        .collect();
    let servers: Vec<serde_json::Value> = report
        .servers
        .iter()
        .map(|s| {
            let (transport, target) = match &s.transport {
                Transport::Stdio { command, args } => {
                    ("stdio", format!("{} {}", command, args.join(" ")))
                }
                Transport::Remote { url, kind } => (kind.as_str(), url.clone()),
                Transport::Unrecognised { reason } => ("unrecognised", reason.clone()),
            };
            serde_json::json!({
                "client": s.client_id,
                "scope": s.scope,
                "path": s.path.display().to_string(),
                "name": s.name,
                "transport": transport,
                "target": target.trim(),
                "suspected_credentials": s.secrets.iter().map(|c| serde_json::json!({
                    "key": c.key,
                    "carrier": match c.carrier {
                        Carrier::Env => "env",
                        Carrier::Header => "header",
                    },
                    "masked": c.masked(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "clients_known_to_this_build": known_clients()
            .into_iter().map(|(id, display)| serde_json::json!({"id": id, "display": display}))
            .collect::<Vec<_>>(),
        "sources": sources,
        "servers": servers,
        "servers_with_cleartext_credentials": report.with_cleartext().count(),
    })
}

fn render_scan(report: &ScanReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    // 🔴 Files we could not read are printed FIRST and never folded into the
    // "nothing found" ending. A config with a hand-written comment in it is the
    // single most common way a scan under-reports, and a user who is told
    // "0 servers" when the truth is "one file did not parse" will conclude
    // their machine is clean (14.C1).
    let unusable: Vec<_> = report.unusable().collect();
    if !unusable.is_empty() {
        for s in &unusable {
            if let SourceStatus::Unusable { reason } = &s.status {
                let _ = writeln!(
                    out,
                    "{} {} · {}",
                    crate::symbols::WARN.s(),
                    s.client_display,
                    s.path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                );
                let _ = writeln!(out, "    {reason}");
            }
        }
        let _ = writeln!(out);
    }

    if report.servers.is_empty() {
        let _ = writeln!(
            out,
            "No MCP servers found in the client configs this build knows about."
        );
        // 🔴 Name the files. "Not found" and "found and empty" send a user to
        // different places, and a developer who has never installed Claude Code
        // needs to be told that rather than left to wonder whether the scan
        // worked (14.C10). 🚫 And nothing is created here — an absent config
        // stays absent.
        for src in &report.sources {
            if let (SourceStatus::Absent, Some(path)) = (&src.status, src.path.as_ref()) {
                let _ = writeln!(
                    out,
                    "  · {} ({}): no config file at {}",
                    src.client_display,
                    src.location_id,
                    path.display()
                );
            }
        }
        if !unusable.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{} {} file(s) above could not be read, so this is NOT a complete picture.",
                crate::symbols::WARN.s(),
                unusable.len()
            );
        }
        let _ = writeln!(out);
        print_scan_boundaries(&mut out, report);
        return out;
    }

    let with_secrets = report.with_cleartext().count();
    let _ = writeln!(
        out,
        "Found {} MCP server(s) on this machine:",
        report.servers.len()
    );
    let _ = writeln!(out);

    let mut last_header = String::new();
    for s in &report.servers {
        let header = format!("{} · {}", s.client_display, s.path.display());
        if header != last_header {
            let _ = writeln!(out, "  {header}");
            last_header = header;
        }
        let (kind, target) = match &s.transport {
            Transport::Stdio { command, args } => {
                ("stdio", format!("{} {}", command, args.join(" ")))
            }
            Transport::Remote { url, kind } => (kind.as_str(), url.clone()),
            Transport::Unrecognised { .. } => ("?", String::new()),
        };
        let _ = writeln!(out, "    {:<14} {:<6} {}", s.name, kind, target.trim());
        if s.managed_by_aikey {
            let _ = writeln!(
                out,
                "                   {} this is the AiKey gateway — already adopted",
                crate::symbols::CHECK.s()
            );
        }
        if s.scope != "user" && s.scope != "project" {
            // The `*` in the shape table matched a project directory: say which
            // one, or a developer with the same server name in five checkouts
            // cannot tell which entry is being reported.
            let _ = writeln!(out, "                   in project {}", s.scope);
        }
        if let Transport::Unrecognised { reason } = &s.transport {
            let _ = writeln!(
                out,
                "                   {} {reason}",
                crate::symbols::WARN.s()
            );
        }
        for c in &s.secrets {
            let carrier = match c.carrier {
                Carrier::Env => "env",
                Carrier::Header => "header",
            };
            let _ = writeln!(
                out,
                "                   {} {}.{} is in cleartext  ({})",
                crate::symbols::WARN.s(),
                carrier,
                c.key,
                c.masked()
            );
        }
    }
    let _ = writeln!(out);
    if with_secrets > 0 {
        let _ = writeln!(
            out,
            "{} of them carry a credential in cleartext. Move those into the vault:",
            with_secrets
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "    aikey mcp adopt");
        let _ = writeln!(out);
    }
    print_scan_boundaries(&mut out, report);
    out
}

/// The three sentences that keep this report honest (R19's boundaries).
///
/// 🔴 Printed on EVERY run, including the clean one. "We found nothing" is the
/// exact moment a user is most likely to conclude they have nothing — and the
/// two reasons that conclusion can be wrong (a client we do not read, a secret
/// our patterns do not recognise) are both invisible from here. 🚫 Never
/// shorten this to "no cleartext credentials found".
fn print_scan_boundaries(out: &mut String, report: &ScanReport) {
    use std::fmt::Write as _;
    let names: Vec<String> = known_clients().into_iter().map(|(_, d)| d).collect();
    let _ = writeln!(out, "What this scan did and did not cover:");
    let _ = writeln!(out, "  · Clients read: {}.", names.join(", "));
    let _ = writeln!(
        out,
        "    Another tool's config, or a copy you saved elsewhere, is not covered."
    );
    let _ = writeln!(
        out,
        "  · Credentials are recognised by name and by known token shapes."
    );
    let _ = writeln!(
        out,
        "    A secret in a variable we do not recognise is not listed here and"
    );
    let _ = writeln!(
        out,
        "    will still be in cleartext after `aikey mcp adopt`."
    );
    let _ = writeln!(out, "  · Nothing was changed. This command only reads.");
    for s in &report.sources {
        if let SourceStatus::Unresolvable { reason } = &s.status {
            let _ = writeln!(
                out,
                "  · {} ({}): not scanned — {reason}",
                s.client_display, s.location_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// tests + fences (tasks 14.F4 / 14.F5, failure paths 14.C1 / 14.C4 / 14.C10)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A home directory containing one `.claude.json` with the given body.
    fn home_with(body: &str) -> (tempfile::TempDir, ScanRoots) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".claude.json"), body).expect("write fixture");
        let roots = ScanRoots {
            home: Some(dir.path().to_path_buf()),
            // 🔴 No cwd and no Desktop: a test that accidentally read the
            // developer's real machine would pass or fail for reasons that have
            // nothing to do with the fixture.
            cwd: None,
            claude_desktop_config: None,
        };
        (dir, roots)
    }

    const THREE_SERVERS: &str = r#"{
      "theme": "dark",
      "mcpServers": {
        "github": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-github"],
          "env": {"GITHUB_TOKEN": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O53a91", "LOG_LEVEL": "debug"}
        },
        "postgres": {
          "command": "npx",
          "env": {"DATABASE_URL": "postgres://app:hunter2@prod-db.internal:5432/app?sslmode=require"}
        },
        "weather": {"type": "http", "url": "https://weather.example.com/mcp"}
      },
      "projects": {
        "/Users/zhao/work/payments": {
          "mcpServers": {
            "jira": {"command": "jira-mcp", "env": {"JIRA_PAT": "abcd1234efgh5678ijkl"}}
          }
        }
      }
    }"#;

    #[test]
    fn finds_servers_in_the_root_map_and_in_every_project_map() {
        let (_d, roots) = home_with(THREE_SERVERS);
        let r = scan(&roots);
        let names: Vec<&str> = r.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names.len(), 4, "servers: {names:?}");
        assert!(
            names.contains(&"jira"),
            "the per-project map was not read: {names:?}"
        );
        let jira = r.servers.iter().find(|s| s.name == "jira").unwrap();
        // The `*` in the shape table names the project, so a developer with the
        // same server in five checkouts can tell which one this is.
        assert_eq!(jira.scope, "/Users/zhao/work/payments");
    }

    #[test]
    fn classifies_transports_from_the_shape_table() {
        let (_d, roots) = home_with(THREE_SERVERS);
        let r = scan(&roots);
        let get = |n: &str| r.servers.iter().find(|s| s.name == n).unwrap();
        assert!(matches!(get("github").transport, Transport::Stdio { .. }));
        match &get("weather").transport {
            Transport::Remote { url, kind } => {
                assert_eq!(url, "https://weather.example.com/mcp");
                assert_eq!(kind, "http");
            }
            other => panic!("weather: {other:?}"),
        }
    }

    /// 14.1f — an entry we cannot classify is REPORTED, never dropped.
    #[test]
    fn an_entry_we_cannot_classify_is_reported_rather_than_skipped() {
        let (_d, roots) =
            home_with(r#"{"mcpServers": {"mystery": {"transport": "carrier-pigeon"}}}"#);
        let r = scan(&roots);
        assert_eq!(r.servers.len(), 1, "the entry was silently dropped");
        match &r.servers[0].transport {
            Transport::Unrecognised { reason } => {
                // Says what it looked for, and says nothing was touched.
                assert!(reason.contains("command"), "{reason}");
                assert!(reason.contains("url"), "{reason}");
            }
            other => panic!("expected Unrecognised, got {other:?}"),
        }
    }

    /// 14.1b + 14.C4 — `LOG_LEVEL=debug` is NOT swept up with the secrets.
    #[test]
    fn flags_credentials_and_leaves_ordinary_settings_alone() {
        let (_d, roots) = home_with(THREE_SERVERS);
        let r = scan(&roots);
        let gh = r.servers.iter().find(|s| s.name == "github").unwrap();
        let keys: Vec<&str> = gh.secrets.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, vec!["GITHUB_TOKEN"]);
        assert_eq!(
            gh.other_env.get("LOG_LEVEL").map(String::as_str),
            Some("debug"),
            "LOG_LEVEL must survive as an ordinary setting, or `adopt` would move it into the vault"
        );
        assert_eq!(r.with_cleartext().count(), 3);
    }

    /// A value whose NAME gives nothing away is still caught by its shape.
    #[test]
    fn a_vendor_token_is_caught_even_when_the_variable_name_is_meaningless() {
        let (_d, roots) = home_with(
            r#"{"mcpServers":{"x":{"command":"c","env":{"GH":"ghp_zzzzzzzzzzzzzzzzzzzz"}}}}"#,
        );
        let r = scan(&roots);
        assert_eq!(r.servers[0].secrets.len(), 1);
        assert!(matches!(
            r.servers[0].secrets[0].reason,
            HintReason::ValuePattern(_)
        ));
    }

    #[test]
    fn an_empty_value_is_not_a_finding() {
        let (_d, roots) = home_with(r#"{"mcpServers":{"x":{"command":"c","env":{"API_KEY":""}}}}"#);
        assert_eq!(scan(&roots).servers[0].secrets.len(), 0);
    }

    // -- masking (task 14.1c / I22) ------------------------------------------

    #[test]
    fn masking_shows_four_characters_at_each_end_and_nothing_else() {
        let m = mask_secret("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O53a91");
        assert_eq!(m, "ghp_****…****3a91");
        assert!(!m.contains("A1b2"), "the mask leaked the body: {m}");
    }

    /// 🔴 The mask must not leak the LENGTH either: a fixed-width middle means
    /// a 40-character PAT and a 14-character staging password look the same.
    #[test]
    fn masking_does_not_leak_the_length() {
        let short = mask_secret(&format!("AAAA{}ZZZZ", "x".repeat(6)));
        let long = mask_secret(&format!("AAAA{}ZZZZ", "x".repeat(400)));
        assert_eq!(short.chars().count(), long.chars().count());
    }

    #[test]
    fn a_short_secret_is_masked_whole() {
        // Twelve characters: showing eight of them would show nearly all of it.
        assert_eq!(mask_secret("abcdefghijkl"), "********");
    }

    /// 🔴 The finding that makes the report land is "this one points at prod".
    /// Masking the whole value throws that away.
    #[test]
    fn masking_a_connection_string_keeps_the_host_and_drops_the_query() {
        let m = mask_secret("postgres://app:hunter2@prod-db.internal:5432/app?sslmode=require");
        assert_eq!(m, "postgres://app:****@prod-db.internal:5432/app?…");
        assert!(!m.contains("hunter2"));
        assert!(
            !m.contains("sslmode"),
            "the query string is dropped whole: tokens hide there and no rule here could promise otherwise"
        );
    }

    // -- failure paths --------------------------------------------------------

    /// 14.C1 — a hand-written comment or a trailing comma is reported WITH the
    /// line, and never silently skipped or "corrected".
    #[test]
    fn a_config_that_is_not_valid_json_is_reported_with_its_line_number() {
        let (dir, roots) = home_with("{\n  // my servers\n  \"mcpServers\": {}\n}\n");
        let before = std::fs::read(dir.path().join(".claude.json")).unwrap();
        let r = scan(&roots);
        let bad = r
            .unusable()
            .next()
            .expect("the broken file was skipped silently");
        let SourceStatus::Unusable { reason } = &bad.status else {
            unreachable!()
        };
        assert!(reason.contains("line 2"), "no line number in: {reason}");
        assert!(
            reason.contains("comments and trailing commas"),
            "the message must name the two causes that produce it: {reason}"
        );
        // 🚫 And it was not "fixed" for the user.
        assert_eq!(
            before,
            std::fs::read(dir.path().join(".claude.json")).unwrap()
        );
    }

    /// 14.C10 — no config file is a clear statement, and 🚫 nothing is created.
    #[test]
    fn an_absent_config_is_reported_and_no_file_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let roots = ScanRoots {
            home: Some(dir.path().to_path_buf()),
            cwd: None,
            claude_desktop_config: None,
        };
        let r = scan(&roots);
        assert!(r.servers.is_empty());
        assert!(r
            .sources
            .iter()
            .any(|s| s.client_id == "claude-code" && s.status == SourceStatus::Absent));
        assert!(
            !dir.path().join(".claude.json").exists(),
            "🔴 scan created a config file the user does not have"
        );
        let text = render_scan(&r);
        assert!(text.contains("no config file at"), "{text}");
    }

    /// An unresolvable location is reported, not swallowed.
    #[test]
    fn a_location_that_cannot_be_resolved_is_named_in_the_report() {
        let roots = ScanRoots {
            home: None,
            cwd: None,
            claude_desktop_config: None,
        };
        let r = scan(&roots);
        assert!(r
            .sources
            .iter()
            .all(|s| matches!(s.status, SourceStatus::Unresolvable { .. })));
        let text = render_scan(&r);
        assert!(text.contains("not scanned"), "{text}");
    }

    // -- fences ---------------------------------------------------------------

    /// 🔴 FENCE 14.F5 — no rendering path can print a raw credential.
    ///
    /// Drives the REAL renderer and the REAL JSON builder, then looks for the
    /// secrets in their output. Asserting on `mask_secret` alone would pass
    /// against a report that formatted the value some other way.
    #[test]
    fn fence_no_report_path_can_print_a_raw_secret() {
        let (_d, roots) = home_with(THREE_SERVERS);
        let r = scan(&roots);
        let human = render_scan(&r);
        let machine = serde_json::to_string(&scan_report_json(&r)).unwrap();
        for raw in [
            "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O53a91",
            "hunter2",
            "abcd1234efgh5678ijkl",
        ] {
            assert!(!human.contains(raw), "🔴 the human report printed {raw}");
            assert!(!machine.contains(raw), "🔴 the JSON report printed {raw}");
        }
        // ...and it did print the masked forms, or the assertions above would
        // pass against a report that printed nothing at all.
        assert!(human.contains("ghp_****…****3a91"), "{human}");
        assert!(machine.contains("ghp_****…****3a91"));
    }

    /// 🔴 FENCE 14.F4 — this module makes no write calls.
    ///
    /// An ALLOWLIST, not a denylist: every `fs::` name in the shipping half of
    /// this file must be one of the read-only ones. A denylist would pass the
    /// first write API nobody thought to forbid, which is the only kind that
    /// ever ships.
    ///
    /// 🔴 Every needle is assembled at runtime. `include_str!` reads THIS file,
    /// so a literal here would match itself and the fence would be green
    /// because of its own source.
    #[test]
    fn fence_scan_module_makes_no_write_calls() {
        let src = include_str!("mcp_scan.rs");
        let test_marker = format!("#[cfg({})]", "test");
        let end = src
            .find(&test_marker)
            .expect("the test module marker moved; this fence would silently scan nothing");
        let shipping = &src[..end];

        // The only filesystem functions the scan path may name.
        let allowed = ["read_to_string"];
        let fs_prefix = format!("fs{}", "::");
        // 🔴 Comment lines are skipped, and only comment lines: this module's
        // own header NAMES the write APIs it forbids, and a fence that went red
        // on the documentation explaining it would be deleted within a week.
        let is_comment = |l: &str| {
            let t = l.trim_start();
            t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
        };
        let mut offenders: Vec<String> = Vec::new();
        for (lineno, line) in shipping.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            let mut rest = line;
            while let Some(i) = rest.find(&fs_prefix) {
                let after = &rest[i + fs_prefix.len()..];
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !allowed.contains(&name.as_str()) {
                    offenders.push(format!("line {}: {}{}", lineno + 1, fs_prefix, name));
                }
                rest = after;
            }
        }
        // Ways to write that never spell `fs::`.
        for needle in [
            format!("File{}create", "::"),
            "OpenOptions".to_string(),
            format!("atomic{}write", "_"),
            format!("Command{}new", "::"),
            format!("{}(&path, ", "save"),
        ] {
            for (lineno, line) in shipping.lines().enumerate() {
                if !is_comment(line) && line.contains(&needle) {
                    offenders.push(format!("line {}: {}", lineno + 1, needle));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "🔴 `aikey mcp scan` must be read-only (task 14.1d / I22). Found:\n  {}\n\
             Users run this command expecting nothing to change; a write here — even a \
             harmless-looking cache — is how they stop running it.",
            offenders.join("\n  ")
        );
    }

    /// 🔴 The raw value has exactly one door, and nothing in the scan path opens it.
    #[test]
    fn fence_the_raw_secret_is_only_reachable_through_the_vault_door() {
        let src = include_str!("mcp_scan.rs");
        let test_marker = format!("#[cfg({})]", "test");
        let shipping = &src[..src.find(&test_marker).unwrap()];
        let door = format!("reveal_for{}vault", "_");
        let uses = shipping.matches(&door).count();
        assert_eq!(
            uses, 1,
            "🔴 `{door}` should appear exactly once in the shipping half of this file — its \
             definition. {uses} occurrences means the scan path itself can now reach the raw \
             value, which is how it ends up in a report."
        );
    }

    /// The shape table is the contract; a typo in it would only surface as
    /// "scan finds nothing" on a real machine.
    #[test]
    fn the_shape_table_parses_and_declares_the_clients_the_docs_promise() {
        let ids: Vec<String> = known_clients().into_iter().map(|(id, _)| id).collect();
        assert!(ids.contains(&"claude-code".to_string()), "{ids:?}");
        assert!(ids.contains(&"claude-desktop".to_string()), "{ids:?}");
        // 🔴 Every client must declare at least one location, or it silently
        // contributes nothing while appearing in the report's honesty footer —
        // which would make that footer a lie.
        for c in &table().clients {
            assert!(!c.locations.is_empty(), "client {} has no locations", c.id);
            for l in &c.locations {
                assert!(
                    !l.server_maps.is_empty(),
                    "{}/{} has no server_maps",
                    c.id,
                    l.id
                );
                if matches!(l.source, PathSource::HomeRelative | PathSource::CwdRelative) {
                    assert!(l.path.is_some(), "{}/{} needs a path", c.id, l.id);
                }
            }
        }
    }

    #[test]
    fn glob_matches_only_the_star() {
        assert!(glob_match("*TOKEN*", "GITHUB_TOKEN"));
        assert!(glob_match("*_KEY", "OPENAI_KEY"));
        assert!(!glob_match("*_KEY", "KEYCHAIN"));
        assert!(glob_match("ghp_*", "ghp_abc"));
        assert!(!glob_match("ghp_*", "xghp_abc"));
        assert!(glob_match("*://*:*@*", "postgres://a:b@h"));
        assert!(!glob_match("*://*:*@*", "https://example.com/mcp"));
        // `?` and `[` carry no meaning here — a bigger language than the table
        // was written against is how a pattern quietly starts matching more.
        assert!(!glob_match("a?c", "abc"));
    }
}
