//! `aikey mcp adopt` — move the credentials this machine already has into the
//! vault, and rewrite the config that held them.
//!
//! 阶段8-平台化 · MCP 网关 · P14 tasks 14.2 / 14.4
//! spec: `workflow/CI/requirements/2026-08-20-mcp-gateway.md` (R19, R21, R21a)
//! design: `roadmap20260320/技术实现/阶段8-平台化/MCP网关/20260820-MCP网关-技术方案.md` §5.6
//!
//! # What "adopted" has to mean
//!
//! 🔴 Copying the secret into the vault is NOT adoption. If the plaintext stays
//! where it was, the machine has one clean path and one dirty path — and it
//! **looks** like it has been dealt with, which is worse than not having started
//! (R19). So the credential move and the config rewrite are one action: either
//! both happened, or neither did and the file is byte-identical to before.
//!
//! # The two stores problem, stated honestly
//!
//! The vault is SQLite and the client config is a file. There is no transaction
//! across them, so this is a saga with compensation, ordered so the survivable
//! failure is the one that happens:
//!
//!   1. parse every target file — fail here and nothing has been touched
//!   2. snapshot every file this will write
//!   3. store the credentials (vault)
//!   4. register the backends (`~/.aikey/mcp.json`)
//!   5. rewrite the client configs
//!   on failure in 4 or 5 → restore every snapshot AND delete the credentials
//!                          this run created (never ones that already existed)
//!
//! 🔴 The order is not arbitrary. The reverse — rewrite first, store second —
//! leaves "config points at the gateway, secret was never stored", and since
//! the plaintext we just deleted was the ONLY copy, the secret is gone for
//! good. This order's bad state is "secret stored, config unchanged", which is
//! recoverable: the next run finds the alias already present, reuses it, and
//! finishes the rewrite. **Idempotence is the recovery** (14.C6), which is why
//! it is a requirement here and not a nicety.
//!
//! # One password, once
//!
//! Storing a secret needs the master password, so `adopt` asks — once, for the
//! whole run, no matter how many credentials move. 🔴 That does not weaken the
//! zero-password rule: that rule is about the WRAPPER path (every `claude`
//! launch), and this is a command a human types on purpose. `scan`, `list`,
//! `remove`, `test` and `review` all remain password-free.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::commands_mcp::{apply_add_core, AddRequest, McpConfig};
use crate::mcp_scan::{FoundServer, ScanReport, Transport};

/// Why a server found by `scan` is not going to be adopted.
///
/// 🔴 Every one of these is REPORTED. A server that is quietly left behind is a
/// server the user believes has been dealt with — and its credential is still
/// in cleartext (R19's second boundary, made concrete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// It is the gateway entry a previous run wrote.
    AlreadyAdopted,
    /// Nothing to move: no credential was recognised in it.
    ///
    /// 🔴 "Nothing we RECOGNISED". The report says so in those words, because a
    /// secret in a variable our patterns do not know is still sitting there.
    NoCleartextCredential,
    /// A remote server. `~/.aikey/mcp.json` hosts child processes only.
    NotStdio { kind: String },
    /// It carries settings that are not credentials, and the local config has
    /// nowhere to put them.
    NonSecretEnv { vars: Vec<String> },
    /// More than one secret on one server; the local config holds one.
    MultipleSecrets { vars: Vec<String> },
    /// We could not tell how it is reached.
    Unrecognised,
    /// The user did not pick it.
    NotSelected,
}

impl SkipReason {
    /// 🔴 The sentence the user reads. Every one names what is still true of the
    /// machine afterwards, because "skipped" on its own reads as "fine".
    pub fn explain(&self, name: &str) -> String {
        match self {
            SkipReason::AlreadyAdopted => {
                format!("{name}: this is the AiKey gateway entry — already adopted.")
            }
            SkipReason::NoCleartextCredential => format!(
                "{name}: no credential we RECOGNISE. Nothing was moved. If it holds a secret in \
                 a variable we do not know, that secret is still in cleartext."
            ),
            SkipReason::NotStdio { kind } => format!(
                "{name}: it is a remote ({kind}) server, and the local gateway hosts child \
                 processes only. Its config was left exactly as it is."
            ),
            SkipReason::NonSecretEnv { vars } => format!(
                "{name}: it also needs settings that are not credentials ({}), and the local \
                 gateway config has nowhere to carry them — adopting it would start the server \
                 without them. Left alone rather than half-migrated.",
                vars.join(", ")
            ),
            SkipReason::MultipleSecrets { vars } => format!(
                "{name}: it carries more than one credential ({}), and one hosted server takes \
                 one. Left alone rather than moving half of them.",
                vars.join(", ")
            ),
            SkipReason::Unrecognised => {
                format!("{name}: this build cannot tell how it is reached, so it was not touched.")
            }
            SkipReason::NotSelected => format!("{name}: not selected."),
        }
    }
}

/// One server that WILL be adopted.
///
/// 🔴 No `Display`, and `Debug` redacts — it carries the plaintext on its way to
/// the vault, and the day this lands in a panic message is the day the command
/// does the opposite of its job.
#[derive(Clone)]
pub struct AdoptItem {
    pub name: String,
    pub scope: String,
    pub path: PathBuf,
    pub command: String,
    pub args: Vec<String>,
    /// Vault alias this credential will live under.
    pub alias: String,
    /// Environment variable the hosted server expects it in.
    pub env_var: String,
    secret: String,
}

impl AdoptItem {
    /// The only rendering that exists.
    pub fn masked(&self) -> String {
        crate::mcp_scan::mask_secret(&self.secret)
    }
    /// For the one caller that must have it: the vault write.
    pub fn reveal_for_vault(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for AdoptItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdoptItem")
            .field("name", &self.name)
            .field("alias", &self.alias)
            .field("env_var", &self.env_var)
            .field("secret", &self.masked())
            .finish()
    }
}

/// What a run is going to do, computed before anything happens.
#[derive(Debug, Clone)]
pub struct AdoptPlan {
    pub items: Vec<AdoptItem>,
    pub skipped: Vec<(String, SkipReason)>,
    /// Config files that will be rewritten. Deduplicated, in a stable order.
    pub files: Vec<PathBuf>,
}

impl AdoptPlan {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Builds the plan. 🔴 Pure: a report in, a plan out, no I/O and no prompts —
/// so the rules below are testable without a vault, a proxy or a home directory.
pub fn plan(report: &ScanReport, only: &[String]) -> AdoptPlan {
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();

    for s in &report.servers {
        if let Some(reason) = skip_reason(s, only) {
            skipped.push((s.name.clone(), reason));
            continue;
        }
        // Exactly one secret, by the checks above.
        let secret = &s.secrets[0];
        items.push(AdoptItem {
            name: s.name.clone(),
            scope: s.scope.clone(),
            path: s.path.clone(),
            command: match &s.transport {
                Transport::Stdio { command, .. } => command.clone(),
                _ => unreachable!("skip_reason admits only stdio"),
            },
            args: match &s.transport {
                Transport::Stdio { args, .. } => args.clone(),
                _ => Vec::new(),
            },
            alias: vault_alias(s, &secret.key),
            env_var: secret.key.clone(),
            secret: secret.reveal_for_vault().to_string(),
        });
        if !files.contains(&s.path) {
            files.push(s.path.clone());
        }
    }
    AdoptPlan {
        items,
        skipped,
        files,
    }
}

fn skip_reason(s: &FoundServer, only: &[String]) -> Option<SkipReason> {
    if s.managed_by_aikey {
        return Some(SkipReason::AlreadyAdopted);
    }
    if !only.is_empty() && !only.iter().any(|n| n == &s.name) {
        return Some(SkipReason::NotSelected);
    }
    match &s.transport {
        Transport::Unrecognised { .. } => return Some(SkipReason::Unrecognised),
        Transport::Remote { kind, .. } => return Some(SkipReason::NotStdio { kind: kind.clone() }),
        Transport::Stdio { .. } => {}
    }
    if s.secrets.is_empty() {
        return Some(SkipReason::NoCleartextCredential);
    }
    if s.secrets.len() > 1 {
        return Some(SkipReason::MultipleSecrets {
            vars: s.secrets.iter().map(|c| c.key.clone()).collect(),
        });
    }
    // 🔴 A server whose other settings cannot travel is NOT adopted.
    //
    // `~/.aikey/mcp.json` deliberately has no `env` map — its absence is what
    // stops a secret being written there by hand (P5). That means an ordinary
    // setting like `GITHUB_HOST` has nowhere to go, and adopting anyway would
    // start the server WITHOUT it: the tools would appear and then misbehave,
    // which is worse than not adopting. 🚫 Do not "fix" this by adding an env
    // map here — that reopens the hole P5 closed. The open question (carry
    // non-secret settings safely, or keep refusing) is recorded in tasks 14.2.
    if !s.other_env.is_empty() {
        return Some(SkipReason::NonSecretEnv {
            vars: s.other_env.keys().cloned().collect(),
        });
    }
    None
}

/// The vault alias a credential lands under.
///
/// 🔴 DETERMINISTIC, because that is what makes a second run idempotent: the
/// same server produces the same alias, so a run interrupted between "stored"
/// and "rewritten" finds its own work and finishes it instead of storing a
/// second copy under a new name (14.C6).
///
/// The scope is folded in for anything but the user-level map, because the same
/// server name can legitimately appear in several projects with DIFFERENT
/// secrets — and one alias for two secrets would silently overwrite one of them.
pub fn vault_alias(s: &FoundServer, var: &str) -> String {
    let base = format!("mcp-{}-{}", sanitize(&s.name), sanitize(var));
    if s.scope == "user" || s.scope == "project" {
        return base;
    }
    format!("{base}-{}", short_hash(&s.scope))
}

fn sanitize(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut last_dash = false;
    for c in v.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// A short, stable discriminator for a scope. 🔴 FNV-1a rather than a crypto
/// hash: it is a namespacing suffix a human reads in `aikey list`, not a
/// security boundary, and it must produce the same six characters on every
/// platform and every build.
fn short_hash(v: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in v.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:06x}", h & 0xff_ffff)
}

// ---------------------------------------------------------------------------
// rewriting the client config
// ---------------------------------------------------------------------------

/// The gateway entry `adopt` writes.
///
/// 🔴 One entry for the whole machine, not one per adopted server: the gateway
/// serves every hosted tool at a single toolset. That means adoption COLLAPSES
/// scope — a server that was configured for one project becomes reachable
/// wherever this entry is. Stated in the output rather than discovered later.
pub fn gateway_entry(endpoint: &str, bearer: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "http",
        "url": endpoint,
        "headers": { "Authorization": format!("Bearer {bearer}") },
    })
}

/// Removes the adopted entries from one parsed document and installs the
/// gateway entry in its root server map.
///
/// 🔴 Pure, and it takes the whole document: every key it does not name is
/// carried through untouched. That is the property fence 14.F6 asserts — a user
/// whose theme, recent projects and approvals were lost to a "migration" would
/// never let us near their machine again.
pub fn rewrite_document(
    doc: &mut serde_json::Value,
    server_maps: &[Vec<String>],
    adopted: &[String],
    managed_name: &str,
    entry: serde_json::Value,
) -> usize {
    let mut removed = 0;
    for pointer in server_maps {
        remove_from_pointer(doc, pointer, adopted, &mut removed);
    }
    if removed == 0 {
        return 0;
    }
    // The gateway entry goes in the ROOT map, which is the one every client
    // reads unconditionally.
    let root = doc
        .as_object_mut()
        .expect("callers pass a JSON object")
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(map) = root.as_object_mut() {
        map.insert(managed_name.to_string(), entry);
    }
    removed
}

fn remove_from_pointer(
    node: &mut serde_json::Value,
    pointer: &[String],
    adopted: &[String],
    removed: &mut usize,
) {
    let Some(seg) = pointer.first() else {
        // Reached the server map itself.
        if let Some(map) = node.as_object_mut() {
            for name in adopted {
                if map.remove(name).is_some() {
                    *removed += 1;
                }
            }
        }
        return;
    };
    let rest = &pointer[1..];
    let Some(obj) = node.as_object_mut() else {
        return;
    };
    if seg == "*" {
        for (_, v) in obj.iter_mut() {
            remove_from_pointer(v, rest, adopted, removed);
        }
    } else if let Some(v) = obj.get_mut(seg) {
        remove_from_pointer(v, rest, adopted, removed);
    }
}

// ---------------------------------------------------------------------------
// executing the plan
// ---------------------------------------------------------------------------

/// What a completed run did.
#[derive(Debug, Clone, Default)]
pub struct AdoptOutcome {
    pub credentials_stored: Vec<String>,
    pub credentials_reused: Vec<String>,
    pub backends_registered: Vec<String>,
    pub files_rewritten: Vec<PathBuf>,
    pub entries_removed: usize,
}

/// The vault operations adoption needs.
///
/// 🔴 A port, so the saga above can be driven — including its ROLLBACK — without
/// a vault, a password or a home directory. The alternative was a test that only
/// exercised the happy path, and what this code does when a step FAILS is the
/// whole point of it (I20/I21). The production implementation holds the master
/// password and calls the same `store_credential` `aikey mcp add` uses; there is
/// no second encryption path.
pub trait AdoptVault {
    fn contains(&self, alias: &str) -> bool;
    fn store(&mut self, alias: &str, secret: &str) -> Result<(), String>;
    fn delete(&mut self, alias: &str) -> Result<(), String>;
}

/// The real vault.
pub struct RealVault {
    password: Option<SecretString>,
    aliases: Vec<String>,
}

impl RealVault {
    /// 🔴 The alias list is read ONCE, up front and without the master password,
    /// so "is this alias already here" is decided before anything is written and
    /// cannot change halfway through the run.
    pub fn open(password: Option<SecretString>) -> RealVault {
        RealVault {
            password,
            aliases: existing_aliases(),
        }
    }
}

impl AdoptVault for RealVault {
    fn contains(&self, alias: &str) -> bool {
        self.aliases.iter().any(|a| a == alias)
    }
    fn store(&mut self, alias: &str, secret: &str) -> Result<(), String> {
        let Some(pw) = self.password.as_ref() else {
            return Err(format!(
                "'{alias}' needs a new vault entry but no master password was provided"
            ));
        };
        crate::commands_mcp::store_credential_for_adopt(
            alias,
            &SecretString::from(secret.to_string()),
            pw,
        )
    }
    fn delete(&mut self, alias: &str) -> Result<(), String> {
        crate::storage::delete_entry(alias)
    }
}

/// Runs the plan, all or nothing.
pub fn execute(
    plan: &AdoptPlan,
    endpoint: &str,
    bearer: &str,
    mcp_config_path: &Path,
    vault: &mut dyn AdoptVault,
) -> Result<AdoptOutcome, String> {
    let mut outcome = AdoptOutcome::default();

    // ── 1. Pre-flight ──────────────────────────────────────────────────────
    //
    // 🔴 Every target file is parsed BEFORE anything is written. A file we
    // cannot parse must stop the run while the machine is still untouched —
    // discovering it halfway through means exercising the rollback path for a
    // problem we could have seen from a standing start.
    let mut docs: Vec<(PathBuf, serde_json::Value)> = Vec::new();
    for f in &plan.files {
        let doc = crate::commands_account::claude_desktop::read_json_object_for_adopt(f)?;
        docs.push((f.clone(), doc));
    }

    let mcp_path = mcp_config_path.to_path_buf();
    let mut mcp_cfg: McpConfig = crate::commands_mcp::load(&mcp_path)?;

    // ── 2. Snapshot ────────────────────────────────────────────────────────
    let mut snapshots: Vec<crate::commands_account::claude_desktop::Snapshot> = plan
        .files
        .iter()
        .map(|f| crate::commands_account::claude_desktop::Snapshot::take(f))
        .collect();
    snapshots.push(crate::commands_account::claude_desktop::Snapshot::take(
        &mcp_path,
    ));

    // ── 3. Credentials ─────────────────────────────────────────────────────
    //
    // 🔴 Aliases that already exist are REUSED, not rewritten: an alias present
    // from an interrupted earlier run is this run's own work, and overwriting it
    // would be pointless; an alias present for another reason is the user's, and
    // overwriting it would destroy a secret we did not create.
    let mut created: Vec<String> = Vec::new();
    for item in &plan.items {
        if vault.contains(&item.alias) {
            outcome.credentials_reused.push(item.alias.clone());
            continue;
        }
        if let Err(e) = vault.store(&item.alias, item.reveal_for_vault()) {
            // Nothing else has been written yet; undo only what this loop did.
            rollback(&snapshots, &created, vault);
            return Err(format!(
                "could not store '{}' in the vault: {e}",
                item.alias
            ));
        }
        created.push(item.alias.clone());
        outcome.credentials_stored.push(item.alias.clone());
    }

    // ── 4 + 5. Registration and rewrite, rolled back together ──────────────
    let result = (|| -> Result<(), String> {
        for item in &plan.items {
            apply_add_core(
                &mut mcp_cfg,
                &AddRequest {
                    name: item.name.clone(),
                    command: item.command.clone(),
                    args: item.args.clone(),
                    credential_alias: item.alias.clone(),
                    credential_env: item.env_var.clone(),
                    // 🔴 Replace: a second run over the same machine must
                    // converge, not refuse. That is what makes the interrupted
                    // run recoverable.
                    replace: true,
                },
            )?;
            outcome.backends_registered.push(item.name.clone());
        }
        crate::commands_mcp::save(&mcp_path, &mcp_cfg)?;

        let managed = crate::mcp_scan::managed_entry_name();
        for (path, doc) in docs.iter_mut() {
            let adopted: Vec<String> = plan
                .items
                .iter()
                .filter(|i| &i.path == path)
                .map(|i| i.name.clone())
                .collect();
            let maps = crate::mcp_scan::server_maps_for(path);
            let removed = rewrite_document(
                doc,
                &maps,
                &adopted,
                managed,
                gateway_entry(endpoint, bearer),
            );
            if removed == 0 {
                continue;
            }
            let pretty = serde_json::to_string_pretty(doc)
                .map_err(|e| format!("cannot encode {}: {e}", path.display()))?;
            crate::profile_activation::atomic_write(path, pretty.as_bytes())
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            outcome.entries_removed += removed;
            outcome.files_rewritten.push(path.clone());
        }
        Ok(())
    })();

    if let Err(e) = result {
        rollback(&snapshots, &created, vault);
        return Err(format!(
            "{e}\n  Nothing was changed: every config file was restored to its previous \
             contents and the credentials this run stored were removed."
        ));
    }
    Ok(outcome)
}

/// Puts the machine back exactly as it was.
///
/// 🔴 Deletes only the aliases THIS RUN created. An alias that already existed
/// belongs to the user (or to an earlier interrupted run of this same command),
/// and deleting it would destroy a secret whose only other copy we may have
/// just removed from their config.
fn rollback(
    snapshots: &[crate::commands_account::claude_desktop::Snapshot],
    created: &[String],
    vault: &mut dyn AdoptVault,
) {
    for s in snapshots {
        s.restore();
    }
    for alias in created {
        if let Err(e) = vault.delete(alias) {
            // 🔴 Loud. A credential left behind after a failed adopt is not
            // dangerous by itself, but a SILENT one means the next run reuses it
            // believing it was placed deliberately.
            eprintln!(
                "[aikey] warn: rolled back, but the vault entry '{alias}' could not be removed: {e}\n\
                 [aikey]       remove it with `aikey remove {alias}` if you do not want it."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// helpers the command shell needs
// ---------------------------------------------------------------------------

/// Where an adopted client should point.
pub fn endpoint() -> String {
    format!(
        "http://127.0.0.1:{}/mcp/local",
        crate::commands_proxy::proxy_port()
    )
}

/// Picks the bearer the rewritten config will carry.
///
/// 🔴 This is a real trade and it is stated in the command's output, not buried:
/// the entry we write holds an AiKey route token, which is a credential too. It
/// is a strictly smaller exposure than what it replaces — it is revocable by us,
/// it only works against `127.0.0.1`, and every call it makes is recorded —
/// whereas a GitHub PAT works from anywhere and a database password cannot be
/// revoked without changing the database. But it is not nothing: whoever can
/// read that file can spend this key's quota *on this machine*.
///
/// 🚫 There is no MCP-only token today. Minting one is a new token kind with its
/// own revocation semantics; that decision is recorded in tasks 14.2 rather than
/// taken here by default.
pub fn pick_bearer(preferred: Option<&str>) -> Result<(String, String), String> {
    let entries = crate::storage::list_entries_with_metadata_readonly()?;
    let mut candidates: Vec<(String, String)> = entries
        .iter()
        .filter_map(|e| {
            e.route_token
                .as_ref()
                .filter(|t| !t.is_empty())
                .map(|t| (e.alias.clone(), t.clone()))
        })
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    if let Some(want) = preferred {
        return candidates
            .into_iter()
            .find(|(alias, _)| alias == want)
            .ok_or_else(|| {
                format!(
                    "no key named '{want}' has a route token.\n  \
                     Run `aikey list` to see your keys, or drop --key to let this pick one."
                )
            });
    }
    candidates.into_iter().next().ok_or_else(|| {
        "this machine has no AiKey key yet, so there is no token to put in the rewritten \
         config.\n  Add one first (`aikey add <name>`), then run `aikey mcp adopt` again.\n  \
         (Nothing was changed.)"
            .to_string()
    })
}

/// The aliases already in the vault, read WITHOUT the master password.
///
/// 🔴 Read first and passed into `execute`, so the decision "is this alias
/// already here" is made before anything is written and cannot change halfway.
pub fn existing_aliases() -> Vec<String> {
    crate::storage::list_entries_with_metadata_readonly()
        .map(|v| v.into_iter().map(|e| e.alias).collect())
        .unwrap_or_default()
}

/// Servers grouped by the file they live in, for the confirmation screen.
pub fn by_file(plan: &AdoptPlan) -> BTreeMap<&Path, Vec<&AdoptItem>> {
    let mut out: BTreeMap<&Path, Vec<&AdoptItem>> = BTreeMap::new();
    for i in &plan.items {
        out.entry(i.path.as_path()).or_default().push(i);
    }
    out
}

// ---------------------------------------------------------------------------
// the command (阶段8 P14 task 14.2)
// ---------------------------------------------------------------------------

/// `aikey mcp adopt` — the second of the two steps.
///
/// 🔴 Two steps, never one. `scan` reports; `adopt` acts, and shows exactly what
/// it is about to do before it does anything. This edits files in the user's
/// home directory, and once the plaintext is gone it is gone — a machine that
/// changed things a user had not seen is a machine they stop running commands on
/// (task 14.2a).
pub fn cmd_adopt<P>(
    only: &[String],
    key: Option<&str>,
    dry_run: bool,
    assume_yes: bool,
    json: bool,
    password_provider: P,
) -> Result<(), String>
where
    P: FnOnce() -> Result<SecretString, String>,
{
    let report = crate::mcp_scan::scan(&crate::mcp_scan::ScanRoots::for_this_machine());

    // 🔴 A file we could not read stops the run. Adopting "the ones we could
    // parse" and staying quiet about the rest is how a user ends up believing a
    // machine is clean when one of its config files was never opened (14.C1).
    let unusable: Vec<_> = report.unusable().collect();
    if !unusable.is_empty() {
        let mut msg = String::from(
            "one or more client configs could not be read, so this run would not see everything \
             on this machine. Nothing was changed.\n",
        );
        for s in &unusable {
            if let crate::mcp_scan::SourceStatus::Unusable { reason } = &s.status {
                msg.push_str(&format!(
                    "  {}: {reason}\n",
                    s.path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ));
            }
        }
        return Err(msg);
    }

    let p = plan(&report, only);

    if json {
        crate::json_output::success(plan_json(&p, dry_run));
    }

    print!("{}", render_plan(&p));
    if p.is_empty() {
        return Ok(());
    }
    if dry_run {
        println!("--dry-run: nothing was changed.");
        return Ok(());
    }

    // Resolve the bearer BEFORE asking for a password: a machine with no key
    // yet cannot be adopted, and finding that out after handing over a master
    // password is the wrong order.
    let (bearer_alias, bearer) = pick_bearer(key)?;
    let ep = endpoint();

    println!("This will:");
    println!("  · move {} credential(s) into your vault", p.items.len());
    println!(
        "  · register {} server(s) with the local gateway",
        p.items.len()
    );
    println!(
        "  · rewrite {} config file(s), replacing those entries with one pointing at {ep}",
        p.files.len()
    );
    println!();
    // 🔴 Said out loud, every time. The entry we write carries an AiKey route
    // token — a smaller exposure than what it replaces (revocable, loopback
    // only, recorded) but not zero, and a user deserves to know what is now in
    // that file rather than discover it.
    println!(
        "  The rewritten entry carries your '{bearer_alias}' route token. It only works against"
    );
    println!("  127.0.0.1 and you can revoke it, unlike the credentials it replaces — but it is");
    println!("  still a credential in that file.");
    println!();
    println!("  Every adopted server becomes reachable wherever that entry is configured;");
    println!("  a server that was set up for one project is no longer limited to it.");
    println!();

    if !assume_yes && !confirm("Go ahead?")? {
        println!("Nothing was changed.");
        return Ok(());
    }

    let existing = existing_aliases();
    let password = if p.items.iter().any(|i| !existing.contains(&i.alias)) {
        Some(password_provider()?)
    } else {
        // Everything is already in the vault — an interrupted earlier run. This
        // is the recovery path, and it must not ask for a password to finish
        // work that only needs a file rewritten.
        None
    };

    let mut vault = RealVault::open(password);
    let outcome = execute(
        &p,
        &ep,
        &bearer,
        &crate::commands_mcp::config_path(),
        &mut vault,
    )?;
    print!("{}", render_outcome(&outcome, &ep));
    first_review(&outcome, assume_yes);
    Ok(())
}

/// The first look at what was just brought in (task 14.3).
///
/// # Why this happens HERE, inside adopt
///
/// 🔴 The gate is only worth having if it is crossed. A backend's tools are not
/// served until a human has looked at them, so an adoption that stopped at
/// "registered" would leave the developer with a rewritten client config and
/// ZERO tools until they happened to run another command — which is the
/// outcome R21 spends its whole argument avoiding, arrived at from a different
/// direction. So adopt registers, asks the gateway to re-read and probe NOW,
/// shows what came back, and takes the answer.
///
/// # Why it does not fail the adoption
///
/// The credentials have already moved and the config has already been rewritten
/// — that part is done and correct. If the gateway is not running there is
/// nothing to probe, and the honest thing is to say what is left to do rather
/// than to unwind a migration that succeeded.
fn first_review(outcome: &AdoptOutcome, assume_yes: bool) {
    if outcome.backends_registered.is_empty() {
        return;
    }
    let body = match crate::commands_mcp::refresh_local_manifest() {
        Ok(b) => b,
        Err(e) => {
            println!();
            println!(
                "{} The gateway did not answer that request: {e}",
                crate::symbols::WARN.s()
            );
            println!("  Your credentials are in the vault and your config is rewritten — that part is done.");
            // 🔴 Both causes, because they need different actions and the user
            // cannot tell them apart from here: a gateway that is not running,
            // and one running an older build that does not know this request.
            println!(
                "  Start the gateway — or restart it if it was already up on an older build —"
            );
            println!("  then run `aikey mcp review`. Until a person has looked at them, none of");
            println!("  these tools are served.");
            return;
        }
    };
    let doc: crate::commands_mcp::ReviewDoc = match serde_json::from_str(&body) {
        Ok(d) => d,
        Err(_) => return,
    };
    let waiting: Vec<&crate::commands_mcp::ReviewBackend> = doc
        .backends
        .iter()
        .filter(|b| b.awaiting_first_review && outcome.backends_registered.contains(&b.backend_id))
        .collect();
    if waiting.is_empty() {
        return;
    }

    println!();
    println!("Before these can be used, one look at what they claim to do.");
    println!(
        "{} A server that was ALREADY poisoned when you brought it in is only ever catchable",
        crate::symbols::WARN.s()
    );
    println!("  here. Change detection can tell you a description changed; it can never tell you");
    println!("  it started wrong. The instruction below is handed to your model verbatim.");
    println!();

    for b in &waiting {
        println!("  {}:", b.backend_id);
        for t in &b.tools {
            let kind = if t.write_op {
                "makes changes"
            } else {
                "read-only"
            };
            println!("    {:<24} {kind}", t.name);
            for line in t.served_description.lines() {
                println!("        {line}");
            }
        }
        println!();
    }

    // 🔴 Everything is already selected (14.3c). Ticking forty boxes is a review
    // people abandon, and abandoning adoption leaves the plaintext where it was
    // — trading a first-order property for a third-order one and getting
    // neither. The human is looking for something obviously wrong.
    if !assume_yes {
        match confirm("Anything look wrong? Accept these and make them available?") {
            Ok(true) => {}
            Ok(false) => {
                println!();
                println!("Left unpublished. Nothing from these servers is being served.");
                println!("  When you have looked:  aikey mcp review");
                return;
            }
            Err(e) => {
                println!(
                    "{} could not read your answer: {e}",
                    crate::symbols::WARN.s()
                );
                return;
            }
        }
    }
    for b in &waiting {
        match crate::commands_mcp::accept_backend(&b.backend_id, &[]) {
            Ok(_) => println!(
                "{} '{}' reviewed — its tools are available now.",
                crate::symbols::CHECK.s(),
                b.backend_id
            ),
            Err(e) => println!(
                "{} '{}' could not be published: {e}\n  Run `aikey mcp review` to try again.",
                crate::symbols::WARN.s(),
                b.backend_id
            ),
        }
    }
}

fn confirm(question: &str) -> Result<bool, String> {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("cannot write to the terminal: {e}"))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read your answer: {e}"))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn plan_json(p: &AdoptPlan, dry_run: bool) -> serde_json::Value {
    serde_json::json!({
        "dry_run": dry_run,
        "adopt": p.items.iter().map(|i| serde_json::json!({
            "name": i.name,
            "scope": i.scope,
            "path": i.path.display().to_string(),
            "vault_alias": i.alias,
            "env_var": i.env_var,
            "credential": i.masked(),
        })).collect::<Vec<_>>(),
        "skipped": p.skipped.iter().map(|(name, r)| serde_json::json!({
            "name": name,
            "reason": r.explain(name),
        })).collect::<Vec<_>>(),
        "files": p.files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>(),
    })
}

/// The confirmation screen.
pub fn render_plan(p: &AdoptPlan) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    if p.items.is_empty() {
        let _ = writeln!(out, "Nothing to adopt.");
        let _ = writeln!(out);
    } else {
        let _ = writeln!(out, "About to adopt {} server(s):", p.items.len());
        let _ = writeln!(out);
        for (path, items) in by_file(p) {
            let _ = writeln!(out, "  {}", path.display());
            for i in items {
                let _ = writeln!(out, "    {:<14} {} {}", i.name, i.command, i.args.join(" "));
                let _ = writeln!(
                    out,
                    "                   env.{} ({})  →  vault alias '{}'",
                    i.env_var,
                    i.masked(),
                    i.alias
                );
            }
            let _ = writeln!(out);
        }
    }

    if !p.skipped.is_empty() {
        // 🔴 Printed in full, never summarised as a count. Each line says what
        // is still true of the machine afterwards — several of them mean "that
        // secret is still in cleartext", which is the opposite of what a user
        // takes from the word "skipped".
        let _ = writeln!(out, "Not adopted:");
        for (name, reason) in &p.skipped {
            if matches!(reason, SkipReason::NotSelected) {
                continue;
            }
            let _ = writeln!(out, "  · {}", reason.explain(name));
        }
        let _ = writeln!(out);
    }
    out
}

fn render_outcome(o: &AdoptOutcome, endpoint: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} Adopted. {} credential(s) moved into the vault, {} entr(y/ies) removed from {} file(s).",
        crate::symbols::CHECK.s(),
        o.credentials_stored.len(),
        o.entries_removed,
        o.files_rewritten.len()
    );
    if !o.credentials_reused.is_empty() {
        let _ = writeln!(
            out,
            "  {} credential(s) were already in the vault from an earlier run and were reused.",
            o.credentials_reused.len()
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "  Your client now talks to:  {endpoint}");
    let _ = writeln!(
        out,
        "  Restart your MCP client, then check:  aikey mcp test"
    );
    let _ = writeln!(out);
    // 🔴 The equivalence-migration promise, and its condition. Every adopted
    // tool is usable immediately — and marked so it can be tightened later.
    let _ = writeln!(
        out,
        "  Every tool you had comes back — after one look at what each one claims to do."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {} We moved the credentials we RECOGNISED. Anything we did not recognise is",
        crate::symbols::WARN.s()
    );
    let _ = writeln!(
        out,
        "     still in cleartext, and so is any copy you saved somewhere we do not read."
    );
    out
}

// ---------------------------------------------------------------------------
// tests + fences (14.F1 / 14.F2 / 14.F3 / 14.F6 / 14.F8, failure paths 14.C2–14.C9)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_scan::{ScanReport, ScanRoots};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    fn scan_home(body: &str) -> (tempfile::TempDir, ScanReport) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".claude.json"), body).expect("write");
        let report = crate::mcp_scan::scan(&ScanRoots {
            home: Some(dir.path().to_path_buf()),
            cwd: None,
            claude_desktop_config: None,
        });
        (dir, report)
    }

    const MACHINE: &str = r#"{
      "theme": "dark",
      "numStartups": 42,
      "mcpServers": {
        "postgres": {
          "command": "npx", "args": ["-y","@x/server-postgres"],
          "env": {"DATABASE_URL": "postgres://app:hunter2@prod-db:5432/app"}
        },
        "github": {
          "command": "npx",
          "env": {"GITHUB_TOKEN": "ghp_zzzzzzzzzzzzzzzzzzzzzzzz", "LOG_LEVEL": "debug"}
        },
        "weather": {"type": "http", "url": "https://weather.example.com/mcp"},
        "twokeys": {
          "command": "two",
          "env": {"A_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaa", "B_TOKEN": "ghp_bbbbbbbbbbbbbbbbbbbbbbbb"}
        },
        "clean": {"command": "clean"}
      },
      "projects": {
        "/w/payments": {"mcpServers": {"jira": {"command":"jira-mcp","env":{"JIRA_PAT":"abcd1234efgh5678ijkl"}}}}
      }
    }"#;

    /// An in-memory vault that can be told to fail.
    struct FakeVault {
        stored: std::collections::BTreeMap<String, String>,
        preexisting: Vec<String>,
        fail_store_on: Option<String>,
        deleted: Vec<String>,
    }
    impl FakeVault {
        fn new() -> FakeVault {
            FakeVault {
                stored: Default::default(),
                preexisting: Vec::new(),
                fail_store_on: None,
                deleted: Vec::new(),
            }
        }
    }
    impl AdoptVault for FakeVault {
        fn contains(&self, alias: &str) -> bool {
            self.preexisting.iter().any(|a| a == alias) || self.stored.contains_key(alias)
        }
        fn store(&mut self, alias: &str, secret: &str) -> Result<(), String> {
            if self.fail_store_on.as_deref() == Some(alias) {
                return Err("disk full".into());
            }
            self.stored.insert(alias.to_string(), secret.to_string());
            Ok(())
        }
        fn delete(&mut self, alias: &str) -> Result<(), String> {
            self.stored.remove(alias);
            self.deleted.push(alias.to_string());
            Ok(())
        }
    }

    // -- planning -----------------------------------------------------------

    #[test]
    fn plans_only_what_can_be_adopted_and_explains_every_refusal() {
        let (_d, report) = scan_home(MACHINE);
        let p = plan(&report, &[]);

        let names: Vec<&str> = p.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["postgres", "jira"], "planned: {names:?}");

        let reasons: std::collections::BTreeMap<&str, &SkipReason> =
            p.skipped.iter().map(|(n, r)| (n.as_str(), r)).collect();
        assert!(matches!(reasons["weather"], SkipReason::NotStdio { .. }));
        assert!(matches!(
            reasons["clean"],
            SkipReason::NoCleartextCredential
        ));
        assert!(matches!(
            reasons["twokeys"],
            SkipReason::MultipleSecrets { .. }
        ));
        // 🔴 The one that costs us the headline case, and it is deliberate: the
        // local config has nowhere to carry LOG_LEVEL, and adopting anyway would
        // start the server without it.
        assert!(matches!(reasons["github"], SkipReason::NonSecretEnv { .. }));
    }

    /// 🔴 Every refusal must say what is still TRUE of the machine. "Skipped"
    /// on its own reads as "fine", and for several of these it means the secret
    /// is still sitting in cleartext.
    ///
    /// 🔴 Asserts the SUBSTANCE, one required phrase per reason. The first
    /// version of this test only checked that the sentence was longer than the
    /// server's name — and the drill proved it: a refusal reduced to
    /// "postgres: skipped." passed it. A test that measures length is measuring
    /// nothing.
    #[test]
    fn every_refusal_names_what_is_still_true_of_the_machine() {
        let (_d, report) = scan_home(MACHINE);
        for (name, reason) in plan(&report, &[]).skipped {
            let text = reason.explain(&name);
            assert!(text.starts_with(&name), "{text}");
            let required: &[&str] = match &reason {
                // The secret is STILL THERE — the one thing the user must not
                // take away as "handled".
                SkipReason::NoCleartextCredential => &["RECOGNISE", "still in cleartext"],
                SkipReason::NonSecretEnv { .. } => &["LOG_LEVEL", "without them"],
                SkipReason::MultipleSecrets { .. } => &["A_TOKEN", "B_TOKEN"],
                SkipReason::NotStdio { .. } => &["remote", "left exactly as it is"],
                SkipReason::AlreadyAdopted => &["already adopted"],
                SkipReason::Unrecognised => &["not touched"],
                SkipReason::NotSelected => &["not selected"],
            };
            for phrase in required {
                assert!(
                    text.contains(phrase),
                    "🔴 this refusal no longer says {phrase:?}, so it reads as \"handled\": {text}"
                );
            }
        }
    }

    #[test]
    fn only_selects_a_subset_and_the_rest_are_marked_not_selected() {
        let (_d, report) = scan_home(MACHINE);
        let p = plan(&report, &["postgres".to_string()]);
        assert_eq!(p.items.len(), 1);
        assert!(p
            .skipped
            .iter()
            .any(|(n, r)| n == "jira" && matches!(r, SkipReason::NotSelected)));
    }

    /// 🔴 Determinism is what makes a second run finish an interrupted first one
    /// instead of storing a second copy under a new name (14.C6).
    #[test]
    fn the_vault_alias_is_deterministic_and_scoped() {
        let (_d, report) = scan_home(MACHINE);
        let a = plan(&report, &[]);
        let b = plan(&report, &[]);
        let names_a: Vec<&str> = a.items.iter().map(|i| i.alias.as_str()).collect();
        let names_b: Vec<&str> = b.items.iter().map(|i| i.alias.as_str()).collect();
        assert_eq!(names_a, names_b);
        assert_eq!(names_a[0], "mcp-postgres-database-url");
        // The project-scoped one carries a scope discriminator, because the same
        // server name in two projects can hold two DIFFERENT secrets and one
        // alias for both would silently overwrite one of them.
        assert!(
            names_a[1].starts_with("mcp-jira-jira-pat-")
                && names_a[1].len() > "mcp-jira-jira-pat-".len(),
            "{}",
            names_a[1]
        );
    }

    #[test]
    fn two_projects_with_the_same_server_get_different_aliases() {
        let (_d, report) = scan_home(
            r#"{"projects":{
              "/w/a":{"mcpServers":{"jira":{"command":"j","env":{"JIRA_PAT":"ghp_aaaaaaaaaaaaaaaa"}}}},
              "/w/b":{"mcpServers":{"jira":{"command":"j","env":{"JIRA_PAT":"ghp_bbbbbbbbbbbbbbbb"}}}}
            }}"#,
        );
        let p = plan(&report, &[]);
        assert_eq!(p.items.len(), 2);
        assert_ne!(
            p.items[0].alias, p.items[1].alias,
            "🔴 one alias for two different secrets silently overwrites one of them"
        );
    }

    /// 14.C6 — the gateway entry we wrote is never adopted again.
    #[test]
    fn our_own_gateway_entry_is_never_adopted() {
        let (_d, report) = scan_home(
            r#"{"mcpServers":{"aikey":{"type":"http","url":"http://127.0.0.1:27200/mcp/local",
               "headers":{"Authorization":"Bearer aikey_personal_deadbeef"}}}}"#,
        );
        let p = plan(&report, &[]);
        assert!(p.items.is_empty(), "planned: {:?}", p.items);
        assert!(matches!(p.skipped[0].1, SkipReason::AlreadyAdopted));
    }

    // -- the rewrite --------------------------------------------------------

    /// 🔴 FENCE 14.F6 — every field that is not a server entry survives.
    ///
    /// Compares each surviving key's serialised VALUE byte-for-byte. Key ORDER
    /// is not preserved (serde_json sorts object keys and this build does not
    /// enable `preserve_order`) — stated rather than hidden, because a user who
    /// versions their dotfiles will see the reordering in a diff.
    #[test]
    fn fence_rewriting_preserves_every_other_field_byte_for_byte() {
        let before: serde_json::Value = serde_json::from_str(MACHINE).unwrap();
        let mut doc = before.clone();
        let maps = vec![
            vec!["mcpServers".to_string()],
            vec![
                "projects".to_string(),
                "*".to_string(),
                "mcpServers".to_string(),
            ],
        ];
        let removed = rewrite_document(
            &mut doc,
            &maps,
            &["postgres".to_string(), "jira".to_string()],
            "aikey",
            gateway_entry("http://127.0.0.1:27200/mcp/local", "tok"),
        );
        assert_eq!(removed, 2);

        let b = before.as_object().unwrap();
        let a = doc.as_object().unwrap();
        for (k, v) in b {
            if k == "mcpServers" || k == "projects" {
                continue;
            }
            assert_eq!(
                serde_json::to_string(v).unwrap(),
                serde_json::to_string(a.get(k).expect("a key vanished")).unwrap(),
                "🔴 the rewrite changed `{k}`. A user whose theme and recent projects were lost \
                 to a 'migration' would never let us near their machine again."
            );
        }
        // Untouched servers are still there, untouched.
        let servers = a["mcpServers"].as_object().unwrap();
        assert_eq!(
            serde_json::to_string(&servers["github"]).unwrap(),
            serde_json::to_string(&b["mcpServers"]["github"]).unwrap()
        );
        assert!(servers.contains_key("weather"));
        assert!(!servers.contains_key("postgres"));
        // The project key survives even though its map is now empty: removing a
        // key the user had is a bigger surprise than leaving an empty object.
        assert!(a["projects"]["/w/payments"]["mcpServers"]
            .as_object()
            .unwrap()
            .is_empty());
        // ...and the gateway entry landed in the root map.
        assert_eq!(servers["aikey"]["url"], "http://127.0.0.1:27200/mcp/local");
    }

    #[test]
    fn rewriting_nothing_installs_nothing() {
        let mut doc: serde_json::Value = serde_json::from_str(r#"{"theme":"dark"}"#).unwrap();
        let removed = rewrite_document(
            &mut doc,
            &[vec!["mcpServers".to_string()]],
            &["nope".to_string()],
            "aikey",
            gateway_entry("u", "t"),
        );
        assert_eq!(removed, 0);
        assert!(
            doc.get("mcpServers").is_none(),
            "🔴 a run that adopted nothing must not leave a gateway entry behind: it would \
             point a client at a gateway hosting nothing"
        );
    }

    // -- the saga -----------------------------------------------------------

    fn run(
        body: &str,
        vault: &mut FakeVault,
        mcp_dir: &Path,
    ) -> (tempfile::TempDir, Result<AdoptOutcome, String>, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join(".claude.json");
        std::fs::write(&cfg, body).unwrap();
        let original = std::fs::read(&cfg).unwrap();
        let report = crate::mcp_scan::scan(&ScanRoots {
            home: Some(dir.path().to_path_buf()),
            cwd: None,
            claude_desktop_config: None,
        });
        let p = plan(&report, &[]);
        let r = execute(
            &p,
            "http://127.0.0.1:27200/mcp/local",
            "tok",
            &mcp_dir.join("mcp.json"),
            vault,
        );
        (dir, r, original)
    }

    #[test]
    fn a_successful_run_moves_the_secret_and_leaves_no_plaintext() {
        let mcp = tempfile::tempdir().unwrap();
        let mut v = FakeVault::new();
        let (dir, r, _) = run(MACHINE, &mut v, mcp.path());
        let out = r.expect("adopt");
        assert_eq!(out.credentials_stored.len(), 2);
        assert_eq!(out.entries_removed, 2);

        let after = std::fs::read_to_string(dir.path().join(".claude.json")).unwrap();
        for secret in ["hunter2", "abcd1234efgh5678ijkl"] {
            assert!(
                !after.contains(secret),
                "🔴 the plaintext is still in the config. Copying the secret into the vault is \
                 not adoption — it leaves one clean path and one dirty one, and it LOOKS done."
            );
        }
        // ...and it really is in the vault.
        assert!(v.stored.values().any(|s| s.contains("hunter2")));
        // The one we refused is untouched, plaintext and all — as reported.
        assert!(after.contains("ghp_zzzzzzzzzzzzzzzzzzzzzzzz"));

        // The backends were registered where the proxy will read them.
        let mcp_cfg = crate::commands_mcp::load(&mcp.path().join("mcp.json")).unwrap();
        assert_eq!(mcp_cfg.backends.len(), 2);
        assert_eq!(mcp_cfg.backends[0].credential_env, "DATABASE_URL");
    }

    /// 🔴 FENCE 14.F2 / I20 — the credential must never be stored while the
    /// rewrite is skipped. That state is the one R19 calls out by name: the user
    /// believes they migrated and the plaintext is still there.
    #[test]
    fn fence_a_failed_rewrite_takes_the_credentials_back_out() {
        let mcp = tempfile::tempdir().unwrap();
        // 🔴 A read-only directory makes the mcp.json write fail for the same
        // reason a real one would (permissions, a full disk) — 🚫 not a flag
        // this code checks, which would prove only that the flag works.
        let mut perms = std::fs::metadata(mcp.path()).unwrap().permissions();
        #[cfg(unix)]
        perms.set_mode(0o500);
        std::fs::set_permissions(mcp.path(), perms).unwrap();

        let mut v = FakeVault::new();
        let (dir, r, original) = run(MACHINE, &mut v, mcp.path());
        assert!(r.is_err(), "the run reported success on an unwritable path");

        // 🔴 Byte-for-byte, MEASURED — not reasoned about (14.C2 / I21).
        assert_eq!(
            std::fs::read(dir.path().join(".claude.json")).unwrap(),
            original,
            "🔴 the config was not restored to its previous bytes"
        );
        assert!(
            v.stored.is_empty(),
            "🔴 credentials stayed in the vault after a failed run: the next run would reuse \
             them believing they were placed deliberately"
        );
        assert_eq!(v.deleted.len(), 2, "the rollback did not remove both");

        let msg = r.unwrap_err();
        assert!(
            msg.contains("Nothing was changed"),
            "the failure must say the machine is unchanged, or the user re-runs blind: {msg}"
        );
    }

    /// 14.C2 — a failure while storing the SECOND credential rolls the first
    /// one back too.
    #[test]
    fn a_failure_partway_through_the_credentials_undoes_the_earlier_ones() {
        let mcp = tempfile::tempdir().unwrap();
        let mut v = FakeVault::new();
        v.fail_store_on = Some("mcp-jira-jira-pat-".to_string());
        // Resolve the real alias first.
        let (_d0, report) = scan_home(MACHINE);
        let p = plan(&report, &[]);
        v.fail_store_on = Some(p.items[1].alias.clone());

        let (dir, r, original) = run(MACHINE, &mut v, mcp.path());
        assert!(r.is_err());
        assert!(v.stored.is_empty(), "the first credential was left behind");
        assert_eq!(
            std::fs::read(dir.path().join(".claude.json")).unwrap(),
            original
        );
    }

    /// 14.C6 — running twice converges instead of duplicating.
    #[test]
    fn a_second_run_over_an_interrupted_first_one_finishes_it_without_a_password() {
        let mcp = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join(".claude.json");
        std::fs::write(&cfg, MACHINE).unwrap();

        let report = crate::mcp_scan::scan(&ScanRoots {
            home: Some(dir.path().to_path_buf()),
            cwd: None,
            claude_desktop_config: None,
        });
        let p = plan(&report, &[]);

        // Simulate the interrupted run: the credentials are in the vault, the
        // config was never rewritten.
        let mut v = FakeVault::new();
        v.preexisting = p.items.iter().map(|i| i.alias.clone()).collect();

        let out = execute(
            &p,
            "http://127.0.0.1:27200/mcp/local",
            "tok",
            &mcp.path().join("mcp.json"),
            &mut v,
        )
        .expect("the recovery run");

        // 🔴 Nothing was stored, so nothing needed a master password — which is
        // what lets the recovery path run unattended.
        assert!(out.credentials_stored.is_empty());
        assert_eq!(out.credentials_reused.len(), 2);
        assert_eq!(out.entries_removed, 2);
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(!after.contains("hunter2"));
    }

    /// 14.C3 — one server that cannot be adopted does not stop the others.
    #[test]
    fn one_unadoptable_server_does_not_abort_the_rest() {
        let mcp = tempfile::tempdir().unwrap();
        let mut v = FakeVault::new();
        let (_dir, r, _) = run(MACHINE, &mut v, mcp.path());
        let out = r.unwrap();
        assert_eq!(out.backends_registered.len(), 2);
        // github / weather / twokeys / clean were all refused, and the run still
        // completed.
    }

    /// 🔴 FENCE 14.F1 — adoption goes through the SAME registration core as
    /// `aikey mcp add`, so there is no bypass that skips its rules.
    #[test]
    fn fence_adoption_registers_through_the_shared_core_not_a_private_path() {
        let src = include_str!("mcp_adopt.rs");
        let marker = format!("#[cfg({})]", "test");
        let shipping = &src[..src.find(&marker).unwrap()];
        let core = format!("apply_add{}core", "_");
        assert!(
            shipping.contains(&core),
            "🔴 adoption must register through `{core}`, the same core `aikey mcp add` uses. \
             A private registration path here would skip its name and credential-pairing rules \
             — and it would be a second place for them to be implemented differently."
        );
        // ...and it must not write the config document itself.
        for banned in [format!("McpConfig {}", "{"), format!("backends{}push", ".")] {
            assert!(
                !shipping.contains(&banned),
                "🔴 adoption is assembling the backend list by hand ({banned}) instead of going \
                 through the shared core"
            );
        }
    }

    /// 🔴 FENCE 14.F8 — only `adopt` rewrites `mcpServers`. `aikey use` and the
    /// desktop takeover must keep PRESERVING it and never write it.
    ///
    /// Their shared reader gained a door for adoption (`read_json_object_for_adopt`);
    /// this checks the door did not become a window.
    #[test]
    fn fence_only_adoption_rewrites_the_client_server_map() {
        let key = format!("mcp{}", "Servers");
        for (name, src) in [
            (
                "profile_activation.rs",
                include_str!("profile_activation.rs"),
            ),
            (
                "claude_desktop.rs",
                include_str!("commands_account/claude_desktop.rs"),
            ),
        ] {
            let marker = format!("#[cfg({})]", "test");
            let shipping = &src[..src.find(&marker).unwrap_or(src.len())];
            for line in shipping.lines() {
                let t = line.trim_start();
                if t.starts_with("//") || t.starts_with("*") || t.starts_with("///") {
                    continue;
                }
                assert!(
                    !line.contains(&key),
                    "🔴 {name} now names `{key}` in shipping code. Those paths take over a \
                     client's routing and must only PRESERVE the user's MCP servers — rewriting \
                     them is `aikey mcp adopt`'s job, and only because the user asked for it \
                     (task 14.2f).\n  offending line: {line}"
                );
            }
        }
    }

    #[test]
    fn short_hash_is_stable_and_six_characters() {
        assert_eq!(short_hash("/w/payments"), short_hash("/w/payments"));
        assert_eq!(short_hash("/w/payments").len(), 6);
        assert_ne!(short_hash("/w/a"), short_hash("/w/b"));
    }

    #[test]
    fn sanitize_collapses_to_an_alias_a_human_can_type() {
        assert_eq!(sanitize("GITHUB_TOKEN"), "github-token");
        assert_eq!(sanitize("@scope/pkg"), "scope-pkg");
        assert_eq!(sanitize("--x--"), "x");
    }
}
