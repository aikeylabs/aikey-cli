//! Claude Desktop takeover — pure file layer (P1).
//!
//! Writes/removes the Claude Desktop `3p` inference-gateway configuration so
//! the GUI app routes model inference through aikey-proxy, following the
//! active anthropic binding (coupled model, D1).
//!
//! Mechanism (reverse-engineered by cc-switch v3.16.5, spike-verified
//! 2026-07-13, record: `workflow/CI/research/claude-desktop-3p/`):
//!   1. write a gateway profile at `Claude-3p/configLibrary/<PROFILE_ID>.json`
//!   2. claim `configLibrary/_meta.json` `appliedId`
//!   3. flip `deploymentMode` to `"3p"` in BOTH `Claude/claude_desktop_config.json`
//!      and `Claude-3p/claude_desktop_config.json` (preserving other keys)
//!
//! Desktop is DUAL-PLANE (spike finding, risk 9): only the inference plane
//! (model menu / v1/messages / count_tokens) goes through this gateway; the
//! account/session plane still talks to claude.ai directly. This module
//! cannot and does not affect that plane.
//!
//! This module is deliberately funnel-free: no caller in P1. P2 wires
//! `reconcile_active` into `apply_third_party_cli_configs` (both call
//! sites — the lifecycle tail AND `handle_key_unuse`'s parallel copy get it
//! for free because the logic lives inside that shared function body).
//!
//! Ownership/idempotency is SEMANTIC (deploymentMode + our profile file +
//! meta appliedId), never comment markers — the kimi/codex
//! `*_content_has_aikey` lesson.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::commands_account::third_party_config as tp;

/// aikey's own gateway profile id. Trailing 12 hex = ASCII "AIKEY";
/// v4/variant-8 legal shape. NEVER change once released — restore and
/// ownership detection key off this exact file name / appliedId.
pub(crate) const PROFILE_ID: &str = "00000000-0000-4000-8000-0041494b4559";
#[allow(dead_code)] // rendered in `aikey desktop status` (P2)
pub(crate) const PROFILE_NAME: &str = "AiKey";
const CONFIG_FILE: &str = "claude_desktop_config.json";
const CONFIG_LIBRARY: &str = "configLibrary";
/// The client key under `clients:` in provider_registry.yaml (D4 rev2).
const REGISTRY_CLIENT: &str = "claude-desktop";

#[derive(Debug, Clone, PartialEq, Eq)]
enum MsixDetection {
    /// Non-Windows paths and test paths that do not need MSIX discovery.
    NotApplicable,
    /// Windows legacy marker was sufficient, so PackageManager was not called.
    NotChecked,
    Registered,
    NotRegistered,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DesktopInstallation {
    Legacy,
    Msix,
    NotInstalled,
    DetectionFailed(String),
}

// ─── Paths ──────────────────────────────────────────────────────────────

/// All filesystem locations the takeover touches. Constructed via
/// `desktop_paths()` in production and `paths_from_dirs()` in tests
/// (tempdir injection — tests never touch the real HOME).
#[derive(Debug, Clone)]
pub(crate) struct DesktopPaths {
    /// `.../Claude` — the deploymentMode config dir. On Windows this dir is
    /// created BY takeover (it does not exist on a clean install), so it is NOT
    /// a valid "installed" signal there — use the installation evidence below.
    pub normal_dir: PathBuf,
    /// Legacy/unpackaged installation marker. Its existence is sufficient to
    /// mean "Claude Desktop is installed"; its absence is not, because Store
    /// installs are discovered from current-user package registration.
    /// macOS: same as `normal_dir` (`~/Library/Application Support/Claude`,
    /// created on first run). Windows: the app dir `%LOCALAPPDATA%\AnthropicClaude`
    /// (where claude.exe lives) — because `normal_dir` (`%LOCALAPPDATA%\Claude`)
    /// only appears after a takeover, so keying detection off it would falsely
    /// report a freshly-installed Windows Claude as "not installed".
    pub install_marker: PathBuf,
    /// Result of the current-user Windows package-registration lookup. Kept
    /// separate from config paths so Store/MSIX discovery never depends on
    /// access to the protected WindowsApps directory.
    msix_detection: MsixDetection,
    pub threep_dir: PathBuf,
    pub normal_config: PathBuf,
    pub threep_config: PathBuf,
    pub config_library: PathBuf,
    pub profile: PathBuf,
    pub meta: PathBuf,
}

pub(crate) fn paths_from_dirs(normal_dir: PathBuf, threep_dir: PathBuf) -> DesktopPaths {
    let config_library = threep_dir.join(CONFIG_LIBRARY);
    DesktopPaths {
        normal_config: normal_dir.join(CONFIG_FILE),
        threep_config: threep_dir.join(CONFIG_FILE),
        profile: config_library.join(format!("{}.json", PROFILE_ID)),
        meta: config_library.join("_meta.json"),
        config_library,
        // Default: the config dir doubles as the install marker (true on
        // macOS, where `~/Library/Application Support/Claude` is created on
        // first run). Platform builders that separate the two (Windows)
        // override `install_marker` after calling this.
        install_marker: normal_dir.clone(),
        msix_detection: MsixDetection::NotApplicable,
        normal_dir,
        threep_dir,
    }
}

/// macOS: `~/Library/Application Support/{Claude, Claude-3p}`.
/// Compiled on every platform (pure path math) so tests run everywhere.
pub(crate) fn macos_paths_from_home(home: &Path) -> DesktopPaths {
    let app_support = home.join("Library").join("Application Support");
    paths_from_dirs(app_support.join("Claude"), app_support.join("Claude-3p"))
}

/// Windows: `%LOCALAPPDATA%\{Claude, Claude-3p}` (fallback
/// `<home>\AppData\Local`).
///
/// ⚠️ The 3p deployment config lives under **LocalAppData** — NOT the
/// well-known MCP-config location `%APPDATA%` (Roaming). Do not "correct"
/// this to Roaming: verified against cc-switch
/// `claude_desktop_config.rs::windows_paths_from_local_app_data` (D10②).
///
/// Config uses exact dir names (also documented by cc-switch). Do not scan or
/// write package-private/versioned directories: Store/MSIX installation is
/// discovered independently through current-user Package registration.
///
/// Windows spike (2026-07-15): the app installs to
/// `%LOCALAPPDATA%\AnthropicClaude` (claude.exe), while `%LOCALAPPDATA%\Claude`
/// / `Claude-3p` (the deploymentMode config dirs) only appear AFTER a takeover.
/// So the app dir is the install marker; the config dirs are created by
/// `takeover_at`. Verified against Claude Desktop `1.21459.0`.
pub(crate) fn windows_paths_from_local_app_data(local_app_data: &Path) -> DesktopPaths {
    let mut paths = paths_from_dirs(
        local_app_data.join("Claude"),
        local_app_data.join("Claude-3p"),
    );
    // The config dir (`Claude`) does not exist on a clean install — detect
    // "installed" via the app dir instead, or a freshly-installed Windows
    // Claude is falsely reported NotInstalled and takeover refuses to run.
    paths.install_marker = local_app_data.join("AnthropicClaude");
    paths.msix_detection = MsixDetection::NotChecked;
    paths
}

/// Platform paths for the real process environment. `None` on platforms
/// without a Claude Desktop build (Linux) — callers skip silently (R7).
#[allow(dead_code)] // wired by the P2 funnel + `aikey desktop` commands
pub(crate) fn desktop_paths() -> Option<DesktopPaths> {
    #[cfg(target_os = "macos")]
    {
        Some(macos_paths_from_home(
            &crate::commands_account::shell_integration::resolve_user_home(),
        ))
    }
    #[cfg(windows)]
    {
        let lad = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                crate::commands_account::shell_integration::resolve_user_home()
                    .join("AppData")
                    .join("Local")
            });
        let mut paths = windows_paths_from_local_app_data(&lad);
        // The unpackaged/legacy app directory is the cheapest and strongest
        // signal. Only ask Windows when that marker is absent. A PackageManager
        // error is retained as an explicit diagnostic state, never collapsed
        // into "not installed".
        if !paths.install_marker.exists() {
            paths.msix_detection =
                match super::claude_desktop_windows::is_claude_msix_registered_for_current_user() {
                    Ok(true) => MsixDetection::Registered,
                    Ok(false) => MsixDetection::NotRegistered,
                    Err(e) => MsixDetection::Failed(e),
                };
        }
        Some(paths)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        None
    }
}

// ─── Route material ─────────────────────────────────────────────────────

/// What the gateway profile points at. Local editions: local proxy +
/// per-provider sentinel (credential-independent — D1's zero-rewrite-on-
/// credential-switch property). Cluster direct-bind VK: central node + real
/// vk_token (same exposure level as active.env on cluster, risk 3). Team OAuth
/// account-pool VKs remain member-local, matching active.env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteMaterial {
    pub base_url: String,
    pub token: String,
}

/// Route material for the CURRENT active anthropic binding. `None` when no
/// anthropic binding exists (nothing to take over — callers restore/skip).
///
/// Reuses the exact `cluster_route` vs sentinel fork active.env is written
/// with (`profile_activation.rs` §5.5) so the two surfaces can never
/// disagree about where anthropic routes.
#[allow(dead_code)] // wired by the P2 funnel + `aikey desktop` commands
pub(crate) fn route_material_for_anthropic(proxy_port: u16) -> Option<RouteMaterial> {
    let binding = crate::storage::get_provider_binding("default", "anthropic")
        .ok()
        .flatten()?;
    // A binding ROW is not servable material (2026-08-27, customer machine).
    // `disable_keys_for_account_scope` (login/account switch) marks the key
    // disabled_by_* but clears no binding rows, and the proxy's route query
    // filters disabled keys out — so a takeover written from this row points
    // Claude Desktop at a route the proxy will refuse ("Couldn't connect to
    // Claude", reproduced in takeover_left_stale_when_account_scope_disables_
    // the_key). Same truth the panel's routes projection reports: a disabled
    // key renders as "unset". Answering Some here made the SAME question —
    // "does anthropic have a credential?" — give two different answers.
    if binding.key_source_type == crate::credential_type::CredentialType::ManagedVirtualKey {
        // 🔴 Ask the SHARED predicate, never re-derive it here (2026-08-31).
        //
        // The first version of this guard wrote its own rule and demanded
        // `local_state == "active"` — a value the sync path never writes. Every
        // team key is `synced_inactive`, so the guard was effectively `false`:
        // Desktop takeover was refused on every machine with a team credential,
        // with a message telling the user to run `aikey use` for a key the panel
        // was already showing as bound. The reconcile consumes this same
        // function, so an installed takeover was torn down as well.
        //
        // `is_servable` is the rule the picker / web set-route / activation have
        // used since 2026-04-10. One name, one answer to one question.
        let on_cluster = crate::commands_account::read_cluster_node().is_some();
        let servable = crate::storage::get_virtual_key_cache(&binding.key_source_ref)
            .ok()
            .flatten()
            .map(|k| k.is_servable(on_cluster))
            .unwrap_or(false);
        if !servable {
            return None;
        }
    }
    let prefix = crate::commands_account::provider_proxy_prefix_pub("anthropic");
    Some(
        match crate::commands_account::cluster_route(
            &binding.key_source_type,
            &binding.key_source_ref,
        ) {
            Some((node, vk_token)) => RouteMaterial {
                base_url: format!("http://{}/{}", node, prefix),
                token: vk_token,
            },
            None => RouteMaterial {
                base_url: format!("http://127.0.0.1:{}/{}", proxy_port, prefix),
                token: "aikey_active_anthropic".to_string(),
            },
        },
    )
}

// ─── Model menu ─────────────────────────────────────────────────────────

/// Desktop rejects the WHOLE `inferenceModels` list if ONE entry fails its
/// `is_claude_safe_model_id` check (fail-all, risk 4). Mirror the check
/// before writing: `claude-{sonnet|opus|haiku|fable}-<non-empty>` and no
/// `[1m]` marker.
pub(crate) fn is_claude_safe_model_id(name: &str) -> bool {
    if name.contains("[1m]") {
        return false;
    }
    [
        "claude-sonnet-",
        "claude-opus-",
        "claude-haiku-",
        "claude-fable-",
    ]
    .iter()
    .any(|p| name.strip_prefix(p).is_some_and(|rest| !rest.is_empty()))
}

/// Menu entries from `provider_registry.yaml` `clients.claude-desktop.models`,
/// with unsafe names filtered out (WARN, never silent — logging conventions).
/// Empty result ⇒ caller omits the `inferenceModels` key entirely rather
/// than writing an empty list Desktop might choke on.
fn validated_menu_entries() -> Vec<Value> {
    crate::provider_registry::client_models("anthropic", REGISTRY_CLIENT)
        .iter()
        .filter_map(|m| {
            if !is_claude_safe_model_id(m.name) {
                eprintln!(
                    "[aikey] warning: claude-desktop menu entry '{}' fails the \
                     claude-safe check (fail-all guard) — dropped from the profile",
                    m.name
                );
                return None;
            }
            Some(if m.supports_1m {
                json!({ "name": m.name, "supports1m": true })
            } else {
                Value::String(m.name.to_string())
            })
        })
        .collect()
}

/// Gateway profile JSON (schema per cc-switch `build_gateway_profile`;
/// spike-verified byte-compatible on Desktop 1.18286.0).
pub(crate) fn build_gateway_profile(material: &RouteMaterial) -> Value {
    let mut profile = json!({
        "coworkEgressAllowedHosts": ["*"],
        "disableDeploymentModeChooser": true,
        "inferenceGatewayApiKey": material.token,
        "inferenceGatewayAuthScheme": "bearer",
        "inferenceGatewayBaseUrl": material.base_url,
        "inferenceProvider": "gateway",
    });
    let models = validated_menu_entries();
    if !models.is_empty() {
        profile["inferenceModels"] = Value::Array(models);
    }
    profile
}

// ─── State detection ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DesktopState {
    /// Neither the platform marker nor current-user MSIX registration exists.
    NotInstalled,
    /// Windows package registration could not be queried. This is distinct
    /// from NotInstalled so diagnosis never turns an infrastructure failure
    /// into a false negative.
    DetectionFailed,
    /// Installed, `deploymentMode` != "3p" (or unset) — official mode.
    Official,
    /// `3p` and the applied profile is ours.
    OursActive,
    /// `3p` but applied by someone else (e.g. cc-switch). D5: silent
    /// takeover is allowed; their profile FILE is never touched.
    ForeignActive,
    /// The normal config exists but cannot be parsed (2026-09-05, third-party
    /// config guard Phase 4). Its own state: before this it fell through
    /// `deployment_mode() == None` and reported OFFICIAL — a file that
    /// plainly exists and is broken was described as "not taken over", and
    /// every write path then either refused (takeover) or rewrote around it
    /// (restore). Every write refuses; `aikey desktop status` / the tray row
    /// show the guard sentence; repair is `hook repair claude-desktop --from-backup`.
    ConfigInvalid,
    /// `3p` with NOBODY's profile applied — no appliedId and no profile file
    /// in the library. This is RESIDUE, not a foreign takeover (2026-08-31,
    /// winpc2). Distinguishing it matters because ForeignActive carries a
    /// promise never to touch it, and a machine parked here would otherwise
    /// route Claude Desktop at a gateway nobody serves, for ever, with no
    /// path back. Healable: the reconcile restores 1p.
    OrphanedThirdParty,
}

fn detect_installation(paths: &DesktopPaths) -> DesktopInstallation {
    // Legacy wins even if a package lookup failed: a concrete app directory
    // is enough evidence and keeps existing installations working.
    if paths.install_marker.exists() {
        return DesktopInstallation::Legacy;
    }
    match &paths.msix_detection {
        MsixDetection::Registered => DesktopInstallation::Msix,
        MsixDetection::Failed(e) => DesktopInstallation::DetectionFailed(e.clone()),
        MsixDetection::NotApplicable | MsixDetection::NotChecked | MsixDetection::NotRegistered => {
            DesktopInstallation::NotInstalled
        }
    }
}

fn read_json_object(path: &Path) -> Result<Value, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let v: Value = serde_json::from_str(crate::strip_bom(&content))
        .map_err(|e| format!("parse {}: {}", path.display(), e))?;
    if !v.is_object() {
        return Err(format!("{}: not a JSON object", path.display()));
    }
    Ok(v)
}

fn deployment_mode(config_path: &Path) -> Option<String> {
    if !config_path.exists() {
        return None;
    }
    read_json_object(config_path)
        .ok()?
        .get("deploymentMode")?
        .as_str()
        .map(str::to_string)
}

fn applied_id(meta_path: &Path) -> Option<String> {
    if !meta_path.exists() {
        return None;
    }
    read_json_object(meta_path)
        .ok()?
        .get("appliedId")?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn detect_state(paths: &DesktopPaths) -> DesktopState {
    match detect_installation(paths) {
        DesktopInstallation::NotInstalled => return DesktopState::NotInstalled,
        DesktopInstallation::DetectionFailed(_) => return DesktopState::DetectionFailed,
        DesktopInstallation::Legacy | DesktopInstallation::Msix => {}
    }
    // The NORMAL config is the authoritative mode switch (the app reads it
    // in both modes; the 3p copy exists for the 3p bundle's own view).
    // A normal config that exists but does not parse is ITS OWN state —
    // never "official" (spec: R-third-party-config-guard-6.S1).
    if paths.normal_config.is_file() && read_json_object(&paths.normal_config).is_err() {
        return DesktopState::ConfigInvalid;
    }
    let mode_3p = deployment_mode(&paths.normal_config).as_deref() == Some("3p");
    if !mode_3p {
        return DesktopState::Official;
    }
    match applied_id(&paths.meta).as_deref() {
        Some(PROFILE_ID) => DesktopState::OursActive,
        // 🔴 Residue, not a foreign owner (2026-08-31). THREE conditions must
        // hold together — a real third-party takeover fails at least one:
        //   mode=3p  AND  no applied id  AND  no profile file in the library.
        // Anything with someone's id, or with a profile file sitting there,
        // stays ForeignActive and keeps the never-touch promise.
        None if !library_has_any_profile(paths) => DesktopState::OrphanedThirdParty,
        _ => DesktopState::ForeignActive,
    }
}

/// Whether the 3p config library holds ANY profile file (ours or a foreign
/// tool's). `_meta.json` is bookkeeping, not a profile.
fn library_has_any_profile(paths: &DesktopPaths) -> bool {
    let Ok(entries) = std::fs::read_dir(&paths.config_library) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name()
            .to_str()
            .map(|n| n != "_meta.json" && n.ends_with(".json"))
            .unwrap_or(false)
    })
}

// ─── Takeover ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TakeoverResult {
    /// Files written (fresh takeover, foreign takeover, or material drift
    /// rewrite). Desktop restart required to pick it up.
    Installed,
    /// Everything already matched — zero writes (semantic idempotency;
    /// credential switches under the sentinel land here, D1/D3 no-op).
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreResult {
    /// `1p` restored + our profile removed. Restart hint applies.
    Restored,
    /// Current `3p` isn't ours (foreign tool) — leave it alone. Restore
    /// only ever undoes what WE did.
    NotOursSkipped,
    /// Nothing to undo (not installed / already official with no residue).
    NothingToDo,
}

/// Snapshot of one path for rollback: `Some(bytes)` = file existed with
/// this content; `None` = did not exist (rollback deletes it).
struct Snapshot {
    path: PathBuf,
    content: Option<Vec<u8>>,
}

impl Snapshot {
    fn take(path: &Path) -> Snapshot {
        Snapshot {
            path: path.to_path_buf(),
            content: std::fs::read(path).ok(),
        }
    }
    fn restore(&self) {
        match &self.content {
            Some(bytes) => {
                let _ = tp::commit(&self.path, Some(bytes));
            }
            None => {
                let _ = tp::commit(&self.path, None);
            }
        }
    }
}

/// Every Desktop write goes through the guard's one door with a versioned
/// backup of whatever was there first (Phase 4, 2026-09-05). The four-file
/// snapshot rollback in `takeover_at` stays on top of this.
fn write_json_guarded(path: &Path, value: &Value) -> Result<(), String> {
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| format!("serialize {}: {}", path.display(), e))?;
    if path.is_file() {
        tp::backup_versioned(path).map_err(|e| format!("back up {}: {}", path.display(), e))?;
    }
    tp::commit(path, Some(pretty.as_bytes()))
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

fn delete_guarded(path: &Path) -> Result<(), String> {
    if path.is_file() {
        tp::backup_versioned(path).map_err(|e| format!("back up {}: {}", path.display(), e))?;
    }
    tp::commit(path, None).map_err(|e| format!("remove {}: {}", path.display(), e))
}

/// The guard's view of the NORMAL config (the authoritative mode switch):
/// strict parse → sentence, versioned backups, `hook repair claude-desktop
/// --from-backup`. Merge/remove are NOT routed through `apply` — the takeover
/// is a four-file transaction with its own snapshot rollback (`takeover_at`),
/// which the design keeps; every one of its writes goes through `tp::commit`.
pub(crate) struct DesktopSurface {
    normal_config: PathBuf,
}

impl DesktopSurface {
    pub(crate) fn at(paths: &DesktopPaths) -> Self {
        DesktopSurface {
            normal_config: paths.normal_config.clone(),
        }
    }
}

impl tp::Surface for DesktopSurface {
    type Doc = Value;
    type Input = ();

    const ID: tp::SurfaceId = tp::SurfaceId::ClaudeDesktop;
    const FORMAT: tp::Format = tp::Format::Json;
    const CREATE: tp::CreatePolicy = tp::CreatePolicy::RequireInstalled;
    const FOREIGN: tp::ForeignPolicy = tp::ForeignPolicy::ClaimWithConsent;
    const OWNED_GRAMMAR: Option<&'static tp::OwnedTomlGrammar> = None;

    fn path(&self) -> PathBuf {
        self.normal_config.clone()
    }
    fn load(&self, text: &str) -> Result<Self::Doc, tp::ParseFailure> {
        let v = tp::parse_json_strict(text)?;
        if !v.is_object() {
            return Err(tp::ParseFailure {
                line: Some(1),
                col: Some(1),
                msg: "top level is not a JSON object".into(),
            });
        }
        Ok(v)
    }
    fn empty_doc(&self) -> Self::Doc {
        json!({})
    }
    fn detect(&self, doc: &Self::Doc) -> tp::Detection {
        let mode_3p = doc.get("deploymentMode").and_then(|m| m.as_str()) == Some("3p");
        tp::Detection::of(if mode_3p {
            tp::TpConfigState::OursActive
        } else {
            tp::TpConfigState::PresentNoAikey
        })
    }
    fn merge(&self, _doc: Self::Doc, _input: &Self::Input) -> Result<Self::Doc, String> {
        Err(
            "Claude Desktop is written by takeover_at (four-file transaction), never by apply"
                .into(),
        )
    }
    fn remove(&self, doc: Self::Doc) -> Self::Doc {
        doc
    }
    fn render(&self, doc: &Self::Doc) -> String {
        serde_json::to_string_pretty(doc).unwrap_or_default()
    }
    fn expected_after_merge(&self, _det: &tp::Detection, _input: &Self::Input) -> bool {
        false
    }
}

pub(crate) fn desktop_inspection_at(paths: &DesktopPaths) -> tp::Inspection {
    tp::inspect(&DesktopSurface::at(paths))
}

/// `None` on platforms without a Claude Desktop build.
pub(crate) fn desktop_inspection() -> Option<tp::Inspection> {
    desktop_paths().map(|p| desktop_inspection_at(&p))
}

fn config_invalid_sentence(paths: &DesktopPaths) -> String {
    desktop_inspection_at(paths)
        .unparseable_sentence()
        .unwrap_or_else(|| format!("{} cannot be read", paths.normal_config.display()))
}

/// Flip `deploymentMode` in one config file, preserving every other key.
/// Missing file ⇒ create a minimal `{"deploymentMode": mode}` (the 3p-side
/// config often doesn't exist before first takeover). Malformed JSON ⇒
/// Err — honest failure, never overwrite a file we can't parse.
fn write_deployment_mode(config_path: &Path, mode: &str) -> Result<(), String> {
    let mut obj = if config_path.exists() {
        read_json_object(config_path)?
    } else {
        json!({})
    };
    obj["deploymentMode"] = Value::String(mode.to_string());
    write_json_guarded(config_path, &obj)
}

/// Claim `_meta.json`'s `appliedId` (D5: taking over a foreign 3p setup
/// claims the pointer but never deletes the foreign profile FILE).
fn write_meta_applied(meta_path: &Path) -> Result<(), String> {
    let mut obj = if meta_path.exists() {
        read_json_object(meta_path)?
    } else {
        json!({})
    };
    obj["appliedId"] = Value::String(PROFILE_ID.to_string());
    write_json_guarded(meta_path, &obj)
}

/// Take over Claude Desktop at `paths` (test-injectable). All-or-nothing:
/// on any failure every touched file is rolled back to its pre-call bytes
/// and an Err is returned (callers WARN + continue — desktop writes must
/// never fail the `use` that triggered them).
pub(crate) fn takeover_at(
    paths: &DesktopPaths,
    material: &RouteMaterial,
) -> Result<TakeoverResult, String> {
    match detect_installation(paths) {
        DesktopInstallation::NotInstalled => {
            return Err("Claude Desktop not detected (app not installed)".to_string())
        }
        DesktopInstallation::DetectionFailed(e) => {
            return Err(format!("Claude Desktop installation detection failed: {e}"))
        }
        DesktopInstallation::Legacy | DesktopInstallation::Msix => {}
    }

    if detect_state(paths) == DesktopState::ConfigInvalid {
        return Err(config_invalid_sentence(paths));
    }
    let profile_json = build_gateway_profile(material);
    let profile_pretty = serde_json::to_string_pretty(&profile_json)
        .map_err(|e| format!("serialize profile: {}", e))?;

    // Semantic idempotency: mode already 3p + meta ours + profile bytes
    // identical ⇒ zero writes. Byte comparison (not JSON equality) so a
    // hand-edited profile counts as drift and gets rewritten.
    if detect_state(paths) == DesktopState::OursActive
        && deployment_mode(&paths.threep_config).as_deref() == Some("3p")
        && std::fs::read(&paths.profile)
            .map(|b| b == profile_pretty.as_bytes())
            .unwrap_or(false)
    {
        return Ok(TakeoverResult::Unchanged);
    }

    // Fail BEFORE any write if either existing config is unparseable —
    // honest failure without a rollback dance.
    for cfg in [&paths.normal_config, &paths.threep_config] {
        if cfg.exists() && cfg.is_file() {
            read_json_object(cfg)?;
        }
    }

    // Create both the config dir and the 3p config-library. On Windows these
    // do NOT exist on a clean install (only the app dir does), and atomic_write
    // does not create parents — so writing normal_config would fail without this.
    // config_library's create_dir_all also makes threep_dir (its parent).
    std::fs::create_dir_all(&paths.normal_dir)
        .map_err(|e| format!("create {}: {}", paths.normal_dir.display(), e))?;
    std::fs::create_dir_all(&paths.config_library)
        .map_err(|e| format!("create {}: {}", paths.config_library.display(), e))?;

    let snapshots = [
        Snapshot::take(&paths.profile),
        Snapshot::take(&paths.meta),
        Snapshot::take(&paths.normal_config),
        Snapshot::take(&paths.threep_config),
    ];

    let result = (|| -> Result<(), String> {
        write_json_guarded(&paths.profile, &profile_json)?;
        // Cluster profiles carry a real vk_token (risk 3) — owner-only.
        // Windows: inherits the user-dir ACL (no 0600 there, D10⑤).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&paths.profile, std::fs::Permissions::from_mode(0o600));
        }
        write_meta_applied(&paths.meta)?;
        write_deployment_mode(&paths.normal_config, "3p")?;
        write_deployment_mode(&paths.threep_config, "3p")?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(TakeoverResult::Installed),
        Err(e) => {
            for s in &snapshots {
                s.restore();
            }
            Err(e)
        }
    }
}

/// Restore official mode at `paths`. Only undoes OUR takeover: a foreign
/// `3p` state is left untouched (`NotOursSkipped`). Deliberately proxy-
/// independent and pure-file (D8②: must work when the proxy is stopped).
pub(crate) fn restore_at(paths: &DesktopPaths) -> Result<RestoreResult, String> {
    match detect_state(paths) {
        DesktopState::NotInstalled => Ok(RestoreResult::NothingToDo),
        DesktopState::DetectionFailed => Err(match detect_installation(paths) {
            DesktopInstallation::DetectionFailed(e) => {
                format!("Claude Desktop installation detection failed: {e}")
            }
            _ => "Claude Desktop installation detection failed".to_string(),
        }),
        DesktopState::ForeignActive => Ok(RestoreResult::NotOursSkipped),
        DesktopState::ConfigInvalid => Err(config_invalid_sentence(paths)),
        // Our own residue (mode=3p, nobody's profile). Same treatment as
        // OursActive: write 1p back and clear what is left. Skipping it —
        // which is what the pre-2026-08-31 ForeignActive verdict caused —
        // parks Claude Desktop on a gateway nobody serves with no way back.
        DesktopState::OrphanedThirdParty => {
            write_deployment_mode(&paths.normal_config, "1p")?;
            if paths.threep_config.exists() {
                write_deployment_mode(&paths.threep_config, "1p")?;
            }
            remove_our_residue(paths)?;
            Ok(RestoreResult::Restored)
        }
        DesktopState::Official => {
            // Mode already official; clear any residue we left behind
            // (profile + meta claim) so state converges. No mode write.
            let removed = remove_our_residue(paths)?;
            Ok(if removed {
                RestoreResult::Restored
            } else {
                RestoreResult::NothingToDo
            })
        }
        DesktopState::OursActive => {
            write_deployment_mode(&paths.normal_config, "1p")?;
            // The 3p-side copy may be missing (e.g. partially cleaned) —
            // only rewrite it when present; creating it during RESTORE
            // would leave more residue than we found.
            if paths.threep_config.exists() {
                write_deployment_mode(&paths.threep_config, "1p")?;
            }
            remove_our_residue(paths)?;
            Ok(RestoreResult::Restored)
        }
    }
}

/// Remove our profile file + our `_meta.json` claim. Returns whether
/// anything was actually removed. Foreign profile files are never touched.
fn remove_our_residue(paths: &DesktopPaths) -> Result<bool, String> {
    let mut removed = false;
    if paths.profile.exists() {
        delete_guarded(&paths.profile)?;
        removed = true;
    }
    if applied_id(&paths.meta).as_deref() == Some(PROFILE_ID) {
        let mut obj = read_json_object(&paths.meta)?;
        obj.as_object_mut().map(|m| m.remove("appliedId"));
        write_json_guarded(&paths.meta, &obj)?;
        removed = true;
    }
    Ok(removed)
}

// ─── P2 · funnel reconcile + consent ────────────────────────────────────

/// Wire-facing summary of what the funnel did to Claude Desktop this pass.
/// Rides `LifecycleOutcome` into the vault-op envelope (`data.desktop_switch`)
/// and drives the web consent modal / restart toast (P3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct DesktopSwitch {
    /// Desktop installation detected on this machine.
    pub detected: bool,
    /// Desktop is (now) routed through the aikey gateway.
    pub configured: bool,
    /// This pass changed files — Desktop must be restarted to pick them up.
    pub restart_required: bool,
    /// A takeover is wanted but consent is missing and this context can't
    /// prompt (headless web bridge) — caller surfaces a consent dialog and
    /// replays `use` with `desktop_consent` (P3 flow).
    pub needs_consent: bool,
}

/// What the staleness reconcile did this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaleReconcile {
    /// No contradiction: not ours, not installed, or material present.
    NoAction,
    /// Our takeover was active with NO servable anthropic material — restored
    /// the official config (idempotent). Desktop must be restarted to pick it
    /// up; the note sidecar carries that fact to the tray.
    Restored,
    /// Contradiction found but the restore write failed — surfaced, not fatal.
    RestoreFailed,
}

/// Idempotent reconcile for the invariant「Desktop takeover active ⇔ anthropic
/// has servable material」(事件驱动写必配幂等对账读, enforced 2026-08-27).
///
/// WHY this exists: the un-takeover half of the funnel only runs on
/// `key use`/`key unuse`/`hook uninstall`. An account switch (`aikey login`)
/// marks the bound key disabled_by_account_scope WITHOUT passing through any
/// of those, so the 3p config outlived its credential and Claude Desktop sat
/// on a dead route with an error page we cannot edit (customer machine,
/// 2026-08-27; reproduced in tests). This is the missing reconcile READ on the
/// consumption path — `status` — which both the tray poll and a human
/// diagnosing the machine are guaranteed to hit.
///
/// Safety properties (each fenced):
///   - only OursActive is ever touched — Official / ForeignActive (cc-switch)
///     are never modified, contradiction or not;
///   - restore is idempotent (second pass → NoAction);
///   - a restore failure degrades to a report, never an error — status is a
///     read surface and must keep answering (旁路不阻塞主链路).
pub(crate) fn reconcile_stale_takeover(proxy_port: u16) -> StaleReconcile {
    let Some(paths) = desktop_paths() else {
        return StaleReconcile::NoAction;
    };
    reconcile_stale_at(&paths, proxy_port)
}

/// Testable core of `reconcile_stale_takeover` (paths injected — the same
/// pattern as `reconcile_active_at`, so fences exercise the REAL logic).
pub(crate) fn reconcile_stale_at(paths: &DesktopPaths, proxy_port: u16) -> StaleReconcile {
    // TWO healable states, not one (2026-08-31, winpc2 live).
    //
    //   OursActive          — takeover live; heal only when its material died.
    //   OrphanedThirdParty  — mode=3p with nobody's profile: OUR residue, and
    //                         ALWAYS wrong regardless of material. A machine
    //                         parked here routes Claude Desktop at a gateway
    //                         nobody serves. The first version gated on
    //                         OursActive alone, so an already-orphaned machine
    //                         answered NoAction for ever — the heal existed and
    //                         could not be reached (found on winpc2 AFTER the
    //                         orphan verdict shipped: state read correctly,
    //                         deploymentMode stayed 3p).
    match detect_state(paths) {
        DesktopState::OrphanedThirdParty => {} // always heal — no material test
        DesktopState::OursActive => {
            if route_material_for_anthropic(proxy_port).is_some() {
                return StaleReconcile::NoAction;
            }
        }
        _ => return StaleReconcile::NoAction,
    }
    // 🔴 restore_at, NOT remove_our_residue (fixed 2026-08-31, winpc2).
    // The first version called the residue cleaner directly and skipped the
    // `write_deployment_mode(1p)` that restore_at does FIRST — leaving
    // mode=3p with nobody's profile applied: an orphan the old detect_state
    // read as ForeignActive, which our own guard then refused to touch. The
    // machine could never come back, while the log claimed "auto-restored".
    // Calling the established restore keeps ONE implementation of "undo a
    // takeover" instead of a second one that drifts.
    match restore_at(paths) {
        Ok(_) => {
            // Best-effort note so the tray can keep saying "restart Claude
            // Desktop" after the fact. Enhancement, never a dependency: a
            // failed write is a WARN and nothing else changes.
            write_restore_note();
            eprintln!(
                "[aikey] Claude Desktop takeover auto-restored: its anthropic credential is no \
                 longer usable on this machine (signed into a different account, or the key was \
                 revoked). Restart Claude Desktop to reconnect it to claude.ai directly."
            );
            StaleReconcile::Restored
        }
        Err(e) => {
            eprintln!(
                "[aikey] warning: Claude Desktop is routed through aikey but anthropic has no \
                 usable credential, and restoring the official config failed: {}. Claude Desktop \
                 will not connect until a credential is bound or the takeover is removed.",
                e
            );
            StaleReconcile::RestoreFailed
        }
    }
}

/// Sidecar note: the tray reads it to keep showing "restart Claude Desktop"
/// after an auto-restore (state alone cannot say it — post-restore the config
/// IS official, but a running Desktop still holds the old routing in memory).
/// Cleared on the next successful takeover. Read/write are both soft.
fn restore_note_path() -> Option<PathBuf> {
    Some(
        crate::commands_account::shell_integration::resolve_aikey_dir()
            .join("desktop_restore_note.json"),
    )
}

fn write_restore_note() {
    let Some(path) = restore_note_path() else {
        return;
    };
    let note = json!({
        "restored_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "reason": "no servable anthropic credential",
    });
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(&path, note.to_string()) {
        eprintln!(
            "[aikey] warning: could not record the desktop restore note: {}",
            e
        );
    }
}

/// Whether an auto-restore note is present and fresh (≤48h). Soft read: a
/// missing or corrupt note is simply "no note".
pub(crate) fn recent_restore_note() -> bool {
    let Some(path) = restore_note_path() else {
        return false;
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    let ts = v.get("restored_at").and_then(|t| t.as_u64()).unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(ts) <= 48 * 3600
}

pub(crate) fn clear_restore_note() {
    if let Some(path) = restore_note_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Funnel entry (anthropic-active branch). State machine per plan §4.1:
/// NotInstalled→skip; OursActive→material drift compare, rewrite if changed;
/// Official/Foreign→consent gate (pref `always`→takeover, `never`→skip,
/// absent→TTY prompt when `interactive`, else `needs_consent`).
///
/// Never returns Err — desktop trouble must not fail the `use` that
/// triggered it (soft-fail: WARN on stderr, envelope shows configured=false).
pub(crate) fn reconcile_active(proxy_port: u16, interactive: bool) -> DesktopSwitch {
    let Some(paths) = desktop_paths() else {
        return DesktopSwitch::default(); // unsupported platform (R7)
    };
    reconcile_active_at(&paths, proxy_port, interactive)
}

/// Testable core of `reconcile_active` (paths injected).
pub(crate) fn reconcile_active_at(
    paths: &DesktopPaths,
    proxy_port: u16,
    interactive: bool,
) -> DesktopSwitch {
    match detect_state(paths) {
        DesktopState::NotInstalled => DesktopSwitch::default(),
        DesktopState::DetectionFailed => {
            let detail = match detect_installation(paths) {
                DesktopInstallation::DetectionFailed(e) => e,
                _ => "unknown Windows package discovery failure".to_string(),
            };
            eprintln!(
                "[aikey] warning: Claude Desktop installation detection failed; active key was still updated: {}",
                detail
            );
            DesktopSwitch::default()
        }
        DesktopState::OursActive => perform_takeover(paths, proxy_port),
        DesktopState::ConfigInvalid => {
            // Say why, once per pass; never write. The row / `desktop status`
            // carry the same sentence.
            eprintln!("  ! {}", config_invalid_sentence(paths));
            DesktopSwitch {
                detected: true,
                ..Default::default()
            }
        }
        // Our own residue takes the consent path like Official does: there is
        // no third party to surprise, and a fresh takeover overwrites the
        // orphan cleanly (2026-08-31).
        DesktopState::Official | DesktopState::OrphanedThirdParty | DesktopState::ForeignActive => {
            match crate::global_config::get_claude_desktop_consent()
                .unwrap_or(None)
                .as_deref()
            {
                Some("always") => perform_takeover(paths, proxy_port),
                Some("never") => DesktopSwitch {
                    detected: true,
                    ..Default::default()
                },
                _ if interactive => match prompt_takeover_consent() {
                    ConsentAnswer::Yes => perform_takeover(paths, proxy_port),
                    ConsentAnswer::Always => {
                        let _ = crate::global_config::set_claude_desktop_consent("always");
                        perform_takeover(paths, proxy_port)
                    }
                    ConsentAnswer::Never => {
                        let _ = crate::global_config::set_claude_desktop_consent("never");
                        DesktopSwitch {
                            detected: true,
                            ..Default::default()
                        }
                    }
                    ConsentAnswer::No => DesktopSwitch {
                        detected: true,
                        ..Default::default()
                    },
                },
                _ => DesktopSwitch {
                    detected: true,
                    needs_consent: true,
                    ..Default::default()
                },
            }
        }
    }
}

/// Consent already established (pref, TTY answer, or web `desktop_consent`
/// replay) — write the takeover and translate the result to wire shape.
pub(crate) fn perform_takeover(paths: &DesktopPaths, proxy_port: u16) -> DesktopSwitch {
    let Some(material) = route_material_for_anthropic(proxy_port) else {
        // has_anthropic implied a binding; defensive skip if it vanished.
        eprintln!("[aikey] warning: claude desktop takeover skipped — no anthropic binding");
        return DesktopSwitch {
            detected: true,
            ..Default::default()
        };
    };
    match takeover_at(paths, &material) {
        Ok(TakeoverResult::Installed) => {
            clear_restore_note();
            DesktopSwitch {
                detected: true,
                configured: true,
                restart_required: true,
                needs_consent: false,
            }
        }
        Ok(TakeoverResult::Unchanged) => DesktopSwitch {
            detected: true,
            configured: true,
            restart_required: false,
            needs_consent: false,
        },
        Err(e) => {
            // Soft-fail (plan R8): binding already switched; desktop write
            // failure must not fail `use`.
            eprintln!("[aikey] warning: claude desktop takeover failed: {}", e);
            DesktopSwitch {
                detected: true,
                ..Default::default()
            }
        }
    }
}

enum ConsentAnswer {
    Yes,
    No,
    Always,
    Never,
}

/// TTY consent prompt (D2/D3). Prompt + input both ride stderr/stdin so
/// stdout stays machine-clean (json_mode callers). Default = Yes.
fn prompt_takeover_consent() -> ConsentAnswer {
    use std::io::Write;
    eprint!(
        "  Claude Desktop detected — route it through aikey too? \
         (rewrites its config; restart required) [Y/n/always/never]: "
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return ConsentAnswer::No; // can't read → don't touch the GUI
    }
    match line.trim().to_lowercase().as_str() {
        "" | "y" | "yes" => ConsentAnswer::Yes,
        "always" | "a" => ConsentAnswer::Always,
        "never" => ConsentAnswer::Never,
        _ => ConsentAnswer::No,
    }
}

/// Funnel entry (anthropic-inactive branch) + hook-uninstall path (D8).
/// Restores official mode when WE took over; clears an `always` grant when
/// a restore actually happened (D6 supplement — the next takeover must ask
/// again). Proxy-independent, soft-fail, quiet on no-op.
pub(crate) fn restore_quiet() {
    let Some(paths) = desktop_paths() else { return };
    restore_quiet_at(&paths);
}

/// Testable core of `restore_quiet` (paths injected).
pub(crate) fn restore_quiet_at(paths: &DesktopPaths) {
    match restore_at(paths) {
        Ok(RestoreResult::Restored) => {
            let _ = crate::global_config::clear_claude_desktop_consent_always();
            eprintln!("  Claude Desktop restored to official mode (1p) — restart Desktop to apply");
        }
        Ok(RestoreResult::NotOursSkipped) | Ok(RestoreResult::NothingToDo) => {}
        Err(e) => {
            eprintln!("[aikey] warning: claude desktop restore failed: {}", e);
        }
    }
}

/// Local-proxy port currently written into the Desktop profile's
/// `inferenceGatewayBaseUrl`, or None when Desktop isn't installed, the
/// takeover isn't ours (`OursActive` only — a foreign gateway on a loopback
/// port is not ours to compare), or the URL isn't loopback.
///
/// Read-only doctor surface for the drift stale-port check
/// (20260728-端口漂移baseurl自愈回写); healing goes through
/// `reconcile_active` via the third-party funnel.
pub(crate) fn profile_local_baseurl_port() -> Option<u16> {
    let paths = desktop_paths()?;
    if !matches!(detect_state(&paths), DesktopState::OursActive) {
        return None;
    }
    let profile = read_json_object(&paths.profile).ok()?;
    let base_url = profile["inferenceGatewayBaseUrl"].as_str()?;
    crate::profile_activation::local_url_port(base_url)
}

// ─── P2 · `aikey desktop` command handlers (plan §4.5) ──────────────────

/// `aikey desktop status [--json]`. Read-only diagnosis surface — the ONLY
/// place a user can see why Desktop routing isn't working, so it must
/// separate the two planes (risk 9): gateway reachability vs claude.ai
/// account-plane reachability, plus port drift (risk 7) and the scanned
/// paths when nothing was detected (risk 8).
pub(crate) fn handle_desktop_status(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let paths = desktop_paths();
    let (installed, install_source, install_detection_error, state, profile_base_url) = match &paths
    {
        None => (false, None, None, "unsupported-platform".to_string(), None),
        Some(p) => {
            let installation = detect_installation(p);
            let (is_installed, source, detection_error) = match &installation {
                DesktopInstallation::Legacy => {
                    #[cfg(windows)]
                    let source = "legacy";
                    #[cfg(not(windows))]
                    let source = "native";
                    (true, Some(source), None)
                }
                DesktopInstallation::Msix => (true, Some("msix"), None),
                DesktopInstallation::NotInstalled => (false, None, None),
                DesktopInstallation::DetectionFailed(e) => (false, None, Some(e.to_string())),
            };
            let st = match detect_state(p) {
                DesktopState::NotInstalled => "not-installed",
                DesktopState::DetectionFailed => "detection-failed",
                DesktopState::Official => "official",
                DesktopState::OursActive => "aikey",
                DesktopState::ForeignActive => "other",
                DesktopState::ConfigInvalid => "config-invalid",
                // Says what it is, not who owns it: "other" sent a 2026-08-31
                // diagnosis down the wrong path ("another tool took it over")
                // when the truth was our own leftovers.
                DesktopState::OrphanedThirdParty => "orphaned-3p (our residue)",
            };
            let base_url = read_json_object(&p.profile)
                .ok()
                .and_then(|v| v["inferenceGatewayBaseUrl"].as_str().map(str::to_string));
            (
                is_installed,
                source,
                detection_error,
                st.to_string(),
                base_url,
            )
        }
    };
    let pref = crate::global_config::get_claude_desktop_consent().unwrap_or(None);

    // Port consistency (risk 7): a stale port in the profile is the one
    // failure `aikey use` can't heal until the next binding touch.
    let proxy_port = crate::commands_proxy::proxy_port();
    let stale_port = profile_base_url
        .as_deref()
        .filter(|u| u.contains("127.0.0.1"))
        .map(|u| !u.contains(&format!(":{}/", proxy_port)))
        .unwrap_or(false);

    // Gateway-plane probe: the exact request Desktop fires on startup.
    let gateway_probe = profile_base_url.as_deref().map(|base| {
        let token = read_json_object(&paths.as_ref().unwrap().profile)
            .ok()
            .and_then(|v| v["inferenceGatewayApiKey"].as_str().map(str::to_string))
            .unwrap_or_default();
        let ok = ureq::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .get(&format!("{}/v1/models", base))
            .set("Authorization", &format!("Bearer {}", token))
            .call()
            .is_ok();
        if ok {
            "ok"
        } else {
            "fail"
        }
    });

    // Account-plane probe (risk 9): geo-blocked claude.ai = chat hangs at
    // "starting session" with zero symptoms anywhere else. 302 to the
    // app-unavailable page is the block signature (spike 2026-07-13).
    let account_plane = {
        let agent = ureq::builder()
            .timeout(std::time::Duration::from_secs(2))
            .redirects(0)
            .build();
        match agent.get("https://claude.ai/").call() {
            Ok(resp) => {
                let loc = resp.header("location").unwrap_or("");
                if loc.contains("app-unavailable-in-region") {
                    "blocked-in-region"
                } else {
                    "ok"
                }
            }
            Err(ureq::Error::Status(code, resp)) => {
                let loc = resp.header("location").unwrap_or("");
                if loc.contains("app-unavailable-in-region") {
                    "blocked-in-region"
                } else if (300..500).contains(&code) {
                    "ok" // reachable; 3xx/4xx bodies are fine for a liveness read
                } else {
                    "unreachable"
                }
            }
            Err(_) => "unreachable",
        }
    };

    let scanned: Vec<String> = paths
        .as_ref()
        .map(|p| {
            #[cfg(windows)]
            {
                let mut inspected = vec![p.install_marker.display().to_string()];
                if !matches!(p.msix_detection, MsixDetection::NotChecked) {
                    inspected.push("windows-package-current-user:Claude".to_string());
                }
                inspected
            }
            #[cfg(not(windows))]
            {
                vec![p.install_marker.display().to_string()]
            }
        })
        .unwrap_or_default();

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "installed": installed,
            "install_source": install_source,
            "install_detection_error": install_detection_error,
            "state": state,
            "consent_pref": pref,
            "profile_path": paths.as_ref().map(|p| p.profile.display().to_string()),
            "base_url": profile_base_url,
            "gateway_probe": gateway_probe,
            "stale_port": stale_port,
            "account_plane": account_plane,
            "scanned_paths": scanned,
        }));
        return Ok(());
    }

    println!("  Claude Desktop");
    println!("    installed:      {}", installed);
    if let Some(source) = install_source {
        println!("    install source: {}", source);
    }
    println!("    state:          {}", state);
    if let Some(error) = &install_detection_error {
        println!(
            "    {} detection:     Windows package lookup failed: {}",
            crate::symbols::WARN.s(),
            error
        );
    }
    println!("    consent:        {}", pref.as_deref().unwrap_or("(ask)"));
    if let Some(p) = &paths {
        if installed {
            if let Some(base) = &profile_base_url {
                println!("    gateway:        {}", base);
                if let Some(g) = gateway_probe {
                    println!("    gateway probe:  {}", g);
                }
                if stale_port {
                    println!(
                        "    {} stale-port:   profile points at a different port than the \
                         running proxy ({}) — run `aikey use <claude credential>` to heal",
                        crate::symbols::WARN.s(),
                        proxy_port
                    );
                }
            }
            println!("    profile:        {}", p.profile.display());
        } else {
            // Risk 8 / D11: expose every installation evidence surface used.
            println!("    scanned:        {}", p.install_marker.display());
            #[cfg(windows)]
            println!("                    current-user package: Claude");
        }
    }
    println!("    claude.ai:      {}", account_plane);
    if account_plane == "blocked-in-region" {
        println!(
            "    {} Desktop chat needs claude.ai reachability (account plane) — \
             the aikey gateway only carries inference. Provide international \
             egress (proxy) or Desktop will hang at \"starting session\".",
            crate::symbols::WARN.s()
        );
    }
    Ok(())
}

/// `aikey desktop install` — manual takeover (D8①). The explicit command is
/// itself actionable consent: it clears a standing `never` (its documented
/// exit) and, on a TTY with no pref, still confirms once (default Yes).
/// The refusal the user reads when Desktop cannot be taken over.
///
/// 🔴 A named function so it can be fenced (2026-08-31). The message used to be
/// one sentence for two very different situations, and for the situation that
/// actually happened — a key WAS chosen, it just was not servable — it told the
/// user to go and choose a key. They had already done that; the panel was even
/// showing it as bound. Being sent to redo the one step you got right is worse
/// than a bare error.
fn desktop_refusal(unservable_reason: Option<String>) -> String {
    match unservable_reason {
        // A credential IS bound; it cannot be served right now. Never suggest
        // `aikey use` here — choosing it again changes nothing.
        Some(why) => format!(
            "[I_DESKTOP_KEY_NOT_SERVABLE] the credential bound to claude cannot be used \
             right now: {}. Desktop follows that binding, so it was not taken over. \
             Nothing on this machine was changed.",
            why
        ),
        // Nothing is bound at all — here, choosing one IS the next step.
        None => "[I_DESKTOP_NO_ANTHROPIC_BINDING] no active claude credential — run \
                 `aikey use <claude credential>` first (Desktop follows the active binding)"
            .to_string(),
    }
}

pub(crate) fn handle_desktop_install() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::IsTerminal;
    let Some(paths) = desktop_paths() else {
        return Err(
            "[I_DESKTOP_UNSUPPORTED_PLATFORM] Claude Desktop has no build for this platform \
             (supported: macOS, Windows)"
                .into(),
        );
    };
    match detect_installation(&paths) {
        DesktopInstallation::NotInstalled => {
            #[cfg(windows)]
            let inspected = format!(
                "{} and the current-user Windows package registration",
                paths.install_marker.display()
            );
            #[cfg(not(windows))]
            let inspected = paths.install_marker.display().to_string();
            return Err(format!(
                "[I_DESKTOP_NOT_INSTALLED] Claude Desktop not found (looked at {}). \
                 Install it first, then re-run `aikey desktop install`.",
                inspected
            )
            .into());
        }
        DesktopInstallation::DetectionFailed(e) => {
            return Err(format!(
                "[I_DESKTOP_DETECTION_FAILED] Claude Desktop installation could not be checked: \
                 {}. The active key is unchanged; retry from a normal (non-service) user session \
                 or run `aikey desktop status` for details.",
                e
            )
            .into())
        }
        DesktopInstallation::Legacy | DesktopInstallation::Msix => {}
    }
    let proxy_port = crate::commands_proxy::proxy_port();
    if route_material_for_anthropic(proxy_port).is_none() {
        // 🔴 Two different situations, two different next steps (2026-08-31).
        //
        // The single message used to be "run `aikey use` first" — which, when the
        // user HAD already chosen a key, sent them to redo the one thing they had
        // done right. That is what made the winpc2 report so confusing: the panel
        // showed the credential bound while this told them there was none.
        //
        // The explanation comes from the shared layer (`unservable_reason`); this
        // file must not inspect key fields itself — re-deriving the rule here is
        // exactly the mistake that caused the outage.
        let on_cluster = crate::commands_account::read_cluster_node().is_some();
        let bound = crate::storage::get_provider_binding("default", "anthropic")
            .ok()
            .flatten();
        let why = bound.and_then(|b| {
            crate::storage::get_virtual_key_cache(&b.key_source_ref)
                .ok()
                .flatten()
                .and_then(|k| k.unservable_reason(on_cluster))
        });
        return Err(desktop_refusal(why).into());
    }
    let pref = crate::global_config::get_claude_desktop_consent().unwrap_or(None);
    if pref.as_deref() == Some("never") {
        // Actionable consent: explicit install lifts the standing refusal.
        let _ = crate::global_config::clear_claude_desktop_consent();
    } else if pref.is_none() && std::io::stderr().is_terminal() {
        match prompt_takeover_consent() {
            ConsentAnswer::No => {
                eprintln!("  Skipped — Claude Desktop left untouched.");
                return Ok(());
            }
            ConsentAnswer::Never => {
                let _ = crate::global_config::set_claude_desktop_consent("never");
                eprintln!("  Skipped — will not ask again (undo: `aikey desktop install`).");
                return Ok(());
            }
            ConsentAnswer::Always => {
                let _ = crate::global_config::set_claude_desktop_consent("always");
            }
            ConsentAnswer::Yes => {}
        }
    }
    let switch = perform_takeover(&paths, proxy_port);
    if !switch.configured {
        return Err(
            "[I_DESKTOP_WRITE_FAILED] takeover did not complete — see the warning above".into(),
        );
    }
    if switch.restart_required {
        println!(
            "  {} Claude Desktop now routes through aikey — restart Desktop to apply.",
            crate::symbols::CHECK.s()
        );
    } else {
        println!(
            "  {} Claude Desktop already routed through aikey (no changes).",
            crate::symbols::CHECK.s()
        );
    }
    Ok(())
}

/// `aikey desktop uninstall` — manual restore + full consent reset (D8①,
/// D3's documented revocation path). Clears BOTH `always` and `never`.
pub(crate) fn handle_desktop_uninstall() -> Result<(), Box<dyn std::error::Error>> {
    let Some(paths) = desktop_paths() else {
        // Nothing a Desktop-less platform could have to undo; clearing the
        // pref is still meaningful (e.g. synced config).
        let _ = crate::global_config::clear_claude_desktop_consent();
        println!("  Nothing to restore on this platform.");
        return Ok(());
    };
    let result = restore_at(&paths)?;
    let _ = crate::global_config::clear_claude_desktop_consent();
    match result {
        RestoreResult::Restored => {
            println!(
                "  {} Claude Desktop restored to official mode (1p) — restart Desktop to apply.",
                crate::symbols::CHECK.s()
            );
        }
        RestoreResult::NotOursSkipped => {
            println!(
                "  Current 3p setup was not applied by aikey — left untouched. \
                 (Consent preference cleared.)"
            );
        }
        RestoreResult::NothingToDo => {
            println!("  Claude Desktop already in official mode — nothing to restore.");
        }
    }
    Ok(())
}

// ─── Tests (P1 plan §3.3 — all inject tempdir paths, never real HOME) ───

#[cfg(test)]
mod tests {
    // ─── 2026-08-27 客户机复现：接管滞留（材料消失后无人收拾）────────
    //
    // 复刻时序（全部真实函数，无 mock）：
    //   1. 有 anthropic 材料（team VK active + binding 行）→ 接管写下
    //   2. 账号切换打标 disable_keys_for_account_scope（login 的真实路径）
    //   3. 期间没有任何 key use/unuse → funnel 从未运行
    // 期望不变量（对账读，尚未实现 → 本测试当前 RED = 复现成功）：
    //   「Desktop 接管 active ⇔ anthropic 路由有可服务材料」
    // 现状（复现证据，见 -- --nocapture 输出）：
    //   接管仍 OursActive；route_material_for_anthropic 仍 Some（binding 行
    //   还在，指向已 disabled 的 VK）——与面板 routes 投影的「未设置」分裂：
    //   同一个「anthropic 有没有凭据」两份实现两个答案。Desktop 打 proxy，
    //   proxy 的路由查询过滤 disabled_by_% → 请求失败 → 客户看到
    //   "Couldn't connect to Claude"（推理面假设 A 的我方边界内证据）。
    /// 🔴 这个文件不许自己推导「KEY 能不能服务」（2026-08-31）。
    ///
    /// 上一版就是在这里从零写了第四份判据并写窄了。行为围栏能挡住"这一次写错"，
    /// 挡不住"下一次又抄一份"——所以再加一道结构断言：本文件的**生产代码**里
    /// 不得出现 `local_state`，要问就问 `is_servable`。
    ///
    /// 扫描前先剥掉注释行，且只扫 `#[cfg(test)]` 之前的部分：注释里本来就写着
    /// `local_state == "active"` 在讲这段历史，测试 fixture 也要写这个字段——
    /// 不剥就会被自己的文字骗（本仓已有三次自匹配围栏的先例）。
    #[test]
    fn this_file_does_not_re_derive_servability() {
        let src = include_str!("claude_desktop.rs");
        let production = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => src,
        };
        let code_only: String = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let needle = format!("local{}state", "_");
        assert!(
            !code_only.contains(&needle),
            "生产代码里又出现了 {needle} —— 可服务性判据只有一个名字（is_servable）。\
             自己推导一份，就是 2026-08-28 那次的复现方式"
        );
        assert!(
            code_only.contains(&format!("is{}servable(", "_")),
            "守卫不再向共享判据提问了；它一旦自己判断，就会和 picker / web / \
             activation 给出不同答案（面板说 bound=true、接管说没凭据）"
        );
    }

    #[test]
    /// 🔴 已经选好 KEY 的用户，不能被支去重新选一次（2026-08-31，winpc2）。
    ///
    /// 两种失败长得完全不同：
    ///   - 压根没绑定 → "去 `aikey use` 选一个" 是对的下一步
    ///   - 绑了但当前不可服务 → 再选一次**什么都不会变**，这句话纯属误导
    /// 出事那天用户看到的正是后者配前者的文案，于是他反复确认自己"明明选了 KEY"。
    ///
    /// 能红：把两条分支的错误码/文案换成同一句。
    fn refusal_tells_a_bound_key_apart_from_no_key_at_all() {
        let bound_but_dead = desktop_refusal(Some("the key is revoked on the server".into()));
        assert!(
            bound_but_dead.contains("I_DESKTOP_KEY_NOT_SERVABLE"),
            "GUI 要靠错误码开对的表单，两种失败必须给不同的码：{bound_but_dead}"
        );
        assert!(
            bound_but_dead.contains("revoked"),
            "没把「为什么不可用」带出来，用户只知道失败不知道下一步：{bound_but_dead}"
        );
        assert!(
            !bound_but_dead.contains("aikey use"),
            "把已经选好 KEY 的用户支去重新选 —— 这正是 winpc2 那天的困惑来源：{bound_but_dead}"
        );

        let nothing_bound = desktop_refusal(None);
        assert!(
            nothing_bound.contains("I_DESKTOP_NO_ANTHROPIC_BINDING"),
            "真的没绑定时要保留原来的码，别把既有的 GUI 处理逻辑打断"
        );
        assert!(
            nothing_bound.contains("aikey use"),
            "这一种情况下「去选一个」才是正确的下一步，不该被一并删掉"
        );
    }

    #[test]
    /// 🔴 winpc2 的那台机器，作为围栏（2026-08-31）。
    ///
    /// 用户选好了团队 KEY、绑定在、面板自己都显示 `bound: true`，点接管却报
    /// `I_DESKTOP_NO_ANTHROPIC_BINDING`「没有可用的 claude 凭据」。原因是
    /// 2026-08-28 加的守卫自己另写了一份判据，要求 `local_state == "active"` ——
    /// 而同步链路给团队 KEY 写的一直是 `synced_inactive`。守卫因此恒假，
    /// **所有**带团队凭据的机器都装不上接管；`reconcile_stale_at` 用的是同一个
    /// 函数，所以已装好的接管还会被它主动拆掉。
    ///
    /// 能红：把守卫改回 `k.local_state == "active"`。
    fn a_synced_team_key_is_servable_material_for_desktop() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let pw = secrecy::SecretString::new("winpc2-pw".to_string());
        crate::storage::initialize_vault(&salt, &pw).unwrap();

        // 真机形态：OAuth 组 KEY，本地无密文（设计如此），local_state 是同步链路
        // 实际写入的 synced_inactive。
        seed_active_vk_with_binding();

        assert!(
            route_material_for_anthropic(27200).is_some(),
            "同步下来的团队 KEY 被判成「没有凭据」——用户选好了 KEY、绑定在、\
             面板显示 bound=true，接管却装不上（winpc2 2026-08-31 现场）"
        );
    }

    #[test]
    fn takeover_left_stale_when_account_scope_disables_the_key() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let pw = secrecy::SecretString::new("takeover-stale-pw".to_string());
        crate::storage::initialize_vault(&salt, &pw).unwrap();

        // 1a. team VK（acct-1 所有，active）——客户机上就是 key-damonlee1020-…
        let entry = crate::storage::VirtualKeyCacheEntry {
            binding_id: String::new(),
            virtual_key_id: "vk-cust".into(),
            org_id: "org-1".into(),
            seat_id: "seat-1".into(),
            alias: "key-cust-claude".into(),
            provider_code: "anthropic".into(),
            protocol_type: "anthropic".into(),
            base_url: String::new(),
            credential_id: String::new(),
            credential_revision: String::new(),
            virtual_key_revision: String::new(),
            key_status: "active".into(),
            share_status: "accepted".into(),
            // 🔴 真机形态，不是想当然的取值（2026-08-31）。同步链路写的是
            // `synced_inactive`（storage.rs，2026-06-05 起），`"active"` 这个值
            // 生产里根本不出现 —— 上一版 fixture 就是拿它演了一台不存在的机器，
            // 于是守卫写错了判据而围栏全绿。
            local_state: "synced_inactive".into(),
            expires_at: None,
            provider_key_nonce: None,
            provider_key_ciphertext: None,
            synced_at: 0,
            local_alias: None,
            supported_providers: vec!["anthropic".into()],
            provider_base_urls: std::collections::HashMap::new(),
            priority: 1,
            fallback_role: "primary".into(),
            route_group_id: String::new(),
            route_group_name: String::new(),
            owner_account_id: Some("acct-1".into()),
            owner_email: None,
            extra: None,
            // OAuth 组 KEY：材料由 proxy 走通道③拉取，本地无密文是**设计如此**。
            // winpc2 上出问题的那把（team-oauth-开发组-…）正是这个形态。
            oauth_group_id: Some("grp-1".into()),
            group_accounts: None,
            routing_config: None,
            group_alias: None,
            group_runtime: None,
        };
        crate::storage::upsert_virtual_key_cache(&entry).unwrap();
        // 1b. anthropic 路由绑定 → 材料可得
        crate::storage::set_provider_binding(
            "default",
            "anthropic",
            "managed_virtual_key",
            "vk-cust",
        )
        .unwrap();
        assert!(
            route_material_for_anthropic(27200).is_some(),
            "前提：有材料（否则接管不会发生）"
        );

        // 1c. 接管写下（真实 reconcile：consent=always 复刻客户机「开关全开」）
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        let tmp_desk = TempDir::new().unwrap();
        let paths = installed_paths(&tmp_desk);
        let sw = reconcile_active_at(&paths, 27200, false);
        assert!(sw.configured, "接管必须成功写下（客户机的既成事实）");
        assert_eq!(detect_state(&paths), DesktopState::OursActive);

        // 2. 账号切换（feishu 登录）→ login 真实路径打标；funnel 不跑
        crate::storage::disable_keys_for_account_scope("acct-feishu").unwrap();

        // ── 复现证据输出 ──
        let material_after = route_material_for_anthropic(27200);
        let state_after = detect_state(&paths);
        eprintln!("── 复现现场 ──");
        eprintln!("  VK local_state      : disabled_by_account_scope（login 打标）");
        eprintln!("  binding 行           : 仍存在（无人清理）");
        eprintln!(
            "  route_material       : {:?}",
            material_after.as_ref().map(|m| &m.base_url)
        );
        eprintln!("  desktop detect_state : {:?}（3p 配置滞留）", state_after);

        // ── 不变量 1（材料统一真相源，2026-08-27 修复）：disabled key 不是材料 ──
        assert!(
            material_after.is_none(),
            "material consistency: key 已 disabled_by_account_scope，takeover 材料函数必须与\
             面板 routes 投影同答「无」— 答 Some 就是同概念两份实现的分裂（客户机事故根因之一）"
        );
        // 打标本身不动 Desktop 文件（login 路径没有 funnel）——滞留仍在：
        assert_eq!(
            state_after,
            DesktopState::OursActive,
            "打标后、对账前：滞留存在（前提）"
        );

        // ── 不变量 2（幂等对账读）：status 必经之路收拾滞留 ──
        let first = reconcile_stale_at(&paths, 27200);
        assert_eq!(
            first,
            StaleReconcile::Restored,
            "对账必须把「接管 active + 无可服务材料」的滞留还原为官方直连"
        );
        assert_ne!(
            detect_state(&paths),
            DesktopState::OursActive,
            "还原后 3p 配置不得仍指向 aikey"
        );
        assert!(
            recent_restore_note(),
            "还原须留下 note，托盘据此持续提示重启 Desktop"
        );
        // 幂等：第二遍必须零动作（status 每 4s 轮询一次，churn 就是事故）
        assert_eq!(
            reconcile_stale_at(&paths, 27200),
            StaleReconcile::NoAction,
            "对账必须幂等 — 第二遍不得再产生任何动作"
        );
    }

    /// 🔴 终态围栏（2026-08-31，winpc2 真机发现）：对账**必须落到 Official**。
    ///
    /// 08-27 的第一版只调 `remove_our_residue`（删 profile + 清 appliedId），
    /// 漏掉了它前面那句 `write_deployment_mode(1p)` —— 结果 deploymentMode 仍是
    /// "3p"，机器停在 mode=3p + appliedId=空 的**孤儿态**：
    ///   · 日志却打 "auto-restored to direct claude.ai"（说谎：Desktop 仍指向死网关）
    ///   · detect_state 把它判成 ForeignActive → 我们自己的 Foreign 守卫拒绝再碰
    ///     → **回不来的中间态**（INV-E1/E2 明令禁止的形态）
    ///
    /// 原 5 条围栏为什么没拦住：它们只断言"离开了 OursActive"和"Foreign 字节不动"，
    /// **没有一条断言"到达了正确终态"**。断言起点不断言终点，孤儿态从这条缝穿过去。
    ///
    /// 能红：把 reconcile 改回只调 `remove_our_residue`。
    #[test]
    fn reconcile_lands_on_official_not_an_orphan() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let pw = secrecy::SecretString::new("orphan-pw".to_string());
        crate::storage::initialize_vault(&salt, &pw).unwrap();
        seed_active_vk_with_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        let tmp_desk = TempDir::new().unwrap();
        let paths = installed_paths(&tmp_desk);
        assert!(reconcile_active_at(&paths, 27200, false).configured);

        // 材料消失（账号切换的真实路径）
        crate::storage::disable_keys_for_account_scope("acct-other").unwrap();
        assert_eq!(reconcile_stale_at(&paths, 27200), StaleReconcile::Restored);

        // ── 终态断言（本围栏的全部理由）──
        assert_eq!(
            deployment_mode(&paths.normal_config).as_deref(),
            Some("1p"),
            "对账后 deploymentMode 必须回到 1p —— 否则 Desktop 仍指向已死的 aikey 网关，\
             而日志已经宣称 auto-restored（说谎）"
        );
        assert_eq!(
            detect_state(&paths),
            DesktopState::Official,
            "对账必须落到 Official。停在 mode=3p + appliedId 空 = 孤儿态，会被 detect_state \
             判成 ForeignActive，然后被我们自己的 Foreign 守卫永久拒绝触碰 —— 回不来的中间态"
        );
    }

    /// 🔴 已中招的机器必须能自愈（2026-08-31 winpc2 活体发现的第二道缝）。
    ///
    /// 上一版围栏只测「从 OursActive 出发 → 落到 Official」，而对账入口
    /// `if detect_state != OursActive { return NoAction }` 把孤儿态挡在门外：
    /// **判定修好了、自愈进不去门**，真机上 state 读对了而 deploymentMode 仍是 3p。
    /// 断言起点齐全 ≠ 断言全部入口。
    ///
    /// 能红：把入口 match 改回只认 OursActive。
    #[test]
    fn an_already_orphaned_machine_heals_itself() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        // winpc2 现场逐字形态：mode=3p、_meta 无 appliedId、库内无 profile
        write_deployment_mode(&paths.normal_config, "3p").unwrap();
        std::fs::create_dir_all(&paths.config_library).unwrap();
        std::fs::write(&paths.meta, "{}").unwrap();
        assert_eq!(detect_state(&paths), DesktopState::OrphanedThirdParty);

        assert_eq!(
            reconcile_stale_at(&paths, 27200),
            StaleReconcile::Restored,
            "孤儿态必须被对账收拾 —— 它与材料无关，任何时候都是错的"
        );
        assert_eq!(
            deployment_mode(&paths.normal_config).as_deref(),
            Some("1p"),
            "自愈后 deploymentMode 必须回到 1p，否则 Desktop 仍指向无人服务的网关"
        );
        assert_eq!(detect_state(&paths), DesktopState::Official);
        // 幂等：第二遍零动作
        assert_eq!(reconcile_stale_at(&paths, 27200), StaleReconcile::NoAction);
    }

    /// 孤儿态（已中招的机器）必须能被自愈，而**真** Foreign 依旧绝不触碰。
    /// 能红：把 OrphanedThirdParty 判定去掉（孤儿又变回 ForeignActive）。
    #[test]
    fn orphaned_third_party_is_healable_but_real_foreign_is_not() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);

        // 孤儿态：mode=3p，appliedId 空，configLibrary 无任何 profile 文件
        // （winpc2 2026-08-31 现场的逐字形态）
        write_deployment_mode(&paths.normal_config, "3p").unwrap();
        std::fs::create_dir_all(&paths.config_library).unwrap();
        std::fs::write(&paths.meta, "{}").unwrap();
        assert_eq!(
            detect_state(&paths),
            DesktopState::OrphanedThirdParty,
            "mode=3p 但没有任何 appliedId、也没有任何 profile 文件 —— 这是我们自己留下的\
             残骸，不是别人的接管；判成 Foreign 会让它永远无法自愈"
        );

        // 真 Foreign：别人的 appliedId 在
        std::fs::write(
            &paths.meta,
            r#"{"appliedId":"cc-switch-0000-0000-0000-000000000000"}"#,
        )
        .unwrap();
        assert_eq!(
            detect_state(&paths),
            DesktopState::ForeignActive,
            "有他人 appliedId = 真的被别的工具接管，安全承诺不变：绝不触碰"
        );
    }

    /// 围栏（不引发新问题之一）：正常态绝不误伤 — 材料在，对账零动作。
    /// 能红：把 reconcile 的材料检查取反 / 删掉 OursActive 门。
    #[test]
    fn reconcile_never_touches_a_healthy_takeover() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let pw = secrecy::SecretString::new("healthy-pw".to_string());
        crate::storage::initialize_vault(&salt, &pw).unwrap();
        seed_active_vk_with_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        let tmp_desk = TempDir::new().unwrap();
        let paths = installed_paths(&tmp_desk);
        assert!(reconcile_active_at(&paths, 27200, false).configured);

        // desktop_paths() inside reconcile_stale_takeover resolves from HOME —
        // point it at OUR tempdir installation by mirroring the layout there.
        // (installed_paths uses its own tempdir; the stale reconcile resolves
        // paths itself, so a healthy state must be asserted through the same
        // detect + material questions it asks.)
        assert_eq!(detect_state(&paths), DesktopState::OursActive);
        assert!(route_material_for_anthropic(27200).is_some());
        // The reconcile applied to THESE paths must answer NoAction:
        assert_eq!(reconcile_stale_at(&paths, 27200), StaleReconcile::NoAction);
        assert_eq!(
            detect_state(&paths),
            DesktopState::OursActive,
            "健康接管不得被拆"
        );
    }

    /// 围栏（不引发新问题之二）：别人的接管（cc-switch / 官方态）绝不触碰 —
    /// 哪怕矛盾条件成立（无材料）。能红：删掉 OursActive 守卫。
    #[test]
    fn reconcile_never_touches_foreign_or_official_configs() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let pw = secrecy::SecretString::new("foreign-pw".to_string());
        crate::storage::initialize_vault(&salt, &pw).unwrap();
        // 无任何 binding → 材料 None（矛盾条件的一半永真）
        let tmp_desk = TempDir::new().unwrap();
        let paths = installed_paths(&tmp_desk);
        // Official 态（无我方 profile）
        assert_ne!(detect_state(&paths), DesktopState::OursActive);
        let read_all = |p: &DesktopPaths| {
            (
                std::fs::read_to_string(&p.normal_config).unwrap_or_default(),
                std::fs::read_to_string(&p.threep_config).unwrap_or_default(),
                std::fs::read_to_string(&p.meta).unwrap_or_default(),
            )
        };
        let before = read_all(&paths);
        assert_eq!(reconcile_stale_at(&paths, 27200), StaleReconcile::NoAction);
        assert_eq!(before, read_all(&paths), "非我方接管的配置一个字节都不许动");
    }

    /// 围栏：note sidecar 软读 — 损坏 JSON 当作无 note，绝不 panic。
    #[test]
    fn restore_note_read_is_soft_against_corruption() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let aikey_dir = crate::commands_account::shell_integration::resolve_aikey_dir();
        std::fs::create_dir_all(&aikey_dir).unwrap();
        std::fs::write(aikey_dir.join("desktop_restore_note.json"), b"{corrupt").unwrap();
        assert!(
            !recent_restore_note(),
            "坏 note 必须当作无 note（增强非依赖）"
        );
    }

    /// 围栏（材料统一不误伤其它凭据型）：personal key 绑定不受 managed 检查影响。
    /// 能红：把 servable 检查扩到所有 key_source_type。
    #[test]
    fn material_check_only_gates_managed_keys() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("vault.db");
        let _guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).unwrap();
        let pw = secrecy::SecretString::new("personal-pw".to_string());
        crate::storage::initialize_vault(&salt, &pw).unwrap();
        crate::storage::set_provider_binding("default", "anthropic", "personal", "my-key").unwrap();
        assert!(
            route_material_for_anthropic(27200).is_some(),
            "personal 绑定无 disabled 概念，材料判定不得误杀"
        );
    }

    /// helper: 一条 active team VK + anthropic binding（多用例共用）。
    fn seed_active_vk_with_binding() {
        let entry = crate::storage::VirtualKeyCacheEntry {
            binding_id: String::new(),
            virtual_key_id: "vk-healthy".into(),
            org_id: "org-1".into(),
            seat_id: "seat-1".into(),
            alias: "key-healthy".into(),
            provider_code: "anthropic".into(),
            protocol_type: "anthropic".into(),
            base_url: String::new(),
            credential_id: String::new(),
            credential_revision: String::new(),
            virtual_key_revision: String::new(),
            key_status: "active".into(),
            share_status: "accepted".into(),
            // 🔴 真机形态，不是想当然的取值（2026-08-31）。同步链路写的是
            // `synced_inactive`（storage.rs，2026-06-05 起），`"active"` 这个值
            // 生产里根本不出现 —— 上一版 fixture 就是拿它演了一台不存在的机器，
            // 于是守卫写错了判据而围栏全绿。
            local_state: "synced_inactive".into(),
            expires_at: None,
            provider_key_nonce: None,
            provider_key_ciphertext: None,
            synced_at: 0,
            local_alias: None,
            supported_providers: vec!["anthropic".into()],
            provider_base_urls: std::collections::HashMap::new(),
            priority: 1,
            fallback_role: "primary".into(),
            route_group_id: String::new(),
            route_group_name: String::new(),
            owner_account_id: Some("acct-1".into()),
            owner_email: None,
            extra: None,
            // OAuth 组 KEY：材料由 proxy 走通道③拉取，本地无密文是**设计如此**。
            // winpc2 上出问题的那把（team-oauth-开发组-…）正是这个形态。
            oauth_group_id: Some("grp-1".into()),
            group_accounts: None,
            routing_config: None,
            group_alias: None,
            group_runtime: None,
        };
        crate::storage::upsert_virtual_key_cache(&entry).unwrap();
        crate::storage::set_provider_binding(
            "default",
            "anthropic",
            "managed_virtual_key",
            "vk-healthy",
        )
        .unwrap();
    }

    use super::*;
    use tempfile::TempDir;

    fn material() -> RouteMaterial {
        RouteMaterial {
            base_url: "http://127.0.0.1:27200/anthropic".to_string(),
            token: "aikey_active_anthropic".to_string(),
        }
    }

    /// Tempdir paths with the normal dir pre-created (= "Desktop installed").
    fn installed_paths(tmp: &TempDir) -> DesktopPaths {
        let paths = paths_from_dirs(tmp.path().join("Claude"), tmp.path().join("Claude-3p"));
        std::fs::create_dir_all(&paths.normal_dir).unwrap();
        paths
    }

    fn read_mode(p: &std::path::Path) -> String {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        v["deploymentMode"].as_str().unwrap().to_string()
    }

    // ── Phase 4 (third-party config guard, 2026-09-05) ──────────────────
    // spec: R-third-party-config-guard-6

    /// A normal config that exists but does not parse is ITS OWN state and
    /// every write path refuses it — before, it read as Official and the
    /// takeover/restore either errored late or wrote around it.
    #[test]
    fn config_invalid_is_its_own_state_and_every_write_refuses() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        std::fs::write(&paths.normal_config, "{ \"deploymentMode\": \"3p\", ").unwrap();
        let before = std::fs::read(&paths.normal_config).unwrap();

        assert_eq!(detect_state(&paths), DesktopState::ConfigInvalid);
        let err = takeover_at(&paths, &material()).expect_err("takeover must refuse");
        assert!(err.contains("is not valid JSON at line "), "{err}");
        assert!(
            err.contains("fix the file by hand"),
            "no backup yet → hand repair: {err}"
        );
        let err = restore_at(&paths).expect_err("restore must refuse");
        assert!(err.contains("is not valid JSON"), "{err}");
        assert_eq!(reconcile_stale_at(&paths, 27200), StaleReconcile::NoAction);
        let sw = reconcile_active_at(&paths, 27200, false);
        assert_eq!(
            sw,
            DesktopSwitch {
                detected: true,
                ..Default::default()
            }
        );

        assert_eq!(
            std::fs::read(&paths.normal_config).unwrap(),
            before,
            "bytes untouched"
        );
        // (TP_COMMITS is process-global and other suites write concurrently;
        // "the door never opened" is asserted by the four files' bytes and
        // the absence of any backup instead.)
        assert!(!paths.profile.exists() && !paths.meta.exists() && !paths.threep_config.exists());
        assert!(tp::list_backups(&paths.normal_config).is_empty());
        let insp = desktop_inspection_at(&paths);
        assert_eq!(
            insp.unparseable_sentence().as_deref(),
            Some(err.as_str()),
            "one sentence everywhere"
        );
    }

    /// Every Desktop write goes through the guard's one door and leaves a
    /// versioned backup of what was there; the explicit restore brings the
    /// pre-aikey normal config back byte for byte.
    #[test]
    fn takeover_and_restore_leave_versioned_backups_through_the_one_door() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        let pre = "{\n  \"theme\": \"x\"\n}";
        std::fs::write(&paths.normal_config, pre).unwrap();

        assert_eq!(
            takeover_at(&paths, &material()).unwrap(),
            TakeoverResult::Installed
        );
        // "all four through the one door" is fenced at the source level
        // (third_party_write_guard_fence: this file has no atomic_write left).
        let normal_backups = tp::list_backups(&paths.normal_config);
        assert_eq!(normal_backups.len(), 1, "{normal_backups:?}");
        assert_eq!(
            std::fs::read_to_string(&normal_backups[0]).unwrap(),
            pre,
            "backup is the pre-aikey file"
        );
        assert!(
            tp::list_backups(&paths.profile).is_empty(),
            "nothing existed to back up"
        );
        assert_eq!(read_mode(&paths.normal_config), "3p");
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.normal_config).unwrap()).unwrap();
        assert_eq!(v["theme"], "x", "other keys preserved");

        assert_eq!(restore_at(&paths).unwrap(), RestoreResult::Restored);
        assert_eq!(read_mode(&paths.normal_config), "1p");
        assert_eq!(
            tp::list_backups(&paths.normal_config).len(),
            2,
            "restore backed up the 3p state too"
        );
        assert_eq!(
            tp::list_backups(&paths.profile).len(),
            1,
            "the deleted profile was backed up first"
        );
        assert!(!paths.profile.exists());

        // Explicit restore of the ORIGINAL normal config (not the newest backup).
        let r = tp::repair(
            &DesktopSurface::at(&paths),
            tp::RepairMode::FromBackup(Some(normal_backups[0].clone())),
            true,
        );
        assert_eq!(
            r.outcome.as_ref().unwrap().action,
            tp::TpAction::Restored,
            "{:?}",
            r.outcome
        );
        assert_eq!(std::fs::read_to_string(&paths.normal_config).unwrap(), pre);
        // and text-stripping is never offered for JSON
        let r = tp::repair(&DesktopSurface::at(&paths), tp::RepairMode::StripOurs, true);
        assert_eq!(
            r.outcome.as_ref().unwrap().reason_code,
            Some(tp::ReasonCode::TpNotApplicable)
        );
    }

    // 1 · fresh takeover: 4 files correct; profile 0600 (unix); meta ours
    #[test]
    fn fresh_takeover_writes_all_four_files() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);

        let r = takeover_at(&paths, &material()).unwrap();
        assert_eq!(r, TakeoverResult::Installed);

        assert_eq!(read_mode(&paths.normal_config), "3p");
        assert_eq!(read_mode(&paths.threep_config), "3p");

        let profile: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.profile).unwrap()).unwrap();
        assert_eq!(profile["inferenceProvider"], "gateway");
        assert_eq!(profile["inferenceGatewayAuthScheme"], "bearer");
        assert_eq!(profile["inferenceGatewayApiKey"], "aikey_active_anthropic");
        assert_eq!(
            profile["inferenceGatewayBaseUrl"],
            "http://127.0.0.1:27200/anthropic"
        );
        assert!(profile["inferenceModels"].as_array().unwrap().len() >= 3);
        assert_eq!(profile["disableDeploymentModeChooser"], true);

        let meta: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.meta).unwrap()).unwrap();
        assert_eq!(meta["appliedId"], PROFILE_ID);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&paths.profile)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "profile must be owner-only");
        }
    }

    // 2 · second takeover with same material: Unchanged, zero writes
    #[test]
    fn second_takeover_is_idempotent_no_rewrite() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        takeover_at(&paths, &material()).unwrap();

        let before = std::fs::metadata(&paths.profile)
            .unwrap()
            .modified()
            .unwrap();
        let bytes_before = std::fs::read(&paths.profile).unwrap();

        let r = takeover_at(&paths, &material()).unwrap();
        assert_eq!(r, TakeoverResult::Unchanged);
        assert_eq!(
            std::fs::metadata(&paths.profile)
                .unwrap()
                .modified()
                .unwrap(),
            before,
            "profile mtime must not change on a no-op takeover"
        );
        assert_eq!(std::fs::read(&paths.profile).unwrap(), bytes_before);
    }

    // 3 · foreign 3p present → silent takeover, foreign profile preserved
    #[test]
    fn foreign_occupation_taken_over_silently_file_preserved() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        std::fs::create_dir_all(&paths.config_library).unwrap();
        let foreign_profile = paths.config_library.join("foreign-tool.json");
        std::fs::write(&foreign_profile, br#"{"inferenceProvider":"gateway"}"#).unwrap();
        std::fs::write(&paths.meta, br#"{"appliedId":"foreign-tool"}"#).unwrap();
        std::fs::write(&paths.normal_config, br#"{"deploymentMode":"3p"}"#).unwrap();
        std::fs::write(&paths.threep_config, br#"{"deploymentMode":"3p"}"#).unwrap();
        assert_eq!(detect_state(&paths), DesktopState::ForeignActive);

        let r = takeover_at(&paths, &material()).unwrap();
        assert_eq!(r, TakeoverResult::Installed);
        assert_eq!(detect_state(&paths), DesktopState::OursActive);
        // D5: their pointer is claimed, their FILE is intact byte-for-byte.
        assert_eq!(
            std::fs::read(&foreign_profile).unwrap(),
            br#"{"inferenceProvider":"gateway"}"#
        );
    }

    // 4 · restore(ours): both 1p, profile gone, meta claim cleared,
    //     foreign file untouched
    #[test]
    fn restore_ours_reverts_and_leaves_foreign_files() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        std::fs::create_dir_all(&paths.config_library).unwrap();
        let foreign_profile = paths.config_library.join("foreign-tool.json");
        std::fs::write(&foreign_profile, b"{}").unwrap();
        takeover_at(&paths, &material()).unwrap();

        let r = restore_at(&paths).unwrap();
        assert_eq!(r, RestoreResult::Restored);
        assert_eq!(read_mode(&paths.normal_config), "1p");
        assert_eq!(read_mode(&paths.threep_config), "1p");
        assert!(!paths.profile.exists());
        let meta: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.meta).unwrap()).unwrap();
        assert!(meta.get("appliedId").is_none());
        assert!(foreign_profile.exists());
    }

    // 5 · restore(foreign): NotOursSkipped, nothing moves
    #[test]
    fn restore_foreign_is_skipped_untouched() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        std::fs::create_dir_all(&paths.config_library).unwrap();
        std::fs::write(&paths.meta, br#"{"appliedId":"foreign-tool"}"#).unwrap();
        std::fs::write(&paths.normal_config, br#"{"deploymentMode":"3p"}"#).unwrap();

        let r = restore_at(&paths).unwrap();
        assert_eq!(r, RestoreResult::NotOursSkipped);
        assert_eq!(read_mode(&paths.normal_config), "3p");
        assert_eq!(
            std::fs::read(&paths.meta).unwrap(),
            br#"{"appliedId":"foreign-tool"}"#
        );
    }

    // 6 · rollback: a failing write mid-sequence restores every file to
    //     its pre-call bytes
    #[test]
    fn failed_write_rolls_back_all_files() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        let original_normal = br#"{"deploymentMode":"1p","keep":"me"}"#;
        std::fs::write(&paths.normal_config, original_normal).unwrap();
        // Make the LAST write (threep_config) fail: a DIRECTORY at the
        // config path defeats atomic_write's rename. It's not a file, so
        // the pre-write parse guard skips it, and reaching it proves the
        // earlier writes must be rolled back.
        std::fs::create_dir_all(&paths.threep_config).unwrap();

        let err = takeover_at(&paths, &material());
        assert!(err.is_err(), "expected takeover failure");
        assert!(!paths.profile.exists(), "profile write must be rolled back");
        assert!(!paths.meta.exists(), "meta write must be rolled back");
        assert_eq!(
            std::fs::read(&paths.normal_config).unwrap(),
            original_normal,
            "normal config must be back to its snapshot"
        );
    }

    // 7 · config flip preserves unrelated keys
    #[test]
    fn deployment_flip_preserves_other_keys() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        std::fs::write(
            &paths.normal_config,
            br#"{"deploymentMode":"1p","preferences":{"theme":"dark"},"mcpServers":{"x":1}}"#,
        )
        .unwrap();

        takeover_at(&paths, &material()).unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.normal_config).unwrap()).unwrap();
        assert_eq!(v["deploymentMode"], "3p");
        assert_eq!(v["preferences"]["theme"], "dark");
        assert_eq!(v["mcpServers"]["x"], 1);
    }

    // 8 · malformed config: honest failure, file NOT overwritten
    #[test]
    fn malformed_config_aborts_without_overwrite() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        std::fs::write(&paths.normal_config, b"{not valid json").unwrap();

        let err = takeover_at(&paths, &material());
        assert!(err.is_err());
        assert_eq!(
            std::fs::read(&paths.normal_config).unwrap(),
            b"{not valid json",
            "malformed file must be left exactly as found"
        );
        assert!(!paths.profile.exists(), "no partial takeover on abort");
    }

    // 9 · model validator: fail-all guard filters bad names
    #[test]
    fn model_validator_filters_unsafe_names() {
        assert!(is_claude_safe_model_id("claude-sonnet-5"));
        assert!(is_claude_safe_model_id("claude-opus-4-8"));
        assert!(is_claude_safe_model_id("claude-haiku-4-5-20251001"));
        assert!(is_claude_safe_model_id("claude-fable-5"));
        // rejected: wrong family, empty suffix, 1m marker
        assert!(!is_claude_safe_model_id("claude-x-1"));
        assert!(!is_claude_safe_model_id("claude-sonnet-"));
        assert!(!is_claude_safe_model_id("claude-opus-4-8[1m]"));
        assert!(!is_claude_safe_model_id("gpt-4o"));
        assert!(!is_claude_safe_model_id(""));
    }

    // 10 · registry: anthropic desktop menu present, valid, both shapes
    #[test]
    fn registry_desktop_menu_nonempty_and_all_safe() {
        let models = crate::provider_registry::client_models("anthropic", REGISTRY_CLIENT);
        assert!(!models.is_empty(), "anthropic claude-desktop menu missing");
        for m in models {
            assert!(
                is_claude_safe_model_id(m.name),
                "registry menu entry '{}' fails the claude-safe validator",
                m.name
            );
        }
        // Both YAML entry shapes present: at least one structured 1m entry
        // and at least one plain entry.
        assert!(models.iter().any(|m| m.supports_1m));
        assert!(models.iter().any(|m| !m.supports_1m));
        // Unknown client key resolves to empty, not an error.
        assert!(crate::provider_registry::client_models("anthropic", "no-such-client").is_empty());
        // The structured entry renders as an object in the profile.
        let profile = build_gateway_profile(&material());
        let arr = profile["inferenceModels"].as_array().unwrap();
        assert!(arr.iter().any(|v| v.is_object() && v["supports1m"] == true));
        assert!(arr.iter().any(|v| v.is_string()));
    }

    // 11 · path shapes: macOS + Windows (LOCALAPPDATA-style injection)
    #[test]
    fn path_resolution_shapes_macos_and_windows() {
        let mac = macos_paths_from_home(Path::new("/Users/alice"));
        assert_eq!(
            mac.normal_config,
            PathBuf::from(
                "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json"
            )
        );
        assert_eq!(
            mac.profile,
            PathBuf::from(format!(
                "/Users/alice/Library/Application Support/Claude-3p/configLibrary/{}.json",
                PROFILE_ID
            ))
        );

        // Windows shape via injected LocalAppData root (what the
        // LOCALAPPDATA env resolves to in production).
        let win = windows_paths_from_local_app_data(Path::new(r"C:\Users\alice\AppData\Local"));
        assert!(win
            .normal_config
            .to_string_lossy()
            .ends_with("claude_desktop_config.json"));
        assert!(win.normal_dir.to_string_lossy().contains("Claude"));
        assert!(win.threep_dir.to_string_lossy().contains("Claude-3p"));
        assert!(win.meta.to_string_lossy().contains("configLibrary"));
    }

    // Bug 1 (Windows spike 2026-07-15) regression fence: the "installed"
    // signal must be the app dir (`AnthropicClaude`), NOT the config dir
    // (`Claude`), which only appears after a takeover. Keying detection off
    // the config dir falsely reports a fresh Windows Claude as NotInstalled
    // and refuses takeover.
    #[test]
    fn windows_install_marker_is_app_dir_not_config_dir() {
        let win = windows_paths_from_local_app_data(Path::new(r"C:\Users\alice\AppData\Local"));
        assert!(
            win.install_marker
                .to_string_lossy()
                .ends_with("AnthropicClaude"),
            "install marker should be the app dir, got {}",
            win.install_marker.display()
        );
        // The config dir is a DIFFERENT path (created by takeover, not the marker).
        assert_ne!(win.install_marker, win.normal_dir);
        assert!(win.normal_dir.to_string_lossy().ends_with("Claude"));
    }

    // Fresh Windows Claude: app dir present, config dir absent (never taken
    // over) ⇒ Official (installed), NOT NotInstalled.
    #[test]
    fn windows_fresh_install_detects_official_not_notinstalled() {
        let tmp = TempDir::new().unwrap();
        let mut paths = paths_from_dirs(tmp.path().join("Claude"), tmp.path().join("Claude-3p"));
        paths.install_marker = tmp.path().join("AnthropicClaude");
        // Create ONLY the app dir (as a clean Windows install would have).
        std::fs::create_dir_all(&paths.install_marker).unwrap();
        assert!(
            !paths.normal_dir.exists(),
            "config dir must be absent (pre-takeover)"
        );
        assert_eq!(
            detect_state(&paths),
            DesktopState::Official,
            "app-dir-present + config-dir-absent must be Official, not NotInstalled"
        );
        // And takeover must succeed (creating the config dir itself).
        assert!(takeover_at(&paths, &material()).is_ok());
        assert!(
            paths.normal_dir.exists(),
            "takeover must create the config dir"
        );
        assert_eq!(detect_state(&paths), DesktopState::OursActive);
    }

    // No app dir at all ⇒ NotInstalled (marker absent).
    #[test]
    fn windows_no_app_dir_is_not_installed() {
        let tmp = TempDir::new().unwrap();
        let mut paths = paths_from_dirs(tmp.path().join("Claude"), tmp.path().join("Claude-3p"));
        paths.install_marker = tmp.path().join("AnthropicClaude");
        paths.msix_detection = MsixDetection::NotRegistered;
        assert_eq!(detect_state(&paths), DesktopState::NotInstalled);
    }

    // Microsoft Store/MSIX installs have no `%LOCALAPPDATA%\AnthropicClaude`
    // directory. Current-user package registration is sufficient evidence,
    // and takeover still writes only the documented LocalAppData config dirs.
    #[test]
    fn windows_msix_registration_detects_and_supports_takeover() {
        let tmp = TempDir::new().unwrap();
        let mut paths = windows_paths_from_local_app_data(tmp.path());
        paths.msix_detection = MsixDetection::Registered;

        assert!(!paths.install_marker.exists());
        assert_eq!(detect_installation(&paths), DesktopInstallation::Msix);
        assert_eq!(detect_state(&paths), DesktopState::Official);
        assert_eq!(
            takeover_at(&paths, &material()).unwrap(),
            TakeoverResult::Installed
        );
        assert_eq!(detect_state(&paths), DesktopState::OursActive);
        assert!(paths.profile.exists());
        assert!(paths.profile.starts_with(tmp.path().join("Claude-3p")));
        assert!(paths
            .profile
            .to_string_lossy()
            .to_ascii_lowercase()
            .find("windowsapps")
            .is_none());
    }

    #[test]
    fn windows_legacy_marker_wins_over_msix_detection_failure() {
        let tmp = TempDir::new().unwrap();
        let mut paths = windows_paths_from_local_app_data(tmp.path());
        paths.msix_detection = MsixDetection::Failed("package API unavailable".to_string());
        std::fs::create_dir_all(&paths.install_marker).unwrap();

        assert_eq!(detect_installation(&paths), DesktopInstallation::Legacy);
        assert_eq!(detect_state(&paths), DesktopState::Official);
        assert!(takeover_at(&paths, &material()).is_ok());
    }

    #[test]
    fn windows_msix_detection_failure_is_visible_and_side_effect_free() {
        let tmp = TempDir::new().unwrap();
        let mut paths = windows_paths_from_local_app_data(tmp.path());
        paths.msix_detection = MsixDetection::Failed("package API unavailable".to_string());

        assert_eq!(
            detect_installation(&paths),
            DesktopInstallation::DetectionFailed("package API unavailable".to_string())
        );
        assert_eq!(detect_state(&paths), DesktopState::DetectionFailed);
        assert!(takeover_at(&paths, &material()).is_err());
        assert_eq!(
            reconcile_active_at(&paths, 27200, false),
            DesktopSwitch::default()
        );
        assert!(!paths.normal_dir.exists());
        assert!(!paths.threep_dir.exists());
    }

    // macOS regression guard: marker == config dir (no behavior change).
    #[test]
    fn macos_install_marker_equals_config_dir() {
        let mac = macos_paths_from_home(Path::new("/Users/alice"));
        assert_eq!(mac.install_marker, mac.normal_dir);
    }

    // extra · uninstalled → detect NotInstalled; restore is a no-op
    #[test]
    fn not_installed_detected_and_restore_noop() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_from_dirs(tmp.path().join("Claude"), tmp.path().join("Claude-3p"));
        assert_eq!(detect_state(&paths), DesktopState::NotInstalled);
        assert_eq!(restore_at(&paths).unwrap(), RestoreResult::NothingToDo);
        assert!(takeover_at(&paths, &material()).is_err());
    }
}

// ─── P2 integration tests (plan §4.7 — consent matrix / funnel semantics) ─
//
// Env isolation: every test grabs ENV_MUTATION_LOCK and points HOME +
// AIKEY_CONFIG + AK_VAULT_PATH into a tempdir, so pref reads/writes and the
// binding DB never touch the real machine. NOTE deliberately absent here:
// `handle_desktop_status`'s probes (claude.ai account plane) — network
// probes of Claude surfaces are FORBIDDEN on dev hosts (memory:
// no-claude-tests-from-host); the status shape is covered by VM E2E DS-15
// instead.
#[cfg(test)]
mod p2_tests {
    use super::*;
    use crate::test_env_lock::ENV_MUTATION_LOCK;
    use tempfile::TempDir;

    struct EnvSandbox {
        _tmp: TempDir,
        // Lock ORDER matters and is established here (the only double-lock
        // site in the crate): ENV_MUTATION_LOCK first, TEST_VAULT_LOCK
        // second. We must hold BOTH because this sandbox mutates env vars
        // from two different lock domains — HOME/AIKEY_CONFIG are guarded
        // by ENV_MUTATION_LOCK, while AK_VAULT_PATH is guarded by
        // storage::TEST_VAULT_LOCK (core_tests / storage::tests convention).
        // Holding only one raced the other domain's tests: the 2026-07-13
        // full-suite run had core_tests read OUR AK_VAULT_PATH mid-test,
        // failing this module's asserts and poisoning the env lock for 22
        // downstream local_server_probe tests.
        _env_guard: std::sync::MutexGuard<'static, ()>,
        _vault_guard: std::sync::MutexGuard<'static, ()>,
        prev_home: Option<String>,
        prev_cfg: Option<String>,
        prev_vault: Option<String>,
    }

    impl EnvSandbox {
        fn new(tmp: TempDir) -> Self {
            let env_guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let vault_guard = crate::storage::TEST_VAULT_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let prev_home = std::env::var("HOME").ok();
            let prev_cfg = std::env::var("AIKEY_CONFIG").ok();
            let prev_vault = std::env::var("AK_VAULT_PATH").ok();
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("AIKEY_CONFIG", tmp.path().join("config.json"));
            std::env::set_var("AK_VAULT_PATH", tmp.path().join("vault.db"));
            EnvSandbox {
                _tmp: tmp,
                _env_guard: env_guard,
                _vault_guard: vault_guard,
                prev_home,
                prev_cfg,
                prev_vault,
            }
        }
    }

    impl Drop for EnvSandbox {
        fn drop(&mut self) {
            fn put(k: &str, v: &Option<String>) {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
            put("HOME", &self.prev_home);
            put("AIKEY_CONFIG", &self.prev_cfg);
            put("AK_VAULT_PATH", &self.prev_vault);
        }
    }

    fn sandbox_with_desktop() -> (EnvSandbox, DesktopPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = paths_from_dirs(tmp.path().join("Claude"), tmp.path().join("Claude-3p"));
        std::fs::create_dir_all(&paths.normal_dir).unwrap();
        (EnvSandbox::new(tmp), paths)
    }

    fn seed_anthropic_binding() {
        crate::storage::set_provider_binding("default", "anthropic", "personal", "test-key")
            .expect("seed binding");
    }

    // §4.7-1 · no pref · Desktop present · non-TTY → needs_consent, ZERO writes
    #[test]
    fn headless_without_pref_reports_needs_consent_and_writes_nothing() {
        let (_sb, paths) = sandbox_with_desktop();
        let d = reconcile_active_at(&paths, 27200, false);
        assert_eq!(
            d,
            DesktopSwitch {
                detected: true,
                configured: false,
                restart_required: false,
                needs_consent: true
            }
        );
        assert!(!paths.profile.exists(), "consent-less pass must not write");
        assert!(!paths.threep_config.exists());
    }

    // §4.7-2 · granted+remember (pref=always, as handle_use step 1 sets it)
    //          → takeover happens, files land, restart flagged
    #[test]
    fn pref_always_takes_over_and_flags_restart() {
        let (_sb, paths) = sandbox_with_desktop();
        seed_anthropic_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();

        let d = reconcile_active_at(&paths, 27200, false);
        assert!(d.configured && d.restart_required && !d.needs_consent);
        assert!(paths.profile.exists());
        let profile: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.profile).unwrap()).unwrap();
        assert_eq!(profile["inferenceGatewayApiKey"], "aikey_active_anthropic");
        assert_eq!(
            profile["inferenceGatewayBaseUrl"],
            "http://127.0.0.1:27200/anthropic"
        );
    }

    // §4.7-3 · switching to ANOTHER claude credential = no-op for Desktop
    //          (D1 coupled model: sentinel is credential-independent)
    #[test]
    fn credential_switch_is_desktop_noop() {
        let (_sb, paths) = sandbox_with_desktop();
        seed_anthropic_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        assert!(reconcile_active_at(&paths, 27200, false).restart_required);
        let bytes = std::fs::read(&paths.profile).unwrap();

        // "Switch credential": rebind anthropic to a different alias.
        crate::storage::set_provider_binding("default", "anthropic", "personal", "other-key")
            .unwrap();
        let d = reconcile_active_at(&paths, 27200, false);
        assert!(d.configured, "still configured");
        assert!(!d.restart_required, "no rewrite → no restart");
        assert_eq!(std::fs::read(&paths.profile).unwrap(), bytes, "byte-stable");
    }

    // §4.7-4 · denied+remember (pref=never) → silent skip forever
    #[test]
    fn pref_never_skips_silently() {
        let (_sb, paths) = sandbox_with_desktop();
        crate::global_config::set_claude_desktop_consent("never").unwrap();
        let d = reconcile_active_at(&paths, 27200, false);
        assert_eq!(
            d,
            DesktopSwitch {
                detected: true,
                configured: false,
                restart_required: false,
                needs_consent: false
            }
        );
        assert!(!paths.profile.exists());
    }

    // §4.7-5 · restore (the unuse-anthropic funnel branch) → 1p + profile
    //          gone + `always` pref CLEARED (D6 supplement)
    #[test]
    fn restore_reverts_and_clears_always_pref() {
        let (_sb, paths) = sandbox_with_desktop();
        seed_anthropic_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        assert!(reconcile_active_at(&paths, 27200, false).configured);

        restore_quiet_at(&paths);
        assert!(!paths.profile.exists());
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.normal_config).unwrap()).unwrap();
        assert_eq!(v["deploymentMode"], "1p");
        assert_eq!(
            crate::global_config::get_claude_desktop_consent().unwrap(),
            None,
            "aikey-performed restore must clear the always grant"
        );
    }

    // §4.7-6 · restore path when pref=never: never SURVIVES a restore
    //          (its only exits are desktop uninstall / explicit install)
    #[test]
    fn restore_leaves_never_pref_alone() {
        let (_sb, paths) = sandbox_with_desktop();
        crate::global_config::set_claude_desktop_consent("never").unwrap();
        restore_quiet_at(&paths); // NothingToDo — never never took over
        assert_eq!(
            crate::global_config::get_claude_desktop_consent().unwrap(),
            Some("never".to_string())
        );
    }

    // §4.7-7b · external flip-back then use with pref=always → silent
    //           re-takeover, pref RETAINED (external flip ≠ aikey restore)
    #[test]
    fn external_flipback_retakes_silently_and_keeps_pref() {
        let (_sb, paths) = sandbox_with_desktop();
        seed_anthropic_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        assert!(reconcile_active_at(&paths, 27200, false).configured);

        // Simulate an external reset (Desktop update / other tool): mode
        // back to 1p, our profile still on disk.
        let mut v: Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.normal_config).unwrap()).unwrap();
        v["deploymentMode"] = Value::String("1p".to_string());
        std::fs::write(&paths.normal_config, serde_json::to_string(&v).unwrap()).unwrap();

        let d = reconcile_active_at(&paths, 27200, false);
        assert!(d.configured && d.restart_required, "silent re-takeover");
        assert!(!d.needs_consent);
        assert_eq!(
            crate::global_config::get_claude_desktop_consent().unwrap(),
            Some("always".to_string()),
            "external flip-back must NOT clear the pref"
        );
    }

    // §4.7-9 · write-failure injection → soft-fail shape (detected but not
    //          configured); the caller's `use` semantics stay intact
    #[test]
    fn write_failure_soft_fails_without_panicking() {
        let (_sb, paths) = sandbox_with_desktop();
        seed_anthropic_binding();
        crate::global_config::set_claude_desktop_consent("always").unwrap();
        // Defeat the threep config write with a directory in its place.
        std::fs::create_dir_all(&paths.threep_config).unwrap();

        let d = reconcile_active_at(&paths, 27200, false);
        assert_eq!(
            d,
            DesktopSwitch {
                detected: true,
                configured: false,
                restart_required: false,
                needs_consent: false
            }
        );
    }

    // §4.7-extra · one-shot grant path used by handle_use step 2:
    //          perform_takeover directly (consent already given)
    #[test]
    fn one_shot_grant_performs_takeover_without_pref() {
        let (_sb, paths) = sandbox_with_desktop();
        seed_anthropic_binding();
        let d = perform_takeover(&paths, 27200);
        assert!(d.configured && d.restart_required);
        assert_eq!(
            crate::global_config::get_claude_desktop_consent().unwrap(),
            None,
            "one-shot grant must leave no standing pref"
        );
    }
}
