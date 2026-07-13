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

// ─── Paths ──────────────────────────────────────────────────────────────

/// All filesystem locations the takeover touches. Constructed via
/// `desktop_paths()` in production and `paths_from_dirs()` in tests
/// (tempdir injection — tests never touch the real HOME).
#[derive(Debug, Clone)]
pub(crate) struct DesktopPaths {
    /// `.../Claude` — presence = "Desktop is installed" detection signal.
    pub normal_dir: PathBuf,
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
/// MVP uses exact dir names. cc-switch additionally falls back to a
/// `Claude*` prefix scan on Windows (`pick_windows_claude_dir`), implying
/// name variants exist in the wild; whether we need that scan is gated on
/// the Windows spike leg's real-dir-name observation (risk 8). If the spike
/// sees a variant name, upgrade this to the scan — exact-name misses would
/// silently report detected=false (feature silently off).
pub(crate) fn windows_paths_from_local_app_data(local_app_data: &Path) -> DesktopPaths {
    paths_from_dirs(
        local_app_data.join("Claude"),
        local_app_data.join("Claude-3p"),
    )
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
        Some(windows_paths_from_local_app_data(&lad))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        None
    }
}

// ─── Route material ─────────────────────────────────────────────────────

/// What the gateway profile points at. Local editions: local proxy +
/// per-provider sentinel (credential-independent — D1's zero-rewrite-on-
/// credential-switch property). Cluster: central node + real vk_token
/// (same exposure level as active.env on cluster, risk 3).
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
    ["claude-sonnet-", "claude-opus-", "claude-haiku-", "claude-fable-"]
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
    /// `Claude/` dir absent — Desktop not installed, skip everything.
    NotInstalled,
    /// Installed, `deploymentMode` != "3p" (or unset) — official mode.
    Official,
    /// `3p` and the applied profile is ours.
    OursActive,
    /// `3p` but applied by someone else (e.g. cc-switch). D5: silent
    /// takeover is allowed; their profile FILE is never touched.
    ForeignActive,
}

fn read_json_object(path: &Path) -> Result<Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
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
    if !paths.normal_dir.exists() {
        return DesktopState::NotInstalled;
    }
    // The NORMAL config is the authoritative mode switch (the app reads it
    // in both modes; the 3p copy exists for the 3p bundle's own view).
    let mode_3p = deployment_mode(&paths.normal_config).as_deref() == Some("3p");
    if !mode_3p {
        return DesktopState::Official;
    }
    if applied_id(&paths.meta).as_deref() == Some(PROFILE_ID) {
        DesktopState::OursActive
    } else {
        DesktopState::ForeignActive
    }
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
                let _ = crate::profile_activation::atomic_write(&self.path, bytes);
            }
            None => {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
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
    let pretty = serde_json::to_string_pretty(&obj)
        .map_err(|e| format!("serialize {}: {}", config_path.display(), e))?;
    crate::profile_activation::atomic_write(config_path, pretty.as_bytes())
        .map_err(|e| format!("write {}: {}", config_path.display(), e))
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
    let pretty = serde_json::to_string_pretty(&obj)
        .map_err(|e| format!("serialize {}: {}", meta_path.display(), e))?;
    crate::profile_activation::atomic_write(meta_path, pretty.as_bytes())
        .map_err(|e| format!("write {}: {}", meta_path.display(), e))
}

/// Take over Claude Desktop at `paths` (test-injectable). All-or-nothing:
/// on any failure every touched file is rolled back to its pre-call bytes
/// and an Err is returned (callers WARN + continue — desktop writes must
/// never fail the `use` that triggered them).
pub(crate) fn takeover_at(
    paths: &DesktopPaths,
    material: &RouteMaterial,
) -> Result<TakeoverResult, String> {
    if !paths.normal_dir.exists() {
        return Err("Claude Desktop not detected (normal dir missing)".to_string());
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

    std::fs::create_dir_all(&paths.config_library)
        .map_err(|e| format!("create {}: {}", paths.config_library.display(), e))?;

    let snapshots = [
        Snapshot::take(&paths.profile),
        Snapshot::take(&paths.meta),
        Snapshot::take(&paths.normal_config),
        Snapshot::take(&paths.threep_config),
    ];

    let result = (|| -> Result<(), String> {
        crate::profile_activation::atomic_write(&paths.profile, profile_pretty.as_bytes())
            .map_err(|e| format!("write {}: {}", paths.profile.display(), e))?;
        // Cluster profiles carry a real vk_token (risk 3) — owner-only.
        // Windows: inherits the user-dir ACL (no 0600 there, D10⑤).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &paths.profile,
                std::fs::Permissions::from_mode(0o600),
            );
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
        DesktopState::ForeignActive => Ok(RestoreResult::NotOursSkipped),
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
        std::fs::remove_file(&paths.profile)
            .map_err(|e| format!("remove {}: {}", paths.profile.display(), e))?;
        removed = true;
    }
    if applied_id(&paths.meta).as_deref() == Some(PROFILE_ID) {
        let mut obj = read_json_object(&paths.meta)?;
        obj.as_object_mut().map(|m| m.remove("appliedId"));
        let pretty = serde_json::to_string_pretty(&obj)
            .map_err(|e| format!("serialize {}: {}", paths.meta.display(), e))?;
        crate::profile_activation::atomic_write(&paths.meta, pretty.as_bytes())
            .map_err(|e| format!("write {}: {}", paths.meta.display(), e))?;
        removed = true;
    }
    Ok(removed)
}

// ─── Tests (P1 plan §3.3 — all inject tempdir paths, never real HOME) ───

#[cfg(test)]
mod tests {
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
            let mode = std::fs::metadata(&paths.profile).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "profile must be owner-only");
        }
    }

    // 2 · second takeover with same material: Unchanged, zero writes
    #[test]
    fn second_takeover_is_idempotent_no_rewrite() {
        let tmp = TempDir::new().unwrap();
        let paths = installed_paths(&tmp);
        takeover_at(&paths, &material()).unwrap();

        let before = std::fs::metadata(&paths.profile).unwrap().modified().unwrap();
        let bytes_before = std::fs::read(&paths.profile).unwrap();

        let r = takeover_at(&paths, &material()).unwrap();
        assert_eq!(r, TakeoverResult::Unchanged);
        assert_eq!(
            std::fs::metadata(&paths.profile).unwrap().modified().unwrap(),
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
        assert!(
            crate::provider_registry::client_models("anthropic", "no-such-client").is_empty()
        );
        // The structured entry renders as an object in the profile.
        let profile = build_gateway_profile(&material());
        let arr = profile["inferenceModels"].as_array().unwrap();
        assert!(arr.iter().any(|v| v.is_object()
            && v["supports1m"] == true));
        assert!(arr.iter().any(|v| v.is_string()));
    }

    // 11 · path shapes: macOS + Windows (LOCALAPPDATA-style injection)
    #[test]
    fn path_resolution_shapes_macos_and_windows() {
        let mac = macos_paths_from_home(Path::new("/Users/alice"));
        assert_eq!(
            mac.normal_config,
            PathBuf::from("/Users/alice/Library/Application Support/Claude/claude_desktop_config.json")
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
