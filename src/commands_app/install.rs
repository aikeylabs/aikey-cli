//! `aikey app install <slug>` — first-party / deep-partner app launcher.
//!
//! ## Design (2026-05-22)
//!
//! This command is a **launcher**, not an orchestrator. It does NOT
//! register the app in the vault, does NOT know plugin-specific config,
//! and does NOT manage plugin lifecycle state. Those responsibilities
//! belong to the plugin's own installer script (referenced from
//! `manifest.service_installer.url`).
//!
//! The split is enforced for a reason:
//!
//! - **Plugin autonomy**: each first-party app has its own manifest
//!   fields (upstreams / follow_user_active / vendor / requested
//!   permissions / etc). The plugin knows them; aikey-cli should not
//!   need to learn them. If aikey-cli read these fields and called
//!   `register`, every new plugin would either need a CLI release or a
//!   schema-coupled manifest parser. By delegating register to the
//!   plugin's installer (which calls `aikey app register --slug ...`
//!   itself), the CLI stays stable across plugins.
//!
//! - **local-install.sh is a launcher too**: it ONLY decides "install
//!   or not", then calls `aikey app install <slug>`. It does not know
//!   plugin internals. Same split, one layer up.
//!
//! - **Idempotent register fallback in the plugin's installer**:
//!   the plugin's `install_service.sh` checks `aikey app list` and
//!   only calls `register` when missing. So standalone curl-pipe
//!   installs (without going through `aikey app install`) ALSO get
//!   vault registration — no path produces a half-installed state.
//!
//! ## Security model
//!
//! The trust anchor is the CLI binary itself. `TRUSTED_APPS` is a
//! compile-time constant containing `(slug, manifest_url, manifest_sha256)`
//! triples. At runtime we:
//!
//! 1. Refuse any slug not in `TRUSTED_APPS` (no opt-in for arbitrary
//!    URLs — that path goes through `aikey app register`, which requires
//!    the caller to already have a manifest in hand).
//! 2. Fetch the manifest over HTTPS.
//! 3. Verify SHA-256 against the compile-time hash. Mismatch → abort
//!    with `I_MANIFEST_TAMPERED`.
//! 4. Persist the verified manifest to `~/.aikey/apps-cache/<slug>/`.
//!    Subsequent runs reuse the cached copy (offline-safe for reinstalls).
//! 5. Run `manifest.service_installer.url` (currently shell-only) under
//!    the user's shell. Plugin owns the rest.
//!
//! No cosign / minisign for MVP — the embedded SHA-256 is already a
//! cryptographic binding to the manifest content. cosign can be added
//! in stage 2 if we need rotation-without-CLI-release.
//!
//! Spec: `roadmap20260320/技术实现/阶段4-增值版/第三方Agent自助接入与应用级Key方案.md`
//! §11.B "aikey app install 的下载与校验机制".

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Built-in trusted apps allow-list.
// ---------------------------------------------------------------------------

/// A single trusted app entry. Compile-time constant so the trust anchor
/// is the CLI binary itself — see file header §Security model.
///
/// `manifest_sha256` is the hex-encoded SHA-256 of the manifest JSON
/// bytes (UTF-8, no canonicalisation — we hash the wire bytes verbatim
/// because that's the only thing we can verify post-download).
struct TrustedApp {
    slug: &'static str,
    manifest_url: &'static str,
    manifest_sha256: &'static str,
}

/// Compile-time allow-list. Adding an entry here is the only way to
/// expand the surface of `aikey app install`. Third-party apps do NOT
/// go through this path; they call `aikey app register` directly from
/// their own installer.
///
/// **degrade-detector entry**: the manifest lives as a release asset on
/// the same v1.0.0-rc.5 release that ships install_service.sh and the
/// trust-local binaries (decision 2026-05-23 — piggyback on the main
/// release tag instead of a separate `manifests-vX.Y.Z` tag, since the
/// manifest version tracks the CLI release 1:1 in this RC).
///
/// Published 2026-05-23 (v1) / 2026-05-24 (v2): served-asset sha256
/// verified equal to the canonical committed file at
/// aikeylabs/launch/manifests/degrade-detector.manifest.json.
///
/// v2 manifest adds `service_installers.windows` for Windows host support
/// (BR-rc.5-56 follow-up). When the v2 manifest is republished, this pin
/// must change in lockstep — see workflow/CI/bugfix/<TODO>.md if this
/// regression repeats.
// BR-rc.5-93 (hotfix): URL + SHA updated for v1.0.0-rc.5.1 release. The
// underlying architectural issue — hardcoded version in TRUSTED_APPS forces
// rebuild-on-every-patch-release — is tracked for rc.6 (build.rs substitution
// of env!("AIKEY_RELEASE_TAG") + auto-computed SHA from manifest source).
// For now, manually bump both fields whenever launch/manifests/*.json or
// the release tag changes. The pair below must be byte-coherent with
// what gets uploaded to https://github.com/aikeylabs/launch/releases/<tag>/.
const TRUSTED_APPS: &[TrustedApp] = &[
    TrustedApp {
        slug: "degrade-detector",
        manifest_url:
            "https://github.com/aikeylabs/launch/releases/download/v1.0.0-rc.5.1/degrade-detector.manifest.json",
        manifest_sha256: "ef7e307ae84c2ab6eb128fba425ccc2814cb184840ce6fbf42590f670275d7fa",
    },
];

// ---------------------------------------------------------------------------
// Manifest schema.
// ---------------------------------------------------------------------------
//
// Schema versions:
//
//   v1 (legacy):  `service_installer: ServiceInstaller` (singular)
//                 - Single URL, implicitly assumed to be a shell script
//                   runnable via `sh`. Worked for macOS / Linux only;
//                   Windows users got 404 / bash-not-found.
//
//   v2 (current): `service_installers: ServiceInstallers` (plural)
//                 - Per-platform entries (`unix`, `windows`) keyed off the
//                   client's current OS at runtime. Same URL/kind shape
//                   per entry; resolver picks the right one.
//
// `Manifest` deserializes both — v1's singular field is mirrored into
// `service_installers.unix` at parse time so downstream code only has to
// handle the v2 shape. See `Manifest::resolve_for_current_os()`.

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Manifest {
    pub schema_version: String,
    pub slug: String,
    pub version: String,
    /// v2 plural — present when schema_version >= "2".
    #[serde(default)]
    pub service_installers: Option<ServiceInstallers>,
    /// v1 singular — present when schema_version == "1". Read for
    /// backward-compat; new manifests should populate v2 instead.
    #[serde(default)]
    pub service_installer: Option<ServiceInstaller>,
    #[serde(default)]
    pub doc_url: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct ServiceInstallers {
    /// macOS / Linux installer (curl-pipe-shell). Required — every
    /// platform-mappable plugin must support at least Unix.
    pub unix: ServiceInstaller,
    /// Windows installer (powershell-iwr-iex). Optional — plugins that
    /// don't support Windows yet can omit this and `aikey app install`
    /// will surface a clean `I_PLATFORM_UNSUPPORTED` error on Win hosts
    /// instead of trying to bash-exec a .ps1.
    #[serde(default)]
    pub windows: Option<ServiceInstaller>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct ServiceInstaller {
    /// Supported kinds:
    ///   - "curl-pipe-shell"     (Unix): runs URL via `sh <tmp_file>`
    ///   - "powershell-iwr-iex"  (Windows): runs URL via
    ///     `powershell -ExecutionPolicy Bypass -File <tmp_file>`
    /// Anything else aborts with `I_UNSUPPORTED_INSTALLER_KIND` — we
    /// want explicit opt-in for new installer protocols (binary
    /// download, package manager, etc).
    pub kind: String,
    /// HTTPS URL pointing at the installer script. Pinned to a git tag
    /// (not `main`) per §11.B so mid-flight branch updates can't introduce
    /// surprises after the manifest is published.
    pub url: String,
}

impl Manifest {
    /// Pick the right ServiceInstaller for the host OS.
    ///
    /// Resolution priority:
    ///   1. v2 `service_installers.{unix|windows}` — preferred
    ///   2. v1 `service_installer` fallback — assumed to be Unix
    ///
    /// Windows hosts with a v1-only manifest get
    /// `I_PLATFORM_UNSUPPORTED` rather than trying to bash-exec a .sh
    /// (which used to silently 404 / fail at runtime).
    pub fn resolve_for_current_os(&self) -> Result<&ServiceInstaller, String> {
        let is_windows = cfg!(target_os = "windows");
        if let Some(installers) = &self.service_installers {
            if is_windows {
                installers.windows.as_ref().ok_or_else(|| {
                    format!(
                        "I_PLATFORM_UNSUPPORTED: plugin '{}' (manifest v{}) declares no Windows \
                         service_installer. Plugin owner must add 'service_installers.windows' \
                         to the manifest, or run the Unix-side installer manually under WSL.",
                        self.slug, self.schema_version
                    )
                })
            } else {
                Ok(&installers.unix)
            }
        } else if let Some(legacy) = &self.service_installer {
            if is_windows {
                Err(format!(
                    "I_PLATFORM_UNSUPPORTED: plugin '{}' uses legacy schema v1 (Unix-only). \
                     Plugin owner must upgrade to schema v2 with a 'service_installers.windows' \
                     entry. Workaround: install on macOS / Linux, or run install_service.ps1 \
                     manually from the plugin's release assets.",
                    self.slug
                ))
            } else {
                Ok(legacy)
            }
        } else {
            Err(format!(
                "manifest for '{}' has neither 'service_installers' (v2) nor 'service_installer' \
                 (v1). Manifest is malformed; plugin owner must fix.",
                self.slug
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/// Implements `aikey app install <slug>`.
///
/// Flow (see file header for full design):
///   1. Validate slug ∈ TRUSTED_APPS.
///   2. Fetch + verify manifest (or use dev fallback when sha placeholder).
///   3. Cache verified manifest under `~/.aikey/apps-cache/<slug>/`.
///   4. curl-pipe-shell the manifest's `service_installer.url`.
///   5. Bubble up the installer's exit code unchanged — plugin's installer
///      is responsible for its own error semantics.
pub fn handle_install(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let trusted = TRUSTED_APPS
        .iter()
        .find(|t| t.slug == slug)
        .ok_or_else(|| {
            format!(
                "slug '{}' is not in the built-in trusted-apps list. Currently allowed: {}.\n\
                 Third-party Agents should call `aikey app register` directly from their own installer.",
                slug,
                TRUSTED_APPS.iter().map(|t| t.slug).collect::<Vec<_>>().join(", "),
            )
        })?;

    if !json_mode {
        println!("→ Installing {} (first-party app)", slug);
    }

    let manifest = fetch_and_verify_manifest(trusted, json_mode)?;
    if manifest.slug != slug {
        return Err(format!(
            "manifest slug mismatch: requested '{}', manifest declares '{}'",
            slug, manifest.slug
        )
        .into());
    }

    cache_manifest(slug, &manifest)?;

    let installer = manifest
        .resolve_for_current_os()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Per-kind dispatch. The kind→runner mapping is the contract surface
    // we extend when new installer protocols ship; an unknown kind aborts
    // with I_UNSUPPORTED_INSTALLER_KIND rather than guessing.
    match installer.kind.as_str() {
        "curl-pipe-shell" | "powershell-iwr-iex" => { /* recognized — dispatch below */ }
        other => {
            return Err(format!(
                "I_UNSUPPORTED_INSTALLER_KIND: '{}' (supported: 'curl-pipe-shell', 'powershell-iwr-iex')",
                other
            )
            .into());
        }
    }

    if !json_mode {
        println!(
            "→ Running service installer: {} (--tag {})",
            installer.url, manifest.version
        );
        println!(
            "  (the installer is owned by the plugin — it will set up its own service,\n\
             register the app in your vault, and configure the proxy as needed.)"
        );
    }

    // Pass `--tag <manifest.version>` so the plugin installer knows
    // exactly which release artifacts to fetch. Two reasons we don't
    // rely on the script's own latest-resolution:
    //   1. GitHub's /releases/latest excludes pre-releases. During the
    //      pre-release window (e.g. v1.0.0-rc.5), the script would
    //      resolve to the previous stable (rc.2) which doesn't carry
    //      trust-local assets → 404.
    //   2. The user installed CLI vX.Y.Z; they implicitly want the
    //      bound vX.Y.Z artifacts, not whatever happens to be "latest"
    //      at curl-pipe time. The manifest's `version` is the source
    //      of truth for that binding.
    // Plugin autonomy still holds: CLI doesn't tell the script HOW to
    // install — only WHICH version. The script can ignore --tag and
    // do its own resolution if a future iteration prefers that.
    if installer.kind == "powershell-iwr-iex" {
        run_powershell_installer(&installer.url, &manifest.version, json_mode)?;
    } else {
        run_curl_pipe_shell(&installer.url, &manifest.version, json_mode)?;
    }

    if !json_mode {
        println!("✓ {} install complete", slug);
        if let Some(doc) = manifest.doc_url.as_deref() {
            println!("  Docs: {}", doc);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall (2026-05-23, paired with rc.5 default-on flip).
// ---------------------------------------------------------------------------

/// Implements `aikey app uninstall <slug>`. Inverse of `handle_install`:
///
///   1. Validate slug ∈ TRUSTED_APPS (same trust anchor as install).
///   2. Resolve service-installer URL — first from cached manifest at
///      `~/.aikey/apps-cache/<slug>/manifest.json` (the file install
///      wrote), then fall back to re-fetching + re-verifying if the
///      cache is missing (e.g. user manually deleted apps-cache).
///   3. Run the same shell script with `--uninstall` flag — the plugin's
///      install_service.sh already handles this (verified for
///      degrade-detector). The script stops the launchd / systemd
///      service, removes the binary, and exits.
///   4. Delete every vault row tied to the slug (`delete_all_app_state`).
///      This bypasses the `mutationLockedSlugs` revoke/rotate guard on
///      aikey-control — uninstall is whole-system (service down +
///      vault clean), not a partial revoke that would leave a running
///      agent with no bearer.
///   5. (Best-effort) remove the cached manifest dir so a future install
///      starts clean.
///
/// Idempotent: running on a never-installed slug succeeds with zero
/// rows deleted + script exit 0 (install_service.sh --uninstall is
/// itself idempotent — see the script's own `ok` lines that fire
/// only on actual file existence).
pub fn handle_uninstall(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // 2026-05-25: uninstall now supports both first-party (via TRUSTED_APPS,
    // full lifecycle: service binary removal + vault wipe) and third-party
    // (identity-only: revoke app_keys for audit + delete app_records +
    // delete bindings). The two paths differ deliberately — first-party is
    // whole-system (AiKey owns the agent binary), third-party is
    // AiKey-side-only (third-party agent binary is user-managed).
    match TRUSTED_APPS.iter().find(|t| t.slug == slug) {
        Some(trusted) => handle_uninstall_first_party(slug, trusted, json_mode),
        None => handle_uninstall_third_party(slug, json_mode),
    }
}

/// First-party uninstall path: runs the agent's own install_service.sh
/// `--uninstall` (which stops the launchd/systemd service + removes the
/// binary), then deletes ALL vault rows for the slug (app_keys included),
/// then clears the manifest cache. The vault wipe bypasses the
/// `mutationLockedSlugs` lock — that lock is for revoke/rotate (partial
/// state breaking), not for whole-system uninstall.
fn handle_uninstall_first_party(
    slug: &str,
    trusted: &TrustedApp,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !json_mode {
        println!("→ Uninstalling {} (first-party app)", slug);
    }

    // Step 2: resolve installer URL + kind for current OS — prefer cache
    // (install wrote it), fall back to fresh fetch + verify.
    let manifest = match read_cached_manifest(slug)? {
        Some(m) => {
            if !json_mode {
                println!("→ Using cached manifest from previous install");
            }
            m
        }
        None => {
            if !json_mode {
                println!("→ Cached manifest missing — re-fetching for uninstall");
            }
            fetch_and_verify_manifest(trusted, json_mode)?
        }
    };
    let installer = manifest
        .resolve_for_current_os()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let installer_url = installer.url.clone();
    let installer_kind = installer.kind.clone();

    // Step 3: run the installer script with --uninstall (Unix) / -Uninstall
    // (Windows). The script's own uninstall path is idempotent (no-op when
    // nothing is installed), so we don't gate this on prior install state.
    if !json_mode {
        let flag = if installer_kind == "powershell-iwr-iex" {
            "-Uninstall"
        } else {
            "--uninstall"
        };
        println!("→ Running service uninstaller: {} {}", installer_url, flag);
    }
    run_service_uninstall(&installer_url, &installer_kind, json_mode)?;

    // Step 4: wipe vault rows (all three tables). First-party uninstall is
    // whole-system so the audit trail isn't needed at vault level (it lives
    // in service logs + usage_event_ods).
    let counts = crate::commands_app::delete_all_app_state(slug)?;
    if !json_mode {
        println!(
            "✓ Vault cleaned: app_keys={}, bindings={}, app_records={}",
            counts.app_keys_deleted, counts.bindings_deleted, counts.app_records_deleted,
        );
    }

    // Step 5: best-effort cache cleanup. If this fails (e.g. file
    // perms shifted), we don't abort — the install/uninstall lifecycle
    // already succeeded.
    if let Err(e) = remove_cached_manifest(slug) {
        if !json_mode {
            eprintln!("⚠ Failed to remove cached manifest (non-fatal): {}", e);
        }
    }

    if !json_mode {
        println!("✓ {} uninstall complete", slug);
        println!("  Re-install any time with: aikey app install {}", slug);
    }
    Ok(())
}

/// Third-party uninstall path: AiKey-side identity removal only.
///
/// Per 2026-05-25 user decision (plan doc
/// `roadmap20260320/技术实现/update/2026-05-25-third-party-app-web-ui-add.md`
/// §5 decision E): removes `app_records` + `user_profile_provider_bindings`
/// rows for the slug, but RETAINS `app_keys` rows by flipping their
/// `status` column to 'revoked'. The retained rows give audit history of
/// "which tokens were ever issued for this slug" without keeping any
/// token in an active state. The third-party agent's own binary is
/// user-managed and not touched by this command.
///
/// Pre-condition: the slug must EXIST in app_records (idempotency tolerates
/// "already partially uninstalled" state — re-running on a slug with no
/// active bindings + no app_records row is OK and reports zero counts —
/// but a slug that never existed at all yields a not-found error so
/// users don't think they cleaned up state they didn't have).
fn handle_uninstall_third_party(
    slug: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check existence so we can give an actionable "not registered" error
    // instead of silently succeeding with zero counts. Look at app_records
    // (the identity table); app_keys may be entirely absent for slugs that
    // were registered but never authorized (legacy two-step flow).
    let existed = crate::commands_app::get_app_record(slug)
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("check existence for slug={:?}: {}", slug, e).into()
        })?
        .is_some();
    if !existed {
        return Err(format!(
            "slug '{}' is not registered. Run `aikey app list` to see registered apps.",
            slug,
        )
        .into());
    }

    if !json_mode {
        println!("→ Uninstalling {} (third-party app)", slug);
        println!("  AiKey-side identity removal only. Your agent's own binary");
        println!("  (if any) is user-managed and not touched.");
    }

    let counts = crate::commands_app::delete_third_party_app_identity(slug)?;
    if !json_mode {
        println!(
            "✓ Vault updated: app_keys revoked={} (history preserved), \
             bindings deleted={}, app_records deleted={}",
            counts.app_keys_revoked, counts.bindings_deleted, counts.app_records_deleted,
        );
        println!("✓ {} uninstall complete", slug);
        println!(
            "  Re-register any time with: aikey app register --slug {} ...",
            slug
        );
    }
    Ok(())
}

/// Read the manifest cache file written by `cache_manifest()` at install
/// time. Returns Ok(None) when the file doesn't exist (clean fallback —
/// caller re-fetches). Returns Err on parse failure (corrupt cache,
/// caller decides whether to bail).
fn read_cached_manifest(slug: &str) -> Result<Option<Manifest>, Box<dyn std::error::Error>> {
    let path = apps_cache_dir()?.join(slug).join("manifest.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse cached manifest {}: {}", path.display(), e))?;
    Ok(Some(manifest))
}

/// Remove the cached manifest directory for the slug. No-op if absent.
fn remove_cached_manifest(slug: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = apps_cache_dir()?.join(slug);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {}", dir.display(), e))?;
    }
    Ok(())
}

/// Inverse of the install-path runners — same download path but invokes
/// the script with `--uninstall` (Unix sh) or `-Uninstall` (PowerShell)
/// instead of `--tag <version>`. Kept as a separate function so the
/// install path stays a clean two-arg signature and uninstall semantics
/// are explicit at the call site.
///
/// `kind` selects the runner:
///   - "curl-pipe-shell"     → `sh <tmp>.sh --uninstall`
///   - "powershell-iwr-iex"  → `powershell -File <tmp>.ps1 -Uninstall`
fn run_service_uninstall(
    url: &str,
    kind: &str,
    _json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = std::env::temp_dir();
    let is_ps = kind == "powershell-iwr-iex";
    let suffix = if is_ps { "ps1" } else { "sh" };
    let tmp_path = tmp_dir.join(format!(
        "aikey-app-uninstaller-{}.{}",
        std::process::id(),
        suffix
    ));
    let cleanup = TmpPath(tmp_path.clone());

    let curl_bin = if is_ps { "curl.exe" } else { "curl" };
    let download = Command::new(curl_bin)
        .arg("-fsSL")
        .arg("--max-time")
        .arg("120")
        .arg("-o")
        .arg(&tmp_path)
        .arg(url)
        .status()
        .map_err(|e| format!("failed to spawn {}: {}", curl_bin, e))?;
    if !download.success() {
        return Err(format!(
            "service uninstaller download failed ({} exit {}): {}",
            curl_bin,
            download
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into()),
            url
        )
        .into());
    }

    let meta =
        fs::metadata(&tmp_path).map_err(|e| format!("stat downloaded uninstaller: {}", e))?;
    if meta.len() == 0 {
        return Err(format!("downloaded uninstaller is empty (0 bytes): {}", url).into());
    }

    let exec = if is_ps {
        Command::new("powershell.exe")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-NoProfile")
            .arg("-File")
            .arg(&tmp_path)
            .arg("-Uninstall")
            .status()
            .map_err(|e| format!("failed to spawn powershell.exe: {}", e))?
    } else {
        Command::new("sh")
            .arg(&tmp_path)
            .arg("--uninstall")
            .status()
            .map_err(|e| format!("failed to spawn shell: {}", e))?
    };
    drop(cleanup);
    if !exec.success() {
        return Err(format!(
            "service uninstaller exited with status {}",
            exec.code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into())
        )
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Manifest fetch + verify.
// ---------------------------------------------------------------------------

/// Download manifest from `trusted.manifest_url`, verify SHA-256
/// against `trusted.manifest_sha256`, return the parsed struct.
///
/// When `manifest_sha256 == "PENDING_LAUNCH_RELEASE"` we instead emit a
/// loud warning and return a built-in dev manifest so end-to-end testing
/// can proceed before the launch release is published. Currently no
/// TRUSTED_APPS entry uses this placeholder (resolved 2026-05-23 by
/// publishing degrade-detector.manifest.json under v1.0.0-rc.5 release);
/// the branch stays as an escape hatch for future trusted apps awaiting
/// their first manifest publication, but MUST be removed before a stable
/// `aikey-cli` release if any TRUSTED_APPS entry still relies on it.
fn fetch_and_verify_manifest(
    trusted: &TrustedApp,
    json_mode: bool,
) -> Result<Manifest, Box<dyn std::error::Error>> {
    if trusted.manifest_sha256 == "PENDING_LAUNCH_RELEASE" {
        if !json_mode {
            eprintln!(
                "⚠ Using built-in DEV manifest for '{}' (TRUSTED_APPS entry still has PENDING_LAUNCH_RELEASE placeholder).\n\
                 This bypasses SHA-256 verification — DO NOT release a CLI binary while this branch is live.",
                trusted.slug
            );
        }
        return dev_manifest_for_slug(trusted.slug)
            .ok_or_else(|| format!("no dev manifest available for '{}'", trusted.slug).into());
    }

    if !json_mode {
        println!("→ Fetching manifest: {}", trusted.manifest_url);
    }

    // Route through the proxy-aware agent — `ureq::get()` ignores both
    // `~/.aikey/proxy.env` AND the process env, which broke first-install
    // on Mac users running Clash / V2Ray with lowercase `https_proxy`
    // exported only. The builder consults proxy.env first, then env
    // (lowercase + uppercase variants).
    // Bugfix: 20260525-aikey-cli-install-bypasses-proxy-aware-agent.md
    let agent = crate::connectivity::build_proxy_aware_agent(std::time::Duration::from_secs(15));
    let resp = agent.get(trusted.manifest_url).call().map_err(|e| {
        // Surface the most common cause for Mac users so they can
        // self-diagnose without reading source. The hint only adds
        // value when a TCP connect actually timed out (proxy unset
        // or pointing at a dead listener); for HTTP-level errors
        // we keep the raw ureq message intact.
        let msg = e.to_string();
        let proxy_hint = if msg.contains("timed out")
            || msg.contains("Connect error")
            || msg.contains("dns error")
        {
            proxy_misconfiguration_hint()
        } else {
            String::new()
        };
        format!("manifest fetch failed: {}{}", e, proxy_hint)
    })?;

    let mut bytes = Vec::with_capacity(8 * 1024);
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("manifest body read failed: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let got_sha = hex::encode(hasher.finalize());

    if got_sha != trusted.manifest_sha256 {
        return Err(format!(
            "I_MANIFEST_TAMPERED: SHA-256 mismatch for '{}'.\n\
              expected: {}\n\
              got:      {}\n\
             The manifest at {} may have been replaced or corrupted. Refusing to install.",
            trusted.slug, trusted.manifest_sha256, got_sha, trusted.manifest_url
        )
        .into());
    }

    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| format!("manifest JSON parse failed: {}", e))?;
    validate_manifest_schema_version(&manifest.schema_version)?;
    Ok(manifest)
}

/// Diagnose the most common manifest-fetch failure mode on Mac:
/// the user has a local proxy (Clash / V2Ray / Surge) configured via
/// lowercase env, but the CLI couldn't reach the network anyway.
/// Returns a multi-line "\n\n│ hint:" suffix or an empty string if no
/// actionable hint applies. Kept tight on purpose — surface only when
/// it materially helps, otherwise leave the raw ureq error alone.
fn proxy_misconfiguration_hint() -> String {
    let lower_https = std::env::var("https_proxy").ok();
    let lower_http = std::env::var("http_proxy").ok();
    let lower_all = std::env::var("all_proxy").ok();
    let upper_https = std::env::var("HTTPS_PROXY").ok();
    let upper_http = std::env::var("HTTP_PROXY").ok();
    let proxy_env_path = std::env::var("HOME")
        .ok()
        .map(|h| format!("{}/.aikey/proxy.env", h));
    let has_proxy_env_file = proxy_env_path
        .as_ref()
        .map(|p| std::path::Path::new(p).exists())
        .unwrap_or(false);

    let lowercase_set = lower_https.is_some() || lower_http.is_some() || lower_all.is_some();
    let uppercase_set = upper_https.is_some() || upper_http.is_some();

    if lowercase_set && !uppercase_set && !has_proxy_env_file {
        // Most common Mac case: GUI proxy app exported only lowercase
        // env. Pre-fix this would silently bypass the proxy and time
        // out on direct connect. Post-fix the agent already honors
        // lowercase, so this branch only fires when our agent did try
        // the lowercase proxy and IT couldn't reach the upstream —
        // tell the user to verify the proxy app is actually running.
        return format!(
            "\n\n│ hint: detected lowercase proxy env ({}) — the CLI did try \
             routing through it. Verify the proxy app is running:\n\
             │   curl -sI {} | head -1   # should print HTTP/2 200 or 302\n\
             │ If curl works but this fetch failed, the proxy is dropping \
             non-curl clients; try restarting the proxy app.",
            lower_https
                .as_ref()
                .or(lower_http.as_ref())
                .or(lower_all.as_ref())
                .map(|s| s.as_str())
                .unwrap_or(""),
            "https://github.com/aikeylabs/launch/releases/latest"
        );
    }
    if !lowercase_set && !uppercase_set && !has_proxy_env_file {
        // No proxy configured anywhere. Likely direct-internet failure
        // (China mainland blocks GitHub Releases CDN intermittently).
        return "\n\n│ hint: no proxy env or ~/.aikey/proxy.env detected. \
             If you're behind a restricted network (e.g. China mainland), \
             export HTTPS_PROXY=http://<host>:<port> (or write it to \
             ~/.aikey/proxy.env) and retry."
            .to_string();
    }
    // Everything else (proxy.env set, or both casings set): hand back
    // the raw error with no hint. Adding noise here would dilute the
    // signal value of the hint when it does fire.
    String::new()
}

/// Manifest schema versions this CLI knows how to deserialize +
/// dispatch on. Adding a new version: add one entry here AND ensure
/// `Manifest::resolve_for_current_os()` handles the new shape AND add
/// a fence test in `tests::manifest_v<N>_accepted`. Bugfix
/// 20260525-aikey-cli-manifest-v2-guard-not-updated.md captures why
/// list-based (not chained `&&`) — `git grep` for this const surfaces
/// every gating decision in one shot.
const SUPPORTED_MANIFEST_SCHEMA_VERSIONS: &[&str] = &["1", "2"];

/// Validate that `schema_version` is one this CLI knows how to handle.
///
/// BR-rc.5-59 fix (2026-05-25): extracted from
/// `fetch_and_verify_manifest` so fence tests can call it directly
/// without needing HTTP mocking. Pre-fix the guard inline was hardcoded
/// `!= "1"` — the v2 manifest shape was fully implemented in this file
/// at line 132-170 + tested at line 893/915 in the same commit
/// (d7ba0b1), but this guard was missed → Released v2 manifest +
/// Released CLI → 100% `I_UNSUPPORTED_MANIFEST_SCHEMA: '2'` on fresh
/// install. List-based guard avoids the chained `&&` anti-pattern
/// (CLAUDE.md "采用配置表的形式进行穷举") — adding v3 is a single
/// entry edit. Mirrors `YAML_CONFIG_REL_CANDIDATES` pattern in
/// `local_server_probe.rs` (BR-rc.5-58, same release cycle).
fn validate_manifest_schema_version(version: &str) -> Result<(), String> {
    if SUPPORTED_MANIFEST_SCHEMA_VERSIONS.contains(&version) {
        return Ok(());
    }
    Err(format!(
        "I_UNSUPPORTED_MANIFEST_SCHEMA: '{}'. This CLI supports schema_version=[{}] — upgrade aikey-cli to install this app.",
        version,
        SUPPORTED_MANIFEST_SCHEMA_VERSIONS.join(", "),
    ))
}

/// Dev-mode fallback manifest, used while `manifest_sha256 ==
/// "PENDING_LAUNCH_RELEASE"`. Mirrors the JSON that will be published
/// on `aikeylabs/launch` for the corresponding slug. Remove the
/// matching entry once the real release lands and the SHA is filled
/// in above.
fn dev_manifest_for_slug(slug: &str) -> Option<Manifest> {
    match slug {
        "degrade-detector" => Some(Manifest {
            schema_version: "2".into(),
            slug: "degrade-detector".into(),
            version: "v1.0.0-rc.5".into(),
            service_installers: Some(ServiceInstallers {
                unix: ServiceInstaller {
                    kind: "curl-pipe-shell".into(),
                    // Points at aikeylabs/launch v1.0.0-rc.5 pre-release.
                    // The .sh / .ps1 scripts are uploaded as release assets
                    // by release.sh Step 7.7 (release-windows-addon.sh +
                    // install_service.{sh,ps1} staging).
                    url: "https://github.com/aikeylabs/launch/releases/download/v1.0.0-rc.5/install_service.sh"
                        .into(),
                },
                windows: Some(ServiceInstaller {
                    kind: "powershell-iwr-iex".into(),
                    url: "https://github.com/aikeylabs/launch/releases/download/v1.0.0-rc.5/install_service.ps1"
                        .into(),
                }),
            }),
            service_installer: None,
            doc_url: Some("https://github.com/aikeylabs/launch".into()),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cache.
// ---------------------------------------------------------------------------

/// Persist the verified manifest to `~/.aikey/apps-cache/<slug>/manifest.json`.
/// Subsequent installs / reinstalls can short-circuit fetch by reading
/// this file (not implemented yet — current MVP always re-fetches and
/// re-verifies, since the trust anchor is the CLI binary not the cached
/// file). We still write it for `aikey app doctor` / debug observability.
fn cache_manifest(slug: &str, manifest: &Manifest) -> Result<(), Box<dyn std::error::Error>> {
    let dir = apps_cache_dir()?.join(slug);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("create apps-cache dir {}: {}", dir.display(), e))?;
    let path = dir.join("manifest.json");
    let json = serde_json::to_string_pretty(manifest)?;
    let mut f = fs::File::create(&path).map_err(|e| format!("write {}: {}", path.display(), e))?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

fn apps_cache_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    Ok(PathBuf::from(home).join(".aikey").join("apps-cache"))
}

// ---------------------------------------------------------------------------
// Service installer dispatch.
// ---------------------------------------------------------------------------

/// Download the installer to a temp file, verify download succeeded,
/// then execute it.
///
/// **Why not `curl … | sh` directly**: in a pipeline, the shell's exit
/// status is the right-hand side's status. `curl -fsSL <404> | sh`
/// produces empty stdin → sh reads nothing → exits 0 → CLI thinks the
/// install succeeded even though the script never ran. Bash users can
/// fix this with `set -o pipefail`, but POSIX `sh` has no such option
/// and we want a portable fix that works on every OS we ship for.
///
/// Two-step download + exec also lets us:
///   - report the curl failure clearly (with URL + status) instead of
///     swallowing it
///   - re-execute or audit the script later via the cached file (a
///     forensic trail when an install goes wrong)
fn run_curl_pipe_shell(
    url: &str,
    version_tag: &str,
    _json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("aikey-app-installer-{}.sh", std::process::id()));
    let cleanup = TmpPath(tmp_path.clone());

    let download = Command::new("curl")
        .arg("-fsSL")
        .arg("--max-time")
        .arg("120")
        .arg("-o")
        .arg(&tmp_path)
        .arg(url)
        .status()
        .map_err(|e| format!("failed to spawn curl: {}", e))?;
    if !download.success() {
        return Err(format!(
            "service installer download failed (curl exit {}): {}",
            download
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into()),
            url
        )
        .into());
    }

    // Sanity: empty file is also a "successful download" per curl exit
    // code, but a no-op shell script is never what a plugin owner
    // intends to ship. Bail loudly rather than silently "succeed".
    let meta = fs::metadata(&tmp_path).map_err(|e| format!("stat downloaded installer: {}", e))?;
    if meta.len() == 0 {
        return Err(format!("downloaded installer is empty (0 bytes): {}", url).into());
    }

    // Hand off to `sh` (portable POSIX). Using `bash` would silently
    // accept bash-only scripts and burn us when a vendor switches host.
    // `--tag <version>` is the plugin's contract for pinning the release
    // artifact set; see comment in handle_install() for why CLI doesn't
    // rely on the script's own /releases/latest lookup.
    let exec = Command::new("sh")
        .arg(&tmp_path)
        .arg("--tag")
        .arg(version_tag)
        .status()
        .map_err(|e| format!("failed to spawn shell: {}", e))?;
    drop(cleanup); // explicit so the file lives through `exec.status()`
    if !exec.success() {
        return Err(format!(
            "service installer exited with status {}",
            exec.code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into())
        )
        .into());
    }
    Ok(())
}

/// Best-effort temp file cleanup. We don't propagate cleanup errors
/// because the install has already succeeded or failed at that point —
/// reporting "couldn't unlink /tmp/x" wouldn't help the user.
struct TmpPath(PathBuf);
impl Drop for TmpPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Windows-side peer of `run_curl_pipe_shell`. Downloads a `.ps1`
/// installer to `%TEMP%`, then execs it via PowerShell.
///
/// We use `curl.exe` (bundled in Windows 10 / Server 2019+ since
/// build 17063) rather than `iwr | iex` because curl gives us
/// deterministic exit codes, --max-time, and SHA-verifiable output
/// (same observability as the Unix path).
///
/// PowerShell exec flags:
///   `-ExecutionPolicy Bypass`  — don't refuse an unsigned script.
///                                The script's authenticity is already
///                                bound by the manifest SHA-256 we
///                                verified upstream.
///   `-NoProfile`               — skip $PROFILE / Modules autoload
///                                so 3rd-party PS modules can't inject.
///   `-File <path>`             — execute as a script (not as a string,
///                                which would interpret -Tag etc as PS
///                                operators rather than args).
fn run_powershell_installer(
    url: &str,
    version_tag: &str,
    _json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("aikey-app-installer-{}.ps1", std::process::id()));
    let cleanup = TmpPath(tmp_path.clone());

    // curl.exe is bundled in Windows 10 1803+ / Server 2019+. We
    // explicitly call curl.exe (not just "curl") because PowerShell's
    // built-in `curl` alias shadows the binary and points at
    // Invoke-WebRequest, which has different semantics + can hang in
    // non-interactive sessions (writing progress to a non-existent
    // console handle). Always call curl.exe by full name.
    let download = Command::new("curl.exe")
        .arg("-fsSL")
        .arg("--max-time")
        .arg("120")
        .arg("-o")
        .arg(&tmp_path)
        .arg(url)
        .status()
        .map_err(|e| format!("failed to spawn curl.exe: {}", e))?;
    if !download.success() {
        return Err(format!(
            "service installer download failed (curl exit {}): {}",
            download
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into()),
            url
        )
        .into());
    }

    let meta = fs::metadata(&tmp_path).map_err(|e| format!("stat downloaded installer: {}", e))?;
    if meta.len() == 0 {
        return Err(format!("downloaded installer is empty (0 bytes): {}", url).into());
    }

    // PowerShell exec — see fn-level comment for why these flags.
    let exec = Command::new("powershell.exe")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-NoProfile")
        .arg("-File")
        .arg(&tmp_path)
        .arg("-Tag")
        .arg(version_tag)
        .status()
        .map_err(|e| format!("failed to spawn powershell.exe: {}", e))?;
    drop(cleanup);
    if !exec.success() {
        return Err(format!(
            "service installer exited with status {}",
            exec.code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into())
        )
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_slug() {
        let err = handle_install("not-a-real-app", true).expect_err("should reject unknown slug");
        let msg = format!("{}", err);
        assert!(msg.contains("trusted-apps list"), "msg was: {}", msg);
    }

    #[test]
    fn dev_manifest_returns_degrade_detector() {
        let m = dev_manifest_for_slug("degrade-detector").expect("present");
        assert_eq!(m.slug, "degrade-detector");
        assert_eq!(m.schema_version, "2");
        let installers = m
            .service_installers
            .as_ref()
            .expect("v2 must populate service_installers");
        assert_eq!(installers.unix.kind, "curl-pipe-shell");
        // Pin a substring so accidental URL renames are caught.
        assert!(installers.unix.url.contains("install_service.sh"));
        let win = installers
            .windows
            .as_ref()
            .expect("Windows entry must exist for degrade-detector v2");
        assert_eq!(win.kind, "powershell-iwr-iex");
        assert!(win.url.contains("install_service.ps1"));
    }

    #[test]
    fn manifest_v1_legacy_resolves_for_unix_but_rejects_windows() {
        // Backward-compat: v1 manifests in the wild (or in caches) should
        // still install on Unix, while clearly failing on Windows hosts
        // (rather than silently bash-execing a .sh that 404s).
        let v1 = Manifest {
            schema_version: "1".into(),
            slug: "legacy-app".into(),
            version: "v0.1.0".into(),
            service_installers: None,
            service_installer: Some(ServiceInstaller {
                kind: "curl-pipe-shell".into(),
                url: "https://example.com/legacy.sh".into(),
            }),
            doc_url: None,
        };
        let resolved = v1.resolve_for_current_os();
        if cfg!(target_os = "windows") {
            assert!(
                resolved.is_err(),
                "v1 manifest on Windows should error with I_PLATFORM_UNSUPPORTED"
            );
            let msg = format!("{}", resolved.unwrap_err());
            assert!(msg.contains("I_PLATFORM_UNSUPPORTED"), "msg was: {}", msg);
        } else {
            let i = resolved.expect("v1 manifest on Unix should resolve to legacy field");
            assert_eq!(i.kind, "curl-pipe-shell");
        }
    }

    #[test]
    fn manifest_v2_resolves_by_target_os() {
        let m = dev_manifest_for_slug("degrade-detector").expect("present");
        let resolved = m
            .resolve_for_current_os()
            .expect("v2 with both platforms should resolve");
        if cfg!(target_os = "windows") {
            assert_eq!(resolved.kind, "powershell-iwr-iex");
            assert!(resolved.url.ends_with(".ps1"));
        } else {
            assert_eq!(resolved.kind, "curl-pipe-shell");
            assert!(resolved.url.ends_with(".sh"));
        }
    }

    #[test]
    fn dev_manifest_unknown_returns_none() {
        assert!(dev_manifest_for_slug("not-real").is_none());
    }

    #[test]
    fn trusted_apps_only_contains_degrade_detector_for_now() {
        // Pin so anyone adding a new entry has to update tests/docs.
        // When this fires, also update `roadmap20260320/技术实现/阶段4-增值版/
        // 第三方Agent自助接入与应用级Key方案.md` §11.B trusted list.
        assert_eq!(TRUSTED_APPS.len(), 1);
        assert_eq!(TRUSTED_APPS[0].slug, "degrade-detector");
    }

    // ─── BR-rc.5-59 fence tests ────────────────────────────────────────
    //
    // Released v2 manifest + released CLI rejected v2 with
    // `I_UNSUPPORTED_MANIFEST_SCHEMA: '2'` because the guard at line 590
    // was missed during the v2-aware refactor (commit d7ba0b1). These
    // pin the guard contract so the regression can't recur:
    //   - v2 (current) and v1 (legacy) both pass
    //   - any other version rejected with the documented error code
    //   - SUPPORTED_MANIFEST_SCHEMA_VERSIONS list is exactly ["1", "2"]
    //     (changing it requires also updating Manifest::resolve_for_
    //     current_os to handle the new shape)

    #[test]
    fn manifest_v2_accepted() {
        // Direct release-team-requested regression pin.
        assert!(
            validate_manifest_schema_version("2").is_ok(),
            "v2 manifest must be accepted; this is the BR-rc.5-59 regression case"
        );
    }

    #[test]
    fn manifest_v1_still_accepted() {
        // Backward-compat: don't regress v1 while adding v2.
        assert!(
            validate_manifest_schema_version("1").is_ok(),
            "v1 manifest must still be accepted (legacy compat)"
        );
    }

    #[test]
    fn manifest_unknown_version_rejected_with_i_unsupported_code() {
        // Boundary: unknown versions (current target: v3, v0, "", etc)
        // must error with the documented I_UNSUPPORTED_MANIFEST_SCHEMA
        // code so scripts can grep for it deterministically.
        for bad in &["3", "0", "", "v2", "1.0", "two"] {
            let err = validate_manifest_schema_version(bad)
                .expect_err(&format!("version {:?} must be rejected", bad));
            assert!(
                err.contains("I_UNSUPPORTED_MANIFEST_SCHEMA"),
                "version {:?} error must contain I_UNSUPPORTED_MANIFEST_SCHEMA; got: {}",
                bad,
                err
            );
            assert!(
                err.contains(bad),
                "error must echo back the offending version {:?}; got: {}",
                bad,
                err
            );
        }
    }

    #[test]
    fn supported_manifest_schema_versions_list_pinned() {
        // Pin the exact accepted-versions list. Re-ordering or adding
        // an entry should force a test edit so reviewers see the
        // contract change. When adding v3:
        //   1. Update SUPPORTED_MANIFEST_SCHEMA_VERSIONS
        //   2. Update Manifest::resolve_for_current_os() to handle v3
        //   3. Add tests::manifest_v3_accepted
        //   4. Update this assertion
        assert_eq!(SUPPORTED_MANIFEST_SCHEMA_VERSIONS, &["1", "2"]);
    }
}
