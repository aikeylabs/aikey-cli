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
/// Published 2026-05-23: served-asset sha256 verified equal to the
/// canonical committed file at aikeylabs/launch/manifests/degrade-detector.manifest.json.
const TRUSTED_APPS: &[TrustedApp] = &[
    TrustedApp {
        slug: "degrade-detector",
        manifest_url:
            "https://github.com/aikeylabs/launch/releases/download/v1.0.0-rc.5/degrade-detector.manifest.json",
        manifest_sha256: "39de932ff058b2d129fea82c77a229695564ae53c474f7d7d66490efda5cc5f3",
    },
];

// ---------------------------------------------------------------------------
// Manifest schema (kept minimal — see file header §Design).
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Manifest {
    pub schema_version: String,
    pub slug: String,
    pub version: String,
    pub service_installer: ServiceInstaller,
    #[serde(default)]
    pub doc_url: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct ServiceInstaller {
    /// MVP supports only `"curl-pipe-shell"`. Anything else aborts with
    /// `I_UNSUPPORTED_INSTALLER_KIND` — we want explicit opt-in for new
    /// installer protocols (binary download, package manager, etc).
    pub kind: String,
    /// HTTPS URL pointing at a shell script. Pinned to a git tag (not
    /// `main`) per §11.B so mid-flight branch updates can't introduce
    /// surprises after the manifest is published.
    pub url: String,
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

    if manifest.service_installer.kind != "curl-pipe-shell" {
        return Err(format!(
            "I_UNSUPPORTED_INSTALLER_KIND: '{}' (only 'curl-pipe-shell' is supported in MVP)",
            manifest.service_installer.kind
        )
        .into());
    }

    if !json_mode {
        println!(
            "→ Running service installer: {} (--tag {})",
            manifest.service_installer.url, manifest.version
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
    run_curl_pipe_shell(
        &manifest.service_installer.url,
        &manifest.version,
        json_mode,
    )?;

    if !json_mode {
        println!("✓ {} install complete", slug);
        if let Some(doc) = manifest.doc_url.as_deref() {
            println!("  Docs: {}", doc);
        }
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
        return dev_manifest_for_slug(trusted.slug).ok_or_else(|| {
            format!("no dev manifest available for '{}'", trusted.slug).into()
        });
    }

    if !json_mode {
        println!("→ Fetching manifest: {}", trusted.manifest_url);
    }

    let resp = ureq::get(trusted.manifest_url)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| format!("manifest fetch failed: {}", e))?;

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

    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("manifest JSON parse failed: {}", e))?;
    if manifest.schema_version != "1" {
        return Err(format!(
            "I_UNSUPPORTED_MANIFEST_SCHEMA: '{}'. This CLI supports schema_version=1 only — upgrade aikey-cli to install this app.",
            manifest.schema_version
        )
        .into());
    }
    Ok(manifest)
}

/// Dev-mode fallback manifest, used while `manifest_sha256 ==
/// "PENDING_LAUNCH_RELEASE"`. Mirrors the JSON that will be published
/// on `aikeylabs/launch` for the corresponding slug. Remove the
/// matching entry once the real release lands and the SHA is filled
/// in above.
fn dev_manifest_for_slug(slug: &str) -> Option<Manifest> {
    match slug {
        "degrade-detector" => Some(Manifest {
            schema_version: "1".into(),
            slug: "degrade-detector".into(),
            version: "v1.0.0-rc.5".into(),
            service_installer: ServiceInstaller {
                kind: "curl-pipe-shell".into(),
                // Points at aikeylabs/launch v1.0.0-rc.5 pre-release.
                // The script is uploaded as a release asset by the
                // degrade-detector GH Actions workflow
                // (.github/workflows/release-trust-local.yml).
                url: "https://github.com/aikeylabs/launch/releases/download/v1.0.0-rc.5/install_service.sh"
                    .into(),
            },
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
    let mut f = fs::File::create(&path)
        .map_err(|e| format!("write {}: {}", path.display(), e))?;
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
    let tmp_path = tmp_dir.join(format!(
        "aikey-app-installer-{}.sh",
        std::process::id()
    ));
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
            download.code().map(|c| c.to_string()).unwrap_or_else(|| "<signal>".into()),
            url
        )
        .into());
    }

    // Sanity: empty file is also a "successful download" per curl exit
    // code, but a no-op shell script is never what a plugin owner
    // intends to ship. Bail loudly rather than silently "succeed".
    let meta = fs::metadata(&tmp_path)
        .map_err(|e| format!("stat downloaded installer: {}", e))?;
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
            exec.code().map(|c| c.to_string()).unwrap_or_else(|| "<signal>".into())
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_slug() {
        let err = handle_install("not-a-real-app", true)
            .expect_err("should reject unknown slug");
        let msg = format!("{}", err);
        assert!(msg.contains("trusted-apps list"), "msg was: {}", msg);
    }

    #[test]
    fn dev_manifest_returns_degrade_detector() {
        let m = dev_manifest_for_slug("degrade-detector").expect("present");
        assert_eq!(m.slug, "degrade-detector");
        assert_eq!(m.schema_version, "1");
        assert_eq!(m.service_installer.kind, "curl-pipe-shell");
        // Pin a substring so accidental URL renames are caught.
        assert!(m.service_installer.url.contains("install_service.sh"));
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
}
