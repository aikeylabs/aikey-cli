//! Phase 3 of the Production form-⓪ multi-protocol egress delivery
//! (roadmap20260320/技术实现/update/20260717-Production成员本地proxy多协议交付-技术方案.md).
//!
//! A Production member's LOCAL aikey-proxy is the GPL-free OSS binary from the
//! GitHub release (socks5 only). This module lets an enrolled member pull the
//! ENTERPRISE aikey-egress-proxy (links mihomo, multi-protocol) from THEIR OWN
//! control panel (member-JWT, HTTPS), verify its sha256, and atomically swap it
//! in — so the node upstream / per-account egress can honor ss/vmess/trojan/
//! fallback specs. The public GitHub release stays mihomo-free (GPL guard).
//!
//! Security (T1 MVP): the binary is fetched over the member-authenticated HTTPS
//! channel and its sha256 is verified against the server manifest BEFORE the
//! swap. Full code-signing is a later hardening.
//!
//! Live swap + restart is verified in a tart VM (per repo policy, candidate
//! proxy binaries are never run/swapped on the host); the pure core here
//! (platform detection, sha256 verification, atomic same-dir swap) is unit-tested.

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// Whether ensure_enterprise_proxy actually replaced the binary (→ caller must
/// restart the proxy) or found nothing to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// This control panel serves no enterprise proxy (personal / OSS) — no-op.
    NotEnterprise,
    /// Local proxy already matches the enterprise binary — no swap.
    AlreadyCurrent,
    /// Enterprise binary fetched, verified, and swapped in — RESTART REQUIRED.
    Swapped,
}

/// Release-asset platform token for THIS host, e.g. "darwin-arm64". Matches the
/// naming build-enterprise-proxies.sh / release.sh use.
pub fn detect_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other, // "linux", "windows"
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{arch}")
}

/// sha256(bytes) as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Constant-shaped equality check of a computed digest against an expected hex
/// (case-insensitive). Returns false on any mismatch — the caller MUST NOT swap
/// on false.
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> bool {
    sha256_hex(bytes).eq_ignore_ascii_case(expected_hex.trim())
}

/// Atomically replace `target` with `bytes` (exec-permissioned). Writes a temp
/// file in the SAME directory (so rename is atomic on one filesystem) then
/// renames over the target. The running proxy keeps its old inode; the new
/// binary takes effect on the next restart. Verify sha256 BEFORE calling this.
pub fn atomic_swap(target: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = target
        .parent()
        .ok_or_else(|| format!("target has no parent dir: {}", target.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    // Same-dir temp so the rename is atomic (cross-fs rename is a copy → not atomic).
    let tmp = dir.join(format!(
        ".{}.enterprise-new",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("aikey-proxy")
    ));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create temp: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("write temp: {e}"))?;
        f.flush().map_err(|e| format!("flush temp: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod temp: {e}"))?;
        }
    }
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename over {}: {e}", target.display())
    })?;
    Ok(())
}

/// Manifest map filename→sha256 as served by GET /accounts/me/enterprise-proxy/manifest.
fn manifest_filename(platform: &str) -> String {
    if platform.starts_with("windows-") {
        format!("aikey-proxy-{platform}.exe")
    } else {
        format!("aikey-proxy-{platform}")
    }
}

/// Fetch the enterprise-proxy manifest. Ok(None) when the panel doesn't serve one
/// (404 → personal / OSS control panel). Err only on a real transport/decode fault.
fn fetch_manifest(
    control_url: &str,
    bearer: &str,
) -> Result<Option<std::collections::HashMap<String, String>>, String> {
    let url = format!(
        "{}/accounts/me/enterprise-proxy/manifest",
        control_url.trim_end_matches('/')
    );
    let resp = ureq::get(&url)
        .set("Authorization", &format!("Bearer {bearer}"))
        .call();
    match resp {
        Ok(r) => {
            #[derive(serde::Deserialize)]
            struct M {
                files: std::collections::HashMap<String, String>,
            }
            let m: M = r.into_json().map_err(|e| format!("decode manifest: {e}"))?;
            Ok(Some(m.files))
        }
        // 404 → this panel has no enterprise proxy (personal / OSS). Not an error.
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(format!("fetch manifest: {e}")),
    }
}

fn fetch_binary(control_url: &str, bearer: &str, platform: &str) -> Result<Vec<u8>, String> {
    let url = format!(
        "{}/accounts/me/enterprise-proxy?platform={}",
        control_url.trim_end_matches('/'),
        platform
    );
    let resp = ureq::get(&url)
        .set("Authorization", &format!("Bearer {bearer}"))
        .call()
        .map_err(|e| format!("fetch binary: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read binary: {e}"))?;
    Ok(buf)
}

/// Ensure the local proxy at `proxy_path` is the enterprise (multi-protocol)
/// binary this member's control panel offers. Best-effort + idempotent:
///   - panel serves no enterprise proxy → NotEnterprise (no-op).
///   - local proxy already matches the manifest sha → AlreadyCurrent.
///   - otherwise fetch → verify sha256 → atomic swap → Swapped (caller restarts).
///
/// Never swaps on a sha mismatch. Callers should treat Err as non-fatal (log +
/// keep the current proxy) so a delivery hiccup never blocks the main flow.
pub fn ensure_enterprise_proxy(
    control_url: &str,
    bearer: &str,
    proxy_path: &Path,
) -> Result<Outcome, String> {
    let files = match fetch_manifest(control_url, bearer)? {
        None => return Ok(Outcome::NotEnterprise),
        Some(f) => f,
    };
    let platform = detect_platform();
    let fname = manifest_filename(&platform);
    let expected = match files.get(&fname) {
        Some(s) => s.clone(),
        None => return Ok(Outcome::NotEnterprise), // no enterprise build for this platform
    };
    // Skip if the local proxy already IS the enterprise binary (idempotent sync).
    if let Ok(cur) = std::fs::read(proxy_path) {
        if verify_sha256(&cur, &expected) {
            return Ok(Outcome::AlreadyCurrent);
        }
    }
    let bytes = fetch_binary(control_url, bearer, &platform)?;
    if !verify_sha256(&bytes, &expected) {
        return Err(format!(
            "enterprise proxy sha256 mismatch (got {}, want {expected}) — REFUSING to swap",
            sha256_hex(&bytes)
        ));
    }
    atomic_swap(proxy_path, &bytes)?;
    Ok(Outcome::Swapped)
}

use std::io::Read as _;

/// Best-effort enterprise-proxy sync, called from `aikey key sync` / enrollment.
/// Reads the enrolled member's control_url + JWT, locates the local proxy, and
/// swaps in the enterprise (multi-protocol) binary IF this control panel serves
/// one. NEVER blocks or fails the caller — a delivery hiccup just leaves the
/// current (socks5-only) proxy in place. On a swap, prints an activation hint
/// (restart needs the master password, which sync doesn't hold, so we don't
/// auto-restart; the swapped binary takes effect on the next proxy restart).
///
/// Live swap + activation is verified in a tart VM (candidate proxy binaries are
/// never run/swapped on the host per repo policy).
pub fn sync_enterprise_proxy_best_effort(json_mode: bool) {
    let acct = match crate::storage::get_platform_account() {
        Ok(Some(a)) => a,
        _ => return, // not enrolled → nothing to do
    };
    if acct.control_url.trim().is_empty() || acct.jwt_token.trim().is_empty() {
        return;
    }
    let proxy_path = match crate::commands_proxy::find_proxy_binary() {
        Ok(p) => p,
        Err(_) => return, // no local proxy installed → nothing to swap
    };
    match ensure_enterprise_proxy(&acct.control_url, &acct.jwt_token, &proxy_path) {
        Ok(Outcome::Swapped) => {
            if !json_mode {
                eprintln!(
                    "  [aikey] multi-protocol egress proxy installed — restart with `aikey proxy restart` to activate."
                );
            }
        }
        Ok(_) => {}
        Err(e) => {
            // Surface, don't fail: keep the current proxy. (logging-conventions: a
            // fallback path must WARN, not silently return.)
            if !json_mode {
                eprintln!("  [aikey] WARN: enterprise proxy sync skipped: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_token_shape() {
        let p = detect_platform();
        // os-arch, os ∈ known set, arch normalized to amd64/arm64 on common hosts.
        assert!(p.contains('-'), "platform {p} should be <os>-<arch>");
        assert!(
            p.starts_with("darwin-") || p.starts_with("linux-") || p.starts_with("windows-"),
            "unexpected os in {p}"
        );
    }

    #[test]
    fn sha_verify_matches_and_rejects() {
        let b = b"the-enterprise-binary-bytes";
        let good = sha256_hex(b);
        assert!(verify_sha256(b, &good));
        assert!(verify_sha256(b, &good.to_uppercase())); // case-insensitive
        assert!(!verify_sha256(b, &sha256_hex(b"tampered")));
        assert!(!verify_sha256(b, "not-a-hash"));
    }

    #[test]
    fn atomic_swap_replaces_and_is_exec() {
        let dir = std::env::temp_dir().join(format!("ep-swap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("aikey-proxy");
        std::fs::write(&target, b"OLD-OSS-BINARY").unwrap();

        atomic_swap(&target, b"NEW-ENTERPRISE-BINARY").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW-ENTERPRISE-BINARY");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "swapped binary must be executable");
        }
        // No leftover temp file.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("enterprise-new"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
