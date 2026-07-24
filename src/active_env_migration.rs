//! `~/.aikey/active.env` legacy-contract auto-migration.
//!
//! After the prefix rename, old `active.env` files (with `aikey_vk_<...>`
//! or `aikey_personal_<alias>` sentinel forms) must be regenerated with the
//! new `aikey_active_<provider>` per-provider sentinels. Otherwise the new
//! proxy returns `TOKEN_INVALID` for every request from CLIs launched in
//! shells that source the old env (claude/codex/kimi/etc.).
//!
//! Two trigger points (both must work):
//!   - **Installer hook**: end of install/upgrade scripts calls
//!     `aikey _refresh-active-env --if-legacy` (no vault password needed —
//!     `user_profile_provider_bindings` table is not encrypted).
//!   - **CLI main entry safety net**: every `aikey <subcommand>` invocation
//!     does a lightweight check at dispatch start; if the on-disk file
//!     contains legacy form, regenerates it. Covers the case where the
//!     installer hook didn't run (manual binary swap, machine-to-machine
//!     copy of `~/.aikey`, etc.).
//!
//! Failure策略 (per spec §5):
//!   - Backup before write: `~/.aikey/active.env.bak.<unix_ts>`. Keep latest 3.
//!   - Installer hook failure → warn, don't block install. CLI safety net
//!     will retry.
//!   - CLI safety net failure → warn, don't block the current command.
//!   - Backup-itself failure → return Err (disk full / FS read-only — user
//!     environment problem, not safe to continue).
//!   - No bindings present → no-op (nothing to follow).
//!
//! Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §5

use std::path::PathBuf;

/// True if `active.env` or its Windows `active.env.flat` mirror contains a
/// legacy contract that must be regenerated. Besides obsolete token prefixes,
/// this includes the short-lived
/// Mock Provider client namespace. Mock is an upstream supplier, so its active
/// credentials must be projected through the Anthropic/OpenAI client routes;
/// keeping `AIKEY_MOCK_PROVIDER_*`, `/mock`, or the old route side channel in
/// the shell environment would bypass that model after a binary upgrade.
///
/// Returns false on any read error (worst case: caller doesn't refresh; the
/// safety net runs again on the next invocation).
pub fn active_env_has_legacy_form() -> bool {
    let path = match crate::proxy_env::active_env_path() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let flat_path = path.with_extension("env.flat");
    let has_legacy = [&path, &flat_path].into_iter().any(|candidate| {
        std::fs::read_to_string(candidate)
            .map(|contents| contents_have_legacy_form(&contents))
            .unwrap_or(false)
    });
    has_legacy
}

/// Pure logic — exposed for unit testing.
///
/// Legacy forms detected:
///   - `aikey_vk_*`        — old prefix entirely
///   - `aikey_personal_<non-64-hex>` — old sentinel form (alias / account_id
///     suffix). NEW personal bearers are 64-hex; if a sentinel-form leaks
///     into active.env it's stale.
///   - `AIKEY_MOCK_PROVIDER_TOKEN` / `AIKEY_MOCK_PROVIDER_BASE_URL` — obsolete
///     provider-keyed client environment namespace.
///   - `AIKEY_ACTIVE_CLIENT_ROUTES` — obsolete projection side channel that
///     encoded `client_route=provider` outside the binding row.
///
/// New forms passed:
///   - `aikey_active_<provider>` — current sentinel
///   - `aikey_personal_<64-hex>` — current bearer (rare in active.env but
///     not a legacy form — shouldn't trigger migration)
///   - `aikey_team_<vk_id>` — current team static bearer
fn contents_have_legacy_form(contents: &str) -> bool {
    if contents.contains("aikey_vk_")
        || [
            "AIKEY_MOCK_PROVIDER_TOKEN",
            "AIKEY_MOCK_PROVIDER_BASE_URL",
            "AIKEY_ACTIVE_CLIENT_ROUTES",
        ]
        .iter()
        .any(|name| {
            contents
                .lines()
                .any(|line| line_assigns_env_var(line, name))
        })
    {
        return true;
    }
    // Look for `aikey_personal_*` followed by suffix that's NOT exactly
    // 64 lowercase hex chars (= legacy sentinel form, not new bearer).
    for line in contents.lines() {
        if let Some(idx) = line.find("aikey_personal_") {
            let after = &line[idx + "aikey_personal_".len()..];
            // Take the suffix until a quote/space/end — most env vars use
            // double-quote terminator, but bare KEY=VALUE format may not.
            let suffix: String = after
                .chars()
                .take_while(|c| !matches!(c, '"' | '\'' | ' ' | '\t' | '\n'))
                .collect();
            if !is_strict_personal_bearer_suffix(&suffix) {
                return true;
            }
        }
    }
    false
}

// The current renderer deliberately emits `unset OLD_VAR` cleanup lines so a
// shell drops obsolete values inherited from its parent. Those lines are the
// opposite of legacy configuration and must never re-trigger migration. Both
// active.env (`export NAME=...`) and active.env.flat (`NAME=...`) are covered.
fn line_assigns_env_var(line: &str, name: &str) -> bool {
    let line = line.trim_start();
    line.strip_prefix("export ")
        .unwrap_or(line)
        .starts_with(&format!("{}=", name))
}

/// True iff `s` is exactly 64 lowercase hex chars — the strict form for
/// `aikey_personal_<...>` bearer post-rename.
fn is_strict_personal_bearer_suffix(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// Backup the current active.env to `active.env.bak.<unix_ts>` and prune
/// older backups so only the latest 3 remain.
///
/// Returns Ok(Some(backup_path)) on success, Ok(None) if no current file
/// to backup, Err(_) on backup failure (caller should NOT proceed with
/// rewrite — env state is unsafe to mutate without a recovery path).
pub fn backup_active_env() -> Result<Option<PathBuf>, String> {
    let current = match crate::proxy_env::active_env_path() {
        Ok(p) => p,
        Err(e) => return Err(format!("active_env_path: {}", e)),
    };
    if !current.exists() {
        return Ok(None);
    }

    let parent = current
        .parent()
        .ok_or_else(|| "active.env path has no parent dir".to_string())?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_path = parent.join(format!("active.env.bak.{}", ts));

    std::fs::copy(&current, &backup_path).map_err(|e| {
        format!(
            "backup copy failed ({} → {}): {}",
            current.display(),
            backup_path.display(),
            e
        )
    })?;

    // Best-effort prune: keep latest 3 backups. Failure here is non-fatal
    // (we already backed up the current file successfully).
    let _ = prune_old_backups(parent, 3);

    Ok(Some(backup_path))
}

fn prune_old_backups(dir: &std::path::Path, keep: usize) -> std::io::Result<()> {
    let mut backups: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().to_string();
            if !name.starts_with("active.env.bak.") {
                return None;
            }
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((mtime, path))
        })
        .collect();

    if backups.len() <= keep {
        return Ok(());
    }
    backups.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    for (_, path) in backups.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// Run a refresh of `~/.aikey/active.env`.
///
/// Behavior:
///   - If `if_legacy` is true and no legacy form is detected → no-op (Ok).
///   - Otherwise: best-effort refresh the employee-facing cluster route,
///     backup, then call `profile_activation::refresh_implicit_profile_activation`.
///   - Backup failure → Err (don't proceed with rewrite).
///   - Refresh failure (binding read / file write) → Err.
///   - No bindings → refresh writes an empty-but-marked active.env (per
///     existing `refresh_implicit_profile_activation` behavior; this is fine
///     and represents "no active key set yet").
pub fn refresh_active_env(if_legacy: bool) -> Result<RefreshOutcome, String> {
    if if_legacy && !active_env_has_legacy_form() {
        return Ok(RefreshOutcome::NoLegacyDetected);
    }

    // No vault yet (fresh install before any `aikey add` / `aikey login`) →
    // there are no bindings to read; refresh would fail with a vault-open
    // error. Per spec failure策略 ("provider 推不出 → no-op"), this is not
    // an error — the user just has nothing to migrate to.
    //
    // Why route through `storage::get_vault_path()` instead of building the
    // path ad-hoc: that function honors `AK_VAULT_PATH` / `AK_STORAGE_PATH`
    // env overrides (CI sandbox, migration tests, custom deployments) — a
    // hard-coded `~/.aikey/data/vault.db` would mis-detect "no vault" in
    // those environments and silently skip the active.env rewrite, leaving
    // legacy `aikey_vk_*` / `aikey_personal_<alias>` tokens in the file.
    // Closes 2026-04-29 third-party review #4 finding [中].
    let vault_path =
        crate::storage::get_vault_path().map_err(|e| format!("resolve vault path: {}", e))?;
    if !vault_path.exists() {
        return Ok(RefreshOutcome::NoBindingsToFollow);
    }

    // The route sidecar is deliberately independent from encrypted key
    // material, so refreshing active.env must not require the vault password.
    // Re-resolve it here before rendering: cluster topology and the
    // employee-facing ingress authority can change across an upgrade while
    // the selected bindings stay the same. On auth/transport failure the
    // resolver preserves the last-known-good sidecar, keeping this operation
    // best-effort and backward compatible.
    let _ = crate::commands_account::try_resolve_and_persist_cluster_node();

    let backup = backup_active_env().map_err(|e| format!("backup before refresh failed: {}", e))?;

    crate::profile_activation::refresh_implicit_profile_activation()
        .map_err(|e| format!("profile activation refresh failed: {}", e))?;

    Ok(RefreshOutcome::Refreshed { backup })
}

#[derive(Debug)]
pub enum RefreshOutcome {
    /// `--if-legacy` was set and no legacy-form token was detected. No-op.
    NoLegacyDetected,
    /// Vault DB doesn't exist yet (fresh install with no `aikey add` / `aikey login`).
    /// Nothing to migrate to. Subsequent `aikey use <key>` will write the new
    /// sentinel naturally. No-op.
    NoBindingsToFollow,
    /// active.env was rewritten with new per-provider sentinels. `backup` is
    /// the path to the prior file (if one existed).
    Refreshed { backup: Option<PathBuf> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_legacy_aikey_vk_in_contents() {
        let env = r#"
export ANTHROPIC_AUTH_TOKEN="aikey_vk_my-team-key"
export AIKEY_ACTIVE_KEYS="anthropic=my-team-key"
"#;
        assert!(contents_have_legacy_form(env));
    }

    #[test]
    fn detects_legacy_personal_alias_form() {
        // Old sentinel: aikey_personal_<alias-with-hyphens>
        let env = r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_my-claude-account""#;
        assert!(contents_have_legacy_form(env));
    }

    #[test]
    fn detects_legacy_personal_short_hex_form() {
        // Old form variant: 32-hex (early v1.0.4 random tokens)
        let env =
            r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_0123456789abcdef0123456789abcdef""#;
        assert!(contents_have_legacy_form(env));
    }

    #[test]
    fn detects_obsolete_mock_provider_client_namespace() {
        let env = r#"
export AIKEY_MOCK_PROVIDER_TOKEN='aikey_team_example'
export AIKEY_MOCK_PROVIDER_BASE_URL='http://node2:27200/mock'
export ANTHROPIC_API_KEY='aikey_team_example'
export ANTHROPIC_BASE_URL='http://node2:27200/mock'
"#;
        assert!(contents_have_legacy_form(env));
    }

    #[test]
    fn detects_obsolete_client_route_projection_side_channel() {
        let env = r#"export AIKEY_ACTIVE_CLIENT_ROUTES='anthropic=mock'"#;
        assert!(contents_have_legacy_form(env));
    }

    #[test]
    fn ignores_obsolete_namespace_cleanup_lines() {
        let env = r#"
unset AIKEY_MOCK_PROVIDER_TOKEN 2>/dev/null
unset AIKEY_MOCK_PROVIDER_BASE_URL 2>/dev/null
unset AIKEY_ACTIVE_CLIENT_ROUTES 2>/dev/null
"#;
        assert!(!contents_have_legacy_form(env));
    }

    #[test]
    fn passes_new_active_sentinel() {
        let env = r#"
export ANTHROPIC_AUTH_TOKEN="aikey_active_anthropic"
export OPENAI_API_KEY="aikey_active_openai"
"#;
        assert!(
            !contents_have_legacy_form(env),
            "new active sentinel must NOT trigger migration"
        );
    }

    #[test]
    fn passes_new_personal_bearer_strict_form() {
        // Should NOT trigger — this IS the legitimate new bearer form.
        let env = r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#;
        assert!(
            !contents_have_legacy_form(env),
            "strict aikey_personal_<64-hex> bearer is legitimate, not legacy"
        );
    }

    #[test]
    fn passes_new_team_token() {
        let env = r#"export ANTHROPIC_AUTH_TOKEN="aikey_team_acc-1234abc""#;
        assert!(
            !contents_have_legacy_form(env),
            "aikey_team_<vk_id> is current form"
        );
    }

    #[test]
    fn passes_empty_or_unset_active_env() {
        assert!(!contents_have_legacy_form(""));
        assert!(!contents_have_legacy_form(
            "# aikey active key — auto-generated\n"
        ));
    }

    #[test]
    fn detects_uppercase_hex_personal_as_legacy() {
        // Uppercase hex isn't strict form — proxy's isTier1Personal would
        // 401 it. Treat as legacy to force regeneration in lowercase.
        let env = r#"export ANTHROPIC_AUTH_TOKEN="aikey_personal_ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789""#;
        assert!(
            contents_have_legacy_form(env),
            "uppercase hex is not strict form; should trigger regeneration"
        );
    }

    #[test]
    fn is_strict_suffix_only_lowercase_hex() {
        assert!(is_strict_personal_bearer_suffix(&"0".repeat(64)));
        assert!(is_strict_personal_bearer_suffix(
            &"abcdef0123456789".repeat(4)
        ));
        assert!(!is_strict_personal_bearer_suffix(&"0".repeat(63))); // too short
        assert!(!is_strict_personal_bearer_suffix(&"0".repeat(65))); // too long
        assert!(!is_strict_personal_bearer_suffix(&"A".repeat(64))); // uppercase
        assert!(!is_strict_personal_bearer_suffix(&"g".repeat(64))); // non-hex
        assert!(!is_strict_personal_bearer_suffix("alias-with-hyphens"));
        assert!(!is_strict_personal_bearer_suffix(""));
    }
}
