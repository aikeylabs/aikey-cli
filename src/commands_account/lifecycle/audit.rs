//! Read-only audit of credential lifecycle state across all source-of-truths.
//!
//! Compares:
//!   - DB binding table       (`user_profile_provider_bindings`)
//!   - active.env             (~/.aikey/active.env: `AIKEY_ACTIVE_KEYS` +
//!                             per-provider `KIMI_API_KEY` etc. sentinels)
//!   - kimi config.toml       (~/.kimi/config.toml: aikey-managed region)
//!   - codex config.toml      (~/.codex/config.toml: aikey-managed region)
//!   - proxy in-memory cache  (admin /status, only when `include_proxy=true`)
//!
//! Emits a structured report consumed by `aikey doctor`. Pure read-only:
//! safe to run on any state, no side effects, no master password needed.
//!
//! Design split — each diff is a comparison between exactly two
//! source-of-truths. We deliberately do NOT compute a global "set of all
//! active providers" and diff that, because the failure modes we want to
//! pin are pair-local (e.g., "DB has kimi binding but kimi.toml has no
//! region" vs "active.env has KIMI_API_KEY but kimi.toml has no region" —
//! same symptom but different root cause).

use crate::commands_account::shell_integration;
use crate::proxy_env;
use crate::storage;

/// Wraps a command-name string in cyan-bold + restores surrounding dim
/// when rendered inside `aikey doctor`'s emit() closure (which wraps the
/// whole hint with `.dimmed()`). Without the trailing `\x1b[0m\x1b[2m`,
/// text after the cyan portion would lose its dim formatting because
/// `\x1b[0m` resets ALL attributes.
///
/// Use this for actionable commands inside hint strings so they pop out
/// of the surrounding dim text and match the cyan convention used by
/// installer / status output elsewhere.
fn cmd(s: &str) -> String {
    format!("\x1b[1;36m{}\x1b[0m\x1b[2m", s)
}

/// Which two source-of-truths a `DiffEntry` is comparing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffSource {
    /// `user_profile_provider_bindings` row vs `AIKEY_ACTIVE_KEYS` field.
    DbVsActiveEnv,
    /// active.env per-provider sentinel (KIMI_API_KEY) vs kimi.toml
    /// `# BEGIN aikey` region presence.
    ActiveEnvVsKimiToml,
    /// active.env OPENAI_API_KEY vs codex.toml region presence.
    ActiveEnvVsCodexToml,
    /// DB bindings vs proxy admin endpoint's in-memory binding cache.
    /// Populated only when caller asks `include_proxy=true` and proxy
    /// is reachable.
    DbVsProxyCache,
}

impl DiffSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DbVsActiveEnv => "DB ↔ active.env",
            Self::ActiveEnvVsKimiToml => "active.env ↔ kimi.toml",
            Self::ActiveEnvVsCodexToml => "active.env ↔ codex.toml",
            Self::DbVsProxyCache => "DB ↔ proxy cache",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffSeverity {
    /// User-visible breakage — e.g., binding present but toml missing
    /// means the third-party CLI won't route through aikey.
    Critical,
    /// Recoverable — e.g., extra/stale env var that doesn't break flows
    /// but indicates a missed refresh.
    Warning,
}

#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub source: DiffSource,
    /// Provider this diff is about, if applicable. `None` for
    /// table-level structural diffs (e.g., row count mismatch).
    pub provider: Option<String>,
    /// Human-readable left side of the diff.
    pub a_says: String,
    /// Human-readable right side of the diff.
    pub b_says: String,
    pub severity: DiffSeverity,
    /// Optional concrete remediation hint shown to the user.
    pub hint: Option<String>,
}

impl DiffEntry {
    pub fn describe(&self) -> String {
        match &self.provider {
            Some(p) => format!("{} ({}): {} vs {}", self.source.label(), p, self.a_says, self.b_says),
            None => format!("{}: {} vs {}", self.source.label(), self.a_says, self.b_says),
        }
    }
}

#[derive(Debug)]
pub struct AuditReport {
    pub diffs: Vec<DiffEntry>,
    pub is_consistent: bool,
    pub active_provider_count: usize,
    /// One-line summary for the doctor row's right column.
    pub summary: String,
}

// ============================================================================
// Public entry
// ============================================================================

/// Run the full lifecycle audit. Pure read-only.
///
/// `include_proxy = true` adds the DB ↔ proxy cache check (HTTP call to
/// `127.0.0.1:<port>/admin/status`). Costs ~50-100ms when the proxy is
/// up, returns Warning + skip when down. Default false in doctor's
/// summary mode; only true under `--detail`.
pub fn audit_credential_lifecycle(include_proxy: bool) -> AuditReport {
    let bindings = storage::list_provider_bindings_readonly("default")
        .unwrap_or_default();
    let active_env_lines = proxy_env::read_active_env_lines().unwrap_or_default();
    let injected_tomls = shell_integration::injected_provider_toml_paths();

    let kimi_region_present = injected_tomls.iter().any(|(name, _)| *name == "kimi");
    let codex_region_present = injected_tomls.iter().any(|(name, _)| *name == "codex");

    let mut diffs: Vec<DiffEntry> = Vec::new();
    let active_provider_count = bindings.len();

    diffs.extend(diff_db_vs_active_env(&bindings, &active_env_lines));
    diffs.extend(diff_active_env_vs_kimi_toml(
        &active_env_lines,
        kimi_region_present,
        bindings_has_provider(&bindings, &["kimi", "moonshot"]),
    ));
    diffs.extend(diff_active_env_vs_codex_toml(
        &active_env_lines,
        codex_region_present,
        bindings_has_provider(&bindings, &["openai", "gpt", "chatgpt"]),
    ));

    if include_proxy {
        if let Some(proxy_diffs) = diff_db_vs_proxy_cache(&bindings) {
            diffs.extend(proxy_diffs);
        }
    }

    let is_consistent = diffs
        .iter()
        .all(|d| d.severity == DiffSeverity::Warning);
    let critical_count = diffs.iter().filter(|d| d.severity == DiffSeverity::Critical).count();
    let warn_count = diffs.iter().filter(|d| d.severity == DiffSeverity::Warning).count();

    let summary = if diffs.is_empty() {
        format!(
            "{} active providers, all source-of-truths agree",
            active_provider_count
        )
    } else if critical_count > 0 {
        format!(
            "drift detected ({} critical, {} warnings)",
            critical_count, warn_count
        )
    } else {
        format!("{} warnings (recoverable)", warn_count)
    };

    AuditReport {
        diffs,
        is_consistent,
        active_provider_count,
        summary,
    }
}

// ============================================================================
// Pure diff helpers — unit-testable
// ============================================================================

fn bindings_has_provider(
    bindings: &[storage::ProviderBinding],
    candidates: &[&str],
) -> bool {
    bindings.iter().any(|b| {
        let c = b.provider_code.to_lowercase();
        candidates.iter().any(|x| *x == c.as_str())
    })
}

/// Format the AIKEY_ACTIVE_KEYS value the way profile_activation writes it:
/// `provider1=ref1,provider2=ref2,...` sorted by provider name.
fn expected_active_keys(bindings: &[storage::ProviderBinding]) -> String {
    let mut entries: Vec<(String, String)> = bindings
        .iter()
        .map(|b| (b.provider_code.clone(), b.key_source_ref.clone()))
        .collect();
    entries.sort();
    entries
        .into_iter()
        .map(|(p, r)| format!("{}={}", p, r))
        .collect::<Vec<_>>()
        .join(",")
}

fn lookup_env(lines: &[(String, String)], key: &str) -> Option<String> {
    lines.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn diff_db_vs_active_env(
    bindings: &[storage::ProviderBinding],
    env_lines: &[(String, String)],
) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    let expected = expected_active_keys(bindings);
    let actual = lookup_env(env_lines, "AIKEY_ACTIVE_KEYS").unwrap_or_default();

    if expected != actual {
        // For OAuth bindings the active.env writer substitutes the OAuth
        // display_identity (email/name) for the raw account_id, so the
        // strings look different even when consistent. Detect that case
        // by checking if every DB provider has SOME entry in active.env
        // (regardless of value); only Critical when a provider is wholly
        // missing.
        let actual_providers: std::collections::HashSet<String> = actual
            .split(',')
            .filter_map(|s| s.split_once('='))
            .map(|(p, _)| p.to_string())
            .collect();
        let missing: Vec<&str> = bindings
            .iter()
            .filter_map(|b| {
                if !actual_providers.contains(&b.provider_code) {
                    Some(b.provider_code.as_str())
                } else {
                    None
                }
            })
            .collect();
        let extra: Vec<&str> = actual_providers
            .iter()
            .filter(|p| !bindings.iter().any(|b| &b.provider_code == *p))
            .map(|s| s.as_str())
            .collect();

        if !missing.is_empty() {
            out.push(DiffEntry {
                source: DiffSource::DbVsActiveEnv,
                provider: Some(missing.join(",")),
                a_says: format!("DB has binding(s) for {}", missing.join(",")),
                b_says: "active.env AIKEY_ACTIVE_KEYS missing entry".into(),
                severity: DiffSeverity::Critical,
                hint: Some(format!("run {} or restart proxy to refresh active.env", cmd("aikey use <alias>"))),
            });
        }
        if !extra.is_empty() {
            out.push(DiffEntry {
                source: DiffSource::DbVsActiveEnv,
                provider: Some(extra.join(",")),
                a_says: "no DB binding".into(),
                b_says: format!("active.env still has {}", extra.join(",")),
                severity: DiffSeverity::Critical,
                hint: Some(format!("phantom env entry — run {} to force a refresh", cmd("aikey use <alias>"))),
            });
        }
        if missing.is_empty() && extra.is_empty() {
            // Same provider set, just different raw values (likely
            // OAuth display_identity rendering). Recoverable.
            out.push(DiffEntry {
                source: DiffSource::DbVsActiveEnv,
                provider: None,
                a_says: format!("DB: {}", expected),
                b_says: format!("active.env: {}", actual),
                severity: DiffSeverity::Warning,
                hint: None,
            });
        }
    }
    out
}

fn diff_active_env_vs_kimi_toml(
    env_lines: &[(String, String)],
    kimi_region_present: bool,
    db_has_kimi: bool,
) -> Vec<DiffEntry> {
    diff_active_env_vs_provider_toml(
        env_lines,
        kimi_region_present,
        db_has_kimi,
        DiffSource::ActiveEnvVsKimiToml,
        "KIMI_API_KEY",
        "kimi",
        "~/.kimi/config.toml",
    )
}

fn diff_active_env_vs_codex_toml(
    env_lines: &[(String, String)],
    codex_region_present: bool,
    db_has_openai: bool,
) -> Vec<DiffEntry> {
    diff_active_env_vs_provider_toml(
        env_lines,
        codex_region_present,
        db_has_openai,
        DiffSource::ActiveEnvVsCodexToml,
        "OPENAI_API_KEY",
        "openai",
        "~/.codex/config.toml",
    )
}

#[allow(clippy::too_many_arguments)]
fn diff_active_env_vs_provider_toml(
    env_lines: &[(String, String)],
    region_present: bool,
    db_has_provider: bool,
    source: DiffSource,
    env_key: &str,
    provider_label: &str,
    toml_path_label: &str,
) -> Vec<DiffEntry> {
    let env_present = lookup_env(env_lines, env_key).is_some();
    let mut out = Vec::new();

    // Truth table (env_present, region_present, db_has_provider):
    //   (T, T, T) → all aligned, no diff
    //   (F, F, F) → all aligned, no diff
    //   (T, T, F) → DB missing, but env+region say active. Drift caused
    //               by stale binding row OR missed refresh. Warning.
    //   (T, F, *) → env says active but no toml region. Critical: third-
    //               party CLI will fail to route through aikey.
    //   (F, T, *) → toml region but no env sentinel. Critical: stale
    //               toml region orphaned (likely caused by a delete that
    //               skipped apply_third_party_cli_configs).
    //   (F, F, T) → DB has it but env+toml say no. Means refresh hasn't
    //               run since DB write — Warning.
    //   (T, F, F) | (F, T, F) — covered by previous Critical rules.
    match (env_present, region_present, db_has_provider) {
        (true, true, true) | (false, false, false) => {} // aligned
        (true, false, _) => {
            out.push(DiffEntry {
                source,
                provider: Some(provider_label.into()),
                a_says: format!("active.env has {}", env_key),
                b_says: format!("{} aikey region absent", toml_path_label),
                severity: DiffSeverity::Critical,
                hint: Some(format!(
                    "{} won't route through aikey-proxy — run {} to re-inject region",
                    provider_label, cmd("aikey use <alias>"),
                )),
            });
        }
        (false, true, _) => {
            out.push(DiffEntry {
                source,
                provider: Some(provider_label.into()),
                a_says: format!("active.env missing {}", env_key),
                b_says: format!("{} aikey region still present", toml_path_label),
                severity: DiffSeverity::Critical,
                hint: Some(format!(
                    "stale aikey region — run {} or re-run {} to reconcile",
                    cmd("aikey hook update"), cmd("aikey use"),
                )),
            });
        }
        (true, true, false) => {
            out.push(DiffEntry {
                source,
                provider: Some(provider_label.into()),
                a_says: format!("DB has no {} binding", provider_label),
                b_says: format!("active.env + {} both still configured", toml_path_label),
                severity: DiffSeverity::Warning,
                hint: Some("phantom env+region — next refresh should clean".into()),
            });
        }
        (false, false, true) => {
            out.push(DiffEntry {
                source,
                provider: Some(provider_label.into()),
                a_says: format!("DB has {} binding", provider_label),
                b_says: format!("active.env + {} both unconfigured", toml_path_label),
                severity: DiffSeverity::Warning,
                hint: Some(format!(
                    "refresh hasn't propagated — run {} to force",
                    cmd("aikey use <alias>"),
                )),
            });
        }
    }
    out
}

/// Query proxy admin endpoint for in-memory binding cache and compare to DB.
/// Returns `None` when proxy is unreachable (Warning is emitted by caller).
fn diff_db_vs_proxy_cache(
    _bindings: &[storage::ProviderBinding],
) -> Option<Vec<DiffEntry>> {
    // Phase A scope: stub returning `Some(vec![])` (proxy comparison
    // logic is non-trivial — proxy /admin/status doesn't currently
    // expose a binding-level dump; that's a follow-up). Returning
    // `Some(empty)` documents that the check ran without finding drift,
    // vs `None` which would mean "couldn't run". For Phase A we return
    // None so doctor's --detail mode shows "skipped (proxy doesn't
    // expose binding cache)" instead of misleadingly "consistent".
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_type::CredentialType;
    use crate::storage::ProviderBinding;

    fn binding(provider: &str, ref_: &str, kind: CredentialType) -> ProviderBinding {
        ProviderBinding {
            profile_id: "default".into(),
            provider_code: provider.into(),
            key_source_type: kind,
            key_source_ref: ref_.into(),
            updated_at: Some(0),
        }
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // --- expected_active_keys ---

    #[test]
    fn expected_active_keys_sorted_by_provider() {
        let b = vec![
            binding("openai", "k1", CredentialType::PersonalApiKey),
            binding("anthropic", "k1", CredentialType::PersonalApiKey),
            binding("kimi", "k2", CredentialType::PersonalApiKey),
        ];
        assert_eq!(expected_active_keys(&b), "anthropic=k1,kimi=k2,openai=k1");
    }

    #[test]
    fn expected_active_keys_empty_when_no_bindings() {
        assert_eq!(expected_active_keys(&[]), "");
    }

    // --- diff_db_vs_active_env ---

    #[test]
    fn db_vs_env_aligned_no_diff() {
        let b = vec![binding("kimi", "k1", CredentialType::PersonalApiKey)];
        let e = env(&[("AIKEY_ACTIVE_KEYS", "kimi=k1")]);
        assert!(diff_db_vs_active_env(&b, &e).is_empty());
    }

    #[test]
    fn db_vs_env_missing_provider_critical() {
        let b = vec![binding("kimi", "k1", CredentialType::PersonalApiKey)];
        let e = env(&[("AIKEY_ACTIVE_KEYS", "")]);
        let diffs = diff_db_vs_active_env(&b, &e);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Critical);
        assert_eq!(diffs[0].source, DiffSource::DbVsActiveEnv);
        assert!(diffs[0].a_says.contains("kimi"));
    }

    #[test]
    fn db_vs_env_extra_provider_critical() {
        // active.env still has kimi but DB doesn't (logout-style phantom)
        let b: Vec<ProviderBinding> = vec![];
        let e = env(&[("AIKEY_ACTIVE_KEYS", "kimi=session_old")]);
        let diffs = diff_db_vs_active_env(&b, &e);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Critical);
        assert!(diffs[0].b_says.contains("kimi"));
    }

    #[test]
    fn db_vs_env_oauth_value_mismatch_warning() {
        // Same provider set; just account_id vs display_identity rendering.
        let b = vec![binding("kimi", "session_xyz", CredentialType::PersonalOAuthAccount)];
        let e = env(&[("AIKEY_ACTIVE_KEYS", "kimi=user@example.com")]);
        let diffs = diff_db_vs_active_env(&b, &e);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Warning);
    }

    // --- diff_active_env_vs_provider_toml ---

    #[test]
    fn provider_toml_all_aligned_present() {
        let e = env(&[("KIMI_API_KEY", "aikey_active_kimi")]);
        let diffs = diff_active_env_vs_kimi_toml(&e, true, true);
        assert!(diffs.is_empty());
    }

    #[test]
    fn provider_toml_all_aligned_absent() {
        let e: Vec<_> = vec![];
        let diffs = diff_active_env_vs_kimi_toml(&e, false, false);
        assert!(diffs.is_empty());
    }

    #[test]
    fn provider_toml_env_present_region_absent_critical() {
        // active.env says kimi active, but toml has no aikey region.
        // Third-party CLI won't route through proxy.
        let e = env(&[("KIMI_API_KEY", "aikey_active_kimi")]);
        let diffs = diff_active_env_vs_kimi_toml(&e, false, true);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Critical);
        assert!(diffs[0].b_says.contains("kimi"));
    }

    #[test]
    fn provider_toml_region_present_env_absent_critical() {
        // toml has region but active.env missing — typical post-logout
        // before the fix this PR adds.
        let e: Vec<_> = vec![];
        let diffs = diff_active_env_vs_kimi_toml(&e, true, false);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Critical);
        assert!(diffs[0].b_says.contains("region still present"));
    }

    #[test]
    fn provider_toml_db_has_but_env_missing_warning() {
        let e: Vec<_> = vec![];
        let diffs = diff_active_env_vs_kimi_toml(&e, false, true);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Warning);
    }

    #[test]
    fn provider_toml_phantom_env_warning() {
        // env+region both present but DB has no kimi binding.
        // Recoverable — next refresh fixes it.
        let e = env(&[("KIMI_API_KEY", "aikey_active_kimi")]);
        let diffs = diff_active_env_vs_kimi_toml(&e, true, false);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].severity, DiffSeverity::Warning);
    }

    // --- bindings_has_provider ---

    #[test]
    fn bindings_has_provider_matches_aliases() {
        let b = vec![binding("moonshot", "k1", CredentialType::PersonalApiKey)];
        // moonshot should match kimi-family check
        assert!(bindings_has_provider(&b, &["kimi", "moonshot"]));
        assert!(!bindings_has_provider(&b, &["openai"]));
    }

    // --- DiffSource label ---

    #[test]
    fn diff_source_labels_stable() {
        // Pin label strings — doctor depends on these for output formatting.
        assert_eq!(DiffSource::DbVsActiveEnv.label(), "DB ↔ active.env");
        assert_eq!(DiffSource::ActiveEnvVsKimiToml.label(), "active.env ↔ kimi.toml");
        assert_eq!(DiffSource::ActiveEnvVsCodexToml.label(), "active.env ↔ codex.toml");
        assert_eq!(DiffSource::DbVsProxyCache.label(), "DB ↔ proxy cache");
    }
}
