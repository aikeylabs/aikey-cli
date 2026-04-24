//! Connectivity test suite — unified pipeline for `aikey add` / `aikey
//! doctor` / `aikey test` / `aikey test <alias>`.
//!
//! Submodules:
//!   - [`targets`]: source resolvers (bindings / alias / new-key) → `Vec<TestTarget>`
//!   - [`runtime`]: low-level probe primitives + suite runner + table renderer
//!
//! Public API is flattened at this module level via `pub use`, so callers
//! depend on `crate::connectivity::*` regardless of which submodule an item
//! actually lives in.

use secrecy::SecretString;

// Submodule declarations + flatten re-export.  The factories defined in this
// file reference `default_base_url` from `runtime`, so we also bring it into
// local scope with a plain `use`.
pub mod targets;
pub mod runtime;

// Why `#[allow(unused_imports)]`: `main.rs` declares `mod connectivity;` with
// `#[allow(dead_code)]` (needed because main.rs re-declares crate-shared
// modules), which makes the binary-crate view of these re-exports appear
// unused even though the library crate exposes them as public API. The
// lib-crate usage path (`crate::connectivity::run_connectivity_suite` etc.)
// *is* the intended API surface — the lint is a false positive in this
// setup. Without this allow, every build emits 7 warnings.
#[allow(unused_imports)]
pub use targets::{
    target_from_binding,
    targets_from_active_bindings,
    targets_from_alias,
    targets_from_new_personal_key,
};
#[allow(unused_imports)]
pub use runtime::{
    ConnectivityResult, ProxyProbeResult,
    provider_defaults, default_base_url,
    tcp_ping,
    test_provider_connectivity, test_proxy_connectivity,
    api_status_hint, chat_status_hint, proxy_status_hint,
    run_connectivity_suite, render_cannot_test_block,
};

// (pub use above brings default_base_url / ConnectivityResult / etc. into
// local scope as a side effect, so the factories + SuiteOutcome compile.)

// ─────────────────────────────────────────────────────────────────────────────
// Connectivity test — unified data model (2026-04-21)
//
// Before the unification, `aikey add` / `aikey doctor` / `aikey test` each
// rendered the ping/API/chat table with their own loop, each carrying a
// slightly different subset of credential types. Team (ManagedVirtualKey)
// bindings were silently dropped everywhere; OAuth was only wired into
// doctor. This drift matches the 2026-04-20 "silent state mismatch" bug
// class — see workflow/CI/IDE/practice/state-mutation-and-error-surface.md
// §Rule A.
//
// The types below describe what we test and how it's rendered. All four
// commands now go through the same pipeline:
//
//   targets_from_<source>(…)  →  Vec<TestTarget>
//                             →  run_connectivity_suite(targets, opts)
//                             →  SuiteOutcome
//
// The low-level `test_provider_connectivity` primitive is untouched — its
// ping→API→chat short-circuit (ping fail skips API; API fail skips chat —
// critical for not getting the key banned by repeated unauth attempts) is
// already correct and shared.
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of credential a test target carries. Drives bearer format, URL
/// destination, and display suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    /// Personal API key stored in the vault. Tested by decrypting the key
    /// locally and hitting the real provider directly.
    PersonalApi,
    /// Team-managed virtual key. Tested via the local proxy with a sentinel
    /// bearer (`aikey_vk_<virtual_key_id>`); the proxy injects the real
    /// provider credential on forward.
    ManagedTeam,
    /// Personal OAuth account. Tested via the local proxy with a sentinel
    /// bearer (`aikey_personal_<account_id>`); the proxy refreshes tokens and
    /// attaches provider-specific persona headers on forward.
    OAuth,
}

impl CredentialKind {
    /// Human suffix appended to `provider_code` in table rows.
    /// Empty for personal keys so the common case stays uncluttered.
    pub fn display_suffix(self) -> &'static str {
        match self {
            CredentialKind::PersonalApi => "",
            CredentialKind::ManagedTeam => " (team)",
            CredentialKind::OAuth       => " (oauth)",
        }
    }

    /// Post-plan-D (2026-04-22) all three credential kinds route through
    /// the local proxy — personal via alias sentinel, team via vk sentinel,
    /// OAuth via account sentinel. Kept as a function in case a future
    /// kind reintroduces a direct path.
    pub fn via_proxy(self) -> bool { true }
}

/// One (provider, URL, bearer) triple ready for `test_provider_connectivity`.
///
/// **Invariant**: `provider_code` is always the **canonical** code
/// (`"anthropic"` / `"openai"` / `"kimi"`), never the broker vocabulary
/// (`"claude"` / `"codex"`). To uphold this, every construction site must
/// go through one of three factories — `personal_target` / `team_target` /
/// `oauth_target` — which encapsulate URL/bearer/kind assignment and (for
/// OAuth) the broker-to-canonical mapping. See the 2026-04-21 unification
/// bugfix record for the incident that motivated this invariant.
///
/// `base_url` is either the real provider URL (PersonalApi) or
/// `http://127.0.0.1:<proxy_port>/<prefix>` (ManagedTeam / OAuth). The
/// factories decide — runners do not.
#[derive(Clone, Debug)]
pub struct TestTarget {
    pub provider_code: String,
    pub base_url:      String,
    pub bearer:        String,
    pub kind:          CredentialKind,
    /// Reference to the source row: vault alias, virtual_key_id, or
    /// provider_account_id. Used for JSON payloads and error messages;
    /// never printed as-is in the table (row shows provider + kind suffix).
    pub source_ref:    String,
}

impl TestTarget {
    /// "kimi" / "anthropic (oauth)" / "openai (team)" — the table label.
    pub fn display_label(&self) -> String {
        format!("{}{}", self.provider_code, self.kind.display_suffix())
    }
}

// ---------------------------------------------------------------------------
// TestTarget factories — the **only** sanctioned construction path.
//
// All four resolvers (`target_from_binding`, `targets_from_active_bindings`,
// `targets_from_alias`, `targets_from_new_personal_key`) route through these
// three fns so that:
//   1. URL / bearer / kind assignment lives in one place per credential
//      type (no drift between resolvers).
//   2. OAuth's broker-to-canonical mapping happens exactly once, at the
//      doorway where raw `acct.provider` becomes `TestTarget.provider_code`.
// ---------------------------------------------------------------------------

/// Build a PersonalApi target routed through the local proxy using the
/// `aikey_personal_alias_<alias>` sentinel bearer.
///
/// Plan D (2026-04-22): CLI never touches plaintext. Proxy already holds
/// the vault derived key from its own startup and decrypts on demand when
/// it sees the sentinel bearer. Per-entry custom base URLs are respected
/// server-side via `GetPersonalKeyByAlias`.
pub fn personal_target(
    source_ref: &str,
    provider_code: &str,
    proxy_port: u16,
) -> TestTarget {
    let prefix = crate::commands_account::provider_proxy_prefix_pub(provider_code);
    TestTarget {
        provider_code: provider_code.to_string(),
        base_url:      format!("http://127.0.0.1:{}/{}", proxy_port, prefix),
        bearer:        format!("aikey_personal_alias_{}", source_ref),
        kind:          CredentialKind::PersonalApi,
        source_ref:    source_ref.to_string(),
    }
}

/// PersonalApi target hitting upstream directly with plaintext. **Only for
/// the `aikey add` pre-save probe** — the alias row doesn't exist in the
/// vault yet, so the sentinel route would 503. The only legitimate caller
/// is `targets_from_new_personal_key`.
pub fn personal_target_direct(
    source_ref: &str,
    plaintext: &str,
    provider_code: &str,
    base_url_override: Option<&str>,
) -> TestTarget {
    let base_url = base_url_override
        .map(str::to_string)
        .or_else(|| default_base_url(provider_code).map(str::to_string))
        .unwrap_or_else(|| "https://unknown".to_string());
    TestTarget {
        provider_code: provider_code.to_string(),
        base_url,
        bearer:        plaintext.trim().to_string(),
        kind:          CredentialKind::PersonalApi,
        source_ref:    source_ref.to_string(),
    }
}

/// Build a ManagedTeam target: `aikey_vk_<id>` sentinel bearer, local-proxy URL.
pub fn team_target(
    virtual_key_id: &str,
    provider_code: &str,
    proxy_port: u16,
) -> TestTarget {
    let prefix = crate::commands_account::provider_proxy_prefix_pub(provider_code);
    TestTarget {
        provider_code: provider_code.to_string(),
        base_url:      format!("http://127.0.0.1:{}/{}", proxy_port, prefix),
        bearer:        format!("aikey_vk_{}", virtual_key_id),
        kind:          CredentialKind::ManagedTeam,
        source_ref:    virtual_key_id.to_string(),
    }
}

/// Build an OAuth target: `aikey_personal_<id>` sentinel bearer, local-proxy URL.
///
/// `raw_provider` may be the broker vocabulary (`"claude"` / `"codex"`); this
/// factory canonicalizes internally so the resulting `provider_code` field
/// is always `"anthropic"` / `"openai"` / `"kimi"` / etc. Single chokepoint
/// that keeps the `TestTarget.provider_code` canonical invariant honest.
pub fn oauth_target(
    account_id: &str,
    raw_provider: &str,
    proxy_port: u16,
) -> TestTarget {
    let provider = crate::commands_account::oauth_provider_to_canonical(raw_provider)
        .to_string();
    let prefix = crate::commands_account::provider_proxy_prefix_pub(&provider);
    TestTarget {
        provider_code: provider,
        base_url:      format!("http://127.0.0.1:{}/{}", proxy_port, prefix),
        bearer:        format!("aikey_personal_{}", account_id),
        kind:          CredentialKind::OAuth,
        source_ref:    account_id.to_string(),
    }
}

/// Reasons a TestTarget could not be constructed from a source.
///
/// These are *not* skips — each variant is a concrete, user-actionable
/// explanation ("proxy isn't running, start it"; "vault password needed but
/// not provided"; "team key hasn't been delivered yet"). The suite prints
/// them in a dedicated "cannot test" section rather than silently dropping
/// the row.
#[derive(Clone, Debug)]
pub enum BuildTargetError {
    /// Team/OAuth target requires the proxy but it is not running.
    ProxyNotRunning { label: String },
    /// Personal key exists but the vault master password is unavailable
    /// (non-interactive mode without session cache).
    PasswordRequired { alias: String },
    /// Personal key exists in vault but decryption failed (wrong password).
    DecryptFailed { alias: String, detail: String },
    /// Team virtual key is assigned to the account but the encrypted key
    /// material has not reached the local cache yet — run `aikey key sync`.
    TeamKeyNotDelivered { virtual_key_id: String, display: String },
    /// OAuth account is registered but currently in a non-usable state
    /// (`reauth_required` / `subscription_required` / etc.). Re-login.
    OAuthUnhealthy { account: String, status: String },
    /// Catch-all for unexpected DB/lookup failures.
    Unknown { label: String, detail: String },
}

impl BuildTargetError {
    /// Short label for the "cannot test" table ("anthropic (oauth)" etc).
    pub fn label(&self) -> &str {
        match self {
            BuildTargetError::ProxyNotRunning { label }            => label,
            BuildTargetError::PasswordRequired { alias }           => alias,
            BuildTargetError::DecryptFailed { alias, .. }          => alias,
            BuildTargetError::TeamKeyNotDelivered { display, .. }  => display,
            BuildTargetError::OAuthUnhealthy { account, .. }       => account,
            BuildTargetError::Unknown { label, .. }                => label,
        }
    }

    /// One-line reason + hint for display beneath the suite table.
    pub fn reason(&self) -> String {
        match self {
            BuildTargetError::ProxyNotRunning { .. } =>
                "proxy required — run `aikey proxy start`".to_string(),
            BuildTargetError::PasswordRequired { .. } =>
                "vault password needed — rerun this command in an interactive terminal".to_string(),
            BuildTargetError::DecryptFailed { detail, .. } =>
                format!("decrypt failed: {}", detail),
            BuildTargetError::TeamKeyNotDelivered { virtual_key_id, .. } =>
                format!("team key not yet delivered ({}) — run `aikey key sync`", virtual_key_id),
            BuildTargetError::OAuthUnhealthy { status, .. } =>
                format!("OAuth status '{}' — run `aikey auth login <provider>`", status),
            BuildTargetError::Unknown { detail, .. } => detail.clone(),
        }
    }
}

/// Options controlling suite behaviour. Each callsite tweaks only what it
/// needs; the defaults are tuned for `aikey test` (no alias).
pub struct SuiteOptions {
    /// Append a proxy-routing row at the bottom. True for add/doctor/test;
    /// false for `test <alias>` (single-key mode).
    pub show_proxy_row: bool,
    /// Optional header line ("🔌 Connectivity Test" for doctor; None elsewhere).
    pub header_label: Option<&'static str>,
    /// Vault master password — required to decrypt PersonalApi bindings.
    /// None means personal bindings will surface as PasswordRequired errors
    /// in the "cannot test" section rather than being tested.
    pub password: Option<SecretString>,
    pub proxy_port: u16,
}

/// Aggregate outcome of one suite run.
pub struct SuiteOutcome {
    /// One entry per tested target, in the same order as inputs.
    pub rows: Vec<(TestTarget, ConnectivityResult)>,
    /// Proxy-row result if `show_proxy_row` was on and a representative
    /// provider existed.
    pub proxy: Option<ProxyProbeResult>,
    /// Targets we could not construct — printed in the "cannot test" block.
    pub build_errors: Vec<BuildTargetError>,
    /// True if any row's chat probe returned 2xx. Drives `aikey add`'s
    /// "Add anyway? [y/N]" prompt.
    pub any_chat_ok: bool,
    /// JSON payload for `--json` mode; empty in interactive mode.
    pub json_results: Vec<serde_json::Value>,
}
#[cfg(test)]
mod connectivity_suite_tests {
    use super::*;

    #[test]
    fn credential_kind_display_suffixes() {
        assert_eq!(CredentialKind::PersonalApi.display_suffix(), "");
        assert_eq!(CredentialKind::ManagedTeam.display_suffix(), " (team)");
        assert_eq!(CredentialKind::OAuth.display_suffix(), " (oauth)");
    }

    #[test]
    fn credential_kind_via_proxy_all_true_after_plan_d() {
        // Plan D (2026-04-22): personal keys now route through the local
        // proxy using the aikey_personal_alias_<alias> sentinel, matching
        // how team and OAuth already worked. `via_proxy()` is `true` for
        // every variant — pinned so a future refactor can't silently
        // reintroduce a direct-upstream path for any kind.
        assert!(CredentialKind::PersonalApi.via_proxy(),
            "personal keys now route via proxy (aikey_personal_alias_ sentinel)");
        assert!(CredentialKind::ManagedTeam.via_proxy(),
            "team keys route via proxy so the sentinel gets swapped for real credential");
        assert!(CredentialKind::OAuth.via_proxy(),
            "OAuth routes via proxy so token refresh + persona headers apply");
    }

    #[test]
    fn test_target_display_label_shapes() {
        let personal = TestTarget {
            provider_code: "kimi".into(),
            base_url:      "https://api.kimi.com/coding/v1".into(),
            bearer:        "sk-redacted".into(),
            kind:          CredentialKind::PersonalApi,
            source_ref:    "kimi-local".into(),
        };
        assert_eq!(personal.display_label(), "kimi",
            "personal keys: just the provider code, no suffix");

        let team = TestTarget {
            kind: CredentialKind::ManagedTeam,
            ..personal.clone()
        };
        assert_eq!(team.display_label(), "kimi (team)");

        let oauth = TestTarget {
            kind: CredentialKind::OAuth,
            ..personal.clone()
        };
        assert_eq!(oauth.display_label(), "kimi (oauth)");
    }

    // ── targets_from_new_personal_key ────────────────────────────────────
    //
    // Pure function — no storage/proxy dependencies. Each selected provider
    // produces one target with the plaintext bearer + default base URL.
    //
    // Why verify explicitly: this is the entry point `aikey add` takes.
    // A regression here makes the post-add connectivity probe test against
    // the wrong URL or with the wrong bearer — silent data-plane breakage.

    #[test]
    fn new_personal_key_single_provider_uses_default_base_url() {
        let targets = targets_from_new_personal_key(
            "my-kimi",
            "  sk-plaintext  ", // whitespace trimmed by builder
            &["kimi".to_string()],
            None,
        );
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        assert_eq!(t.provider_code, "kimi");
        assert_eq!(t.bearer, "sk-plaintext", "bearer must be trimmed before probe");
        assert_eq!(t.kind, CredentialKind::PersonalApi);
        assert_eq!(t.source_ref, "my-kimi");
        assert!(t.base_url.starts_with("https://api.kimi.com"),
            "default base URL for kimi expected, got {:?}", t.base_url);
    }

    #[test]
    fn new_personal_key_override_url_beats_default() {
        let targets = targets_from_new_personal_key(
            "alias",
            "sk-x",
            &["kimi".to_string()],
            Some("https://example.corp/proxy"),
        );
        assert_eq!(targets[0].base_url, "https://example.corp/proxy",
            "caller-supplied override must win over provider default");
    }

    #[test]
    fn new_personal_key_multi_provider_fans_out() {
        let targets = targets_from_new_personal_key(
            "multi",
            "sk-y",
            &["openai".into(), "anthropic".into(), "kimi".into()],
            None,
        );
        assert_eq!(targets.len(), 3,
            "one target per selected provider — no dedup, no merge");
        let providers: Vec<&str> = targets.iter().map(|t| t.provider_code.as_str()).collect();
        assert_eq!(providers, vec!["openai", "anthropic", "kimi"],
            "target order must mirror caller input — stable for UX");
    }

    #[test]
    fn new_personal_key_unknown_provider_falls_back_to_unknown_url() {
        let targets = targets_from_new_personal_key(
            "alias",
            "sk-z",
            &["completely-fake-provider-that-nobody-would-add".into()],
            None,
        );
        assert_eq!(targets.len(), 1);
        // The suite will report ping fail on this URL, but the target still
        // gets built — caller decides whether to surface as error.
        assert!(targets[0].base_url.starts_with("https://"),
            "unknown provider still gets a well-formed URL (not an empty string)");
    }

    // ── BuildTargetError messages ────────────────────────────────────────
    //
    // Each variant maps to a user-facing one-liner in the "cannot test" block.
    // Pinning these forces future edits to stay actionable (not generic).

    #[test]
    fn build_target_error_reasons_are_actionable() {
        let e = BuildTargetError::ProxyNotRunning { label: "kimi (team)".into() };
        assert!(e.reason().contains("aikey proxy start"),
            "ProxyNotRunning must tell user exactly what to run, got: {:?}", e.reason());

        let e = BuildTargetError::TeamKeyNotDelivered {
            virtual_key_id: "vk_abc".into(),
            display:        "alice-key".into(),
        };
        assert!(e.reason().contains("aikey key sync"),
            "team-key-not-delivered must reference the sync command: {:?}", e.reason());

        let e = BuildTargetError::OAuthUnhealthy {
            account: "alice@example.com".into(),
            status:  "reauth_required".into(),
        };
        assert!(e.reason().contains("aikey auth login"),
            "OAuth unhealthy must point at re-login: {:?}", e.reason());
    }

    #[test]
    fn build_target_error_label_matches_kind() {
        // Labels feed the "Cannot test" table's first column. Each variant
        // must produce a non-empty label so the table doesn't render blank
        // rows.
        for e in [
            BuildTargetError::ProxyNotRunning { label: "anthropic (oauth)".into() },
            BuildTargetError::PasswordRequired { alias: "my-key".into() },
            BuildTargetError::DecryptFailed { alias: "my-key".into(), detail: "wrong password".into() },
            BuildTargetError::TeamKeyNotDelivered { virtual_key_id: "vk1".into(), display: "team-a".into() },
            BuildTargetError::OAuthUnhealthy { account: "a@b.com".into(), status: "expired".into() },
            BuildTargetError::Unknown { label: "mystery".into(), detail: "-".into() },
        ] {
            assert!(!e.label().is_empty(), "variant {:?} produced empty label", e);
            assert!(!e.reason().is_empty(), "variant {:?} produced empty reason", e);
        }
    }

    // ── targets_from_alias: priority ordering ────────────────────────────
    //
    // Full DB-backed end-to-end tests live in tests/ — here we only pin the
    // "not found" shape (empty Vec, not an error). The contract "personal
    // wins over team wins over OAuth" is covered by the e2e suite because
    // it needs real storage fixtures (can't be constructed cheaply in a
    // unit test).

    #[test]
    fn alias_unknown_source_returns_empty_vec_not_error() {
        // When an alias matches nothing, callers should see an empty Vec
        // and print "not found" guidance — not a panic or an Err.
        let targets = targets_from_alias(
            "definitely-not-a-real-alias-9f8e7d6c",
            None,
            None,
            27200,
        );
        assert!(targets.is_empty(),
            "unknown alias must produce an empty target list");
    }

    // ── OAuth provider canonicalization ──────────────────────────────────
    //
    // `targets_from_alias` OAuth branch must return the CANONICAL provider
    // code (anthropic/openai/kimi), not the raw broker code stored on the
    // account (claude/codex/kimi). Otherwise persona tweaks inside
    // test_provider_connectivity (`?beta=true`, Responses API path) key off
    // the wrong string and the chat probe 404s — while `aikey test` over
    // bindings happens to succeed because bindings already store the
    // canonical code.
    //
    // First discovered in the wild: the same OAuth account showed chat=ok
    // via `aikey test` but chat=404 via `aikey test <email>`. The only
    // difference was which string fed `test_provider_connectivity`.

    #[test]
    fn oauth_canonicalization_maps_claude_to_anthropic() {
        assert_eq!(
            crate::commands_account::oauth_provider_to_canonical("claude"),
            "anthropic",
            "targets_from_alias must canonicalize before driving persona tweaks — \
             Claude OAuth chat probe needs provider_code == \"anthropic\" so the \
             `?beta=true` + metadata.user_id branch triggers");
    }

    #[test]
    fn oauth_canonicalization_maps_codex_to_openai() {
        assert_eq!(
            crate::commands_account::oauth_provider_to_canonical("codex"),
            "openai",
            "Codex OAuth chat probe needs provider_code == \"openai\" + \
             is_via_proxy so it picks the Responses API path (/responses) \
             rather than generic chat completions");
    }

    #[test]
    fn oauth_canonicalization_passes_unknown_through() {
        // Third-party OAuth providers (kimi today; others in the future) use
        // the same code in both slots, so no mapping needed.
        assert_eq!(
            crate::commands_account::oauth_provider_to_canonical("kimi"),
            "kimi");
        assert_eq!(
            crate::commands_account::oauth_provider_to_canonical("something-new"),
            "something-new");
    }

    // ── Factory invariants ──────────────────────────────────────────────
    //
    // These pin the contract that every TestTarget with `kind == OAuth` has
    // a canonical provider_code, regardless of whether the caller passed a
    // broker code ("claude") or an already-canonical code ("anthropic").
    // Future regressions that construct OAuth targets bypassing `oauth_target`
    // will fail these tests.

    #[test]
    fn oauth_target_canonicalizes_claude_input() {
        let t = oauth_target("acc_123", "claude", 27200);
        assert_eq!(t.provider_code, "anthropic",
            "oauth_target MUST normalize broker vocab so downstream persona \
             tweaks key on the canonical code");
        assert_eq!(t.kind, CredentialKind::OAuth);
        assert_eq!(t.bearer, "aikey_personal_acc_123");
        assert!(t.base_url.starts_with("http://127.0.0.1:27200/"),
            "OAuth targets always route via local proxy, got: {}", t.base_url);
        assert_eq!(t.display_label(), "anthropic (oauth)",
            "display label uses the canonical code (matches `aikey test` over bindings)");
    }

    #[test]
    fn oauth_target_canonicalizes_codex_input() {
        let t = oauth_target("acc_456", "codex", 27200);
        assert_eq!(t.provider_code, "openai");
        assert_eq!(t.display_label(), "openai (oauth)");
    }

    #[test]
    fn oauth_target_idempotent_on_already_canonical() {
        // Bindings store canonical codes — calling `oauth_target` with one
        // must not accidentally re-map to something else.
        let t = oauth_target("acc_789", "anthropic", 27200);
        assert_eq!(t.provider_code, "anthropic");
        let t2 = oauth_target("acc_789", "openai", 27200);
        assert_eq!(t2.provider_code, "openai");
    }

    #[test]
    fn team_target_uses_vk_sentinel_and_proxy_url() {
        let t = team_target("vk_abc", "anthropic", 27200);
        assert_eq!(t.kind, CredentialKind::ManagedTeam);
        assert_eq!(t.bearer, "aikey_vk_vk_abc");
        assert!(t.base_url.starts_with("http://127.0.0.1:27200/anthropic"));
        assert_eq!(t.display_label(), "anthropic (team)");
        assert_eq!(t.source_ref, "vk_abc");
    }

    #[test]
    fn personal_target_routes_via_proxy_with_sentinel() {
        // Plan D (2026-04-22): bearer is the sentinel, URL is local proxy.
        let t = personal_target("my-key", "kimi", 27200);
        assert_eq!(t.kind, CredentialKind::PersonalApi);
        assert_eq!(t.bearer, "aikey_personal_alias_my-key",
            "bearer must be the sentinel, not plaintext — CLI never decrypts");
        assert!(t.base_url.starts_with("http://127.0.0.1:27200/"),
            "personal keys route through local proxy, got: {}", t.base_url);
        assert_eq!(t.display_label(), "kimi");
    }

    #[test]
    fn personal_target_direct_still_uses_plaintext() {
        // Direct variant reserved for `aikey add` pre-save probe. Pinned so
        // a refactor can't silently redirect to the sentinel (which would 503
        // because the alias row doesn't exist in vault yet).
        let t = personal_target_direct("my-key", "sk-plaintext", "kimi", None);
        assert_eq!(t.bearer, "sk-plaintext");
        assert!(t.base_url.starts_with("https://api.kimi.com"),
            "direct variant must hit upstream, not proxy");
    }

    #[test]
    fn personal_target_direct_trims_bearer_whitespace() {
        let t = personal_target_direct("x", "  sk-padded\n", "openai", None);
        assert_eq!(t.bearer, "sk-padded",
            "factory must trim so the Authorization header is valid");
    }

    // ── ConnectivityResult shape (Stage 2, 2026-04-22) ──────────────────
    //
    // The 4-phase redesign split Ping into Ping(DIRECT) and Ping(PROXY).
    // These tests pin the struct shape so a future edit can't silently
    // drop a field.

    #[test]
    fn connectivity_result_has_both_ping_kinds() {
        // Build a zero result just to force the compiler to evaluate field
        // names. If someone renames/drops ping_direct_ok this test fails to
        // compile — early warning.
        let r = ConnectivityResult {
            ping_direct_ok: false, ping_direct_ms: 0,
            ping_ok: false, ping_ms: 0,
            api_ok: false, api_ms: 0, api_status: None,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
        // Ping(DIRECT) must not participate in success bookkeeping —
        // it's informational only. Main overall-success logic keys on API.
        assert!(!r.api_ok,
            "zero result should not accidentally report API success");
    }

    #[test]
    fn connectivity_result_ping_direct_independent_of_ping_proxy() {
        // The user can legitimately have Ping(D) ok + Ping(PROXY) fail
        // (laptop can reach upstream; proxy is broken) or vice-versa.
        // The struct must let both states coexist.
        let r = ConnectivityResult {
            ping_direct_ok: true, ping_direct_ms: 10,
            ping_ok: false, ping_ms: 3000,
            api_ok: false, api_ms: 0, api_status: None,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
        assert!(r.ping_direct_ok && !r.ping_ok,
            "struct must represent 'laptop ok, proxy broken' as a valid state");
    }
}
