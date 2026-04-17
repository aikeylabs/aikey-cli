//! Unit tests for `aikey activate` / `aikey deactivate`.
//!
//! Included into main.rs via `#[path = "activate_tests.rs"] mod activate_tests;`
//! so private items like `shell_escape`, `canonical_provider`, etc. are accessible
//! through `use super::*;`.

use super::*;

// ── shell_escape ────────────────────────────────────────────────────────

#[test]
fn shell_escape_plain() {
    assert_eq!(shell_escape("hello"), "'hello'");
}

#[test]
fn shell_escape_single_quote() {
    assert_eq!(shell_escape("it's"), "'it'\\''s'");
}

#[test]
fn shell_escape_dollar_parens() {
    assert_eq!(shell_escape("$(rm -rf /)"), "'$(rm -rf /)'");
}

#[test]
fn shell_escape_backtick() {
    assert_eq!(shell_escape("`cmd`"), "'`cmd`'");
}

#[test]
fn shell_escape_newline() {
    assert_eq!(shell_escape("a\nb"), "'a\nb'");
}

#[test]
fn shell_escape_double_quotes() {
    assert_eq!(shell_escape(r#"test"key"#), r#"'test"key'"#);
}

// ── powershell_escape ───────────────────────────────────────────────────

#[test]
fn powershell_escape_single_quote() {
    assert_eq!(powershell_escape("it's"), "'it''s'");
}

#[test]
fn powershell_escape_plain() {
    assert_eq!(powershell_escape("hello"), "'hello'");
}

// ── cmd_escape ──────────────────────────────────────────────────────────

#[test]
fn cmd_escape_safe() {
    assert!(cmd_escape("my-key_01.test@host").is_ok());
}

#[test]
fn cmd_escape_unsafe_ampersand() {
    assert!(cmd_escape("a&b").is_err());
}

#[test]
fn cmd_escape_unsafe_pipe() {
    assert!(cmd_escape("a|b").is_err());
}

#[test]
fn cmd_escape_unsafe_spaces() {
    assert!(cmd_escape("a b").is_err());
}

#[test]
fn cmd_escape_plus_sign_allowed() {
    // Email tags like alice+work@example.com must be accepted.
    assert!(cmd_escape("alice+work@example.com").is_ok());
}

// ── prompt escaping ─────────────────────────────────────────────────────

#[test]
fn zsh_prompt_escape_percent() {
    assert_eq!(zsh_prompt_escape("%F{red}evil%f"), "%%F{red}evil%%f");
}

#[test]
fn zsh_prompt_escape_safe_label() {
    assert_eq!(zsh_prompt_escape("my-key-01"), "my-key-01");
}

#[test]
fn bash_prompt_escape_backslash() {
    // Backslash is sanitized to "_" (not doubled), because bash PS1 with
    // `promptvars` ON re-interprets `\X` sequences. Predictable literal
    // display beats trying to escape properly across bash versions.
    assert_eq!(bash_prompt_escape("\\u@\\h"), "_u@_h");
}

#[test]
fn bash_prompt_escape_safe_label() {
    assert_eq!(bash_prompt_escape("my-key-01"), "my-key-01");
}

#[test]
fn bash_prompt_escape_command_injection() {
    // Prompt injection via $(...) and `...` MUST be blocked — these would
    // execute on every prompt display when `promptvars` is on (default).
    assert_eq!(bash_prompt_escape("$(evil)"), "_(evil)");
    assert_eq!(bash_prompt_escape("`evil`"), "_evil_");
    assert_eq!(bash_prompt_escape("$var"), "_var");
    assert_eq!(bash_prompt_escape("a!b"), "a_b");
}

#[test]
fn zsh_prompt_escape_command_injection() {
    // Same injection vectors via PROMPT_SUBST (common via oh-my-zsh).
    assert_eq!(zsh_prompt_escape("$(evil)"), "_(evil)");
    assert_eq!(zsh_prompt_escape("`evil`"), "_evil_");
    assert_eq!(zsh_prompt_escape("50%$"), "50%%_");
}

// ── resolve_single_provider ─────────────────────────────────────────────

#[test]
fn single_provider_no_override() {
    let providers = vec!["anthropic".to_string()];
    let result = resolve_single_provider("key1", &providers, None);
    assert_eq!(result.unwrap(), "anthropic");
}

#[test]
fn multi_provider_no_override_errors() {
    let providers = vec!["anthropic".to_string(), "openai".to_string()];
    let result = resolve_single_provider("key1", &providers, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("multiple providers"));
}

#[test]
fn multi_provider_with_override() {
    let providers = vec!["anthropic".to_string(), "openai".to_string()];
    let result = resolve_single_provider("key1", &providers, Some("openai"));
    assert_eq!(result.unwrap(), "openai");
}

#[test]
fn provider_override_not_supported() {
    let providers = vec!["anthropic".to_string()];
    let result = resolve_single_provider("key1", &providers, Some("openai"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not support"));
}

#[test]
fn multi_provider_error_includes_example_command() {
    // L3: error should show a copy-paste-ready command, not just "specify --provider".
    let providers = vec!["anthropic".to_string(), "openai".to_string()];
    let err = resolve_single_provider("my-key", &providers, None).unwrap_err().to_string();
    assert!(err.contains("aikey activate my-key --provider anthropic"),
        "error should include full command example, got: {}", err);
}

// ── provider_canonical / provider_proxy_path (L5 unified 2026-04-17) ─────
//
// These replace the old `canonical_provider` fn. provider_canonical returns the
// data-model canonical code (for vault/display normalization); provider_proxy_path
// returns the URL path segment used when building base_url for third-party clients.
//
// After L5 unification, both route and activate use provider_proxy_path for URL
// building, so kimi/moonshot now get /v1 on both paths (fixing the route bug).

#[test]
fn provider_canonical_claude_to_anthropic() {
    assert_eq!(provider_canonical("claude"), "anthropic");
}

#[test]
fn provider_canonical_openai_aliases() {
    assert_eq!(provider_canonical("codex"), "openai");
    assert_eq!(provider_canonical("gpt"), "openai");
    assert_eq!(provider_canonical("chatgpt"), "openai");
}

#[test]
fn provider_canonical_gemini_to_google() {
    assert_eq!(provider_canonical("gemini"), "google");
}

#[test]
fn provider_canonical_moonshot_to_kimi() {
    // moonshot is a brand of kimi at the vault/routing layer.
    // DO NOT break this without updating proxy/internal/proxy/middleware.go.
    assert_eq!(provider_canonical("moonshot"), "kimi");
}

#[test]
fn provider_canonical_codes_unchanged() {
    for code in ["anthropic", "openai", "google", "kimi", "deepseek"] {
        assert_eq!(provider_canonical(code), code,
            "canonical code {} should pass through unchanged", code);
    }
}

#[test]
fn provider_canonical_case_insensitive() {
    assert_eq!(provider_canonical("Claude"), "anthropic");
    assert_eq!(provider_canonical("CHATGPT"), "openai");
    assert_eq!(provider_canonical("MOONSHOT"), "kimi");
}

#[test]
fn provider_canonical_unknown_falls_back_lowercased() {
    // Unknown providers fall back to the lowercased input so new server-side
    // providers keep working even before the CLI knows them. Lowercasing (vs
    // pass-through) ensures consistent casing across all code paths.
    assert_eq!(provider_canonical("new-provider"), "new-provider");
    assert_eq!(provider_canonical("NewProvider"), "newprovider");
}

// ── provider_proxy_path (URL path segment for base_url) ─────────────────

#[test]
fn provider_proxy_path_anthropic_aliases_same() {
    assert_eq!(provider_proxy_path("anthropic"), "anthropic");
    assert_eq!(provider_proxy_path("claude"), "anthropic");
}

#[test]
fn provider_proxy_path_openai_aliases_same() {
    assert_eq!(provider_proxy_path("openai"), "openai");
    assert_eq!(provider_proxy_path("codex"), "openai");
    assert_eq!(provider_proxy_path("gpt"), "openai");
    assert_eq!(provider_proxy_path("chatgpt"), "openai");
}

#[test]
fn provider_proxy_path_kimi_has_v1_suffix() {
    // Kimi's upstream base is /coding (no /v1), and Kimi uses an OpenAI-compatible
    // SDK that treats base_url as "already includes /v1". So the proxy-side path
    // MUST carry /v1 to produce /coding/v1/chat/completions at upstream.
    assert_eq!(provider_proxy_path("kimi"), "kimi/v1");
}

#[test]
fn provider_proxy_path_moonshot_keeps_brand_but_has_v1() {
    // moonshot URL preserves the brand (not rewritten to /kimi) because the
    // proxy registers BOTH /moonshot and /kimi path prefixes and both map to
    // the same upstream. Preserving the brand avoids surprising the user.
    assert_eq!(provider_proxy_path("moonshot"), "moonshot/v1");
}

#[test]
fn provider_proxy_path_deepseek_no_v1() {
    // DeepSeek's upstream base already includes /v1, so the proxy path stays bare.
    assert_eq!(provider_proxy_path("deepseek"), "deepseek");
}

#[test]
fn provider_proxy_path_unknown_falls_back_lowercased() {
    assert_eq!(provider_proxy_path("custom"), "custom");
    assert_eq!(provider_proxy_path("FooBar"), "foobar");
}

// ── L5 consistency: route and activate now agree on every known provider ──
//
// Before L5, `route` used canonical_provider (→ /kimi) while `activate` used
// provider_proxy_prefix (→ /kimi/v1). This test battery ensures both code paths
// now produce IDENTICAL base_url values, so users see the same config regardless
// of which command they consult.

#[test]
fn route_and_activate_paths_agree_all_known_providers() {
    // For every provider with env vars (i.e. every known provider), the URL path
    // used by `aikey route` (provider_proxy_path) must equal the one used by
    // `aikey activate` (commands_account::provider_proxy_prefix_pub).
    for code in &[
        "anthropic", "claude",
        "openai", "codex", "gpt", "chatgpt",
        "google", "gemini",
        "kimi", "moonshot", "deepseek",
    ] {
        let route_path = provider_proxy_path(code);
        let activate_path = commands_account::provider_proxy_prefix_pub(code);
        assert_eq!(route_path, activate_path,
            "route and activate should emit the same URL path for '{}', \
             got route={:?} activate={:?}", code, route_path, activate_path);
    }
}

#[test]
fn route_activate_paths_identical_for_kimi_after_l5() {
    // Explicit regression test for the original kimi divergence that motivated L5.
    // This replaces the old `route_and_activate_paths_currently_diverge_for_kimi`.
    assert_eq!(provider_proxy_path("kimi"), "kimi/v1");
    assert_eq!(commands_account::provider_proxy_prefix_pub("kimi"), "kimi/v1");
}

#[test]
fn route_activate_paths_identical_for_moonshot_after_l5() {
    assert_eq!(provider_proxy_path("moonshot"), "moonshot/v1");
    assert_eq!(commands_account::provider_proxy_prefix_pub("moonshot"), "moonshot/v1");
}

// ── ProviderInfo: all fields set consistently per provider ─────────────

#[test]
fn provider_info_returns_none_for_unknown() {
    assert!(commands_account::provider_info("totally-unknown-provider").is_none());
    assert!(commands_account::provider_info("").is_none());
}

#[test]
fn provider_info_aliases_share_canonical_code() {
    // All aliases of the same provider must have identical canonical_code.
    let anthropic = commands_account::provider_info("anthropic").unwrap().canonical_code;
    let claude    = commands_account::provider_info("claude").unwrap().canonical_code;
    assert_eq!(anthropic, claude);

    let openai    = commands_account::provider_info("openai").unwrap().canonical_code;
    let codex     = commands_account::provider_info("codex").unwrap().canonical_code;
    let gpt       = commands_account::provider_info("gpt").unwrap().canonical_code;
    let chatgpt   = commands_account::provider_info("chatgpt").unwrap().canonical_code;
    assert_eq!(openai, codex);
    assert_eq!(openai, gpt);
    assert_eq!(openai, chatgpt);
}

#[test]
fn provider_info_moonshot_canonical_is_kimi_but_env_vars_distinct() {
    // L5 preserves the asymmetry: moonshot canonical-maps to "kimi" (same vault
    // account / binding lookup key) but keeps its own env vars so users can
    // optionally configure MOONSHOT_API_KEY separately if desired.
    let kimi     = commands_account::provider_info("kimi").unwrap();
    let moonshot = commands_account::provider_info("moonshot").unwrap();
    assert_eq!(kimi.canonical_code, moonshot.canonical_code); // both "kimi"
    assert_ne!(kimi.env_vars, moonshot.env_vars);             // distinct env vars
    assert_ne!(kimi.proxy_path, moonshot.proxy_path);         // distinct URL paths
}

#[test]
fn provider_info_all_known_have_env_vars_and_path() {
    // Full coverage sweep: every known code yields Some(info) with non-empty fields.
    for code in &[
        "anthropic", "claude",
        "openai", "codex", "gpt", "chatgpt",
        "google", "gemini",
        "kimi", "moonshot", "deepseek",
    ] {
        let info = commands_account::provider_info(code)
            .unwrap_or_else(|| panic!("provider_info('{}') returned None", code));
        assert!(!info.canonical_code.is_empty(), "{}: canonical_code empty", code);
        assert!(!info.proxy_path.is_empty(), "{}: proxy_path empty", code);
        assert!(!info.env_vars.0.is_empty() && !info.env_vars.1.is_empty(),
            "{}: env_vars empty", code);
    }
}
