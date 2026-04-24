//! Provider Registry — loads `data/provider_registry.yaml` at startup and
//! exposes typed lookup / iteration APIs.
//!
//! # Why this module exists (2026-04-24)
//!
//! Before this file, provider capability was scattered across FOUR tables:
//!   - `commands_account::provider_info`  (env_vars + proxy_path + canonical)
//!   - `commands_account::oauth_provider_to_canonical`  (alias → canonical)
//!   - `connectivity::PROVIDER_DEFAULTS`  (default base_url)
//!   - `main.rs::KNOWN_PROVIDERS`  (picker list)
//!
//! Adding a provider meant editing all four + adding a Go-side analog in
//! `aikey-proxy/internal/proxy/middleware.go`. Drift bugs inevitable. This
//! module is the single Rust-side source of truth; the four consumers are
//! now thin wrappers over `lookup()` / `entries()` / `canonical()`.
//!
//! Proxy-side duplication is flagged with a big TODO (build-time shared-
//! JSON codegen); until then the two language copies must be kept in sync
//! manually.
//!
//! # Lookup semantics
//!
//! `lookup(code)` matches in this order:
//!   1. exact match on `entry.code`
//!   2. match on any `entry.oauth_aliases[i]`
//!   3. returns `None`
//!
//! `canonical(code)` returns the canonical `code` for OAuth brand alias
//! resolution (replaces `oauth_provider_to_canonical`). Unknown codes pass
//! through unchanged — matching the old helper's behavior so unregistered
//! codes (custom providers the user typed in `aikey add`) still work.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// Registry YAML bundled into the binary at compile time. Keeps the CLI
/// self-contained (no runtime file lookup, no shipping a data dir) and
/// matches how `provider_fingerprint.yaml` is consumed — see that file for
/// the precedent.
const REGISTRY_YAML: &str = include_str!("../data/provider_registry.yaml");

#[derive(Debug, Deserialize)]
struct RegistryFile {
    providers: Vec<RegistryEntryRaw>,
}

#[derive(Debug, Deserialize)]
struct RegistryEntryRaw {
    code: String,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    oauth_aliases: Vec<String>,
    proxy_path: String,
    env_api_key: String,
    env_base_url: String,
    default_base_url: String,
    picker: bool,
    #[serde(default)]
    display: Option<String>,
    #[serde(default)]
    extra_env_vars: Vec<ExtraEnvVarRaw>,
}

#[derive(Debug, Deserialize)]
struct ExtraEnvVarRaw {
    var: String,
    value: String,
}

/// Public registry entry (static strings for cheap borrowing).
#[derive(Debug)]
pub struct RegistryEntry {
    /// Canonical provider_code stored in bindings table.
    pub code: &'static str,
    /// Protocol family for vault-UI grouping. Defaults to `code` when the
    /// registry entry has no explicit `family` field.
    pub family: &'static str,
    /// OAuth broker aliases that normalize to `code` at binding write time.
    pub oauth_aliases: &'static [&'static str],
    /// URL path segment in aikey-proxy.
    pub proxy_path: &'static str,
    /// `(api_key_var, base_url_var)` — env vars written by `aikey use` into
    /// `~/.aikey/active.env`.
    pub env_vars: (&'static str, &'static str),
    /// Upstream default base URL (used in drawer hint + connectivity probes).
    pub default_base_url: &'static str,
    /// Whether this provider appears in the `aikey add` interactive picker.
    pub picker: bool,
    /// Human-facing label for the picker. Defaults to `code`.
    pub display: &'static str,
    /// Extra env vars (e.g. `KIMI_MODEL_NAME`) written alongside api_key /
    /// base_url for SDKs that need additional context.
    pub extra_env_vars: &'static [(&'static str, &'static str)],
}

struct RegistryState {
    entries: Vec<RegistryEntry>,
    /// `code` or any alias → index into `entries`.
    index: HashMap<String, usize>,
}

static REGISTRY: OnceLock<RegistryState> = OnceLock::new();

fn state() -> &'static RegistryState {
    REGISTRY.get_or_init(|| {
        let raw: RegistryFile = serde_yaml::from_str(REGISTRY_YAML)
            .expect("embedded provider_registry.yaml must be valid");

        // Leak raw strings to get 'static lifetimes. The registry is
        // process-global and immutable after first load, so one-shot leak
        // per provider field is the cheapest option (no Arc<str> clones on
        // every lookup). Total footprint: ~14 entries × 6 short strings =
        // negligible vs. the cost of an Arc-based alternative.
        fn leak(s: String) -> &'static str {
            Box::leak(s.into_boxed_str())
        }
        fn leak_vec(v: Vec<String>) -> &'static [&'static str] {
            let boxed: Box<[&'static str]> = v.into_iter().map(leak).collect();
            Box::leak(boxed)
        }
        fn leak_extras(v: Vec<ExtraEnvVarRaw>) -> &'static [(&'static str, &'static str)] {
            let boxed: Box<[(&'static str, &'static str)]> = v.into_iter()
                .map(|e| (leak(e.var), leak(e.value)))
                .collect();
            Box::leak(boxed)
        }

        let mut entries: Vec<RegistryEntry> = Vec::with_capacity(raw.providers.len());
        for r in raw.providers {
            let code: &'static str = leak(r.code);
            let family: &'static str = match r.family {
                Some(f) => leak(f),
                None => code,
            };
            let display: &'static str = match r.display {
                Some(d) => leak(d),
                None => code,
            };
            entries.push(RegistryEntry {
                code,
                family,
                oauth_aliases: leak_vec(r.oauth_aliases),
                proxy_path: leak(r.proxy_path),
                env_vars: (leak(r.env_api_key), leak(r.env_base_url)),
                default_base_url: leak(r.default_base_url),
                picker: r.picker,
                display,
                extra_env_vars: leak_extras(r.extra_env_vars),
            });
        }

        // Build lookup index: code → idx, plus every alias → same idx.
        let mut index: HashMap<String, usize> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            if index.insert(e.code.to_string(), i).is_some() {
                panic!("provider_registry.yaml: duplicate code '{}'", e.code);
            }
            for alias in e.oauth_aliases {
                if let Some(prior) = index.insert(alias.to_string(), i) {
                    // An alias shouldn't collide with another entry — if
                    // it does, the registry is logically inconsistent.
                    panic!(
                        "provider_registry.yaml: alias '{}' on '{}' collides with entry #{}",
                        alias, e.code, prior
                    );
                }
            }
        }

        RegistryState { entries, index }
    })
}

/// Look up a provider by canonical code or OAuth alias. Case-insensitive.
/// Returns `None` for unknown codes (custom providers not in the registry).
pub fn lookup(code: &str) -> Option<&'static RegistryEntry> {
    let lower = code.to_lowercase();
    let s = state();
    s.index.get(&lower).map(|&i| &s.entries[i])
}

/// Iterate all entries in YAML declaration order. Stable across processes
/// (used by the `aikey add` picker so provider list ordering is deterministic).
pub fn entries() -> &'static [RegistryEntry] {
    &state().entries
}

/// Entries flagged `picker: true`, in YAML order. Drives the interactive
/// `aikey add` provider select.
pub fn picker_entries() -> Vec<&'static RegistryEntry> {
    state().entries.iter().filter(|e| e.picker).collect()
}

/// Canonical code for an OAuth brand alias (e.g. "claude" → "anthropic",
/// "codex" → "openai"). Unknown codes pass through unchanged so custom
/// user-entered provider names still work for add/use flows.
///
/// Replaces the hand-rolled `commands_account::oauth_provider_to_canonical`
/// — that function is now a thin delegation shim.
pub fn canonical(code: &str) -> &'static str {
    match lookup(code) {
        Some(e) => e.code,
        None => {
            // Unknown — return a leaked copy of the lowercased input so the
            // caller gets a 'static str matching what they would have had
            // if the switch just passed through. Cached per-value to avoid
            // unbounded leaks from adversarial inputs; see cached_leak below.
            cached_leak(&code.to_lowercase())
        }
    }
}

/// Leak-once cache for unknown-code passthrough in `canonical()`. Bounded
/// by the distinct set of unknown codes the CLI ever sees in its lifetime
/// (in practice: a handful of user-typed custom provider names).
fn cached_leak(s: &str) -> &'static str {
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&cached) = guard.get(s) {
        return cached;
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    guard.insert(s.to_string(), leaked);
    leaked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_loads_without_panic() {
        let es = entries();
        assert!(!es.is_empty(), "registry loaded zero entries");
        assert!(es.len() >= 14, "expected >= 14 entries after P0+P1, got {}", es.len());
    }

    #[test]
    fn lookup_by_code_exact() {
        let e = lookup("anthropic").expect("anthropic present");
        assert_eq!(e.code, "anthropic");
        assert_eq!(e.env_vars.0, "ANTHROPIC_API_KEY");
    }

    #[test]
    fn lookup_by_oauth_alias() {
        assert_eq!(lookup("claude").unwrap().code, "anthropic");
        assert_eq!(lookup("codex").unwrap().code, "openai");
        assert_eq!(lookup("gemini").unwrap().code, "google");
        assert_eq!(lookup("gpt").unwrap().code, "openai");
    }

    #[test]
    fn lookup_case_insensitive() {
        assert_eq!(lookup("CLAUDE").unwrap().code, "anthropic");
        assert_eq!(lookup("Anthropic").unwrap().code, "anthropic");
    }

    #[test]
    fn unknown_code_returns_none() {
        assert!(lookup("definitely-not-a-real-provider-xyz").is_none());
    }

    #[test]
    fn canonical_passes_through_unknown() {
        let code = canonical("custom-aggregator");
        assert_eq!(code, "custom-aggregator");
        // Second call returns the same 'static str (cached)
        let code2 = canonical("custom-aggregator");
        assert_eq!(code.as_ptr(), code2.as_ptr(), "cache should return same ptr");
    }

    #[test]
    fn canonical_maps_oauth_aliases() {
        assert_eq!(canonical("claude"), "anthropic");
        assert_eq!(canonical("codex"), "openai");
        assert_eq!(canonical("gpt"), "openai");
        assert_eq!(canonical("gemini"), "google");
        // moonshot is NOT an alias of kimi — it's a distinct entry
        // (different env vars). canonical returns itself.
        assert_eq!(canonical("moonshot"), "moonshot");
    }

    #[test]
    fn p0_providers_present() {
        for code in &["groq", "xai", "openrouter", "perplexity"] {
            let e = lookup(code).unwrap_or_else(|| panic!("missing P0: {}", code));
            assert_eq!(e.code, *code);
            assert!(e.picker, "{} should be in picker", code);
        }
    }

    #[test]
    fn p1_providers_present() {
        for code in &["zhipu", "qwen", "doubao", "siliconflow"] {
            let e = lookup(code).unwrap_or_else(|| panic!("missing P1: {}", code));
            assert_eq!(e.code, *code);
            assert!(e.picker, "{} should be in picker", code);
        }
    }

    #[test]
    fn chinese_oauth_aliases_resolve() {
        // zhipu accepts the common民间 alias "glm" and the SDK-convention "zhipuai"
        assert_eq!(lookup("glm").unwrap().code, "zhipu");
        assert_eq!(lookup("zhipuai").unwrap().code, "zhipu");
        // qwen accepts SDK-convention "dashscope" + 民间 "tongyi"
        assert_eq!(lookup("dashscope").unwrap().code, "qwen");
        assert_eq!(lookup("tongyi").unwrap().code, "qwen");
        // doubao accepts SDK-convention "ark" + platform "volcengine"
        assert_eq!(lookup("ark").unwrap().code, "doubao");
        assert_eq!(lookup("volcengine").unwrap().code, "doubao");
    }

    #[test]
    fn env_var_names_match_sdk_conventions() {
        // Sanity check: the env var names match what provider SDKs look for.
        assert_eq!(lookup("zhipu").unwrap().env_vars.0, "ZHIPUAI_API_KEY");
        assert_eq!(lookup("qwen").unwrap().env_vars.0, "DASHSCOPE_API_KEY");
        assert_eq!(lookup("doubao").unwrap().env_vars.0, "ARK_API_KEY");
        assert_eq!(lookup("groq").unwrap().env_vars.0, "GROQ_API_KEY");
        assert_eq!(lookup("xai").unwrap().env_vars.0, "XAI_API_KEY");
    }

    #[test]
    fn protocol_family_defaults_to_code() {
        // moonshot is the only entry with explicit `family: kimi` —
        // everything else's family should equal its code.
        assert_eq!(lookup("moonshot").unwrap().family, "kimi");
        assert_eq!(lookup("kimi").unwrap().family, "kimi");
        assert_eq!(lookup("anthropic").unwrap().family, "anthropic");
        assert_eq!(lookup("zhipu").unwrap().family, "zhipu");
    }

    #[test]
    fn kimi_has_extra_env_vars_for_sdk() {
        let e = lookup("kimi").unwrap();
        assert!(e.extra_env_vars.iter().any(|(k, _)| *k == "KIMI_MODEL_NAME"));
        assert!(e.extra_env_vars.iter().any(|(k, _)| *k == "KIMI_MODEL_MAX_CONTEXT_SIZE"));
        // moonshot shares the same extras (same SDK expectations).
        let m = lookup("moonshot").unwrap();
        assert!(m.extra_env_vars.iter().any(|(k, _)| *k == "KIMI_MODEL_NAME"));
    }

    #[test]
    fn picker_list_non_empty_and_ordered() {
        let list = picker_entries();
        assert!(!list.is_empty());
        // anthropic should be first (YAML declaration order) — if someone
        // reorders the YAML, this pins the expectation.
        assert_eq!(list[0].code, "anthropic");
    }
}
