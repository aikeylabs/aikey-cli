//! Provider definitions and environment variable mappings.
//!
//! Maps LLM provider names to the environment variable names their SDKs expect.

/// Known LLM providers with their canonical env var names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Provider {
    OpenAI,
    Anthropic,
    Google,
    Cohere,
    Mistral,
    Custom(String),
}

impl std::str::FromStr for Provider {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Provider::parse(s))
    }
}

impl Provider {
    /// Parse a provider name string (case-insensitive) into a Provider variant.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "openai"    => Provider::OpenAI,
            "anthropic" => Provider::Anthropic,
            "google"    => Provider::Google,
            "cohere"    => Provider::Cohere,
            "mistral"   => Provider::Mistral,
            other       => Provider::Custom(other.to_string()),
        }
    }

    /// The canonical name used in config files and CLI flags.
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        match self {
            Provider::OpenAI    => "openai",
            Provider::Anthropic => "anthropic",
            Provider::Google    => "google",
            Provider::Cohere    => "cohere",
            Provider::Mistral   => "mistral",
            Provider::Custom(n) => n.as_str(),
        }
    }

    /// The environment variable name the provider's SDK reads.
    pub fn env_var(&self) -> String {
        match self {
            Provider::OpenAI    => "OPENAI_API_KEY".to_string(),
            Provider::Anthropic => "ANTHROPIC_API_KEY".to_string(),
            Provider::Google    => "GOOGLE_API_KEY".to_string(),
            Provider::Cohere    => "COHERE_API_KEY".to_string(),
            Provider::Mistral   => "MISTRAL_API_KEY".to_string(),
            Provider::Custom(n) => format!("AIKEY_{}_API_KEY", n.to_uppercase()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_providers_env_vars() {
        assert_eq!(Provider::OpenAI.env_var(),    "OPENAI_API_KEY");
        assert_eq!(Provider::Anthropic.env_var(), "ANTHROPIC_API_KEY");
        assert_eq!(Provider::Google.env_var(),    "GOOGLE_API_KEY");
        assert_eq!(Provider::Cohere.env_var(),    "COHERE_API_KEY");
        assert_eq!(Provider::Mistral.env_var(),   "MISTRAL_API_KEY");
    }

    #[test]
    fn test_custom_provider_env_var() {
        let p = Provider::parse("myservice");
        assert_eq!(p.env_var(), "AIKEY_MYSERVICE_API_KEY");
    }

    // Canonicalization regression (bugfix 2026-04-25, audit follow-up):
    // Provider::parse only handles canonical names — feeding it a raw OAuth
    // alias (`claude` / `codex` / `gemini`) falls through to Custom() and
    // emits a wrong env-var name (`AIKEY_CLAUDE_API_KEY` instead of
    // `ANTHROPIC_API_KEY`). The contract is "callers MUST canonicalize
    // first"; the executor and active.env writers do, but anyone touching
    // this enum needs to know the failure mode. These tests document it.
    #[test]
    fn parse_oauth_alias_falls_into_custom_arm() {
        // Documented (mis)behaviour: parse() doesn't know about OAuth aliases.
        // Callers (executor.rs / active.env writers) MUST canonicalize first.
        assert_eq!(Provider::parse("claude"), Provider::Custom("claude".into()));
        assert_eq!(Provider::parse("codex"),  Provider::Custom("codex".into()));
        assert_eq!(Provider::parse("gemini"), Provider::Custom("gemini".into()));
    }

    #[test]
    fn parse_after_canonicalization_yields_correct_env_var() {
        // The fix path: canonicalize → then parse → correct env var.
        // Mirrors the executor.rs fix: anyone constructing a Provider from
        // a raw value must route through `oauth_provider_to_canonical`.
        use crate::commands_account::oauth_provider_to_canonical as canon;
        assert_eq!(Provider::parse(canon("claude")).env_var(), "ANTHROPIC_API_KEY");
        assert_eq!(Provider::parse(canon("codex")).env_var(),  "OPENAI_API_KEY");
        assert_eq!(Provider::parse(canon("gemini")).env_var(), "GOOGLE_API_KEY");
        // Idempotence: canonical input passes through unchanged.
        assert_eq!(Provider::parse(canon("anthropic")).env_var(), "ANTHROPIC_API_KEY");
        assert_eq!(Provider::parse(canon("openai")).env_var(),    "OPENAI_API_KEY");
    }

    #[test]
    fn test_from_str_case_insensitive() {
        assert_eq!(Provider::parse("OpenAI"),    Provider::OpenAI);
        assert_eq!(Provider::parse("ANTHROPIC"), Provider::Anthropic);
        assert_eq!(Provider::parse("Google"),    Provider::Google);
    }

    #[test]
    fn test_provider_name() {
        assert_eq!(Provider::OpenAI.name(),    "openai");
        assert_eq!(Provider::Anthropic.name(), "anthropic");
        assert_eq!(Provider::Custom("foo".to_string()).name(), "foo");
    }
}
