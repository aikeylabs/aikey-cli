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
