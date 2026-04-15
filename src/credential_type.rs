/// Credential type enum — unified across Rust CLI and Go proxy.
///
/// Replaces scattered string comparisons ("personal", "team") with a typed enum.
/// Backward-compatible: `from_db_str("personal")` → `PersonalApiKey`,
/// `from_db_str("team")` → `ManagedVirtualKey`.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    PersonalApiKey,
    ManagedVirtualKey,
    PersonalOAuthAccount,
    // Future: ManagedOAuthBrokeredAccount (shared pool, Phase 4)
}

impl CredentialType {
    /// Returns the canonical DB string for this credential type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PersonalApiKey => "personal",
            Self::ManagedVirtualKey => "team",
            Self::PersonalOAuthAccount => "personal_oauth_account",
        }
    }

    /// Parses a DB string into a CredentialType.
    /// Backward-compatible with legacy values ("personal", "team").
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "personal" | "personal_api_key" => Self::PersonalApiKey,
            "team" | "managed_virtual_key" => Self::ManagedVirtualKey,
            "personal_oauth_account" => Self::PersonalOAuthAccount,
            // Unknown values default to PersonalApiKey to avoid breaking existing vaults
            _ => Self::PersonalApiKey,
        }
    }

    /// Whether this credential type is an OAuth account (requires proxy for token management).
    pub fn is_oauth(&self) -> bool {
        matches!(self, Self::PersonalOAuthAccount)
    }
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_db_str_personal() {
        assert_eq!(CredentialType::from_db_str("personal"), CredentialType::PersonalApiKey);
        assert_eq!(CredentialType::from_db_str("personal_api_key"), CredentialType::PersonalApiKey);
    }

    #[test]
    fn from_db_str_team() {
        assert_eq!(CredentialType::from_db_str("team"), CredentialType::ManagedVirtualKey);
        assert_eq!(CredentialType::from_db_str("managed_virtual_key"), CredentialType::ManagedVirtualKey);
    }

    #[test]
    fn from_db_str_oauth() {
        assert_eq!(
            CredentialType::from_db_str("personal_oauth_account"),
            CredentialType::PersonalOAuthAccount
        );
    }

    #[test]
    fn from_db_str_unknown_defaults_to_personal() {
        assert_eq!(CredentialType::from_db_str(""), CredentialType::PersonalApiKey);
        assert_eq!(CredentialType::from_db_str("garbage"), CredentialType::PersonalApiKey);
    }

    #[test]
    fn as_str_roundtrip() {
        for ct in [
            CredentialType::PersonalApiKey,
            CredentialType::ManagedVirtualKey,
            CredentialType::PersonalOAuthAccount,
        ] {
            assert_eq!(CredentialType::from_db_str(ct.as_str()), ct);
        }
    }

    #[test]
    fn is_oauth() {
        assert!(!CredentialType::PersonalApiKey.is_oauth());
        assert!(!CredentialType::ManagedVirtualKey.is_oauth());
        assert!(CredentialType::PersonalOAuthAccount.is_oauth());
    }
}
