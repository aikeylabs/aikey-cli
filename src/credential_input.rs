//! Normalisation of what a user pastes when adding a personal key.
//!
//! Two problems collapse into one module because they share the same choke
//! point (every add path — CLI `aikey add`, web Add-Key dialog, the dialog's
//! pre-save probe — calls these before anything is stored or probed):
//!
//! 1. **`newapi_channel_conn` connection strings.** new-api-style gateways
//!    (tokenhub / pingtoken) let users copy one JSON blob
//!    `{"_type":"newapi_channel_conn","key":"sk-…","url":"https://host"}`
//!    instead of two fields. Pasting it into the secret box used to store the
//!    whole JSON as the key.
//! 2. **Bare-host base_url for `/v1`-rooted providers.** OpenAI-compatible
//!    gateways serve their API under `<host>/v1`; the bare host is usually the
//!    gateway's web site, whose SPA answers `200 text/html` to every path. A
//!    key saved with `https://gateway.example` then "passes" the API probe and
//!    fails every real request with `stream closed before response.completed`
//!    (bugfix 2026-07-19-codex-agent-baseurl-missing-v1-404.md, and again
//!    2026-09-04 on winpc2). The rule is registry-driven, not a provider list:
//!    a provider whose `default_base_url` path is exactly `/v1` gets `/v1`
//!    appended when the user gave only a host. Providers rooted elsewhere
//!    (anthropic `/`, google `/v1beta`, kimi `/coding/v1`) are left alone —
//!    guessing a deeper path would be a new source of wrong URLs.
//!
//! Bugfix: workflow/CI/bugfix/2026-09-05-add-key-dialog-draft-probe-sends-
//! unresolvable-source-ref.md (part A).

/// A user's secret input after decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSecretInput {
    /// The credential to store / probe.
    pub secret: String,
    /// A base_url carried inside the input (connection string). Callers
    /// prefer their explicit `base_url` field over this.
    pub embedded_base_url: Option<String>,
}

/// Decode a pasted secret. Plain keys pass through unchanged; a
/// `newapi_channel_conn` JSON blob yields its `key` + `url`.
///
/// Only that exact `_type` is recognised — any other JSON is treated as an
/// opaque secret (some providers do hand out JSON service-account blobs).
pub fn decode_secret_input(raw: &str) -> DecodedSecretInput {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if v.get("_type").and_then(|t| t.as_str()) == Some("newapi_channel_conn") {
                if let Some(key) = v.get("key").and_then(|k| k.as_str()).map(str::trim) {
                    if !key.is_empty() {
                        let url = v
                            .get("url")
                            .and_then(|u| u.as_str())
                            .map(str::trim)
                            .filter(|u| !u.is_empty())
                            .map(str::to_string);
                        return DecodedSecretInput {
                            secret: key.to_string(),
                            embedded_base_url: url,
                        };
                    }
                }
            }
        }
    }
    DecodedSecretInput {
        secret: trimmed.to_string(),
        embedded_base_url: None,
    }
}

/// Canonical form of a user-supplied base_url for `provider_code`.
///
/// - trims whitespace and trailing slashes (`https://h/` → `https://h`);
/// - appends `/v1` when the URL has no path and the provider's registry
///   `default_base_url` is rooted at exactly `/v1` (see module docs);
/// - otherwise returns the trimmed input — a URL that already has a path is
///   the user's explicit choice and is never rewritten.
pub fn normalize_base_url(provider_code: &str, raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if !url_has_path(trimmed) && provider_api_root_is_v1(provider_code) {
        return format!("{}/v1", trimmed);
    }
    trimmed.to_string()
}

/// `https://host[:port]` → false; anything after the authority → true.
fn url_has_path(url: &str) -> bool {
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    after_scheme.contains('/')
}

fn provider_api_root_is_v1(provider_code: &str) -> bool {
    crate::provider_registry::lookup(provider_code)
        .map(|e| {
            let d = e.default_base_url.trim_end_matches('/');
            let path = match d.find("://") {
                Some(i) => &d[i + 3..],
                None => d,
            };
            match path.find('/') {
                Some(j) => &path[j..] == "/v1",
                None => false,
            }
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_key_passes_through_trimmed() {
        let d = decode_secret_input("  sk-abc  ");
        assert_eq!(d.secret, "sk-abc");
        assert_eq!(d.embedded_base_url, None);
    }

    #[test]
    fn newapi_channel_conn_yields_key_and_url() {
        let d = decode_secret_input(
            r#"{"_type":"newapi_channel_conn","key":"sk-xyz","url":"https://pingtoken.ai"}"#,
        );
        assert_eq!(d.secret, "sk-xyz");
        assert_eq!(d.embedded_base_url.as_deref(), Some("https://pingtoken.ai"));
    }

    #[test]
    fn other_json_is_an_opaque_secret() {
        let raw = r#"{"type":"service_account","private_key":"x"}"#;
        let d = decode_secret_input(raw);
        assert_eq!(d.secret, raw);
        assert_eq!(d.embedded_base_url, None);
    }

    #[test]
    fn newapi_blob_without_key_is_left_alone() {
        let raw = r#"{"_type":"newapi_channel_conn","url":"https://x"}"#;
        assert_eq!(decode_secret_input(raw).secret, raw);
    }

    #[test]
    fn bare_host_gets_v1_only_for_v1_rooted_providers() {
        // openai's registry root is https://api.openai.com/v1 → append.
        assert_eq!(
            normalize_base_url("openai", "https://pingtoken.ai"),
            "https://pingtoken.ai/v1"
        );
        assert_eq!(
            normalize_base_url("openai", "https://pingtoken.ai/"),
            "https://pingtoken.ai/v1"
        );
        // anthropic is rooted at the host → untouched.
        assert_eq!(
            normalize_base_url("anthropic", "https://gw.example"),
            "https://gw.example"
        );
        // google is /v1beta-rooted → untouched (we never guess deeper paths).
        assert_eq!(
            normalize_base_url("google", "https://gw.example"),
            "https://gw.example"
        );
        // unknown provider → untouched.
        assert_eq!(
            normalize_base_url("nope", "https://gw.example"),
            "https://gw.example"
        );
    }

    #[test]
    fn explicit_path_is_never_rewritten() {
        assert_eq!(
            normalize_base_url("openai", "https://pingtoken.ai/v1"),
            "https://pingtoken.ai/v1"
        );
        assert_eq!(
            normalize_base_url("openai", "https://pingtoken.ai/vi"),
            "https://pingtoken.ai/vi",
            "a typo path is the user's explicit choice; the probe must expose it, not hide it"
        );
        assert_eq!(
            normalize_base_url("openai", "https://gw.example/openai/"),
            "https://gw.example/openai"
        );
        assert_eq!(normalize_base_url("openai", "   "), "");
    }
}
