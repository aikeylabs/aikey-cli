//! Proxy env file management (`~/.aikey/proxy.env`).
//!
//! Provides parse, read, write, mask, and hash utilities for the proxy
//! environment file.  This file holds user-managed env vars that are
//! injected into the `aikey-proxy` process at start/restart time.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Returns the canonical path to `~/.aikey/proxy.env`.
pub fn proxy_env_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .map_err(|_| "Could not determine HOME directory".to_string())?;
    Ok(PathBuf::from(home).join(".aikey").join("proxy.env"))
}

/// Returns the canonical path to `~/.aikey/active.env`.
pub fn active_env_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .map_err(|_| "Could not determine HOME directory".to_string())?;
    Ok(PathBuf::from(home).join(".aikey").join("active.env"))
}

/// A parsed env entry (key=value).
pub type EnvMap = BTreeMap<String, String>;

/// Parse a dotenv-style file into a BTreeMap (sorted by key).
/// Skips blank lines and lines starting with `#`.
pub fn parse_env_file(content: &str) -> Result<EnvMap, String> {
    let mut map = EnvMap::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Strip optional "export " prefix.
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let (key, value) = parse_kv(stripped)
            .ok_or_else(|| format!("Line {}: invalid format: {}", i + 1, trimmed))?;
        validate_env_key(&key)
            .map_err(|e| format!("Line {}: {}", i + 1, e))?;
        map.insert(key, value);
    }
    Ok(map)
}

/// Parse CLI arguments after `--` into env entries.
/// Supports: `KEY=VALUE`, `export KEY=VALUE`, semicolon-separated.
pub fn parse_set_args(args: &[String]) -> Result<EnvMap, String> {
    let joined = args.join(" ");
    let mut map = EnvMap::new();

    // Split by semicolons first, then by spaces for KEY=VALUE pairs.
    for segment in joined.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        // Each segment may contain multiple KEY=VALUE separated by spaces,
        // but values may also contain spaces if the segment is a single assignment.
        // Strategy: try to find KEY=VALUE patterns.
        let stripped = segment.strip_prefix("export ").unwrap_or(segment);
        // Split on spaces, but rejoin if a token doesn't contain '='.
        let tokens: Vec<&str> = stripped.split_whitespace().collect();
        let mut i = 0;
        while i < tokens.len() {
            if let Some(eq_pos) = tokens[i].find('=') {
                let key = tokens[i][..eq_pos].to_string();
                let mut value = tokens[i][eq_pos + 1..].to_string();
                // Strip surrounding quotes.
                value = strip_quotes(&value);
                validate_env_key(&key)?;
                if value.contains('\n') {
                    return Err(format!("Multiline values are not supported: {}", key));
                }
                map.insert(key, value);
                i += 1;
            } else {
                // Token without '=' — skip "export" keyword.
                if tokens[i] == "export" {
                    i += 1;
                    continue;
                }
                return Err(format!("Invalid token (no '='): {}", tokens[i]));
            }
        }
    }
    Ok(map)
}

/// Parse a single KEY=VALUE string.
fn parse_kv(s: &str) -> Option<(String, String)> {
    let eq_pos = s.find('=')?;
    let key = s[..eq_pos].trim().to_string();
    let value = strip_quotes(s[eq_pos + 1..].trim());
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Validate that a key is a legal environment variable name.
fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("Empty environment variable name".to_string());
    }
    let first = key.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(format!("Invalid env var name '{}': must start with letter or _", key));
    }
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(format!("Invalid env var name '{}': illegal character '{}'", key, c));
        }
    }
    Ok(())
}

/// Strip surrounding single or double quotes from a value.
fn strip_quotes(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Read and parse `~/.aikey/proxy.env`.  Returns empty map if file doesn't exist.
pub fn read_proxy_env() -> Result<EnvMap, String> {
    let path = proxy_env_path()?;
    if !path.exists() {
        return Ok(EnvMap::new());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    parse_env_file(&content)
}

/// Read a single variable from `~/.aikey/proxy.env`.
/// Returns `None` if the file doesn't exist or the key is not found.
pub fn read_proxy_env_var(key: &str) -> Option<String> {
    let map = read_proxy_env().ok()?;
    map.get(key).cloned()
}

/// Write the env map to `~/.aikey/proxy.env` in stable sorted order.
pub fn write_proxy_env(map: &EnvMap) -> Result<(), String> {
    let path = proxy_env_path()?;
    // Ensure directory exists.
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    let mut content = String::new();
    for (key, value) in map {
        content.push_str(&format!("{}={}\n", key, value));
    }
    std::fs::write(&path, &content)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    Ok(())
}

/// Read `~/.aikey/active.env` as raw lines (for display).
pub fn read_active_env_lines() -> Result<Vec<(String, String)>, String> {
    let path = active_env_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Skip shell conditional/guard syntax (e.g. `case "$no_proxy" in ...`)
        // that leaks into display as a pseudo KEY=VALUE with an unparseable key.
        // We only want clean `[export] KEY=VALUE` assignments.
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some(eq_pos) = stripped.find('=') {
            let key = stripped[..eq_pos].to_string();
            // A valid shell identifier is [A-Za-z_][A-Za-z0-9_]*. Anything else
            // (spaces, punctuation, `$`, `(`, etc.) is a shell control line —
            // skip it rather than display shell internals to the user.
            let is_ident = !key.is_empty()
                && key.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !is_ident { continue; }
            let value = strip_quotes(&stripped[eq_pos + 1..]);
            entries.push((key, value));
        }
    }
    Ok(entries)
}

/// Extract the effective no_proxy bypass list from active.env, even when
/// it's expressed as a `case` guard (`case ",$no_proxy," in *,X,*) ;; *) export no_proxy="X,..."`).
/// Returns the comma-joined bypass tokens, or None if active.env is missing/unparsable.
pub fn read_active_bypass_summary() -> Option<String> {
    let path = active_env_path().ok()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let mut tokens: Vec<String> = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if !line.starts_with("case ") { continue; }
        // The export clause carries the full bypass list, e.g.
        //   ... *) export no_proxy="127.0.0.1,localhost,${no_proxy}"
        let export_key = if line.contains("no_proxy=") { "no_proxy=" }
                         else if line.contains("NO_PROXY=") { "NO_PROXY=" }
                         else { continue; };
        if let Some(pos) = line.find(export_key) {
            let after = &line[pos + export_key.len()..];
            let after = after.trim_start_matches('"');
            // Take up to the closing quote.
            let value = after.split('"').next().unwrap_or("");
            // Drop shell var expansions like ${no_proxy} / $no_proxy.
            for tok in value.split(',') {
                let t = tok.trim();
                if t.is_empty() { continue; }
                if t.starts_with('$') || t.starts_with("${") { continue; }
                if !tokens.iter().any(|s| s == t) {
                    tokens.push(t.to_string());
                }
            }
        }
    }
    if tokens.is_empty() { None } else { Some(tokens.join(",")) }
}

// ── Masking ──────────────────────────────────────────────────────────────────

/// Sensitive key fragments — values for these are always masked.
const SENSITIVE_FRAGMENTS: &[&str] = &[
    "key", "token", "secret", "password", "authorization", "cookie",
];

/// Keys that match SENSITIVE_FRAGMENTS but are NOT sensitive (display values, labels).
const NON_SENSITIVE_KEYS: &[&str] = &[
    "aikey_active_keys",     // provider=identity mapping, not a secret
    "aikey_active_label",    // display label for shell prompt
];

/// Returns true if the key name suggests a sensitive value.
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    if NON_SENSITIVE_KEYS.iter().any(|k| lower == *k) {
        return false;
    }
    SENSITIVE_FRAGMENTS.iter().any(|f| lower.contains(f))
}

/// Mask a value for display. Sensitive values show first 12 chars + "...".
pub fn mask_value(key: &str, value: &str) -> String {
    let lower = key.to_lowercase();
    let is_known_safe = NON_SENSITIVE_KEYS.iter().any(|k| lower == *k);
    if is_known_safe {
        // Known non-sensitive: always show full value.
        value.to_string()
    } else if is_sensitive_key(key) {
        if value.len() <= 12 {
            value.to_string()
        } else {
            format!("{}...", &value[..12])
        }
    } else if value.len() > 40 {
        // Long values may contain tokens even if key name is innocent.
        format!("{}...", &value[..20])
    } else {
        value.to_string()
    }
}

// ── Config hash ──────────────────────────────────────────────────────────────

/// Compute a short config hash from the env map (for logging/audit).
/// The hash covers real values but only the hash is exposed externally.
pub fn config_hash(map: &EnvMap) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for (k, v) in map {
        k.hash(&mut hasher);
        v.hash(&mut hasher);
    }
    format!("{:08x}", hasher.finish() & 0xFFFFFFFF)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_kv() {
        let map = parse_env_file("FOO=bar\nBAZ=123\n").unwrap();
        assert_eq!(map["BAZ"], "123");
        assert_eq!(map["FOO"], "bar");
    }

    #[test]
    fn parse_with_export_prefix() {
        let map = parse_env_file("export FOO=bar\nexport BAZ=123").unwrap();
        assert_eq!(map["FOO"], "bar");
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let map = parse_env_file("# comment\n\nFOO=bar\n").unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn parse_rejects_invalid_key() {
        assert!(parse_env_file("1BAD=value").is_err());
        assert!(parse_env_file("BAD KEY=value").is_err());
    }

    #[test]
    fn parse_set_args_basic() {
        let args = vec!["FOO=bar".into(), "BAZ=123".into()];
        let map = parse_set_args(&args).unwrap();
        assert_eq!(map["FOO"], "bar");
        assert_eq!(map["BAZ"], "123");
    }

    #[test]
    fn parse_set_args_semicolons() {
        let args = vec!["export FOO=bar; export BAZ=123".into()];
        let map = parse_set_args(&args).unwrap();
        assert_eq!(map["FOO"], "bar");
        assert_eq!(map["BAZ"], "123");
    }

    #[test]
    fn mask_sensitive() {
        // Short values (<= 12 chars): shown as-is (too short to partially mask)
        assert_eq!(mask_value("OPENAI_API_KEY", "sk-xxx"), "sk-xxx");
        assert_eq!(mask_value("MY_TOKEN", "abc"), "abc");
        assert_eq!(mask_value("MY_SECRET", "abc"), "abc");
        assert_eq!(mask_value("DB_PASSWORD", "abc"), "abc");
        // Long values (> 12 chars): first 12 chars + "..."
        assert_eq!(mask_value("OPENAI_API_KEY", "sk-1234567890abcdef"), "sk-123456789...");
    }

    #[test]
    fn mask_non_sensitive() {
        assert_eq!(mask_value("MY_FLAG", "on"), "on");
        assert_eq!(mask_value("DEBUG_LEVEL", "verbose"), "verbose");
        assert_eq!(mask_value("RUST_LOG", "info"), "info");
        // Proxy URLs are not sensitive — they are routing config, not credentials.
        assert_eq!(mask_value("http_proxy", "http://1.2.3.4"), "http://1.2.3.4");
        assert_eq!(mask_value("https_proxy", "http://1.2.3.4"), "http://1.2.3.4");
        assert_eq!(mask_value("all_proxy", "socks5://1.2.3.4"), "socks5://1.2.3.4");
    }

    #[test]
    fn hash_stability() {
        let mut map = EnvMap::new();
        map.insert("A".into(), "1".into());
        map.insert("B".into(), "2".into());
        let h1 = config_hash(&map);
        let h2 = config_hash(&map);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 8);
    }

    #[test]
    fn hash_changes_on_value() {
        let mut m1 = EnvMap::new();
        m1.insert("A".into(), "1".into());
        let mut m2 = EnvMap::new();
        m2.insert("A".into(), "2".into());
        assert_ne!(config_hash(&m1), config_hash(&m2));
    }
}
