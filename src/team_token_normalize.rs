//! Team token normalization shared helper.
//!
//! Used by both `aikey route <team>` (handle_route) and `aikey activate <team>`
//! (resolve_activate_key) to construct the runtime team bearer token from a
//! server-issued vk_id. Defensive against historical prefix residue
//! (`aikey_vk_` / `aikey_team_`) and pathological double-prefix dirty data.
//!
//! The Go-side equivalent lives at
//! `aikey-proxy/internal/supervisor/team_token_normalize.go` and must produce
//! identical output for every input — verified by the shared golden-cases
//! fixture at `tests/fixtures/team_token_normalize.json`.
//!
//! Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §3 / §4.

/// Build the runtime team token from a server-issued vk_id.
///
/// Steps:
///   1. Trim leading/trailing whitespace.
///   2. Loop-strip any known historical prefix (`aikey_vk_`) or current prefix
///      (`aikey_team_`) plus any whitespace exposed after each strip. Loop
///      covers the pathological double-prefix case (e.g. `aikey_vk_aikey_team_<bare>`)
///      that a corrupted cache could theoretically contain.
///   3. Reject empty / whitespace-only input — `mk.virtual_key_id` should
///      never be empty; if it is, that's an upstream data bug. Caller skips
///      the registration / surfaces the error rather than producing a
///      degenerate `"aikey_team_"` token.
///   4. Re-apply the canonical `aikey_team_` prefix.
///
/// Why a shared helper: route / activate / any future call site must emit
/// the same token regardless of historical cache state, otherwise
/// `aikey route` and `aikey activate` could disagree for the same team key.
pub fn team_token_from_vk_id(raw: &str) -> Result<String, &'static str> {
    let mut bare = raw.trim();
    loop {
        let stripped = bare
            .strip_prefix("aikey_team_")
            .or_else(|| bare.strip_prefix("aikey_vk_"));
        match stripped {
            Some(s) => bare = s.trim(),
            None => break,
        }
    }
    if bare.is_empty() {
        return Err("empty vk_id");
    }
    Ok(format!("aikey_team_{}", bare))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_bare_vk_id() {
        assert_eq!(
            team_token_from_vk_id("acc-1234").unwrap(),
            "aikey_team_acc-1234"
        );
    }

    #[test]
    fn strips_old_vk_prefix() {
        assert_eq!(
            team_token_from_vk_id("aikey_vk_acc-1234").unwrap(),
            "aikey_team_acc-1234"
        );
    }

    #[test]
    fn idempotent_on_new_prefix() {
        assert_eq!(
            team_token_from_vk_id("aikey_team_acc-1234").unwrap(),
            "aikey_team_acc-1234"
        );
    }

    #[test]
    fn double_prefix_vk_outer_team_inner() {
        assert_eq!(
            team_token_from_vk_id("aikey_vk_aikey_team_acc-1234").unwrap(),
            "aikey_team_acc-1234"
        );
    }

    #[test]
    fn double_prefix_team_outer_vk_inner() {
        assert_eq!(
            team_token_from_vk_id("aikey_team_aikey_vk_acc-1234").unwrap(),
            "aikey_team_acc-1234"
        );
    }

    #[test]
    fn empty_input_rejected() {
        assert_eq!(team_token_from_vk_id(""), Err("empty vk_id"));
    }

    #[test]
    fn whitespace_only_rejected() {
        assert_eq!(team_token_from_vk_id("   "), Err("empty vk_id"));
    }

    #[test]
    fn prefix_only_no_suffix_rejected() {
        assert_eq!(team_token_from_vk_id("aikey_vk_"), Err("empty vk_id"));
        assert_eq!(team_token_from_vk_id("aikey_team_"), Err("empty vk_id"));
    }

    #[test]
    fn trims_outer_whitespace() {
        assert_eq!(
            team_token_from_vk_id("  acc-1234  ").unwrap(),
            "aikey_team_acc-1234"
        );
    }

    #[test]
    fn trims_whitespace_after_old_prefix() {
        assert_eq!(
            team_token_from_vk_id("aikey_vk_ acc-1234").unwrap(),
            "aikey_team_acc-1234"
        );
    }
}
