//! Light/dark theme preference for AiKey's desktop tray.
//!
//! 🔴 SCOPE: this governs the DESKTOP TRAY's simple view only. The console has
//! its own theme control with its own store (browser-side, `[data-theme]`); the
//! CLI's own output has no colours to theme. Same scope note as
//! `display_language`, and for the same reason — the tray is the surface whose
//! users are, by definition, people who do not open a terminal.
//!
//! Why a stored preference at all, when the page already follows the operating
//! system: because "follow the OS" was the ONLY behaviour, and a user whose OS
//! is dark had no way to see the light panel — or the reverse. The console hit
//! exactly this and recorded it: a two-state toggle there became one-way, with
//! nothing in the UI able to return it to the OS. That is why the tray ships
//! three values and not two — `auto` is a value you can choose your way back to,
//! not merely the state you started in.
//!
//! 🔴 WHY THE CLI OWNS THIS AND NOT THE PAGE (spec T4b, 2026-09-06, superseding
//! T4 "no in-page switch"). The tray's simple view must keep working when
//! everything else is broken, so it is forbidden from persisting anything of its
//! own — no `localStorage`, and `sessionStorage` for the window size alone.
//! Storing the preference here keeps that ban intact AND gives the terminal and
//! the panel one shared memory, exactly as `display.language` already does.
//! The page's `auto` path is pure CSS (`prefers-color-scheme`) and needs no
//! JavaScript at all, so a dead poll or a thrown script degrades to "follow the
//! OS" rather than to an unreadable setting.
//!
//! Same shape as `display.language`, deliberately — one convention for "the
//! machine's default is usually right, but let me override it".

const DISPLAY_THEME_KEY: &str = "display.theme";

/// Themes the tray can render. `auto` follows the operating system.
pub const SUPPORTED: &[&str] = &["auto", "light", "dark"];

/// The stored preference, or "auto" when unset or unrecognised.
pub fn preference() -> String {
    match crate::storage::get_text_config(DISPLAY_THEME_KEY) {
        None => "auto".to_string(),
        Some(value) if SUPPORTED.contains(&value.as_str()) => value,
        Some(value) => {
            // Never silently fall back: an unreadable stored value is a fact the
            // user needs, or the override they set will look ignored.
            eprintln!(
                "[aikey] WARN: invalid display.theme '{}'; following the system theme",
                value
            );
            "auto".to_string()
        }
    }
}

pub fn set_preference(value: &str) -> Result<String, String> {
    let clean = value.trim().to_lowercase();
    if clean == "auto" || clean.is_empty() {
        // 🔴 `auto` is stored as the ABSENCE of the key, not as the string
        // "auto". The page's zero-JavaScript path is a CSS media query, and the
        // absent state is what every failure path falls back to; writing a value
        // for it would create a second way to mean "follow the OS", one of which
        // is only readable when the vault is.
        crate::storage::delete_text_config(DISPLAY_THEME_KEY)?;
        return Ok("auto".to_string());
    }
    if !SUPPORTED.contains(&clean.as_str()) {
        return Err(format!(
            "Invalid display theme '{}'. Supported: {}.",
            value,
            SUPPORTED.join(", ")
        ));
    }
    crate::storage::try_set_text_config(DISPLAY_THEME_KEY, &clean)?;
    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary HOME + vault path. `HomeVaultEnvGuard` holds the crate's env
    /// and vault mutexes for its lifetime, which is what serialises these tests
    /// against every other test that touches HOME or the vault.
    ///
    /// 🔴 Deliberately does NOT call `initialize_vault`: the whole point of
    /// storing the preference in the `config` table is that it needs no vault
    /// and no master password (spec T9's admission criteria). Testing on a bare
    /// temporary path is what proves that property rather than assuming it.
    fn isolated() -> (tempfile::TempDir, crate::test_env_lock::HomeVaultEnvGuard) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        let guard = crate::test_env_lock::HomeVaultEnvGuard::new(dir.path(), &db_path);
        (dir, guard)
    }

    #[test]
    fn unset_follows_the_system() {
        let (_dir, _guard) = isolated();
        assert_eq!(preference(), "auto");
    }

    #[test]
    fn works_with_no_vault_and_no_master_password() {
        let (_dir, _guard) = isolated();
        // Never initialised, never unlocked. If this ever starts failing, the
        // tray's CLI allowlist admission for `config theme` no longer holds.
        assert_eq!(set_preference("dark").unwrap(), "dark");
        assert_eq!(preference(), "dark");
    }

    #[test]
    fn an_explicit_choice_round_trips() {
        let (_dir, _guard) = isolated();
        assert_eq!(set_preference("light").unwrap(), "light");
        assert_eq!(preference(), "light");
        assert_eq!(set_preference("dark").unwrap(), "dark");
        assert_eq!(preference(), "dark");
    }

    #[test]
    fn auto_deletes_the_key_rather_than_storing_a_value() {
        let (_dir, _guard) = isolated();
        set_preference("dark").unwrap();
        assert_eq!(set_preference("auto").unwrap(), "auto");
        // The assertion that matters: `auto` must be the ABSENT state, so the
        // CSS media query is what answers and no stored string can disagree with
        // it. Reading the raw config back is the only way to tell "deleted"
        // apart from "stored the word auto".
        assert_eq!(crate::storage::get_text_config(DISPLAY_THEME_KEY), None);
        assert_eq!(preference(), "auto");
    }

    #[test]
    fn case_and_padding_are_normalised() {
        let (_dir, _guard) = isolated();
        assert_eq!(set_preference("  LIGHT  ").unwrap(), "light");
        assert_eq!(preference(), "light");
    }

    #[test]
    fn an_invalid_value_is_refused_and_writes_nothing() {
        let (_dir, _guard) = isolated();
        set_preference("dark").unwrap();
        let err = set_preference("solarized").unwrap_err();
        assert!(err.contains("solarized"), "error must name the bad value: {err}");
        assert!(
            err.contains("auto, light, dark"),
            "error must list what IS accepted, so the user's next step is in the message: {err}"
        );
        // A rejected write must not disturb the value already stored.
        assert_eq!(preference(), "dark");
    }

    #[test]
    fn an_unreadable_stored_value_falls_back_loudly() {
        let (_dir, _guard) = isolated();
        // Simulate a value written by a newer build, or hand-edited. preference()
        // must not silently pretend it is "auto" without saying so on stderr.
        crate::storage::try_set_text_config(DISPLAY_THEME_KEY, "solarized").unwrap();
        assert_eq!(preference(), "auto");
    }
}
