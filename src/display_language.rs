//! Display-language preference for AiKey's end-user surfaces.
//!
//! 🔴 SCOPE: this governs the DESKTOP TRAY's simple view only, per the
//! 2026-08-17 rule change in principles/code-and-ui-language.md. The console,
//! the CLI's own output, error codes and `--help` stay English — the tray is
//! the exception because its users are, by definition, people who do not use a
//! terminal.
//!
//! Why a stored preference at all, when the page already follows the operating
//! system: a developer on an English macOS cannot otherwise SEE the Chinese
//! build to check it, and a user whose OS language does not match how they read
//! has no way to say so. Same shape as `display.time_zone`, deliberately —
//! one convention for "the machine's default is usually right, but let me
//! override it".

const DISPLAY_LANGUAGE_KEY: &str = "display.language";

/// Languages the tray ships strings for. `auto` follows the operating system.
pub const SUPPORTED: &[&str] = &["auto", "en", "zh"];

/// The stored preference, or "auto" when unset or unrecognised.
pub fn preference() -> String {
    match crate::storage::get_text_config(DISPLAY_LANGUAGE_KEY) {
        None => "auto".to_string(),
        Some(value) if SUPPORTED.contains(&value.as_str()) => value,
        Some(value) => {
            // Never silently fall back: an unreadable stored value is a fact
            // the user needs, or the override they set will look ignored.
            eprintln!(
                "[aikey] WARN: invalid display.language '{}'; following the system language",
                value
            );
            "auto".to_string()
        }
    }
}

pub fn set_preference(value: &str) -> Result<String, String> {
    let clean = value.trim().to_lowercase();
    if clean == "auto" || clean.is_empty() {
        crate::storage::delete_text_config(DISPLAY_LANGUAGE_KEY)?;
        return Ok("auto".to_string());
    }
    if !SUPPORTED.contains(&clean.as_str()) {
        return Err(format!(
            "Invalid display language '{}'. Supported: {}.",
            value,
            SUPPORTED.join(", ")
        ));
    }
    crate::storage::try_set_text_config(DISPLAY_LANGUAGE_KEY, &clean)?;
    Ok(clean)
}
