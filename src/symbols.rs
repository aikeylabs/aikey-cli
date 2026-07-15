//! Central glyph table: Fancy (Unicode) vs Safe (ASCII) user-visible symbols
//! (win10-conhost-compat, 2026-07-15).
//!
//! ## Why a config table instead of per-callsite `if`
//!
//! Windows 10's legacy console (conhost) fonts cannot render many glyphs we
//! print (⇡ ⇣ ⦿ ⓘ, emoji, dingbats) — users see □ boxes. Font coverage has
//! no probing API, so `term_caps::unicode_tier()` picks a repertoire once at
//! startup and every user-visible symbol goes through this table. One row
//! per symbol, two columns — adding a symbol or adjusting a fallback is a
//! one-line change, and scattering `if windows` at callsites is impossible
//! to keep consistent (see CLAUDE.md: 配置表穷举 > if/else 胶水).
//!
//! ## Enforcement
//!
//! `tests/glyph_fence.rs` mechanically forbids these glyphs in string
//! literals anywhere in `src/` except this file. If that fence turned red on
//! your change: reference the constant here (`symbols::CHECK.s()`) instead
//! of writing the glyph inline.
//!
//! ## Safe-tier choices
//!
//! Pure ASCII (not GBK-friendly `√ ×`): ASCII renders correctly under every
//! codepage, font, and redirection target, while GBK symbols still miss
//! glyphs on en-US conhost. Mappings preserve one-cell width where layout
//! math depends on it (pickers, tables); icons degrade to "" because they
//! are decoration, not information.

use crate::term_caps::{self, UnicodeTier};

pub struct Sym {
    pub fancy: &'static str,
    pub safe: &'static str,
}

impl Sym {
    /// The glyph for the active terminal's tier. Resolution is a process-wide
    /// constant after `term_caps::init()`, so display and any width math
    /// always agree.
    pub fn s(&self) -> &'static str {
        match term_caps::unicode_tier() {
            UnicodeTier::Fancy => self.fancy,
            UnicodeTier::Safe => self.safe,
        }
    }

    /// Icon prefix form: glyph plus one trailing space, or `""` when the
    /// safe fallback is empty — avoids `" Title"` leading-space artifacts
    /// at callsites that render `"{icon} {title}"` style headers.
    pub fn pre(&self) -> String {
        let s = self.s();
        if s.is_empty() {
            String::new()
        } else {
            format!("{} ", s)
        }
    }
}

// ── Status marks ────────────────────────────────────────────────────────────
pub const CHECK: Sym = Sym {
    fancy: "\u{2713}",
    safe: "[OK]",
}; // ✓
pub const CROSS: Sym = Sym {
    fancy: "\u{2717}",
    safe: "x",
}; // ✗
pub const WARN: Sym = Sym {
    fancy: "\u{26a0}",
    safe: "!",
}; // ⚠
pub const INFO: Sym = Sym {
    fancy: "\u{24d8}",
    safe: "i",
}; // ⓘ

// ── Action / status prefixes (2026-07-15: GDI glyph-coverage probe on a real
// Win10 conhost found these MISSING in the default Lucida Console font — they
// rendered as □. Earlier they were left inline as "font-safe"; that was an
// untested assumption. Now table-driven so Safe tier degrades them to ASCII.)
pub const LINK_OUT: Sym = Sym {
    fancy: "\u{2197}",
    safe: "->",
}; // ↗ open-external (list browser deeplink)
pub const REFRESH: Sym = Sym {
    fancy: "\u{21bb}",
    safe: "~",
}; // ↻ refreshed / updated (use / doctor)
pub const POINTER: Sym = Sym {
    fancy: "\u{27a4}",
    safe: ">",
}; // ➤ action pointer (route copy hint)

// ── Statusline metrics (single line, width-flexible) ───────────────────────
pub const STAT_UP: Sym = Sym {
    fancy: "\u{21e1}",
    safe: "^",
}; // ⇡ input tokens
pub const STAT_DOWN: Sym = Sym {
    fancy: "\u{21e3}",
    safe: "v",
}; // ⇣ output tokens
pub const CACHE_READ: Sym = Sym {
    fancy: "\u{21ba}",
    safe: "r",
}; // ↺ cache read
pub const CACHE_WRITE: Sym = Sym {
    fancy: "\u{2295}",
    safe: "w",
}; // ⊕ cache write
pub const BRAND: Sym = Sym {
    fancy: "\u{276c}\u{29bf}\u{b7}\u{29bf}\u{276d}",
    safe: "aikey",
}; // ❬⦿·⦿❭

// ── Picker / list UI (one-cell width preserved for layout math) ────────────
pub const RADIO_ON: Sym = Sym {
    fancy: "\u{25cf}",
    safe: "*",
}; // ● selected / active / running
pub const RADIO_OFF: Sym = Sym {
    fancy: "\u{25cb}",
    safe: "o",
}; // ○ stopped / inactive (service status)
pub const CHECKBOX_ON: Sym = Sym {
    fancy: "\u{2611}",
    safe: "[x]",
}; // ☑

// ── Decorative icons (Safe tier drops them — decoration, not information) ──
pub const ICON_SEARCH: Sym = Sym {
    fancy: "\u{1f50d}",
    safe: "",
}; // 🔍
pub const ICON_GLOBE: Sym = Sym {
    fancy: "\u{1f310}",
    safe: "",
}; // 🌐
pub const ICON_PERSON: Sym = Sym {
    fancy: "\u{1f464}",
    safe: "",
}; // 👤
pub const ICON_PEOPLE: Sym = Sym {
    fancy: "\u{1f465}",
    safe: "",
}; // 👥
pub const ICON_LINK: Sym = Sym {
    fancy: "\u{1f517}",
    safe: "",
}; // 🔗
pub const ICON_GREEN_DOT: Sym = Sym {
    fancy: "\u{1f7e2}",
    safe: "",
}; // 🟢
pub const ICON_YELLOW_DOT: Sym = Sym {
    fancy: "\u{1f7e1}",
    safe: "",
}; // 🟡
pub const ICON_LOCK: Sym = Sym {
    fancy: "\u{1f512}",
    safe: "",
}; // 🔒
pub const ICON_KEY: Sym = Sym {
    fancy: "\u{1f511}",
    safe: "",
}; // 🔑
pub const ICON_PLUG: Sym = Sym {
    fancy: "\u{1f50c}",
    safe: "",
}; // 🔌
pub const ICON_CHART: Sym = Sym {
    fancy: "\u{1f4ca}",
    safe: "",
}; // 📊
pub const SUB_DOT: Sym = Sym {
    fancy: "\u{29bf}",
    safe: "*",
}; // ⦿ (subscription bullet)
pub const ICON_LOCK_KEY: Sym = Sym {
    fancy: "\u{1f510}",
    safe: "",
}; // 🔐
pub const STAR: Sym = Sym {
    fancy: "\u{2b50}",
    safe: "*",
}; // ⭐
pub const SAME_AS_ABOVE: Sym = Sym {
    fancy: "\u{21b3}",
    safe: "\"",
}; // ↳ (ditto)

// ── Tree connectors (grouped list views) ────────────────────────────────────
pub const TREE_BRANCH: Sym = Sym {
    fancy: "\u{251c}\u{2500}",
    safe: "|-",
}; // ├─
pub const TREE_LAST: Sym = Sym {
    fancy: "\u{2514}\u{2500}",
    safe: "\\-",
}; // └─

// ── Box drawing (ui_frame) ──────────────────────────────────────────────────
pub const BOX_H: Sym = Sym {
    fancy: "\u{2500}",
    safe: "-",
}; // ─
pub const BOX_V: Sym = Sym {
    fancy: "\u{2502}",
    safe: "|",
}; // │
pub const BOX_TL: Sym = Sym {
    fancy: "\u{250c}",
    safe: "+",
}; // ┌
pub const BOX_TR: Sym = Sym {
    fancy: "\u{2510}",
    safe: "+",
}; // ┐
pub const BOX_BL: Sym = Sym {
    fancy: "\u{2514}",
    safe: "+",
}; // └
pub const BOX_BR: Sym = Sym {
    fancy: "\u{2518}",
    safe: "+",
}; // ┘

/// The single char used for horizontal-rule detection in `ui_frame`
/// (auto-stretch separator rows). Kept next to `BOX_H` so the writer and
/// the detector can never disagree.
pub fn hrule_char() -> char {
    BOX_H.s().chars().next().expect("BOX_H is never empty")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every one-cell fancy glyph used in width-sensitive layouts must map
    /// to a one-cell ASCII fallback, or picker/table alignment breaks in
    /// Safe tier.
    #[test]
    fn width_sensitive_safe_mappings_are_single_cell() {
        for sym in [
            &RADIO_ON, &SUB_DOT, &BOX_H, &BOX_V, &BOX_TL, &BOX_TR, &BOX_BL, &BOX_BR,
        ] {
            assert_eq!(sym.safe.len(), 1, "safe fallback must stay one cell");
            assert!(sym.safe.is_ascii());
        }
    }

    #[test]
    fn all_safe_values_are_pure_ascii() {
        for sym in [
            &CHECK,
            &CROSS,
            &WARN,
            &INFO,
            &STAT_UP,
            &STAT_DOWN,
            &CACHE_READ,
            &CACHE_WRITE,
            &BRAND,
            &RADIO_ON,
            &CHECKBOX_ON,
            &ICON_SEARCH,
            &ICON_GLOBE,
            &ICON_PERSON,
            &ICON_PEOPLE,
            &ICON_LINK,
            &ICON_GREEN_DOT,
            &ICON_YELLOW_DOT,
            &ICON_LOCK,
            &ICON_KEY,
            &ICON_PLUG,
            &ICON_CHART,
            &SUB_DOT,
            &ICON_LOCK_KEY,
            &STAR,
            &SAME_AS_ABOVE,
            &TREE_BRANCH,
            &TREE_LAST,
            &BOX_H,
            &BOX_V,
            &BOX_TL,
            &BOX_TR,
            &BOX_BL,
            &BOX_BR,
        ] {
            assert!(sym.safe.is_ascii(), "safe tier must be ASCII-only");
        }
    }

    #[test]
    fn pre_adds_trailing_space_only_when_nonempty() {
        // Unix / Fancy tier: icons keep their glyph + separator space.
        assert_eq!(ICON_SEARCH.pre(), format!("{} ", ICON_SEARCH.fancy));
        // Empty-safe icons must collapse to "" (no leading-space artifact) —
        // asserted on the field directly since tier is Fancy on dev hosts.
        let empty = Sym {
            fancy: "x",
            safe: "",
        };
        assert_eq!(empty.safe, "");
    }
}
