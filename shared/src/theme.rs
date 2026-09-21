//! The user-editable look (`theme.json`). Pure Rust so it is unit-tested anywhere;
//! `ui/common.rs` turns it into egui styling.
#![cfg_attr(not(windows), allow(dead_code))]

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Colors are "#RRGGBB" strings. Every field is optional; missing or invalid ones fall back
/// to the defaults below (dark slate with an amber accent).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Theme {
    pub background: String,
    pub panel: String,
    pub input: String,
    pub text: String,
    pub muted: String,
    pub accent: String,
    pub accent_text: String,
    pub button: String,
    pub button_hover: String,
    pub danger: String,
    pub ok: String,
    pub rounding: f32,
    pub font_size: f32,
    pub spacing: f32,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            background: "#0F172A".into(),
            panel: "#1E293B".into(),
            input: "#0B1220".into(),
            text: "#E5E7EB".into(),
            muted: "#94A3B8".into(),
            accent: "#F5A524".into(),
            accent_text: "#1E293B".into(),
            button: "#334155".into(),
            button_hover: "#475569".into(),
            danger: "#F87171".into(),
            ok: "#4ADE80".into(),
            rounding: 8.0,
            font_size: 15.0,
            spacing: 8.0,
        }
    }
}

impl Theme {
    pub fn load(path: &Path) -> Theme {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
}

/// "#RRGGBB" (or "RRGGBB") to [r, g, b].
pub fn parse_hex(text: &str) -> Option<[u8; 3]> {
    let hex = text.trim().trim_start_matches('#');
    if hex.len() != 6 || !hex.is_ascii() {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_colors() {
        assert_eq!(parse_hex("#F5A524"), Some([245, 165, 36]));
        assert_eq!(parse_hex("  1e293b "), Some([30, 41, 59]));
        for bad in ["", "#12345", "#GGGGGG", "#1234567", "red"] {
            assert_eq!(parse_hex(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn defaults_are_valid_colors() {
        let t = Theme::default();
        for c in [
            &t.background, &t.panel, &t.input, &t.text, &t.muted, &t.accent, &t.accent_text,
            &t.button, &t.button_hover, &t.danger, &t.ok,
        ] {
            assert!(parse_hex(c).is_some(), "{c}");
        }
    }

    #[test]
    fn partial_and_broken_files_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("theme.json");
        assert_eq!(Theme::load(&path).accent, "#F5A524");

        fs::write(&path, r##"{ "accent": "#00FF88", "rounding": 2.5 }"##).unwrap();
        let t = Theme::load(&path);
        assert_eq!(t.accent, "#00FF88");
        assert_eq!(t.rounding, 2.5);
        assert_eq!(t.background, "#0F172A");

        fs::write(&path, "nope").unwrap();
        assert_eq!(Theme::load(&path).accent, "#F5A524");
    }
}
