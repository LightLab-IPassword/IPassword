//! Hotkeys and the user-editable settings file (`config.json`).
//! Pure Rust with no Win32, so it is unit-tested on any platform.
#![cfg_attr(not(windows), allow(dead_code))]

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const MOD_ALT: u32 = 0x0001;
pub const MOD_CONTROL: u32 = 0x0002;
pub const MOD_SHIFT: u32 = 0x0004;
pub const MOD_WIN: u32 = 0x0008;
pub const MOD_NOREPEAT: u32 = 0x4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hotkey {
    pub mods: u32,
    pub vk: u32,
}

impl Hotkey {
    /// Parses things like "Alt+C", "ctrl + shift + F5", "Win+7". At least one modifier is required.
    pub fn parse(text: &str) -> Result<Hotkey, String> {
        let mut mods = 0u32;
        let mut key: Option<u32> = None;
        for raw in text.split('+') {
            let token = raw.trim().to_ascii_lowercase();
            if token.is_empty() {
                return Err("empty part in hotkey".into());
            }
            match token.as_str() {
                "alt" => mods |= MOD_ALT,
                "ctrl" | "control" => mods |= MOD_CONTROL,
                "shift" => mods |= MOD_SHIFT,
                "win" | "windows" | "super" => mods |= MOD_WIN,
                other => {
                    if key.is_some() {
                        return Err("only one non-modifier key is allowed".into());
                    }
                    key = Some(parse_key(other)?);
                }
            }
        }
        let vk = key.ok_or_else(|| "missing key (e.g. Alt+C)".to_string())?;
        if mods == 0 {
            return Err("needs at least one modifier (Alt, Ctrl, Shift or Win)".into());
        }
        Ok(Hotkey { mods, vk })
    }

    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.mods & MOD_CONTROL != 0 {
            parts.push("Ctrl".into());
        }
        if self.mods & MOD_ALT != 0 {
            parts.push("Alt".into());
        }
        if self.mods & MOD_SHIFT != 0 {
            parts.push("Shift".into());
        }
        if self.mods & MOD_WIN != 0 {
            parts.push("Win".into());
        }
        parts.push(match self.vk {
            0x30..=0x39 | 0x41..=0x5A => char::from(self.vk as u8).to_string(),
            0x70..=0x87 => format!("F{}", self.vk - 0x70 + 1),
            other => format!("0x{other:02X}"),
        });
        parts.join("+")
    }
}

fn parse_key(token: &str) -> Result<u32, String> {
    let bytes = token.as_bytes();
    if bytes.len() == 1 {
        return match bytes[0] {
            b'a'..=b'z' => Ok(u32::from(bytes[0] - b'a') + 0x41),
            b'0'..=b'9' => Ok(u32::from(bytes[0])),
            _ => Err(format!("unsupported key '{token}'")),
        };
    }
    if let Some(n) = token.strip_prefix('f').and_then(|n| n.parse::<u32>().ok()) {
        if (1..=24).contains(&n) {
            return Ok(0x70 + n - 1);
        }
    }
    Err(format!("unsupported key '{token}' (use A-Z, 0-9 or F1-F24)"))
}

/// The contents of `config.json`. Every field is optional; missing ones use these defaults.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub capture_hotkey: String,
    pub paste_hotkey: String,
    /// Paste window closes itself after this many idle seconds once unlocked.
    pub paste_idle_seconds: u64,
    /// Sign-in screens close themselves after this many idle seconds.
    pub idle_seconds: u64,
    /// If set, ipassword_core.dll is only loaded when its SHA-256 matches this hex string.
    pub core_dll_sha256: Option<String>,
    /// Where vaults are stored. Supports %ENV% variables. Empty/null = automatic.
    pub data_dir: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            capture_hotkey: "Alt+C".into(),
            paste_hotkey: "Alt+V".into(),
            paste_idle_seconds: 45,
            idle_seconds: 120,
            core_dll_sha256: None,
            data_dir: None,
        }
    }
}

impl Config {
    /// Missing or unreadable files fall back to defaults instead of failing.
    pub fn load(path: &Path) -> Config {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fs::write(path, json)
    }

    pub fn hotkeys(&self) -> Result<(Hotkey, Hotkey), String> {
        let capture =
            Hotkey::parse(&self.capture_hotkey).map_err(|e| format!("Capture hotkey: {e}"))?;
        let paste = Hotkey::parse(&self.paste_hotkey).map_err(|e| format!("Paste hotkey: {e}"))?;
        if capture == paste {
            return Err("The two hotkeys must be different.".into());
        }
        Ok((capture, paste))
    }
}

/// Replaces `%NAME%` with the environment variable's value. Unknown names are left as-is.
pub fn expand_env(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) if !name.is_empty() => out.push_str(&value),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_hotkeys() {
        assert_eq!(
            Hotkey::parse("alt+c").unwrap(),
            Hotkey { mods: MOD_ALT, vk: 0x43 }
        );
        assert_eq!(
            Hotkey::parse(" Ctrl + Shift + F5 ").unwrap(),
            Hotkey { mods: MOD_CONTROL | MOD_SHIFT, vk: 0x74 }
        );
        assert_eq!(
            Hotkey::parse("Win+7").unwrap(),
            Hotkey { mods: MOD_WIN, vk: 0x37 }
        );
    }

    #[test]
    fn rejects_bad_hotkeys() {
        for bad in ["", "c", "alt", "alt+", "alt+ctrl", "alt+ab", "alt+f25", "alt+c+v", "alt+!"] {
            assert!(Hotkey::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn describe_round_trips() {
        for text in ["Alt+C", "Ctrl+Shift+F5", "Win+7", "Ctrl+Alt+Z"] {
            assert_eq!(Hotkey::parse(text).unwrap().describe(), text);
        }
    }

    #[test]
    fn defaults_are_valid_and_distinct() {
        let (capture, paste) = Config::default().hotkeys().unwrap();
        assert_eq!(capture.describe(), "Alt+C");
        assert_eq!(paste.describe(), "Alt+V");

        let same = Config {
            paste_hotkey: "alt+c".into(),
            ..Config::default()
        };
        assert!(same.hotkeys().is_err());
    }

    #[test]
    fn load_handles_missing_partial_and_broken_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        assert_eq!(Config::load(&path).capture_hotkey, "Alt+C");

        fs::write(&path, r#"{ "paste_hotkey": "Ctrl+Alt+V" }"#).unwrap();
        let cfg = Config::load(&path);
        assert_eq!(cfg.paste_hotkey, "Ctrl+Alt+V");
        assert_eq!(cfg.capture_hotkey, "Alt+C");

        fs::write(&path, "{ not json").unwrap();
        assert_eq!(Config::load(&path).paste_hotkey, "Alt+V");
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let cfg = Config {
            capture_hotkey: "Ctrl+Shift+K".into(),
            core_dll_sha256: Some("abc".into()),
            ..Config::default()
        };
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path);
        assert_eq!(loaded.capture_hotkey, "Ctrl+Shift+K");
        assert_eq!(loaded.core_dll_sha256.as_deref(), Some("abc"));
    }

    #[test]
    fn expands_environment_variables() {
        std::env::set_var("IPW_TEST_EXPAND_VAR", "value");
        assert_eq!(expand_env("%IPW_TEST_EXPAND_VAR%\\x"), "value\\x");
        assert_eq!(expand_env("a%IPW_DOES_NOT_EXIST_1%b"), "a%IPW_DOES_NOT_EXIST_1%b");
        assert_eq!(expand_env("100%"), "100%");
        assert_eq!(expand_env("plain"), "plain");
    }
}
