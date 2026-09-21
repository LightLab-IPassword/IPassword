//! Where things live. The install (or portable) folder holds the program, the core library,
//! config.json, theme.json and assets; saved passwords live in a separate data folder.

use std::env;
use std::fs;
use std::path::PathBuf;

use crate::config::{expand_env, Config};
use crate::platform::platform;

const PORTABLE_DIR: &str = "IPasswordData";

pub fn exe_path() -> PathBuf {
    env::current_exe().unwrap_or_else(|_| PathBuf::from("ipassword"))
}

pub fn exe_dir() -> PathBuf {
    exe_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default()
}

/// True when an `IPasswordData` folder sits next to the program (the portable layout).
pub fn is_portable() -> bool {
    exe_dir().join(PORTABLE_DIR).is_dir()
}

/// A per-user copy of a settings file (Linux). Portable installs never use it: they stay
/// self-contained.
fn user_file(name: &str) -> Option<PathBuf> {
    if is_portable() {
        return None;
    }
    platform().user_config_dir().map(|dir| dir.join(name))
}

fn read_path(name: &str) -> PathBuf {
    match user_file(name) {
        Some(path) if path.is_file() => path,
        _ => exe_dir().join(name),
    }
}

/// The config.json to read: the per-user one if it exists, otherwise the one beside the program.
pub fn config_path() -> PathBuf {
    read_path("config.json")
}

/// The theme.json to read (same rule as config.json).
pub fn theme_path() -> PathBuf {
    read_path("theme.json")
}

/// Where the settings window saves config.json: the per-user folder when there is one (so a
/// system-wide install doesn't need write access), otherwise beside the program.
pub fn config_write_path() -> PathBuf {
    match user_file("config.json") {
        Some(path) => {
            if let Some(dir) = path.parent() {
                let _ = fs::create_dir_all(dir);
            }
            path
        }
        None => exe_dir().join("config.json"),
    }
}

/// Vault folder, in order of priority:
/// 1. `data_dir` from config.json (relative paths are relative to the program folder),
/// 2. `IPasswordData` next to the program (portable),
/// 3. the platform default (`%APPDATA%\IPassword`, or `~/.local/share/ipassword`).
pub fn data_dir() -> PathBuf {
    let config = Config::load(&config_path());
    if let Some(custom) = config
        .data_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let path = PathBuf::from(expand_env(custom));
        return if path.is_absolute() {
            path
        } else {
            exe_dir().join(path)
        };
    }
    let portable = exe_dir().join(PORTABLE_DIR);
    if portable.is_dir() {
        return portable;
    }
    platform().default_data_dir()
}
