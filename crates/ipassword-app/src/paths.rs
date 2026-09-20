//! Where things live. The install (or portable) folder holds the program, DLLs, config.json,
//! theme.json and assets; vaults live in a separate data folder.

use std::env;
use std::path::PathBuf;

use crate::config::{expand_env, Config};

const PORTABLE_DIR: &str = "IPasswordData";

pub fn exe_path() -> PathBuf {
    env::current_exe().unwrap_or_else(|_| PathBuf::from("IPassword.exe"))
}

pub fn exe_dir() -> PathBuf {
    exe_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default()
}

pub fn config_path() -> PathBuf {
    exe_dir().join("config.json")
}

pub fn theme_path() -> PathBuf {
    exe_dir().join("theme.json")
}

/// True when an `IPasswordData` folder sits next to the program (the portable layout).
pub fn is_portable() -> bool {
    exe_dir().join(PORTABLE_DIR).is_dir()
}

/// Vault folder, in order of priority:
/// 1. `data_dir` from config.json (relative paths are relative to the program folder),
/// 2. `IPasswordData` next to the program (portable),
/// 3. `%APPDATA%\IPassword`.
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
    match env::var_os("APPDATA") {
        Some(appdata) => PathBuf::from(appdata).join("IPassword"),
        None => portable,
    }
}
