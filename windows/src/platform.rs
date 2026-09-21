//! Connects the shared code to Windows.

use std::path::{Path, PathBuf};

use ipassword_shared::paths;
use ipassword_shared::platform::{Platform, TypeJob};

pub struct WindowsPlatform;

impl Platform for WindowsPlatform {
    fn message_box(&self, title: &str, text: &str, is_error: bool) {
        crate::win::message_box(title, text, is_error);
    }

    fn default_data_dir(&self) -> PathBuf {
        match std::env::var_os("APPDATA") {
            Some(appdata) => PathBuf::from(appdata).join("IPassword"),
            None => paths::exe_dir().join("IPasswordData"),
        }
    }

    fn user_config_dir(&self) -> Option<PathBuf> {
        // config.json and theme.json sit beside the program on Windows.
        None
    }

    fn core_library_name(&self) -> &'static str {
        "ipassword_core.dll"
    }

    fn daemon_running(&self) -> bool {
        crate::win::daemon_window().is_some()
    }

    fn start_daemon(&self) {
        crate::win::start_daemon();
    }

    fn stop_daemon(&self) -> bool {
        crate::win::stop_daemon()
    }

    fn restart_daemon(&self) {
        crate::win::restart_daemon();
    }

    fn autostart_enabled(&self) -> bool {
        crate::win::autostart_enabled()
    }

    fn set_autostart(&self, enable: bool) -> Result<(), String> {
        crate::win::set_autostart(enable)
    }

    fn open_folder(&self, path: &Path) {
        crate::win::open_folder(path);
    }

    fn deliver(&self, target: usize, job: &TypeJob) {
        crate::win::deliver(target, job);
    }

    fn run_daemon(&self) {
        crate::daemon::run();
    }

    fn before_popup(&self) {
        crate::win::allow_foreground_switch();
    }
}
