//! The one place where the shared code asks the operating system to do something. The Windows
//! and Linux apps each provide an implementation of [`Platform`].

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// What to type into the window the user came from. Wiped when dropped.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct TypeJob {
    pub username: Option<String>,
    pub password: Option<String>,
}

pub trait Platform: Send + Sync + 'static {
    /// A blocking pop-up message (used for errors when there's no window of our own).
    fn message_box(&self, title: &str, text: &str, is_error: bool);

    /// Where saved passwords live when the app isn't portable and config.json doesn't say.
    fn default_data_dir(&self) -> PathBuf;

    /// A per-user folder for config.json / theme.json (Linux), or `None` to keep them beside
    /// the program (Windows).
    fn user_config_dir(&self) -> Option<PathBuf>;

    /// File name of the core library next to the program.
    fn core_library_name(&self) -> &'static str;

    fn daemon_running(&self) -> bool;
    fn start_daemon(&self);
    fn stop_daemon(&self) -> bool;
    fn restart_daemon(&self);

    fn autostart_enabled(&self) -> bool;
    fn set_autostart(&self, enable: bool) -> Result<(), String>;

    fn open_folder(&self, path: &Path);

    /// Brings `target` (the window the user came from) to the front and types the job into it.
    /// Must type nothing if focus can't be restored.
    fn deliver(&self, target: usize, job: &TypeJob);

    /// The background process: owns the global hotkeys and launches the popups. Never returns
    /// until the process is asked to quit.
    fn run_daemon(&self);

    /// Called just before a popup window is launched.
    fn before_popup(&self) {}
}

static PLATFORM: OnceLock<Box<dyn Platform>> = OnceLock::new();

pub fn set_platform(platform: Box<dyn Platform>) {
    let _ = PLATFORM.set(platform);
}

/// The current operating system's implementation. `ipassword_shared::run` sets it first thing.
pub fn platform() -> &'static dyn Platform {
    PLATFORM
        .get()
        .expect("the platform is set at startup by ipassword_shared::run")
        .as_ref()
}
