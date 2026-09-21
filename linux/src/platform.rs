//! Connects the shared code to Linux (X11).

use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ipassword_shared::paths;
use ipassword_shared::platform::{Platform, TypeJob};

use crate::{daemon, tools};

pub struct LinuxPlatform;

fn home() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

/// `$XDG_CONFIG_HOME`, or `~/.config`.
fn config_home() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home().map(|h| h.join(".config")))
}

/// `$XDG_DATA_HOME`, or `~/.local/share`.
fn data_home() -> Option<PathBuf> {
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home().map(|h| h.join(".local").join("share")))
}

fn autostart_path() -> Option<PathBuf> {
    config_home().map(|dir| dir.join("autostart").join("ipassword.desktop"))
}

/// The autostart entry that runs the background process at sign-in.
fn desktop_entry(exe: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=IPassword\nComment=Password manager background process\nExec=\"{}\" --daemon\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        exe.display()
    )
}

fn run_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

impl Platform for LinuxPlatform {
    fn message_box(&self, title: &str, text: &str, is_error: bool) {
        let zenity_flag = if is_error { "--error" } else { "--info" };
        if run_ok("zenity", &[zenity_flag, "--title", title, "--text", text]) {
            return;
        }
        let kdialog_flag = if is_error { "--error" } else { "--msgbox" };
        if run_ok("kdialog", &[kdialog_flag, text, "--title", title]) {
            return;
        }
        if run_ok("xmessage", &["-center", text]) {
            return;
        }
        eprintln!("{title}: {text}");
    }

    fn default_data_dir(&self) -> PathBuf {
        match data_home() {
            Some(dir) => dir.join("ipassword"),
            None => paths::exe_dir().join("IPasswordData"),
        }
    }

    fn user_config_dir(&self) -> Option<PathBuf> {
        config_home().map(|dir| dir.join("ipassword"))
    }

    fn core_library_name(&self) -> &'static str {
        "libipassword_core.so"
    }

    fn daemon_running(&self) -> bool {
        daemon::running_pid().is_some()
    }

    fn start_daemon(&self) {
        // Its own process group, so closing a terminal or the main window doesn't take it along.
        let _ = Command::new(paths::exe_path())
            .arg("--daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn();
    }

    fn stop_daemon(&self) -> bool {
        match daemon::running_pid() {
            Some(pid) => run_ok("kill", &[&pid.to_string()]),
            None => false,
        }
    }

    fn restart_daemon(&self) {
        self.stop_daemon();
        let start = Instant::now();
        while self.daemon_running() && start.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(50));
        }
        self.start_daemon();
    }

    fn autostart_enabled(&self) -> bool {
        autostart_path().map(|p| p.is_file()).unwrap_or(false)
    }

    fn set_autostart(&self, enable: bool) -> Result<(), String> {
        let path = autostart_path().ok_or_else(|| "Couldn't find your config folder.".to_string())?;
        if enable {
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir).map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?;
            }
            fs::write(&path, desktop_entry(&paths::exe_path()))
                .map_err(|e| format!("Couldn't write {}: {e}", path.display()))
        } else {
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("Couldn't remove {}: {e}", path.display())),
            }
        }
    }

    fn open_folder(&self, path: &Path) {
        let _ = fs::create_dir_all(path);
        let _ = Command::new("xdg-open")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }

    /// Types the job into `target`, but only if `target` really is the window in front. If focus
    /// can't be restored we type nothing rather than risk putting a password in the wrong place.
    fn deliver(&self, target: usize, job: &TypeJob) {
        if target == 0 {
            self.message_box(
                "IPassword",
                "IPassword couldn't tell which window to type into, so nothing was typed.",
                true,
            );
            return;
        }
        thread::sleep(Duration::from_millis(120));
        tools::activate(target);
        let start = Instant::now();
        while tools::active_window() != Some(target) {
            if start.elapsed() > Duration::from_millis(1500) {
                self.message_box(
                    "IPassword",
                    "IPassword couldn't return to the window you came from, so nothing was typed.",
                    true,
                );
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        thread::sleep(Duration::from_millis(80));

        if let Some(username) = &job.username {
            tools::type_text(username);
        }
        if job.username.is_some() && job.password.is_some() {
            tools::press_tab();
        }
        if let Some(password) = &job.password {
            tools::type_text(password);
        }
    }

    fn run_daemon(&self) {
        daemon::run();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_entry_launches_the_background_process() {
        let entry = desktop_entry(Path::new("/opt/ipassword/ipassword"));
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert!(entry.contains("Exec=\"/opt/ipassword/ipassword\" --daemon\n"));
        assert!(entry.contains("Type=Application"));
    }
}
