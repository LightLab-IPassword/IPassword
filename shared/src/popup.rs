//! Launching the small popup windows. Each popup is a separate short-lived process, so secrets
//! it handles vanish from memory when it exits.

use std::io::Write;
use std::process::{Child, Command, Stdio};

use crate::paths;
use crate::platform::platform;

/// Starts `<this program> <mode> --target <window>`. `stdin_data` is piped in (used to hand the
/// captured text to the save window without putting it on a command line, where other users'
/// programs could read it).
pub fn spawn(mode: &str, target: usize, stdin_data: Option<&str>) -> std::io::Result<Child> {
    platform().before_popup();
    let mut command = Command::new(paths::exe_path());
    command.arg(mode).arg("--target").arg(target.to_string());
    command.stdin(if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn()?;
    if let (Some(data), Some(mut stdin)) = (stdin_data, child.stdin.take()) {
        let _ = stdin.write_all(data.as_bytes());
        // `stdin` is dropped here, which closes the pipe so the popup sees end-of-input.
    }
    Ok(child)
}

/// True while the popup in `slot` is still open, so a second hotkey press doesn't stack another.
/// Clears the slot once the popup has exited.
pub fn is_running(slot: &mut Option<Child>) -> bool {
    if let Some(child) = slot.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return true;
        }
    }
    *slot = None;
    false
}
