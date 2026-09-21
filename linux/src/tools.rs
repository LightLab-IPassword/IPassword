//! Talking to X11 through two small, ubiquitous programs: `xdotool` (windows and typing) and
//! `xclip` (clipboard).
//!
//! Secrets are only ever passed on standard input, never as command-line arguments, because other
//! users' programs can read another process's arguments.

use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Runs a program and returns its standard output, or `None` if it failed or isn't installed.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_quiet(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Runs a program, feeds `input` to its standard input, and waits for it to finish.
fn run_with_stdin(program: &str, args: &[&str], input: &str) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// The window that currently has keyboard focus.
pub fn active_window() -> Option<usize> {
    output("xdotool", &["getactivewindow"])?.trim().parse().ok()
}

/// Lower-cased application class of a window, e.g. "gnome-terminal-server".
pub fn window_class(id: usize) -> String {
    output("xdotool", &["getwindowclassname", &id.to_string()])
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

/// Terminals treat Ctrl+C as "interrupt", so we never send it to them.
pub fn is_terminal_class(class: &str) -> bool {
    const TERMINALS: [&str; 20] = [
        "xterm",
        "uxterm",
        "urxvt",
        "rxvt",
        "st",
        "st-256color",
        "alacritty",
        "kitty",
        "wezterm",
        "foot",
        "tilix",
        "terminator",
        "konsole",
        "yakuake",
        "guake",
        "terminology",
        "lxterminal",
        "xfce4-terminal",
        "mate-terminal",
        "gnome-terminal-server",
    ];
    TERMINALS.contains(&class) || class.contains("terminal")
}

pub fn activate(id: usize) {
    let _ = run_quiet("xdotool", &["windowactivate", "--sync", &id.to_string()]);
}

/// Sends Ctrl+C. `--clearmodifiers` temporarily releases keys still held from the hotkey.
pub fn send_ctrl_c() {
    let _ = run_quiet("xdotool", &["key", "--clearmodifiers", "ctrl+c"]);
}

pub fn press_tab() {
    let _ = run_quiet("xdotool", &["key", "--clearmodifiers", "Tab"]);
}

/// Types text into the focused window. The text travels on stdin, not on the command line.
pub fn type_text(text: &str) -> bool {
    run_with_stdin(
        "xdotool",
        &["type", "--clearmodifiers", "--delay", "6", "--file", "-"],
        text,
    )
}

pub fn read_clipboard() -> Option<String> {
    output("xclip", &["-selection", "clipboard", "-o"])
}

pub fn write_clipboard(text: &str) -> bool {
    run_with_stdin("xclip", &["-selection", "clipboard", "-i"], text)
}

/// Copies whatever is selected in `target` by sending Ctrl+C and reads it, then puts the user's
/// previous clipboard text back. To notice that a copy happened even when the selection equals
/// the old clipboard, the clipboard is first set to a unique marker.
pub fn capture_selection(target: usize) -> Option<String> {
    if target == 0 || is_terminal_class(&window_class(target)) {
        return None;
    }
    let previous = read_clipboard();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let marker = format!("ipassword-capture-{stamp}");
    if !write_clipboard(&marker) {
        return None;
    }

    send_ctrl_c();

    let mut captured = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(700) {
        thread::sleep(Duration::from_millis(40));
        if let Some(text) = read_clipboard() {
            if text != marker {
                captured = Some(text);
                break;
            }
        }
    }

    // Put the clipboard back (or clear it if it held something other than text).
    match &previous {
        Some(text) => {
            write_clipboard(text);
        }
        None => {
            write_clipboard("");
        }
    }

    // A password is short. Anything huge is a normal text selection, not something to save.
    captured.filter(|s| !s.is_empty() && s.len() <= 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_terminal_windows() {
        for class in ["xterm", "alacritty", "kitty", "konsole", "gnome-terminal-server", "foot"] {
            assert!(is_terminal_class(class), "{class}");
        }
        // Anything with "terminal" in the name counts too.
        assert!(is_terminal_class("some-new-terminal"));
    }

    #[test]
    fn ordinary_windows_are_not_terminals() {
        for class in ["firefox", "chromium", "gedit", "code", "nautilus", ""] {
            assert!(!is_terminal_class(class), "{class:?}");
        }
    }
}
