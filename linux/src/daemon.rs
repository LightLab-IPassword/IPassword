//! The background process on Linux (X11): grabs the two hotkeys and launches the popup windows.
//! It never handles the master password; the popups it launches do.

use std::fs;
use std::path::PathBuf;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use ipassword_shared::config::{Config, Hotkey};
use ipassword_shared::platform::platform;
use ipassword_shared::{paths, popup};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, GrabMode, ModMask};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use zeroize::Zeroizing;

use crate::{keys, tools};

#[derive(Clone, Copy)]
enum Action {
    Capture,
    Paste,
}

struct Grab {
    action: Action,
    keycode: u8,
    mods: u16,
    /// Every key that has to be let go of before we inject keystrokes.
    release_codes: Vec<u8>,
}

fn pidfile() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("ipassword-daemon.pid")
}

/// The process id of a running background process, if there is one. A stale pid file (left after
/// a crash) is ignored: the process must exist and really be called `ipassword`.
pub fn running_pid() -> Option<u32> {
    let pid: u32 = fs::read_to_string(pidfile()).ok()?.trim().parse().ok()?;
    let name = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    if name.trim() == "ipassword" {
        Some(pid)
    } else {
        None
    }
}

fn describe<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Asks the X server to deliver the hotkeys to us, even when Caps Lock or Num Lock is on.
fn grab_hotkeys(
    conn: &RustConnection,
    root: u32,
    capture: Hotkey,
    paste: Hotkey,
) -> Result<Vec<Grab>, String> {
    let setup = conn.setup();
    let (min, max) = (setup.min_keycode, setup.max_keycode);
    let mapping = conn
        .get_keyboard_mapping(min, max - min + 1)
        .map_err(describe)?
        .reply()
        .map_err(describe)?;
    let per = mapping.keysyms_per_keycode as usize;
    let code_of = |keysym: u32| keys::keycode_for(&mapping.keysyms, per, min, keysym);

    let mut grabs = Vec::new();
    for (action, hotkey) in [(Action::Capture, capture), (Action::Paste, paste)] {
        let keysym = keys::keysym_from_vk(hotkey.vk)
            .ok_or_else(|| format!("The hotkey {} isn't supported on Linux.", hotkey.describe()))?;
        let keycode = code_of(keysym).ok_or_else(|| {
            format!("Your keyboard layout has no key for {}.", hotkey.describe())
        })?;
        let mods = keys::x_modifiers(hotkey.mods);

        for extra in [0, keys::X_LOCK, keys::X_MOD2, keys::X_LOCK | keys::X_MOD2] {
            conn.grab_key(
                true,
                root,
                ModMask::from(mods | extra),
                keycode,
                GrabMode::ASYNC,
                GrabMode::ASYNC,
            )
            .map_err(describe)?
            .check()
            .map_err(|_| {
                format!(
                    "Couldn't claim {}. Another program is probably using it.",
                    hotkey.describe()
                )
            })?;
        }

        let mut release_codes = vec![keycode];
        for keysym in keys::modifier_keysyms(hotkey.mods) {
            if let Some(code) = code_of(keysym) {
                release_codes.push(code);
            }
        }
        grabs.push(Grab {
            action,
            keycode,
            mods,
            release_codes,
        });
    }
    conn.flush().map_err(describe)?;
    Ok(grabs)
}

/// Waits (up to about a second) for the user to let go of the hotkey, so injected keystrokes
/// aren't mixed up with keys that are still held.
fn wait_for_release(conn: &RustConnection, codes: &[u8]) {
    let deadline = Instant::now() + Duration::from_millis(1200);
    loop {
        let held = conn
            .query_keymap()
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| {
                codes
                    .iter()
                    .any(|&code| reply.keys[usize::from(code / 8)] & (1 << (code % 8)) != 0)
            })
            .unwrap_or(false);
        if !held || Instant::now() > deadline {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn open_popup(child: &mut Option<Child>, mode: &str, target: usize, data: Option<&str>) {
    match popup::spawn(mode, target, data) {
        Ok(started) => *child = Some(started),
        Err(e) => platform().message_box(
            "IPassword",
            &format!("Couldn't open the window: {e}"),
            true,
        ),
    }
}

pub fn run() {
    if running_pid().is_some() {
        return;
    }

    let config = Config::load(&paths::config_path());
    let (capture, paste) = match config.hotkeys() {
        Ok(pair) => pair,
        Err(e) => {
            platform().message_box(
                "IPassword",
                &format!("{e}\n\nFix the hotkeys in config.json or in the IPassword window."),
                true,
            );
            return;
        }
    };

    let (conn, screen) = match RustConnection::connect(None) {
        Ok(pair) => pair,
        Err(_) => {
            platform().message_box(
                "IPassword",
                "Couldn't connect to the X server. The hotkeys need an X11 session (or XWayland).",
                true,
            );
            return;
        }
    };
    let root = conn.setup().roots[screen].root;
    let grabs = match grab_hotkeys(&conn, root, capture, paste) {
        Ok(grabs) => grabs,
        Err(message) => {
            platform().message_box("IPassword", &message, true);
            return;
        }
    };
    let _ = fs::write(pidfile(), std::process::id().to_string());

    let mut child: Option<Child> = None;
    loop {
        let event = match conn.wait_for_event() {
            Ok(event) => event,
            Err(_) => break,
        };
        let Event::KeyPress(press) = event else {
            continue;
        };
        let state = keys::ignoring_lock_bits(u16::from(press.state));
        let Some(grab) = grabs
            .iter()
            .find(|g| g.keycode == press.detail && g.mods == state)
        else {
            continue;
        };
        if popup::is_running(&mut child) {
            continue;
        }

        let target = tools::active_window().unwrap_or(0);
        wait_for_release(&conn, &grab.release_codes);
        match grab.action {
            Action::Capture => {
                let selected = tools::capture_selection(target).map(Zeroizing::new);
                let data: &str = selected.as_deref().map(|s| s.as_str()).unwrap_or("");
                open_popup(&mut child, "popup-capture", target, Some(data));
            }
            Action::Paste => open_popup(&mut child, "popup-paste", target, None),
        }
    }
    let _ = fs::remove_file(pidfile());
}
