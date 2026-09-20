//! Direct Win32 calls: keyboard injection, clipboard, foreground window, registry autostart and
//! control of the background process. Together with daemon.rs and core_dll.rs, this is where
//! all of the app's `unsafe` lives.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};
use std::{mem, ptr, thread};

use winapi::shared::minwindef::{DWORD, HKEY, UINT};
use winapi::shared::windef::HWND;
use winapi::um::winbase::{GlobalAlloc, GlobalFree, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
use winapi::um::winnt::{KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ};
use winapi::um::winreg::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY_CURRENT_USER,
};
use winapi::um::winuser::{
    AllowSetForegroundWindow, CloseClipboard, EmptyClipboard, FindWindowW, GetAsyncKeyState,
    GetClassNameW, GetClipboardData, GetClipboardSequenceNumber, GetForegroundWindow, IsWindow,
    MessageBoxW, OpenClipboard, PostMessageW, SendInput, SetClipboardData, SetForegroundWindow,
    CF_UNICODETEXT, INPUT, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    MB_ICONERROR, MB_ICONINFORMATION, MB_OK, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
    VK_TAB, WM_CLOSE,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{Hotkey, MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN};
use crate::paths;

pub const DAEMON_CLASS: &str = "IPasswordDaemonWnd";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "IPassword";

/// What to type into the window the user came from. Wiped when dropped.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct TypeJob {
    pub username: Option<String>,
    pub password: Option<String>,
}

pub fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn message_box(title: &str, text: &str, is_error: bool) {
    let t = wide(title);
    let m = wide(text);
    let icon = if is_error { MB_ICONERROR } else { MB_ICONINFORMATION };
    unsafe {
        MessageBoxW(ptr::null_mut(), m.as_ptr(), t.as_ptr(), MB_OK | icon);
    }
}

/// The window that currently has keyboard focus, as a number (0 if none).
pub fn foreground() -> usize {
    unsafe { GetForegroundWindow() as usize }
}

/// Lets the next process we start bring its window to the front.
pub fn allow_foreground_switch() {
    unsafe {
        AllowSetForegroundWindow(0xFFFF_FFFF);
    }
}

// ---------------------------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------------------------

unsafe fn kbd(vk: u16, scan: u16, flags: DWORD) -> INPUT {
    let mut input: INPUT = mem::zeroed();
    input.type_ = INPUT_KEYBOARD;
    *input.u.ki_mut() = KEYBDINPUT {
        wVk: vk,
        wScan: scan,
        dwFlags: flags,
        time: 0,
        dwExtraInfo: 0,
    };
    input
}

unsafe fn send(inputs: &mut [INPUT]) {
    if !inputs.is_empty() {
        SendInput(
            inputs.len() as UINT,
            inputs.as_mut_ptr(),
            mem::size_of::<INPUT>() as i32,
        );
    }
}

unsafe fn key_down(vk: i32) -> bool {
    (GetAsyncKeyState(vk) as u16 & 0x8000) != 0
}

fn modifier_keys(mods: u32) -> Vec<i32> {
    let mut keys = Vec::new();
    if mods & MOD_ALT != 0 {
        keys.push(VK_MENU);
    }
    if mods & MOD_CONTROL != 0 {
        keys.push(VK_CONTROL);
    }
    if mods & MOD_SHIFT != 0 {
        keys.push(VK_SHIFT);
    }
    if mods & MOD_WIN != 0 {
        keys.push(VK_LWIN);
        keys.push(VK_RWIN);
    }
    keys
}

unsafe fn is_hotkey_down(hk: &Hotkey) -> bool {
    key_down(hk.vk as i32) || modifier_keys(hk.mods).into_iter().any(|vk| key_down(vk))
}

/// Call right after a hotkey fires, before injecting any keys.
///
/// * Taps an unassigned key while Alt/Win is still held, so that releasing it afterwards
///   doesn't pop open the target app's menu bar or the Start menu.
/// * Waits for the user to physically let go of the hotkey, so our injected keystrokes
///   aren't mangled by keys that are still down.
pub fn prepare_for_injection(hk: &Hotkey) {
    unsafe {
        if hk.mods & (MOD_ALT | MOD_WIN) != 0 {
            let mut mask = [kbd(0xE8, 0, 0), kbd(0xE8, 0, KEYEVENTF_KEYUP)];
            send(&mut mask);
        }
        let deadline = Instant::now() + Duration::from_millis(1200);
        while is_hotkey_down(hk) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if is_hotkey_down(hk) {
            // Still held after the timeout: release the modifiers logically.
            let mut ups: Vec<INPUT> = modifier_keys(hk.mods)
                .into_iter()
                .map(|vk| kbd(vk as u16, 0, KEYEVENTF_KEYUP))
                .collect();
            send(&mut ups);
        }
    }
}

/// Types text as Unicode key events. No clipboard involved, so nothing lands in clipboard history.
unsafe fn type_text(text: &str) {
    for unit in text.encode_utf16() {
        let mut pair = [
            kbd(0, unit, KEYEVENTF_UNICODE),
            kbd(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
        ];
        send(&mut pair);
        thread::sleep(Duration::from_millis(3));
    }
}

unsafe fn tap(vk: i32) {
    let mut pair = [kbd(vk as u16, 0, 0), kbd(vk as u16, 0, KEYEVENTF_KEYUP)];
    send(&mut pair);
}

/// Types the job into `target`, but only if `target` is really the window in front. If focus
/// can't be restored we type nothing rather than risk putting a password in the wrong place.
pub fn deliver(target: usize, job: &TypeJob) {
    if target == 0 {
        message_box("IPassword", "IPassword couldn't tell which window to type into, so nothing was typed.", true);
        return;
    }
    thread::sleep(Duration::from_millis(120));
    unsafe {
        let hwnd = target as HWND;
        if IsWindow(hwnd) == 0 {
            message_box("IPassword", "The window you came from is gone, so nothing was typed.", true);
            return;
        }
        if GetForegroundWindow() != hwnd {
            SetForegroundWindow(hwnd);
        }
        let start = Instant::now();
        while GetForegroundWindow() != hwnd {
            if start.elapsed() > Duration::from_millis(1500) {
                message_box(
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
            type_text(username);
        }
        if job.username.is_some() && job.password.is_some() {
            tap(VK_TAB);
        }
        if let Some(password) = &job.password {
            type_text(password);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Clipboard capture (Alt+C)
// ---------------------------------------------------------------------------------------------

unsafe fn open_clipboard_retry() -> bool {
    for _ in 0..20 {
        if OpenClipboard(ptr::null_mut()) != 0 {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

unsafe fn read_clipboard_text() -> Option<String> {
    if !open_clipboard_retry() {
        return None;
    }
    let handle = GetClipboardData(CF_UNICODETEXT as UINT);
    let mut text = None;
    if !handle.is_null() {
        let max_units = GlobalSize(handle) / 2;
        let p = GlobalLock(handle) as *const u16;
        if !p.is_null() {
            let mut len = 0usize;
            while len < max_units && *p.add(len) != 0 {
                len += 1;
            }
            text = Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)));
            GlobalUnlock(handle);
        }
    }
    CloseClipboard();
    text
}

unsafe fn write_clipboard_text(text: &str) -> bool {
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mem_handle = GlobalAlloc(GMEM_MOVEABLE, units.len() * 2);
    if mem_handle.is_null() {
        return false;
    }
    let dest = GlobalLock(mem_handle) as *mut u16;
    if dest.is_null() {
        GlobalFree(mem_handle);
        return false;
    }
    ptr::copy_nonoverlapping(units.as_ptr(), dest, units.len());
    GlobalUnlock(mem_handle);

    if !open_clipboard_retry() {
        GlobalFree(mem_handle);
        return false;
    }
    EmptyClipboard();
    let stored = !SetClipboardData(CF_UNICODETEXT as UINT, mem_handle).is_null();
    if !stored {
        GlobalFree(mem_handle);
    }
    CloseClipboard();
    stored
}

unsafe fn clear_clipboard() {
    if open_clipboard_retry() {
        EmptyClipboard();
        CloseClipboard();
    }
}

/// Terminals treat Ctrl+C as "interrupt", so we never send it to them.
unsafe fn is_terminal(hwnd: HWND) -> bool {
    let mut buf = [0u16; 128];
    let n = GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    if n <= 0 {
        return false;
    }
    let name = String::from_utf16_lossy(&buf[..n as usize]);
    matches!(
        name.as_str(),
        "ConsoleWindowClass" | "CASCADIA_HOSTING_WINDOW_CLASS" | "mintty" | "VirtualConsoleClass"
    )
}

/// Copies whatever is selected in `target` by sending Ctrl+C, reads it, and puts the user's
/// previous clipboard text back (or clears the clipboard if it held something other than text).
/// Returns `None` if nothing was selected or capturing isn't safe here.
pub fn capture_selection(target: usize) -> Option<String> {
    unsafe {
        if target == 0 || is_terminal(target as HWND) {
            return None;
        }
        let previous = read_clipboard_text();
        let seq_before = GetClipboardSequenceNumber();

        let mut keys = [
            kbd(VK_CONTROL as u16, 0, 0),
            kbd(0x43, 0, 0),
            kbd(0x43, 0, KEYEVENTF_KEYUP),
            kbd(VK_CONTROL as u16, 0, KEYEVENTF_KEYUP),
        ];
        send(&mut keys);

        let start = Instant::now();
        let mut changed = false;
        while start.elapsed() < Duration::from_millis(700) {
            if GetClipboardSequenceNumber() != seq_before {
                changed = true;
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
        if !changed {
            return None;
        }
        thread::sleep(Duration::from_millis(30));
        let captured = read_clipboard_text();

        match &previous {
            Some(text) => {
                write_clipboard_text(text);
            }
            None => clear_clipboard(),
        }

        // A password is short. Anything huge is a normal text selection, not something to save.
        captured.filter(|s| !s.is_empty() && s.len() <= 1024)
    }
}

// ---------------------------------------------------------------------------------------------
// Autostart and the background process
// ---------------------------------------------------------------------------------------------

pub fn autostart_enabled() -> bool {
    unsafe {
        let key = wide(RUN_KEY);
        let name = wide(RUN_VALUE);
        let mut hkey: HKEY = ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, key.as_ptr(), 0, KEY_QUERY_VALUE, &mut hkey) != 0 {
            return false;
        }
        let found = RegQueryValueExW(
            hkey,
            name.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0;
        RegCloseKey(hkey);
        found
    }
}

pub fn set_autostart(enable: bool) -> Result<(), String> {
    unsafe {
        let key = wide(RUN_KEY);
        let name = wide(RUN_VALUE);
        let mut hkey: HKEY = ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, key.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) != 0 {
            return Err("Couldn't open the Windows startup list.".into());
        }
        let status = if enable {
            let command = format!("\"{}\" --daemon", paths::exe_path().display());
            let data = wide(&command);
            RegSetValueExW(
                hkey,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as DWORD,
            )
        } else {
            let status = RegDeleteValueW(hkey, name.as_ptr());
            if status == 2 {
                0 // already absent
            } else {
                status
            }
        };
        RegCloseKey(hkey);
        if status == 0 {
            Ok(())
        } else {
            Err("Couldn't update the Windows startup list.".into())
        }
    }
}

/// The daemon's hidden window, if the background process is running.
pub fn daemon_window() -> Option<HWND> {
    unsafe {
        let class = wide(DAEMON_CLASS);
        let hwnd = FindWindowW(class.as_ptr(), ptr::null());
        if hwnd.is_null() {
            None
        } else {
            Some(hwnd)
        }
    }
}

pub fn stop_daemon() -> bool {
    match daemon_window() {
        Some(hwnd) => unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) != 0 },
        None => false,
    }
}

pub fn start_daemon() {
    // DETACHED_PROCESS so it isn't tied to whoever launched it.
    let _ = Command::new(paths::exe_path())
        .arg("--daemon")
        .creation_flags(0x0000_0008)
        .spawn();
}

/// Stops the background process and starts a fresh one (used after changing hotkeys).
pub fn restart_daemon() {
    stop_daemon();
    for _ in 0..40 {
        if daemon_window().is_none() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    start_daemon();
}

/// Opens a folder in Explorer.
pub fn open_folder(path: &std::path::Path) {
    let _ = std::fs::create_dir_all(path);
    let _ = Command::new("explorer").arg(path).spawn();
}
