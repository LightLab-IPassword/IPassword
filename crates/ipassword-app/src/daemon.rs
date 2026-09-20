//! The always-running background process: a hidden window that owns the global hotkeys and the
//! tray icon. It never handles the master password; the popups it launches do.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::{mem, ptr};

use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::{HWND, POINT};
use winapi::shared::winerror::ERROR_ALREADY_EXISTS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::shellapi::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
};
use winapi::um::synchapi::CreateMutexW;
use winapi::um::winuser::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, PostMessageW, PostQuitMessage,
    RegisterClassW, RegisterHotKey, RegisterWindowMessageW, SetForegroundWindow, TrackPopupMenu,
    TranslateMessage, UnregisterHotKey, IDI_APPLICATION, MF_SEPARATOR, MF_STRING, MSG,
    TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_HOTKEY,
    WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WNDCLASSW,
};
use zeroize::Zeroizing;

use crate::config::{Config, Hotkey, MOD_NOREPEAT};
use crate::{paths, win};

const ID_CAPTURE: i32 = 1;
const ID_PASTE: i32 = 2;
const MENU_OPEN: usize = 101;
const MENU_QUIT: usize = 102;
const WM_TRAY: UINT = WM_APP + 1;

struct State {
    capture: Hotkey,
    paste: Hotkey,
    child: Option<Child>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    let mutex = STATE.get()?;
    let mut guard = mutex.lock().ok()?;
    Some(f(&mut guard))
}

/// True while a popup we launched is still open (so a second hotkey press doesn't stack another).
fn popup_running(state: &mut State) -> bool {
    if let Some(child) = state.child.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return true;
        }
    }
    state.child = None;
    false
}

fn spawn_popup(mode: &str, target: usize, stdin_data: Option<&str>) -> std::io::Result<Child> {
    win::allow_foreground_switch();
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

fn on_capture() {
    let _ = with_state(|st| {
        if popup_running(st) {
            return;
        }
        let target = win::foreground();
        win::prepare_for_injection(&st.capture);
        let selected = win::capture_selection(target).map(Zeroizing::new);
        let data: &str = selected.as_deref().map(|s| s.as_str()).unwrap_or("");
        match spawn_popup("popup-capture", target, Some(data)) {
            Ok(child) => st.child = Some(child),
            Err(e) => win::message_box(
                "IPassword",
                &format!("Couldn't open the save window: {e}"),
                true,
            ),
        }
    });
}

fn on_paste() {
    let _ = with_state(|st| {
        if popup_running(st) {
            return;
        }
        let target = win::foreground();
        win::prepare_for_injection(&st.paste);
        match spawn_popup("popup-paste", target, None) {
            Ok(child) => st.child = Some(child),
            Err(e) => win::message_box(
                "IPassword",
                &format!("Couldn't open the paste window: {e}"),
                true,
            ),
        }
    });
}

fn open_main_window() {
    let _ = Command::new(paths::exe_path()).spawn();
}

unsafe fn tray_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut nid: NOTIFYICONDATAW = mem::zeroed();
    nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;

    // Resource id 1 is the icon embedded by build.rs; fall back to the generic one.
    let module = GetModuleHandleW(ptr::null());
    let mut icon = LoadIconW(module, 1usize as *const u16);
    if icon.is_null() {
        icon = LoadIconW(ptr::null_mut(), IDI_APPLICATION);
    }
    nid.hIcon = icon;

    let tip = win::wide("IPassword is running");
    let count = tip.len().min(nid.szTip.len() - 1);
    nid.szTip[..count].copy_from_slice(&tip[..count]);
    nid
}

unsafe fn add_tray(hwnd: HWND) {
    let mut nid = tray_data(hwnd);
    Shell_NotifyIconW(NIM_ADD, &mut nid);
}

unsafe fn remove_tray(hwnd: HWND) {
    let mut nid = tray_data(hwnd);
    Shell_NotifyIconW(NIM_DELETE, &mut nid);
}

unsafe fn show_tray_menu(hwnd: HWND) {
    let menu = CreatePopupMenu();
    if menu.is_null() {
        return;
    }
    let open = win::wide("Open IPassword");
    let quit = win::wide("Quit");
    AppendMenuW(menu, MF_STRING, MENU_OPEN, open.as_ptr());
    AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
    AppendMenuW(menu, MF_STRING, MENU_QUIT, quit.as_ptr());

    let mut point: POINT = mem::zeroed();
    GetCursorPos(&mut point);
    // Required so the menu closes when the user clicks elsewhere.
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, ptr::null());
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_HOTKEY => {
            match wparam as i32 {
                ID_CAPTURE => on_capture(),
                ID_PASTE => on_paste(),
                _ => {}
            }
            0
        }
        WM_TRAY => {
            match (lparam & 0xFFFF) as UINT {
                WM_RBUTTONUP | WM_CONTEXTMENU => show_tray_menu(hwnd),
                WM_LBUTTONUP => open_main_window(),
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            match wparam & 0xFFFF {
                MENU_OPEN => open_main_window(),
                MENU_QUIT => {
                    DestroyWindow(hwnd);
                }
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            remove_tray(hwnd);
            PostQuitMessage(0);
            0
        }
        _ => {
            let taskbar = TASKBAR_CREATED.load(Ordering::Relaxed);
            if taskbar != 0 && msg == taskbar {
                // Explorer restarted: put the tray icon back.
                add_tray(hwnd);
                0
            } else {
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
        }
    }
}

pub fn run() {
    // One background process per user session.
    unsafe {
        let name = win::wide(r"Local\IPassword.Daemon");
        let handle = CreateMutexW(ptr::null_mut(), 0, name.as_ptr());
        if handle.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
            return;
        }
        // The handle is deliberately never closed: the mutex must live as long as this process.
    }

    let config = Config::load(&paths::config_path());
    let (capture, paste) = match config.hotkeys() {
        Ok(pair) => pair,
        Err(e) => {
            win::message_box(
                "IPassword",
                &format!("{e}\n\nFix the hotkeys in config.json or in the IPassword window (Settings tab)."),
                true,
            );
            return;
        }
    };
    let _ = STATE.set(Mutex::new(State {
        capture,
        paste,
        child: None,
    }));

    unsafe {
        let hinstance = GetModuleHandleW(ptr::null());
        let class = win::wide(win::DAEMON_CLASS);
        let title = win::wide("IPassword background process");

        let mut wc: WNDCLASSW = mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinstance;
        wc.lpszClassName = class.as_ptr();
        if RegisterClassW(&wc) == 0 {
            win::message_box("IPassword", "Couldn't start the background process.", true);
            return;
        }

        // A normal (never shown) window rather than a message-only one: the tray icon needs it.
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            hinstance,
            ptr::null_mut(),
        );
        if hwnd.is_null() {
            win::message_box("IPassword", "Couldn't start the background process.", true);
            return;
        }

        for (id, hotkey, what) in [(ID_CAPTURE, capture, "save"), (ID_PASTE, paste, "paste")] {
            if RegisterHotKey(hwnd, id, hotkey.mods | MOD_NOREPEAT, hotkey.vk) == 0 {
                win::message_box(
                    "IPassword",
                    &format!(
                        "Couldn't claim the {what} hotkey ({}). Another program is probably using it.\n\nPick a different one in the IPassword window (Settings tab).",
                        hotkey.describe()
                    ),
                    true,
                );
                DestroyWindow(hwnd);
                return;
            }
        }

        let taskbar_msg = win::wide("TaskbarCreated");
        TASKBAR_CREATED.store(RegisterWindowMessageW(taskbar_msg.as_ptr()), Ordering::Relaxed);
        add_tray(hwnd);

        let mut msg: MSG = mem::zeroed();
        while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        UnregisterHotKey(hwnd, ID_CAPTURE);
        UnregisterHotKey(hwnd, ID_PASTE);
    }
}
