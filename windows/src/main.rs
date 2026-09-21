// No console window for any of the app's processes.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod daemon;
#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod win;

/// The Windows build. Everything portable lives in `ipassword-shared`; this crate only supplies the
/// Win32 parts (hotkeys, typing, clipboard capture, tray icon, autostart).
#[cfg(windows)]
fn main() {
    ipassword_shared::run(Box::new(platform::WindowsPlatform));
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This is the Windows build of IPassword. Cross-compile it with scripts/build.sh.");
    std::process::exit(1);
}
