// No console window for any of the app's processes.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod config;
mod records;
mod theme;

#[cfg(windows)]
mod core_dll;
#[cfg(windows)]
mod daemon;
#[cfg(windows)]
mod paths;
#[cfg(windows)]
mod ui;
#[cfg(windows)]
mod win;

/// One executable, several roles, chosen by the first argument:
///   (none)          the main window (also makes sure the background process is running)
///   --daemon        the hidden background process that owns the global hotkeys and the tray icon
///   popup-capture   the "save a password" window (started by the daemon on Alt+C)
///   popup-paste     the "paste a password" window (started by the daemon on Alt+V)
#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    match args.first().map(String::as_str) {
        Some("--daemon") => daemon::run(),
        Some("popup-capture") => ui::capture::run(target),
        Some("popup-paste") => ui::paste::run(target),
        _ => ui::manage::run(),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("IPassword's app only runs on Windows. Cross-compile it with scripts/build.sh.");
    std::process::exit(1);
}
