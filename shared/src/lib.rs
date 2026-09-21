//! Code shared by the Windows and Linux apps: the windows (egui), settings, and the loader for
//! the core library. Everything that touches the operating system goes through [`Platform`],
//! which `src/windows` and `src/linux` each implement.

pub mod config;
pub mod core_lib;
pub mod paths;
pub mod platform;
pub mod popup;
pub mod records;
pub mod theme;
pub mod ui;

use platform::{platform, set_platform, Platform};

/// The whole program, for either operating system. One executable plays several roles, chosen by
/// the first command-line argument:
///
/// * (none)         the main window (also makes sure the background process is running)
/// * `--daemon`     the hidden background process that owns the hotkeys
/// * `popup-capture` the "save a password" window (started by the daemon on the capture hotkey)
/// * `popup-paste`  the "paste a password" window (started by the daemon on the paste hotkey)
pub fn run(os: Box<dyn Platform>) {
    set_platform(os);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    match args.first().map(String::as_str) {
        Some("--daemon") => platform().run_daemon(),
        Some("popup-capture") => ui::capture::run(target),
        Some("popup-paste") => ui::paste::run(target),
        _ => ui::manage::run(),
    }
}
