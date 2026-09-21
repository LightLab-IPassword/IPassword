//! The Linux build. Everything portable lives in `ipassword-shared`; this crate supplies the X11
//! parts: global hotkeys, typing, clipboard capture and autostart.
//!
//! Runtime requirements: an X11 session (or XWayland), plus `xdotool` and `xclip`.

#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod keys;
#[cfg(unix)]
mod platform;
#[cfg(unix)]
mod tools;

#[cfg(unix)]
fn main() {
    ipassword_shared::run(Box::new(platform::LinuxPlatform));
}

#[cfg(not(unix))]
fn main() {
    eprintln!("This is the Linux build of IPassword.");
    std::process::exit(1);
}
