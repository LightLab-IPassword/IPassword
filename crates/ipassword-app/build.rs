// Embeds the app icon and version info into the .exe when cross-compiling for Windows (GNU).
// If windres is missing or fails, the build still succeeds, just without the icon.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/ipassword.ico");

    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows-gnu") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let object = out_dir.join("app_res.o");
    let arch = if target.starts_with("i686") { "i686" } else { "x86_64" };
    let windres = env::var("WINDRES").unwrap_or_else(|_| format!("{arch}-w64-mingw32-windres"));

    let status = Command::new(&windres)
        .args(["--input", "assets/app.rc", "--output-format=coff", "--output"])
        .arg(&object)
        .status();

    match status {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg-bins={}", object.display()),
        _ => println!(
            "cargo:warning=`{windres}` failed or is missing (or assets/ipassword.ico is absent); building without the app icon"
        ),
    }
}
