# IPassword

A free, local-first password manager for Windows, written in Rust.

Select a password in any app and press **Alt+C** to save it. Click into a login box and press **Alt+V**
to pick a saved login; IPassword types it in for you. Every app gets its own encrypted file, and
nothing ever leaves your computer.

## Using it

1. Run the installer (or `IPassword.exe` from the portable folder) and open the main window.
2. **Account tab:** create a user with a master password. There is no recovery: forget it and the
   data is gone.
3. Select a password in any app and press **Alt+C**. Enter your username, master password and the
   app's name (for example `netflix`), and it is encrypted and saved.
4. In a login box press **Alt+V**, sign in, name the app, and click **Password**, **Username**
   or **User + Pass**. It is typed into the window you came from.

A background process (shown as a tray icon, and started at sign-in if you ticked that box in the
installer) listens for the hotkeys. Right-click the tray icon to open IPassword or quit it.

## How it protects your passwords

* Your master password is never stored. It is stretched with **Argon2id** into a key that
  unwraps a random 256-bit vault key. Each app's file is encrypted with **AES-256-GCM**.
* Login only ever *decrypts*. A wrong password fails the authentication check and changes
  nothing on disk.
* App file names are keyed hashes, so the folder doesn't reveal which apps you use. Files are
  padded to 1 KiB steps and are bound to their own name, so they can't be swapped around.
* Passwords are typed with simulated keystrokes and never go through the clipboard.
* All algorithms and formats are public; every key is generated per user at runtime.

See `src/crates/ipassword-core/src/lib.rs` for the full design and its known limits.

### Limits worth knowing

* **Alt+C copies with Ctrl+C.** If Windows clipboard history or cloud clipboard is on, the copied
  text can land there. Turn them off (Settings > System > Clipboard), or type the password into
  the save window instead. Terminals are skipped, because Ctrl+C would interrupt what's running.
  If your clipboard held something other than text (like an image), it is cleared after a capture.
* Malware already running as you can read keystrokes and memory. No local password manager
  fixes that.
* Keep `install.json` in the data folder: it maps usernames to their folders.
* This code has not been independently audited.

## Installed layout

```
IPassword/
  IPassword.exe           launcher, background process, windows
  ipassword_core.dll      crypto and storage (a C API, usable from other languages)
  config.json             hotkeys, timeouts, data folder, optional pinned DLL hash
  theme.json              colors, corner radius, font size
  assets/                 icon.ico, icon.svg
```

Saved passwords live in `%APPDATA%\IPassword`, or in `IPasswordData` next to the program in the
portable version. `config.json` can point `data_dir` somewhere else. Edit `config.json` and
`theme.json` with any text editor and restart IPassword; no rebuild needed.

The program loads `ipassword_core.dll` from its own folder, which is what makes it moddable. That
also means anything that can write to that folder could swap it. To lock it down, put the DLL's
SHA-256 (printed at the end of the build) in `config.json` as `core_dll_sha256`; IPassword then
refuses to load any other file.

The C API is in `src/crates/ipassword-ffi/src/lib.rs` (`ipw_unlock`, `ipw_vault_get_app`, ...).

## Project layout

`src/` holds only the app itself. The build tooling sits beside it.

```
src/                    the app's source
  Cargo.toml            Rust workspace
  crates/
    ipassword-core/     storage + crypto (no unsafe code, unit-tested)
    ipassword-ffi/      C API, built as ipassword_core.dll
    ipassword-app/      the Windows app: hotkeys, tray, windows (egui)
  assets/               default config.json and theme.json (shipped with the app)
  GUIAssets/icon.svg    the app icon (the build converts it to .ico)
scripts/                WSL setup and build scripts
installer/              NSIS installer script
dist/                   build output (created by the build, not committed)
```

## Building (Windows + WSL)

It is cross-compiled from Debian inside WSL. Run these from the project folder:

```
scripts\setup-wsl.bat     one time: installs rust, mingw-w64, nsis, imagemagick... (asks for sudo)
scripts\build.bat         tests, builds, and writes everything to dist\
```

`dist\` then contains `IPassword-Setup.exe`, the `IPassword-portable` folder and
`IPassword-portable.zip`, plus `SHA256SUMS.txt`.

Setup installs Rust through rustup, since Debian's own packages don't include the Windows target;
there is nothing to install by hand. The `.bat` launchers strip Windows line endings from the
`.sh` scripts before running them, so CRLF files are fine.

To run just the tests on Linux or WSL: `cd src && cargo test --workspace`.

The executable is not code-signed, so Windows SmartScreen may warn on first run, and some antivirus
software is wary of programs that use global hotkeys and keystroke injection.
