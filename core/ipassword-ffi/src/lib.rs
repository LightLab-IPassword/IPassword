//! C API over `ipassword-core`, built as a DLL (`ipassword_core.dll` once the build script renames it).
//!
//! The desktop app loads this DLL at runtime, and so can anything else that speaks C:
//! C#, Python (ctypes), Delphi... Conventions:
//!
//! * All text is NUL-terminated UTF-8.
//! * Functions return 0 (`IPW_OK`) or a non-zero error code; `ipw_error_message` describes it.
//! * `IpwVault` is an opaque handle: get it from `ipw_unlock`, release it with `ipw_vault_free`.
//! * Strings returned to you (`char **out`) belong to you: release with `ipw_string_free`,
//!   which wipes the memory first.
//! * `ipw_vault_get_app` returns JSON: `{"display_name":..., "entries":[{"id","username","secret","note",...}]}`.
//! * `ipw_vault_list_apps` returns a JSON array of app names.
//!
//! A panic never crosses the boundary: it is caught and reported as `IPW_INTERNAL`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use ipassword_core::{generate_password, Entry, Error, GenOptions, KdfParams, Store, Vault};
use zeroize::Zeroize;

pub const IPW_OK: c_int = 0;
pub const IPW_WRONG_PASSWORD: c_int = 1;
pub const IPW_USER_NOT_FOUND: c_int = 2;
pub const IPW_USER_EXISTS: c_int = 3;
pub const IPW_NOT_FOUND: c_int = 4;
pub const IPW_INVALID: c_int = 5;
pub const IPW_CORRUPT: c_int = 6;
pub const IPW_IO: c_int = 7;
pub const IPW_INTERNAL: c_int = 8;

/// Bit flags for `ipw_generate_password`.
pub const IPW_GEN_LOWER: c_int = 1;
pub const IPW_GEN_UPPER: c_int = 2;
pub const IPW_GEN_DIGITS: c_int = 4;
pub const IPW_GEN_SYMBOLS: c_int = 8;
pub const IPW_GEN_AVOID_AMBIGUOUS: c_int = 16;

#[cfg(test)]
fn kdf_params() -> KdfParams {
    KdfParams::INSECURE_FAST
}

#[cfg(not(test))]
fn kdf_params() -> KdfParams {
    KdfParams::DEFAULT
}

fn code(e: &Error) -> c_int {
    match e {
        Error::WrongPasswordOrCorrupt => IPW_WRONG_PASSWORD,
        Error::UserNotFound => IPW_USER_NOT_FOUND,
        Error::UserExists => IPW_USER_EXISTS,
        Error::EntryNotFound => IPW_NOT_FOUND,
        Error::Invalid(_) => IPW_INVALID,
        Error::ItemCorrupt
        | Error::InvalidHeader(_)
        | Error::UnsupportedVersion(_)
        | Error::Json(_) => IPW_CORRUPT,
        Error::Io(_) => IPW_IO,
        _ => IPW_INTERNAL,
    }
}

fn guard(f: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(IPW_INTERNAL)
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

/// Library version, e.g. "0.1.0". The returned pointer is static; do not free it.
#[no_mangle]
pub extern "C" fn ipw_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Human-readable text for an error code. The returned pointer is static; do not free it.
#[no_mangle]
pub extern "C" fn ipw_error_message(code: c_int) -> *const c_char {
    let text: &'static str = match code {
        IPW_OK => "ok\0",
        IPW_WRONG_PASSWORD => "Wrong master password (or the vault header is damaged).\0",
        IPW_USER_NOT_FOUND => "No such user.\0",
        IPW_USER_EXISTS => "That user already exists.\0",
        IPW_NOT_FOUND => "Not found.\0",
        IPW_INVALID => "Invalid input.\0",
        IPW_CORRUPT => "A vault file is damaged, tampered with, or from a different version.\0",
        IPW_IO => "A file could not be read or written.\0",
        _ => "Internal error.\0",
    };
    text.as_ptr() as *const c_char
}

/// Create a user. `data_dir` is the folder that holds all vaults.
#[no_mangle]
pub unsafe extern "C" fn ipw_create_user(
    data_dir: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> c_int {
    guard(|| {
        let (Some(d), Some(u), Some(p)) = (cstr(data_dir), cstr(username), cstr(password)) else {
            return IPW_INVALID;
        };
        match Store::open(d).and_then(|s| s.create_user(u, p, kdf_params())) {
            Ok(_) => IPW_OK,
            Err(e) => code(&e),
        }
    })
}

/// Change a master password. Verifies the old one first.
#[no_mangle]
pub unsafe extern "C" fn ipw_change_password(
    data_dir: *const c_char,
    username: *const c_char,
    old_password: *const c_char,
    new_password: *const c_char,
) -> c_int {
    guard(|| {
        let (Some(d), Some(u), Some(o), Some(n)) = (
            cstr(data_dir),
            cstr(username),
            cstr(old_password),
            cstr(new_password),
        ) else {
            return IPW_INVALID;
        };
        match Store::open(d).and_then(|s| s.change_password(u, o, n, kdf_params())) {
            Ok(()) => IPW_OK,
            Err(e) => code(&e),
        }
    })
}

/// Unlock a user's vault. On success `*out` is a handle; on failure it is NULL.
#[no_mangle]
pub unsafe extern "C" fn ipw_unlock(
    data_dir: *const c_char,
    username: *const c_char,
    password: *const c_char,
    out: *mut *mut c_void,
) -> c_int {
    guard(|| {
        if out.is_null() {
            return IPW_INVALID;
        }
        *out = ptr::null_mut();
        let (Some(d), Some(u), Some(p)) = (cstr(data_dir), cstr(username), cstr(password)) else {
            return IPW_INVALID;
        };
        match Store::open(d).and_then(|s| s.unlock(u, p)) {
            Ok(vault) => {
                *out = Box::into_raw(Box::new(vault)) as *mut c_void;
                IPW_OK
            }
            Err(e) => code(&e),
        }
    })
}

/// Release a vault handle (wipes its keys). Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ipw_vault_free(vault: *mut c_void) {
    if !vault.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(vault as *mut Vault))));
    }
}

/// Release a string returned by this library. Wipes it first. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ipw_string_free(s: *mut c_char) {
    if !s.is_null() {
        let mut bytes = CString::from_raw(s).into_bytes_with_nul();
        bytes.zeroize();
    }
}

/// Fetch everything saved for an app as JSON. Returns `IPW_NOT_FOUND` if nothing is saved.
#[no_mangle]
pub unsafe extern "C" fn ipw_vault_get_app(
    vault: *mut c_void,
    app: *const c_char,
    out: *mut *mut c_char,
) -> c_int {
    guard(|| {
        if vault.is_null() || out.is_null() {
            return IPW_INVALID;
        }
        *out = ptr::null_mut();
        let Some(app) = cstr(app) else {
            return IPW_INVALID;
        };
        let vault = &*(vault as *const Vault);
        match vault.get_app(app) {
            Ok(Some(record)) => {
                let mut json = match serde_json::to_string(&record) {
                    Ok(j) => j,
                    Err(_) => return IPW_INTERNAL,
                };
                let result = CString::new(json.as_str());
                json.zeroize();
                match result {
                    Ok(c) => {
                        *out = c.into_raw();
                        IPW_OK
                    }
                    Err(_) => IPW_INTERNAL,
                }
            }
            Ok(None) => IPW_NOT_FOUND,
            Err(e) => code(&e),
        }
    })
}

/// Display names of every saved app, as a JSON array. Decrypts all app files.
#[no_mangle]
pub unsafe extern "C" fn ipw_vault_list_apps(vault: *mut c_void, out: *mut *mut c_char) -> c_int {
    guard(|| {
        if vault.is_null() || out.is_null() {
            return IPW_INVALID;
        }
        *out = ptr::null_mut();
        let vault = &*(vault as *const Vault);
        match vault.list_apps() {
            Ok(names) => match serde_json::to_string(&names)
                .ok()
                .and_then(|j| CString::new(j).ok())
            {
                Some(c) => {
                    *out = c.into_raw();
                    IPW_OK
                }
                None => IPW_INTERNAL,
            },
            Err(e) => code(&e),
        }
    })
}

/// Add a login under an app (creating the app if needed). `note` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn ipw_vault_add_entry(
    vault: *mut c_void,
    app: *const c_char,
    username: *const c_char,
    secret: *const c_char,
    note: *const c_char,
) -> c_int {
    guard(|| {
        if vault.is_null() {
            return IPW_INVALID;
        }
        let (Some(app), Some(username), Some(secret)) = (cstr(app), cstr(username), cstr(secret))
        else {
            return IPW_INVALID;
        };
        let note = if note.is_null() {
            None
        } else {
            cstr(note).filter(|s| !s.is_empty()).map(str::to_string)
        };
        let vault = &*(vault as *const Vault);
        match Entry::new(username, secret, note).and_then(|entry| vault.add_entry(app, entry)) {
            Ok(()) => IPW_OK,
            Err(e) => code(&e),
        }
    })
}

/// Replace the secret of an existing login.
#[no_mangle]
pub unsafe extern "C" fn ipw_vault_update_secret(
    vault: *mut c_void,
    app: *const c_char,
    entry_id: *const c_char,
    new_secret: *const c_char,
) -> c_int {
    guard(|| {
        if vault.is_null() {
            return IPW_INVALID;
        }
        let (Some(app), Some(id), Some(secret)) = (cstr(app), cstr(entry_id), cstr(new_secret))
        else {
            return IPW_INVALID;
        };
        if secret.is_empty() {
            return IPW_INVALID;
        }
        let secret = secret.to_string();
        let vault = &*(vault as *const Vault);
        let result = vault.update_entry(app, id, move |e| {
            e.secret.zeroize();
            e.secret = secret;
        });
        match result {
            Ok(()) => IPW_OK,
            Err(e) => code(&e),
        }
    })
}

/// Generate a random password (length 8 to 128) from the OS random source. `flags` is a mix of
/// the `IPW_GEN_*` bits; every kind you enable is guaranteed to appear. Free the result with
/// `ipw_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ipw_generate_password(
    length: c_int,
    flags: c_int,
    out: *mut *mut c_char,
) -> c_int {
    guard(|| {
        if out.is_null() || length < 0 {
            return IPW_INVALID;
        }
        *out = ptr::null_mut();
        let options = GenOptions {
            length: length as usize,
            lowercase: flags & IPW_GEN_LOWER != 0,
            uppercase: flags & IPW_GEN_UPPER != 0,
            digits: flags & IPW_GEN_DIGITS != 0,
            symbols: flags & IPW_GEN_SYMBOLS != 0,
            avoid_ambiguous: flags & IPW_GEN_AVOID_AMBIGUOUS != 0,
        };
        match generate_password(&options) {
            // The `Zeroizing` wrapper wipes our copy when it goes out of scope.
            Ok(password) => match CString::new(password.as_str()) {
                Ok(c) => {
                    *out = c.into_raw();
                    IPW_OK
                }
                Err(_) => IPW_INTERNAL,
            },
            Err(e) => code(&e),
        }
    })
}

/// Remove one login. Removing an app's last login deletes the app.
#[no_mangle]
pub unsafe extern "C" fn ipw_vault_remove_entry(
    vault: *mut c_void,
    app: *const c_char,
    entry_id: *const c_char,
) -> c_int {
    guard(|| {
        if vault.is_null() {
            return IPW_INVALID;
        }
        let (Some(app), Some(id)) = (cstr(app), cstr(entry_id)) else {
            return IPW_INVALID;
        };
        let vault = &*(vault as *const Vault);
        match vault.remove_entry(app, id) {
            Ok(()) => IPW_OK,
            Err(e) => code(&e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn full_flow_through_the_c_api() {
        let dir = tempfile::tempdir().unwrap();
        let d = c(dir.path().to_str().unwrap());
        let (user, pw, app) = (c("alice"), c("correct horse"), c("Netflix"));
        unsafe {
            assert_eq!(ipw_create_user(d.as_ptr(), user.as_ptr(), pw.as_ptr()), IPW_OK);
            assert_eq!(
                ipw_create_user(d.as_ptr(), user.as_ptr(), pw.as_ptr()),
                IPW_USER_EXISTS
            );

            let wrong = c("nope");
            let mut vault: *mut c_void = ptr::null_mut();
            assert_eq!(
                ipw_unlock(d.as_ptr(), user.as_ptr(), wrong.as_ptr(), &mut vault),
                IPW_WRONG_PASSWORD
            );
            assert!(vault.is_null());

            assert_eq!(
                ipw_unlock(d.as_ptr(), user.as_ptr(), pw.as_ptr(), &mut vault),
                IPW_OK
            );
            assert!(!vault.is_null());

            let (account, secret) = (c("a@b.c"), c("hunter2"));
            assert_eq!(
                ipw_vault_add_entry(vault, app.as_ptr(), account.as_ptr(), secret.as_ptr(), ptr::null()),
                IPW_OK
            );

            let lookup = c("netflix");
            let mut json: *mut c_char = ptr::null_mut();
            assert_eq!(ipw_vault_get_app(vault, lookup.as_ptr(), &mut json), IPW_OK);
            let text = CStr::from_ptr(json).to_str().unwrap().to_string();
            assert!(text.contains("hunter2") && text.contains("Netflix"));
            ipw_string_free(json);

            let missing = c("hulu");
            assert_eq!(
                ipw_vault_get_app(vault, missing.as_ptr(), &mut json),
                IPW_NOT_FOUND
            );
            assert!(json.is_null());

            let mut names: *mut c_char = ptr::null_mut();
            assert_eq!(ipw_vault_list_apps(vault, &mut names), IPW_OK);
            assert_eq!(CStr::from_ptr(names).to_str().unwrap(), "[\"Netflix\"]");
            ipw_string_free(names);

            ipw_vault_free(vault);
        }
    }

    #[test]
    fn generate_password_through_the_c_api() {
        unsafe {
            let mut out: *mut c_char = ptr::null_mut();
            let flags = IPW_GEN_LOWER | IPW_GEN_UPPER | IPW_GEN_DIGITS;
            assert_eq!(ipw_generate_password(24, flags, &mut out), IPW_OK);
            let text = CStr::from_ptr(out).to_str().unwrap().to_string();
            ipw_string_free(out);
            assert_eq!(text.chars().count(), 24);
            assert!(text.chars().all(|c| c.is_ascii_alphanumeric()));

            // No character kinds, or a bad length, is rejected and returns no string.
            assert_eq!(ipw_generate_password(24, 0, &mut out), IPW_INVALID);
            assert!(out.is_null());
            assert_eq!(ipw_generate_password(3, flags, &mut out), IPW_INVALID);
            assert_eq!(ipw_generate_password(-1, flags, &mut out), IPW_INVALID);
            assert_eq!(ipw_generate_password(24, flags, ptr::null_mut()), IPW_INVALID);
        }
    }

    #[test]
    fn bad_arguments_are_rejected_not_crashed() {
        unsafe {
            let mut vault: *mut c_void = ptr::null_mut();
            assert_eq!(
                ipw_unlock(ptr::null(), ptr::null(), ptr::null(), &mut vault),
                IPW_INVALID
            );
            assert_eq!(ipw_vault_remove_entry(ptr::null_mut(), ptr::null(), ptr::null()), IPW_INVALID);
            ipw_vault_free(ptr::null_mut());
            ipw_string_free(ptr::null_mut());
        }
    }
}
