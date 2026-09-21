//! Loads the core library (`ipassword_core.dll` / `libipassword_core.so`) from the program folder
//! at runtime and wraps its C API.
//!
//! Because the core is a separate library it can be swapped for a modified build, and the same
//! library can be used by other front ends. To pin the exact file you trust, put its SHA-256 in
//! `config.json` (`core_dll_sha256`); the app then refuses to load any other file.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::mem;
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use libloading::Library;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config::Config;
use crate::paths;
use crate::platform::platform;
use crate::records::RecordData;

pub const WRONG_PASSWORD: i32 = 1;
pub const USER_NOT_FOUND: i32 = 2;
pub const USER_EXISTS: i32 = 3;
pub const NOT_FOUND: i32 = 4;
pub const INVALID: i32 = 5;
pub const CORRUPT: i32 = 6;
pub const INTERNAL: i32 = 8;

/// Bit flags for [`Core::generate_password`].
pub const GEN_LOWER: u32 = 1;
pub const GEN_UPPER: u32 = 2;
pub const GEN_DIGITS: u32 = 4;
pub const GEN_SYMBOLS: u32 = 8;
pub const GEN_AVOID_AMBIGUOUS: u32 = 16;

#[derive(Debug, Clone)]
pub struct CoreError {
    pub code: i32,
    pub message: String,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

type FnVersion = unsafe extern "C" fn() -> *const c_char;
type FnErrorMessage = unsafe extern "C" fn(c_int) -> *const c_char;
type FnCreateUser = unsafe extern "C" fn(*const c_char, *const c_char, *const c_char) -> c_int;
type FnChangePassword =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *const c_char) -> c_int;
type FnUnlock =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_void) -> c_int;
type FnVaultFree = unsafe extern "C" fn(*mut c_void);
type FnStringFree = unsafe extern "C" fn(*mut c_char);
type FnGetApp = unsafe extern "C" fn(*mut c_void, *const c_char, *mut *mut c_char) -> c_int;
type FnAddEntry = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
) -> c_int;
type FnUpdateSecret =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, *const c_char) -> c_int;
type FnRemoveEntry = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> c_int;
type FnGenerate = unsafe extern "C" fn(c_int, c_int, *mut *mut c_char) -> c_int;

struct Fns {
    version: FnVersion,
    error_message: FnErrorMessage,
    create_user: FnCreateUser,
    change_password: FnChangePassword,
    unlock: FnUnlock,
    vault_free: FnVaultFree,
    string_free: FnStringFree,
    get_app: FnGetApp,
    add_entry: FnAddEntry,
    update_secret: FnUpdateSecret,
    remove_entry: FnRemoveEntry,
    generate: FnGenerate,
}

/// The loaded library. Keeps it mapped for as long as it exists.
pub struct Core {
    _library: Library,
    f: Fns,
}

static CORE: OnceLock<Core> = OnceLock::new();

/// Loads the library on first use. Errors are user-presentable text.
pub fn core() -> Result<&'static Core, String> {
    if let Some(core) = CORE.get() {
        return Ok(core);
    }
    let config = Config::load(&paths::config_path());
    let path = paths::exe_dir().join(platform().core_library_name());
    let loaded = Core::load(&path, config.core_dll_sha256.as_deref())?;
    let _ = CORE.set(loaded);
    CORE.get()
        .ok_or_else(|| "Internal error while loading the core library.".to_string())
}

/// A C string that wipes itself when dropped (used for passwords and secrets).
struct C(CString);

impl C {
    fn new(text: &str) -> Result<C, CoreError> {
        CString::new(text).map(C).map_err(|_| CoreError {
            code: INVALID,
            message: "Text can't contain NUL characters.".to_string(),
        })
    }

    fn ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }
}

impl Drop for C {
    fn drop(&mut self) {
        let mut bytes = mem::take(&mut self.0).into_bytes_with_nul();
        bytes.zeroize();
    }
}

/// Looks up one function in the library.
unsafe fn symbol<T: Copy>(library: &Library, name: &str) -> Result<T, String> {
    let found: libloading::Symbol<T> = library
        .get(name.as_bytes())
        .map_err(|_| format!("The core library is missing the function {name}."))?;
    Ok(*found)
}

impl Core {
    fn load(path: &Path, expected_sha256: Option<&str>) -> Result<Core, String> {
        if !path.is_file() {
            return Err(format!(
                "Can't find {}.\nReinstall IPassword, or put the core library next to the program.",
                path.display()
            ));
        }

        if let Some(expected) = expected_sha256.map(str::trim).filter(|s| !s.is_empty()) {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("Couldn't read {}: {e}", path.display()))?;
            let actual = hex::encode(Sha256::digest(&bytes));
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(format!(
                    "The core library does not match the hash pinned in config.json (core_dll_sha256).\nExpected {expected}\nFound    {actual}"
                ));
            }
        }

        unsafe {
            let library = Library::new(path).map_err(|e| {
                format!(
                    "Couldn't load {} ({e}). A runtime library it needs may be missing.",
                    path.display()
                )
            })?;
            let f = Fns {
                version: symbol(&library, "ipw_version")?,
                error_message: symbol(&library, "ipw_error_message")?,
                create_user: symbol(&library, "ipw_create_user")?,
                change_password: symbol(&library, "ipw_change_password")?,
                unlock: symbol(&library, "ipw_unlock")?,
                vault_free: symbol(&library, "ipw_vault_free")?,
                string_free: symbol(&library, "ipw_string_free")?,
                get_app: symbol(&library, "ipw_vault_get_app")?,
                add_entry: symbol(&library, "ipw_vault_add_entry")?,
                update_secret: symbol(&library, "ipw_vault_update_secret")?,
                remove_entry: symbol(&library, "ipw_vault_remove_entry")?,
                generate: symbol(&library, "ipw_generate_password")?,
            };
            Ok(Core {
                _library: library,
                f,
            })
        }
    }

    pub fn version(&self) -> String {
        unsafe {
            let p = (self.f.version)();
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        }
    }

    fn err(&self, code: c_int) -> CoreError {
        let message = unsafe {
            let p = (self.f.error_message)(code);
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        CoreError { code, message }
    }

    pub fn create_user(
        &self,
        data_dir: &Path,
        username: &str,
        password: &str,
    ) -> Result<(), CoreError> {
        let d = C::new(&data_dir.to_string_lossy())?;
        let u = C::new(username)?;
        let p = C::new(password)?;
        let rc = unsafe { (self.f.create_user)(d.ptr(), u.ptr(), p.ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(self.err(rc))
        }
    }

    pub fn change_password(
        &self,
        data_dir: &Path,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), CoreError> {
        let d = C::new(&data_dir.to_string_lossy())?;
        let u = C::new(username)?;
        let o = C::new(old_password)?;
        let n = C::new(new_password)?;
        let rc = unsafe { (self.f.change_password)(d.ptr(), u.ptr(), o.ptr(), n.ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(self.err(rc))
        }
    }

    /// Log in. Only ever decrypts: a wrong password fails and changes nothing on disk.
    pub fn unlock(
        &'static self,
        data_dir: &Path,
        username: &str,
        password: &str,
    ) -> Result<Vault, CoreError> {
        let d = C::new(&data_dir.to_string_lossy())?;
        let u = C::new(username)?;
        let p = C::new(password)?;
        let mut handle: *mut c_void = ptr::null_mut();
        let rc = unsafe { (self.f.unlock)(d.ptr(), u.ptr(), p.ptr(), &mut handle) };
        if rc != 0 {
            return Err(self.err(rc));
        }
        if handle.is_null() {
            return Err(self.err(INTERNAL));
        }
        Ok(Vault { core: self, handle })
    }

    /// A random password from the OS random source. `flags` is a mix of the `GEN_*` bits.
    /// Every kind of character you enable is guaranteed to appear. Wiped when dropped.
    pub fn generate_password(&self, length: u32, flags: u32) -> Result<Zeroizing<String>, CoreError> {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe { (self.f.generate)(length as c_int, flags as c_int, &mut out) };
        if rc != 0 {
            return Err(self.err(rc));
        }
        if out.is_null() {
            return Err(self.err(INTERNAL));
        }
        let text = unsafe { CStr::from_ptr(out).to_string_lossy().into_owned() };
        unsafe { (self.f.string_free)(out) };
        Ok(Zeroizing::new(text))
    }
}

/// An unlocked vault. Dropping it wipes the keys held by the library.
pub struct Vault {
    core: &'static Core,
    handle: *mut c_void,
}

impl Drop for Vault {
    fn drop(&mut self) {
        unsafe { (self.core.f.vault_free)(self.handle) };
    }
}

impl Vault {
    /// Everything saved for an app, or `None` if nothing is saved under that name.
    pub fn get_app(&self, app: &str) -> Result<Option<RecordData>, CoreError> {
        let a = C::new(app)?;
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe { (self.core.f.get_app)(self.handle, a.ptr(), &mut out) };
        if rc == NOT_FOUND {
            return Ok(None);
        }
        if rc != 0 {
            return Err(self.core.err(rc));
        }
        if out.is_null() {
            return Err(self.core.err(INTERNAL));
        }
        let parsed = unsafe {
            CStr::from_ptr(out)
                .to_str()
                .ok()
                .and_then(|json| serde_json::from_str::<RecordData>(json).ok())
        };
        unsafe { (self.core.f.string_free)(out) };
        match parsed {
            Some(record) => Ok(Some(record)),
            None => Err(self.core.err(CORRUPT)),
        }
    }

    pub fn add_entry(&self, app: &str, username: &str, secret: &str) -> Result<(), CoreError> {
        let a = C::new(app)?;
        let u = C::new(username)?;
        let s = C::new(secret)?;
        let rc = unsafe {
            (self.core.f.add_entry)(self.handle, a.ptr(), u.ptr(), s.ptr(), ptr::null())
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(self.core.err(rc))
        }
    }

    pub fn update_secret(&self, app: &str, entry_id: &str, secret: &str) -> Result<(), CoreError> {
        let a = C::new(app)?;
        let i = C::new(entry_id)?;
        let s = C::new(secret)?;
        let rc = unsafe { (self.core.f.update_secret)(self.handle, a.ptr(), i.ptr(), s.ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(self.core.err(rc))
        }
    }

    pub fn remove_entry(&self, app: &str, entry_id: &str) -> Result<(), CoreError> {
        let a = C::new(app)?;
        let i = C::new(entry_id)?;
        let rc = unsafe { (self.core.f.remove_entry)(self.handle, a.ptr(), i.ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(self.core.err(rc))
        }
    }
}
