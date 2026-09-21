//! Users, unlocking, and the per-app encrypted files.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Key, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::entry::{decode_record, encode_record, now_unix, AppRecord, Entry};
use crate::error::{Error, Result};
use crate::fsutil::write_atomic;
use crate::names;

const FORMAT_VERSION: u32 = 1;
const ITEM_MAGIC: &[u8; 4] = b"IPW1";
const KDF_ALGORITHM: &str = "argon2id";

// Domain-separation labels. These are public, not secrets: they only ensure
// that keys and IDs derived for different purposes can never collide.
const LABEL_USER: &[u8] = b"ipassword/v1/user-folder";
const LABEL_APP: &[u8] = b"ipassword/v1/app-file";
const INFO_NAME_KEY: &[u8] = b"ipassword/v1/name-key";
const INFO_ITEM_KEY: &[u8] = b"ipassword/v1/item-key";
const AAD_WRAP: &[u8] = b"ipassword/v1/wrap\0";
const AAD_ITEM: &[u8] = b"ipassword/v1/item\0";

#[derive(Serialize, Deserialize)]
struct InstallFile {
    version: u32,
    /// Per-install random salt for hiding usernames in folder names.
    salt: String,
}

/// `vault.json`: everything needed to unlock, and nothing that helps without
/// the master password.
#[derive(Serialize, Deserialize)]
struct VaultHeader {
    version: u32,
    kdf_algorithm: String,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    wrapped_key: String,
}

fn decode_hex(s: &str, what: &'static str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|_| Error::InvalidHeader(what))
}

fn wrap_aad(user_id: &str) -> Vec<u8> {
    [AAD_WRAP, user_id.as_bytes()].concat()
}

fn item_aad(file_id: &str) -> Vec<u8> {
    [AAD_ITEM, file_id.as_bytes()].concat()
}

/// Encrypt the vault key under a key derived from the master password.
fn wrap_vault_key(
    vault_key: &Key,
    password: &str,
    params: KdfParams,
    user_id: &str,
) -> Result<VaultHeader> {
    let salt = crypto::random_array::<SALT_LEN>()?;
    let password_key = crypto::derive_password_key(password.as_bytes(), &salt, params)?;
    let (nonce, wrapped) = crypto::seal(&password_key, &wrap_aad(user_id), &vault_key[..])?;
    Ok(VaultHeader {
        version: FORMAT_VERSION,
        kdf_algorithm: KDF_ALGORITHM.to_string(),
        kdf: params,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        wrapped_key: hex::encode(wrapped),
    })
}

/// The on-disk root: a folder holding one sub-folder per user.
///
/// ```text
/// <root>/
///   install.json                 per-install salt (keep it with the folder!)
///   users/<user id>/
///     vault.json                 salt, KDF params, wrapped vault key
///     items/<file id>.ipw        one encrypted file per app
/// ```
pub struct Store {
    root: PathBuf,
    install_salt: Vec<u8>,
}

impl Store {
    /// Open (or initialise) a store at `root`.
    ///
    /// `install.json` is required to map usernames to folders. If it goes
    /// missing while user folders still exist we refuse to invent a new one,
    /// since that would silently make every existing user "not found".
    pub fn open(root: impl AsRef<Path>) -> Result<Store> {
        let root = root.as_ref().to_path_buf();
        let users_dir = root.join("users");
        fs::create_dir_all(&users_dir)?;

        let install_path = root.join("install.json");
        let install_salt = match fs::read(&install_path) {
            Ok(bytes) => {
                let file: InstallFile = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::InvalidHeader("install.json is not valid"))?;
                if file.version != FORMAT_VERSION {
                    return Err(Error::UnsupportedVersion(file.version));
                }
                let salt = decode_hex(&file.salt, "install salt is not valid hex")?;
                if salt.len() != 32 {
                    return Err(Error::InvalidHeader("install salt has the wrong length"));
                }
                salt
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if fs::read_dir(&users_dir)?.next().is_some() {
                    return Err(Error::InvalidHeader(
                        "install.json is missing but user folders exist",
                    ));
                }
                let salt = crypto::random_array::<32>()?;
                let file = InstallFile {
                    version: FORMAT_VERSION,
                    salt: hex::encode(salt),
                };
                write_atomic(&install_path, &serde_json::to_vec_pretty(&file)?)?;
                salt.to_vec()
            }
            Err(e) => return Err(e.into()),
        };

        Ok(Store { root, install_salt })
    }

    /// Folder name for a user: HMAC(install salt, username). Hides which
    /// usernames exist. This layer is weaker than the rest (the key is a salt
    /// on disk, not derived from a password) because we must find the folder
    /// *before* we have any password-derived key.
    fn user_id(&self, username: &str) -> Result<String> {
        let name = names::normalize(username)
            .ok_or(Error::Invalid("username is empty or too long"))?;
        Ok(crypto::keyed_id(&self.install_salt, LABEL_USER, &name))
    }

    fn user_dir(&self, user_id: &str) -> PathBuf {
        self.root.join("users").join(user_id)
    }

    /// Create a new user and return their unlocked vault.
    pub fn create_user(&self, username: &str, password: &str, params: KdfParams) -> Result<Vault> {
        params.validate_for_creation()?;
        if password.is_empty() {
            return Err(Error::Invalid("master password is empty"));
        }
        let user_id = self.user_id(username)?;
        let dir = self.user_dir(&user_id);
        let header_path = dir.join("vault.json");
        if header_path.exists() {
            return Err(Error::UserExists);
        }

        let vault_key = crypto::random_key()?;
        let header = wrap_vault_key(&vault_key, password, params, &user_id)?;
        fs::create_dir_all(dir.join("items"))?;
        write_atomic(&header_path, &serde_json::to_vec_pretty(&header)?)?;
        Vault::new(&dir, &vault_key)
    }

    pub fn user_exists(&self, username: &str) -> Result<bool> {
        let user_id = self.user_id(username)?;
        Ok(self.user_dir(&user_id).join("vault.json").is_file())
    }

    /// Log in. This never encrypts or writes anything: it re-derives a key
    /// from what was typed and tries to *decrypt* the wrapped vault key. Only
    /// the correct password yields a key that passes the GCM tag check, so a
    /// wrong password fails cleanly and can't damage the vault.
    pub fn unlock(&self, username: &str, password: &str) -> Result<Vault> {
        let (dir, _user_id, vault_key) = self.unlock_raw(username, password)?;
        Vault::new(&dir, &vault_key)
    }

    fn unlock_raw(&self, username: &str, password: &str) -> Result<(PathBuf, String, Key)> {
        let user_id = self.user_id(username)?;
        let dir = self.user_dir(&user_id);

        let header_bytes = match fs::read(dir.join("vault.json")) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(Error::UserNotFound),
            Err(e) => return Err(e.into()),
        };
        let header: VaultHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| Error::InvalidHeader("vault.json is not valid"))?;
        if header.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(header.version));
        }
        if header.kdf_algorithm != KDF_ALGORITHM {
            return Err(Error::InvalidHeader("unknown key derivation algorithm"));
        }
        header.kdf.validate_bounds()?;

        let salt = decode_hex(&header.salt, "salt is not valid hex")?;
        let nonce = decode_hex(&header.nonce, "nonce is not valid hex")?;
        let wrapped = decode_hex(&header.wrapped_key, "wrapped key is not valid hex")?;
        if salt.len() != SALT_LEN {
            return Err(Error::InvalidHeader("salt has the wrong length"));
        }
        if nonce.len() != NONCE_LEN {
            return Err(Error::InvalidHeader("nonce has the wrong length"));
        }

        let password_key = crypto::derive_password_key(password.as_bytes(), &salt, header.kdf)?;
        let raw = crypto::open(&password_key, &nonce, &wrap_aad(&user_id), &wrapped).map_err(
            |e| match e {
                Error::Decrypt => Error::WrongPasswordOrCorrupt,
                other => other,
            },
        )?;
        if raw.len() != KEY_LEN {
            return Err(Error::InvalidHeader("wrapped key has the wrong length"));
        }
        let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
        vault_key.copy_from_slice(&raw);
        Ok((dir, user_id, vault_key))
    }

    /// Change the master password. Only the small wrapped vault key is
    /// re-encrypted; app files are untouched because the vault key itself
    /// doesn't change. The old password is verified first.
    pub fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
        params: KdfParams,
    ) -> Result<()> {
        params.validate_for_creation()?;
        if new_password.is_empty() {
            return Err(Error::Invalid("master password is empty"));
        }
        let (dir, user_id, vault_key) = self.unlock_raw(username, old_password)?;
        let header = wrap_vault_key(&vault_key, new_password, params, &user_id)?;
        write_atomic(&dir.join("vault.json"), &serde_json::to_vec_pretty(&header)?)?;
        Ok(())
    }
}

/// An unlocked user vault. Holds only derived subkeys (wiped on drop), never
/// the master password.
pub struct Vault {
    items_dir: PathBuf,
    name_key: Key,
    item_key: Key,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

impl Vault {
    fn new(user_dir: &Path, vault_key: &Key) -> Result<Vault> {
        Ok(Vault {
            items_dir: user_dir.join("items"),
            name_key: crypto::derive_subkey(vault_key, INFO_NAME_KEY)?,
            item_key: crypto::derive_subkey(vault_key, INFO_ITEM_KEY)?,
        })
    }

    /// App name -> (file id, path). The file name is an HMAC keyed with a
    /// per-user secret, so it reveals nothing about the app name and can't be
    /// brute-forced from a list of common app names.
    fn locate(&self, app_name: &str) -> Result<(String, PathBuf)> {
        let normalized = names::normalize(app_name)
            .ok_or(Error::Invalid("app name is empty or too long"))?;
        let id = crypto::keyed_id(&self.name_key[..], LABEL_APP, &normalized);
        let path = self.items_dir.join(format!("{id}.ipw"));
        Ok((id, path))
    }

    fn read_record(&self, id: &str, path: &Path) -> Result<Option<AppRecord>> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() < ITEM_MAGIC.len() + NONCE_LEN + TAG_LEN || bytes[..4] != ITEM_MAGIC[..] {
            return Err(Error::ItemCorrupt);
        }
        let (nonce, ciphertext) = bytes[ITEM_MAGIC.len()..].split_at(NONCE_LEN);
        // The file id is authenticated data, so a file copied or renamed to a
        // different app's slot fails to decrypt.
        let plaintext = crypto::open(&self.item_key, nonce, &item_aad(id), ciphertext).map_err(
            |e| match e {
                Error::Decrypt => Error::ItemCorrupt,
                other => other,
            },
        )?;
        decode_record(&plaintext).map(Some)
    }

    fn write_record(&self, id: &str, path: &Path, record: &AppRecord) -> Result<()> {
        let plaintext = encode_record(record)?;
        let (nonce, ciphertext) = crypto::seal(&self.item_key, &item_aad(id), &plaintext)?;
        let mut out = Vec::with_capacity(ITEM_MAGIC.len() + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(ITEM_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        write_atomic(path, &out)?;
        Ok(())
    }

    /// Everything saved for an app, or `None` if that app isn't saved.
    pub fn get_app(&self, app_name: &str) -> Result<Option<AppRecord>> {
        let (id, path) = self.locate(app_name)?;
        self.read_record(&id, &path)
    }

    pub fn app_exists(&self, app_name: &str) -> Result<bool> {
        let (_, path) = self.locate(app_name)?;
        Ok(path.is_file())
    }

    /// Save an entry under an app, creating the app's file if needed.
    pub fn add_entry(&self, app_name: &str, entry: Entry) -> Result<()> {
        let display = names::display_form(app_name)
            .ok_or(Error::Invalid("app name is empty or too long"))?;
        let (id, path) = self.locate(app_name)?;
        let now = now_unix();
        let mut record = self.read_record(&id, &path)?.unwrap_or_else(|| AppRecord {
            display_name: display,
            entries: Vec::new(),
            created_at: now,
            updated_at: now,
        });
        record.entries.push(entry);
        record.updated_at = now;
        self.write_record(&id, &path, &record)
    }

    /// Modify one entry in place (e.g. rotate its password).
    pub fn update_entry<F: FnOnce(&mut Entry)>(
        &self,
        app_name: &str,
        entry_id: &str,
        change: F,
    ) -> Result<()> {
        let (id, path) = self.locate(app_name)?;
        let mut record = self.read_record(&id, &path)?.ok_or(Error::EntryNotFound)?;
        let entry = record
            .entries
            .iter_mut()
            .find(|e| e.id == entry_id)
            .ok_or(Error::EntryNotFound)?;
        change(entry);
        let now = now_unix();
        entry.updated_at = now;
        record.updated_at = now;
        self.write_record(&id, &path, &record)
    }

    /// Remove one entry. If it was the app's last entry, the app file is
    /// deleted too.
    pub fn remove_entry(&self, app_name: &str, entry_id: &str) -> Result<()> {
        let (id, path) = self.locate(app_name)?;
        let mut record = self.read_record(&id, &path)?.ok_or(Error::EntryNotFound)?;
        let before = record.entries.len();
        record.entries.retain(|e| e.id != entry_id);
        if record.entries.len() == before {
            return Err(Error::EntryNotFound);
        }
        if record.entries.is_empty() {
            fs::remove_file(&path)?;
            return Ok(());
        }
        record.updated_at = now_unix();
        self.write_record(&id, &path, &record)
    }

    /// Delete an app and all its entries. Returns whether anything existed.
    pub fn delete_app(&self, app_name: &str) -> Result<bool> {
        let (_, path) = self.locate(app_name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Display names of all saved apps, sorted. Decrypts every app file, so
    /// it's meant for management screens and tests; the capture/paste flow
    /// only ever needs `get_app`.
    pub fn list_apps(&self) -> Result<Vec<String>> {
        let read_dir = match fs::read_dir(&self.items_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names_out = Vec::new();
        for item in read_dir {
            let path = item?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ipw") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if let Some(record) = self.read_record(id, &path)? {
                names_out.push(record.display_name);
            }
        }
        names_out.sort_by_key(|n| n.to_lowercase());
        Ok(names_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;

    fn new_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn entry(user: &str, secret: &str) -> Entry {
        Entry::new(user, secret, None).unwrap()
    }

    /// Every file under `root` (path, bytes), sorted.
    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            for e in fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    let bytes = fs::read(&p).unwrap();
                    out.push((p, bytes));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, &mut out);
        out.sort();
        out
    }

    fn item_files(root: &Path) -> Vec<PathBuf> {
        snapshot(root)
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("ipw"))
            .collect()
    }

    #[test]
    fn create_lock_unlock_roundtrip_across_store_instances() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "correct horse", FAST).unwrap();
        vault
            .add_entry("Netflix", entry("alice@example.com", "hunter2"))
            .unwrap();
        drop(vault);

        // A brand new Store on the same folder (as after an app restart).
        let store2 = Store::open(dir.path()).unwrap();
        let vault = store2.unlock("alice", "correct horse").unwrap();
        let app = vault.get_app("netflix").unwrap().unwrap();
        assert_eq!(app.display_name, "Netflix");
        assert_eq!(app.entries.len(), 1);
        assert_eq!(app.entries[0].username, "alice@example.com");
        assert_eq!(app.entries[0].secret, "hunter2");
        assert!(vault.get_app("hulu").unwrap().is_none());
    }

    #[test]
    fn wrong_password_is_rejected_and_changes_nothing() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "correct horse", FAST).unwrap();
        vault.add_entry("Netflix", entry("a", "hunter2")).unwrap();
        drop(vault);

        let before = snapshot(dir.path());
        for wrong in ["wrong", "correct hors", "Correct horse", " correct horse"] {
            assert!(matches!(
                store.unlock("alice", wrong),
                Err(Error::WrongPasswordOrCorrupt)
            ));
        }
        // Nothing was written or re-encrypted by the failed attempts...
        assert_eq!(snapshot(dir.path()), before);
        // ...so the real password still works.
        let vault = store.unlock("alice", "correct horse").unwrap();
        assert_eq!(
            vault.get_app("netflix").unwrap().unwrap().entries[0].secret,
            "hunter2"
        );
    }

    #[test]
    fn unknown_user_and_duplicate_user() {
        let (_dir, store) = new_store();
        assert!(matches!(
            store.unlock("nobody", "pw"),
            Err(Error::UserNotFound)
        ));
        store.create_user("Alice", "pw", FAST).unwrap();
        assert!(store.user_exists(" alice ").unwrap());
        assert!(matches!(
            store.create_user("alice", "pw2", FAST),
            Err(Error::UserExists)
        ));
    }

    #[test]
    fn empty_inputs_are_rejected() {
        let (_dir, store) = new_store();
        assert!(store.create_user("  ", "pw", FAST).is_err());
        assert!(store.create_user("alice", "", FAST).is_err());
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        assert!(vault.get_app("   ").is_err());
    }

    #[test]
    fn app_names_are_case_and_whitespace_insensitive() {
        let (_dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        vault.add_entry("Netflix", entry("a", "one")).unwrap();
        vault.add_entry("  NETFLIX ", entry("b", "two")).unwrap();
        let app = vault.get_app("netflix").unwrap().unwrap();
        assert_eq!(app.entries.len(), 2);
        assert_eq!(vault.list_apps().unwrap(), vec!["Netflix".to_string()]);
        assert!(vault.app_exists("nEtFlIx").unwrap());
    }

    #[test]
    fn nothing_on_disk_reveals_app_names_or_secrets() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        vault
            .add_entry("Netflix", entry("alice@example.com", "hunter2"))
            .unwrap();
        for (path, bytes) in snapshot(dir.path()) {
            let rel = path.strip_prefix(dir.path()).unwrap().to_string_lossy();
            let rel = rel.to_lowercase();
            assert!(!rel.contains("netflix"), "file name leaks app: {rel}");
            assert!(!rel.contains("alice"), "path leaks username: {rel}");
            let needles: [&[u8]; 3] = [b"netflix", b"hunter2", b"alice@example.com"];
            for needle in needles {
                assert!(
                    !bytes
                        .windows(needle.len())
                        .any(|w| w.eq_ignore_ascii_case(needle)),
                    "file contents leak plaintext in {rel}"
                );
            }
        }
    }

    #[test]
    fn file_names_differ_between_users_and_installs() {
        // Same app name, two users in one store -> different file names.
        let (dir, store) = new_store();
        let v1 = store.create_user("alice", "pw1", FAST).unwrap();
        let v2 = store.create_user("bob", "pw2", FAST).unwrap();
        v1.add_entry("Netflix", entry("a", "x")).unwrap();
        v2.add_entry("Netflix", entry("b", "y")).unwrap();
        let names: std::collections::HashSet<_> = item_files(dir.path())
            .iter()
            .map(|p| p.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(names.len(), 2);

        // Same username in two separate installs -> different folder names.
        let (_d2, other) = new_store();
        assert_ne!(
            store.user_id("alice").unwrap(),
            other.user_id("alice").unwrap()
        );
    }

    #[test]
    fn tampered_app_file_is_detected() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        vault.add_entry("Netflix", entry("a", "x")).unwrap();
        let file = item_files(dir.path()).remove(0);
        let mut bytes = fs::read(&file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&file, bytes).unwrap();
        assert!(matches!(
            vault.get_app("netflix"),
            Err(Error::ItemCorrupt)
        ));
    }

    #[test]
    fn swapping_two_app_files_is_detected() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        vault.add_entry("Netflix", entry("a", "x")).unwrap();
        vault.add_entry("Hulu", entry("b", "y")).unwrap();
        let files = item_files(dir.path());
        assert_eq!(files.len(), 2);
        let (a, b) = (fs::read(&files[0]).unwrap(), fs::read(&files[1]).unwrap());
        fs::write(&files[0], b).unwrap();
        fs::write(&files[1], a).unwrap();
        assert!(matches!(vault.get_app("netflix"), Err(Error::ItemCorrupt)));
        assert!(matches!(vault.get_app("hulu"), Err(Error::ItemCorrupt)));
    }

    #[test]
    fn app_files_from_another_user_do_not_decrypt() {
        let (dir, store) = new_store();
        let v1 = store.create_user("alice", "pw1", FAST).unwrap();
        let v2 = store.create_user("bob", "pw2", FAST).unwrap();
        v1.add_entry("Netflix", entry("a", "x")).unwrap();
        let file = item_files(dir.path()).remove(0);
        let bytes = fs::read(&file).unwrap();
        // Bob's vault has a different name key, so this file isn't even at
        // the path Bob would look. Force it there and confirm it's rejected.
        let (_, bob_path) = v2.locate("netflix").unwrap();
        fs::create_dir_all(bob_path.parent().unwrap()).unwrap();
        fs::write(&bob_path, bytes).unwrap();
        assert!(matches!(v2.get_app("netflix"), Err(Error::ItemCorrupt)));
    }

    #[test]
    fn tampering_with_the_header_is_detected() {
        let (_dir, store) = new_store();
        store.create_user("alice", "pw", FAST).unwrap();
        let path = store
            .user_dir(&store.user_id("alice").unwrap())
            .join("vault.json");

        let original = fs::read(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&original).unwrap();
        json["kdf"]["t_cost"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(matches!(
            store.unlock("alice", "pw"),
            Err(Error::WrongPasswordOrCorrupt)
        ));

        // Hostile parameters are refused before any expensive work happens.
        json["kdf"]["t_cost"] = serde_json::json!(1);
        json["kdf"]["m_cost_kib"] = serde_json::json!(4_000_000u32);
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(matches!(
            store.unlock("alice", "pw"),
            Err(Error::InvalidHeader(_))
        ));

        // Restoring the original makes it work again.
        fs::write(&path, original).unwrap();
        assert!(store.unlock("alice", "pw").is_ok());
    }

    #[test]
    fn change_password_rewraps_without_touching_app_files() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "old pw", FAST).unwrap();
        vault.add_entry("Netflix", entry("a", "hunter2")).unwrap();
        drop(vault);
        let app_files_before: Vec<_> = item_files(dir.path())
            .iter()
            .map(|p| fs::read(p).unwrap())
            .collect();

        assert!(matches!(
            store.change_password("alice", "not the old pw", "new pw", FAST),
            Err(Error::WrongPasswordOrCorrupt)
        ));
        store
            .change_password("alice", "old pw", "new pw", FAST)
            .unwrap();

        assert!(matches!(
            store.unlock("alice", "old pw"),
            Err(Error::WrongPasswordOrCorrupt)
        ));
        let vault = store.unlock("alice", "new pw").unwrap();
        assert_eq!(
            vault.get_app("netflix").unwrap().unwrap().entries[0].secret,
            "hunter2"
        );
        let app_files_after: Vec<_> = item_files(dir.path())
            .iter()
            .map(|p| fs::read(p).unwrap())
            .collect();
        assert_eq!(app_files_before, app_files_after);
    }

    #[test]
    fn update_and_remove_entries() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        let e1 = entry("a", "one");
        let e2 = entry("b", "two");
        let (id1, id2) = (e1.id.clone(), e2.id.clone());
        vault.add_entry("Netflix", e1).unwrap();
        vault.add_entry("Netflix", e2).unwrap();

        vault
            .update_entry("netflix", &id1, |e| e.secret = "rotated".into())
            .unwrap();
        let app = vault.get_app("netflix").unwrap().unwrap();
        assert_eq!(
            app.entries.iter().find(|e| e.id == id1).unwrap().secret,
            "rotated"
        );

        vault.remove_entry("netflix", &id1).unwrap();
        assert_eq!(vault.get_app("netflix").unwrap().unwrap().entries.len(), 1);
        assert!(matches!(
            vault.remove_entry("netflix", &id1),
            Err(Error::EntryNotFound)
        ));

        vault.remove_entry("netflix", &id2).unwrap();
        assert!(vault.get_app("netflix").unwrap().is_none());
        assert!(item_files(dir.path()).is_empty());
    }

    #[test]
    fn delete_app_and_list_apps() {
        let (_dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        assert!(vault.list_apps().unwrap().is_empty());
        vault.add_entry("Netflix", entry("a", "x")).unwrap();
        vault.add_entry("amazon", entry("a", "y")).unwrap();
        assert_eq!(
            vault.list_apps().unwrap(),
            vec!["amazon".to_string(), "Netflix".to_string()]
        );
        assert!(vault.delete_app("NETFLIX").unwrap());
        assert!(!vault.delete_app("netflix").unwrap());
        assert_eq!(vault.list_apps().unwrap(), vec!["amazon".to_string()]);
    }

    #[test]
    fn file_sizes_only_reveal_a_coarse_bucket() {
        let (dir, store) = new_store();
        let vault = store.create_user("alice", "pw", FAST).unwrap();
        vault.add_entry("Short", entry("a", "x")).unwrap();
        vault
            .add_entry("Longer", entry("someone@example.com", &"y".repeat(200)))
            .unwrap();
        let sizes: std::collections::HashSet<u64> = item_files(dir.path())
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .collect();
        assert_eq!(sizes.len(), 1, "small records should pad to the same size");
    }

    #[test]
    fn missing_install_file_is_refused_instead_of_regenerated() {
        let (dir, store) = new_store();
        store.create_user("alice", "pw", FAST).unwrap();
        fs::remove_file(dir.path().join("install.json")).unwrap();
        assert!(matches!(
            Store::open(dir.path()),
            Err(Error::InvalidHeader(_))
        ));
    }
}
