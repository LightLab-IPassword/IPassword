#![forbid(unsafe_code)]
//! # ipassword-core
//!
//! The crypto and storage core of IPassword. No UI, no OS hooks: those live in
//! other crates so this one can be tested (and audited) on its own.
//!
//! ## How unlocking works
//!
//! * On signup we generate a random 256-bit **vault key**, and encrypt ("wrap")
//!   it with AES-256-GCM under a key derived from the master password with
//!   Argon2id + a random salt. The salt, the Argon2 settings and the wrapped
//!   key are stored in `vault.json`. The master password, the derived key and
//!   the plain vault key are never written to disk.
//! * On login we re-derive the key from what was typed and try to *decrypt*
//!   the wrapped vault key. GCM authenticates, so only the right password
//!   succeeds; a wrong one fails without writing or re-encrypting anything.
//! * Two subkeys are derived from the vault key with HKDF-SHA256: one
//!   encrypts app files, the other names them.
//!
//! ## Files
//!
//! Each app is one encrypted file whose name is
//! `HMAC(name key, normalized app name)`, so the folder reveals neither app
//! names nor (because the key is per-user) anything a precomputed list of
//! common names could match. The real name lives inside the ciphertext. Each
//! file's ID is bound into its authentication tag, so files can't be swapped
//! between apps or users. Plaintexts are padded to 1 KiB buckets.
//!
//! ## Not secrets
//!
//! The algorithms, labels and file format are all public. Every key is
//! generated per user at runtime; nothing secret is ever compiled in.
//!
//! ## Known limits
//!
//! * Metadata visible to someone with the folder: the number of users, the
//!   number of apps per user, and coarse file sizes/timestamps.
//! * An offline attacker with the folder can guess master passwords, limited
//!   only by Argon2id's cost. A strong master password matters.
//! * `install.json` must travel with the folder. Without it usernames can't
//!   be mapped to their folders.
//! * Malware running as you can read memory and keystrokes. No local
//!   password manager fixes that.
//! * This code has not been independently audited.

mod crypto;
mod entry;
mod error;
mod fsutil;
mod names;
mod store;

pub use crypto::KdfParams;
pub use entry::{AppRecord, Entry};
pub use error::{Error, Result};
pub use store::{Store, Vault};
