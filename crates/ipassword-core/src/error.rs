use std::io;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors never contain secrets (passwords, keys, entry contents).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("malformed data: {0}")]
    Json(#[from] serde_json::Error),

    #[error("a user with that name already exists")]
    UserExists,

    #[error("no such user")]
    UserNotFound,

    /// The vault key could not be unwrapped. Authenticated encryption cannot
    /// tell "wrong password" from "header was tampered with / damaged", so
    /// both surface as this error.
    #[error("wrong master password (or the vault header is damaged)")]
    WrongPasswordOrCorrupt,

    /// An app file failed authentication or is structurally invalid.
    #[error("app file is corrupt, tampered with, or belongs to a different vault")]
    ItemCorrupt,

    #[error("no such entry")]
    EntryNotFound,

    #[error("invalid input: {0}")]
    Invalid(&'static str),

    #[error("invalid vault header: {0}")]
    InvalidHeader(&'static str),

    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("cryptographic failure: {0}")]
    Crypto(&'static str),

    /// Low-level AEAD authentication failure. Internal: the store maps this
    /// to `WrongPasswordOrCorrupt` or `ItemCorrupt` depending on context.
    #[error("authentication failed")]
    Decrypt,

    #[error("the system random number generator failed")]
    Rng,
}
