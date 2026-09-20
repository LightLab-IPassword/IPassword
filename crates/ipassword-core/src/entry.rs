use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::random_array;
use crate::error::{Error, Result};

/// Records are padded to a multiple of this many bytes before encryption, so
/// file sizes only reveal a coarse size bucket, not exact content length.
const PAD_BUCKET: usize = 1024;

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One saved login for an app. Wiped from memory on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    /// Random ID, used to target this entry for update/removal.
    pub id: String,
    /// The account's username or email.
    pub username: String,
    /// The password (or whatever secret text was captured).
    pub secret: String,
    #[serde(default)]
    pub note: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Entry {
    pub fn new(
        username: impl Into<String>,
        secret: impl Into<String>,
        note: Option<String>,
    ) -> Result<Entry> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(Error::Invalid("secret is empty"));
        }
        let now = now_unix();
        Ok(Entry {
            id: hex::encode(random_array::<8>()?),
            username: username.into(),
            secret,
            note,
            created_at: now,
            updated_at: now,
        })
    }
}

// Deliberately hides the secret so it can't leak through `{:?}` or logs.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Everything saved for one app (the decrypted contents of one app file).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppRecord {
    /// The app name as the user typed it (whitespace-collapsed, case kept).
    pub display_name: String,
    pub entries: Vec<Entry>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Frame: u32 LE length || JSON || zero padding up to the next bucket.
pub(crate) fn encode_record(record: &AppRecord) -> Result<Zeroizing<Vec<u8>>> {
    let json = Zeroizing::new(serde_json::to_vec(record)?);
    let framed_len = 4 + json.len();
    let padded_len = framed_len.div_ceil(PAD_BUCKET) * PAD_BUCKET;
    let mut buf = Zeroizing::new(Vec::with_capacity(padded_len));
    buf.extend_from_slice(&(json.len() as u32).to_le_bytes());
    buf.extend_from_slice(&json);
    buf.resize(padded_len, 0);
    Ok(buf)
}

pub(crate) fn decode_record(buf: &[u8]) -> Result<AppRecord> {
    let len_bytes: [u8; 4] = buf
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::ItemCorrupt)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let end = 4usize.checked_add(len).ok_or(Error::ItemCorrupt)?;
    let body = buf.get(4..end).ok_or(Error::ItemCorrupt)?;
    serde_json::from_slice(body).map_err(|_| Error::ItemCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AppRecord {
        AppRecord {
            display_name: "Netflix".into(),
            entries: vec![Entry::new("a@b.c", "hunter2", None).unwrap()],
            created_at: 1,
            updated_at: 2,
        }
    }

    #[test]
    fn encode_decode_roundtrip_and_padding() {
        let enc = encode_record(&record()).unwrap();
        assert_eq!(enc.len() % PAD_BUCKET, 0);
        let dec = decode_record(&enc).unwrap();
        assert_eq!(dec.display_name, "Netflix");
        assert_eq!(dec.entries[0].secret, "hunter2");
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_record(&[]).is_err());
        assert!(decode_record(&[255, 255, 255, 255, 1]).is_err());
        assert!(decode_record(&[2, 0, 0, 0, b'h', b'i']).is_err());
    }

    #[test]
    fn debug_output_hides_secret() {
        let e = Entry::new("a@b.c", "hunter2", None).unwrap();
        let shown = format!("{e:?} {:?}", record());
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn empty_secret_rejected() {
        assert!(Entry::new("a", "", None).is_err());
    }
}
