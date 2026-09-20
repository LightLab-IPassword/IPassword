//! The JSON shapes returned by ipassword_core.dll. Secrets are wiped when these are dropped.
#![cfg_attr(not(windows), allow(dead_code))]

use std::fmt;

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryData {
    pub id: String,
    #[serde(default)]
    pub username: String,
    pub secret: String,
    #[serde(default)]
    pub note: Option<String>,
}

// Never prints the secret.
impl fmt::Debug for EntryData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryData")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RecordData {
    pub display_name: String,
    pub entries: Vec<EntryData>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_the_core_produces() {
        let json = r#"{"display_name":"Netflix","entries":[
            {"id":"ab12","username":"a@b.c","secret":"hunter2","note":null,"created_at":1,"updated_at":2}
        ],"created_at":1,"updated_at":2}"#;
        let record: RecordData = serde_json::from_str(json).unwrap();
        assert_eq!(record.display_name, "Netflix");
        assert_eq!(record.entries[0].username, "a@b.c");
        assert_eq!(record.entries[0].secret, "hunter2");
        assert!(record.entries[0].note.is_none());
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let json = r#"{"display_name":"X","entries":[{"id":"1","secret":"hunter2"}]}"#;
        let record: RecordData = serde_json::from_str(json).unwrap();
        assert!(!format!("{record:?}").contains("hunter2"));
    }
}
