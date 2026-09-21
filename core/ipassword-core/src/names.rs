//! Normalization for the names users type (usernames and app names).
//!
//! Because the user types the name every time, "Netflix", " netflix " and
//! "NETFLIX" must all find the same file. Note: this does case folding via
//! `to_lowercase` and whitespace collapsing, but not full Unicode (NFC)
//! normalization.

const MAX_NAME_CHARS: usize = 256;

/// Whitespace-collapsed form, original case kept. Used for display.
/// `None` if empty or too long.
pub(crate) fn display_form(input: &str) -> Option<String> {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() || collapsed.chars().count() > MAX_NAME_CHARS {
        None
    } else {
        Some(collapsed)
    }
}

/// Canonical lookup form: display form, lowercased.
pub(crate) fn normalize(input: &str) -> Option<String> {
    display_form(input).map(|s| s.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_whitespace() {
        assert_eq!(normalize("  Net   FLIX ").as_deref(), Some("net flix"));
        assert_eq!(display_form("  Net   FLIX ").as_deref(), Some("Net FLIX"));
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(normalize("   ").is_none());
        assert!(normalize("").is_none());
        assert!(normalize(&"a".repeat(257)).is_none());
        assert!(normalize(&"a".repeat(256)).is_some());
    }
}
