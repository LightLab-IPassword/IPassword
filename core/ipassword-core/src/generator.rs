//! Secure random password generation.
//!
//! Characters come from the operating system's random source. Each pick uses rejection
//! sampling, so every character in the pool is exactly as likely as any other (no modulo bias).
//! Every kind of character you turn on is guaranteed to appear at least once, so the result
//! passes sites' "needs a number / a capital / a symbol" rules.

use zeroize::Zeroizing;

use crate::crypto::random_array;
use crate::error::{Error, Result};

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;
pub const DEFAULT_LENGTH: usize = 20;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
// Chosen to be accepted by most sites: no quotes, backslash, spaces, or angle brackets.
const SYMBOLS: &str = "!@#$%^&*-_=+?.,:;~()[]{}";
// Characters that are easy to mistake for each other when read aloud or typed by hand.
const AMBIGUOUS: &str = "0O1lIo|";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            length: DEFAULT_LENGTH,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

fn class(chars: &str, avoid_ambiguous: bool) -> Vec<u8> {
    chars
        .bytes()
        .filter(|b| !(avoid_ambiguous && AMBIGUOUS.as_bytes().contains(b)))
        .collect()
}

/// A uniformly random number in `0..n` (for `1 <= n <= 256`).
fn random_below(n: usize) -> Result<usize> {
    debug_assert!((1..=256).contains(&n));
    // Throw away bytes from the uneven tail so that `byte % n` is unbiased.
    let limit = 256 - (256 % n);
    loop {
        let byte = usize::from(random_array::<1>()?[0]);
        if byte < limit {
            return Ok(byte % n);
        }
    }
}

/// Generates a password. The result is wiped from memory when dropped.
pub fn generate(options: &GenOptions) -> Result<Zeroizing<String>> {
    let mut classes: Vec<Vec<u8>> = Vec::new();
    if options.lowercase {
        classes.push(class(LOWER, options.avoid_ambiguous));
    }
    if options.uppercase {
        classes.push(class(UPPER, options.avoid_ambiguous));
    }
    if options.digits {
        classes.push(class(DIGITS, options.avoid_ambiguous));
    }
    if options.symbols {
        classes.push(class(SYMBOLS, options.avoid_ambiguous));
    }
    if classes.is_empty() {
        return Err(Error::Invalid("pick at least one kind of character"));
    }
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(Error::Invalid("password length must be 8 to 128"));
    }

    let pool: Vec<u8> = classes.iter().flatten().copied().collect();
    let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(options.length));

    // One from each enabled kind first, then fill the rest from everything allowed.
    for kind in &classes {
        chars.push(kind[random_below(kind.len())?]);
    }
    while chars.len() < options.length {
        chars.push(pool[random_below(pool.len())?]);
    }

    // Fisher-Yates shuffle so the guaranteed characters don't sit at the front.
    for i in (1..chars.len()).rev() {
        let j = random_below(i + 1)?;
        chars.swap(i, j);
    }

    String::from_utf8(chars.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto("generated password was not valid text"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(password: &str, set: &str) -> bool {
        password.chars().any(|c| set.contains(c))
    }

    #[test]
    fn exact_length_and_only_allowed_characters() {
        for length in [8, 20, 64, 128] {
            let options = GenOptions {
                length,
                ..GenOptions::default()
            };
            let password = generate(&options).unwrap();
            assert_eq!(password.chars().count(), length);
            let allowed = format!("{LOWER}{UPPER}{DIGITS}{SYMBOLS}");
            assert!(password.chars().all(|c| allowed.contains(c)));
        }
    }

    #[test]
    fn every_enabled_kind_appears_even_at_minimum_length() {
        let options = GenOptions {
            length: 8,
            ..GenOptions::default()
        };
        for _ in 0..300 {
            let password = generate(&options).unwrap();
            let text = password.as_str();
            assert!(has(text, LOWER), "no lowercase in {text}");
            assert!(has(text, UPPER), "no uppercase in {text}");
            assert!(has(text, DIGITS), "no digit in {text}");
            assert!(has(text, SYMBOLS), "no symbol in {text}");
        }
    }

    #[test]
    fn disabled_kinds_never_appear() {
        let options = GenOptions {
            length: 32,
            lowercase: true,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        };
        for _ in 0..300 {
            let password = generate(&options).unwrap();
            assert!(password.chars().all(|c| LOWER.contains(c) || DIGITS.contains(c)));
        }
    }

    #[test]
    fn look_alikes_are_excluded_when_asked() {
        let options = GenOptions {
            length: 40,
            avoid_ambiguous: true,
            ..GenOptions::default()
        };
        for _ in 0..300 {
            let password = generate(&options).unwrap();
            let text = password.as_str();
            assert!(!has(text, AMBIGUOUS), "look-alike in {text}");
        }
    }

    #[test]
    fn bad_options_are_rejected() {
        let none = GenOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..GenOptions::default()
        };
        assert!(generate(&none).is_err());
        for length in [0, 7, 129, 1000] {
            let options = GenOptions {
                length,
                ..GenOptions::default()
            };
            assert!(generate(&options).is_err(), "length {length}");
        }
    }

    #[test]
    fn passwords_are_not_repeated() {
        let options = GenOptions::default();
        let a = generate(&options).unwrap();
        let b = generate(&options).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn random_below_stays_in_range_and_is_roughly_uniform() {
        let mut counts = [0usize; 7];
        for _ in 0..14_000 {
            counts[random_below(7).unwrap()] += 1;
        }
        // Expected 2000 each (standard deviation about 41), so this is a very loose check.
        for count in counts {
            assert!((1500..2500).contains(&count), "{counts:?}");
        }
        for n in [1usize, 2, 3, 100, 256] {
            for _ in 0..200 {
                assert!(random_below(n).unwrap() < n);
            }
        }
    }
}
