//! Single-use recovery (backup) code generation.

use crate::error::{Error, Result};

/// Alphabet without look-alike characters (no `0 O 1 I`); exactly 32 symbols
/// so every random byte maps without modulo bias.
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Default number of backup codes.
pub const DEFAULT_COUNT: usize = 10;
/// Default code length in characters (50 bits of entropy).
pub const DEFAULT_LENGTH: usize = 10;

/// Generates `count` unique codes of `length` characters, hyphenated in groups of five.
pub fn generate(count: usize, length: usize) -> Result<Vec<String>> {
    if !(1..=100).contains(&count) {
        return Err(Error::BackupCount(count));
    }
    if !(6..=32).contains(&length) {
        return Err(Error::BackupLength(length));
    }
    let mut codes: Vec<String> = Vec::with_capacity(count);
    let mut buf = vec![0u8; length];
    while codes.len() < count {
        getrandom::fill(&mut buf).map_err(|e| Error::Rng(e.to_string()))?;
        let raw: Vec<u8> = buf.iter().map(|b| ALPHABET[(b & 0x1f) as usize]).collect();
        let code = raw
            .chunks(5)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-");
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    Ok(codes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_length_and_format() {
        let codes = generate(10, 10).unwrap();
        assert_eq!(codes.len(), 10);
        for c in &codes {
            assert_eq!(c.len(), 11);
            assert_eq!(c.as_bytes()[5], b'-');
            assert!(c.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn codes_are_unique() {
        let codes = generate(100, 6).unwrap();
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn odd_lengths() {
        assert_eq!(generate(1, 7).unwrap()[0].len(), 8);
    }

    #[test]
    fn bounds() {
        assert!(generate(0, 10).is_err());
        assert!(generate(101, 10).is_err());
        assert!(generate(1, 5).is_err());
        assert!(generate(1, 33).is_err());
    }
}
