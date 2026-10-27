//! Cryptographically secure secret generation and Base32 handling.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// Smallest accepted secret size in bytes (80 bits).
pub const MIN_SECRET_BYTES: usize = 10;
/// Default secret size in bytes (160 bits, as recommended by RFC 4226).
pub const DEFAULT_SECRET_BYTES: usize = 20;
/// Largest accepted secret size in bytes (the SHA-512 block size).
pub const MAX_SECRET_BYTES: usize = 64;

/// A shared TOTP secret. Memory is wiped on drop and `Debug` never prints it.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

fn check_len(len: usize) -> Result<()> {
    if (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&len) {
        Ok(())
    } else {
        Err(Error::SecretLength {
            min: MIN_SECRET_BYTES,
            max: MAX_SECRET_BYTES,
            got: len,
        })
    }
}

impl Secret {
    /// Generates a new secret of `len` bytes from the operating-system CSPRNG.
    pub fn generate(len: usize) -> Result<Self> {
        check_len(len)?;
        let mut bytes = vec![0u8; len];
        getrandom::fill(&mut bytes).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// Builds a secret from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    /// Parses a Base32 secret. Case, spaces, hyphens and `=` padding are ignored.
    pub fn from_base32(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let bytes = Zeroizing::new(
            BASE32_NOPAD
                .decode(cleaned.as_bytes())
                .map_err(|e| Error::InvalidSecret(e.to_string()))?,
        );
        Self::from_bytes(&bytes)
    }

    /// Encodes the secret as unpadded RFC 4648 Base32.
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// Raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn generates_requested_length() {
        for len in [MIN_SECRET_BYTES, DEFAULT_SECRET_BYTES, 32, MAX_SECRET_BYTES] {
            assert_eq!(Secret::generate(len).unwrap().as_bytes().len(), len);
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(Secret::generate(MIN_SECRET_BYTES - 1).is_err());
        assert!(Secret::generate(MAX_SECRET_BYTES + 1).is_err());
        assert!(Secret::from_bytes(&[1; 9]).is_err());
    }

    #[test]
    fn generated_secrets_differ() {
        let a = Secret::generate(20).unwrap();
        let b = Secret::generate(20).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn base32_roundtrip() {
        let s = Secret::generate(20).unwrap();
        let again = Secret::from_base32(&s.to_base32()).unwrap();
        assert_eq!(s, again);
        assert_eq!(s.to_base32().len(), 32);
    }

    #[test]
    fn base32_is_normalised() {
        let canonical = Secret::from_base32(RFC).unwrap();
        assert_eq!(canonical.as_bytes(), b"12345678901234567890");
        let messy = "gezd gnbv-gy3t qojq GEZDGNBVGY3TQOJQ";
        assert_eq!(Secret::from_base32(messy).unwrap(), canonical);
        assert_eq!(
            Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====").unwrap(),
            canonical
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(Secret::from_base32("not base32 !!").is_err());
        assert!(Secret::from_base32("").is_err());
        assert!(Secret::from_base32("MFRGG").is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let s = Secret::from_base32(RFC).unwrap();
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }
}
