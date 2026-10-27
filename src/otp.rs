//! HOTP (RFC 4226) and TOTP (RFC 6238) primitives.

use std::fmt;
use std::str::FromStr;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Default number of digits.
pub const DEFAULT_DIGITS: u32 = 6;
/// Default time step in seconds.
pub const DEFAULT_PERIOD: u64 = 30;
/// Minimum number of digits.
pub const MIN_DIGITS: u32 = 6;
/// Maximum number of digits.
pub const MAX_DIGITS: u32 = 8;
/// Maximum time step in seconds.
pub const MAX_PERIOD: u64 = 3600;

/// HMAC hash algorithm.
///
/// `Sha1` is the only value supported by every authenticator app.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// HMAC-SHA1 (default, universally supported).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl Algorithm {
    /// Name as used in `otpauth://` URIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "").as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(Error::UnknownAlgorithm(s.to_owned())),
        }
    }
}

/// TOTP parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpParams {
    /// HMAC algorithm.
    pub algorithm: Algorithm,
    /// Number of digits (6..=8).
    pub digits: u32,
    /// Time step in seconds (1..=3600).
    pub period: u64,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Sha1,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
        }
    }
}

impl TotpParams {
    /// Creates validated parameters.
    pub fn new(algorithm: Algorithm, digits: u32, period: u64) -> Result<Self> {
        let params = Self {
            algorithm,
            digits,
            period,
        };
        params.validate()?;
        Ok(params)
    }

    /// Checks that digits and period are within supported ranges.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) {
            return Err(Error::InvalidDigits(self.digits));
        }
        if !(1..=MAX_PERIOD).contains(&self.period) {
            return Err(Error::InvalidPeriod(self.period));
        }
        Ok(())
    }
}

fn mac(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($hash:ty) => {{
            let mut m =
                <Hmac<$hash> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        Algorithm::Sha1 => run!(Sha1),
        Algorithm::Sha256 => run!(Sha256),
        Algorithm::Sha512 => run!(Sha512),
    }
}

/// Computes an HOTP value (RFC 4226).
pub fn hotp(secret: &Secret, counter: u64, algorithm: Algorithm, digits: u32) -> Result<String> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidDigits(digits));
    }
    let hash = mac(algorithm, secret.as_bytes(), &counter.to_be_bytes());
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let code = bin % 10u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

/// Computes the TOTP value (RFC 6238) for `unix_time`.
pub fn totp(secret: &Secret, unix_time: u64, params: &TotpParams) -> Result<String> {
    params.validate()?;
    hotp(
        secret,
        unix_time / params.period,
        params.algorithm,
        params.digits,
    )
}

/// Seconds until the code valid at `unix_time` expires.
pub fn seconds_remaining(unix_time: u64, period: u64) -> u64 {
    let period = period.max(1);
    period - unix_time % period
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verifies `code` against `unix_time` allowing `window` steps of clock drift
/// in either direction. Returns the matching step offset (negative = past).
pub fn verify(
    secret: &Secret,
    code: &str,
    unix_time: u64,
    params: &TotpParams,
    window: u32,
) -> Result<Option<i64>> {
    params.validate()?;
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != params.digits as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidCodeFormat(params.digits));
    }
    let step = unix_time / params.period;
    let window = i64::from(window);
    let mut matched = None;
    for offset in -window..=window {
        let Some(counter) = step.checked_add_signed(offset) else {
            continue;
        };
        let expected = hotp(secret, counter, params.algorithm, params.digits)?;
        if ct_eq(expected.as_bytes(), code.as_bytes()) && matched.is_none() {
            matched = Some(offset);
        }
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(len: usize) -> Secret {
        let seed = b"1234567890";
        let bytes: Vec<u8> = (0..len).map(|i| seed[i % 10]).collect();
        Secret::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        let k = key(20);
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(&k, counter as u64, Algorithm::Sha1, 6).unwrap(), *want);
        }
    }

    #[test]
    fn rfc6238_totp_vectors() {
        let cases = [
            (Algorithm::Sha1, 20, 59, "94287082"),
            (Algorithm::Sha1, 20, 1_111_111_109, "07081804"),
            (Algorithm::Sha1, 20, 1_234_567_890, "89005924"),
            (Algorithm::Sha1, 20, 2_000_000_000, "69279037"),
            (Algorithm::Sha256, 32, 59, "46119246"),
            (Algorithm::Sha256, 32, 1_111_111_109, "68084774"),
            (Algorithm::Sha512, 64, 59, "90693936"),
            (Algorithm::Sha512, 64, 1_111_111_109, "25091201"),
        ];
        for (algorithm, len, time, want) in cases {
            let params = TotpParams::new(algorithm, 8, 30).unwrap();
            assert_eq!(totp(&key(len), time, &params).unwrap(), want);
        }
    }

    #[test]
    fn verify_respects_window() {
        let k = key(20);
        let params = TotpParams::default();
        let now = 1_700_000_000;
        let code = totp(&k, now, &params).unwrap();
        assert_eq!(verify(&k, &code, now, &params, 0).unwrap(), Some(0));
        assert_eq!(verify(&k, &code, now + 30, &params, 1).unwrap(), Some(-1));
        assert_eq!(verify(&k, &code, now - 30, &params, 1).unwrap(), Some(1));
        assert_eq!(verify(&k, &code, now + 300, &params, 1).unwrap(), None);
    }

    #[test]
    fn verify_rejects_malformed_codes() {
        let k = key(20);
        let params = TotpParams::default();
        assert!(verify(&k, "12345", 0, &params, 1).is_err());
        assert!(verify(&k, "12345a", 0, &params, 1).is_err());
        assert!(verify(&k, "123 456", 0, &params, 1).is_ok());
    }

    #[test]
    fn params_are_validated() {
        assert!(TotpParams::new(Algorithm::Sha1, 5, 30).is_err());
        assert!(TotpParams::new(Algorithm::Sha1, 9, 30).is_err());
        assert!(TotpParams::new(Algorithm::Sha1, 6, 0).is_err());
        assert!(TotpParams::new(Algorithm::Sha1, 6, 3601).is_err());
    }

    #[test]
    fn algorithm_parsing() {
        assert_eq!("SHA-256".parse::<Algorithm>().unwrap(), Algorithm::Sha256);
        assert_eq!("sha1".parse::<Algorithm>().unwrap(), Algorithm::Sha1);
        assert!("md5".parse::<Algorithm>().is_err());
    }

    #[test]
    fn remaining_seconds() {
        assert_eq!(seconds_remaining(59, 30), 1);
        assert_eq!(seconds_remaining(60, 30), 30);
    }
}
