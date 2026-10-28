//! # otpforge
//!
//! Secure generator for two-factor authentication (TOTP) secrets.
//!
//! * CSPRNG-backed secret generation with zeroize-on-drop storage
//! * RFC 4226 / RFC 6238 compliant HOTP/TOTP (SHA-1, SHA-256, SHA-512)
//! * `otpauth://` provisioning URIs, terminal and SVG QR codes
//! * Single-use backup codes
//! * Local account vault (optionally encrypted with Argon2id + ChaCha20-Poly1305)
//!
//! ```
//! use otpforge::{otp::{self, TotpParams}, secret::Secret, uri};
//!
//! let secret = Secret::generate(20)?;
//! let params = TotpParams::default();
//! let provisioning = uri::totp_uri(&secret, "alice@example.com", Some("ACME"), &params)?;
//! assert!(provisioning.starts_with("otpauth://totp/ACME:"));
//!
//! let code = otp::totp(&secret, 1_700_000_000, &params)?;
//! assert_eq!(otp::verify(&secret, &code, 1_700_000_000, &params, 1)?, Some(0));
//! # Ok::<(), otpforge::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backup;
pub mod clipboard;
pub mod error;
pub mod otp;
pub mod qr;
pub mod secret;
pub mod uri;
pub mod vault;

pub use error::{Error, Result};
