//! Error type shared by the library and the CLI.

use thiserror::Error;

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by `otpforge`.
#[derive(Debug, Error)]
pub enum Error {
    /// Secret length is outside the supported range.
    #[error("secret length must be between {min} and {max} bytes (got {got})")]
    SecretLength {
        /// Minimum accepted length in bytes.
        min: usize,
        /// Maximum accepted length in bytes.
        max: usize,
        /// Length that was supplied.
        got: usize,
    },
    /// The supplied Base32 secret could not be decoded.
    #[error("invalid base32 secret: {0}")]
    InvalidSecret(String),
    /// No secret was supplied to a command that needs one.
    #[error("no secret provided: use --secret-stdin, --secret or the OTPFORGE_SECRET environment variable")]
    MissingSecret,
    /// Digit count outside 6..=8.
    #[error("digits must be between 6 and 8 (got {0})")]
    InvalidDigits(u32),
    /// Period outside 1..=3600 seconds.
    #[error("period must be between 1 and 3600 seconds (got {0})")]
    InvalidPeriod(u64),
    /// The supplied one-time code is malformed.
    #[error("invalid code format: expected exactly {0} decimal digits")]
    InvalidCodeFormat(u32),
    /// Account or issuer label is not acceptable.
    #[error("invalid {field}: {reason}")]
    InvalidLabel {
        /// Which label was rejected.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Unknown HMAC algorithm name.
    #[error("unknown algorithm '{0}' (expected sha1, sha256 or sha512)")]
    UnknownAlgorithm(String),
    /// Backup code count outside 1..=100.
    #[error("backup code count must be between 1 and 100 (got {0})")]
    BackupCount(usize),
    /// Backup code length outside 6..=32.
    #[error("backup code length must be between 6 and 32 (got {0})")]
    BackupLength(usize),
    /// Operating-system random number generator failure.
    #[error("system random number generator failure: {0}")]
    Rng(String),
    /// QR code encoding failure.
    #[error("QR code error: {0}")]
    Qr(String),
    /// Output file already exists and `--force` was not given.
    #[error("refusing to overwrite existing file '{0}' (use --force)")]
    OutputExists(String),
    /// Mutually exclusive or unsupported option combination.
    #[error("{0}")]
    Usage(String),
    /// The system clock is set before the Unix epoch.
    #[error("system clock is set before the Unix epoch")]
    Clock,
    /// Malformed `otpauth://` URI.
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(&'static str),
    /// Account name is not acceptable.
    #[error("invalid account name '{0}': use 1-64 characters from A-Z a-z 0-9 . _ @ - (not starting with '-') and not a command name")]
    InvalidName(String),
    /// No saved account matches the query.
    #[error("no saved account matching '{0}' (see `otpforge list`, add one with `otpforge add`)")]
    EntryNotFound(String),
    /// Several saved accounts match the query.
    #[error("'{query}' is ambiguous, it matches: {matches}")]
    AmbiguousEntry {
        /// What the user typed.
        query: String,
        /// Comma-separated matching names.
        matches: String,
    },
    /// An account with this name already exists.
    #[error("account '{0}' already exists (use --force to replace it)")]
    EntryExists(String),
    /// Vault storage, encryption or format problem.
    #[error("vault error: {0}")]
    Vault(String),
    /// JSON (de)serialisation failure.
    #[error("format error: {0}")]
    Json(#[from] serde_json::Error),
    /// Clipboard unavailable or failed.
    #[error("clipboard error: {0}")]
    Clipboard(String),
    /// I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
