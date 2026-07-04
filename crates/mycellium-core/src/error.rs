//! The single error type for the core.

use core::fmt;

/// Errors produced by the Mycellium core.
///
/// Host-supplied traits ([`crate::transport`], [`crate::storage`]) carry their
/// own associated error types; this enum covers protocol-level failures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A handle violated the naming rules (see [`crate::identity::Handle`]).
    InvalidHandle,
    /// A signature failed to verify against the claimed key.
    BadSignature,
    /// Bytes could not be decoded into the expected structure.
    Malformed,
    /// A record was older than one already known (anti-rollback, `seq`).
    StaleRecord,
    /// AEAD decryption or authentication failed.
    DecryptFailed,
    /// A message would require skipping more keys than allowed.
    TooManySkipped,
    /// A key-agreement input was a low-order point (all-zero DH output); the
    /// handshake fails closed rather than deriving a weak secret.
    WeakKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::InvalidHandle => "invalid handle",
            Error::BadSignature => "signature verification failed",
            Error::Malformed => "malformed encoding",
            Error::StaleRecord => "record is older than the known one",
            Error::DecryptFailed => "decryption failed",
            Error::TooManySkipped => "too many skipped messages",
            Error::WeakKey => "low-order key rejected",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
