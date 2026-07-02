//! Versioned wire encoding.
//!
//! One place decides how Mycellium types become bytes, so signing and transmission
//! stay consistent across every device. We use [postcard]: compact,
//! deterministic for a fixed type (no map reordering), and `no_std`-friendly.
//!
//! Two entry points:
//! - [`canonical`] — the exact bytes that get **signed** (no version prefix, so
//!   a signature stays valid regardless of envelope changes).
//! - [`encode`] / [`decode`] — framed for **transmission**, with a version byte.

use alloc::vec::Vec;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Error;

/// Current wire envelope version.
pub const VERSION: u8 = 1;

/// The deterministic canonical encoding of `value` — the bytes that get signed.
///
/// No version prefix: signatures are over the *content*, so they survive
/// envelope-format changes.
pub fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("in-memory postcard encoding is infallible")
}

/// Encode `value` for transmission: a 1-byte version, then its canonical body.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let body = canonical(value);
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(VERSION);
    out.extend_from_slice(&body);
    out
}

/// Decode a value produced by [`encode`], rejecting unknown versions.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    match bytes.split_first() {
        Some((&VERSION, body)) => postcard::from_bytes(body).map_err(|_| Error::Malformed),
        _ => Err(Error::Malformed),
    }
}
