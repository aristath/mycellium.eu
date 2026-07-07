//! The out-of-band **contact card** — a compact `{version, handle, wallet}` a
//! peer shows in person (or over a trusted channel) so the other side can verify
//! them without reading a long safety number aloud.
//!
//! The wallet is public, so a card carries no secret. On the wire it travels as
//! hex-of-JSON; this type is the single source of truth for its field contract,
//! shared by every client (CLI, SDK, wasm) so the shape can never drift between
//! the builder and the parser.

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// A peer's self-asserted `(handle, wallet)` binding, verified out of band and
/// then checked against the directory's record. Serialized as JSON (then hex) on
/// the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactCard {
    /// Card format version (currently `1`).
    pub version: u32,
    /// The handle the card claims.
    pub handle: String,
    /// The wallet public key the card claims, lowercase hex.
    pub wallet: String,
}
