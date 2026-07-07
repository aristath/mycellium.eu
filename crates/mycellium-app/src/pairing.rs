//! **Secure device pairing** — the trust root for the multi-device feature.
//!
//! The multi-device layer ([`mycellium_multidevice`]) trusts the account's signed
//! device list absolutely: whatever pubkeys the account key signs into the list
//! become full MLS leaves of the account, enrolled into every group. That makes
//! the *act of adding a device* the security boundary. If an attacker can get the
//! manager to sign a rogue key into the list, that rogue device joins every
//! conversation.
//!
//! Adding a device is inherently an out-of-band affair — the new device's pubkey
//! has to reach the manager over some channel (a QR code, a copy/paste string). A
//! naive flow trusts that channel: whatever pubkey arrives gets pinned. A
//! man-in-the-middle on the QR/copy channel could swap in their own key.
//!
//! This module closes that with a **short authentication string (SAS)**. Both
//! sides derive a short human code *deterministically from the device pubkey*:
//!
//! - The **new device** produces a [`PairingOffer`] carrying its freshly generated
//!   device pubkey, shows the offer string (copyable / QR), and shows its
//!   [`PairingOffer::sas`].
//! - The **manager** parses the received offer and computes the SAS from
//!   `offer.device_pubkey` — the *same* derivation — and displays it. The human
//!   confirms the two screens show the same code. **The human is the
//!   authenticated out-of-band channel; the SAS compare is the security.**
//!
//! Because the SAS is a function of the pubkey, a MITM who swapped the pubkey on
//! the copy/QR channel produces a *different* SAS on the manager's screen than the
//! new device shows → the human sees a mismatch → aborts. Same pubkey in, same
//! code out; different pubkey in, different code out.

use nostr::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The textual prefix of an encoded [`PairingOffer`] — a tag so a scanned/pasted
/// blob is recognisably a Mycellium pairing offer and not some other QR payload.
pub const PAIRING_OFFER_PREFIX: &str = "mycpair";

/// The current pairing-offer wire version. Bumped if the encoding or the SAS
/// derivation changes, so an old device and a new one can detect a mismatch
/// rather than silently derive different codes.
pub const PAIRING_OFFER_VERSION: u8 = 1;

/// A **pairing offer** minted by a brand-new device: its freshly generated device
/// pubkey plus the offer version. Shown to the manager as a copyable string / QR
/// via [`Display`](std::fmt::Display), parsed back via [`FromStr`](std::str::FromStr).
///
/// The offer is *not secret* — it carries only a public key. Its integrity is what
/// matters, and that is exactly what the [`PairingOffer::sas`] compare protects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingOffer {
    /// The new device's own freshly generated pubkey (its future MLS-leaf /
    /// KeyPackage identity).
    pub device_pubkey: PublicKey,
    /// The offer-format version (see [`PAIRING_OFFER_VERSION`]).
    pub v: u8,
}

impl PairingOffer {
    /// Mint an offer for a new device's pubkey at the current offer version.
    #[must_use]
    pub fn new(device_pubkey: PublicKey) -> Self {
        Self {
            device_pubkey,
            v: PAIRING_OFFER_VERSION,
        }
    }

    /// The **short authentication string** for this offer: a short human code
    /// derived deterministically from `device_pubkey`. Computed identically on the
    /// new device (from its own key) and on the manager (from the key in the
    /// received offer), so the two screens match iff the pubkey was not tampered
    /// with in transit. See [`sas_for`].
    #[must_use]
    pub fn sas(&self) -> String {
        sas_for(&self.device_pubkey)
    }
}

impl std::fmt::Display for PairingOffer {
    /// Compact, single-line encoding: `mycpair:<version>:<pubkey-hex>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{PAIRING_OFFER_PREFIX}:{}:{}",
            self.v,
            self.device_pubkey.to_hex()
        )
    }
}

impl std::str::FromStr for PairingOffer {
    type Err = ParseOfferError;

    /// Parse `mycpair:<version>:<pubkey-hex>`, rejecting a wrong prefix, an
    /// unsupported version, or a malformed pubkey.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.trim().splitn(3, ':');
        let prefix = parts.next().ok_or(ParseOfferError::BadFormat)?;
        let version = parts.next().ok_or(ParseOfferError::BadFormat)?;
        let pubkey = parts.next().ok_or(ParseOfferError::BadFormat)?;
        if prefix != PAIRING_OFFER_PREFIX {
            return Err(ParseOfferError::BadFormat);
        }
        let v: u8 = version.parse().map_err(|_| ParseOfferError::BadFormat)?;
        if v != PAIRING_OFFER_VERSION {
            return Err(ParseOfferError::UnsupportedVersion(v));
        }
        let device_pubkey =
            PublicKey::from_hex(pubkey).map_err(|e| ParseOfferError::BadPubkey(e.to_string()))?;
        Ok(Self { device_pubkey, v })
    }
}

/// Failure parsing a [`PairingOffer`] from its encoded string.
#[derive(Debug, thiserror::Error)]
pub enum ParseOfferError {
    /// The string was not a `mycpair:<v>:<pubkey>` triple.
    #[error("not a mycellium pairing offer (expected '{PAIRING_OFFER_PREFIX}:<v>:<pubkey-hex>')")]
    BadFormat,
    /// The version field named a format this build does not understand.
    #[error("unsupported pairing-offer version {0} (this build speaks {PAIRING_OFFER_VERSION})")]
    UnsupportedVersion(u8),
    /// The pubkey field was not a valid public key.
    #[error("invalid device pubkey in pairing offer: {0}")]
    BadPubkey(String),
}

/// Derive the pairing **SAS** from a device pubkey: a 6-digit decimal code shown
/// as two space-separated groups (`"NNN NNN"`).
///
/// This is the single shared derivation both sides call — the new device on its
/// own key, the manager on the key carried in the received offer — so it MUST stay
/// identical on both ends (that is the whole security argument). It is
/// domain-separated and version-tagged so it cannot collide with the account-key
/// [`crate::safety_number`] and so a future change is a clean version bump.
///
/// 6 decimal digits ≈ 20 bits: enough that an attacker who swapped the pubkey has
/// only a ~1-in-a-million chance of landing the same code the human is comparing
/// against — and they get one shot, live, in front of the user.
#[must_use]
pub fn sas_for(device_pubkey: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mycellium-pairing-sas:v1");
    hasher.update(device_pubkey.to_hex().as_bytes());
    let digest = hasher.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    #[test]
    fn offer_round_trips_through_its_string_encoding() {
        let pk = Keys::generate().public_key();
        let offer = PairingOffer::new(pk);
        let encoded = offer.to_string();
        assert!(encoded.starts_with("mycpair:1:"));
        let parsed: PairingOffer = encoded.parse().expect("round-trips");
        assert_eq!(parsed, offer);
        assert_eq!(parsed.device_pubkey, pk);
    }

    #[test]
    fn sas_is_deterministic_and_shape_is_six_digits() {
        let pk = Keys::generate().public_key();
        let offer = PairingOffer::new(pk);
        // Same pubkey → same code, on both sides of the pairing.
        assert_eq!(offer.sas(), sas_for(&pk));
        assert_eq!(offer.sas(), offer.sas());
        let sas = offer.sas();
        let groups: Vec<&str> = sas.split(' ').collect();
        assert_eq!(groups.len(), 2);
        assert!(groups
            .iter()
            .all(|g| g.len() == 3 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn tampered_pubkey_yields_a_different_sas() {
        // The property that makes pairing secure: swap the pubkey on the channel
        // and the SAS the manager computes no longer matches the new device's.
        let real = Keys::generate().public_key();
        let rogue = Keys::generate().public_key();
        assert_ne!(sas_for(&real), sas_for(&rogue));
    }

    #[test]
    fn bad_encodings_are_rejected() {
        assert!("nope".parse::<PairingOffer>().is_err());
        assert!("mycpair:1:not-hex".parse::<PairingOffer>().is_err());
        let pk = Keys::generate().public_key().to_hex();
        // Unsupported version.
        assert!(matches!(
            format!("mycpair:99:{pk}").parse::<PairingOffer>(),
            Err(ParseOfferError::UnsupportedVersion(99))
        ));
        // Wrong prefix.
        assert!(matches!(
            format!("other:1:{pk}").parse::<PairingOffer>(),
            Err(ParseOfferError::BadFormat)
        ));
    }
}
