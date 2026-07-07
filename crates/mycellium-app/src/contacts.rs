//! Contacts, trust pinning (TOFU), and key/identity-change detection.
//!
//! Nostr has **no built-in protection** against the key behind a human identity
//! changing: an `npub` is a raw public key, and a NIP-05 name (or any petname you
//! know a friend by) can silently start resolving to a *different* key — an
//! account migration, or an impersonation. MLS/Marmot secures the *transport*
//! once you know who you are talking to, but says nothing about whether the key
//! you are talking to is still the person you pinned.
//!
//! This module is that hardening:
//!
//! - A [`Contact`] pins the account public key you first saw for a local handle
//!   (trust-on-first-use).
//! - [`classify`] compares a *freshly observed* account key against the pin and
//!   the out-of-band verification record, yielding a [`TrustStatus`]. A different
//!   key surfaces as [`TrustStatus::IdentityChanged`] — the engine refuses to
//!   silently re-pin it and warns instead.
//! - [`safety_number`] is the out-of-band verification helper: a stable digit
//!   string derived from the two account keys that two people can read aloud to
//!   confirm they pinned the same identities.

use nostr::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A local address-book entry: a stable handle you know a person by, with the
/// **account public key** you pinned for them on first add (TOFU).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// The local handle / petname you refer to this person by (stable key).
    pub id: String,
    /// The account public key pinned when the contact was added.
    pub account: PublicKey,
    /// Optional NIP-05 identifier (`name@domain`) recorded for the contact — the
    /// address to re-resolve when checking the name→key binding still holds.
    pub nip05: Option<String>,
    /// Whether the recorded [`Self::nip05`] address was **verified** to resolve to
    /// the pinned [`Self::account`] key (a NIP-05 binding check — distinct from the
    /// out-of-band [`Self::verified`] safety-number confirmation). A later
    /// rebinding to a different key does **not** clear this silently; it surfaces
    /// as a mismatch signal instead.
    pub nip05_verified: bool,
    /// Optional display name.
    pub name: Option<String>,
    /// Whether this identity was confirmed out of band (safety-number compare).
    pub verified: bool,
    /// Unix seconds when the contact was added.
    pub added_at: u64,
}

/// How much the engine trusts that an observed account key really belongs to a
/// known contact, in the account-key (npub) identity model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustStatus {
    /// Confirmed out of band **and** the observed key matches — safe.
    Verified,
    /// Pinned on first use (TOFU) and the observed key matches — trusted.
    Pinned,
    /// A key was pinned/verified before, but the observed key **differs**. A new
    /// account, a key migration, or an impersonation attempt — never silently
    /// trusted.
    IdentityChanged,
    /// No pin exists for this handle yet — a first, unverified contact.
    Unverified,
}

impl TrustStatus {
    /// A short, glanceable label for CLI/UI output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TrustStatus::Verified => "verified",
            TrustStatus::Pinned => "pinned (TOFU, not verified)",
            TrustStatus::IdentityChanged => "IDENTITY CHANGED",
            TrustStatus::Unverified => "unverified (first contact)",
        }
    }

    /// Whether it is safe to proceed automatically. Only a matching pin or an
    /// out-of-band verification qualifies; an identity change or an unknown
    /// contact must be surfaced to the user.
    #[must_use]
    pub fn is_trusted(self) -> bool {
        matches!(self, TrustStatus::Verified | TrustStatus::Pinned)
    }
}

/// Classify how much an `observed` account key is trusted for `contact`.
///
/// - Verified pin that matches → [`TrustStatus::Verified`].
/// - Verified/plain pin that **differs** → [`TrustStatus::IdentityChanged`].
/// - Plain (TOFU) pin that matches → [`TrustStatus::Pinned`].
#[must_use]
pub fn classify(contact: Option<&Contact>, observed: &PublicKey) -> TrustStatus {
    match contact {
        None => TrustStatus::Unverified,
        Some(c) if &c.account != observed => TrustStatus::IdentityChanged,
        Some(c) if c.verified => TrustStatus::Verified,
        Some(_) => TrustStatus::Pinned,
    }
}

/// A stable, human-readable **safety number** for a pair of account keys, for
/// out-of-band verification (read it aloud / scan it; if both sides see the same
/// number they pinned the same two identities).
///
/// Order-independent (both parties compute the same value): the two keys are
/// sorted, concatenated, and hashed; the digest is rendered as 12 groups of five
/// decimal digits.
#[must_use]
pub fn safety_number(a: &PublicKey, b: &PublicKey) -> String {
    let (x, y) = {
        let (ha, hb) = (a.to_hex(), b.to_hex());
        if ha <= hb {
            (ha, hb)
        } else {
            (hb, ha)
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(b"mycellium-safety-number:v1");
    hasher.update(x.as_bytes());
    hasher.update(y.as_bytes());
    let digest = hasher.finalize();

    // 12 groups of 5 digits: each group is 5 bytes of the digest reduced mod 1e5.
    let mut groups = Vec::with_capacity(12);
    for chunk in digest.chunks(2).take(12) {
        let n = u32::from(chunk[0]) << 8 | u32::from(*chunk.get(1).unwrap_or(&0));
        groups.push(format!("{:05}", n % 100_000));
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn contact(account: PublicKey, verified: bool) -> Contact {
        Contact {
            id: "bob".into(),
            account,
            nip05: None,
            nip05_verified: false,
            name: None,
            verified,
            added_at: 0,
        }
    }

    #[test]
    fn classify_reflects_pin_and_verification() {
        let bob1 = Keys::generate().public_key();
        let bob2 = Keys::generate().public_key();

        // Nobody known → unverified first contact.
        assert_eq!(classify(None, &bob1), TrustStatus::Unverified);

        // Pinned (TOFU): same key trusted, different key flagged.
        let pinned = contact(bob1, false);
        assert_eq!(classify(Some(&pinned), &bob1), TrustStatus::Pinned);
        assert_eq!(classify(Some(&pinned), &bob2), TrustStatus::IdentityChanged);

        // Verified out of band: same key strongly trusted, different key flagged.
        let verified = contact(bob1, true);
        assert_eq!(classify(Some(&verified), &bob1), TrustStatus::Verified);
        assert_eq!(
            classify(Some(&verified), &bob2),
            TrustStatus::IdentityChanged
        );
    }

    #[test]
    fn safety_number_is_order_independent_and_stable() {
        let a = Keys::generate().public_key();
        let b = Keys::generate().public_key();
        let ab = safety_number(&a, &b);
        let ba = safety_number(&b, &a);
        assert_eq!(ab, ba, "safety number must not depend on argument order");
        assert_eq!(ab, safety_number(&a, &b), "must be deterministic");
        assert_eq!(ab.split(' ').count(), 12, "12 groups");
        assert!(ab
            .split(' ')
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
        // Different pairs → different numbers (overwhelmingly).
        let c = Keys::generate().public_key();
        assert_ne!(ab, safety_number(&a, &c));
    }
}
