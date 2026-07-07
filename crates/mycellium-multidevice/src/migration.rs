//! **Account-key migration attestation**: the signed, mutual-consent statement
//! that links an account's *old* identity key to a *new* one.
//!
//! # Why this exists
//!
//! An account is a stable Nostr identity — the **account key** (npub) that signs
//! the [device list](crate::DeviceList). Sometimes that key must change: routine
//! hygiene (proactive rotation), or recovery after the key is believed
//! compromised. Nostr has no built-in notion of "this new key continues that old
//! identity", so we define one.
//!
//! Crucially, MLS leaves are bound to **device** keys, not the account key, so an
//! account-key rotation does **not** re-key any MLS group. It only (a) re-signs
//! the device list under the new key and (b) publishes this attestation so a
//! contact who pinned the old key can *learn* about — and deliberately decide
//! whether to trust — the transition.
//!
//! # The trust model (mutual consent, not auto-accept)
//!
//! A migration is only meaningful if **both** keys consent:
//!
//! - The **old key** authorizes the move ("I am migrating to `new_pubkey`"). This
//!   is the **outer** Nostr event: it is *authored and signed by the old key*, so
//!   `event.pubkey` **is** the old identity. A migration that is not signed by the
//!   pinned old key is a forgery and is rejected outright ([`verify_migration`]).
//! - The **new key** accepts continuation ("I am the continuation of
//!   `old_pubkey`"). This is a nested Nostr event *signed by the new key*,
//!   embedded in the outer event's body. Both signatures are checked.
//!
//! # The honest limit
//!
//! A valid mutual signature proves *only* that both keys signed — **not** that the
//! rotation is legitimate. A **compromised** old key can sign a perfectly valid
//! migration to an *attacker's* key (and can even equivocate: sign two conflicting
//! migrations, each individually valid). The signature therefore cannot, on its
//! own, distinguish an honest rotation from attacker capture. That is why the app
//! layer never auto-accepts a migration: a valid one is surfaced as a signal that
//! **requires out-of-band re-verification** (compare the new safety number) before
//! the contact re-pins. Proactive rotation of an uncompromised key is clean;
//! post-compromise recovery fundamentally rests on that out-of-band step, not on
//! this signature.

use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag};
use serde::{Deserialize, Serialize};

/// Nostr `kind` for a Mycellium account-key migration attestation.
///
/// Addressable (NIP-33 / 30000-range) so it is replaceable per
/// `(kind, account_pubkey, d-tag)`. Chosen adjacent to the device list (30444)
/// and KeyPackage (30443) so the account-layer artifacts sit together.
pub const KIND_KEY_MIGRATION: u16 = 30445;

/// The fixed `d`-tag identifier that makes the migration attestation addressable —
/// one canonical current migration per key.
pub const KEY_MIGRATION_IDENTIFIER: &str = "mycellium-marmot-key-migration";

/// The bare old→new claim that **both** keys sign over (the new key signs it as
/// the nested attestation; the old key's copy lives in the outer body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationClaim {
    /// The account identity being migrated away from.
    old_pubkey: PublicKey,
    /// The account identity being migrated to.
    new_pubkey: PublicKey,
}

/// The outer event's JSON body: the old key's claim plus the new key's own signed
/// attestation (a nested Nostr event), so a single published event carries **both**
/// keys' consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationBody {
    old_pubkey: PublicKey,
    new_pubkey: PublicKey,
    /// The new key's continuation attestation — a Nostr event signed by
    /// `new_pubkey` whose content is the same [`MigrationClaim`].
    new_key_attestation: Event,
}

/// A migration attestation that has passed full mutual-signature verification.
///
/// Holding one of these means: the outer event was signed by `old_pubkey`
/// itself, and an embedded attestation was signed by `new_pubkey` — both keys
/// consented to the link. It does **not** mean the migration is safe to accept
/// (a compromised old key can produce a valid one); the app layer must still
/// require out-of-band re-verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMigration {
    /// The old identity (equal to the outer event's signer).
    pub old_pubkey: PublicKey,
    /// The new identity the account is migrating to.
    pub new_pubkey: PublicKey,
    /// Unix seconds the attestation was created.
    pub created_at: u64,
}

/// Why a purported migration attestation was rejected.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// The event is not a migration attestation kind.
    #[error("event kind {0} is not a Mycellium key migration (expected {KIND_KEY_MIGRATION})")]
    NotMigration(u16),
    /// The outer event's own signature (the old key's authorization) is invalid.
    #[error("migration outer signature is invalid")]
    BadOuterSignature,
    /// The event is not signed by the key it names as the old identity — i.e. the
    /// old key did **not** authorize this. A forgery.
    #[error("migration is not signed by the key it claims as the old identity")]
    OldKeyMismatch,
    /// The embedded new-key attestation signature is invalid.
    #[error("migration new-key attestation signature is invalid")]
    BadNewKeySignature,
    /// The embedded attestation is not signed by the claimed new key.
    #[error("migration new-key attestation is signed by a different key")]
    NewKeyMismatch,
    /// The nested new-key claim disagrees with the outer old→new claim.
    #[error("migration inner and outer old/new claims disagree")]
    ClaimMismatch,
    /// The body could not be parsed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Build a mutual-consent migration attestation moving `old_keys` → `new_keys`.
///
/// Produces the outer Nostr event (kind [`KIND_KEY_MIGRATION`], addressable):
/// authored/signed by the **old** key, with the **new** key's own signed
/// continuation attestation embedded in the body. Publishing this single event
/// therefore carries both keys' consent.
///
/// Both key-holders must run through the same caller (the account being rotated
/// holds both the old and new secret keys at the moment of rotation), so no
/// interactive handshake is needed to collect the two signatures.
pub async fn build_migration(old_keys: &Keys, new_keys: &Keys) -> Result<Event, MigrationError> {
    let old_pubkey = old_keys.public_key();
    let new_pubkey = new_keys.public_key();
    let claim = MigrationClaim {
        old_pubkey,
        new_pubkey,
    };
    let claim_json = serde_json::to_string(&claim)?;

    // Inner: the NEW key attests it is the continuation of the old identity.
    let new_key_attestation =
        EventBuilder::new(Kind::Custom(KIND_KEY_MIGRATION), claim_json.clone())
            .tags([
                Tag::identifier(KEY_MIGRATION_IDENTIFIER),
                Tag::public_key(old_pubkey),
            ])
            .build(new_pubkey)
            .sign(new_keys)
            .await
            .map_err(|_| MigrationError::BadNewKeySignature)?;

    // Outer: the OLD key authorizes the migration, embedding the new key's proof.
    let body = MigrationBody {
        old_pubkey,
        new_pubkey,
        new_key_attestation,
    };
    let body_json = serde_json::to_string(&body)?;
    let outer = EventBuilder::new(Kind::Custom(KIND_KEY_MIGRATION), body_json)
        .tags([
            Tag::identifier(KEY_MIGRATION_IDENTIFIER),
            Tag::public_key(new_pubkey),
        ])
        .build(old_pubkey)
        .sign(old_keys)
        .await
        .map_err(|_| MigrationError::BadOuterSignature)?;
    Ok(outer)
}

/// Verify a purported migration attestation, checking **both** keys' signatures.
///
/// On success the returned [`VerifiedMigration`] guarantees:
/// 1. the outer event is a well-formed migration kind with a valid signature;
/// 2. the outer event was signed by the very key it names as `old_pubkey`
///    (old-key authorization — an event *not* signed by that key is rejected);
/// 3. the embedded attestation was signed by the named `new_pubkey`
///    (new-key acceptance of continuation);
/// 4. the inner and outer old→new claims agree.
///
/// The caller must still confirm `old_pubkey` equals the key it had *pinned* for
/// the contact, and — because a compromised old key can produce a valid
/// attestation — require out-of-band re-verification before acting on it.
pub fn verify_migration(event: &Event) -> Result<VerifiedMigration, MigrationError> {
    if event.kind != Kind::Custom(KIND_KEY_MIGRATION) {
        return Err(MigrationError::NotMigration(event.kind.as_u16()));
    }
    // The outer signature is the old key's authorization. Verify it explicitly
    // (defence in depth — the relay/sdk also verifies before delivery).
    event
        .verify()
        .map_err(|_| MigrationError::BadOuterSignature)?;

    let body: MigrationBody = serde_json::from_str(&event.content)?;

    // The old-key consent is bound to the *authorship*: the event must be signed
    // by exactly the key it claims as the old identity. This is what makes a
    // fabricated migration (signed by anyone other than the old key) a forgery.
    if body.old_pubkey != event.pubkey {
        return Err(MigrationError::OldKeyMismatch);
    }

    // The new-key consent is the embedded, independently-signed attestation.
    let inner = &body.new_key_attestation;
    inner
        .verify()
        .map_err(|_| MigrationError::BadNewKeySignature)?;
    if inner.pubkey != body.new_pubkey {
        return Err(MigrationError::NewKeyMismatch);
    }
    let inner_claim: MigrationClaim = serde_json::from_str(&inner.content)?;
    if inner_claim.old_pubkey != body.old_pubkey || inner_claim.new_pubkey != body.new_pubkey {
        return Err(MigrationError::ClaimMismatch);
    }

    Ok(VerifiedMigration {
        old_pubkey: body.old_pubkey,
        new_pubkey: body.new_pubkey,
        created_at: event.created_at.as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn valid_migration_verifies_with_both_signatures() {
        let old = Keys::generate();
        let new = Keys::generate();
        let event = build_migration(&old, &new).await.expect("build");
        let verified = verify_migration(&event).expect("verify");
        assert_eq!(verified.old_pubkey, old.public_key());
        assert_eq!(verified.new_pubkey, new.public_key());
    }

    #[tokio::test]
    async fn migration_not_signed_by_old_key_is_rejected() {
        // An attacker fabricates a migration CLAIMING victim -> attacker, but
        // cannot sign the outer event as the victim (they lack the old key), so
        // they sign it with their own key. `event.pubkey` is then the attacker,
        // not the claimed old key: rejected as a forgery.
        let victim = Keys::generate();
        let attacker = Keys::generate();

        let claim = MigrationClaim {
            old_pubkey: victim.public_key(),
            new_pubkey: attacker.public_key(),
        };
        let claim_json = serde_json::to_string(&claim).unwrap();
        let inner = EventBuilder::new(Kind::Custom(KIND_KEY_MIGRATION), claim_json.clone())
            .build(attacker.public_key())
            .sign(&attacker)
            .await
            .unwrap();
        let body = MigrationBody {
            old_pubkey: victim.public_key(),
            new_pubkey: attacker.public_key(),
            new_key_attestation: inner,
        };
        let forged = EventBuilder::new(
            Kind::Custom(KIND_KEY_MIGRATION),
            serde_json::to_string(&body).unwrap(),
        )
        .build(attacker.public_key()) // signed by the attacker, NOT the victim
        .sign(&attacker)
        .await
        .unwrap();

        let err = verify_migration(&forged).expect_err("forgery must be rejected");
        assert!(matches!(err, MigrationError::OldKeyMismatch), "{err:?}");
    }

    #[tokio::test]
    async fn migration_without_new_key_consent_is_rejected() {
        // The old key alone signs both the outer AND the "new key" attestation —
        // the new key never consented. The inner attestation is signed by the old
        // key, not the claimed new key: rejected.
        let old = Keys::generate();
        let new = Keys::generate();
        let claim = MigrationClaim {
            old_pubkey: old.public_key(),
            new_pubkey: new.public_key(),
        };
        let claim_json = serde_json::to_string(&claim).unwrap();
        let inner = EventBuilder::new(Kind::Custom(KIND_KEY_MIGRATION), claim_json)
            .build(old.public_key())
            .sign(&old) // old key forging the new key's attestation
            .await
            .unwrap();
        let body = MigrationBody {
            old_pubkey: old.public_key(),
            new_pubkey: new.public_key(),
            new_key_attestation: inner,
        };
        let event = EventBuilder::new(
            Kind::Custom(KIND_KEY_MIGRATION),
            serde_json::to_string(&body).unwrap(),
        )
        .build(old.public_key())
        .sign(&old)
        .await
        .unwrap();

        let err = verify_migration(&event).expect_err("missing new-key consent must be rejected");
        assert!(matches!(err, MigrationError::NewKeyMismatch), "{err:?}");
    }
}
