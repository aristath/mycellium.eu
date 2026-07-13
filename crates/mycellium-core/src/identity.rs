//! Identity: the handle, the three key types, and the local secret [`Identity`].
//!
//! Every identity is rooted in a **wallet key** (secp256k1) — a raw random
//! account secret, **not** a seed phrase. The wallet key certifies two
//! subordinate keys: the **device key** (Ed25519, basis of the libp2p PeerId)
//! and the **messaging key** (X25519, used by X3DH). One root vouches for
//! everything. A fresh device starts from fresh local secret material and
//! publishes a new signed record for peers to import or verify.
//!
//! Public material and the local secret bundle both live here. Secret keys are
//! held only inside [`Identity`], which never derives `Debug` and zeroizes its
//! account secret on drop.

use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signature as EdSignature, SigningKey as DeviceSigningKey};
use hkdf::Hkdf;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey as WalletSigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::Sha512;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::Error;
use crate::platform::Platform;

/// A human-readable public name, e.g. `ari` (Layer 9.2).
///
/// Handles are the *memorable* part of an identity; the security lives in the
/// keys underneath. Rules are intentionally strict so a handle is unambiguous
/// across devices and display contexts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Handle(String);

impl TryFrom<String> for Handle {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Handle::new(s)
    }
}

impl From<Handle> for String {
    fn from(h: Handle) -> String {
        h.0
    }
}

impl Handle {
    /// Maximum handle length, in bytes.
    pub const MAX_LEN: usize = 32;

    /// Validate and wrap a handle.
    ///
    /// Allowed: 1..=[`MAX_LEN`](Self::MAX_LEN) characters, each a lowercase
    /// ASCII letter, digit, or underscore. Everything else is rejected so that
    /// two handles can never look alike.
    pub fn new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        if s.is_empty() || s.len() > Self::MAX_LEN {
            return Err(Error::InvalidHandle);
        }
        let ok = s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !ok {
            return Err(Error::InvalidHandle);
        }
        Ok(Handle(s))
    }

    /// Borrow the handle as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A compressed secp256k1 public key (33 bytes): the **root wallet identity**.
///
/// This is who you are. It signs your peer record. It never takes part in the
/// encrypted channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPublicKey(#[serde(with = "BigArray")] pub [u8; 33]);

impl WalletPublicKey {
    /// Verify a wallet signature over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        let vk = VerifyingKey::from_sec1_bytes(&self.0).map_err(|_| Error::Malformed)?;
        let sig = EcdsaSignature::from_slice(&sig.0).map_err(|_| Error::BadSignature)?;
        vk.verify(msg, &sig).map_err(|_| Error::BadSignature)
    }
}

/// An Ed25519 public key (32 bytes): the **device key**.
///
/// Its hash is the libp2p [`PeerId`]; it secures the transport. A new device
/// gets a new device key, re-certified by the unchanged wallet key (Layer 9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicKey(pub [u8; 32]);

impl DevicePublicKey {
    /// Verify a signature made by the corresponding device key.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.0).map_err(|_| Error::Malformed)?;
        let bytes: [u8; 64] = sig
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature)?;
        key.verify(msg, &EdSignature::from_bytes(&bytes))
            .map_err(|_| Error::BadSignature)
    }
}

/// An X25519 public key (32 bytes): the long-term **messaging key** for X3DH.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagingPublicKey(pub [u8; 32]);

/// A libp2p peer identifier (the multihash of the device public key).
///
/// Stored as raw bytes here so the core stays independent of any specific
/// libp2p version; the transport layer converts to/from its native type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Vec<u8>);

/// A detached signature over some canonical bytes.
///
/// Length varies by scheme (Ed25519 = 64 bytes, secp256k1 ECDSA = 64), so this
/// is kept variable-length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

/// The local secret identity: the account (wallet) secret plus this device's
/// own derived keypairs.
///
/// This is the crown jewel of a device. The account is a raw random wallet
/// secret — **not** a seed phrase; there is no mnemonic. It intentionally does
/// not implement `Debug` or `Clone`.
pub struct Identity {
    /// The account wallet's raw secp256k1 secret scalar. Held encrypted at rest
    /// and never shown to the user or serialized to a URL.
    wallet_secret: [u8; 32],
    device_seed: [u8; 32],
    wallet: WalletSigningKey,
    device: DeviceSigningKey,
    messaging: StaticSecret,
    signed_pre_key: StaticSecret,
}

impl Identity {
    /// Create a brand-new account on a fresh device: a random wallet secret plus
    /// an independent random device seed (Layer 11 — device-local message keys).
    pub fn generate<P: Platform>(platform: &mut P) -> Result<Self, Error> {
        // Draw a valid secp256k1 scalar (rejecting the astronomically-rare
        // zero/overflow that `from_slice` refuses).
        let mut wallet_secret = [0u8; 32];
        loop {
            platform.fill_random(&mut wallet_secret);
            if WalletSigningKey::from_slice(&wallet_secret).is_ok() {
                break;
            }
        }
        let mut device_seed = [0u8; 32];
        platform.fill_random(&mut device_seed);
        Self::build(wallet_secret, device_seed)
    }

    /// Adopt an **existing** account wallet on a **new active device**: a fresh
    /// device seed is drawn, so the new device gets its own message keys and
    /// never inherits another device's traffic keys.
    pub fn adopt<P: Platform>(platform: &mut P, wallet_secret: [u8; 32]) -> Result<Self, Error> {
        let mut device_seed = [0u8; 32];
        platform.fill_random(&mut device_seed);
        Self::build(wallet_secret, device_seed)
    }

    /// Reload a device from its persisted wallet secret + device seed.
    pub fn from_wallet_secret(
        wallet_secret: [u8; 32],
        device_seed: [u8; 32],
    ) -> Result<Self, Error> {
        Self::build(wallet_secret, device_seed)
    }

    fn build(wallet_secret: [u8; 32], device_seed: [u8; 32]) -> Result<Self, Error> {
        let wallet = WalletSigningKey::from_slice(&wallet_secret).map_err(|_| Error::Malformed)?;

        // Device and messaging keys come from the **device seed** (random, held
        // only by this device) — not the account secret — so an account-key leak
        // can authorize a new device but never retroactively decrypt this
        // device's traffic.
        let device =
            DeviceSigningKey::from_bytes(&derive_key(&device_seed, b"mycellium:device:ed25519:v1"));
        let messaging =
            StaticSecret::from(derive_key(&device_seed, b"mycellium:messaging:x25519:v1"));
        let signed_pre_key =
            StaticSecret::from(derive_key(&device_seed, b"mycellium:spk:x25519:v1:0"));
        Ok(Self {
            wallet_secret,
            device_seed,
            wallet,
            device,
            messaging,
            signed_pre_key,
        })
    }

    /// This device's random seed, to persist so the device can be reloaded with
    /// [`Identity::from_wallet_secret`]. Handle with the same care as the account.
    pub fn device_seed(&self) -> [u8; 32] {
        self.device_seed
    }

    /// The account wallet secret, to persist encrypted. Handle with the utmost
    /// care.
    pub fn wallet_secret(&self) -> [u8; 32] {
        self.wallet_secret
    }

    /// The root wallet public key.
    pub fn wallet_public(&self) -> WalletPublicKey {
        let point = self.wallet.verifying_key().to_encoded_point(true);
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(point.as_bytes());
        WalletPublicKey(bytes)
    }

    /// The device public key (Ed25519).
    pub fn device_public(&self) -> DevicePublicKey {
        DevicePublicKey(self.device.verifying_key().to_bytes())
    }

    /// A 32-byte key for encrypting local data at rest (message history, etc.).
    ///
    /// Derived from the device key by HKDF with a distinct label, so it is
    /// bound to this identity and unrelated to any key used on the wire.
    pub fn storage_key(&self) -> [u8; 32] {
        let device = self.device.to_bytes();
        let hk = Hkdf::<Sha512>::new(None, &device);
        let mut key = [0u8; 32];
        hk.expand(b"mycellium:local-storage:v1", &mut key)
            .expect("32 is a valid HKDF-SHA512 output length");
        key
    }

    /// The device key's 32-byte Ed25519 secret seed.
    ///
    /// Exposed so a transport can build its identity (e.g. a libp2p keypair)
    /// from the *same* key, ensuring the network PeerId derives from the device
    /// key as the concept requires (Layer 8.1). Handle with the same care as the
    /// seed itself.
    pub fn device_secret(&self) -> [u8; 32] {
        self.device.to_bytes()
    }

    /// The long-term messaging public key (X25519) — the X3DH identity key.
    pub fn messaging_public(&self) -> MessagingPublicKey {
        MessagingPublicKey(XPublicKey::from(&self.messaging).to_bytes())
    }

    /// The signed pre-key public (X25519). Distinct from the identity key; the
    /// responder holds its secret and it also seeds the first ratchet step.
    pub fn signed_pre_key_public(&self) -> MessagingPublicKey {
        MessagingPublicKey(XPublicKey::from(&self.signed_pre_key).to_bytes())
    }

    /// Diffie-Hellman between the **identity (messaging)** secret and `peer`.
    pub(crate) fn dh_identity(&self, peer: &MessagingPublicKey) -> [u8; 32] {
        self.messaging
            .diffie_hellman(&XPublicKey::from(peer.0))
            .to_bytes()
    }

    /// Diffie-Hellman between the **signed pre-key** secret and `peer`.
    pub(crate) fn dh_signed_pre_key(&self, peer: &MessagingPublicKey) -> [u8; 32] {
        self.signed_pre_key
            .diffie_hellman(&XPublicKey::from(peer.0))
            .to_bytes()
    }

    /// The signed pre-key secret, for seeding the responder's first ratchet.
    pub(crate) fn signed_pre_key_secret(&self) -> &StaticSecret {
        &self.signed_pre_key
    }

    /// This device's peer identifier.
    ///
    /// Placeholder derivation: the transport layer maps the device key to a
    /// real libp2p PeerId. Kept here so records can be assembled by the core.
    pub fn peer_id(&self) -> PeerId {
        PeerId(self.device_public().0.to_vec())
    }

    /// Sign `msg` with the wallet key (secp256k1 ECDSA over SHA-256).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig: EcdsaSignature = self.wallet.sign(msg);
        Signature(sig.to_bytes().to_vec())
    }

    /// Sign a device-scoped protocol statement with this device's Ed25519 key.
    pub fn sign_device(&self, msg: &[u8]) -> Signature {
        Signature(self.device.sign(msg).to_bytes().to_vec())
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.wallet_secret.zeroize();
        self.device_seed.zeroize();
        // The dalek and k256 key types zeroize their own secret material.
    }
}

/// HKDF-SHA512 domain-separated derivation of a 32-byte key from `ikm`.
///
/// Used for this device's Ed25519/X25519 keys, keyed on the random device seed
/// (see [`Identity::build`]). The wallet key is the raw account secret directly,
/// not a derivation.
fn derive_key(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 is a valid HKDF-SHA512 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Platform;

    struct SeededPlatform(u8);
    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    #[test]
    fn storage_key_is_per_device() {
        let a = Identity::generate(&mut SeededPlatform(1)).unwrap();
        let a_reloaded = Identity::from_wallet_secret(a.wallet_secret(), a.device_seed()).unwrap();
        let b = Identity::generate(&mut SeededPlatform(200)).unwrap();

        // Reloading the *same* device (same device seed) -> same storage key.
        assert_eq!(a.storage_key(), a_reloaded.storage_key());
        // A different device (even same account) -> different storage key.
        assert_ne!(a.storage_key(), b.storage_key());
    }

    #[test]
    fn a_new_device_shares_the_wallet_but_not_message_keys() {
        let a = Identity::generate(&mut SeededPlatform(1)).unwrap();
        // Adopting the account wallet on a new device: same wallet, fresh
        // device keys.
        let b = Identity::adopt(&mut SeededPlatform(200), a.wallet_secret()).unwrap();
        assert_eq!(a.wallet_public(), b.wallet_public(), "same account");
        assert_ne!(a.device_public(), b.device_public(), "new device key");
        assert_ne!(
            a.messaging_public(),
            b.messaging_public(),
            "new message key"
        );
    }

    #[test]
    fn wallet_secret_round_trips_the_account() {
        let a = Identity::generate(&mut SeededPlatform(7)).unwrap();
        // The account is fully captured by its wallet secret: rebuilding from it
        // (same device seed) reproduces the same wallet identity.
        let same = Identity::from_wallet_secret(a.wallet_secret(), a.device_seed()).unwrap();
        assert_eq!(a.wallet_public(), same.wallet_public());
        assert_eq!(a.device_public(), same.device_public());
    }
}
