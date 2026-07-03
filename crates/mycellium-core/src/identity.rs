//! Identity: the handle, the three key types, and the local secret [`Identity`].
//!
//! Every identity is rooted in a **wallet key** (secp256k1), derived from a
//! 24-word BIP-39 seed (Layer 9). The wallet key certifies two subordinate
//! keys: the **device key** (Ed25519, basis of the libp2p PeerId) and the
//! **messaging key** (X25519, used by X3DH). One root vouches for everything.
//!
//! Public material and the local secret bundle both live here. Secret keys are
//! held only inside [`Identity`], which never derives `Debug` and zeroizes its
//! mnemonic on drop.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bip32::{DerivationPath, XPrv};
use ed25519_dalek::SigningKey as DeviceSigningKey;
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
/// This is who you are. It signs your directory record and authenticates you at
/// login (SIWE). It never takes part in the encrypted channel.
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

/// The local secret identity: the seed phrase and the three derived keypairs.
///
/// This is the crown jewel of a device. It is created once from a fresh seed
/// (or restored from an existing one) and used to sign records and, later, to
/// run the handshake. It intentionally does not implement `Debug` or `Clone`.
pub struct Identity {
    mnemonic: String,
    device_seed: [u8; 32],
    wallet: WalletSigningKey,
    device: DeviceSigningKey,
    messaging: StaticSecret,
    signed_pre_key: StaticSecret,
}

impl Identity {
    /// Create a brand-new identity from fresh entropy (Layer 9.1).
    ///
    /// 32 bytes of host CSPRNG entropy become a 24-word BIP-39 mnemonic (the
    /// account/wallet), and a second, independent 32 bytes seed this device's
    /// own message keys (Layer 11 — device-local, never derived from the seed).
    pub fn generate<P: Platform>(platform: &mut P) -> Result<Self, Error> {
        let mut entropy = [0u8; 32];
        platform.fill_random(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|_| Error::Malformed)?;
        entropy.zeroize();
        let mut device_seed = [0u8; 32];
        platform.fill_random(&mut device_seed);
        Self::build(mnemonic, device_seed)
    }

    /// Adopt an existing account (24-word phrase) on a **new device** (Layer 11).
    ///
    /// The wallet is recovered from the phrase, but a fresh device seed is drawn,
    /// so the new device joins the cluster with its own keys — it does not
    /// inherit another device's message keys (that is what keeps past traffic
    /// safe). Use [`Identity::restore`] to reload *this* device from storage.
    pub fn from_phrase<P: Platform>(phrase: &str, platform: &mut P) -> Result<Self, Error> {
        let mnemonic =
            bip39::Mnemonic::parse_normalized(phrase).map_err(|_| Error::Malformed)?;
        let mut device_seed = [0u8; 32];
        platform.fill_random(&mut device_seed);
        Self::build(mnemonic, device_seed)
    }

    /// Reload a device from its persisted phrase + device seed (same device).
    pub fn restore(phrase: &str, device_seed: [u8; 32]) -> Result<Self, Error> {
        let mnemonic =
            bip39::Mnemonic::parse_normalized(phrase).map_err(|_| Error::Malformed)?;
        Self::build(mnemonic, device_seed)
    }

    fn build(mnemonic: bip39::Mnemonic, device_seed: [u8; 32]) -> Result<Self, Error> {
        let mut seed = mnemonic.to_seed("");

        // Wallet key: standard BIP-44 Ethereum path, so the same seed imports
        // into external wallets (MetaMask et al.) and yields the same address.
        let path: DerivationPath = "m/44'/60'/0'/0/0".parse().map_err(|_| Error::Malformed)?;
        let xprv = XPrv::derive_from_path(seed, &path).map_err(|_| Error::Malformed)?;
        let wallet = WalletSigningKey::from_slice(&xprv.to_bytes()).map_err(|_| Error::Malformed)?;
        seed.zeroize();

        // Device and messaging keys come from the **device seed** (random, held
        // only by this device) — not the mnemonic — so a seed leak can authorize
        // a new device but never retroactively decrypt this device's traffic.
        let device = DeviceSigningKey::from_bytes(&derive_key(&device_seed, b"mycellium:device:ed25519:v1"));
        let messaging = StaticSecret::from(derive_key(&device_seed, b"mycellium:messaging:x25519:v1"));
        let signed_pre_key = StaticSecret::from(derive_key(&device_seed, b"mycellium:spk:x25519:v1:0"));
        Ok(Self {
            mnemonic: mnemonic.to_string(),
            device_seed,
            wallet,
            device,
            messaging,
            signed_pre_key,
        })
    }

    /// This device's random seed, to persist so the device can be reloaded with
    /// [`Identity::restore`]. Handle with the same care as the mnemonic.
    pub fn device_seed(&self) -> [u8; 32] {
        self.device_seed
    }

    /// The 24-word phrase, to show the user for backup. Handle with care.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
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
        self.messaging.diffie_hellman(&XPublicKey::from(peer.0)).to_bytes()
    }

    /// Diffie-Hellman between the **signed pre-key** secret and `peer`.
    pub(crate) fn dh_signed_pre_key(&self, peer: &MessagingPublicKey) -> [u8; 32] {
        self.signed_pre_key.diffie_hellman(&XPublicKey::from(peer.0)).to_bytes()
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

    /// The wallet private key bytes — test-only, to check the BIP-44 vector.
    #[cfg(test)]
    pub(crate) fn wallet_secret_bytes(&self) -> [u8; 32] {
        self.wallet.to_bytes().into()
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
        self.device_seed.zeroize();
        // The dalek and k256 key types zeroize their own secret material.
    }
}

/// HKDF-SHA512 domain-separated derivation of a 32-byte key from `ikm`.
///
/// Used for this device's Ed25519/X25519 keys, keyed on the random device seed
/// (see [`Identity::build`]). The wallet key uses standard BIP-44 instead, from
/// the mnemonic seed, for external-wallet interop.
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
        let a_reloaded = Identity::restore(a.mnemonic(), a.device_seed()).unwrap();
        let b = Identity::generate(&mut SeededPlatform(200)).unwrap();

        // Reloading the *same* device (same device seed) -> same storage key.
        assert_eq!(a.storage_key(), a_reloaded.storage_key());
        // A different device (even same account) -> different storage key.
        assert_ne!(a.storage_key(), b.storage_key());
    }

    #[test]
    fn a_new_device_shares_the_wallet_but_not_message_keys() {
        let a = Identity::generate(&mut SeededPlatform(1)).unwrap();
        // Adopting the account on a new device: same wallet, fresh device keys.
        let b = Identity::from_phrase(a.mnemonic(), &mut SeededPlatform(200)).unwrap();
        assert_eq!(a.wallet_public(), b.wallet_public(), "same account");
        assert_ne!(a.device_public(), b.device_public(), "new device key");
        assert_ne!(a.messaging_public(), b.messaging_public(), "new message key");
    }

    fn from_hex_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn bip44_matches_hardhat_account_zero() {
        // The canonical Hardhat/Anvil default mnemonic. Its m/44'/60'/0'/0/0
        // private key is a stable, widely-known vector — proof our derivation
        // is standard BIP-44 and imports into external wallets.
        let id = Identity::from_phrase(
            "test test test test test test test test test test test junk",
            &mut SeededPlatform(0),
        )
        .unwrap();
        assert_eq!(
            id.wallet_secret_bytes(),
            from_hex_32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
        );
    }
}
