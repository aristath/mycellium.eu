//! Shared symmetric primitives: the chain-key KDF and the message AEAD.
//!
//! Used by both the Double Ratchet ([`crate::ratchet`]) and group sender keys
//! ([`crate::group`]), so there is one audited implementation rather than two.
//!
//! - **HMAC-SHA256** for the chain/message-key KDF,
//! - **ChaCha20-Poly1305** for the message AEAD (key + nonce via **HKDF-SHA256**).

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::Error;

type HmacSha256 = Hmac<Sha256>;

/// Chain KDF: `message_key = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`.
pub(crate) fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac(ck, &[0x01]);
    let ck_next = hmac(ck, &[0x02]);
    (ck_next, mk)
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derive the AEAD key and nonce from a message key.
fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
    let mut okm = [0u8; 44];
    hk.expand(b"Mycellium-Msg", &mut okm)
        .expect("44 is a valid HKDF-SHA256 output length");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (key, nonce)
}

/// Encrypt `plaintext` under message key `mk`, binding `aad`.
pub(crate) fn aead_encrypt(mk: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (mut key, nonce) = message_keys(mk);
    let key_ga: Key = key.into();
    let nonce_ga: Nonce = nonce.into();
    let cipher = ChaCha20Poly1305::new(&key_ga);
    let out = cipher
        .encrypt(
            &nonce_ga,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption is infallible for valid keys");
    key.zeroize();
    out
}

/// Decrypt `ciphertext` under message key `mk`, checking `aad`.
pub(crate) fn aead_decrypt(mk: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let (mut key, nonce) = message_keys(mk);
    let key_ga: Key = key.into();
    let nonce_ga: Nonce = nonce.into();
    let cipher = ChaCha20Poly1305::new(&key_ga);
    let result = cipher.decrypt(
        &nonce_ga,
        Payload {
            msg: ciphertext,
            aad,
        },
    );
    key.zeroize();
    result.map_err(|_| Error::DecryptFailed)
}
