//! Web Push (VAPID, RFC 8292) — **contentless** wake pings.
//!
//! When a message is deposited for a wallet, the queue POSTs a bodyless push to
//! each of the recipient's registered browser subscriptions. The push carries
//! **no content** (no sender, no text) — it only wakes the recipient's service
//! worker, which then shows a generic notification and/or syncs. The vendor push
//! endpoint (Google/Mozilla/Apple, per the browser) thus learns only that "some
//! device got a wake ping", never what or from whom.

use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

/// The server's VAPID identity — a P-256 keypair that authenticates our pushes
/// to the browser push services. The public key is handed to clients so they can
/// subscribe; the private key signs each push's JWT.
pub struct Vapid {
    signing: SigningKey,
    /// base64url (unpadded) of the 65-byte uncompressed public key.
    public_b64: String,
    subject: String,
}

impl Vapid {
    /// Generate a fresh VAPID keypair. (In-memory today; persist it in a real
    /// deployment so existing subscriptions keep working across restarts.)
    pub fn generate() -> Self {
        let signing = loop {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).expect("OS RNG");
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                break key;
            }
        };
        let point = signing.verifying_key().to_encoded_point(false);
        let public_b64 = b64url(point.as_bytes());
        Vapid { signing, public_b64, subject: "mailto:push@mycellium.invalid".to_string() }
    }

    /// The base64url public key clients pass as `applicationServerKey`.
    pub fn public_key(&self) -> &str {
        &self.public_b64
    }

    /// Send a single contentless wake to `endpoint` (a browser push endpoint).
    pub fn send(&self, endpoint: &str, now: u64) -> Result<(), String> {
        let aud = origin_of(endpoint).ok_or("bad endpoint")?;
        let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = format!(r#"{{"aud":"{aud}","exp":{},"sub":"{}"}}"#, now + 12 * 3600, self.subject);
        let signing_input = format!("{header}.{}", b64url(claims.as_bytes()));
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64url(&sig.to_bytes()));

        ureq::post(endpoint)
            .set("Authorization", &format!("vapid t={jwt}, k={}", self.public_b64))
            .set("TTL", "86400")
            .send_bytes(&[]) // no payload → wake only
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The `scheme://host[:port]` origin of a URL — the VAPID `aud` claim.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vapid_public_key_is_base64url_65_bytes() {
        let v = Vapid::generate();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v.public_key()).unwrap();
        assert_eq!(raw.len(), 65); // uncompressed P-256 point
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(origin_of("https://fcm.googleapis.com/fcm/send/abc").as_deref(), Some("https://fcm.googleapis.com"));
        assert_eq!(origin_of("https://updates.push.services.mozilla.com/wpush/v2/xyz").as_deref(), Some("https://updates.push.services.mozilla.com"));
        assert_eq!(origin_of("not-a-url"), None);
    }
}
