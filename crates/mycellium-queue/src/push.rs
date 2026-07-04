//! Web Push (VAPID, RFC 8292) — **contentless** wake pings.
//!
//! When a message is deposited for a wallet, the queue POSTs a bodyless push to
//! each of the recipient's registered browser subscriptions. The push carries
//! **no content** (no sender, no text) — it only wakes the recipient's service
//! worker, which then shows a generic notification and/or syncs. The vendor push
//! endpoint (Google/Mozilla/Apple, per the browser) thus learns only that "some
//! device got a wake ping", never what or from whom.
//!
//! Because the ping is bodyless, storing **only the endpoint URL** is sufficient
//! and intentional — the `p256dh` / `auth` keys of a `PushSubscription` are only
//! needed to *encrypt a payload* (RFC 8291), which we deliberately never send (a
//! payload would put content in front of the vendor). If a future change ever
//! needs encrypted payloads, `subscribe` must also capture and store those keys
//! (`PushSubscription.toJSON()`); until then this is a non-gap, not a limitation.

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
    /// Generate a fresh VAPID keypair. Persist its [`seed`](Self::seed) so
    /// existing browser subscriptions keep working across restarts.
    pub fn generate() -> Self {
        let signing = loop {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).expect("OS RNG");
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                break key;
            }
        };
        Self::from_signing(signing)
    }

    /// Reconstruct the keypair from a persisted 32-byte private scalar.
    pub fn from_seed(seed: &[u8; 32]) -> Option<Self> {
        SigningKey::from_slice(seed).ok().map(Self::from_signing)
    }

    /// The 32-byte private scalar, to persist so the public key is stable.
    pub fn seed(&self) -> [u8; 32] {
        let bytes = self.signing.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn from_signing(signing: SigningKey) -> Self {
        let point = signing.verifying_key().to_encoded_point(false);
        let public_b64 = b64url(point.as_bytes());
        Vapid { signing, public_b64, subject: "mailto:push@mycellium.invalid".to_string() }
    }

    /// The base64url public key clients pass as `applicationServerKey`.
    pub fn public_key(&self) -> &str {
        &self.public_b64
    }

    /// Send a single contentless wake to `endpoint` (a browser push endpoint).
    pub fn send(&self, endpoint: &str, now: u64) -> SendResult {
        let aud = match origin_of(endpoint) {
            Some(a) => a,
            None => return SendResult::Failed,
        };
        let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = format!(r#"{{"aud":"{aud}","exp":{},"sub":"{}"}}"#, now + 12 * 3600, self.subject);
        let signing_input = format!("{header}.{}", b64url(claims.as_bytes()));
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64url(&sig.to_bytes()));

        match ureq::post(endpoint)
            .set("Authorization", &format!("vapid t={jwt}, k={}", self.public_b64))
            .set("TTL", "86400")
            .send_bytes(&[])
        // no payload → wake only
        {
            Ok(_) => SendResult::Ok,
            // The push service says this subscription is gone — the recipient
            // unsubscribed or it expired. The caller should drop it.
            Err(ureq::Error::Status(404 | 410, _)) => SendResult::Gone,
            Err(_) => SendResult::Failed,
        }
    }
}

/// The outcome of a push send, so callers can prune dead subscriptions.
#[derive(Debug, PartialEq, Eq)]
pub enum SendResult {
    /// Accepted by the push service.
    Ok,
    /// The subscription is gone (404/410) — remove it.
    Gone,
    /// A transient failure — leave the subscription in place.
    Failed,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The `scheme://host[:port]` origin of a URL — the VAPID `aud` claim.
pub(crate) fn origin_of(url: &str) -> Option<String> {
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
