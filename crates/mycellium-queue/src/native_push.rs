//! Contentless **native** push: APNs (Apple) and FCM (Google) wake payloads and
//! provider-auth construction — the in-repo slice of #71.
//!
//! Mirrors the contentless discipline of [`crate::push`]: a wake tells the
//! device *"go check your mailbox"* and carries **no** sender, text, peer,
//! group, thread, or preview. The two payload constructors here are pure and
//! unit-tested (see this module's tests) to guarantee that invariant — nothing
//! per-message ever reaches Apple or Google.
//!
//! ## Scope (safe in-repo slice)
//!
//! This builds and tests the payload + provider-JWT **construction**. The actual
//! network **delivery** is out of the in-repo slice and needs external accounts +
//! devices: APNs is HTTP/2 to `api.push.apple.com` with a `.p8` provider key, and
//! FCM needs a service-account OAuth2 bearer. So an **unconfigured** transport is
//! skipped at fan-out (mail stays queued — the reliability invariant), and a
//! configured one constructs the payload/auth but reports [`SendResult::Failed`]
//! rather than fake a send. No credentials are invented here.
//! See `docs/research/NATIVE-PUSH.md` §8.

use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

use crate::push::SendResult;
use crate::Subscription;

/// A contentless APNs **background** wake: `content-available:1` and nothing
/// else, so the app wakes and calls `sync()`. Carries no content by construction
/// — the notification the user sees is composed **on the device** after `sync()`
/// decrypts (decrypt-then-display).
pub fn apns_wake_payload() -> String {
    r#"{"aps":{"content-available":1}}"#.to_string()
}

/// A contentless FCM **data-only** wake: a single opaque flag, no `notification`
/// block and no per-message content, so `onMessageReceived` runs and calls
/// `sync()`. The destination registration token is supplied by the sender in the
/// request envelope, never by this body.
pub fn fcm_wake_payload() -> String {
    r#"{"message":{"data":{"w":"1"}}}"#.to_string()
}

/// Build an APNs provider **JWT** (ES256) — the same P-256 / ES256 signing the
/// VAPID path in [`crate::push`] already uses. Header
/// `{"alg":"ES256","kid":<key_id>}`, claims `{"iss":<team_id>,"iat":<now>}`. The
/// real sender reuses one token for up to ~1h. Pure and testable: no network.
pub fn apns_provider_jwt(signing: &SigningKey, key_id: &str, team_id: &str, now: u64) -> String {
    let header = b64url(format!(r#"{{"alg":"ES256","kid":"{key_id}"}}"#).as_bytes());
    let claims = b64url(format!(r#"{{"iss":"{team_id}","iat":{now}}}"#).as_bytes());
    let signing_input = format!("{header}.{claims}");
    let sig: Signature = signing.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig.to_bytes()))
}

/// Operator-configured native transports. Each is enabled iff its credentials
/// are present; an unconfigured transport is **skipped** at fan-out (fail-soft —
/// mail stays queued), never an error and never a faked delivery.
#[derive(Default)]
pub struct NativePush {
    apns: Option<ApnsCreds>,
    fcm: Option<FcmCreds>,
}

impl NativePush {
    /// Build an unconfigured native push dispatcher. The in-repo slice ships the
    /// payload + auth **construction** only; wiring real APNs (`.p8`) / FCM
    /// (service-account) credential loading + delivery lands with the on-device
    /// phases (`docs/research/NATIVE-PUSH.md` §8.2). Until then this is
    /// unconfigured, so native fan-out is skipped and mail waits for `sync()`.
    pub fn unconfigured() -> Self {
        Self::default()
    }

    /// Construct (and, when a transport is wired, attempt) a contentless wake for
    /// a **native** subscription. Returns `None` when that transport isn't
    /// configured at this operator (skip — mail stays queued); `Some(SendResult)`
    /// when it is. Delivery itself is out of the in-repo slice, so a configured
    /// transport constructs the payload/auth and reports [`SendResult::Failed`]
    /// (mail stays queued) rather than fake a network send. Web Push / UnifiedPush
    /// are VAPID transports handled by [`crate::push::Vapid`], so they return
    /// `None` here.
    pub(crate) fn wake(&self, sub: &Subscription, now: u64) -> Option<SendResult> {
        match sub {
            Subscription::Apns { token, topic } => {
                let creds = self.apns.as_ref()?;
                let _payload = apns_wake_payload();
                let _jwt = creds.provider_jwt(now);
                let _request = format!("https://{}/3/device/{token}", creds.host());
                let _topic = topic;
                Some(SendResult::Failed)
            }
            Subscription::Fcm { token } => {
                let creds = self.fcm.as_ref()?;
                let _payload = fcm_wake_payload();
                let _request = format!(
                    "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                    creds.project_id
                );
                let _token = token;
                Some(SendResult::Failed)
            }
            Subscription::WebPush { .. } | Subscription::UnifiedPush { .. } => None,
        }
    }
}

/// APNs provider-auth material: an ES256 `.p8` key plus its ids. Constructed by
/// the operator-config loader (and tests); used to mint the provider JWT.
pub struct ApnsCreds {
    signing: SigningKey,
    key_id: String,
    team_id: String,
    /// Apple's push host: production vs. sandbox.
    production: bool,
}

impl ApnsCreds {
    /// Assemble APNs creds from an ES256 signing key and its ids.
    pub fn new(signing: SigningKey, key_id: String, team_id: String, production: bool) -> Self {
        Self {
            signing,
            key_id,
            team_id,
            production,
        }
    }

    /// Mint a provider JWT valid at `now`.
    pub fn provider_jwt(&self, now: u64) -> String {
        apns_provider_jwt(&self.signing, &self.key_id, &self.team_id, now)
    }

    /// The APNs host for this environment.
    pub fn host(&self) -> &'static str {
        if self.production {
            "api.push.apple.com"
        } else {
            "api.development.push.apple.com"
        }
    }
}

/// FCM provider-auth material. Minting the OAuth2 bearer from a service-account
/// key (RS256 JWT → token exchange) lands with FCM delivery (out of the in-repo
/// slice); this holds the project the message targets.
pub struct FcmCreds {
    /// The Firebase project id in the `messages:send` URL.
    pub project_id: String,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    /// The heart of the privacy guarantee: a constructed APNs/FCM wake must
    /// contain **none** of a set of forbidden content markers. This regression
    /// guard runs in CI forever so no content can ever leak into a wake.
    #[test]
    fn wake_payloads_are_contentless() {
        // Stand-ins for every category §4 forbids: sender handle, sender/peer
        // wallet hex, message text, the literal "from", a peer name, a group
        // name, and a thread/conversation id.
        let forbidden = [
            "alice",                                                              // sender handle
            "bob",                                                                // peer handle
            "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", // wallet hex
            "hello over the sdk",                                                 // message text
            "from",                                                               // sender label
            "Bob",       // peer display name
            "team",      // group name
            "thread-42", // thread/conversation id
            "preview",   // snippet/preview
        ];

        for payload in [apns_wake_payload(), fcm_wake_payload()] {
            let bytes = payload.as_bytes();
            for marker in forbidden {
                assert!(
                    !payload.contains(marker),
                    "wake payload leaked a forbidden content marker {marker:?}: {payload}"
                );
                // Also assert over the raw serialized bytes, since that is what
                // actually crosses to the push vendor.
                assert!(
                    bytes.windows(marker.len()).all(|w| w != marker.as_bytes()),
                    "serialized wake bytes leaked {marker:?}"
                );
            }
        }

        // Positively assert each payload is one of the two allowed shapes.
        assert_eq!(apns_wake_payload(), r#"{"aps":{"content-available":1}}"#);
        assert_eq!(fcm_wake_payload(), r#"{"message":{"data":{"w":"1"}}}"#);
    }

    #[test]
    fn apns_provider_jwt_is_es256_and_verifies() {
        let signing = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let jwt = apns_provider_jwt(&signing, "KEY12345", "TEAM6789", 1000);

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWT is three dot-separated segments");

        let dec = |s: &str| {
            String::from_utf8(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .unwrap(),
            )
            .unwrap()
        };
        let header = dec(parts[0]);
        assert!(header.contains("ES256"), "alg must be ES256");
        assert!(header.contains("KEY12345"), "kid must be present");
        let claims = dec(parts[1]);
        assert!(claims.contains("TEAM6789"), "iss (team) must be present");
        assert!(claims.contains("\"iat\":1000"), "iat must be present");

        // The signature verifies against the public key over `header.claims`.
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let verifying: VerifyingKey = *signing.verifying_key();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        assert!(verifying.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn unconfigured_native_transports_are_skipped() {
        let native = NativePush::unconfigured(); // no operator creds in-repo
        assert_eq!(
            native.wake(
                &Subscription::Apns {
                    token: "deadbeef".into(),
                    topic: "eu.mycellium.app".into()
                },
                0
            ),
            None,
            "unconfigured APNs is skipped, leaving mail queued"
        );
        assert_eq!(
            native.wake(
                &Subscription::Fcm {
                    token: "tok".into()
                },
                0
            ),
            None,
            "unconfigured FCM is skipped, leaving mail queued"
        );
        // A configured transport constructs the payload/auth but reports Failed
        // (no faked delivery in the in-repo slice) — mail still stays queued.
        let native = NativePush {
            apns: Some(ApnsCreds::new(
                SigningKey::from_slice(&[9u8; 32]).unwrap(),
                "KID".into(),
                "TEAM".into(),
                false,
            )),
            fcm: Some(FcmCreds {
                project_id: "proj".into(),
            }),
        };
        assert_eq!(
            native.wake(
                &Subscription::Apns {
                    token: "abcd".into(),
                    topic: "eu.mycellium.app".into()
                },
                0
            ),
            Some(SendResult::Failed)
        );
        assert_eq!(
            native.wake(
                &Subscription::Fcm {
                    token: "tok".into()
                },
                0
            ),
            Some(SendResult::Failed)
        );
    }
}
