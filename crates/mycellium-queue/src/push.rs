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
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Bound outbound push attempts so a dead push provider cannot strand one OS
/// thread per deposit forever. These run off the request path, but still need a
/// finite lifetime under load.
const PUSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PUSH_IO_TIMEOUT: Duration = Duration::from_secs(15);

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
        Vapid {
            signing,
            public_b64,
            subject: "mailto:push@mycellium.invalid".to_string(),
        }
    }

    /// The base64url public key clients pass as `applicationServerKey`.
    pub fn public_key(&self) -> &str {
        &self.public_b64
    }

    /// Send a single contentless wake to `endpoint` (a browser push endpoint).
    pub fn send(&self, endpoint: &str, now: u64) -> SendResult {
        // SSRF guard: resolve the host and refuse if it maps to any internal
        // range (loopback / link-local / private / metadata). Done here — not
        // only at subscribe time — so a DNS name that *resolves* to an internal
        // IP (or a rebind) can't get us to POST to it.
        if !endpoint_is_safe_to_connect(endpoint) {
            return SendResult::Failed;
        }
        let aud = match origin_of(endpoint) {
            Some(a) => a,
            None => return SendResult::Failed,
        };
        let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = format!(
            r#"{{"aud":"{aud}","exp":{},"sub":"{}"}}"#,
            now + 12 * 3600,
            self.subject
        );
        let signing_input = format!("{header}.{}", b64url(claims.as_bytes()));
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64url(&sig.to_bytes()));

        match push_agent()
            .post(endpoint)
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

/// Send a single **contentless** wake to a UnifiedPush endpoint (e.g. ntfy
/// `?up=1`, or any self-hosted distributor).
///
/// Unlike Web Push, UnifiedPush requires **no VAPID**: the push provider simply
/// accepts a bare POST to the endpoint URL and forwards it to the device's
/// distributor. So this is a plain contentless POST — the body MUST be empty; no
/// sender, wallet, handle, or text ever crosses to the distributor, exactly like
/// the VAPID path in [`Vapid::send`]. A short `TTL` bounds how long the provider
/// holds the wake if the device is offline. `404`/`410` mean the endpoint is
/// gone (the distributor was uninstalled or the topic revoked) so the caller
/// should drop the subscription; any other error is transient (mail stays
/// queued).
pub(crate) fn unifiedpush_send(endpoint: &str, _now: u64) -> SendResult {
    // Same SSRF guard as the VAPID path: resolve and refuse an internal target
    // before we ever open a socket.
    if !endpoint_is_safe_to_connect(endpoint) {
        return SendResult::Failed;
    }
    match push_agent().post(endpoint).set("TTL", "60").send_bytes(&[])
    // empty body → wake only, never content
    {
        Ok(_) => SendResult::Ok,
        Err(ureq::Error::Status(404 | 410, _)) => SendResult::Gone,
        Err(_) => SendResult::Failed,
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

/// A ureq agent that **never follows redirects**, so a push service answering a
/// wake with a `302` to an internal URL can't slip past the SSRF guard (which
/// only vetted the original endpoint). Every outbound push goes through this.
fn push_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(PUSH_CONNECT_TIMEOUT)
            .timeout_read(PUSH_IO_TIMEOUT)
            .timeout_write(PUSH_IO_TIMEOUT)
            .redirects(0)
            .build()
    })
}

/// Hostnames that always name an internal service and must never be POSTed to,
/// regardless of what (if anything) they resolve to. `localhost` and any
/// `*.localhost` are covered separately.
const BLOCKED_HOSTS: &[&str] = &["metadata.google.internal", "metadata"];

/// The bare host of a URL (no scheme, no port, no brackets) — e.g.
/// `https://[::1]:8443/x` → `::1`, `https://h:443/x` → `h`.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // Drop any userinfo (`user:pass@host`).
    let authority = authority.rsplit('@').next()?;
    if let Some(after_bracket) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]:port`.
        let host = after_bracket.split(']').next()?;
        return (!host.is_empty()).then(|| host.to_string());
    }
    let host = authority.split(':').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// True if `ip` sits in a range an SSRF guard must refuse: loopback, link-local,
/// private, shared/CGNAT, unspecified, broadcast, or multicast.
pub(crate) fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()        // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254.0.0/16 (incl. the cloud metadata IP)
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_multicast()    // 224.0.0.0/4
        || (a == 100 && (b & 0xc0) == 0x40) // 100.64.0.0/10 (CGNAT/shared)
}

fn is_blocked_v6(ip: &Ipv6Addr) -> bool {
    // Map an IPv4-in-IPv6 address back and reuse the v4 rules.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(&v4);
    }
    let head = ip.segments()[0];
    ip.is_loopback()              // ::1
        || ip.is_unspecified()      // ::
        || ip.is_multicast()        // ff00::/8
        || (head & 0xfe00) == 0xfc00 // fc00::/7  unique-local
        || (head & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

/// Cheap, DNS-free check: is this endpoint's host *statically* known-internal —
/// a literal IP in a blocked range, or a loopback/metadata hostname? Used at
/// subscribe time so an obviously-internal endpoint is rejected on the spot.
pub(crate) fn is_blocked_endpoint_static(url: &str) -> bool {
    let Some(host) = host_of(url) else {
        return true; // no parseable host → nothing safe to POST to
    };
    let lower = host.to_ascii_lowercase();
    if BLOCKED_HOSTS.contains(&lower.as_str())
        || lower == "localhost"
        || lower.ends_with(".localhost")
    {
        return true;
    }
    // A bracketless IPv6 or an IPv4 literal parses directly.
    if let Ok(ip) = lower.parse::<IpAddr>() {
        return is_blocked_ip(&ip);
    }
    false
}

/// The `host[:port]` authority of a URL, lowercased — e.g.
/// `http://127.0.0.1:8443/x` → `127.0.0.1:8443`. Used to match the operator
/// send-time allowlist.
fn authority_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    (!authority.is_empty()).then(|| authority.to_ascii_lowercase())
}

/// Operator-configured `host:port` authorities that bypass the internal-target
/// guard **at send time only** — for a self-hosted push distributor an operator
/// deliberately runs on an otherwise-blocked address (loopback / LAN). Seeded
/// once from `MYCELLIUM_PUSH_ALLOW_HOSTS` (comma-separated `host:port`). This
/// never relaxes *subscribe*-time validation of client-supplied endpoints, so a
/// client still cannot register an internal endpoint.
fn allow_registry() -> &'static Mutex<HashSet<String>> {
    static REG: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    REG.get_or_init(|| {
        let mut set = HashSet::new();
        if let Ok(v) = std::env::var("MYCELLIUM_PUSH_ALLOW_HOSTS") {
            for h in v.split(',') {
                let h = h.trim().to_ascii_lowercase();
                if !h.is_empty() {
                    set.insert(h);
                }
            }
        }
        Mutex::new(set)
    })
}

/// Test-only: register an exact `host:port` authority the send-time guard should
/// treat as an operator-allowlisted internal distributor (mirrors seeding subs
/// an operator configured). Exact-match so it can't relax the strict checks other
/// tests assert on different addresses/ports.
#[cfg(test)]
pub(crate) fn allow_authority_for_test(authority: &str) {
    allow_registry()
        .lock()
        .unwrap()
        .insert(authority.to_ascii_lowercase());
}

/// The full SSRF check applied immediately before connecting: reject anything
/// statically-internal, then **resolve** the host and reject if *any* resolved
/// address is internal (guards DNS names and rebinding). Returns `false` — do
/// not connect — if resolution fails or yields no address. An operator-allowlisted
/// authority bypasses the guard (self-hosted internal distributor).
pub(crate) fn endpoint_is_safe_to_connect(url: &str) -> bool {
    if let Some(auth) = authority_of(url) {
        if allow_registry().lock().unwrap().contains(&auth) {
            return true;
        }
    }
    if is_blocked_endpoint_static(url) {
        return false;
    }
    let Some(host) = host_of(url) else {
        return false;
    };
    // The port doesn't change which IPs a host resolves to; 443 is fine for the
    // HTTPS endpoints we accept.
    match (host.as_str(), 443u16).to_socket_addrs() {
        Ok(addrs) => {
            let mut resolved_any = false;
            for addr in addrs {
                resolved_any = true;
                if is_blocked_ip(&addr.ip()) {
                    return false;
                }
            }
            resolved_any
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vapid_public_key_is_base64url_65_bytes() {
        let v = Vapid::generate();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(v.public_key())
            .unwrap();
        assert_eq!(raw.len(), 65); // uncompressed P-256 point
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin_of("https://fcm.googleapis.com/fcm/send/abc").as_deref(),
            Some("https://fcm.googleapis.com")
        );
        assert_eq!(
            origin_of("https://updates.push.services.mozilla.com/wpush/v2/xyz").as_deref(),
            Some("https://updates.push.services.mozilla.com")
        );
        assert_eq!(origin_of("not-a-url"), None);
    }

    #[test]
    fn host_extraction_handles_ports_and_ipv6_brackets() {
        assert_eq!(
            host_of("https://push.example/x").as_deref(),
            Some("push.example")
        );
        assert_eq!(
            host_of("https://push.example:8443/x").as_deref(),
            Some("push.example")
        );
        assert_eq!(
            host_of("https://127.0.0.1:2379/x").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(host_of("https://[::1]:443/x").as_deref(), Some("::1"));
        assert_eq!(host_of("https://[fe80::1]/x").as_deref(), Some("fe80::1"));
        assert_eq!(
            host_of("https://user:pw@10.0.0.5/x").as_deref(),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn ssrf_guard_blocks_internal_ip_ranges() {
        // Literal IPs across every blocked family are refused by the static (no
        // DNS) check — the exact families that reached the network before the fix.
        for bad in [
            "https://169.254.169.254/latest/meta-data/", // cloud metadata (link-local)
            "https://127.0.0.1:2379/put",                // loopback (etcd)
            "https://10.0.0.5/x",                        // private 10/8
            "https://172.16.0.1/x",                      // private 172.16/12
            "https://192.168.1.1/x",                     // private 192.168/16
            "https://100.100.100.200/x",                 // CGNAT/shared 100.64/10
            "https://0.0.0.0/x",                         // unspecified
            "https://[::1]/x",                           // IPv6 loopback
            "https://[fe80::1]/x",                       // IPv6 link-local
            "https://[fc00::1]/x",                       // IPv6 unique-local
            "https://[::ffff:127.0.0.1]/x",              // IPv4-mapped loopback
            "https://metadata.google.internal/computeMetadata/v1/", // metadata hostname
            "https://localhost/x",                       // loopback hostname
        ] {
            assert!(
                is_blocked_endpoint_static(bad),
                "expected {bad} to be blocked statically"
            );
            assert!(
                !endpoint_is_safe_to_connect(bad),
                "expected {bad} to be refused before connecting"
            );
        }
    }

    #[test]
    fn ssrf_guard_allows_a_public_looking_host() {
        // A normal public host is NOT blocked statically (subscribe must accept
        // it; the connect-time check still resolves it, but the static gate that
        // subscribe uses must pass).
        assert!(!is_blocked_endpoint_static("https://push.example.com/abc"));
        assert!(!is_blocked_endpoint_static(
            "https://fcm.googleapis.com/fcm/send/x"
        ));
    }

    #[test]
    fn ssrf_guard_refuses_send_to_loopback_without_connecting() {
        // A send to a loopback endpoint returns Failed via the guard — never a
        // connection attempt (the port is closed; if we tried to connect we'd
        // still get Failed, but the guard short-circuits first, which is what a
        // literal-IP static block proves: no DNS, no socket).
        let v = Vapid::generate();
        assert_eq!(v.send("https://127.0.0.1:1/x", 0), SendResult::Failed);
        assert_eq!(v.send("https://169.254.169.254/x", 0), SendResult::Failed);
        assert_eq!(
            unifiedpush_send("https://127.0.0.1:1/x", 0),
            SendResult::Failed
        );
    }
}
