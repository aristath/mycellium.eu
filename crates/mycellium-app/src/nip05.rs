//! **NIP-05** — verifiable human-name ↔ key binding (`alice@mycellium.eu`).
//!
//! A NIP-05 address is a DNS-based internet identifier for a Nostr key. It
//! resolves via an HTTPS GET to the domain's well-known file:
//!
//! ```text
//!   GET https://<domain>/.well-known/nostr.json?name=<name>
//!   →  { "names": { "<name>": "<hex-pubkey>" }, "relays"?: { "<hex>": ["wss://…"] } }
//! ```
//!
//! The binding is **verified** when the resolved pubkey equals the key you
//! already hold (the one you pinned). That is the whole point: in this engine a
//! NIP-05 is *never* an identity source — the trust pin is (see
//! [`crate::contacts`]). NIP-05 is an **additional** binding to check against
//! that pin, and a name that later resolves to a *different* key is a red flag
//! (a rebinding), surfaced through the trust layer, never silently accepted.
//!
//! # What this module owns
//!
//! - [`Nip05Address`] — a parsed `name@domain` (domain lowercased), with the
//!   `.well-known` URL it resolves at. `_@domain` is the domain-root identity.
//! - [`Nip05Resolver`] — a trait (`resolve(&Nip05Address) -> Nip05Record`) so the
//!   verification logic is testable against a stub with no real DNS/TLS. The real
//!   [`HttpsResolver`] performs the actual HTTPS GET (blocking `ureq` on a
//!   blocking task); tests inject their own.
//! - [`Nip05Record`] — what a resolve yields: the `pubkey` the name maps to now,
//!   plus any advertised `relays`.
//!
//! # Honest trust boundary
//!
//! Resolution trusts DNS + the domain's TLS certificate + the domain operator:
//! whoever controls the domain controls what `name` maps to, and can *rebind* it.
//! That is exactly why this is advisory over the pin, not an override — a
//! rebinding is detected ([`crate::Nip05Status::Mismatch`]) and surfaced, and
//! re-pinning still requires the same out-of-band confirmation as a key change.

use std::fmt;
use std::str::FromStr;

use nostr::{PublicKey, RelayUrl};

/// A parsed NIP-05 address: a `name@domain` internet identifier for a key.
///
/// The domain is stored lowercased (DNS is case-insensitive); the name is kept
/// verbatim because it is the literal JSON key looked up in `nostr.json`. A bare
/// `domain` (no `@`) or `_@domain` denotes the **domain-root** identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nip05Address {
    name: String,
    domain: String,
}

/// Error parsing a NIP-05 address string.
#[derive(Debug, thiserror::Error)]
pub enum ParseAddressError {
    /// The input was empty / whitespace only.
    #[error("nip05 address is empty")]
    Empty,
    /// The input had an empty name or domain, or an extra `@`.
    #[error("'{0}' is not a valid nip05 address (expected name@domain)")]
    Malformed(String),
}

impl Nip05Address {
    /// Parse a `name@domain` address (or a bare `domain`, treated as the
    /// `_@domain` root). The domain is lowercased; the name is preserved as-is.
    pub fn parse(address: &str) -> Result<Self, ParseAddressError> {
        let address = address.trim();
        if address.is_empty() {
            return Err(ParseAddressError::Empty);
        }
        // A bare domain (no `@`) is the domain-root identity, name `_`.
        let (name, domain) = match address.split_once('@') {
            Some((name, domain)) => (name, domain),
            None => ("_", address),
        };
        if name.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
            return Err(ParseAddressError::Malformed(address.to_string()));
        }
        Ok(Self {
            name: name.to_string(),
            domain: domain.to_ascii_lowercase(),
        })
    }

    /// The local part (the `nostr.json` `names` key). `_` for a root identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The (lowercased) domain the identity is hosted under.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Whether this is the domain-root identity (`_@domain`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.name == "_"
    }

    /// The `.well-known/nostr.json` URL this address resolves at.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "https://{}/.well-known/nostr.json?name={}",
            self.domain, self.name
        )
    }
}

impl fmt::Display for Nip05Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.domain)
    }
}

impl FromStr for Nip05Address {
    type Err = ParseAddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// The result of resolving a [`Nip05Address`]: the key the name currently maps
/// to, plus any relays the domain advertises for that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nip05Record {
    /// The hex pubkey the domain's `nostr.json` maps this name to *right now*.
    pub pubkey: PublicKey,
    /// Any relays advertised for that pubkey (`relays` map; may be empty).
    pub relays: Vec<RelayUrl>,
}

/// Error resolving a NIP-05 address to a [`Nip05Record`]. Typed so callers can
/// distinguish "the name is gone" from "the server is unreachable" from "the
/// server returned junk" — none of these ever panics.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The HTTPS request failed (DNS, TLS, connection, non-2xx, read error).
    #[error("could not reach nip05 endpoint '{0}': {1}")]
    Network(String, String),
    /// The endpoint responded, but the body was not valid `nostr.json`.
    #[error("nip05 response for '{0}' was malformed: {1}")]
    MalformedJson(String, String),
    /// The endpoint responded with valid JSON, but it has no entry for this name.
    #[error("name '{0}' is not present in the domain's nostr.json")]
    NameNotFound(String),
}

/// Resolves a [`Nip05Address`] to the key it currently maps to.
///
/// A trait so the verification logic can be exercised against a **stub** with no
/// real DNS/TLS in tests, while production uses [`HttpsResolver`]. Static
/// dispatch only (callers take `&impl Nip05Resolver`), so no `Send`-bounded
/// boxing is required — hence the deliberate `async_fn_in_trait`.
#[allow(async_fn_in_trait)]
pub trait Nip05Resolver {
    /// Resolve `address` to its current [`Nip05Record`], or a typed error.
    async fn resolve(&self, address: &Nip05Address) -> Result<Nip05Record, ResolveError>;
}

/// Parse a `nostr.json` body for `address`, extracting the mapped pubkey and any
/// advertised relays. Shared by [`HttpsResolver`] and reusable by test stubs.
pub fn parse_nostr_json(address: &Nip05Address, body: &str) -> Result<Nip05Record, ResolveError> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| ResolveError::MalformedJson(address.to_string(), e.to_string()))?;
    let hex = json
        .get("names")
        .and_then(|names| names.get(address.name()))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ResolveError::NameNotFound(address.to_string()))?;
    let pubkey = PublicKey::from_hex(hex).map_err(|_| {
        ResolveError::MalformedJson(
            address.to_string(),
            format!("names['{}'] is not a valid hex pubkey", address.name()),
        )
    })?;
    let relays = json
        .get("relays")
        .and_then(|relays| relays.get(pubkey.to_hex()))
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| RelayUrl::parse(&s).ok())
        .collect();
    Ok(Nip05Record { pubkey, relays })
}

/// The production resolver: one HTTPS GET to the domain's `.well-known/nostr.json`.
///
/// rustls-backed (via `ureq`), so no OpenSSL/native-tls and no extra async DNS
/// resolver. The blocking request runs on a [`tokio::task::spawn_blocking`] worker
/// so it never stalls the async runtime.
///
/// **Out of scope (server-side):** *hosting* the `.well-known/nostr.json` file is
/// the domain operator's job. This resolver only *reads* it to verify a binding.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpsResolver;

impl Nip05Resolver for HttpsResolver {
    async fn resolve(&self, address: &Nip05Address) -> Result<Nip05Record, ResolveError> {
        let url = address.url();
        let addr = address.clone();
        let body = tokio::task::spawn_blocking(move || -> Result<String, ResolveError> {
            let resp = ureq::get(&url)
                .call()
                .map_err(|e| ResolveError::Network(url.clone(), e.to_string()))?;
            resp.into_string()
                .map_err(|e| ResolveError::Network(url.clone(), e.to_string()))
        })
        .await
        .map_err(|e| ResolveError::Network(address.to_string(), e.to_string()))??;
        parse_nostr_json(&addr, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_display_round_trip() {
        for input in ["alice@mycellium.eu", "_@mycellium.eu"] {
            let addr = Nip05Address::parse(input).unwrap();
            assert_eq!(addr.to_string(), input, "round-trip {input}");
        }
    }

    #[test]
    fn bare_domain_is_root_identity() {
        let addr = Nip05Address::parse("mycellium.eu").unwrap();
        assert!(addr.is_root());
        assert_eq!(addr.name(), "_");
        assert_eq!(addr.domain(), "mycellium.eu");
        assert_eq!(addr.to_string(), "_@mycellium.eu");
    }

    #[test]
    fn domain_is_lowercased() {
        let addr = Nip05Address::parse("Alice@MyCellium.EU").unwrap();
        assert_eq!(addr.domain(), "mycellium.eu");
        assert_eq!(addr.name(), "Alice", "name is case-preserving");
    }

    #[test]
    fn url_targets_well_known() {
        let addr = Nip05Address::parse("alice@mycellium.eu").unwrap();
        assert_eq!(
            addr.url(),
            "https://mycellium.eu/.well-known/nostr.json?name=alice"
        );
    }

    #[test]
    fn malformed_addresses_rejected() {
        assert!(matches!(
            Nip05Address::parse(""),
            Err(ParseAddressError::Empty)
        ));
        for bad in ["@mycellium.eu", "alice@", "a@b@c.eu", "nodot"] {
            assert!(
                matches!(
                    Nip05Address::parse(bad),
                    Err(ParseAddressError::Malformed(_))
                ),
                "should reject '{bad}'"
            );
        }
    }

    #[test]
    fn parse_json_extracts_key_and_relays() {
        let bob = nostr::Keys::generate().public_key();
        let addr = Nip05Address::parse("bob@mycellium.eu").unwrap();
        let body = format!(
            r#"{{"names":{{"bob":"{}"}},"relays":{{"{}":["wss://relay.mycellium.eu"]}}}}"#,
            bob.to_hex(),
            bob.to_hex()
        );
        let rec = parse_nostr_json(&addr, &body).unwrap();
        assert_eq!(rec.pubkey, bob);
        assert_eq!(rec.relays.len(), 1);
    }

    #[test]
    fn parse_json_name_not_found_and_malformed() {
        let addr = Nip05Address::parse("bob@mycellium.eu").unwrap();
        assert!(matches!(
            parse_nostr_json(&addr, r#"{"names":{"alice":"deadbeef"}}"#),
            Err(ResolveError::NameNotFound(_))
        ));
        assert!(matches!(
            parse_nostr_json(&addr, "not json"),
            Err(ResolveError::MalformedJson(..))
        ));
    }
}
