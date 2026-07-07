//! Name policy: what a `name@mycellium.eu` local part may be, and how many a
//! single key may hold. This is the "controlled namespace" rule layer — the one
//! part of the identity we legitimately gate (the npub itself stays open and
//! portable). Registration is otherwise self-service and key-authenticated.

use std::collections::HashSet;

use thiserror::Error;

/// The registration rules applied to every requested name.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The domain names are issued under (e.g. `mycellium.eu`).
    pub domain: String,
    /// Minimum local-part length.
    pub min_len: usize,
    /// Maximum local-part length.
    pub max_len: usize,
    /// Names nobody may self-register (operator/root/abuse handles, the NIP-05
    /// root `_`, …).
    pub reserved: HashSet<String>,
    /// How many names one key may hold (anti-squatting).
    pub max_names_per_key: usize,
}

impl Default for Policy {
    fn default() -> Self {
        let reserved = [
            "_",
            "admin",
            "root",
            "support",
            "abuse",
            "postmaster",
            "hostmaster",
            "mycellium",
            "nostr",
            "help",
            "info",
            "security",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        Self {
            domain: "mycellium.eu".to_string(),
            min_len: 1,
            max_len: 30,
            reserved,
            max_names_per_key: 1,
        }
    }
}

/// A requested name rejected by [`Policy::normalize`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("name must be {min}–{max} characters")]
    Length { min: usize, max: usize },
    #[error("name may only contain a–z, 0–9, '-' and '_'")]
    Charset,
    #[error("that name is reserved")]
    Reserved,
}

impl Policy {
    /// Validate a requested local name and return its canonical (lowercased)
    /// form — the key it is stored and resolved under.
    pub fn normalize(&self, name: &str) -> Result<String, PolicyError> {
        let name = name.trim().to_ascii_lowercase();
        let len = name.chars().count();
        if len < self.min_len || len > self.max_len {
            return Err(PolicyError::Length {
                min: self.min_len,
                max: self.max_len,
            });
        }
        // Already lowercased, so ascii-lowercase covers every allowed letter; any
        // non-ascii or punctuation char falls through to the charset error.
        let ok = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok {
            return Err(PolicyError::Charset);
        }
        if self.reserved.contains(&name) {
            return Err(PolicyError::Reserved);
        }
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_lowercases_a_valid_name() {
        let p = Policy::default();
        assert_eq!(p.normalize("Alice").unwrap(), "alice");
        assert_eq!(p.normalize("  bob_42-x ").unwrap(), "bob_42-x");
    }

    #[test]
    fn rejects_charset_length_and_reserved() {
        let p = Policy::default();
        assert_eq!(p.normalize("a b"), Err(PolicyError::Charset));
        assert_eq!(p.normalize("aliçe"), Err(PolicyError::Charset));
        assert_eq!(
            p.normalize(""),
            Err(PolicyError::Length { min: 1, max: 30 })
        );
        assert_eq!(
            p.normalize(&"x".repeat(31)),
            Err(PolicyError::Length { min: 1, max: 30 })
        );
        assert_eq!(p.normalize("admin"), Err(PolicyError::Reserved));
        assert_eq!(p.normalize("_"), Err(PolicyError::Reserved));
    }
}
