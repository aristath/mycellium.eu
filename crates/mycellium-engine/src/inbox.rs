//! Durable recipient-side acceptance records.
//!
//! A receiver records an accepted `(delivery id, payload digest)` before sending
//! the device-signed ACK. A retry with the same pair is idempotent and receives
//! the same proof again; reuse of an id for different bytes is rejected.

use anyhow::{anyhow, Result as AnyResult};
use serde::{Deserialize, Serialize};

use mycellium_core::delivery::PayloadDigest;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

const LEGACY_KEY: &[u8] = b"accepted-deliveries";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedDelivery {
    pub id: String,
    pub payload_digest: PayloadDigest,
    pub accepted_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    New,
    Duplicate,
    Collision,
}

fn key(id: &str) -> Vec<u8> {
    let mut key = b"accepted-delivery:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn decode_entry(bytes: &[u8]) -> AnyResult<AcceptedDelivery> {
    wire::decode(bytes).map_err(|_| anyhow!("accepted delivery state is corrupt"))
}

fn legacy_entry<S: Storage>(store: &S, id: &str) -> AnyResult<Option<AcceptedDelivery>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let Some(bytes) = store.get(LEGACY_KEY)? else {
        return Ok(None);
    };
    let accepted: Vec<AcceptedDelivery> =
        wire::decode(&bytes).map_err(|_| anyhow!("legacy accepted delivery index is corrupt"))?;
    Ok(accepted.into_iter().find(|entry| entry.id == id))
}

pub fn seen<S: Storage>(store: &S, id: &str, payload_digest: &PayloadDigest) -> AnyResult<Seen>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let entry = match store.get(&key(id))? {
        Some(bytes) => Some(decode_entry(&bytes)?),
        None => legacy_entry(store, id)?,
    };
    Ok(match entry.as_ref() {
        None => Seen::New,
        Some(entry) if &entry.payload_digest == payload_digest => Seen::Duplicate,
        Some(_) => Seen::Collision,
    })
}

pub fn record<S: Storage>(
    store: &mut S,
    id: String,
    payload_digest: PayloadDigest,
    now: u64,
) -> AnyResult<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let existing = match store.get(&key(&id))? {
        Some(bytes) => Some(decode_entry(&bytes)?),
        None => legacy_entry(store, &id)?,
    };
    if let Some(existing) = existing {
        if existing.payload_digest == payload_digest {
            return Ok(());
        }
        // Do not overwrite a valid id with different bytes.
        return Ok(());
    }
    let accepted = AcceptedDelivery {
        id,
        payload_digest,
        accepted_at: now,
    };
    store.put(&key(&accepted.id), &wire::encode(&accepted))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct Mem(HashMap<Vec<u8>, Vec<u8>>);

    impl Storage for Mem {
        type Error = Infallible;
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(key).cloned())
        }
        fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
            self.0.remove(key);
            Ok(())
        }
    }

    #[test]
    fn duplicate_is_idempotent_and_id_reuse_is_rejected() {
        let mut store = Mem::default();
        let digest = [1; 32];
        assert_eq!(seen(&store, "d1", &digest).unwrap(), Seen::New);
        record(&mut store, "d1".into(), digest, 10).unwrap();
        assert_eq!(seen(&store, "d1", &digest).unwrap(), Seen::Duplicate);
        assert_eq!(seen(&store, "d1", &[2; 32]).unwrap(), Seen::Collision);
    }

    #[test]
    fn accepted_deliveries_are_independent_durable_keys() {
        let mut store = Mem::default();
        record(&mut store, "old".into(), [1; 32], 1).unwrap();
        record(&mut store, "new".into(), [2; 32], 100 * 86_400).unwrap();
        assert_eq!(seen(&store, "old", &[1; 32]).unwrap(), Seen::Duplicate);
        assert_eq!(seen(&store, "new", &[2; 32]).unwrap(), Seen::Duplicate);
        assert!(store.0.contains_key(&key("old")));
        assert!(store.0.contains_key(&key("new")));
        assert!(!store.0.contains_key(LEGACY_KEY));
    }

    #[test]
    fn corrupt_acceptance_state_fails_closed() {
        let mut store = Mem::default();
        store.0.insert(key("d1"), b"broken".to_vec());
        assert!(seen(&store, "d1", &[1; 32]).is_err());
    }
}
