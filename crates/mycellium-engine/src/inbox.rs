//! Durable recipient-side acceptance records.
//!
//! A receiver records an accepted `(delivery id, payload digest)` before sending
//! the device-signed ACK. A retry with the same pair is idempotent and receives
//! the same proof again; reuse of an id for different bytes is rejected.

use serde::{Deserialize, Serialize};

use mycellium_core::delivery::PayloadDigest;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

const KEY: &[u8] = b"accepted-deliveries";

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

fn load<S: Storage>(store: &S) -> Result<Vec<AcceptedDelivery>, S::Error> {
    Ok(crate::decode_or_warn(
        store.get(KEY)?,
        "accepted delivery index",
    ))
}

fn save<S: Storage>(store: &mut S, accepted: &[AcceptedDelivery]) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(&accepted.to_vec()))
}

pub fn seen<S: Storage>(
    store: &S,
    id: &str,
    payload_digest: &PayloadDigest,
) -> Result<Seen, S::Error> {
    Ok(match load(store)?.iter().find(|entry| entry.id == id) {
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
) -> Result<(), S::Error> {
    let mut accepted = load(store)?;
    if let Some(existing) = accepted.iter().find(|entry| entry.id == id) {
        if existing.payload_digest == payload_digest {
            return Ok(());
        }
        // Do not overwrite a valid id with different bytes.
        return Ok(());
    }
    accepted.push(AcceptedDelivery {
        id,
        payload_digest,
        accepted_at: now,
    });
    save(store, &accepted)
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
    fn accepted_deliveries_are_retained_without_time_expiry() {
        let mut store = Mem::default();
        record(&mut store, "old".into(), [1; 32], 1).unwrap();
        record(&mut store, "new".into(), [2; 32], 100 * 86_400).unwrap();
        assert_eq!(seen(&store, "old", &[1; 32]).unwrap(), Seen::Duplicate);
        assert_eq!(seen(&store, "new", &[2; 32]).unwrap(), Seen::Duplicate);
    }
}
