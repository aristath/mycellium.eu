//! Durable encrypted attachment bodies.
//!
//! Attachments are protocol data, not presentation events. A recipient stores
//! the bytes in the same transaction as message history before acknowledging
//! delivery; hosts may then render or export them whenever convenient.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use mycellium_core::storage::Storage;
use mycellium_core::wire;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAttachment {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
}

fn key(id: &str) -> Vec<u8> {
    let mut key = b"attachment:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

pub fn save<S: Storage>(store: &mut S, attachment: &StoredAttachment) -> Result<(), S::Error> {
    store.put(&key(&attachment.id), &wire::encode(attachment))
}

pub fn load<S: Storage>(store: &S, id: &str) -> Result<Option<StoredAttachment>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let Some(bytes) = store.get(&key(id))? else {
        return Ok(None);
    };
    wire::decode(&bytes)
        .map(Some)
        .map_err(|_| anyhow!("stored attachment '{id}' is corrupt"))
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
    fn attachment_round_trips_and_corruption_fails_closed() {
        let mut store = Mem::default();
        let attachment = StoredAttachment {
            id: "message-1".into(),
            name: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: vec![1, 2, 3],
        };
        save(&mut store, &attachment).unwrap();
        assert_eq!(load(&store, &attachment.id).unwrap(), Some(attachment));
        store.0.insert(key("message-1"), b"broken".to_vec());
        assert!(load(&store, "message-1").is_err());
    }
}
