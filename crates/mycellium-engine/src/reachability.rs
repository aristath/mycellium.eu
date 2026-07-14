//! Local delivery outcomes.
//!
//! Hard-serverless Mycellium has one network path: direct peer-to-peer delivery.
//! If direct delivery fails, the caller may park the encrypted item in the
//! sender's local outbox. There is no routing score database here.

use mycellium_core::storage::Storage;

/// Observable outcome of a delivery attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryPath {
    /// Live delivery over a direct route to the authenticated active device.
    Direct,
    /// Parked in this device's local encrypted outbox for a later retry.
    Outbox,
    /// Nothing worked this pass.
    Failed,
}

impl DeliveryPath {
    pub fn is_delivered(self) -> bool {
        matches!(self, DeliveryPath::Direct)
    }

    pub fn is_live_direct(self) -> bool {
        matches!(self, DeliveryPath::Direct)
    }
}

pub fn default_order() -> Vec<DeliveryPath> {
    vec![DeliveryPath::Direct]
}

pub fn record<S: Storage>(
    _store: &mut S,
    _device_key: &str,
    _path: DeliveryPath,
    _ok: bool,
    _now: u64,
) -> Result<(), S::Error> {
    Ok(())
}

pub fn best_paths<S: Storage>(_store: &S, _device_key: &str, _now: u64) -> Vec<DeliveryPath> {
    default_order()
}

pub fn best_paths_for<S: Storage>(
    _store: &S,
    _device_key: &str,
    live: DeliveryPath,
    _now: u64,
) -> Vec<DeliveryPath> {
    vec![live]
}

pub fn clear<S: Storage>(_store: &mut S) -> Result<(), S::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemStore {
        data: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl Storage for MemStore {
        type Error = std::convert::Infallible;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.data.get(key).cloned())
        }

        fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
            self.data.insert(key.to_vec(), val.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
            self.data.remove(key);
            Ok(())
        }
    }

    #[test]
    fn direct_is_the_only_default_path() {
        let store = MemStore::default();
        assert_eq!(
            best_paths(&store, "never-seen", 1_000),
            vec![DeliveryPath::Direct]
        );
    }

    #[test]
    fn delivery_status_helpers_are_exact() {
        assert!(DeliveryPath::Direct.is_delivered());
        assert!(!DeliveryPath::Outbox.is_delivered());
        assert!(!DeliveryPath::Failed.is_delivered());
        assert!(DeliveryPath::Direct.is_live_direct());
        assert!(!DeliveryPath::Outbox.is_live_direct());
    }
}
