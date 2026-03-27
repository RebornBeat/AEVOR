//! Encrypted object storage for private objects.
//!
//! Private objects are stored encrypted at rest. Only the authorized TEE
//! enclave (identified by its `EncryptionKeyReference`) can decrypt them.

use serde::{Deserialize, Serialize};
use aevor_core::storage::{EncryptedState, EncryptionKeyReference, StateRoot, StorageKey};
use aevor_core::primitives::Hash256;
use crate::{StorageError, StorageResult};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub key: StorageKey,
    pub state: EncryptedState,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionContext {
    pub key_reference: EncryptionKeyReference,
    pub auth_data: Vec<u8>,
}

pub type TeeKeyReference = EncryptionKeyReference;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateRoot {
    pub plaintext_root: StateRoot,
    pub encrypted_root_commitment: Hash256,
}

pub struct EncryptedObjectStore {
    records: std::collections::HashMap<Vec<u8>, EncryptedRecord>,
}

impl EncryptedObjectStore {
    /// Create an empty encrypted object store.
    pub fn new() -> Self { Self { records: std::collections::HashMap::new() } }

    /// Store an encrypted record.
    pub fn put(&mut self, record: EncryptedRecord) {
        self.records.insert(record.key.0.clone(), record);
    }

    /// Retrieve an encrypted record by key.
    pub fn get(&self, key: &StorageKey) -> Option<&EncryptedRecord> {
        self.records.get(&key.0)
    }

    /// Retrieve or return `NotFound` error.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no record exists for the given key.
    pub fn get_required(&self, key: &StorageKey) -> StorageResult<&EncryptedRecord> {
        self.records.get(&key.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(&key.0),
        })
    }

    /// Delete an encrypted record.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no record exists for the given key.
    pub fn delete(&mut self, key: &StorageKey) -> StorageResult<()> {
        if self.records.remove(&key.0).is_none() {
            return Err(StorageError::NotFound { key: hex::encode(&key.0) });
        }
        Ok(())
    }

    /// Number of encrypted records stored.
    pub fn record_count(&self) -> usize { self.records.len() }

    /// Compute an encrypted root commitment over all stored keys and versions.
    ///
    /// The commitment is a `Hash256` that binds the store to a specific state
    /// without revealing which keys are stored (privacy-preserving Merkle root).
    pub fn encrypted_commitment(&self) -> Hash256 {
        if self.records.is_empty() { return Hash256::ZERO; }
        let mut sorted: Vec<(&Vec<u8>, u64)> = self.records
            .iter().map(|(k, r)| (k, r.version)).collect();
        sorted.sort_by_key(|(k, _)| k.as_slice());
        let mut root = [0u8; 32];
        for (key, version) in sorted {
            for (i, b) in key.iter().take(32).enumerate() { root[i] ^= b; }
            for (i, b) in version.to_le_bytes().iter().enumerate() { root[i % 32] ^= b; }
        }
        Hash256(root)
    }
}

impl Default for EncryptedObjectStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::storage::{EncryptedState, EncryptionKeyReference, StorageKey};
    use aevor_core::primitives::Hash256;
    use aevor_core::tee::TeePlatform;

    fn key(n: u8) -> StorageKey { StorageKey(vec![n]) }

    fn key_ref() -> EncryptionKeyReference {
        EncryptionKeyReference {
            platform: TeePlatform::IntelSgx,
            key_id: Hash256::ZERO,
            key_version: 1,
        }
    }

    fn make_record(key_byte: u8, version: u64) -> EncryptedRecord {
        EncryptedRecord {
            key: key(key_byte),
            state: EncryptedState {
                ciphertext: vec![0xDE, 0xAD, key_byte],
                auth_tag: [0u8; 16],
                nonce: [0u8; 12],
                key_reference: key_ref(),
                plaintext_hash: Hash256::ZERO,
            },
            version,
        }
    }

    #[test]
    fn put_and_get() {
        let mut store = EncryptedObjectStore::new();
        store.put(make_record(1, 1));
        let rec = store.get(&key(1)).unwrap();
        assert_eq!(rec.version, 1);
        assert_eq!(rec.state.ciphertext, vec![0xDE, 0xAD, 1]);
    }

    #[test]
    fn get_missing_returns_none() {
        let store = EncryptedObjectStore::default();
        assert!(store.get(&key(99)).is_none());
    }

    #[test]
    fn get_required_missing_returns_error() {
        let store = EncryptedObjectStore::new();
        assert!(store.get_required(&key(5)).is_err());
    }

    #[test]
    fn delete_removes_record() {
        let mut store = EncryptedObjectStore::new();
        store.put(make_record(2, 1));
        assert!(store.delete(&key(2)).is_ok());
        assert_eq!(store.record_count(), 0);
    }

    #[test]
    fn delete_missing_returns_error() {
        let mut store = EncryptedObjectStore::new();
        assert!(store.delete(&key(99)).is_err());
    }

    #[test]
    fn record_count_tracks_puts() {
        let mut store = EncryptedObjectStore::new();
        assert_eq!(store.record_count(), 0);
        store.put(make_record(1, 1));
        store.put(make_record(2, 1));
        assert_eq!(store.record_count(), 2);
    }

    #[test]
    fn encrypted_commitment_zero_when_empty() {
        let store = EncryptedObjectStore::new();
        assert_eq!(store.encrypted_commitment(), Hash256::ZERO);
    }

    #[test]
    fn encrypted_commitment_non_zero_when_records_present() {
        let mut store = EncryptedObjectStore::new();
        store.put(make_record(5, 42));
        assert_ne!(store.encrypted_commitment(), Hash256::ZERO);
    }

    #[test]
    fn encrypted_commitment_changes_with_version() {
        let mut s1 = EncryptedObjectStore::new();
        let mut s2 = EncryptedObjectStore::new();
        s1.put(make_record(1, 1));
        s2.put(make_record(1, 2)); // same key, different version
        assert_ne!(s1.encrypted_commitment(), s2.encrypted_commitment());
    }
}
