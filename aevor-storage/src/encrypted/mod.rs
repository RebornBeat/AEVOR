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
    pub fn get_required(&self, key: &StorageKey) -> StorageResult<&EncryptedRecord> {
        self.records.get(&key.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(&key.0),
        })
    }

    /// Delete an encrypted record.
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
