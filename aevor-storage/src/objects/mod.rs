//! Object store: CRUD operations for blockchain objects.
//!
//! Keyed under domain `b"object"` in the storage backend.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Hash256, ObjectId};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::storage::StorageKey;
use crate::{StorageError, StorageResult};

/// Domain prefix for object storage keys.
const OBJECT_DOMAIN: &[u8] = b"object";

/// Build a storage key for an object ID.
fn object_key(id: &ObjectId) -> StorageKey {
    StorageKey::from_hash(OBJECT_DOMAIN, &id.as_hash().0)
}

/// Metadata about a stored blockchain object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Unique object identifier.
    pub id: ObjectId,
    /// Current owner of this object.
    pub owner: Address,
    /// Privacy level controlling visibility.
    pub privacy_level: PrivacyLevel,
    /// Monotonically increasing version counter.
    pub version: u64,
    /// BLAKE3 hash of the object content.
    pub content_hash: Hash256,
    /// Size of the serialized object data in bytes.
    pub size_bytes: usize,
}

/// A full object record including its data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectRecord {
    /// Metadata about the object.
    pub metadata: ObjectMetadata,
    /// Raw object data (may be encrypted for private objects).
    pub data: Vec<u8>,
}

/// A lightweight version descriptor (no data).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectVersion {
    /// Object identifier.
    pub id: ObjectId,
    /// Version number.
    pub version: u64,
    /// Content hash at this version.
    pub content_hash: Hash256,
}

/// Filter for querying objects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectQuery {
    /// Filter by owner address.
    pub owner: Option<Address>,
    /// Filter by privacy level.
    pub privacy_level: Option<PrivacyLevel>,
    /// Maximum number of results.
    pub limit: usize,
    /// Number of results to skip.
    pub offset: usize,
}

impl Default for ObjectQuery {
    fn default() -> Self {
        Self { owner: None, privacy_level: None, limit: 50, offset: 0 }
    }
}

/// A page of object results with an optional continuation token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectBatch {
    /// Objects in this page.
    pub objects: Vec<ObjectRecord>,
    /// Opaque token for fetching the next page (`None` = last page).
    pub continuation_token: Option<String>,
}

/// Result of a successful write operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectUpdateResult {
    /// Identifier of the object that was written.
    pub id: ObjectId,
    /// New version number after the write.
    pub new_version: u64,
    /// New content hash after the write.
    pub new_hash: Hash256,
}

/// Key-value object store backed by the configured `StorageBackend`.
pub struct ObjectStore {
    backend: Box<dyn crate::backend::StorageBackend>,
}

impl ObjectStore {
    /// Create a new object store using the given backend.
    pub fn new(backend: Box<dyn crate::backend::StorageBackend>) -> Self {
        Self { backend }
    }

    /// Retrieve an object by its identifier.
    ///
    /// Returns `Ok(None)` if the object does not exist.
    pub fn get(&self, id: &ObjectId) -> StorageResult<Option<ObjectRecord>> {
        let key = object_key(id);
        let value = self.backend.get(&key)?;
        match value {
            None => Ok(None),
            Some(v) => {
                let record: ObjectRecord = bincode::deserialize(&v.0)
                    .map_err(|e| StorageError::BackendError(
                        format!("deserialization failed for {:?}: {}", id, e)
                    ))?;
                Ok(Some(record))
            }
        }
    }

    /// Write an object record, creating or overwriting it.
    ///
    /// Returns the new version and content hash on success.
    pub fn put(&mut self, record: ObjectRecord) -> StorageResult<ObjectUpdateResult> {
        let id = record.metadata.id;
        let new_version = record.metadata.version;
        let new_hash = record.metadata.content_hash;
        let key = object_key(&id);
        let data = bincode::serialize(&record)
            .map_err(|e| StorageError::BackendError(
                format!("serialization failed for {:?}: {}", id, e)
            ))?;
        self.backend.put(key, aevor_core::storage::StorageValue::from_bytes(data))?;
        Ok(ObjectUpdateResult { id, new_version, new_hash })
    }

    /// Delete an object from the store.
    ///
    /// Returns `Ok(())` whether or not the object existed.
    pub fn delete(&mut self, id: &ObjectId) -> StorageResult<()> {
        let key = object_key(id);
        self.backend.delete(&key)
    }

    /// Check whether an object exists.
    pub fn exists(&self, id: &ObjectId) -> StorageResult<bool> {
        let key = object_key(id);
        Ok(self.backend.get(&key)?.is_some())
    }
}
