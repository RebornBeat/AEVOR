//! Block storage and indexing.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHash, BlockHeight};
pub use aevor_core::block::BlockAttestation as StoredAttestation;
use crate::{StorageError, StorageResult};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRecord {
    pub hash: BlockHash,
    pub height: BlockHeight,
    pub size_bytes: u32,
    pub transaction_count: u32,
    pub is_finalized: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockQuery {
    pub height: Option<BlockHeight>,
    pub hash: Option<BlockHash>,
    pub finalized_only: bool,
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockIndex {
    pub height_to_hash: std::collections::BTreeMap<u64, BlockHash>,
}

impl BlockIndex {
    pub fn new() -> Self { Self { height_to_hash: std::collections::BTreeMap::new() } }
    pub fn insert(&mut self, height: BlockHeight, hash: BlockHash) {
        self.height_to_hash.insert(height.as_u64(), hash);
    }
    pub fn get_by_height(&self, height: BlockHeight) -> Option<BlockHash> {
        self.height_to_hash.get(&height.as_u64()).copied()
    }
}

impl Default for BlockIndex {
    fn default() -> Self { Self::new() }
}

pub struct BlockStore {
    records: std::collections::HashMap<[u8; 32], BlockRecord>,
    index: BlockIndex,
}

impl BlockStore {
    /// Create an empty block store.
    pub fn new() -> Self { Self { records: std::collections::HashMap::new(), index: BlockIndex::new() } }

    /// Store a block record.
    pub fn store(&mut self, record: BlockRecord) {
        self.index.insert(record.height, record.hash);
        self.records.insert(record.hash.0, record);
    }

    /// Retrieve a block by hash.
    pub fn get(&self, hash: &BlockHash) -> Option<&BlockRecord> { self.records.get(&hash.0) }

    /// Retrieve a block by height.
    pub fn get_by_height(&self, height: BlockHeight) -> Option<&BlockRecord> {
        self.index.get_by_height(height).and_then(|h| self.get(&h))
    }

    /// Retrieve a block or return `NotFound`.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no block with this hash is stored.
    pub fn get_required(&self, hash: &BlockHash) -> StorageResult<&BlockRecord> {
        self.get(hash).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(hash.0),
        })
    }

    /// Mark a block as finalized.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no block with this hash is stored.
    pub fn mark_finalized(&mut self, hash: &BlockHash) -> StorageResult<()> {
        let record = self.records.get_mut(&hash.0)
            .ok_or_else(|| StorageError::NotFound { key: hex::encode(hash.0) })?;
        record.is_finalized = true;
        Ok(())
    }

    /// Number of stored blocks.
    pub fn count(&self) -> usize { self.records.len() }
}

impl Default for BlockStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{BlockHash, BlockHeight, Hash256};

    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }
    fn height(n: u64) -> BlockHeight { BlockHeight(n) }

    fn make_record(hash_byte: u8, h: u64) -> BlockRecord {
        BlockRecord {
            hash: bh(hash_byte),
            height: height(h),
            size_bytes: 1024,
            transaction_count: 10,
            is_finalized: false,
        }
    }

    #[test]
    fn block_index_insert_and_get() {
        let mut idx = BlockIndex::new();
        idx.insert(height(100), bh(5));
        assert_eq!(idx.get_by_height(height(100)), Some(bh(5)));
        assert!(idx.get_by_height(height(200)).is_none());
    }

    #[test]
    fn block_store_store_and_get_by_hash() {
        let mut store = BlockStore::new();
        store.store(make_record(1, 100));
        let rec = store.get(&bh(1)).unwrap();
        assert_eq!(rec.hash, bh(1));
        assert_eq!(rec.height, height(100));
    }

    #[test]
    fn block_store_get_by_height() {
        let mut store = BlockStore::new();
        store.store(make_record(2, 200));
        let rec = store.get_by_height(height(200)).unwrap();
        assert_eq!(rec.hash, bh(2));
    }

    #[test]
    fn block_store_get_required_returns_error_for_missing() {
        let store = BlockStore::default();
        assert!(store.get_required(&bh(99)).is_err());
    }

    #[test]
    fn block_store_mark_finalized() {
        let mut store = BlockStore::new();
        store.store(make_record(3, 300));
        assert!(!store.get(&bh(3)).unwrap().is_finalized);
        store.mark_finalized(&bh(3)).unwrap();
        assert!(store.get(&bh(3)).unwrap().is_finalized);
    }

    #[test]
    fn block_store_mark_finalized_missing_returns_error() {
        let mut store = BlockStore::new();
        assert!(store.mark_finalized(&bh(0)).is_err());
    }

    #[test]
    fn block_store_count() {
        let mut store = BlockStore::new();
        assert_eq!(store.count(), 0);
        store.store(make_record(1, 1));
        store.store(make_record(2, 2));
        assert_eq!(store.count(), 2);
    }
}
