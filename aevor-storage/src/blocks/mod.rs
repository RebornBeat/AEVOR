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
    pub fn get_required(&self, hash: &BlockHash) -> StorageResult<&BlockRecord> {
        self.get(hash).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(&hash.0),
        })
    }

    /// Mark a block as finalized.
    pub fn mark_finalized(&mut self, hash: &BlockHash) -> StorageResult<()> {
        let record = self.records.get_mut(&hash.0)
            .ok_or_else(|| StorageError::NotFound { key: hex::encode(&hash.0) })?;
        record.is_finalized = true;
        Ok(())
    }

    /// Number of stored blocks.
    pub fn count(&self) -> usize { self.records.len() }
}

impl Default for BlockStore {
    fn default() -> Self { Self::new() }
}
