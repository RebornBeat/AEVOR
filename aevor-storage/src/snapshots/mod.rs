//! State snapshots for fast sync and checkpointing.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHeight, EpochNumber, Hash256};
use aevor_core::storage::StateRoot;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub id: Hash256,
    pub height: BlockHeight,
    pub epoch: EpochNumber,
    pub state_root: StateRoot,
    pub size_bytes: u64,
    pub created_at_round: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub metadata: SnapshotMetadata,
    pub objects: Vec<crate::objects::ObjectRecord>,
}

impl StateSnapshot {
    pub fn object_count(&self) -> usize { self.objects.len() }
}

pub type CheckpointSnapshot = StateSnapshot;

pub struct SnapshotCreator {
    target_height: BlockHeight,
}

impl SnapshotCreator {
    pub fn new(target_height: BlockHeight) -> Self { Self { target_height } }
    pub fn target_height(&self) -> BlockHeight { self.target_height }
}

pub struct SnapshotLoader {
    snapshots: Vec<SnapshotMetadata>,
}

impl SnapshotLoader {
    pub fn new() -> Self { Self { snapshots: Vec::new() } }

    pub fn register(&mut self, meta: SnapshotMetadata) { self.snapshots.push(meta); }

    pub fn latest(&self) -> Option<&SnapshotMetadata> {
        self.snapshots.iter().max_by_key(|s| s.height.as_u64())
    }
}

impl Default for SnapshotLoader {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{BlockHeight, EpochNumber, Hash256};
    use aevor_core::storage::MerkleRoot;

    fn meta(height: u64) -> SnapshotMetadata {
        SnapshotMetadata {
            id: Hash256([height as u8; 32]),
            height: BlockHeight(height),
            epoch: EpochNumber(height / 1000),
            state_root: MerkleRoot::EMPTY,
            size_bytes: 1024 * 1024,
            created_at_round: height * 2,
        }
    }

    #[test]
    fn snapshot_creator_stores_target_height() {
        let c = SnapshotCreator::new(BlockHeight(500));
        assert_eq!(c.target_height(), BlockHeight(500));
    }

    #[test]
    fn snapshot_loader_empty_latest_is_none() {
        let loader = SnapshotLoader::default();
        assert!(loader.latest().is_none());
    }

    #[test]
    fn snapshot_loader_latest_returns_highest_height() {
        let mut loader = SnapshotLoader::new();
        loader.register(meta(100));
        loader.register(meta(500));
        loader.register(meta(300));
        let latest = loader.latest().unwrap();
        assert_eq!(latest.height, BlockHeight(500));
    }

    #[test]
    fn snapshot_loader_single_entry_is_latest() {
        let mut loader = SnapshotLoader::new();
        loader.register(meta(42));
        assert_eq!(loader.latest().unwrap().height, BlockHeight(42));
    }

    #[test]
    fn snapshot_metadata_fields() {
        let m = meta(1000);
        assert_eq!(m.height.as_u64(), 1000);
        assert_eq!(m.size_bytes, 1024 * 1024);
        assert_eq!(m.created_at_round, 2000);
    }
}
