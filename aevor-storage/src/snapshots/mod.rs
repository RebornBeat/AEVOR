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
