//! Macro-DAG: concurrent block production without a single leader bottleneck.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHash, BlockHeight, ValidatorId};
use aevor_core::consensus::ConsensusTimestamp;
pub use aevor_core::block::MacroDagBlock;

/// The full Macro-DAG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MacroDag {
    pub blocks: Vec<MacroDagBlock>,
    pub height: BlockHeight,
    pub tips: Vec<BlockHash>,
}

impl MacroDag {
    pub fn tip_count(&self) -> usize { self.tips.len() }
    pub fn block_count(&self) -> usize { self.blocks.len() }
    pub fn is_canonical(&self) -> bool { self.tips.len() == 1 }
}

/// Parent references for a block in the Macro-DAG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockParents {
    pub block: BlockHash,
    pub parents: Vec<BlockHash>,
    pub height: BlockHeight,
}

/// Set of validators producing blocks concurrently in the same round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConcurrentProducers {
    pub round: u64,
    pub producers: Vec<ValidatorId>,
    pub blocks: Vec<BlockHash>,
}

/// Builds a Macro-DAG from incoming blocks.
pub struct MacroDagBuilder {
    blocks: Vec<MacroDagBlock>,
}

impl MacroDagBuilder {
    pub fn new() -> Self { Self { blocks: Vec::new() } }

    pub fn add_block(&mut self, block: MacroDagBlock) {
        self.blocks.push(block);
    }

    pub fn build(self) -> MacroDag {
        let tips = self.compute_tips();
        let height = self.blocks.iter()
            .map(|b| b.header.height)
            .max()
            .unwrap_or(aevor_core::primitives::BlockHeight::GENESIS);
        MacroDag { height, tips, blocks: self.blocks }
    }

    fn compute_tips(&self) -> Vec<BlockHash> {
        let referenced: std::collections::HashSet<BlockHash> = self.blocks.iter()
            .flat_map(|b| b.dag_parents.iter().copied())
            .collect();
        self.blocks.iter()
            .filter(|b| !referenced.contains(&b.header.hash))
            .map(|b| b.header.hash)
            .collect()
    }
}

impl Default for MacroDagBuilder {
    fn default() -> Self { Self::new() }
}

/// Resolves competing fork branches in the DAG.
pub struct ForkResolution;

impl ForkResolution {
    pub fn resolve(tips: &[BlockHash]) -> Option<BlockHash> {
        // Deterministic: pick the lexicographically smallest hash.
        tips.iter().min_by_key(|h| h.0).copied()
    }
}

/// Total ordering of blocks from the DAG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockOrdering {
    /// Blocks in causal order.
    pub ordered_blocks: Vec<BlockHash>,
    /// Whether this ordering is the canonical (single-tip) ordering.
    pub is_canonical: bool,
}

/// A snapshot of the Macro-DAG at a specific consensus timestamp.
///
/// Used by finality gadgets to anchor the DAG state at a given point in time
/// and verify that no conflicting forks exist before the snapshot timestamp.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagSnapshot {
    /// The consensus timestamp at which this snapshot was taken.
    pub timestamp: ConsensusTimestamp,
    /// DAG tips at snapshot time.
    pub tips: Vec<BlockHash>,
    /// Total number of blocks in the DAG at snapshot time.
    pub block_count: usize,
}

impl DagSnapshot {
    /// Create a snapshot from the current DAG state.
    pub fn from_dag(dag: &MacroDag, timestamp: ConsensusTimestamp) -> Self {
        Self { timestamp, tips: dag.tips.clone(), block_count: dag.block_count() }
    }

    /// Returns `true` if the DAG was canonical (single tip) at snapshot time.
    pub fn was_canonical(&self) -> bool { self.tips.len() == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{BlockHash, Hash256};

    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }

    #[test]
    fn empty_builder_produces_empty_dag() {
        let dag = MacroDagBuilder::new().build();
        assert_eq!(dag.block_count(), 0);
        assert_eq!(dag.tip_count(), 0);
        assert!(!dag.is_canonical());
    }

    #[test]
    fn fork_resolution_picks_lexicographically_smallest() {
        let tips = vec![bh(5), bh(1), bh(3)];
        let resolved = ForkResolution::resolve(&tips).unwrap();
        assert_eq!(resolved, bh(1));
    }

    #[test]
    fn fork_resolution_empty_returns_none() {
        assert!(ForkResolution::resolve(&[]).is_none());
    }

    #[test]
    fn macro_dag_single_tip_is_canonical() {
        let dag = MacroDag {
            blocks: vec![],
            height: aevor_core::primitives::BlockHeight(0),
            tips: vec![bh(1)],
        };
        assert!(dag.is_canonical());
    }

    #[test]
    fn macro_dag_multiple_tips_not_canonical() {
        let dag = MacroDag {
            blocks: vec![],
            height: aevor_core::primitives::BlockHeight(0),
            tips: vec![bh(1), bh(2)],
        };
        assert!(!dag.is_canonical());
        assert_eq!(dag.tip_count(), 2);
    }

    #[test]
    fn dag_snapshot_canonical_with_one_tip() {
        let dag = MacroDag {
            blocks: vec![],
            height: aevor_core::primitives::BlockHeight(1),
            tips: vec![bh(7)],
        };
        let snap = DagSnapshot::from_dag(&dag, aevor_core::consensus::ConsensusTimestamp::new(1, 0, 1));
        assert!(snap.was_canonical());
        assert_eq!(snap.block_count, 0);
    }
}
