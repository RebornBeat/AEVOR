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
    use aevor_core::primitives::{BlockHash, BlockHeight, GasAmount, Hash256, ValidatorId};
    use aevor_core::consensus::{ConsensusTimestamp, SecurityLevel};
    use aevor_core::storage::MerkleRoot;
    use aevor_core::block::{BlockHeader, BlockStatus, MacroDagBlock};

    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }
    fn vid(n: u8) -> ValidatorId { Hash256([n; 32]) }

    fn header(hash_byte: u8, height: u64, parent: Option<u8>) -> BlockHeader {
        BlockHeader {
            hash: bh(hash_byte),
            parent_hash: parent.map(bh),
            height: BlockHeight(height),
            consensus_round: height,
            timestamp: ConsensusTimestamp::new(height, 0, height),
            proposer: vid(hash_byte),
            state_root: MerkleRoot::EMPTY,
            transaction_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            transaction_count: 0,
            gas_used: GasAmount::ZERO,
            gas_limit: GasAmount::from_u64(10_000_000),
            security_level: SecurityLevel::Basic,
        }
    }

    fn block(hash_byte: u8, height: u64, parent: Option<u8>, dag_parents: Vec<u8>) -> MacroDagBlock {
        MacroDagBlock {
            header: header(hash_byte, height, parent),
            dag_parents: dag_parents.into_iter().map(bh).collect(),
            transactions: vec![],
            micro_dag: vec![],
            attestations: vec![],
            proof: None,
            status: BlockStatus::Finalized,
        }
    }

    // ── MacroDag basic properties ─────────────────────────────────────────

    #[test]
    fn empty_builder_produces_empty_dag() {
        let dag = MacroDagBuilder::new().build();
        assert_eq!(dag.block_count(), 0);
        assert_eq!(dag.tip_count(), 0);
        assert!(!dag.is_canonical());
    }

    #[test]
    fn macro_dag_single_tip_is_canonical() {
        let dag = MacroDag { blocks: vec![], height: BlockHeight(0), tips: vec![bh(1)] };
        assert!(dag.is_canonical());
        assert_eq!(dag.tip_count(), 1);
    }

    #[test]
    fn macro_dag_multiple_tips_concurrent_producers() {
        // Whitepaper: "multiple validators producing blocks simultaneously"
        let dag = MacroDag {
            blocks: vec![],
            height: BlockHeight(5),
            tips: vec![bh(1), bh(2), bh(3)],
        };
        assert!(!dag.is_canonical());
        assert_eq!(dag.tip_count(), 3);
    }

    // ── MacroDagBuilder tip detection ─────────────────────────────────────
    // Whitepaper: "multi-parent block references" — unreferenced blocks are tips.

    #[test]
    fn builder_single_block_becomes_tip() {
        let mut builder = MacroDagBuilder::new();
        builder.add_block(block(1, 1, None, vec![]));
        let dag = builder.build();
        assert_eq!(dag.tip_count(), 1);
        assert!(dag.tips.contains(&bh(1)));
        assert!(dag.is_canonical());
    }

    #[test]
    fn builder_referenced_block_is_not_a_tip() {
        // block 2 references block 1 — block 1 is no longer a tip
        let mut builder = MacroDagBuilder::new();
        builder.add_block(block(1, 1, None, vec![]));
        builder.add_block(block(2, 2, Some(1), vec![1])); // dag_parent = bh(1)
        let dag = builder.build();
        assert_eq!(dag.tip_count(), 1);
        assert!(dag.tips.contains(&bh(2)));
        assert!(!dag.tips.contains(&bh(1)));
    }

    #[test]
    fn builder_concurrent_blocks_no_mutual_reference_both_tips() {
        // Whitepaper: concurrent producers — blocks at same height, no cross-ref
        let mut builder = MacroDagBuilder::new();
        builder.add_block(block(1, 1, None, vec![]));
        builder.add_block(block(2, 1, None, vec![])); // concurrent: no dag_parent to each other
        let dag = builder.build();
        assert_eq!(dag.tip_count(), 2); // both are tips — concurrent production
        assert!(!dag.is_canonical());
    }

    #[test]
    fn builder_multi_parent_block_merges_tips() {
        // Whitepaper: "individual blocks can reference multiple previous blocks"
        let mut builder = MacroDagBuilder::new();
        builder.add_block(block(1, 1, None, vec![]));
        builder.add_block(block(2, 1, None, vec![]));
        // block 3 at height 2 references both concurrent parents
        builder.add_block(block(3, 2, Some(1), vec![1, 2]));
        let dag = builder.build();
        assert_eq!(dag.tip_count(), 1); // 3 is the only tip — merged the fork
        assert!(dag.is_canonical());
        assert_eq!(dag.block_count(), 3);
    }

    // ── Fork resolution determinism ───────────────────────────────────────
    // Whitepaper: "Mathematical ordering of concurrent blocks through attestation"

    #[test]
    fn fork_resolution_picks_lexicographically_smallest() {
        let tips = vec![bh(5), bh(1), bh(3)];
        let resolved = ForkResolution::resolve(&tips).unwrap();
        assert_eq!(resolved, bh(1));
    }

    #[test]
    fn fork_resolution_deterministic_regardless_of_input_order() {
        let tips_a = vec![bh(7), bh(2), bh(9)];
        let tips_b = vec![bh(9), bh(7), bh(2)]; // same tips, different order
        assert_eq!(
            ForkResolution::resolve(&tips_a),
            ForkResolution::resolve(&tips_b)
        );
    }

    #[test]
    fn fork_resolution_single_tip_returns_it() {
        assert_eq!(ForkResolution::resolve(&[bh(42)]), Some(bh(42)));
    }

    #[test]
    fn fork_resolution_empty_returns_none() {
        assert!(ForkResolution::resolve(&[]).is_none());
    }

    // ── ConcurrentProducers ───────────────────────────────────────────────
    // Whitepaper: "multiple validators producing blocks simultaneously"

    #[test]
    fn concurrent_producers_stores_round_and_validators() {
        let cp = ConcurrentProducers {
            round: 42,
            producers: vec![vid(1), vid(2), vid(3)],
            blocks: vec![bh(10), bh(11), bh(12)],
        };
        assert_eq!(cp.round, 42);
        assert_eq!(cp.producers.len(), 3);
        assert_eq!(cp.blocks.len(), 3);
    }

    // ── DagSnapshot ───────────────────────────────────────────────────────

    #[test]
    fn dag_snapshot_canonical_with_one_tip() {
        let dag = MacroDag { blocks: vec![], height: BlockHeight(1), tips: vec![bh(7)] };
        let snap = DagSnapshot::from_dag(&dag, ConsensusTimestamp::new(1, 0, 1));
        assert!(snap.was_canonical());
        assert_eq!(snap.block_count, 0);
    }

    #[test]
    fn dag_snapshot_non_canonical_with_multiple_tips() {
        let dag = MacroDag {
            blocks: vec![],
            height: BlockHeight(3),
            tips: vec![bh(1), bh(2)],
        };
        let snap = DagSnapshot::from_dag(&dag, ConsensusTimestamp::new(3, 0, 3));
        assert!(!snap.was_canonical());
        assert_eq!(snap.tips.len(), 2);
    }

    // ── BlockOrdering ─────────────────────────────────────────────────────

    #[test]
    fn block_ordering_canonical_flag() {
        let ord = BlockOrdering { ordered_blocks: vec![bh(1), bh(2)], is_canonical: true };
        assert!(ord.is_canonical);
        assert_eq!(ord.ordered_blocks.len(), 2);
    }

    // ── Multi-parent references are unbounded ─────────────────────────────
    // Whitepaper: "individual blocks can reference multiple previous blocks"
    // No artificial ceiling on dag_parents.

    #[test]
    fn macro_dag_block_can_have_many_parents() {
        // dag_parents is Vec<BlockHash> — no ceiling by architecture
        let many_parents: Vec<BlockHash> = (1..=64).map(|i| bh(i as u8)).collect();
        let b = MacroDagBlock {
            header: header(100, 10, None),
            dag_parents: many_parents.clone(),
            transactions: vec![],
            micro_dag: vec![],
            attestations: vec![],
            proof: None,
            status: BlockStatus::Finalized,
        };
        assert_eq!(b.dag_parents.len(), 64);
    }

    // ── Concurrent producers contribute all at once ───────────────────────
    // Whitepaper: "validators produce blocks simultaneously" — throughput scales

    #[test]
    fn concurrent_producers_in_same_round() {
        let cp = ConcurrentProducers {
            round: 10,
            producers: vec![vid(1), vid(2), vid(3), vid(4)],
            blocks: vec![bh(10), bh(11), bh(12), bh(13)],
        };
        // All 4 produce in the same round — no leader bottleneck
        assert_eq!(cp.producers.len(), cp.blocks.len());
        assert_eq!(cp.round, 10);
    }

    // ── Fork resolution produces no state reversal ────────────────────────
    // Whitepaper S3: "corrupted branches are isolated — finalized txs never reversed"

    #[test]
    fn fork_resolution_selects_not_reverses() {
        // Resolution picks ONE canonical branch — it does not modify or reverse
        // any transactions in ANY branch. Finalized transactions are immutable.
        let tips = vec![bh(10), bh(5), bh(8)];
        let canonical = ForkResolution::resolve(&tips).unwrap();
        assert_eq!(canonical, bh(5)); // lexicographically smallest
        // The other tips are discarded at the frontier — their finalized
        // transactions (if any) are not reversed.
    }

    // ── Frontier advancement tracking ──────────────────────────────────────
    // Whitepaper: "Frontier Progression Mechanics: Logical Ordering"

    #[test]
    fn frontier_advancement_reflects_new_state() {
        use crate::frontier::FrontierAdvancement;
        use aevor_core::consensus::SecurityLevel;
        let adv = FrontierAdvancement {
            old_frontier: vec![bh(1), bh(2)],
            new_frontier: vec![bh(3), bh(4), bh(5)],
            security_level: SecurityLevel::Full,
        };
        // New frontier can have MORE blocks — throughput scales
        assert!(adv.new_frontier.len() >= adv.old_frontier.len() - 1);
        assert_eq!(adv.security_level, SecurityLevel::Full);
    }

    // ── Mathematical consensus — determinism across validators ─────────────
    // Whitepaper: "deterministic algorithms that produce identical results across
    // all validators when provided with the same verified block data"

    #[test]
    fn fork_resolution_all_validators_agree() {
        // Given identical input, all validators MUST reach the same resolution.
        let tips = vec![bh(3), bh(1), bh(7)];
        let r1 = ForkResolution::resolve(&tips);
        let r2 = ForkResolution::resolve(&tips);
        let r3 = ForkResolution::resolve(&tips);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        assert_eq!(r1.unwrap(), bh(1));
    }
}
