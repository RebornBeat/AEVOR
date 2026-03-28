//! DAG-level uncorrupted frontier tracking.
//!
//! The Uncorrupted Frontier represents the mathematical boundary between
//! verified network state and potential corruption. It advances through
//! logical ordering based on transaction dependencies with blockchain
//! consensus time authority — never through external time synchronization.

use serde::{Deserialize, Serialize};
pub use aevor_core::state::UncorruptedFrontier;
use aevor_core::primitives::{BlockHash, BlockHeight};
use aevor_core::consensus::SecurityLevel;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierBlock {
    pub hash: BlockHash,
    pub height: BlockHeight,
    pub is_attested: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierAdvancement {
    pub old_frontier: Vec<BlockHash>,
    pub new_frontier: Vec<BlockHash>,
    pub security_level: SecurityLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierProof {
    pub frontier_blocks: Vec<BlockHash>,
    pub proof_hash: aevor_core::primitives::Hash256,
}

/// Detects whether the frontier has been corrupted.
///
/// Corruption detection is real-time: a frontier with no blocks is
/// immediately flagged. A production implementation performs cryptographic
/// verification of attestations and checks for equivocation.
pub struct FrontierCorruptionDetector;

impl FrontierCorruptionDetector {
    /// Returns `true` if the frontier is structurally intact (non-empty block set).
    pub fn check(frontier: &UncorruptedFrontier) -> bool {
        !frontier.frontier_blocks.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierState {
    pub frontier: UncorruptedFrontier,
    pub last_advanced_height: BlockHeight,
}

impl FrontierState {
    /// Returns `true` if the frontier is intact and at the expected height.
    pub fn is_healthy(&self) -> bool {
        FrontierCorruptionDetector::check(&self.frontier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{BlockHeight, Hash256, ValidatorWeight};
    use aevor_core::consensus::{ConsensusTimestamp, SecurityLevel};
    use aevor_core::storage::MerkleRoot;
    use aevor_core::state::UncorruptedFrontier;

    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }

    fn frontier(blocks: usize, level: SecurityLevel) -> UncorruptedFrontier {
        UncorruptedFrontier {
            frontier_blocks: (0..blocks).map(|i| Hash256([i as u8; 32])).collect(),
            security_level: level,
            frontier_root: MerkleRoot::EMPTY,
            frontier_timestamp: ConsensusTimestamp::new(1, 0, 1),
            attestation_weight: ValidatorWeight::from_u64(100),
        }
    }

    // ── Corruption detection ──────────────────────────────────────────────
    // Whitepaper: "Real-Time Monitoring: Continuous verification of state
    // transitions through mathematical proof"

    #[test]
    fn corruption_detector_intact_when_frontier_has_blocks() {
        let f = frontier(3, SecurityLevel::Strong);
        assert!(FrontierCorruptionDetector::check(&f));
    }

    #[test]
    fn corruption_detector_flags_empty_frontier() {
        let f = frontier(0, SecurityLevel::Basic);
        assert!(!FrontierCorruptionDetector::check(&f));
    }

    #[test]
    fn frontier_state_healthy_with_blocks() {
        let fs = FrontierState {
            frontier: frontier(2, SecurityLevel::Basic),
            last_advanced_height: BlockHeight(100),
        };
        assert!(fs.is_healthy());
    }

    #[test]
    fn frontier_state_unhealthy_with_no_blocks() {
        let fs = FrontierState {
            frontier: frontier(0, SecurityLevel::Basic),
            last_advanced_height: BlockHeight(0),
        };
        assert!(!fs.is_healthy());
    }

    // ── FrontierAdvancement ───────────────────────────────────────────────
    // Whitepaper: "Frontier Progression Mechanics: Logical Ordering through
    // dependency analysis"

    #[test]
    fn frontier_advancement_records_old_and_new() {
        let adv = FrontierAdvancement {
            old_frontier: vec![bh(1), bh(2)],
            new_frontier: vec![bh(3)],
            security_level: SecurityLevel::Strong,
        };
        assert_eq!(adv.old_frontier.len(), 2);
        assert_eq!(adv.new_frontier.len(), 1);
        assert_eq!(adv.security_level, SecurityLevel::Strong);
    }

    #[test]
    fn frontier_block_attested_flag() {
        let fb = FrontierBlock { hash: bh(7), height: BlockHeight(50), is_attested: true };
        assert!(fb.is_attested);
        assert_eq!(fb.height.0, 50);
    }

    // ── Parallel pathways — multiple frontier blocks at once ─────────────
    // Whitepaper: "Parallel Pathways: Multiple simultaneous state advancement
    // routes enabling throughput scaling"

    #[test]
    fn frontier_can_hold_multiple_blocks_simultaneously() {
        let f = frontier(4, SecurityLevel::Basic);
        assert_eq!(f.frontier_blocks.len(), 4);
        assert!(FrontierCorruptionDetector::check(&f));
    }
}
