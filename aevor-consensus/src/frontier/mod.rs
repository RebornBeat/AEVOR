//! Uncorrupted frontier management and verification.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::consensus::SecurityLevel;
use aevor_core::storage::StateRoot;

pub use aevor_core::state::UncorruptedFrontier;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierBlock {
    pub hash: aevor_core::primitives::BlockHash,
    pub height: aevor_core::primitives::BlockHeight,
    pub attestation_weight: aevor_core::primitives::ValidatorWeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierAdvancement {
    pub from_height: aevor_core::primitives::BlockHeight,
    pub to_height: aevor_core::primitives::BlockHeight,
    pub new_frontier: UncorruptedFrontier,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierProof {
    pub frontier_hash: Hash256,
    pub state_root: StateRoot,
    pub attestations: Vec<aevor_core::consensus::FinalityProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierCorruption {
    pub detected_at_height: aevor_core::primitives::BlockHeight,
    pub description: String,
    pub evidence: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierState {
    pub frontier: UncorruptedFrontier,
    pub corruption_detected: bool,
    pub last_clean_height: aevor_core::primitives::BlockHeight,
}

pub struct UncorruptedFrontierVerifier;

impl UncorruptedFrontierVerifier {
    pub fn verify(frontier: &UncorruptedFrontier, required_level: SecurityLevel) -> bool {
        frontier.meets_security_level(required_level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{BlockHash, BlockHeight, Hash256, ValidatorWeight};
    use aevor_core::consensus::{ConsensusTimestamp, SecurityLevel};
    use aevor_core::state::UncorruptedFrontier;
    use aevor_core::storage::MerkleRoot;

    fn frontier(level: SecurityLevel, blocks: usize) -> UncorruptedFrontier {
        UncorruptedFrontier {
            frontier_blocks: (0..blocks).map(|i| Hash256([i as u8; 32])).collect(),
            security_level: level,
            frontier_root: MerkleRoot::EMPTY,
            frontier_timestamp: ConsensusTimestamp::new(1, 0, 1),
            attestation_weight: ValidatorWeight::from_u64(100),
        }
    }

    #[test]
    fn verifier_accepts_matching_security_level() {
        let f = frontier(SecurityLevel::Strong, 2);
        assert!(UncorruptedFrontierVerifier::verify(&f, SecurityLevel::Strong));
    }

    #[test]
    fn verifier_accepts_higher_than_required() {
        // Full > Strong > Basic > Minimal
        let f = frontier(SecurityLevel::Full, 2);
        assert!(UncorruptedFrontierVerifier::verify(&f, SecurityLevel::Basic));
    }

    #[test]
    fn verifier_rejects_lower_than_required() {
        let f = frontier(SecurityLevel::Basic, 2);
        assert!(!UncorruptedFrontierVerifier::verify(&f, SecurityLevel::Strong));
    }

    #[test]
    fn frontier_block_stores_fields() {
        let fb = FrontierBlock {
            hash: Hash256([1u8; 32]),
            height: BlockHeight(500),
            attestation_weight: ValidatorWeight::from_u64(75),
        };
        assert_eq!(fb.height.0, 500);
        assert_eq!(fb.attestation_weight.as_u64(), 75);
    }

    #[test]
    fn frontier_state_no_corruption_initially() {
        let fs = FrontierState {
            frontier: frontier(SecurityLevel::Basic, 1),
            corruption_detected: false,
            last_clean_height: BlockHeight(100),
        };
        assert!(!fs.corruption_detected);
        assert_eq!(fs.last_clean_height.0, 100);
    }

    #[test]
    fn frontier_corruption_stores_description() {
        let fc = FrontierCorruption {
            detected_at_height: BlockHeight(999),
            description: "double-sign detected".into(),
            evidence: vec![0xDE, 0xAD],
        };
        assert_eq!(fc.detected_at_height.0, 999);
        assert_eq!(fc.description, "double-sign detected");
    }
}
