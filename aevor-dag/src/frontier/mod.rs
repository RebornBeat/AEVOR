//! DAG-level uncorrupted frontier tracking.

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

pub struct FrontierCorruptionDetector;

impl FrontierCorruptionDetector {
    pub fn check(frontier: &UncorruptedFrontier) -> bool {
        !frontier.frontier_blocks.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierState {
    pub frontier: UncorruptedFrontier,
    pub last_advanced_height: BlockHeight,
}
