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
