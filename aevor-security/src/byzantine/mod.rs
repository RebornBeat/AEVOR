//! Extended Byzantine behavior analysis.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::ValidatorId;
use aevor_core::consensus::ConsensusTimestamp;
pub use aevor_core::consensus::ByzantineFaultProof as ExtendedByzantineEvidence;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ByzantinePattern {
    pub pattern_type: String,
    pub validators_involved: Vec<ValidatorId>,
    pub first_observed: ConsensusTimestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ByzantineReport {
    pub patterns: Vec<ByzantinePattern>,
    pub is_coordinated_attack: bool,
    pub affected_validators: Vec<ValidatorId>,
}

pub struct CoordinatedAttackDetector { window_rounds: u64 }
impl CoordinatedAttackDetector {
    pub fn new(window_rounds: u64) -> Self { Self { window_rounds } }
    pub fn is_coordinated(&self, faults: &[ExtendedByzantineEvidence]) -> bool {
        faults.len() >= 3
    }
}

pub struct ByzantineAnalyzer;
impl ByzantineAnalyzer {
    pub fn analyze(faults: &[ExtendedByzantineEvidence]) -> ByzantineReport {
        let validators: Vec<ValidatorId> = faults.iter().map(|f| f.offender).collect();
        ByzantineReport {
            patterns: Vec::new(),
            is_coordinated_attack: validators.len() >= 3,
            affected_validators: validators,
        }
    }
}
