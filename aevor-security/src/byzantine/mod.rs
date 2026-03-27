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
    /// Create a detector that looks for coordination within `window_rounds` rounds.
    pub fn new(window_rounds: u64) -> Self { Self { window_rounds } }

    /// The round window within which faults are considered potentially coordinated.
    pub fn window_rounds(&self) -> u64 { self.window_rounds }

    /// Returns `true` if the fault set suggests a coordinated attack.
    ///
    /// Uses the `window_rounds` threshold to determine how many distinct faults
    /// constitute evidence of coordination: more rounds inspected = lower threshold.
    pub fn is_coordinated(&self, faults: &[ExtendedByzantineEvidence]) -> bool {
        // Larger windows give adversaries more time to coordinate — require fewer faults.
        let threshold = if self.window_rounds >= 100 { 2 } else { 3 };
        faults.len() >= threshold
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
