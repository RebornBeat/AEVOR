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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ValidatorId};
    use aevor_core::consensus::{ByzantineFaultProof, ByzantineFaultType, ConsensusTimestamp};

    fn vid(n: u8) -> ValidatorId { Hash256([n; 32]) }

    fn fault(n: u8) -> ExtendedByzantineEvidence {
        ByzantineFaultProof {
            offender: vid(n),
            fault_type: ByzantineFaultType::Equivocation,
            evidence_a: vec![n],
            evidence_b: None,
            timestamp: ConsensusTimestamp::new(1, 0, 1),
        }
    }

    #[test]
    fn coordinated_attack_detector_short_window_threshold_3() {
        let det = CoordinatedAttackDetector::new(50);
        assert!(!det.is_coordinated(&[fault(1), fault(2)])); // < 3
        assert!(det.is_coordinated(&[fault(1), fault(2), fault(3)])); // == 3
    }

    #[test]
    fn coordinated_attack_detector_long_window_threshold_2() {
        let det = CoordinatedAttackDetector::new(100);
        assert!(!det.is_coordinated(&[fault(1)])); // < 2
        assert!(det.is_coordinated(&[fault(1), fault(2)])); // == 2
    }

    #[test]
    fn byzantine_analyzer_three_faults_is_coordinated() {
        let faults = vec![fault(1), fault(2), fault(3)];
        let report = ByzantineAnalyzer::analyze(&faults);
        assert!(report.is_coordinated_attack);
        assert_eq!(report.affected_validators.len(), 3);
    }

    #[test]
    fn byzantine_analyzer_two_faults_not_coordinated() {
        let faults = vec![fault(1), fault(2)];
        let report = ByzantineAnalyzer::analyze(&faults);
        assert!(!report.is_coordinated_attack);
    }

    #[test]
    fn byzantine_pattern_stores_fields() {
        let p = ByzantinePattern {
            pattern_type: "double-sign-wave".into(),
            validators_involved: vec![vid(1), vid(2)],
            first_observed: ConsensusTimestamp::new(10, 0, 100),
        };
        assert_eq!(p.pattern_type, "double-sign-wave");
        assert_eq!(p.validators_involved.len(), 2);
    }
}
