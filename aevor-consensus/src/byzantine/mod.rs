//! Byzantine fault detection and isolation.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{ByzantineFaultProof, ByzantineFaultType};
use aevor_core::primitives::ValidatorId;

pub type ByzantineEvidence = ByzantineFaultProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MisbehaviorType {
    DoubleSign,
    InvalidAttestation,
    Equivocation,
    ExtendedDowntime,
    CoordinatedAttack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorruptionProof {
    pub offender: ValidatorId,
    pub misbehavior: MisbehaviorType,
    pub evidence: Vec<u8>,
    pub proof_hash: aevor_core::primitives::Hash256,
}

pub struct ByzantineDetector {
    threshold_fraction: f64,
}

impl ByzantineDetector {
    pub fn new(threshold_fraction: f64) -> Self {
        Self { threshold_fraction }
    }

    pub fn is_byzantine(&self, participation: f64) -> bool {
        participation < (1.0 - self.threshold_fraction)
    }
}

pub struct ByzantineIsolation {
    isolated: Vec<ValidatorId>,
}

impl ByzantineIsolation {
    pub fn new() -> Self { Self { isolated: Vec::new() } }

    pub fn isolate(&mut self, validator: ValidatorId) {
        if !self.isolated.contains(&validator) {
            self.isolated.push(validator);
        }
    }

    pub fn is_isolated(&self, validator: &ValidatorId) -> bool {
        self.isolated.contains(validator)
    }
}

impl Default for ByzantineIsolation {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ValidatorId};

    fn vid(n: u8) -> ValidatorId { Hash256([n; 32]) }

    #[test]
    fn byzantine_detector_flags_low_participation() {
        // threshold 1/3 → participation < 2/3 is byzantine
        let det = ByzantineDetector::new(1.0 / 3.0);
        assert!(det.is_byzantine(0.5));  // 50% < 66.7%
        assert!(!det.is_byzantine(0.7)); // 70% ≥ 66.7%
    }

    #[test]
    fn byzantine_detector_boundary() {
        let det = ByzantineDetector::new(0.33);
        // Exactly at boundary 1.0 - 0.33 = 0.67
        assert!(!det.is_byzantine(0.67));
        assert!(det.is_byzantine(0.66));
    }

    #[test]
    fn byzantine_isolation_starts_empty() {
        let iso = ByzantineIsolation::new();
        assert!(!iso.is_isolated(&vid(1)));
    }

    #[test]
    fn byzantine_isolation_isolate_and_check() {
        let mut iso = ByzantineIsolation::new();
        iso.isolate(vid(1));
        assert!(iso.is_isolated(&vid(1)));
        assert!(!iso.is_isolated(&vid(2)));
    }

    #[test]
    fn byzantine_isolation_idempotent() {
        let mut iso = ByzantineIsolation::new();
        iso.isolate(vid(1));
        iso.isolate(vid(1)); // same validator again
        assert_eq!(iso.isolated.len(), 1);
    }

    #[test]
    fn corruption_proof_stores_misbehavior() {
        let proof = CorruptionProof {
            offender: vid(5),
            misbehavior: MisbehaviorType::DoubleSign,
            evidence: vec![0xFF],
            proof_hash: Hash256::ZERO,
        };
        assert_eq!(proof.offender, vid(5));
        assert_eq!(proof.misbehavior, MisbehaviorType::DoubleSign);
    }

    #[test]
    fn misbehavior_variants_are_distinct() {
        assert_ne!(MisbehaviorType::DoubleSign, MisbehaviorType::Equivocation);
        assert_ne!(MisbehaviorType::InvalidAttestation, MisbehaviorType::ExtendedDowntime);
    }
}
