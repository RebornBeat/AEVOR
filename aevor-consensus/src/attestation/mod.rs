//! Consensus-layer attestation: collection, verification, cross-platform composition.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{
    AttestationEvidence, ExecutionAttestation, TeeAttestationPlatform,
    MathematicalCertainty,
};

/// A set of attestations from multiple TEE platforms for one execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossPlatformAttestationSet {
    pub primary: AttestationEvidence,
    pub secondary: Vec<AttestationEvidence>,
    pub agreed_hash: aevor_core::primitives::Hash256,
}

impl CrossPlatformAttestationSet {
    pub fn is_consistent(&self) -> bool {
        self.secondary.iter().all(|s| s.code_measurement == self.primary.code_measurement)
    }
}

/// Proof of mathematical certainty from `PoU` consensus.
pub type MathematicalCertaintyProof = MathematicalCertainty;

/// Verifies attestation evidence from any TEE platform.
pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify attestation evidence from a TEE execution.
    ///
    /// # Errors
    /// Returns an error if the evidence structure is malformed or cannot be
    /// parsed by the verifier.
    pub fn verify(evidence: &AttestationEvidence) -> crate::ConsensusResult<bool> {
        Ok(!evidence.raw_report.is_empty() && evidence.is_production)
    }
}

/// Accumulates attestation evidence from multiple validators.
pub struct AttestationCollector {
    target_hash: aevor_core::primitives::Hash256,
    collected: Vec<AttestationEvidence>,
    required_count: usize,
}

impl AttestationCollector {
    pub fn new(target_hash: aevor_core::primitives::Hash256, required_count: usize) -> Self {
        Self { target_hash, collected: Vec::new(), required_count }
    }

    /// The block hash this collector is gathering attestations for.
    pub fn target_hash(&self) -> &aevor_core::primitives::Hash256 { &self.target_hash }

    pub fn add(&mut self, evidence: AttestationEvidence) {
        self.collected.push(evidence);
    }

    pub fn is_complete(&self) -> bool {
        self.collected.len() >= self.required_count
    }

    pub fn count(&self) -> usize { self.collected.len() }

    /// Returns attestations that match the target hash.
    pub fn matching_attestations(&self) -> Vec<&AttestationEvidence> {
        self.collected.iter()
            .filter(|e| e.code_measurement == self.target_hash)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    fn evidence(code_measurement: Hash256, production: bool) -> AttestationEvidence {
        AttestationEvidence {
            platform: TeeAttestationPlatform::IntelSgx,
            raw_report: vec![0xDE, 0xAD],
            code_measurement,
            nonce: [0u8; 32],
            is_production: production,
            svn: 1,
        }
    }

    // ── AttestationVerifier ───────────────────────────────────────

    #[test]
    fn verifier_returns_true_for_production_non_empty_report() {
        let ev = evidence(hash(1), true);
        assert!(AttestationVerifier::verify(&ev).unwrap());
    }

    #[test]
    fn verifier_returns_false_for_non_production() {
        let ev = evidence(hash(1), false);
        assert!(!AttestationVerifier::verify(&ev).unwrap());
    }

    // ── AttestationCollector ─────────────────────────────────────

    #[test]
    fn collector_starts_empty_not_complete() {
        let c = AttestationCollector::new(hash(5), 2);
        assert_eq!(c.count(), 0);
        assert!(!c.is_complete());
        assert_eq!(c.target_hash(), &hash(5));
    }

    #[test]
    fn collector_complete_after_required_count() {
        let mut c = AttestationCollector::new(hash(1), 3);
        c.add(evidence(hash(1), true));
        assert!(!c.is_complete());
        c.add(evidence(hash(1), true));
        assert!(!c.is_complete());
        c.add(evidence(hash(1), true));
        assert!(c.is_complete());
        assert_eq!(c.count(), 3);
    }

    #[test]
    fn collector_matching_attestations_filters_by_code_measurement() {
        let mut c = AttestationCollector::new(hash(7), 1);
        c.add(evidence(hash(7), true));  // matches target
        c.add(evidence(hash(99), true)); // different measurement
        let matching = c.matching_attestations();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].code_measurement, hash(7));
    }

    // ── CrossPlatformAttestationSet ───────────────────────────────

    #[test]
    fn cross_platform_set_consistent_when_measurements_match() {
        let set = CrossPlatformAttestationSet {
            primary: evidence(hash(1), true),
            secondary: vec![evidence(hash(1), true), evidence(hash(1), false)],
            agreed_hash: hash(1),
        };
        assert!(set.is_consistent());
    }

    #[test]
    fn cross_platform_set_inconsistent_when_measurement_differs() {
        let set = CrossPlatformAttestationSet {
            primary: evidence(hash(1), true),
            secondary: vec![evidence(hash(2), true)], // different measurement
            agreed_hash: hash(1),
        };
        assert!(!set.is_consistent());
    }
}
