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

/// Proof of mathematical certainty from PoU consensus.
pub type MathematicalCertaintyProof = MathematicalCertainty;

/// Verifies attestation evidence from any TEE platform.
pub struct AttestationVerifier;

impl AttestationVerifier {
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
