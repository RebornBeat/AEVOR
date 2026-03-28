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
///
/// **Infrastructure vs Policy separation:** `verify` checks structural validity
/// only — non-empty report and a recognised platform. Whether `is_production`
/// is required is an **application-layer policy** enforced by the caller
/// (e.g. consensus config). Use `verify_with_policy` when production enforcement
/// is required.
pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify attestation evidence from a TEE execution (structural check only).
    ///
    /// Returns `true` if the evidence is structurally valid: non-empty raw
    /// report and a known platform. Production vs simulation enforcement is
    /// left to the caller via `verify_with_policy`.
    ///
    /// # Errors
    /// Returns an error if the evidence structure is malformed.
    pub fn verify(evidence: &AttestationEvidence) -> crate::ConsensusResult<bool> {
        Ok(!evidence.raw_report.is_empty())
    }

    /// Verify evidence and enforce the `require_production` policy.
    ///
    /// This is a convenience wrapper for consensus configurations that require
    /// production-mode attestations (e.g. mainnet). Devnet and testnet deployments
    /// should call `verify` and handle the production flag themselves.
    ///
    /// # Errors
    /// Returns an error if the underlying structural verification step fails
    /// (delegates to `verify`).
    pub fn verify_with_policy(
        evidence: &AttestationEvidence,
        require_production: bool,
    ) -> crate::ConsensusResult<bool> {
        let structurally_valid = Self::verify(evidence)?;
        if !structurally_valid { return Ok(false); }
        if require_production && !evidence.is_production { return Ok(false); }
        Ok(true)
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

    fn evidence_on(platform: TeeAttestationPlatform, code: Hash256, production: bool) -> AttestationEvidence {
        AttestationEvidence {
            platform,
            raw_report: vec![0xDE, 0xAD],
            code_measurement: code,
            nonce: [0u8; 32],
            is_production: production,
            svn: 1,
        }
    }

    fn evidence(code: Hash256, production: bool) -> AttestationEvidence {
        evidence_on(TeeAttestationPlatform::IntelSgx, code, production)
    }

    // ── Structural verification (infrastructure — no policy) ──────────────
    // verify() checks structure only; production/simulation is caller policy.

    #[test]
    fn verifier_accepts_structurally_valid_production_evidence() {
        let ev = evidence(hash(1), true);
        assert!(AttestationVerifier::verify(&ev).unwrap());
    }

    #[test]
    fn verifier_accepts_structurally_valid_non_production_evidence() {
        // Non-production is valid for devnet/testnet — policy not infra
        let ev = evidence(hash(1), false);
        assert!(AttestationVerifier::verify(&ev).unwrap());
    }

    #[test]
    fn verifier_rejects_empty_raw_report() {
        let mut ev = evidence(hash(1), true);
        ev.raw_report = vec![];
        assert!(!AttestationVerifier::verify(&ev).unwrap());
    }

    // ── All 5 platforms pass structural verification ──────────────────────

    #[test]
    fn all_five_platforms_structurally_valid() {
        for platform in [
            TeeAttestationPlatform::IntelSgx,
            TeeAttestationPlatform::AmdSev,
            TeeAttestationPlatform::ArmTrustZone,
            TeeAttestationPlatform::RiscvKeystone,
            TeeAttestationPlatform::AwsNitro,
        ] {
            let ev = evidence_on(platform, hash(1), false); // non-production — still valid
            assert!(
                AttestationVerifier::verify(&ev).unwrap(),
                "Platform {:?} should pass structural verification", platform
            );
        }
    }

    // ── Policy-layer verification ─────────────────────────────────────────

    #[test]
    fn verify_with_policy_accepts_production_when_required() {
        let ev = evidence(hash(1), true);
        assert!(AttestationVerifier::verify_with_policy(&ev, true).unwrap());
    }

    #[test]
    fn verify_with_policy_rejects_non_production_when_required() {
        let ev = evidence(hash(1), false);
        assert!(!AttestationVerifier::verify_with_policy(&ev, true).unwrap());
    }

    #[test]
    fn verify_with_policy_accepts_non_production_when_not_required() {
        // devnet/testnet config: require_production = false
        let ev = evidence(hash(1), false);
        assert!(AttestationVerifier::verify_with_policy(&ev, false).unwrap());
    }

    #[test]
    fn verify_with_policy_rejects_empty_report_regardless_of_policy() {
        let mut ev = evidence(hash(1), true);
        ev.raw_report = vec![];
        assert!(!AttestationVerifier::verify_with_policy(&ev, false).unwrap());
    }

    // ── AttestationCollector ──────────────────────────────────────────────

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

    // ── CrossPlatformAttestationSet ───────────────────────────────────────

    #[test]
    fn cross_platform_set_consistent_when_measurements_match() {
        let set = CrossPlatformAttestationSet {
            primary: evidence_on(TeeAttestationPlatform::IntelSgx, hash(1), true),
            secondary: vec![
                evidence_on(TeeAttestationPlatform::AmdSev, hash(1), true),
                evidence_on(TeeAttestationPlatform::ArmTrustZone, hash(1), false),
            ],
            agreed_hash: hash(1),
        };
        assert!(set.is_consistent());
    }

    #[test]
    fn cross_platform_set_inconsistent_when_measurement_differs() {
        let set = CrossPlatformAttestationSet {
            primary: evidence_on(TeeAttestationPlatform::IntelSgx, hash(1), true),
            secondary: vec![evidence_on(TeeAttestationPlatform::AwsNitro, hash(2), true)],
            agreed_hash: hash(1),
        };
        assert!(!set.is_consistent());
    }
}
