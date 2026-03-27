//! Response verification: Merkle proofs and attestation checks.

use serde::{Deserialize, Serialize};
use aevor_core::storage::MerkleProof;
use crate::ClientResult;

/// A response that has been (or needs to be) cryptographically verified.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedResponse<T: Serialize + Clone> {
    /// The response payload.
    pub data: T,
    /// Merkle proof linking this data to a trusted state root (if available).
    pub proof: Option<MerkleProof>,
    /// Whether `proof` was checked and passed.
    pub verified: bool,
}

impl<T: Serialize + Clone> VerifiedResponse<T> {
    /// Wrap data that has already been verified.
    pub fn verified(data: T, proof: MerkleProof) -> Self {
        Self { data, proof: Some(proof), verified: true }
    }

    /// Wrap data without proof (trusted endpoint, e.g. local node).
    pub fn trusted(data: T) -> Self {
        Self { data, proof: None, verified: false }
    }

    /// Returns `true` if the response is backed by a valid Merkle proof.
    pub fn is_verified(&self) -> bool { self.verified }
}

/// Verifies Merkle proofs against a trusted state root.
pub struct MerkleVerifier;

impl MerkleVerifier {
    /// Verify a Merkle proof.
    ///
    /// Returns `true` if the proof is structurally valid.
    /// Full root-based verification requires `verify_against`.
    pub fn verify(proof: &MerkleProof) -> bool { proof.verify() }

    /// Verify a Merkle proof against a specific state root and leaf value.
    pub fn verify_against(proof: &MerkleProof, root: &aevor_core::primitives::Hash256, leaf: &[u8]) -> bool {
        proof.verify_against(root, leaf)
    }
}

/// Verifies TEE attestation reports in API responses.
pub struct AttestationVerifier;

/// Type alias exported in the prelude.
pub type ClientAttestationVerifier = AttestationVerifier;

impl AttestationVerifier {
    /// Verify that an attestation report is genuine.
    ///
    /// Delegates to `aevor-tee` for platform-specific verification.
    pub fn verify(attestation: &aevor_core::consensus::ExecutionAttestation) -> bool {
        // Full implementation: call aevor_tee::attestation::verify_report()
        // For now: structural check only
        !attestation.evidence.raw_report.is_empty() && !attestation.input_hash.is_zero()
    }
}

/// Verifies complete API responses including optional Merkle proofs.
pub struct ResponseVerifier;

impl ResponseVerifier {
    /// Verify a response that includes an optional Merkle proof.
    ///
    /// If `root` is provided and a proof exists, full Merkle verification
    /// is performed. Otherwise the response is returned as unverified.
    ///
    /// # Errors
    /// Returns an error if the data cannot be serialized for leaf hash computation.
    pub fn verify<T: Serialize + Clone + serde::de::DeserializeOwned>(
        data: T,
        proof: Option<MerkleProof>,
        root: Option<&aevor_core::primitives::Hash256>,
    ) -> ClientResult<VerifiedResponse<T>> {
        match (proof, root) {
            (Some(p), Some(r)) => {
                let leaf_bytes = bincode::serialize(&data)
                    .map_err(|e| crate::ClientError::InvalidResponse { reason: e.to_string() })?;
                let verified = p.verify_against(r, &leaf_bytes);
                Ok(VerifiedResponse { data, proof: Some(p), verified })
            }
            (Some(p), None) => {
                Ok(VerifiedResponse { data, proof: Some(p), verified: false })
            }
            _ => Ok(VerifiedResponse::trusted(data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, Signature};
    use aevor_core::storage::{MerkleProof, MerkleRoot, StorageKey, StorageValue};
    use aevor_core::consensus::{
        AttestationEvidence, ExecutionAttestation, TeeAttestationPlatform,
    };

    fn empty_proof() -> MerkleProof {
        MerkleProof {
            key: StorageKey(vec![1]),
            value: StorageValue(vec![]),
            siblings: vec![],
            root: MerkleRoot::EMPTY,
            is_inclusion: false,
        }
    }

    fn make_attestation(empty_report: bool) -> ExecutionAttestation {
        ExecutionAttestation {
            evidence: AttestationEvidence {
                platform: TeeAttestationPlatform::IntelSgx,
                raw_report: if empty_report { vec![] } else { vec![0xDE, 0xAD] },
                code_measurement: Hash256::ZERO,
                nonce: [0u8; 32],
                is_production: false,
                svn: 0,
            },
            input_hash: if empty_report { Hash256::ZERO } else { Hash256([1u8; 32]) },
            output_hash: Hash256::ZERO,
            transaction_hash: Hash256::ZERO,
            validator_id: Hash256::ZERO,
            validator_signature: Signature([0u8; 64]),
        }
    }

    #[test]
    fn verified_response_is_verified() {
        let resp = VerifiedResponse::verified(42u32, empty_proof());
        assert!(resp.is_verified());
        assert!(resp.proof.is_some());
        assert_eq!(resp.data, 42u32);
    }

    #[test]
    fn trusted_response_is_not_verified() {
        let resp = VerifiedResponse::trusted("hello");
        assert!(!resp.is_verified());
        assert!(resp.proof.is_none());
    }

    #[test]
    fn merkle_verifier_empty_siblings_returns_false() {
        // An empty siblings list always fails structural verification
        let proof = empty_proof();
        assert!(!MerkleVerifier::verify(&proof));
    }

    #[test]
    fn attestation_verifier_empty_report_returns_false() {
        let att = make_attestation(true);
        assert!(!AttestationVerifier::verify(&att));
    }

    #[test]
    fn attestation_verifier_non_empty_report_with_non_zero_input_hash() {
        let att = make_attestation(false);
        assert!(AttestationVerifier::verify(&att));
    }

    #[test]
    fn response_verifier_no_proof_returns_trusted() {
        let resp = ResponseVerifier::verify(99u32, None, None).unwrap();
        assert!(!resp.is_verified());
        assert!(resp.proof.is_none());
        assert_eq!(resp.data, 99u32);
    }

    #[test]
    fn response_verifier_proof_no_root_returns_unverified() {
        let resp = ResponseVerifier::verify(42u32, Some(empty_proof()), None).unwrap();
        assert!(!resp.is_verified());
        assert!(resp.proof.is_some());
    }
}
