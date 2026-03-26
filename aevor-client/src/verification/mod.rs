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
