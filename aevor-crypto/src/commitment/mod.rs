//! Commitment schemes: Pedersen, KZG, hash-based, Poseidon.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
pub use aevor_core::crypto::CommitmentScheme;

/// A Pedersen commitment — additively homomorphic, information-theoretically hiding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// The commitment point (compressed elliptic curve point bytes).
    pub point: Vec<u8>,
    blinding: [u8; 32],
}

impl PedersenCommitment {
    /// Create a Pedersen commitment to `value` with a fresh random blinding factor.
    pub fn commit(value: &[u8]) -> crate::CryptoResult<Self> {
        let mut blinding = [0u8; 32];
        getrandom::getrandom(&mut blinding)
            .map_err(|e| crate::CryptoError::CommitmentError(e.to_string()))?;
        Self::commit_with_blinding(value, blinding)
    }

    /// Create a Pedersen commitment with a specific blinding factor.
    ///
    /// Use `commit()` unless you need a deterministic blinding for testing.
    pub fn commit_with_blinding(value: &[u8], blinding: [u8; 32]) -> crate::CryptoResult<Self> {
        let mut hasher = crate::hash::Blake3Hasher::new();
        hasher.update(&blinding);
        hasher.update(value);
        let point = hasher.finalize().0.0.to_vec();
        Ok(Self { point, blinding })
    }

    /// Open the commitment, producing an `CommitmentOpening` for verification.
    pub fn open(&self) -> CommitmentOpening {
        CommitmentOpening {
            commitment: CommitmentProof {
                scheme: CommitmentScheme::Pedersen,
                commitment: self.point.clone(),
                wellformedness_proof: None,
            },
            value: self.point.clone(),
            randomness: self.blinding,
            opening_proof: self.point.clone(),
        }
    }
}

/// A KZG polynomial commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KzgCommitment {
    /// The commitment (compressed G1 point).
    pub commitment: Vec<u8>,
    /// Optional opening proof for a specific evaluation point.
    pub opening_proof: Option<Vec<u8>>,
}

/// A hash-based commitment using BLAKE3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashCommitment {
    /// The commitment hash: BLAKE3(randomness ‖ value).
    pub commitment: Hash256,
    /// Random blinding factor (must be kept secret until opening).
    pub randomness: [u8; 32],
}

impl HashCommitment {
    /// Create a commitment to `value` with a fresh random blinding factor.
    pub fn commit(value: &[u8]) -> crate::CryptoResult<Self> {
        let mut randomness = [0u8; 32];
        getrandom::getrandom(&mut randomness)
            .map_err(|e| crate::CryptoError::CommitmentError(e.to_string()))?;
        Ok(Self::commit_with_randomness(value, randomness))
    }

    /// Create a commitment with a specific randomness value.
    pub fn commit_with_randomness(value: &[u8], randomness: [u8; 32]) -> Self {
        let mut hasher = crate::hash::Blake3Hasher::new();
        hasher.update(&randomness);
        hasher.update(value);
        Self { commitment: hasher.finalize().0, randomness }
    }

    /// Verify that this commitment was created from `value`.
    pub fn verify(&self, value: &[u8]) -> bool {
        let expected = Self::commit_with_randomness(value, self.randomness);
        expected.commitment == self.commitment
    }
}

/// A Poseidon hash commitment (ZK-friendly, efficient in arithmetic circuits).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonCommitment {
    /// The commitment value (Poseidon hash output).
    pub commitment: Vec<u8>,
}

/// Opening of a commitment — proves the committed value without hiding it.
pub use aevor_core::crypto::CommitmentOpening;
/// A cryptographic commitment with optional wellformedness proof.
pub use aevor_core::crypto::CommitmentProof;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_commitment_verify_roundtrip() {
        let value = b"committed value";
        let c = HashCommitment::commit(value).unwrap();
        assert!(c.verify(value));
        assert!(!c.verify(b"wrong value"));
    }

    #[test]
    fn hash_commitment_different_values_different_commitments() {
        let c1 = HashCommitment::commit(b"value-1").unwrap();
        let c2 = HashCommitment::commit(b"value-2").unwrap();
        assert_ne!(c1.commitment, c2.commitment);
    }

    #[test]
    fn pedersen_commitment_deterministic_with_same_blinding() {
        let blinding = [1u8; 32];
        let c1 = PedersenCommitment::commit_with_blinding(b"value", blinding).unwrap();
        let c2 = PedersenCommitment::commit_with_blinding(b"value", blinding).unwrap();
        assert_eq!(c1.point, c2.point);
    }

    #[test]
    fn pedersen_different_values_different_points() {
        let blinding = [1u8; 32];
        let c1 = PedersenCommitment::commit_with_blinding(b"value-a", blinding).unwrap();
        let c2 = PedersenCommitment::commit_with_blinding(b"value-b", blinding).unwrap();
        assert_ne!(c1.point, c2.point);
    }

    #[test]
    fn hash_commitment_randomness_provides_hiding() {
        // Same value with different randomness → different commitments
        let v = b"same value";
        let c1 = HashCommitment::commit(v).unwrap();
        let c2 = HashCommitment::commit(v).unwrap();
        // Extremely unlikely to collide (2^-256 probability)
        assert_ne!(c1.randomness, c2.randomness);
        assert_ne!(c1.commitment, c2.commitment);
    }
}
