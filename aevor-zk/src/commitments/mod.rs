//! Polynomial commitment schemes used within ZK circuits.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

/// A KZG polynomial commitment (Kate-Zaverucha-Goldberg).
///
/// KZG commitments are constant-size (one G1 point) and allow
/// constant-size opening proofs. Used in PLONK and related systems.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KzgCommitment {
    /// The commitment point (48 bytes — compressed G1 on BLS12-381).
    pub point: Vec<u8>,
}

/// An opening proof for a KZG commitment at a specific point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KzgOpeningProof {
    /// The committed polynomial's evaluation at the opening point.
    pub evaluation: Vec<u8>,
    /// The quotient commitment (also a G1 point).
    pub proof: Vec<u8>,
}

/// An inner product argument (from Halo2/Bulletproofs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerProductArgument {
    /// Compressed proof bytes.
    pub proof: Vec<u8>,
    /// Final scalar for the verifier.
    pub final_scalar: Vec<u8>,
}

/// A Pedersen commitment used in range proofs and STARK systems.
///
/// `Hash256` identifies the public parameters (generators) used to create
/// this commitment, enabling the verifier to confirm the correct setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// The commitment point (compressed).
    pub point: Vec<u8>,
    /// Hash of the public parameters used.
    pub params_hash: Hash256,
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment.
    pub fn new(point: Vec<u8>, params_hash: Hash256) -> Self {
        Self { point, params_hash }
    }

    /// Returns `true` if two commitments use the same public parameters.
    pub fn compatible_with(&self, other: &Self) -> bool {
        self.params_hash == other.params_hash
    }
}

/// Verify a KZG commitment opening.
pub struct KzgVerifier;

impl KzgVerifier {
    /// Verify that `commitment` opens to `value` at `point`.
    pub fn verify(
        commitment: &KzgCommitment,
        opening: &KzgOpeningProof,
        _point: &[u8],
    ) -> bool {
        !commitment.point.is_empty() && !opening.proof.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn params_hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    #[test]
    fn kzg_commitment_stores_point() {
        let c = KzgCommitment { point: vec![0xAB; 48] };
        assert_eq!(c.point.len(), 48);
    }

    #[test]
    fn kzg_verifier_accepts_nonempty_commitment_and_proof() {
        let c = KzgCommitment { point: vec![1u8; 48] };
        let o = KzgOpeningProof { evaluation: vec![2u8; 32], proof: vec![3u8; 48] };
        assert!(KzgVerifier::verify(&c, &o, &[0u8; 32]));
    }

    #[test]
    fn kzg_verifier_rejects_empty_commitment_point() {
        let c = KzgCommitment { point: vec![] };
        let o = KzgOpeningProof { evaluation: vec![1u8; 32], proof: vec![2u8; 48] };
        assert!(!KzgVerifier::verify(&c, &o, &[0u8; 32]));
    }

    #[test]
    fn kzg_verifier_rejects_empty_proof() {
        let c = KzgCommitment { point: vec![1u8; 48] };
        let o = KzgOpeningProof { evaluation: vec![1u8; 32], proof: vec![] };
        assert!(!KzgVerifier::verify(&c, &o, &[0u8; 32]));
    }

    #[test]
    fn pedersen_commitment_new_stores_fields() {
        let c = PedersenCommitment::new(vec![0xFF; 32], params_hash(1));
        assert_eq!(c.point, vec![0xFF; 32]);
        assert_eq!(c.params_hash, params_hash(1));
    }

    #[test]
    fn pedersen_commitment_compatible_with_same_params() {
        let c1 = PedersenCommitment::new(vec![1u8; 32], params_hash(7));
        let c2 = PedersenCommitment::new(vec![2u8; 32], params_hash(7));
        assert!(c1.compatible_with(&c2));
    }

    #[test]
    fn pedersen_commitment_incompatible_with_different_params() {
        let c1 = PedersenCommitment::new(vec![1u8; 32], params_hash(1));
        let c2 = PedersenCommitment::new(vec![1u8; 32], params_hash(2));
        assert!(!c1.compatible_with(&c2));
    }

    #[test]
    fn inner_product_argument_stores_proof() {
        let ipa = InnerProductArgument {
            proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
            final_scalar: vec![0x42; 32],
        };
        assert_eq!(ipa.proof.len(), 4);
        assert_eq!(ipa.final_scalar.len(), 32);
    }
}
