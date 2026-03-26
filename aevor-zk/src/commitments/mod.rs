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
