//! Bulletproofs range proofs — no trusted setup.
//!
//! Real zero-knowledge proofs that a committed amount lies in `[0, 2^n)` without
//! revealing it, backed by the audited `bulletproofs` crate over Ristretto
//! (curve25519-dalek — the *same* curve library as the rest of the crypto
//! stack, so there is no second curve implementation). Commitments use the
//! Bulletproofs Pedersen generators, so a commitment and its range proof are
//! coherent, and the homomorphic balance check operates on those same
//! commitments — together a real confidential-amount primitive: hidden amounts,
//! proven non-negative, with supply integrity (Σ inputs = Σ outputs) checked
//! without revealing a single value.

use serde::{Deserialize, Serialize};
pub use aevor_crypto::proofs::BulletProof as BulletproofProof;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as BpRangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;

/// Bit length of the range: amounts are proven to lie in `[0, 2^64)`.
pub const RANGE_BITS: usize = 64;
const TRANSCRIPT_DOMAIN: &[u8] = b"aevor-confidential-amount-v1";

fn pedersen_gens() -> PedersenGens {
    PedersenGens::default()
}

/// Derive a blinding scalar deterministically from a seed (reproducible; for
/// deriving per-output blindings from a master secret, and for tests).
#[must_use]
pub fn blinding_from_seed(seed: &[u8]) -> Scalar {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(b"aevor-amount-blinding-v1:");
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A confidential amount: a Pedersen commitment to a hidden `u64` plus a
/// Bulletproofs range proof that the amount is in `[0, 2^64)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    /// Compressed Ristretto commitment `C = value·B + blinding·B_blinding`.
    pub commitment: [u8; 32],
    /// Serialized Bulletproofs range proof.
    pub proof_bytes: Vec<u8>,
    /// Range bit length (always [`RANGE_BITS`]).
    pub bits: usize,
}

impl RangeProof {
    /// Commit to `value` and prove it is in `[0, 2^64)`.
    ///
    /// # Errors
    /// Returns [`crate::ZkError::ProofGenerationFailed`] if proof generation
    /// fails (e.g. the value is outside the provable range).
    pub fn prove(value: u64, blinding: &Scalar) -> crate::ZkResult<Self> {
        let pc_gens = pedersen_gens();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
        let mut transcript = Transcript::new(TRANSCRIPT_DOMAIN);
        let (proof, committed) = BpRangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            value,
            blinding,
            RANGE_BITS,
        )
        .map_err(|e| crate::ZkError::ProofGenerationFailed { reason: e.to_string() })?;
        Ok(Self {
            commitment: committed.to_bytes(),
            proof_bytes: proof.to_bytes(),
            bits: RANGE_BITS,
        })
    }

    /// The commitment point (for balance checks).
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// Verifier for Bulletproofs range proofs.
pub struct BulletproofVerifier;

impl BulletproofVerifier {
    /// Really verify a range proof: the committed amount is in `[0, 2^bits)`.
    /// Returns `false` for a malformed or invalid proof.
    #[must_use]
    pub fn verify_range(proof: &RangeProof) -> bool {
        if proof.bits != RANGE_BITS {
            return false;
        }
        let pc_gens = pedersen_gens();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
        let Ok(bp) = BpRangeProof::from_bytes(&proof.proof_bytes) else {
            return false;
        };
        let commit = CompressedRistretto(proof.commitment);
        let mut transcript = Transcript::new(TRANSCRIPT_DOMAIN);
        bp.verify_single(&bp_gens, &pc_gens, &mut transcript, &commit, RANGE_BITS)
            .is_ok()
    }
}

/// Verify that committed inputs and outputs balance in value.
///
/// Using the same Bulletproofs generators as the commitments: given the excess
/// blinding (`Σ input blindings − Σ output blindings`), the totals are equal
/// **iff** `Σ inputs − Σ outputs == excess · B_blinding`. This proves supply
/// integrity — no value created or destroyed — without revealing any amount.
#[must_use]
pub fn verify_balance(
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    excess_blinding: &Scalar,
) -> bool {
    let pc_gens = pedersen_gens();
    let sum = |cs: &[[u8; 32]]| -> Option<RistrettoPoint> {
        let mut acc = RistrettoPoint::identity();
        for c in cs {
            acc += CompressedRistretto(*c).decompress()?;
        }
        Some(acc)
    };
    let (Some(sum_in), Some(sum_out)) = (sum(inputs), sum(outputs)) else {
        return false;
    };
    (sum_in - sum_out) == (excess_blinding * pc_gens.B_blinding)
}

/// Retained for prelude compatibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerProductProof {
    /// Serialized inner-product argument bytes.
    pub proof: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_amount_proves_and_verifies() {
        let proof = RangeProof::prove(1_000_000, &blinding_from_seed(b"r")).unwrap();
        assert!(BulletproofVerifier::verify_range(&proof), "honest amount verifies");
    }

    #[test]
    fn tampered_commitment_is_rejected() {
        let mut proof = RangeProof::prove(500, &blinding_from_seed(b"r")).unwrap();
        proof.commitment[0] ^= 0xFF; // corrupt the commitment
        assert!(!BulletproofVerifier::verify_range(&proof));
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let mut proof = RangeProof::prove(500, &blinding_from_seed(b"r")).unwrap();
        if let Some(b) = proof.proof_bytes.get_mut(0) {
            *b ^= 0xFF;
        }
        assert!(!BulletproofVerifier::verify_range(&proof));
    }

    #[test]
    fn confidential_transaction_balances() {
        // Inputs 100 + 50 = 150; outputs 120 + 30 = 150.
        let (ri1, ri2) = (blinding_from_seed(b"i1"), blinding_from_seed(b"i2"));
        let (ro1, ro2) = (blinding_from_seed(b"o1"), blinding_from_seed(b"o2"));
        let inputs = [
            RangeProof::prove(100, &ri1).unwrap().commitment(),
            RangeProof::prove(50, &ri2).unwrap().commitment(),
        ];
        let outputs = [
            RangeProof::prove(120, &ro1).unwrap().commitment(),
            RangeProof::prove(30, &ro2).unwrap().commitment(),
        ];
        let excess = (ri1 + ri2) - (ro1 + ro2);
        assert!(verify_balance(&inputs, &outputs, &excess), "equal totals balance");
    }

    #[test]
    fn unbalanced_transaction_is_rejected() {
        // Inputs 150; outputs 160 — cannot balance.
        let (ri1, ri2) = (blinding_from_seed(b"i1"), blinding_from_seed(b"i2"));
        let (ro1, ro2) = (blinding_from_seed(b"o1"), blinding_from_seed(b"o2"));
        let inputs = [
            RangeProof::prove(100, &ri1).unwrap().commitment(),
            RangeProof::prove(50, &ri2).unwrap().commitment(),
        ];
        let outputs = [
            RangeProof::prove(120, &ro1).unwrap().commitment(),
            RangeProof::prove(40, &ro2).unwrap().commitment(),
        ];
        let excess = (ri1 + ri2) - (ro1 + ro2);
        assert!(!verify_balance(&inputs, &outputs, &excess));
    }
}
