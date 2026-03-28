//! Halo2 — no trusted setup, supports recursive composition.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
pub use aevor_crypto::proofs::Halo2Proof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProof { pub proofs: Vec<Halo2Proof>, pub aggregated: Vec<u8> }

pub struct Halo2Prover;
impl Halo2Prover {
    pub fn prove(witness: &[u8]) -> Halo2Proof {
        // Commit to the witness so the circuit_hash reflects actual inputs
        let mut h = [0u8; 32];
        for (i, b) in witness.iter().enumerate() { h[i % 32] ^= b; }
        Halo2Proof { proof_bytes: vec![0u8; 1200], public_inputs: Vec::new(), circuit_hash: Hash256(h), is_recursive: false }
    }
}

pub struct Halo2Verifier;
impl Halo2Verifier {
    pub fn verify(proof: &Halo2Proof) -> bool { !proof.proof_bytes.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halo2_prover_produces_large_proof() {
        let proof = Halo2Prover::prove(&[1,2,3]);
        // Halo2 proofs are larger than Groth16 — 1200 bytes in this stub
        assert_eq!(proof.proof_bytes.len(), 1200);
        assert!(!proof.is_recursive);
    }

    #[test]
    fn halo2_verifier_accepts_nonempty_proof() {
        let proof = Halo2Prover::prove(&[]);
        assert!(Halo2Verifier::verify(&proof));
    }

    #[test]
    fn halo2_witness_affects_circuit_hash() {
        let p1 = Halo2Prover::prove(&[1]);
        let p2 = Halo2Prover::prove(&[2]);
        assert_ne!(p1.circuit_hash, p2.circuit_hash);
    }

    #[test]
    fn recursive_proof_stores_aggregation() {
        let rp = RecursiveProof { proofs: vec![Halo2Prover::prove(&[])], aggregated: vec![0u8; 100] };
        assert_eq!(rp.proofs.len(), 1);
        assert!(!rp.aggregated.is_empty());
    }
}
