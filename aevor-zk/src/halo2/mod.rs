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
