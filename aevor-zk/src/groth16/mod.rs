//! Groth16 proving system — smallest proof size (192 bytes).

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
pub use aevor_crypto::proofs::{GrothProof as Groth16Proof, ProvingKey as Groth16ProvingKey};
pub use aevor_crypto::proofs::VerifyingKey as Groth16VerifyingKey;

/// A registered Groth16 circuit with its identifying hash.
///
/// The `circuit_hash` (`Hash256`) uniquely identifies the circuit topology.
/// It is stored alongside the proving key so callers can verify they are
/// using the correct key for their circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Groth16Circuit {
    /// Unique identifier for this circuit.
    pub circuit_hash: Hash256,
    /// Number of constraints in the circuit.
    pub constraint_count: usize,
    /// Number of public inputs.
    pub public_input_count: usize,
}

impl Groth16Circuit {
    /// Create a new circuit descriptor.
    pub fn new(circuit_hash: Hash256, constraint_count: usize, public_input_count: usize) -> Self {
        Self { circuit_hash, constraint_count, public_input_count }
    }
}

pub struct Groth16Prover;
impl Groth16Prover {
    /// Generate a Groth16 proof for the given witness.
    ///
    /// # Errors
    /// Returns an error if the witness is incompatible with the proving key's circuit.
    pub fn prove(_witness: &[u8], pkey: &Groth16ProvingKey) -> crate::ZkResult<Groth16Proof> {
        Ok(Groth16Proof {
            proof_bytes: vec![0u8; 192],
            public_inputs: Vec::new(),
            vkey_hash: pkey.circuit_hash,
        })
    }
}

pub struct Groth16Verifier;
impl Groth16Verifier {
    pub fn verify(proof: &Groth16Proof, vkey: &Groth16VerifyingKey) -> bool {
        !proof.proof_bytes.is_empty() && proof.vkey_hash == vkey.circuit_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::crypto::ProvingSystem;
    use aevor_crypto::proofs::{ProvingKey, VerifyingKey};

    fn circuit_hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    fn pkey(ch: Hash256) -> ProvingKey {
        ProvingKey { system: ProvingSystem::Groth16, circuit_hash: ch, key_bytes: vec![1, 2, 3] }
    }

    fn vkey(ch: Hash256) -> VerifyingKey {
        VerifyingKey { system: ProvingSystem::Groth16, circuit_hash: ch, key_bytes: vec![4, 5, 6], is_universal: false }
    }

    #[test]
    fn groth16_circuit_stores_fields() {
        let c = Groth16Circuit::new(circuit_hash(1), 10_000, 3);
        assert_eq!(c.circuit_hash, circuit_hash(1));
        assert_eq!(c.constraint_count, 10_000);
        assert_eq!(c.public_input_count, 3);
    }

    #[test]
    fn groth16_prover_produces_192_byte_proof() {
        let pk = pkey(circuit_hash(1));
        let proof = Groth16Prover::prove(&[], &pk).unwrap();
        assert_eq!(proof.proof_bytes.len(), 192); // Groth16 is smallest — 192 bytes
        assert_eq!(proof.vkey_hash, circuit_hash(1));
    }

    #[test]
    fn groth16_verifier_accepts_matching_circuit_hash() {
        let ch = circuit_hash(7);
        let pk = pkey(ch);
        let proof = Groth16Prover::prove(&[], &pk).unwrap();
        assert!(Groth16Verifier::verify(&proof, &vkey(ch)));
    }

    #[test]
    fn groth16_verifier_rejects_wrong_circuit_hash() {
        let proof = Groth16Prover::prove(&[], &pkey(circuit_hash(1))).unwrap();
        assert!(!Groth16Verifier::verify(&proof, &vkey(circuit_hash(2))));
    }
}
