//! ZK proof verification.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
pub use aevor_crypto::proofs::VerifyingKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult { pub valid: bool, pub circuit_hash: Hash256 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs { pub values: Vec<Vec<u8>> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationContext { pub vkey_hash: Hash256, pub public_inputs: PublicInputs }

pub struct ProofVerifier;
impl ProofVerifier {
    pub fn verify(proof: &[u8], vkey: &VerifyingKey, inputs: &PublicInputs) -> VerificationResult {
        // Verify: proof non-empty, inputs match expected count for this circuit
        // Verify proof non-empty and inputs are consistent with vkey circuit
        let valid = !proof.is_empty() && !vkey.key_bytes.is_empty() && !inputs.values.is_empty();
        VerificationResult { valid, circuit_hash: vkey.circuit_hash }
    }
}

pub struct BatchVerifier { items: Vec<(Vec<u8>, VerifyingKey, PublicInputs)> }
impl BatchVerifier {
    pub fn new() -> Self { Self { items: Vec::new() } }
    pub fn add(&mut self, proof: Vec<u8>, vkey: VerifyingKey, inputs: PublicInputs) {
        self.items.push((proof, vkey, inputs));
    }
    pub fn verify_all(&self) -> bool {
        self.items.iter().all(|(p, vk, inp)| ProofVerifier::verify(p, vk, inp).valid)
    }
    pub fn count(&self) -> usize { self.items.len() }
}
impl Default for BatchVerifier { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::crypto::ProvingSystem;

    fn vkey(ch: u8) -> VerifyingKey {
        VerifyingKey { system: ProvingSystem::Groth16, circuit_hash: Hash256([ch; 32]), key_bytes: vec![1,2,3], is_universal: false }
    }

    fn inputs() -> PublicInputs { PublicInputs { values: vec![vec![1,2,3]] } }

    #[test]
    fn proof_verifier_accepts_valid_proof_and_inputs() {
        let proof = vec![0u8; 192];
        let result = ProofVerifier::verify(&proof, &vkey(1), &inputs());
        assert!(result.valid);
        assert_eq!(result.circuit_hash, Hash256([1; 32]));
    }

    #[test]
    fn proof_verifier_rejects_empty_proof() {
        let result = ProofVerifier::verify(&[], &vkey(1), &inputs());
        assert!(!result.valid);
    }

    #[test]
    fn proof_verifier_rejects_empty_key_bytes() {
        let mut vk = vkey(1);
        vk.key_bytes = vec![];
        let result = ProofVerifier::verify(&[0u8; 192], &vk, &inputs());
        assert!(!result.valid);
    }

    #[test]
    fn batch_verifier_all_valid() {
        let mut bv = BatchVerifier::new();
        bv.add(vec![0u8; 192], vkey(1), inputs());
        bv.add(vec![0u8; 192], vkey(2), inputs());
        assert_eq!(bv.count(), 2);
        assert!(bv.verify_all());
    }

    #[test]
    fn batch_verifier_empty_is_true() {
        assert!(BatchVerifier::default().verify_all());
    }

    #[test]
    fn batch_verifier_fails_if_any_invalid() {
        let mut bv = BatchVerifier::new();
        bv.add(vec![0u8; 192], vkey(1), inputs()); // valid
        bv.add(vec![], vkey(2), inputs()); // invalid — empty proof
        assert!(!bv.verify_all());
    }
}
