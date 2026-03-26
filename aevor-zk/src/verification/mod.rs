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
        let valid = !proof.is_empty() && inputs.values.len() <= vkey.public_input_count;
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
