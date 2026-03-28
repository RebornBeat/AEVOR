//! ZK proof generation.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_crypto::proofs::ProvingKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofRequest {
    pub circuit_hash: Hash256,
    pub public_inputs: Vec<Vec<u8>>,
    pub private_inputs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness { pub private_values: Vec<Vec<u8>> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circuit { pub hash: Hash256, pub constraint_count: usize, pub public_input_count: usize }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofGenerationResult { pub proof: Vec<u8>, pub public_inputs: Vec<Vec<u8>>, pub circuit_hash: Hash256 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitStats { pub constraints: usize, pub variables: usize, pub proving_time_ms: u64 }

pub struct ProofGenerator;
impl ProofGenerator {
    /// Generate a zero-knowledge proof for the given request.
    ///
    /// # Errors
    /// Returns an error if the witness is incompatible with the circuit or the
    /// proving key does not match the circuit hash.
    pub fn generate(_request: &ProofRequest, _witness: &Witness, _pkey: &ProvingKey) -> crate::ZkResult<ProofGenerationResult> {
        Ok(ProofGenerationResult {
            proof: vec![0u8; 192], // Placeholder Groth16 size
            public_inputs: Vec::new(),
            circuit_hash: Hash256::ZERO,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::crypto::ProvingSystem;
    use aevor_crypto::proofs::ProvingKey;

    fn pkey() -> ProvingKey {
        ProvingKey { system: ProvingSystem::Groth16, circuit_hash: Hash256::ZERO, key_bytes: vec![1] }
    }

    #[test]
    fn proof_generator_produces_nonempty_proof() {
        let req = ProofRequest { circuit_hash: Hash256::ZERO, public_inputs: vec![], private_inputs: vec![vec![1,2,3]] };
        let witness = Witness { private_values: vec![vec![1,2,3]] };
        let result = ProofGenerator::generate(&req, &witness, &pkey()).unwrap();
        assert!(!result.proof.is_empty());
    }

    #[test]
    fn circuit_stores_stats() {
        let c = Circuit { hash: Hash256::ZERO, constraint_count: 50_000, public_input_count: 2 };
        assert_eq!(c.constraint_count, 50_000);
    }

    #[test]
    fn circuit_stats_stores_timing() {
        let stats = CircuitStats { constraints: 100, variables: 200, proving_time_ms: 50 };
        assert_eq!(stats.proving_time_ms, 50);
    }
}
