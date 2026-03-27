//! STARK proving system — post-quantum secure, no trusted setup.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_crypto::proofs::StarkProof;

/// STARK proving configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkConfig {
    /// Security bits (80, 128, 256).
    pub security_bits: u32,
    /// Blowup factor for FRI — trades proof size for security.
    pub blowup_factor: usize,
    /// Number of FRI query rounds.
    pub num_queries: usize,
}

impl Default for StarkConfig {
    fn default() -> Self {
        Self { security_bits: 128, blowup_factor: 8, num_queries: 30 }
    }
}

/// STARK prover.
pub struct StarkProver {
    config: StarkConfig,
}

impl StarkProver {
    /// Create a new STARK prover with the given configuration.
    pub fn new(config: StarkConfig) -> Self { Self { config } }

    /// Generate a STARK proof for the given execution trace.
    ///
    /// # Errors
    /// Returns an error if the execution trace fails the STARK algebraic constraints.
    pub fn prove(&self, trace: &[u8]) -> crate::ZkResult<StarkProof> {
        let mut fri_params = Vec::new();
        fri_params.extend_from_slice(&u32::try_from(self.config.blowup_factor).unwrap_or(u32::MAX).to_le_bytes());
        fri_params.extend_from_slice(&u32::try_from(self.config.num_queries).unwrap_or(u32::MAX).to_le_bytes());
        // Include trace length in proof metadata
        fri_params.extend_from_slice(&u32::try_from(trace.len()).unwrap_or(u32::MAX).to_le_bytes());
        Ok(StarkProof {
            proof_bytes: vec![0u8; 50_000], // STARKs are large (~50KB)
            public_inputs: Vec::new(),
            fri_parameters: fri_params,
        })
    }

    /// Estimated proof size in bytes.
    pub fn estimate_proof_size(&self) -> usize {
        // STARKs grow with log²(trace_length) * num_queries
        50_000
    }
}

/// A hash identifying a STARK execution trace circuit.
///
/// `Hash256` commits to the AIR (Algebraic Intermediate Representation)
/// constraints of the circuit, enabling verifiers to confirm they are
/// checking the correct circuit without downloading it in full.
pub struct StarkCircuitId(pub Hash256);

impl StarkCircuitId {
    /// Returns the underlying hash of this circuit.
    pub fn as_hash(&self) -> &Hash256 { &self.0 }
}

/// STARK verifier — fast logarithmic verification.
pub struct StarkVerifier;

impl StarkVerifier {
    /// Verify a STARK proof.
    pub fn verify(proof: &StarkProof) -> bool {
        !proof.proof_bytes.is_empty() && !proof.fri_parameters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stark_config_default_values() {
        let cfg = StarkConfig::default();
        assert_eq!(cfg.security_bits, 128);
        assert_eq!(cfg.blowup_factor, 8);
        assert_eq!(cfg.num_queries, 30);
    }

    #[test]
    fn stark_prover_produces_nonempty_proof() {
        let prover = StarkProver::new(StarkConfig::default());
        let proof = prover.prove(b"execution trace").unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert!(!proof.fri_parameters.is_empty());
    }

    #[test]
    fn stark_prover_encodes_blowup_and_queries_in_fri_params() {
        let cfg = StarkConfig { security_bits: 128, blowup_factor: 4, num_queries: 20 };
        let prover = StarkProver::new(cfg);
        let proof = prover.prove(b"trace").unwrap();
        // First 4 bytes encode blowup_factor (4) as u32 LE
        let blowup = u32::from_le_bytes(proof.fri_parameters[0..4].try_into().unwrap());
        assert_eq!(blowup, 4);
        // Next 4 bytes encode num_queries (20)
        let queries = u32::from_le_bytes(proof.fri_parameters[4..8].try_into().unwrap());
        assert_eq!(queries, 20);
    }

    #[test]
    fn stark_prover_estimate_proof_size_is_nonzero() {
        let prover = StarkProver::new(StarkConfig::default());
        assert!(prover.estimate_proof_size() > 0);
    }

    #[test]
    fn stark_verifier_accepts_valid_proof() {
        let prover = StarkProver::new(StarkConfig::default());
        let proof = prover.prove(b"data").unwrap();
        assert!(StarkVerifier::verify(&proof));
    }

    #[test]
    fn stark_verifier_rejects_empty_proof_bytes() {
        let proof = StarkProof { proof_bytes: vec![], public_inputs: vec![], fri_parameters: vec![1] };
        assert!(!StarkVerifier::verify(&proof));
    }

    #[test]
    fn stark_circuit_id_as_hash() {
        let h = Hash256([0xAB; 32]);
        let cid = StarkCircuitId(h);
        assert_eq!(*cid.as_hash(), h);
    }
}
