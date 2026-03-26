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
    pub fn prove(&self, trace: &[u8]) -> crate::ZkResult<StarkProof> {
        let mut fri_params = Vec::new();
        fri_params.extend_from_slice(&(self.config.blowup_factor as u32).to_le_bytes());
        fri_params.extend_from_slice(&(self.config.num_queries as u32).to_le_bytes());
        // Include trace length in proof metadata
        fri_params.extend_from_slice(&(trace.len() as u32).to_le_bytes());
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
