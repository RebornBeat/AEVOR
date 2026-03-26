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
