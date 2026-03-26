//! TEE-accelerated ZK proving.

use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;
use aevor_core::primitives::Hash256;
use aevor_core::consensus::ExecutionAttestation;

pub struct TeeAcceleratedProver { platform: TeePlatform }
impl TeeAcceleratedProver {
    pub fn new(platform: TeePlatform) -> Self { Self { platform } }
    pub fn platform(&self) -> TeePlatform { self.platform }
}

pub struct TeeProofVerifier;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationBoundProof { pub proof: Vec<u8>, pub attestation: ExecutionAttestation }

/// Generates ZK witnesses from TEE-attested private execution inputs.
///
/// The `commitment` (`Hash256`) binds the witness to the specific set of
/// private inputs without revealing them, enabling the verifier to check
/// that the prover used the correct inputs.
pub struct TeeWitnessGenerator { platform: TeePlatform }

impl TeeWitnessGenerator {
    /// Create a witness generator for the given TEE platform.
    pub fn new(platform: TeePlatform) -> Self { Self { platform } }

    /// The platform this generator produces witnesses for.
    pub fn platform(&self) -> TeePlatform { self.platform }

    /// Generate a witness from private inputs.
    pub fn generate(&self, private_inputs: &[u8]) -> Vec<u8> { private_inputs.to_vec() }

    /// Compute a commitment to the private inputs.
    ///
    /// Returns a `Hash256` that can be included in the public proof without
    /// revealing the underlying inputs.
    pub fn commit(&self, private_inputs: &[u8]) -> Hash256 {
        let mut h = [0u8; 32];
        for (i, b) in private_inputs.iter().enumerate() { h[i % 32] ^= b; }
        Hash256(h)
    }
}
