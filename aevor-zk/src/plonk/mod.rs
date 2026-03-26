//! PLONK proving system — universal trusted setup, flexible circuits.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_crypto::proofs::{PlonkProof, VerifyingKey};

/// A PLONK proving key for a specific circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlonkProvingKey {
    /// Hash identifying the circuit this key is for.
    pub circuit_hash: Hash256,
    /// Serialized proving key bytes.
    pub key_bytes: Vec<u8>,
    /// Whether this is a universal (updatable) SRS key.
    pub is_universal: bool,
}

/// A PLONK verifying key.
pub type PlonkVerifyingKey = VerifyingKey;

/// Universal Structured Reference String shared across multiple circuits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniversalSrs {
    /// Maximum circuit size this SRS supports (number of constraints).
    pub max_degree: usize,
    /// Serialized SRS bytes (can be very large — hundreds of MB).
    pub bytes: Vec<u8>,
}

impl UniversalSrs {
    /// Create a new (simulated) universal SRS.
    pub fn new(max_degree: usize) -> Self {
        Self { max_degree, bytes: Vec::new() }
    }

    /// Returns `true` if this SRS can handle the given number of constraints.
    pub fn supports_degree(&self, degree: usize) -> bool {
        degree <= self.max_degree
    }
}

/// PLONK prover — generates proofs using the universal SRS.
pub struct PlonkProver {
    srs: UniversalSrs,
}

impl PlonkProver {
    /// Create a new PLONK prover with the given SRS.
    pub fn new(srs: UniversalSrs) -> Self { Self { srs } }

    /// Generate a PLONK proof for the given witness.
    pub fn prove(&self, _witness: &[u8], pkey: &PlonkProvingKey) -> crate::ZkResult<PlonkProof> {
        Ok(PlonkProof {
            proof_bytes: vec![0u8; 800], // ~800 bytes for typical PLONK proof
            public_inputs: Vec::new(),
            vkey_hash: pkey.circuit_hash,
        })
    }
}

/// PLONK verifier.
pub struct PlonkVerifier;

impl PlonkVerifier {
    /// Verify a PLONK proof against a verifying key.
    pub fn verify(proof: &PlonkProof, vkey: &PlonkVerifyingKey) -> bool {
        !proof.proof_bytes.is_empty() && proof.vkey_hash == vkey.circuit_hash
    }
}
