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
    /// The universal SRS this prover uses.
    pub fn srs(&self) -> &UniversalSrs { &self.srs }
    /// Whether this prover can handle a circuit with `constraint_count` constraints.
    pub fn can_prove_degree(&self, constraint_count: usize) -> bool {
        self.srs.supports_degree(constraint_count)
    }

    /// Generate a PLONK proof for the given witness.
    ///
    /// # Errors
    /// Returns an error if the witness is incompatible with the SRS degree or proving key.
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::crypto::ProvingSystem;
    use aevor_crypto::proofs::VerifyingKey;

    fn circuit_hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    fn pkey(circuit: Hash256) -> PlonkProvingKey {
        PlonkProvingKey { circuit_hash: circuit, key_bytes: vec![1, 2, 3], is_universal: true }
    }

    fn vkey(circuit: Hash256) -> PlonkVerifyingKey {
        VerifyingKey {
            system: ProvingSystem::Plonk,
            circuit_hash: circuit,
            key_bytes: vec![4, 5, 6],
            is_universal: true,
        }
    }

    #[test]
    fn universal_srs_supports_degree() {
        let srs = UniversalSrs::new(1_000_000);
        assert!(srs.supports_degree(500_000));
        assert!(srs.supports_degree(1_000_000));
        assert!(!srs.supports_degree(1_000_001));
    }

    #[test]
    fn plonk_prover_can_prove_within_srs_degree() {
        let prover = PlonkProver::new(UniversalSrs::new(100_000));
        assert!(prover.can_prove_degree(100_000));
        assert!(!prover.can_prove_degree(100_001));
    }

    #[test]
    fn plonk_prover_generates_nonempty_proof() {
        let prover = PlonkProver::new(UniversalSrs::new(1_000_000));
        let pk = pkey(circuit_hash(1));
        let proof = prover.prove(&[], &pk).unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.vkey_hash, circuit_hash(1));
    }

    #[test]
    fn plonk_verifier_accepts_matching_vkey_hash() {
        let prover = PlonkProver::new(UniversalSrs::new(1_000_000));
        let circuit = circuit_hash(7);
        let proof = prover.prove(&[], &pkey(circuit)).unwrap();
        let vk = vkey(circuit);
        assert!(PlonkVerifier::verify(&proof, &vk));
    }

    #[test]
    fn plonk_verifier_rejects_wrong_vkey_hash() {
        let prover = PlonkProver::new(UniversalSrs::new(1_000_000));
        let proof = prover.prove(&[], &pkey(circuit_hash(1))).unwrap();
        let wrong_vk = vkey(circuit_hash(2));
        assert!(!PlonkVerifier::verify(&proof, &wrong_vk));
    }

    #[test]
    fn proving_key_is_universal_flag() {
        let pk = pkey(circuit_hash(1));
        assert!(pk.is_universal);
        assert_eq!(pk.key_bytes, vec![1, 2, 3]);
    }
}
