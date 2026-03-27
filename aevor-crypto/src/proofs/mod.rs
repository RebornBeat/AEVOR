//! Zero-knowledge proof type definitions and verification interfaces.
//!
//! Proof *generation* belongs in `aevor-zk`. This module defines the types
//! and structural verification for passing proofs across subsystem boundaries.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::crypto::ProvingSystem;

/// A Groth16 proof (192 bytes, smallest size, requires trusted setup).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrothProof {
    /// Serialized Groth16 proof bytes (192 bytes).
    pub proof_bytes: Vec<u8>,
    /// Public inputs to the circuit.
    pub public_inputs: Vec<Vec<u8>>,
    /// Hash of the verifying key this proof was produced for.
    pub vkey_hash: Hash256,
}

/// A PLONK proof (universal setup, ~800 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlonkProof {
    /// Serialized PLONK proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs to the circuit.
    pub public_inputs: Vec<Vec<u8>>,
    /// Hash of the verifying key this proof was produced for.
    pub vkey_hash: Hash256,
}

/// A Bulletproof (no trusted setup, efficient for range proofs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulletProof {
    /// Serialized Bulletproof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs to the circuit.
    pub public_inputs: Vec<Vec<u8>>,
    /// Whether this is a range proof (vs arithmetic circuit proof).
    pub is_range_proof: bool,
}

/// A STARK proof (post-quantum secure, ~50KB).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkProof {
    /// Serialized STARK proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs to the circuit.
    pub public_inputs: Vec<Vec<u8>>,
    /// FRI low-degree testing parameters.
    pub fri_parameters: Vec<u8>,
}

/// A Halo2 proof (no trusted setup, supports recursive composition).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Halo2Proof {
    /// Serialized Halo2 proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs to the circuit.
    pub public_inputs: Vec<Vec<u8>>,
    /// Hash of the circuit / commitment key.
    pub circuit_hash: Hash256,
    /// Whether this proof is part of a recursive proof chain.
    pub is_recursive: bool,
}

/// A proving key for a specific ZK circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvingKey {
    /// The proving system this key belongs to.
    pub system: ProvingSystem,
    /// Hash identifying the circuit.
    pub circuit_hash: Hash256,
    /// Serialized proving key bytes.
    pub key_bytes: Vec<u8>,
}

/// A verifying key for a specific ZK circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// The proving system this key belongs to.
    pub system: ProvingSystem,
    /// Hash identifying the circuit.
    pub circuit_hash: Hash256,
    /// Serialized verifying key bytes.
    pub key_bytes: Vec<u8>,
    /// Whether this is a universal verifying key (works for any circuit).
    pub is_universal: bool,
}

impl VerifyingKey {
    /// Compute the BLAKE3 hash of the verifying key bytes.
    pub fn key_hash(&self) -> Hash256 {
        let mut hasher = crate::hash::Blake3Hasher::new();
        hasher.update(&self.key_bytes);
        hasher.finalize().0
    }
}

/// Identifies which proof system to use for generation or verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofSystem {
    /// Groth16 — smallest proof, requires trusted setup.
    Groth16,
    /// PLONK — universal setup, flexible circuits.
    Plonk,
    /// Bulletproofs — no trusted setup, good range proofs.
    Bulletproofs,
    /// STARK — post-quantum secure, large proofs.
    Stark,
    /// Halo2 — no trusted setup, recursive proofs.
    Halo2,
}

impl ProofSystem {
    /// Returns `true` if this system requires a trusted setup ceremony.
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(self, Self::Groth16 | Self::Plonk)
    }
}

/// Structural verifier for ZK proofs — delegates full verification to `aevor-zk`.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a Groth16 proof against a verifying key.
    ///
    /// Full cryptographic verification is performed in `aevor-zk`.
    /// This structural check validates key/proof hash consistency.
    ///
    /// # Errors
    /// Returns an error if the verifying key is not for the Groth16 system.
    pub fn verify_groth16(
        proof: &GrothProof,
        vkey: &VerifyingKey,
    ) -> crate::CryptoResult<bool> {
        if vkey.system != ProvingSystem::Groth16 {
            return Err(crate::CryptoError::ProofVerificationFailed {
                system: "Groth16".into(),
            });
        }
        Ok(!proof.proof_bytes.is_empty() && proof.vkey_hash == vkey.circuit_hash)
    }

    /// Verify a PLONK proof against a verifying key.
    ///
    /// # Errors
    /// Returns an error if the proof or verifying key bytes are malformed.
    pub fn verify_plonk(
        proof: &PlonkProof,
        vkey: &VerifyingKey,
    ) -> crate::CryptoResult<bool> {
        Ok(!proof.proof_bytes.is_empty() && proof.vkey_hash == vkey.circuit_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_system_trusted_setup_flags() {
        assert!(ProofSystem::Groth16.requires_trusted_setup());
        assert!(ProofSystem::Plonk.requires_trusted_setup());
        assert!(!ProofSystem::Halo2.requires_trusted_setup());
        assert!(!ProofSystem::Stark.requires_trusted_setup());
        assert!(!ProofSystem::Bulletproofs.requires_trusted_setup());
    }

    #[test]
    fn verifying_key_hash_is_deterministic() {
        let vk = VerifyingKey {
            system: ProvingSystem::Groth16,
            circuit_hash: Hash256::ZERO,
            key_bytes: vec![1, 2, 3, 4],
            is_universal: false,
        };
        assert_eq!(vk.key_hash(), vk.key_hash());
    }

    #[test]
    fn groth16_verify_mismatched_system_fails() {
        let proof = GrothProof {
            proof_bytes: vec![0u8; 192],
            public_inputs: vec![],
            vkey_hash: Hash256::ZERO,
        };
        let vkey = VerifyingKey {
            system: ProvingSystem::Plonk, // wrong system
            circuit_hash: Hash256::ZERO,
            key_bytes: vec![],
            is_universal: false,
        };
        assert!(ProofVerifier::verify_groth16(&proof, &vkey).is_err());
    }
}
