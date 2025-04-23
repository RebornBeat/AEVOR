use std::fmt;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::crypto::HashAlgorithm;
use crate::crypto::ZkProofScheme;
use crate::error::{AevorError, Result};

mod schnorr;
mod bulletproof;
mod groth16;
mod stark;

pub use schnorr::{SchnorrProof, SchnorrProofSystem};
pub use bulletproof::{BulletproofRangeProof, BulletproofProofSystem};
pub use groth16::{Groth16Proof, Groth16ProofSystem};
pub use stark::{StarkProof, StarkProofSystem};

/// A generic zero-knowledge proof
#[derive(Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// The proof scheme used
    pub proof_type: ZkProofScheme,
    
    /// Public parameters for the proof
    pub public_params: Vec<u8>,
    
    /// The proof data
    pub proof_data: Vec<u8>,
}

impl ZkProof {
    /// Creates a new zero-knowledge proof
    pub fn new(proof_type: ZkProofScheme, public_params: Vec<u8>, proof_data: Vec<u8>) -> Self {
        Self {
            proof_type,
            public_params,
            proof_data,
        }
    }
    
    /// Gets the proof type
    pub fn proof_type(&self) -> ZkProofScheme {
        self.proof_type
    }
    
    /// Gets the public parameters
    pub fn public_params(&self) -> &[u8] {
        &self.public_params
    }
    
    /// Gets the proof data
    pub fn proof_data(&self) -> &[u8] {
        &self.proof_data
    }
    
    /// Verifies the proof using the appropriate proof system
    pub fn verify(&self) -> Result<bool> {
        match self.proof_type {
            ZkProofScheme::Schnorr => {
                let schnorr_proof = SchnorrProof::from_bytes(&self.proof_data)?;
                let public_key = &self.public_params;
                SchnorrProofSystem::verify_knowledge_of_secret_key(public_key, &schnorr_proof)
            },
            ZkProofScheme::Bulletproof => {
                let bulletproof = BulletproofRangeProof::from_bytes(&self.proof_data)?;
                let params = bulletproof::RangeProofParams::from_bytes(&self.public_params)?;
                BulletproofProofSystem::verify_range_proof(&params, &bulletproof)
            },
            ZkProofScheme::Groth16 => {
                let groth16_proof = Groth16Proof::from_bytes(&self.proof_data)?;
                let params = groth16::VerifyingKey::from_bytes(&self.public_params)?;
                Groth16ProofSystem::verify(&params, &groth16_proof)
            },
            ZkProofScheme::STARK => {
                let stark_proof = StarkProof::from_bytes(&self.proof_data)?;
                let params = stark::VerifyingKey::from_bytes(&self.public_params)?;
                StarkProofSystem::verify(&params, &stark_proof)
            },
        }
    }
}

impl fmt::Debug for ZkProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZkProof")
            .field("proof_type", &self.proof_type)
            .field("public_params_size", &self.public_params.len())
            .field("proof_data_size", &self.proof_data.len())
            .finish()
    }
}

/// Interface for zero-knowledge proof systems
pub trait ProofSystem<Params, Proof> {
    /// Verifies a proof
    fn verify(params: &Params, proof: &Proof) -> Result<bool>;
}

/// Trait for types that can be proven in zero-knowledge
pub trait ZkProvable {
    /// The type of proof this provable generates
    type Proof;
    
    /// The type of public parameters for this provable
    type Params;
    
    /// Generates a proof
    fn prove(&self, params: &Self::Params) -> Result<Self::Proof>;
}

/// Trait for types that can be verified in zero-knowledge
pub trait ZkVerifiable {
    /// The type of proof this verifiable accepts
    type Proof;
    
    /// The type of public parameters for this verifiable
    type Params;
    
    /// Verifies a proof
    fn verify(&self, params: &Self::Params, proof: &Self::Proof) -> Result<bool>;
}

/// Creates a Merlin transcript for proof generation and verification
pub fn create_transcript(label: &[u8]) -> Transcript {
    Transcript::new(label)
}

/// Creates a domain separator for zero-knowledge proofs
pub fn domain_separator(label: &[u8]) -> [u8; 32] {
    use crate::crypto::hash::Hash;
    let hash = Hash::hash_with_algorithm(HashAlgorithm::BLAKE3, label);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash.value);
    result
}

/// Utility functions for zero-knowledge proofs
pub mod util {
    use super::*;
    
    /// Serializes a proof to bytes
    pub fn serialize_proof<T: Serialize>(proof: &T) -> Result<Vec<u8>> {
        bincode::serialize(proof).map_err(|e| {
            AevorError::crypto(
                "Failed to serialize proof".into(),
                e.to_string(),
                None,
            )
        })
    }
    
    /// Deserializes a proof from bytes
    pub fn deserialize_proof<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T> {
        bincode::deserialize(bytes).map_err(|e| {
            AevorError::crypto(
                "Failed to deserialize proof".into(),
                e.to_string(),
                None,
            )
        })
    }
    
    /// Serializes parameters to bytes
    pub fn serialize_params<T: Serialize>(params: &T) -> Result<Vec<u8>> {
        bincode::serialize(params).map_err(|e| {
            AevorError::crypto(
                "Failed to serialize parameters".into(),
                e.to_string(),
                None,
            )
        })
    }
    
    /// Deserializes parameters from bytes
    pub fn deserialize_params<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T> {
        bincode::deserialize(bytes).map_err(|e| {
            AevorError::crypto(
                "Failed to deserialize parameters".into(),
                e.to_string(),
                None,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // This is a simple test for the ZkProof struct itself
    // More comprehensive tests are in the individual proof system modules
    #[test]
    fn test_zk_proof_creation() {
        let proof_type = ZkProofScheme::Schnorr;
        let public_params = vec![1, 2, 3, 4];
        let proof_data = vec![5, 6, 7, 8];
        
        let proof = ZkProof::new(proof_type, public_params.clone(), proof_data.clone());
        
        assert_eq!(proof.proof_type(), proof_type);
        assert_eq!(proof.public_params(), &public_params);
        assert_eq!(proof.proof_data(), &proof_data);
    }
    
    #[test]
    fn test_domain_separator() {
        let label1 = b"test_domain_1";
        let label2 = b"test_domain_2";
        
        let separator1 = domain_separator(label1);
        let separator2 = domain_separator(label2);
        
        // Different labels should produce different separators
        assert_ne!(separator1, separator2);
        
        // Same label should produce the same separator
        let separator1_again = domain_separator(label1);
        assert_eq!(separator1, separator1_again);
    }
    
    #[test]
    fn test_transcript_creation() {
        let label = b"test_transcript";
        let transcript = create_transcript(label);
        
        // Just test that we can create a transcript without errors
        // The actual behavior of the transcript is tested in the Merlin crate
        assert!(true);
    }
    
    #[test]
    fn test_serialization_utils() {
        // Create a simple serializable structure
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct TestStruct {
            a: u32,
            b: Vec<u8>,
        }
        
        let test_struct = TestStruct {
            a: 42,
            b: vec![1, 2, 3, 4],
        };
        
        // Test serialization
        let serialized = util::serialize_proof(&test_struct).unwrap();
        
        // Test deserialization
        let deserialized: TestStruct = util::deserialize_proof(&serialized).unwrap();
        
        // Should get back the original struct
        assert_eq!(test_struct, deserialized);
        
        // Test with invalid data
        let invalid_data = vec![1, 2, 3];
        let result: Result<TestStruct> = util::deserialize_proof(&invalid_data);
        assert!(result.is_err());
    }
}
