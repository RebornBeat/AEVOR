use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::crypto::hash::{Hash, HashAlgorithm};
use crate::error::{AevorError, Result};

use super::{ProofSystem, create_transcript, util};

/// A Schnorr proof of knowledge of a discrete logarithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// The commitment R = r*G
    pub commitment: CompressedRistretto,
    
    /// The challenge response z = r + c*x
    pub response: Scalar,
}

impl SchnorrProof {
    /// Creates a new Schnorr proof
    pub fn new(commitment: CompressedRistretto, response: Scalar) -> Self {
        Self {
            commitment,
            response,
        }
    }
    
    /// Converts the proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_proof(self)
    }
    
    /// Creates a proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_proof(bytes)
    }
}

/// Parameters for Schnorr proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrParams {
    /// The public key (P = x*G)
    pub public_key: CompressedRistretto,
    
    /// Domain separator for this proof
    pub domain: [u8; 32],
}

impl SchnorrParams {
    /// Creates new parameters
    pub fn new(public_key: CompressedRistretto, domain: [u8; 32]) -> Self {
        Self {
            public_key,
            domain,
        }
    }
    
    /// Converts parameters to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_params(self)
    }
    
    /// Creates parameters from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_params(bytes)
    }
}

/// The Schnorr proof system
pub struct SchnorrProofSystem;

impl SchnorrProofSystem {
    /// Generates a Schnorr proof of knowledge of the secret key corresponding to a public key
    pub fn prove_knowledge_of_secret_key<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &Scalar,
        public_key: &[u8],
    ) -> Result<SchnorrProof> {
        // Convert public key bytes to a RistrettoPoint
        let public_key_point = RistrettoPoint::from_uniform_bytes(&extract_32_bytes(public_key)?);
        let compressed_public_key = public_key_point.compress();
        
        // Create a transcript for this proof
        let mut transcript = create_transcript(b"schnorr_proof");
        transcript.append_message(b"domain", b"knowledge_of_secret_key");
        transcript.append_message(b"public_key", compressed_public_key.as_bytes());
        
        // Choose a random nonce
        let mut nonce_bytes = [0u8; 32];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Scalar::from_bytes_mod_order_wide(&hash_to_scalar(&nonce_bytes));
        
        // Calculate commitment R = nonce * G
        let commitment = (nonce * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Calculate challenge c = H(R || P)
        transcript.append_message(b"commitment", commitment.as_bytes());
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        
        // Calculate response z = nonce + challenge * secret_key
        let response = nonce + challenge * secret_key;
        
        Ok(SchnorrProof::new(commitment, response))
    }
    
    /// Verifies a Schnorr proof of knowledge of the secret key
    pub fn verify_knowledge_of_secret_key(
        public_key: &[u8],
        proof: &SchnorrProof,
    ) -> Result<bool> {
        // Convert public key bytes to a RistrettoPoint
        let public_key_point = match CompressedRistretto::from_slice(public_key).decompress() {
            Some(point) => point,
            None => return Ok(false),
        };
        let compressed_public_key = public_key_point.compress();
        
        // Create a transcript for this proof
        let mut transcript = create_transcript(b"schnorr_proof");
        transcript.append_message(b"domain", b"knowledge_of_secret_key");
        transcript.append_message(b"public_key", compressed_public_key.as_bytes());
        transcript.append_message(b"commitment", proof.commitment.as_bytes());
        
        // Calculate challenge c = H(R || P)
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        
        // Verify that z*G = R + c*P
        let left = proof.response * RISTRETTO_BASEPOINT_POINT;
        let right_commitment = match proof.commitment.decompress() {
            Some(point) => point,
            None => return Ok(false),
        };
        let right = right_commitment + (challenge * public_key_point);
        
        Ok(left == right)
    }
    
    /// Creates a signature with a Schnorr proof
    pub fn sign<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &Scalar,
        message: &[u8],
    ) -> Result<SchnorrProof> {
        // Calculate public key
        let public_key = (secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Create a transcript for this signature
        let mut transcript = create_transcript(b"schnorr_signature");
        transcript.append_message(b"domain", b"message_signature");
        transcript.append_message(b"public_key", public_key.as_bytes());
        transcript.append_message(b"message", message);
        
        // Choose a random nonce
        let mut nonce_bytes = [0u8; 32];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Scalar::from_bytes_mod_order_wide(&hash_to_scalar(&nonce_bytes));
        
        // Calculate commitment R = nonce * G
        let commitment = (nonce * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Calculate challenge c = H(R || P || message)
        transcript.append_message(b"commitment", commitment.as_bytes());
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        
        // Calculate response z = nonce + challenge * secret_key
        let response = nonce + challenge * secret_key;
        
        Ok(SchnorrProof::new(commitment, response))
    }
    
    /// Verifies a Schnorr signature
    pub fn verify_signature(
        public_key: &[u8],
        message: &[u8],
        proof: &SchnorrProof,
    ) -> Result<bool> {
        // Convert public key bytes to a RistrettoPoint
        let public_key_point = match CompressedRistretto::from_slice(public_key).decompress() {
            Some(point) => point,
            None => return Ok(false),
        };
        let compressed_public_key = public_key_point.compress();
        
        // Create a transcript for this signature
        let mut transcript = create_transcript(b"schnorr_signature");
        transcript.append_message(b"domain", b"message_signature");
        transcript.append_message(b"public_key", compressed_public_key.as_bytes());
        transcript.append_message(b"message", message);
        transcript.append_message(b"commitment", proof.commitment.as_bytes());
        
        // Calculate challenge c = H(R || P || message)
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        
        // Verify that z*G = R + c*P
        let left = proof.response * RISTRETTO_BASEPOINT_POINT;
        let right_commitment = match proof.commitment.decompress() {
            Some(point) => point,
            None => return Ok(false),
        };
        let right = right_commitment + (challenge * public_key_point);
        
        Ok(left == right)
    }
}

impl ProofSystem<SchnorrParams, SchnorrProof> for SchnorrProofSystem {
    fn verify(params: &SchnorrParams, proof: &SchnorrProof) -> Result<bool> {
        // Convert public key to bytes
        let public_key_bytes = params.public_key.as_bytes();
        
        // Create a transcript for this proof
        let mut transcript = create_transcript(b"schnorr_proof");
        transcript.append_message(b"domain", &params.domain);
        transcript.append_message(b"public_key", &public_key_bytes);
        transcript.append_message(b"commitment", proof.commitment.as_bytes());
        
        // Calculate challenge c = H(R || P)
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        
        // Verify that z*G = R + c*P
        let left = proof.response * RISTRETTO_BASEPOINT_POINT;
        
        let right_commitment = match proof.commitment.decompress() {
            Some(point) => point,
            None => return Ok(false),
        };
        
        let public_key_point = match params.public_key.decompress() {
            Some(point) => point,
            None => return Ok(false),
        };
        
        let right = right_commitment + (challenge * public_key_point);
        
        Ok(left == right)
    }
}

/// Hash data to a scalar
fn hash_to_scalar(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    let mut result = [0u8; 64];
    result.copy_from_slice(&hash);
    result
}

/// Extract a 32-byte array from a slice
fn extract_32_bytes(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 32 {
        return Err(AevorError::crypto(
            "Invalid data length".into(),
            format!("Expected at least 32 bytes, got {}", data.len()),
            None,
        ));
    }
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&data[..32]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_schnorr_proof_of_knowledge() {
        let mut rng = OsRng;
        
        // Generate a secret key
        let secret_key = Scalar::random(&mut rng);
        
        // Calculate the public key
        let public_key = (secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Create a proof of knowledge of the secret key
        let proof = SchnorrProofSystem::prove_knowledge_of_secret_key(
            &mut rng,
            &secret_key,
            public_key.as_bytes(),
        ).unwrap();
        
        // Verify the proof
        let result = SchnorrProofSystem::verify_knowledge_of_secret_key(
            public_key.as_bytes(),
            &proof,
        ).unwrap();
        
        assert!(result);
        
        // Verify with the wrong public key
        let wrong_secret_key = Scalar::random(&mut rng);
        let wrong_public_key = (wrong_secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        let result = SchnorrProofSystem::verify_knowledge_of_secret_key(
            wrong_public_key.as_bytes(),
            &proof,
        ).unwrap();
        
        assert!(!result);
    }
    
    #[test]
    fn test_schnorr_signature() {
        let mut rng = OsRng;
        
        // Generate a secret key
        let secret_key = Scalar::random(&mut rng);
        
        // Calculate the public key
        let public_key = (secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Message to sign
        let message = b"Aevor blockchain";
        
        // Create a signature
        let signature = SchnorrProofSystem::sign(
            &mut rng,
            &secret_key,
            message,
        ).unwrap();
        
        // Verify the signature
        let result = SchnorrProofSystem::verify_signature(
            public_key.as_bytes(),
            message,
            &signature,
        ).unwrap();
        
        assert!(result);
        
        // Verify with a different message
        let different_message = b"Different message";
        
        let result = SchnorrProofSystem::verify_signature(
            public_key.as_bytes(),
            different_message,
            &signature,
        ).unwrap();
        
        assert!(!result);
        
        // Verify with a different public key
        let wrong_secret_key = Scalar::random(&mut rng);
        let wrong_public_key = (wrong_secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        let result = SchnorrProofSystem::verify_signature(
            wrong_public_key.as_bytes(),
            message,
            &signature,
        ).unwrap();
        
        assert!(!result);
    }
    
    #[test]
    fn test_schnorr_proof_serialization() {
        let mut rng = OsRng;
        
        // Generate a secret key
        let secret_key = Scalar::random(&mut rng);
        
        // Calculate the public key
        let public_key = (secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Create a proof of knowledge of the secret key
        let proof = SchnorrProofSystem::prove_knowledge_of_secret_key(
            &mut rng,
            &secret_key,
            public_key.as_bytes(),
        ).unwrap();
        
        // Serialize the proof
        let serialized = proof.to_bytes().unwrap();
        
        // Deserialize the proof
        let deserialized = SchnorrProof::from_bytes(&serialized).unwrap();
        
        // Verify the deserialized proof
        let result = SchnorrProofSystem::verify_knowledge_of_secret_key(
            public_key.as_bytes(),
            &deserialized,
        ).unwrap();
        
        assert!(result);
    }
    
    #[test]
    fn test_schnorr_params() {
        let mut rng = OsRng;
        
        // Generate a secret key
        let secret_key = Scalar::random(&mut rng);
        
        // Calculate the public key
        let public_key = (secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Create domain separator
        let domain = [0u8; 32];
        
        // Create parameters
        let params = SchnorrParams::new(public_key, domain);
        
        // Serialize the parameters
        let serialized = params.to_bytes().unwrap();
        
        // Deserialize the parameters
        let deserialized = SchnorrParams::from_bytes(&serialized).unwrap();
        
        // Check that the deserialized parameters match the original
        assert_eq!(params.public_key.as_bytes(), deserialized.public_key.as_bytes());
        assert_eq!(params.domain, deserialized.domain);
    }
    
    #[test]
    fn test_proof_system_trait() {
        let mut rng = OsRng;
        
        // Generate a secret key
        let secret_key = Scalar::random(&mut rng);
        
        // Calculate the public key
        let public_key = (secret_key * RISTRETTO_BASEPOINT_POINT).compress();
        
        // Create domain separator
        let domain = [0u8; 32];
        
        // Create parameters
        let params = SchnorrParams::new(public_key, domain);
        
        // Create a proof of knowledge of the secret key
        let proof = SchnorrProofSystem::prove_knowledge_of_secret_key(
            &mut rng,
            &secret_key,
            public_key.as_bytes(),
        ).unwrap();
        
        // Verify using the ProofSystem trait
        let result = SchnorrProofSystem::verify(&params, &proof).unwrap();
        
        assert!(result);
    }
}
