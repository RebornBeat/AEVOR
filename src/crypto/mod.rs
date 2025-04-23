// Aevor Cryptography Module
// 
// This module provides cryptographic primitives used throughout the Aevor blockchain,
// including digital signatures, hashing, encryption, key management, and zero-knowledge proofs.
// These components are crucial for the security of the consensus mechanism and the integrity
// of transactions and blocks.

pub mod bls;
pub mod encryption;
pub mod hash;
pub mod keys;
pub mod signature;
pub mod zk_proofs;

use crate::error::{AevorError, Result};

/// Cryptographic hash algorithms supported by Aevor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 hash algorithm
    SHA256,
    
    /// SHA-512 hash algorithm
    SHA512,
    
    /// BLAKE3 hash algorithm (preferred for most operations)
    BLAKE3,
    
    /// Keccak-256 hash algorithm (Ethereum compatibility)
    Keccak256,
}

/// Signature algorithms supported by Aevor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Ed25519 signature algorithm
    ED25519,
    
    /// Secp256k1 signature algorithm (Ethereum compatibility)
    Secp256k1,
    
    /// BLS signature algorithm (for aggregation)
    BLS12_381,
}

/// Encryption algorithms supported by Aevor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-256 in GCM mode
    AES256GCM,
    
    /// ChaCha20-Poly1305
    CHACHA20POLY1305,
    
    /// X25519-XSalsa20-Poly1305 (libsodium box)
    X25519,
}

/// Zero-knowledge proof schemes supported by Aevor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProofScheme {
    /// Schnorr proofs for knowledge of discrete logarithm
    Schnorr,
    
    /// Bulletproofs for range proofs
    Bulletproof,
    
    /// zk-SNARKs using Groth16
    Groth16,
    
    /// zk-STARKs
    STARK,
}

/// Represents a cryptographic random source
pub trait RandomSource {
    /// Fills the provided buffer with random bytes
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<()>;
    
    /// Generates a random 32-byte value
    fn random_32_bytes(&self) -> Result<[u8; 32]>;
    
    /// Generates a random value in the range [0, n)
    fn random_u64(&self, n: u64) -> Result<u64>;
}

/// Secure random source implementation using OS random number generator
pub struct SecureRandom;

impl SecureRandom {
    /// Creates a new secure random source
    pub fn new() -> Self {
        Self {}
    }
}

impl RandomSource for SecureRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), dest);
        Ok(())
    }
    
    fn random_32_bytes(&self) -> Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        self.fill_bytes(&mut bytes)?;
        Ok(bytes)
    }
    
    fn random_u64(&self, n: u64) -> Result<u64> {
        use rand::Rng;
        if n == 0 {
            return Err(AevorError::crypto(
                "Invalid range".into(),
                "Upper bound cannot be zero".into(),
                None,
            ));
        }
        Ok(rand::thread_rng().gen_range(0..n))
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a default secure random source
pub fn default_rng() -> impl RandomSource {
    SecureRandom::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_random() {
        let rng = SecureRandom::new();
        
        // Test fill_bytes
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        
        assert!(rng.fill_bytes(&mut bytes1).is_ok());
        assert!(rng.fill_bytes(&mut bytes2).is_ok());
        
        // Two consecutive random arrays should be different
        assert_ne!(bytes1, bytes2);
        
        // Test random_32_bytes
        let bytes1 = rng.random_32_bytes().unwrap();
        let bytes2 = rng.random_32_bytes().unwrap();
        
        assert_ne!(bytes1, bytes2);
        
        // Test random_u64
        let num1 = rng.random_u64(100).unwrap();
        let num2 = rng.random_u64(100).unwrap();
        
        // The numbers should be in range
        assert!(num1 < 100);
        assert!(num2 < 100);
        
        // Test random_u64 with invalid range
        assert!(rng.random_u64(0).is_err());
    }
    
    #[test]
    fn test_default_rng() {
        let rng = default_rng();
        
        // Test that the default RNG works
        let mut bytes = [0u8; 32];
        assert!(rng.fill_bytes(&mut bytes).is_ok());
        
        // Test that the array is not all zeros after filling
        assert_ne!(bytes, [0u8; 32]);
    }
}
