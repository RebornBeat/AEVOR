use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use std::fmt;

use crate::error::{AevorError, Result};
use crate::crypto::HashAlgorithm;

/// A cryptographic hash value
#[derive(Clone, PartialEq, Eq)]
pub struct Hash {
    /// The hash algorithm used
    pub algorithm: HashAlgorithm,
    
    /// The hash value as bytes
    pub value: Vec<u8>,
}

impl Hash {
    /// Creates a new hash with the given algorithm and value
    pub fn new(algorithm: HashAlgorithm, value: Vec<u8>) -> Self {
        Self { algorithm, value }
    }
    
    /// Creates a new hash from a byte array and algorithm
    pub fn from_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Self {
        Self {
            algorithm,
            value: bytes.to_vec(),
        }
    }
    
    /// Creates a new hasher for the given algorithm
    pub fn new_hasher(algorithm: HashAlgorithm) -> Box<dyn HashDigest> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(Sha256Digest::new()),
            HashAlgorithm::SHA512 => Box::new(Sha512Digest::new()),
            HashAlgorithm::BLAKE3 => Box::new(Blake3Digest::new()),
            HashAlgorithm::Keccak256 => Box::new(Keccak256Digest::new()),
        }
    }
    
    /// Hashes the given data with the specified algorithm
    pub fn hash_with_algorithm(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let mut hasher = Self::new_hasher(algorithm);
        hasher.update(data);
        Self::new(algorithm, hasher.finalize())
    }
    
    /// Hashes the given data with SHA-256
    pub fn sha256(data: &[u8]) -> Self {
        Self::hash_with_algorithm(HashAlgorithm::SHA256, data)
    }
    
    /// Hashes the given data with SHA-512
    pub fn sha512(data: &[u8]) -> Self {
        Self::hash_with_algorithm(HashAlgorithm::SHA512, data)
    }
    
    /// Hashes the given data with BLAKE3
    pub fn blake3(data: &[u8]) -> Self {
        Self::hash_with_algorithm(HashAlgorithm::BLAKE3, data)
    }
    
    /// Hashes the given data with Keccak-256
    pub fn keccak256(data: &[u8]) -> Self {
        Self::hash_with_algorithm(HashAlgorithm::Keccak256, data)
    }
    
    /// Verifies that this hash matches the hash of the given data
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Hash::hash_with_algorithm(self.algorithm, data);
        self.value == computed.value
    }
    
    /// Converts the hash to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.value)
    }
    
    /// Creates a hash from a hexadecimal string
    pub fn from_hex(algorithm: HashAlgorithm, hex_str: &str) -> Result<Self> {
        let value = hex::decode(hex_str)
            .map_err(|e| AevorError::crypto(
                "Invalid hex string".into(),
                e.to_string(),
                None,
            ))?;
        
        Ok(Self { algorithm, value })
    }
    
    /// Gets the size of the hash in bytes
    pub fn size(&self) -> usize {
        self.value.len()
    }
    
    /// Checks if this hash is the zero hash (all zeros)
    pub fn is_zero(&self) -> bool {
        self.value.iter().all(|&b| b == 0)
    }
    
    /// Creates a zero hash with the given algorithm
    pub fn zero(algorithm: HashAlgorithm) -> Self {
        let size = match algorithm {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA512 => 64,
            HashAlgorithm::BLAKE3 => 32,
            HashAlgorithm::Keccak256 => 32,
        };
        
        Self {
            algorithm,
            value: vec![0; size],
        }
    }
    
    /// Converts the hash to a fixed-size byte array (if possible)
    pub fn to_fixed_bytes<const N: usize>(&self) -> Result<[u8; N]> {
        if self.value.len() != N {
            return Err(AevorError::crypto(
                "Hash size mismatch".into(),
                format!("Expected {} bytes, got {}", N, self.value.len()),
                None,
            ));
        }
        
        let mut result = [0u8; N];
        result.copy_from_slice(&self.value);
        Ok(result)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({:?}, {})", self.algorithm, self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Trait for hashable types
pub trait Hashable {
    /// Hashes this object with the specified algorithm
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> Hash;
    
    /// Hashes this object with SHA-256
    fn sha256(&self) -> Hash {
        self.hash_with_algorithm(HashAlgorithm::SHA256)
    }
    
    /// Hashes this object with SHA-512
    fn sha512(&self) -> Hash {
        self.hash_with_algorithm(HashAlgorithm::SHA512)
    }
    
    /// Hashes this object with BLAKE3
    fn blake3(&self) -> Hash {
        self.hash_with_algorithm(HashAlgorithm::BLAKE3)
    }
    
    /// Hashes this object with Keccak-256
    fn keccak256(&self) -> Hash {
        self.hash_with_algorithm(HashAlgorithm::Keccak256)
    }
}

/// Implementation of Hashable for common types
impl<T: AsRef<[u8]>> Hashable for T {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> Hash {
        Hash::hash_with_algorithm(algorithm, self.as_ref())
    }
}

/// Hash digest trait for uniform hash function interface
pub trait HashDigest {
    /// Updates the hash with more data
    fn update(&mut self, data: &[u8]);
    
    /// Finalizes the hash computation and returns the result
    fn finalize(&self) -> Vec<u8>;
    
    /// Creates a new hasher of the same type
    fn reset(&mut self);
}

/// SHA-256 hash digest implementation
struct Sha256Digest {
    hasher: Sha256,
}

impl Sha256Digest {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
}

impl HashDigest for Sha256Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    
    fn finalize(&self) -> Vec<u8> {
        let mut hasher = self.hasher.clone();
        hasher.finalize().to_vec()
    }
    
    fn reset(&mut self) {
        self.hasher = Sha256::new();
    }
}

/// SHA-512 hash digest implementation
struct Sha512Digest {
    hasher: Sha512,
}

impl Sha512Digest {
    fn new() -> Self {
        Self {
            hasher: Sha512::new(),
        }
    }
}

impl HashDigest for Sha512Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    
    fn finalize(&self) -> Vec<u8> {
        let mut hasher = self.hasher.clone();
        hasher.finalize().to_vec()
    }
    
    fn reset(&mut self) {
        self.hasher = Sha512::new();
    }
}

/// BLAKE3 hash digest implementation
struct Blake3Digest {
    hasher: blake3::Hasher,
}

impl Blake3Digest {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl HashDigest for Blake3Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    
    fn finalize(&self) -> Vec<u8> {
        let output = self.hasher.finalize();
        output.as_bytes().to_vec()
    }
    
    fn reset(&mut self) {
        self.hasher = blake3::Hasher::new();
    }
}

/// Keccak-256 hash digest implementation
struct Keccak256Digest {
    hasher: Keccak256,
}

impl Keccak256Digest {
    fn new() -> Self {
        Self {
            hasher: Keccak256::new(),
        }
    }
}

impl HashDigest for Keccak256Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    
    fn finalize(&self) -> Vec<u8> {
        let mut hasher = self.hasher.clone();
        hasher.finalize().to_vec()
    }
    
    fn reset(&mut self) {
        self.hasher = Keccak256::new();
    }
}

/// Utility functions for hash operations
pub mod util {
    use super::*;
    
    /// Hashes multiple pieces of data together with the specified algorithm
    pub fn hash_multiple(algorithm: HashAlgorithm, data: &[&[u8]]) -> Hash {
        let mut hasher = Hash::new_hasher(algorithm);
        for item in data {
            hasher.update(item);
        }
        Hash::new(algorithm, hasher.finalize())
    }
    
    /// Computes a double hash of the data using the specified algorithm
    pub fn double_hash(algorithm: HashAlgorithm, data: &[u8]) -> Hash {
        let first_hash = Hash::hash_with_algorithm(algorithm, data);
        Hash::hash_with_algorithm(algorithm, &first_hash.value)
    }
    
    /// Computes the Merkle root of a list of hashes using the specified algorithm
    pub fn merkle_root(algorithm: HashAlgorithm, hashes: &[Vec<u8>]) -> Vec<u8> {
        if hashes.is_empty() {
            return vec![0; algorithm_output_size(algorithm)];
        }
        
        if hashes.len() == 1 {
            return hashes[0].clone();
        }
        
        let mut current_level = hashes.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    let mut hasher = Hash::new_hasher(algorithm);
                    hasher.update(&current_level[i]);
                    hasher.update(&current_level[i + 1]);
                    next_level.push(hasher.finalize());
                } else {
                    // If there's an odd number of elements, duplicate the last one
                    let mut hasher = Hash::new_hasher(algorithm);
                    hasher.update(&current_level[i]);
                    hasher.update(&current_level[i]);
                    next_level.push(hasher.finalize());
                }
            }
            
            current_level = next_level;
        }
        
        current_level[0].clone()
    }
    
    /// Returns the output size in bytes for the given algorithm
    pub fn algorithm_output_size(algorithm: HashAlgorithm) -> usize {
        match algorithm {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA512 => 64,
            HashAlgorithm::BLAKE3 => 32,
            HashAlgorithm::Keccak256 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_algorithms() {
        let data = b"Aevor blockchain";
        
        // Test SHA-256
        let sha256_hash = Hash::sha256(data);
        assert_eq!(sha256_hash.algorithm, HashAlgorithm::SHA256);
        assert_eq!(sha256_hash.size(), 32);
        
        // Test SHA-512
        let sha512_hash = Hash::sha512(data);
        assert_eq!(sha512_hash.algorithm, HashAlgorithm::SHA512);
        assert_eq!(sha512_hash.size(), 64);
        
        // Test BLAKE3
        let blake3_hash = Hash::blake3(data);
        assert_eq!(blake3_hash.algorithm, HashAlgorithm::BLAKE3);
        assert_eq!(blake3_hash.size(), 32);
        
        // Test Keccak-256
        let keccak_hash = Hash::keccak256(data);
        assert_eq!(keccak_hash.algorithm, HashAlgorithm::Keccak256);
        assert_eq!(keccak_hash.size(), 32);
        
        // Different algorithms should produce different hashes
        assert_ne!(sha256_hash.value, sha512_hash.value);
        assert_ne!(sha256_hash.value, blake3_hash.value);
        assert_ne!(sha256_hash.value, keccak_hash.value);
    }
    
    #[test]
    fn test_hash_verification() {
        let data = b"Aevor blockchain";
        
        // Create a hash
        let hash = Hash::sha256(data);
        
        // Verify the hash
        assert!(hash.verify(data));
        
        // Verify with different data should fail
        let different_data = b"Different data";
        assert!(!hash.verify(different_data));
    }
    
    #[test]
    fn test_hash_hex() {
        let data = b"Aevor blockchain";
        let hash = Hash::sha256(data);
        
        // Convert to hex
        let hex = hash.to_hex();
        
        // Convert back from hex
        let hash2 = Hash::from_hex(HashAlgorithm::SHA256, &hex).unwrap();
        
        // Should be the same hash
        assert_eq!(hash, hash2);
        
        // Test with invalid hex
        let result = Hash::from_hex(HashAlgorithm::SHA256, "invalid");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_zero_hash() {
        let zero_hash = Hash::zero(HashAlgorithm::SHA256);
        assert!(zero_hash.is_zero());
        assert_eq!(zero_hash.size(), 32);
        
        let zero_hash = Hash::zero(HashAlgorithm::SHA512);
        assert!(zero_hash.is_zero());
        assert_eq!(zero_hash.size(), 64);
        
        let data = b"Aevor blockchain";
        let hash = Hash::sha256(data);
        assert!(!hash.is_zero());
    }
    
    #[test]
    fn test_to_fixed_bytes() {
        let data = b"Aevor blockchain";
        let hash = Hash::sha256(data);
        
        // Convert to fixed bytes
        let bytes: [u8; 32] = hash.to_fixed_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        
        // Convert SHA-512 to fixed bytes (should fail)
        let hash = Hash::sha512(data);
        let result: Result<[u8; 32]> = hash.to_fixed_bytes();
        assert!(result.is_err());
    }
    
    #[test]
    fn test_hashable_trait() {
        let data = b"Aevor blockchain";
        
        // Test hashing with the Hashable trait
        let hash1 = data.sha256();
        let hash2 = Hash::sha256(data);
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_hash_multiple() {
        let data1 = b"Aevor";
        let data2 = b"blockchain";
        
        // Hash multiple pieces of data
        let hash1 = util::hash_multiple(HashAlgorithm::SHA256, &[data1, data2]);
        
        // Hash the concatenated data
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(data1);
        concatenated.extend_from_slice(data2);
        let hash2 = Hash::sha256(&concatenated);
        
        // Should be the same
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_double_hash() {
        let data = b"Aevor blockchain";
        
        // Double hash
        let double_hash = util::double_hash(HashAlgorithm::SHA256, data);
        
        // Compute double hash manually
        let first_hash = Hash::sha256(data);
        let second_hash = Hash::sha256(&first_hash.value);
        
        assert_eq!(double_hash, second_hash);
    }
    
    #[test]
    fn test_merkle_root() {
        // Test with empty list
        let empty_root = util::merkle_root(HashAlgorithm::SHA256, &[]);
        assert_eq!(empty_root, vec![0; 32]);
        
        // Test with single item
        let data = b"Aevor blockchain";
        let single_hash = Hash::sha256(data).value;
        let single_root = util::merkle_root(HashAlgorithm::SHA256, &[single_hash.clone()]);
        assert_eq!(single_root, single_hash);
        
        // Test with two items
        let data2 = b"Second data";
        let hash2 = Hash::sha256(data2).value;
        let hashes = vec![single_hash.clone(), hash2.clone()];
        
        let root = util::merkle_root(HashAlgorithm::SHA256, &hashes);
        
        // Compute root manually
        let mut hasher = Hash::new_hasher(HashAlgorithm::SHA256);
        hasher.update(&single_hash);
        hasher.update(&hash2);
        let expected_root = hasher.finalize();
        
        assert_eq!(root, expected_root);
    }
    
    #[test]
    fn test_algorithm_output_size() {
        assert_eq!(util::algorithm_output_size(HashAlgorithm::SHA256), 32);
        assert_eq!(util::algorithm_output_size(HashAlgorithm::SHA512), 64);
        assert_eq!(util::algorithm_output_size(HashAlgorithm::BLAKE3), 32);
        assert_eq!(util::algorithm_output_size(HashAlgorithm::Keccak256), 32);
    }
}
