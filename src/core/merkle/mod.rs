use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::error::{AevorError, Result};

mod tree;
mod proof;
mod map;

pub use tree::MerkleTree;
pub use proof::MerkleProof;
pub use map::MerkleMap;

/// Calculate the Merkle root of a list of hashes
pub fn calculate_merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    if hashes.is_empty() {
        // Return empty root for empty tree
        return vec![0; 32];
    }
    
    if hashes.len() == 1 {
        // Return single hash as the root
        return hashes[0].clone();
    }
    
    // Create a copy of the hashes to work with
    let mut current_level = hashes.to_vec();
    
    // Keep combining pairs of hashes until we have a single root
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        // Process pairs of hashes
        for i in (0..current_level.len()).step_by(2) {
            if i + 1 < current_level.len() {
                // We have a pair, combine them
                let combined = combine_hashes(&current_level[i], &current_level[i + 1]);
                next_level.push(combined);
            } else {
                // We have an odd number of hashes, duplicate the last one
                let combined = combine_hashes(&current_level[i], &current_level[i]);
                next_level.push(combined);
            }
        }
        
        current_level = next_level;
    }
    
    // Return the root hash
    current_level[0].clone()
}

/// Combine two hashes into a single hash
fn combine_hashes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// Check if a number is a power of two
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Get the next power of two greater than or equal to n
pub fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    
    if is_power_of_two(n) {
        return n;
    }
    
    let mut power = 1;
    while power < n {
        power *= 2;
    }
    
    power
}

/// Hash a key-value pair for use in a MerkleMap
pub fn hash_key_value<K, V>(key: &K, value: &V) -> Vec<u8>
where
    K: Hashable,
    V: Hashable,
{
    let key_hash = key.hash_with_algorithm(HashAlgorithm::SHA256).value;
    let value_hash = value.hash_with_algorithm(HashAlgorithm::SHA256).value;
    
    let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
    hasher.update(&key_hash);
    hasher.update(&value_hash);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_calculate_merkle_root_empty() {
        let hashes: Vec<Vec<u8>> = Vec::new();
        let root = calculate_merkle_root(&hashes);
        
        // Empty tree should have a specific root
        assert_eq!(root, vec![0; 32]);
    }
    
    #[test]
    fn test_calculate_merkle_root_single() {
        let hash = vec![1; 32];
        let hashes = vec![hash.clone()];
        let root = calculate_merkle_root(&hashes);
        
        // Single hash should be the root
        assert_eq!(root, hash);
    }
    
    #[test]
    fn test_calculate_merkle_root_pair() {
        let hash1 = vec![1; 32];
        let hash2 = vec![2; 32];
        let hashes = vec![hash1.clone(), hash2.clone()];
        
        let expected = combine_hashes(&hash1, &hash2);
        let root = calculate_merkle_root(&hashes);
        
        assert_eq!(root, expected);
    }
    
    #[test]
    fn test_calculate_merkle_root_odd() {
        let hash1 = vec![1; 32];
        let hash2 = vec![2; 32];
        let hash3 = vec![3; 32];
        let hashes = vec![hash1.clone(), hash2.clone(), hash3.clone()];
        
        // For odd number, the last one gets duplicated
        // Level 1: [hash1, hash2, hash3]
        // Level 2: [combine(hash1, hash2), combine(hash3, hash3)]
        // Level 3: [final_root]
        
        let level2_left = combine_hashes(&hash1, &hash2);
        let level2_right = combine_hashes(&hash3, &hash3);
        let expected = combine_hashes(&level2_left, &level2_right);
        
        let root = calculate_merkle_root(&hashes);
        
        assert_eq!(root, expected);
    }
    
    #[test]
    fn test_calculate_merkle_root_four() {
        let hash1 = vec![1; 32];
        let hash2 = vec![2; 32];
        let hash3 = vec![3; 32];
        let hash4 = vec![4; 32];
        let hashes = vec![hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];
        
        // Level 1: [hash1, hash2, hash3, hash4]
        // Level 2: [combine(hash1, hash2), combine(hash3, hash4)]
        // Level 3: [final_root]
        
        let level2_left = combine_hashes(&hash1, &hash2);
        let level2_right = combine_hashes(&hash3, &hash4);
        let expected = combine_hashes(&level2_left, &level2_right);
        
        let root = calculate_merkle_root(&hashes);
        
        assert_eq!(root, expected);
    }
    
    #[test]
    fn test_is_power_of_two() {
        assert!(!is_power_of_two(0));
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(!is_power_of_two(3));
        assert!(is_power_of_two(4));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(6));
        assert!(!is_power_of_two(7));
        assert!(is_power_of_two(8));
        assert!(is_power_of_two(16));
        assert!(is_power_of_two(32));
        assert!(is_power_of_two(64));
        assert!(is_power_of_two(128));
        assert!(is_power_of_two(256));
    }
    
    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(4), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(7), 8);
        assert_eq!(next_power_of_two(8), 8);
        assert_eq!(next_power_of_two(9), 16);
        assert_eq!(next_power_of_two(15), 16);
        assert_eq!(next_power_of_two(16), 16);
        assert_eq!(next_power_of_two(17), 32);
    }
    
    #[test]
    fn test_combine_hashes() {
        let hash1 = vec![1; 32];
        let hash2 = vec![2; 32];
        
        let combined = combine_hashes(&hash1, &hash2);
        
        // Ensure the combined hash is different from inputs
        assert_ne!(combined, hash1);
        assert_ne!(combined, hash2);
        
        // Ensure the same input produces the same output
        let combined2 = combine_hashes(&hash1, &hash2);
        assert_eq!(combined, combined2);
        
        // Ensure different order produces different output
        let combined3 = combine_hashes(&hash2, &hash1);
        assert_ne!(combined, combined3);
    }
    
    #[test]
    fn test_hash_key_value() {
        // Simple test using byte arrays as key and value
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];
        
        let result = hash_key_value(&key, &value);
        
        // Ensure the hash is not empty
        assert!(!result.is_empty());
        
        // Ensure the same input produces the same output
        let result2 = hash_key_value(&key, &value);
        assert_eq!(result, result2);
        
        // Ensure different inputs produce different outputs
        let key2 = vec![2, 3, 4, 5];
        let result3 = hash_key_value(&key2, &value);
        assert_ne!(result, result3);
    }
}
