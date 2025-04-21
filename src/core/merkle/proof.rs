use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm};

/// Represents a Merkle proof for verifying inclusion of a leaf in a Merkle tree
#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Proof nodes (sibling hashes along the path)
    proof_nodes: Vec<Vec<u8>>,
    
    /// Hash of the leaf being proven
    leaf_hash: Vec<u8>,
    
    /// Index of the leaf in the tree
    leaf_index: usize,
}

impl MerkleProof {
    /// Creates a new Merkle proof
    pub fn new(proof_nodes: Vec<Vec<u8>>, leaf_hash: Vec<u8>, leaf_index: usize) -> Self {
        Self {
            proof_nodes,
            leaf_hash,
            leaf_index,
        }
    }
    
    /// Gets the proof nodes
    pub fn proof_nodes(&self) -> &[Vec<u8>] {
        &self.proof_nodes
    }
    
    /// Gets the leaf hash
    pub fn leaf_hash(&self) -> &Vec<u8> {
        &self.leaf_hash
    }
    
    /// Gets the leaf index
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }
    
    /// Calculates the root hash using the proof
    pub fn calculate_root(&self) -> Vec<u8> {
        // If we have an empty proof, return the leaf hash as the root
        if self.proof_nodes.is_empty() {
            return self.leaf_hash.clone();
        }
        
        let mut current_hash = self.leaf_hash.clone();
        let mut current_index = self.leaf_index;
        
        // For each level in the proof, combine the current hash with the sibling
        for sibling in &self.proof_nodes {
            let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
            
            // Determine if the current hash is the left or right child
            if current_index % 2 == 0 {
                // Current hash is left child, sibling is right child
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                // Current hash is right child, sibling is left child
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            
            // Update the current hash for the next level
            current_hash = hasher.finalize().to_vec();
            
            // Update the current index for the next level
            current_index /= 2;
        }
        
        current_hash
    }
    
    /// Verifies the proof against a known root hash
    pub fn verify(&self, root_hash: &[u8]) -> bool {
        let calculated_root = self.calculate_root();
        calculated_root == root_hash
    }
    
    /// Gets the number of nodes in the proof
    pub fn proof_size(&self) -> usize {
        self.proof_nodes.len()
    }
    
    /// Check if this is an empty proof (no proof nodes)
    pub fn is_empty(&self) -> bool {
        self.proof_nodes.is_empty()
    }
}

impl fmt::Debug for MerkleProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleProof")
            .field("leaf_hash", &hex::encode(&self.leaf_hash))
            .field("leaf_index", &self.leaf_index)
            .field("proof_size", &self.proof_nodes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::merkle::calculate_merkle_root;
    
    #[test]
    fn test_merkle_proof_empty() {
        // Test with a single leaf (empty proof)
        let leaf_hash = vec![1; 32];
        let proof = MerkleProof::new(Vec::new(), leaf_hash.clone(), 0);
        
        // With a single leaf, the root is the leaf hash
        let root = leaf_hash.clone();
        assert!(proof.verify(&root));
        
        // Calculate the root manually
        let calculated_root = proof.calculate_root();
        assert_eq!(calculated_root, leaf_hash);
    }
    
    #[test]
    fn test_merkle_proof_simple() {
        // Create a simple tree with two leaves
        let leaf1 = vec![1; 32];
        let leaf2 = vec![2; 32];
        let leaves = vec![leaf1.clone(), leaf2.clone()];
        
        // Calculate the root
        let root = calculate_merkle_root(&leaves);
        
        // Create proofs for both leaves
        let proof1 = MerkleProof::new(vec![leaf2.clone()], leaf1.clone(), 0);
        let proof2 = MerkleProof::new(vec![leaf1.clone()], leaf2.clone(), 1);
        
        // Verify both proofs
        assert!(proof1.verify(&root));
        assert!(proof2.verify(&root));
        
        // Verify the calculated roots
        assert_eq!(proof1.calculate_root(), root);
        assert_eq!(proof2.calculate_root(), root);
    }
    
    #[test]
    fn test_merkle_proof_four_leaves() {
        // Create a tree with four leaves
        let leaf1 = vec![1; 32];
        let leaf2 = vec![2; 32];
        let leaf3 = vec![3; 32];
        let leaf4 = vec![4; 32];
        let leaves = vec![leaf1.clone(), leaf2.clone(), leaf3.clone(), leaf4.clone()];
        
        // Calculate the root
        let root = calculate_merkle_root(&leaves);
        
        // Calculate intermediate nodes
        let node1 = {
            let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
            hasher.update(&leaf1);
            hasher.update(&leaf2);
            hasher.finalize().to_vec()
        };
        
        let node2 = {
            let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
            hasher.update(&leaf3);
            hasher.update(&leaf4);
            hasher.finalize().to_vec()
        };
        
        // Create proofs for each leaf
        let proof1 = MerkleProof::new(vec![leaf2.clone(), node2.clone()], leaf1.clone(), 0);
        let proof2 = MerkleProof::new(vec![leaf1.clone(), node2.clone()], leaf2.clone(), 1);
        let proof3 = MerkleProof::new(vec![leaf4.clone(), node1.clone()], leaf3.clone(), 2);
        let proof4 = MerkleProof::new(vec![leaf3.clone(), node1.clone()], leaf4.clone(), 3);
        
        // Verify all proofs
        assert!(proof1.verify(&root));
        assert!(proof2.verify(&root));
        assert!(proof3.verify(&root));
        assert!(proof4.verify(&root));
        
        // Check proof sizes
        assert_eq!(proof1.proof_size(), 2);
        assert_eq!(proof2.proof_size(), 2);
        assert_eq!(proof3.proof_size(), 2);
        assert_eq!(proof4.proof_size(), 2);
        
        // Verify calculated roots
        assert_eq!(proof1.calculate_root(), root);
        assert_eq!(proof2.calculate_root(), root);
        assert_eq!(proof3.calculate_root(), root);
        assert_eq!(proof4.calculate_root(), root);
    }
    
    #[test]
    fn test_merkle_proof_invalid() {
        // Create a simple tree with two leaves
        let leaf1 = vec![1; 32];
        let leaf2 = vec![2; 32];
        let leaves = vec![leaf1.clone(), leaf2.clone()];
        
        // Calculate the root
        let root = calculate_merkle_root(&leaves);
        
        // Create a valid proof
        let proof = MerkleProof::new(vec![leaf2.clone()], leaf1.clone(), 0);
        assert!(proof.verify(&root));
        
        // Create an invalid proof by changing the leaf hash
        let different_leaf = vec![3; 32];
        let invalid_proof = MerkleProof::new(vec![leaf2.clone()], different_leaf, 0);
        assert!(!invalid_proof.verify(&root));
        
        // Create an invalid proof by changing the sibling
        let different_sibling = vec![4; 32];
        let invalid_proof = MerkleProof::new(vec![different_sibling], leaf1.clone(), 0);
        assert!(!invalid_proof.verify(&root));
        
        // Create an invalid proof by changing the leaf index
        let invalid_proof = MerkleProof::new(vec![leaf2.clone()], leaf1.clone(), 1);
        assert!(!invalid_proof.verify(&root));
        
        // Check against a different root
        let different_root = vec![5; 32];
        assert!(!proof.verify(&different_root));
    }
    
    #[test]
    fn test_merkle_proof_odd_nodes() {
        // Create a tree with three leaves
        let leaf1 = vec![1; 32];
        let leaf2 = vec![2; 32];
        let leaf3 = vec![3; 32];
        let leaves = vec![leaf1.clone(), leaf2.clone(), leaf3.clone()];
        
        // Calculate the root
        let root = calculate_merkle_root(&leaves);
        
        // For odd number of leaves:
        // Level 1: [leaf1, leaf2, leaf3]
        // Level 2: [node1, node2]  where node1 = hash(leaf1, leaf2) and node2 = hash(leaf3, leaf3)
        // Level 3: [root]  where root = hash(node1, node2)
        
        let node1 = {
            let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
            hasher.update(&leaf1);
            hasher.update(&leaf2);
            hasher.finalize().to_vec()
        };
        
        let node2 = {
            let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
            hasher.update(&leaf3);
            hasher.update(&leaf3); // Duplicate for odd number
            hasher.finalize().to_vec()
        };
        
        // Create proof for leaf3
        let proof3 = MerkleProof::new(vec![leaf3.clone(), node1.clone()], leaf3.clone(), 2);
        assert!(proof3.verify(&root));
    }
}
