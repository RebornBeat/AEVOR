use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::error::{AevorError, Result};

use super::{calculate_merkle_root, is_power_of_two, next_power_of_two, MerkleProof};

/// Represents a Merkle tree for efficient state verification
#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Root hash of the tree
    root: Vec<u8>,
    
    /// Leaf nodes (hashes)
    leaves: Vec<Vec<u8>>,
    
    /// Internal nodes for path verification
    nodes: Vec<Vec<Vec<u8>>>,
}

impl MerkleTree {
    /// Creates a new Merkle tree from leaf data
    pub fn from_leaves(leaves: Vec<Vec<u8>>) -> Self {
        if leaves.is_empty() {
            // Empty tree
            return Self {
                root: vec![0; 32],
                leaves: Vec::new(),
                nodes: Vec::new(),
            };
        }
        
        if leaves.len() == 1 {
            // Single leaf tree
            return Self {
                root: leaves[0].clone(),
                leaves,
                nodes: Vec::new(),
            };
        }
        
        // Create a copy of the leaves to work with
        let mut current_level = leaves.clone();
        let mut nodes = Vec::new();
        
        // If the number of leaves is not a power of two, pad with duplicates of the last leaf
        let leaf_count = next_power_of_two(leaves.len());
        while current_level.len() < leaf_count {
            current_level.push(current_level.last().unwrap().clone());
        }
        
        // Build the tree bottom-up
        while current_level.len() > 1 {
            nodes.push(current_level.clone());
            
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = &current_level[i + 1];
                
                let mut hasher = CryptoHash::new_hasher(HashAlgorithm::SHA256);
                hasher.update(left);
                hasher.update(right);
                
                next_level.push(hasher.finalize().to_vec());
            }
            
            current_level = next_level;
        }
        
        // The final level contains just the root
        let root = current_level[0].clone();
        
        Self {
            root,
            leaves,
            nodes,
        }
    }
    
    /// Creates a new Merkle tree from data that can be hashed
    pub fn from_data<T: Hashable>(data: &[T]) -> Self {
        let leaves: Vec<Vec<u8>> = data
            .iter()
            .map(|item| item.hash_with_algorithm(HashAlgorithm::SHA256).value)
            .collect();
        
        Self::from_leaves(leaves)
    }
    
    /// Gets the root hash of the tree
    pub fn root(&self) -> &[u8] {
        &self.root
    }
    
    /// Gets the number of leaves in the tree
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
    
    /// Gets all leaf hashes
    pub fn leaves(&self) -> &[Vec<u8>] {
        &self.leaves
    }
    
    /// Checks if the tree contains a specific leaf value
    pub fn contains(&self, value: &[u8]) -> bool {
        self.leaves.iter().any(|leaf| leaf == value)
    }
    
    /// Gets the index of a leaf value
    pub fn index_of(&self, value: &[u8]) -> Option<usize> {
        self.leaves.iter().position(|leaf| leaf == value)
    }
    
    /// Generates a proof for a specific leaf index
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(AevorError::validation(format!("Leaf index {} out of bounds", leaf_index)));
        }
        
        // If we have a single leaf or empty tree, return an empty proof
        if self.leaves.len() <= 1 {
            return Ok(MerkleProof::new(Vec::new(), self.leaves[leaf_index].clone(), leaf_index));
        }
        
        let mut proof_nodes = Vec::new();
        let mut current_index = leaf_index;
        
        // For each level in the tree, add the sibling node to the proof
        for level in 0..self.nodes.len() {
            let level_nodes = &self.nodes[level];
            
            // Calculate the sibling index
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            // Check if the sibling index is valid
            if sibling_index < level_nodes.len() {
                proof_nodes.push(level_nodes[sibling_index].clone());
            }
            
            // Update the current index for the next level
            current_index /= 2;
        }
        
        Ok(MerkleProof::new(proof_nodes, self.leaves[leaf_index].clone(), leaf_index))
    }
    
    /// Generates a proof for a specific leaf value
    pub fn generate_proof_for_value(&self, value: &[u8]) -> Result<MerkleProof> {
        match self.index_of(value) {
            Some(index) => self.generate_proof(index),
            None => Err(AevorError::validation("Value not found in tree")),
        }
    }
    
    /// Verifies a Merkle proof against the tree's root
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        proof.verify(&self.root)
    }
    
    /// Updates a leaf and recalculates the affected paths
    pub fn update_leaf(&mut self, leaf_index: usize, new_value: Vec<u8>) -> Result<()> {
        if leaf_index >= self.leaves.len() {
            return Err(AevorError::validation(format!("Leaf index {} out of bounds", leaf_index)));
        }
        
        // Update the leaf
        self.leaves[leaf_index] = new_value;
        
        // Recalculate the tree
        *self = Self::from_leaves(self.leaves.clone());
        
        Ok(())
    }
    
    /// Adds a new leaf to the tree and recalculates the root
    pub fn add_leaf(&mut self, value: Vec<u8>) {
        self.leaves.push(value);
        *self = Self::from_leaves(self.leaves.clone());
    }
    
    /// Gets a structured JSON representation of the tree
    pub fn to_json(&self) -> serde_json::Value {
        let mut levels = Vec::new();
        
        // Add the leaves level
        levels.push(self.leaves.iter().map(hex::encode).collect::<Vec<_>>());
        
        // Add each internal node level
        for level in &self.nodes {
            levels.push(level.iter().map(hex::encode).collect::<Vec<_>>());
        }
        
        // Add the root as the final level
        levels.push(vec![hex::encode(&self.root)]);
        
        serde_json::json!({
            "root": hex::encode(&self.root),
            "leaf_count": self.leaves.len(),
            "levels": levels,
        })
    }
}

impl fmt::Debug for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleTree")
            .field("root", &hex::encode(&self.root))
            .field("leaf_count", &self.leaves.len())
            .field("height", &self.nodes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_tree_from_leaves() {
        // Create some test leaves
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let tree = MerkleTree::from_leaves(leaves.clone());
        
        // Check that the tree has the correct leaves
        assert_eq!(tree.leaves(), &leaves);
        assert_eq!(tree.leaf_count(), 4);
        
        // Check that the root is calculated correctly
        let expected_root = calculate_merkle_root(&leaves);
        assert_eq!(tree.root(), &expected_root);
    }
    
    #[test]
    fn test_merkle_tree_from_data() {
        // Create some test data
        #[derive(Debug, Clone)]
        struct TestData(u8);
        
        impl Hashable for TestData {
            fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
                let mut hasher = CryptoHash::new_hasher(algorithm);
                hasher.update(&[self.0]);
                CryptoHash::new(algorithm, hasher.finalize())
            }
        }
        
        let data = vec![
            TestData(1),
            TestData(2),
            TestData(3),
            TestData(4),
        ];
        
        let tree = MerkleTree::from_data(&data);
        
        // Check that the tree has the correct number of leaves
        assert_eq!(tree.leaf_count(), 4);
        
        // The leaves should be the hashes of the data
        let expected_leaves: Vec<Vec<u8>> = data.iter()
            .map(|item| item.hash_with_algorithm(HashAlgorithm::SHA256).value)
            .collect();
        
        assert_eq!(tree.leaves(), &expected_leaves);
    }
    
    #[test]
    fn test_merkle_tree_contains() {
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let tree = MerkleTree::from_leaves(leaves.clone());
        
        // Check if tree contains existing leaves
        assert!(tree.contains(&leaves[0]));
        assert!(tree.contains(&leaves[1]));
        assert!(tree.contains(&leaves[2]));
        assert!(tree.contains(&leaves[3]));
        
        // Check if tree doesn't contain non-existing leaf
        assert!(!tree.contains(&vec![5; 32]));
    }
    
    #[test]
    fn test_merkle_tree_generate_proof() {
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let tree = MerkleTree::from_leaves(leaves.clone());
        
        // Generate a proof for each leaf
        for i in 0..leaves.len() {
            let proof = tree.generate_proof(i).unwrap();
            
            // Verify the proof against the tree's root
            assert!(tree.verify_proof(&proof));
            
            // Verify the proof manually
            assert!(proof.verify(&tree.root()));
            
            // Check that the proof's leaf hash matches
            assert_eq!(proof.leaf_hash(), &leaves[i]);
        }
        
        // Test with invalid leaf index
        assert!(tree.generate_proof(leaves.len()).is_err());
    }
    
    #[test]
    fn test_merkle_tree_generate_proof_for_value() {
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let tree = MerkleTree::from_leaves(leaves.clone());
        
        // Generate a proof for an existing value
        let proof = tree.generate_proof_for_value(&leaves[2]).unwrap();
        assert!(tree.verify_proof(&proof));
        
        // Try to generate a proof for a non-existing value
        assert!(tree.generate_proof_for_value(&vec![5; 32]).is_err());
    }
    
    #[test]
    fn test_merkle_tree_update_leaf() {
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let mut tree = MerkleTree::from_leaves(leaves.clone());
        let original_root = tree.root().to_vec();
        
        // Update a leaf
        let new_leaf = vec![5; 32];
        tree.update_leaf(2, new_leaf.clone()).unwrap();
        
        // Check that the leaf was updated
        assert_eq!(tree.leaves()[2], new_leaf);
        
        // Check that the root hash changed
        assert_ne!(tree.root(), &original_root);
        
        // Test with invalid leaf index
        assert!(tree.update_leaf(leaves.len(), vec![6; 32]).is_err());
    }
    
    #[test]
    fn test_merkle_tree_add_leaf() {
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let mut tree = MerkleTree::from_leaves(leaves.clone());
        let original_root = tree.root().to_vec();
        
        // Add a new leaf
        let new_leaf = vec![5; 32];
        tree.add_leaf(new_leaf.clone());
        
        // Check that the new leaf was added
        assert_eq!(tree.leaf_count(), leaves.len() + 1);
        assert_eq!(tree.leaves()[leaves.len()], new_leaf);
        
        // Check that the root hash changed
        assert_ne!(tree.root(), &original_root);
    }
    
    #[test]
    fn test_merkle_tree_edge_cases() {
        // Empty tree
        let empty_tree = MerkleTree::from_leaves(Vec::new());
        assert_eq!(empty_tree.leaf_count(), 0);
        assert_eq!(empty_tree.root(), &vec![0; 32]);
        
        // Single leaf tree
        let single_leaf = vec![1; 32];
        let single_tree = MerkleTree::from_leaves(vec![single_leaf.clone()]);
        assert_eq!(single_tree.leaf_count(), 1);
        assert_eq!(single_tree.root(), &single_leaf);
        
        // Test with non-power-of-two number of leaves
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
        ];
        
        let tree = MerkleTree::from_leaves(leaves.clone());
        assert_eq!(tree.leaf_count(), 3);
        
        // Root should match manual calculation
        let expected_root = calculate_merkle_root(&leaves);
        assert_eq!(tree.root(), &expected_root);
    }
    
    #[test]
    fn test_merkle_tree_proof_invalid() {
        let leaves = vec![
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![4; 32],
        ];
        
        let tree = MerkleTree::from_leaves(leaves.clone());
        
        // Generate a valid proof
        let proof = tree.generate_proof(1).unwrap();
        assert!(tree.verify_proof(&proof));
        
        // Create an invalid proof by changing the leaf hash
        let mut invalid_proof = proof.clone();
        let different_leaf = vec![5; 32];
        
        let invalid_proof = MerkleProof::new(
            proof.proof_nodes().to_vec(),
            different_leaf,
            proof.leaf_index(),
        );
        
        // This should fail verification
        assert!(!tree.verify_proof(&invalid_proof));
    }
}
