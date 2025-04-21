use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::error::{AevorError, Result};

use super::{hash_key_value, MerkleProof, MerkleTree};

/// An efficient Merkle tree implementation for mapping keys to values with proofs
#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleMap<K, V>
where
    K: Clone + Eq + Hash + Hashable,
    V: Clone + Hashable,
{
    /// The underlying data map
    data: HashMap<K, V>,
    
    /// Merkle tree of key-value pairs
    tree: Option<MerkleTree>,
    
    /// Flag indicating if the tree needs to be rebuilt
    dirty: bool,
}

impl<K, V> MerkleMap<K, V>
where
    K: Clone + Eq + Hash + Hashable,
    V: Clone + Hashable,
{
    /// Creates a new empty MerkleMap
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            tree: None,
            dirty: false,
        }
    }
    
    /// Creates a new MerkleMap with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: HashMap::with_capacity(capacity),
            tree: None,
            dirty: false,
        }
    }
    
    /// Creates a new MerkleMap from an existing HashMap
    pub fn from_map(map: HashMap<K, V>) -> Self {
        let mut merkle_map = Self {
            data: map,
            tree: None,
            dirty: true,
        };
        
        // Build the tree
        merkle_map.build_tree();
        
        merkle_map
    }
    
    /// Gets the number of key-value pairs in the map
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Checks if the map is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Gets a value by key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }
    
    /// Checks if the map contains a key
    pub fn contains_key(&self, key: &K) -> bool {
        self.data.contains_key(key)
    }
    
    /// Inserts a key-value pair into the map
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let old_value = self.data.insert(key, value);
        self.dirty = true;
        old_value
    }
    
    /// Removes a key-value pair from the map
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.data.remove(key);
        if value.is_some() {
            self.dirty = true;
        }
        value
    }
    
    /// Gets all keys in the map
    pub fn keys(&self) -> Vec<K> {
        self.data.keys().cloned().collect()
    }
    
    /// Gets all values in the map
    pub fn values(&self) -> Vec<V> {
        self.data.values().cloned().collect()
    }
    
    /// Gets all key-value pairs in the map
    pub fn entries(&self) -> Vec<(K, V)> {
        self.data.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    
    /// Gets the root hash of the tree
    pub fn root(&mut self) -> Vec<u8> {
        // If the tree is dirty or doesn't exist, rebuild it
        if self.dirty || self.tree.is_none() {
            self.build_tree();
        }
        
        // If we have a tree, return its root hash
        match &self.tree {
            Some(tree) => tree.root().to_vec(),
            None => vec![0; 32], // Empty root for empty tree
        }
    }
    
    /// Rebuilds the Merkle tree
    fn build_tree(&mut self) {
        if self.data.is_empty() {
            self.tree = None;
            self.dirty = false;
            return;
        }
        
        // Generate key-value hashes
        let mut leaves = Vec::with_capacity(self.data.len());
        
        for (key, value) in &self.data {
            let leaf_hash = hash_key_value(key, value);
            leaves.push(leaf_hash);
        }
        
        // Build the tree
        self.tree = Some(MerkleTree::from_leaves(leaves));
        self.dirty = false;
    }
    
    /// Generates a proof for a specific key
    pub fn generate_proof(&mut self, key: &K) -> Result<MerkleProof> {
        if !self.contains_key(key) {
            return Err(AevorError::validation("Key not found in map"));
        }
        
        // If the tree is dirty or doesn't exist, rebuild it
        if self.dirty || self.tree.is_none() {
            self.build_tree();
        }
        
        // Get the tree
        let tree = self.tree.as_ref().ok_or_else(|| AevorError::validation("Tree is empty"))?;
        
        // Get the value
        let value = self.get(key).unwrap();
        
        // Generate the leaf hash
        let leaf_hash = hash_key_value(key, value);
        
        // Find the leaf index
        let leaf_index = tree.index_of(&leaf_hash).ok_or_else(|| AevorError::validation("Leaf not found in tree"))?;
        
        // Generate the proof
        tree.generate_proof(leaf_index)
    }
    
    /// Verifies a proof for a specific key-value pair
    pub fn verify_proof(&mut self, key: &K, value: &V, proof: &MerkleProof) -> bool {
        // If the tree is dirty or doesn't exist, rebuild it
        if self.dirty || self.tree.is_none() {
            self.build_tree();
        }
        
        // If we don't have a tree, we can't verify
        let tree = match &self.tree {
            Some(tree) => tree,
            None => return false,
        };
        
        // Generate the leaf hash
        let leaf_hash = hash_key_value(key, value);
        
        // Check if the proof is for this leaf
        if proof.leaf_hash() != &leaf_hash {
            return false;
        }
        
        // Verify the proof
        tree.verify_proof(proof)
    }
    
    /// Clears all key-value pairs from the map
    pub fn clear(&mut self) {
        self.data.clear();
        self.tree = None;
        self.dirty = false;
    }
    
    /// Updates a value for an existing key
    pub fn update(&mut self, key: &K, value: V) -> Result<()> {
        if !self.contains_key(key) {
            return Err(AevorError::validation("Key not found in map"));
        }
        
        self.data.insert(key.clone(), value);
        self.dirty = true;
        
        Ok(())
    }
    
    /// Gets the underlying data map
    pub fn data(&self) -> &HashMap<K, V> {
        &self.data
    }
    
    /// Gets the underlying Merkle tree
    pub fn tree(&mut self) -> Option<&MerkleTree> {
        if self.dirty {
            self.build_tree();
        }
        self.tree.as_ref()
    }
}

impl<K, V> fmt::Debug for MerkleMap<K, V>
where
    K: Clone + Eq + Hash + Hashable + fmt::Debug,
    V: Clone + Hashable + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleMap")
            .field("len", &self.len())
            .field("dirty", &self.dirty)
            .field("tree", &self.tree)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Test data types
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestKey(u32);
    
    #[derive(Debug, Clone, PartialEq)]
    struct TestValue(Vec<u8>);
    
    // Implement Hashable for our test types
    impl Hashable for TestKey {
        fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
            let mut hasher = CryptoHash::new_hasher(algorithm);
            hasher.update(&self.0.to_le_bytes());
            CryptoHash::new(algorithm, hasher.finalize())
        }
    }
    
    impl Hashable for TestValue {
        fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
            let mut hasher = CryptoHash::new_hasher(algorithm);
            hasher.update(&self.0);
            CryptoHash::new(algorithm, hasher.finalize())
        }
    }
    
    #[test]
    fn test_merkle_map_basics() {
        let mut map = MerkleMap::new();
        
        // Test empty map
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert_eq!(map.root(), vec![0; 32]);
        
        // Insert some key-value pairs
        let key1 = TestKey(1);
        let value1 = TestValue(vec![1, 2, 3]);
        let key2 = TestKey(2);
        let value2 = TestValue(vec![4, 5, 6]);
        
        map.insert(key1.clone(), value1.clone());
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        
        // Test get
        assert_eq!(map.get(&key1), Some(&value1));
        assert_eq!(map.get(&key2), None);
        
        // Test contains_key
        assert!(map.contains_key(&key1));
        assert!(!map.contains_key(&key2));
        
        // Insert another key-value pair
        map.insert(key2.clone(), value2.clone());
        assert_eq!(map.len(), 2);
        
        // Test keys and values
        let keys = map.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&key1));
        assert!(keys.contains(&key2));
        
        let values = map.values();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&value1));
        assert!(values.contains(&value2));
        
        // Test entries
        let entries = map.entries();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&(key1.clone(), value1.clone())));
        assert!(entries.contains(&(key2.clone(), value2.clone())));
    }
    
    #[test]
    fn test_merkle_map_root() {
        let mut map = MerkleMap::new();
        
        // Empty map should have a specific root
        let empty_root = map.root();
        assert_eq!(empty_root, vec![0; 32]);
        
        // Add a key-value pair
        let key1 = TestKey(1);
        let value1 = TestValue(vec![1, 2, 3]);
        map.insert(key1.clone(), value1.clone());
        
        // Root should change
        let root1 = map.root();
        assert_ne!(root1, empty_root);
        
        // Add another key-value pair
        let key2 = TestKey(2);
        let value2 = TestValue(vec![4, 5, 6]);
        map.insert(key2.clone(), value2.clone());
        
        // Root should change again
        let root2 = map.root();
        assert_ne!(root2, root1);
        
        // Update an existing key
        let value1_updated = TestValue(vec![7, 8, 9]);
        map.update(&key1, value1_updated.clone()).unwrap();
        
        // Root should change again
        let root3 = map.root();
        assert_ne!(root3, root2);
        
        // Remove a key
        map.remove(&key2);
        
        // Root should change again
        let root4 = map.root();
        assert_ne!(root4, root3);
        
        // Clear the map
        map.clear();
        
        // Root should be the empty root again
        let root5 = map.root();
        assert_eq!(root5, empty_root);
    }
    
    #[test]
    fn test_merkle_map_proofs() {
        let mut map = MerkleMap::new();
        
        // Add some key-value pairs
        let key1 = TestKey(1);
        let value1 = TestValue(vec![1, 2, 3]);
        let key2 = TestKey(2);
        let value2 = TestValue(vec![4, 5, 6]);
        let key3 = TestKey(3);
        let value3 = TestValue(vec![7, 8, 9]);
        
        map.insert(key1.clone(), value1.clone());
        map.insert(key2.clone(), value2.clone());
        map.insert(key3.clone(), value3.clone());
        
        // Generate and verify proofs for each key-value pair
        for (key, value) in &[(key1.clone(), value1.clone()), 
                             (key2.clone(), value2.clone()), 
                             (key3.clone(), value3.clone())] {
            // Generate proof
            let proof = map.generate_proof(key).unwrap();
            
            // Verify proof
            assert!(map.verify_proof(key, value, &proof));
            
            // Verify proof with a different value (should fail)
            let wrong_value = TestValue(vec![0, 0, 0]);
            assert!(!map.verify_proof(key, &wrong_value, &proof));
            
            // Verify proof with a different key (should fail)
            let wrong_key = TestKey(99);
            assert!(!map.verify_proof(&wrong_key, value, &proof));
        }
        
        // Try to generate a proof for a non-existent key
        let nonexistent_key = TestKey(99);
        assert!(map.generate_proof(&nonexistent_key).is_err());
    }
    
    #[test]
    fn test_merkle_map_tree_building() {
        let mut map = MerkleMap::new();
        
        // Initially no tree
        assert!(map.tree().is_none());
        
        // Add some key-value pairs
        let key1 = TestKey(1);
        let value1 = TestValue(vec![1, 2, 3]);
        let key2 = TestKey(2);
        let value2 = TestValue(vec![4, 5, 6]);
        
        map.insert(key1.clone(), value1.clone());
        map.insert(key2.clone(), value2.clone());
        
        // Tree should be built on demand
        assert!(map.tree().is_some());
        
        // Tree should have 2 leaves
        assert_eq!(map.tree().unwrap().leaf_count(), 2);
        
        // Update a value
        let value1_updated = TestValue(vec![7, 8, 9]);
        map.update(&key1, value1_updated.clone()).unwrap();
        
        // Tree should be rebuilt
        assert_eq!(map.tree().unwrap().leaf_count(), 2);
        
        // Remove a key
        map.remove(&key2);
        
        // Tree should be rebuilt
        assert_eq!(map.tree().unwrap().leaf_count(), 1);
        
        // Clear the map
        map.clear();
        
        // No tree again
        assert!(map.tree().is_none());
    }
    
    #[test]
    fn test_merkle_map_from_map() {
        // Create a HashMap
        let mut hash_map = HashMap::new();
        hash_map.insert(TestKey(1), TestValue(vec![1, 2, 3]));
        hash_map.insert(TestKey(2), TestValue(vec![4, 5, 6]));
        hash_map.insert(TestKey(3), TestValue(vec![7, 8, 9]));
        
        // Create a MerkleMap from the HashMap
        let mut merkle_map = MerkleMap::from_map(hash_map);
        
        // Check that the MerkleMap has the correct data
        assert_eq!(merkle_map.len(), 3);
        assert_eq!(merkle_map.get(&TestKey(1)), Some(&TestValue(vec![1, 2, 3])));
        assert_eq!(merkle_map.get(&TestKey(2)), Some(&TestValue(vec![4, 5, 6])));
        assert_eq!(merkle_map.get(&TestKey(3)), Some(&TestValue(vec![7, 8, 9])));
        
        // Tree should be already built
        assert!(!merkle_map.dirty);
        assert!(merkle_map.tree().is_some());
        assert_eq!(merkle_map.tree().unwrap().leaf_count(), 3);
    }
    
    #[test]
    fn test_merkle_map_with_capacity() {
        // Create a MerkleMap with capacity
        let map = MerkleMap::<TestKey, TestValue>::with_capacity(100);
        
        // The map should be empty but have the specified capacity
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        
        // We can't directly test the capacity, but we can check that the map works
        assert_eq!(map.data().capacity(), 100);
    }
    
    #[test]
    fn test_merkle_map_update() {
        let mut map = MerkleMap::new();
        
        // Add a key-value pair
        let key = TestKey(1);
        let value = TestValue(vec![1, 2, 3]);
        map.insert(key.clone(), value.clone());
        
        // Update the value
        let new_value = TestValue(vec![4, 5, 6]);
        assert!(map.update(&key, new_value.clone()).is_ok());
        
        // Check that the value was updated
        assert_eq!(map.get(&key), Some(&new_value));
        
        // Try to update a non-existent key
        let nonexistent_key = TestKey(99);
        assert!(map.update(&nonexistent_key, TestValue(vec![7, 8, 9])).is_err());
    }
}
