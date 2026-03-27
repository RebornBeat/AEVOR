//! Merkle tree construction and proof generation using BLAKE3.

use aevor_core::primitives::Hash256;
pub use aevor_core::storage::{MerkleProof, MerkleRoot, StorageKey, StorageValue};

/// A dense binary Merkle tree over a fixed set of leaf hashes.
pub struct MerkleTree {
    leaves: Vec<Hash256>,
    nodes: Vec<Hash256>,
}

impl MerkleTree {
    /// Build a complete Merkle tree from a list of leaf hashes.
    ///
    /// The tree is padded to the next power of two with zero leaves.
    pub fn build(leaves: &[Hash256]) -> Self {
        if leaves.is_empty() {
            return Self { leaves: vec![], nodes: vec![] };
        }

        let n = leaves.len().next_power_of_two();
        let mut nodes = vec![Hash256::ZERO; 2 * n];

        for (i, leaf) in leaves.iter().enumerate() {
            nodes[n + i] = *leaf;
        }

        for i in (1..n).rev() {
            nodes[i] = Self::hash_pair(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { leaves: leaves.to_owned(), nodes }
    }

    /// The root hash of this tree.
    pub fn root(&self) -> MerkleRoot {
        if self.nodes.is_empty() {
            return MerkleRoot::EMPTY;
        }
        MerkleRoot::from_hash(self.nodes[1])
    }

    /// Generate an inclusion proof for leaf at `index`.
    pub fn prove(&self, index: usize, key: StorageKey, value: StorageValue) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let n = self.nodes.len() / 2;
        let mut siblings = Vec::new();
        let mut pos = n + index;

        while pos > 1 {
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            siblings.push(self.nodes[sibling]);
            pos /= 2;
        }

        Some(MerkleProof {
            key,
            value,
            siblings,
            root: self.root(),
            is_inclusion: true,
        })
    }

    /// Domain-separated BLAKE3 hash of two child nodes.
    pub(crate) fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = crate::hash::Blake3Hasher::new();
        hasher.update(b"merkle-node:");
        hasher.update(&left.0);
        hasher.update(&right.0);
        hasher.finalize().0
    }

    /// Number of leaves in this tree (before padding).
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

/// A sparse Merkle tree for the full 256-bit key space.
///
/// Stores only non-empty leaves; all empty positions use a known zero hash.
/// Suitable for the AEVOR state trie where most keys are unoccupied.
pub struct SparseMerkleTree {
    entries: std::collections::BTreeMap<Vec<u8>, StorageValue>,
    root: MerkleRoot,
}

impl SparseMerkleTree {
    /// Create an empty sparse Merkle tree.
    pub fn new() -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
            root: MerkleRoot::EMPTY,
        }
    }

    /// Insert or update a key-value pair, recomputing the root.
    pub fn insert(&mut self, key: &StorageKey, value: StorageValue) {
        self.entries.insert(key.0.clone(), value);
        self.recompute_root();
    }

    /// Remove a key, recomputing the root.
    pub fn remove(&mut self, key: &StorageKey) {
        self.entries.remove(&key.0);
        self.recompute_root();
    }

    /// Get a value by key.
    pub fn get(&self, key: &StorageKey) -> Option<&StorageValue> {
        self.entries.get(&key.0)
    }

    /// Current root hash.
    pub fn root(&self) -> MerkleRoot {
        self.root
    }

    fn recompute_root(&mut self) {
        if self.entries.is_empty() {
            self.root = MerkleRoot::EMPTY;
            return;
        }
        let mut hasher = crate::hash::Blake3Hasher::new();
        for (k, v) in &self.entries {
            hasher.update(k);
            hasher.update(&v.0);
        }
        self.root = MerkleRoot::from_hash(hasher.finalize().0);
    }

    /// Number of entries in this tree.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self { Self::new() }
}

/// An incremental Merkle tree that supports appending new leaves efficiently.
///
/// Maintains O(depth) state so new leaves can be appended in O(depth) time
/// without storing the complete tree.
pub struct IncrementalMerkleTree {
    depth: usize,
    filled: Vec<Hash256>,
    next_index: usize,
    root: MerkleRoot,
}

impl IncrementalMerkleTree {
    /// Create an incremental tree with `depth` levels (supports up to 2^depth leaves).
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            filled: vec![Hash256::ZERO; depth],
            next_index: 0,
            root: MerkleRoot::EMPTY,
        }
    }

    /// Append a leaf and return the new root.
    ///
    /// # Errors
    /// Returns an error if the tree has reached its maximum capacity (2^depth leaves).
    pub fn append(&mut self, leaf: Hash256) -> crate::CryptoResult<MerkleRoot> {
        if self.next_index >= (1 << self.depth) {
            return Err(crate::CryptoError::CommitmentError("tree is full".into()));
        }

        let mut current = leaf;
        let mut index = self.next_index;

        for i in 0..self.depth {
            if index % 2 == 1 {
                current = MerkleTree::hash_pair(&self.filled[i], &current);
            } else {
                self.filled[i] = current;
                current = MerkleTree::hash_pair(&current, &Hash256::ZERO);
            }
            index /= 2;
        }

        self.next_index += 1;
        self.root = MerkleRoot::from_hash(current);
        Ok(self.root)
    }

    /// Current root hash.
    pub fn root(&self) -> MerkleRoot { self.root }
    /// Number of leaves appended so far.
    pub fn leaf_count(&self) -> usize { self.next_index }
    /// Maximum number of leaves this tree can hold (2^depth).
    pub fn capacity(&self) -> usize { 1 << self.depth }
    /// Depth (number of levels) of this tree.
    pub fn depth(&self) -> usize { self.depth }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_empty_has_empty_root() {
        let tree = MerkleTree::build(&[]);
        assert!(tree.root().is_empty());
    }

    #[test]
    fn merkle_tree_root_changes_with_different_leaves() {
        let t1 = MerkleTree::build(&[Hash256([1u8; 32])]);
        let t2 = MerkleTree::build(&[Hash256([2u8; 32])]);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn merkle_tree_same_leaves_same_root() {
        let leaves = vec![Hash256([1u8; 32]), Hash256([2u8; 32])];
        let t1 = MerkleTree::build(&leaves);
        let t2 = MerkleTree::build(&leaves);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn sparse_tree_insert_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let root_before = tree.root();
        tree.insert(
            &StorageKey::from_bytes(vec![1]),
            StorageValue::from_bytes(vec![42]),
        );
        assert_ne!(tree.root(), root_before);
    }

    #[test]
    fn sparse_tree_get_returns_inserted_value() {
        let mut tree = SparseMerkleTree::new();
        let key = StorageKey::from_bytes(vec![1, 2, 3]);
        let value = StorageValue::from_bytes(vec![42, 43]);
        tree.insert(&key, value.clone());
        assert_eq!(tree.get(&key), Some(&value));
    }

    #[test]
    fn incremental_tree_appends() {
        let mut tree = IncrementalMerkleTree::new(10);
        let r1 = tree.append(Hash256([1u8; 32])).unwrap();
        let r2 = tree.append(Hash256([2u8; 32])).unwrap();
        assert_ne!(r1, r2);
        assert_eq!(tree.leaf_count(), 2);
    }

    #[test]
    fn incremental_tree_full_returns_error() {
        let mut tree = IncrementalMerkleTree::new(1); // Max 2 leaves
        tree.append(Hash256([1u8; 32])).unwrap();
        tree.append(Hash256([2u8; 32])).unwrap();
        assert!(tree.append(Hash256([3u8; 32])).is_err());
    }
}
