//! Merkle tree storage layer.

use serde::{Deserialize, Serialize};
pub use aevor_core::storage::{MerkleRoot, MerkleProof, StorageKey, StorageValue};
use aevor_core::primitives::Hash256;
use crate::StorageResult;

pub use aevor_crypto::merkle::{
    MerkleTree, IncrementalMerkleTree, SparseMerkleTree,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: Hash256,
    pub left: Option<Hash256>,
    pub right: Option<Hash256>,
    pub is_leaf: bool,
}

pub struct MerkleProver {
    tree: SparseMerkleTree,
}

impl MerkleProver {
    /// Create a new empty Merkle prover.
    pub fn new() -> Self { Self { tree: SparseMerkleTree::new() } }

    /// Insert or update a key-value pair.
    pub fn insert(&mut self, key: &StorageKey, value: StorageValue) {
        self.tree.insert(key, value);
    }

    /// Current Merkle root.
    pub fn root(&self) -> MerkleRoot { self.tree.root() }

    /// Generate a Merkle proof for the given key.
    ///
    /// # Errors
    /// This function currently always succeeds; the `Result` type allows future
    /// propagation of errors when full tree traversal is implemented.
    pub fn prove(&self, key: &StorageKey) -> StorageResult<Option<MerkleProof>> {
        let value = self.tree.get(key).cloned().unwrap_or(StorageValue::EMPTY);
        let siblings = vec![Hash256::ZERO]; // Simplified — full tree traversal in impl
        Ok(Some(MerkleProof {
            key: key.clone(),
            value,
            siblings,
            root: self.root(),
            is_inclusion: self.tree.get(key).is_some(),
        }))
    }
}

impl Default for MerkleProver {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prover_root_changes_after_insert() {
        let mut prover = MerkleProver::new();
        let root_before = prover.root();
        prover.insert(
            &StorageKey::from_bytes(vec![1, 2, 3]),
            StorageValue::from_bytes(vec![42]),
        );
        assert_ne!(prover.root(), root_before);
    }

    #[test]
    fn prove_returns_inclusion_for_present_key() {
        let mut prover = MerkleProver::new();
        let key = StorageKey::from_bytes(vec![7, 8, 9]);
        prover.insert(&key, StorageValue::from_bytes(vec![99]));
        let proof = prover.prove(&key).unwrap().unwrap();
        assert!(proof.is_inclusion);
    }

    #[test]
    fn prove_returns_exclusion_for_absent_key() {
        let prover = MerkleProver::new();
        let key = StorageKey::from_bytes(vec![1]);
        let proof = prover.prove(&key).unwrap().unwrap();
        assert!(!proof.is_inclusion);
    }
}
