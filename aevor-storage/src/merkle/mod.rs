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
    pub fn new() -> Self { Self { tree: SparseMerkleTree::new() } }

    pub fn insert(&mut self, key: StorageKey, value: StorageValue) {
        self.tree.insert(key, value);
    }

    pub fn root(&self) -> MerkleRoot { self.tree.root() }

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
