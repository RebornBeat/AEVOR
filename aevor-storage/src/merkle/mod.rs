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

/// A real binary Merkle tree over the (sorted) key-value set, producing genuine
/// inclusion proofs and verification.
///
/// Hashing is domain-separated and commutative:
/// - leaf  = `BLAKE3(0x00 ‖ key_len ‖ key ‖ value)`
/// - node  = `BLAKE3(0x01 ‖ min(l,r) ‖ max(l,r))`
///
/// Commutative internal hashing means a proof is just the ordered list of
/// sibling hashes — no left/right direction bits are needed, so proofs fit the
/// existing `MerkleProof` type. Odd nodes at a level are carried up unchanged
/// (not duplicated), avoiding the classic Merkle duplication malleability.
pub struct MerkleProver {
    entries: std::collections::BTreeMap<Vec<u8>, StorageValue>,
    /// Precomputed leaf hash per key. A rebuild reads these instead of
    /// re-hashing every value, so leaf hashing is O(1) amortized per write
    /// rather than O(n) on every root computation (the dominant cost when
    /// values are large).
    leaf_hashes: std::collections::BTreeMap<Vec<u8>, Hash256>,
    /// Cached root, invalidated on any mutation, so repeated `root()`/`prove()`
    /// calls between writes (the engine computes the root several times per
    /// block) don't rebuild the tree.
    cached_root: std::cell::Cell<Option<MerkleRoot>>,
}

impl MerkleProver {
    /// Create a new empty Merkle prover.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
            leaf_hashes: std::collections::BTreeMap::new(),
            cached_root: std::cell::Cell::new(Some(MerkleRoot::EMPTY)),
        }
    }

    /// Insert or update a key-value pair.
    pub fn insert(&mut self, key: &StorageKey, value: StorageValue) {
        let leaf = Self::leaf_hash(&key.0, &value.0);
        self.entries.insert(key.0.clone(), value);
        self.leaf_hashes.insert(key.0.clone(), leaf);
        self.cached_root.set(None);
    }

    /// Remove a key.
    pub fn remove(&mut self, key: &StorageKey) {
        self.entries.remove(&key.0);
        self.leaf_hashes.remove(&key.0);
        self.cached_root.set(None);
    }

    /// Look up a value.
    #[must_use]
    pub fn get(&self, key: &StorageKey) -> Option<&StorageValue> {
        self.entries.get(&key.0)
    }

    /// Number of committed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn leaf_hash(key: &[u8], value: &[u8]) -> Hash256 {
        // Canonical Merkle hashing lives in aevor-core, shared with the verifier.
        aevor_core::storage::merkle_leaf_hash(key, value)
    }

    fn node_hash(a: &Hash256, b: &Hash256) -> Hash256 {
        aevor_core::storage::merkle_node_hash(a, b)
    }

    /// Build every level of the tree bottom-up (`levels[0]` = leaves).
    fn levels(&self) -> Vec<Vec<Hash256>> {
        // Leaves come from the precomputed per-key hashes (same sorted-key order
        // as `entries`), so a rebuild never re-hashes unchanged values.
        let leaves: Vec<Hash256> = self.leaf_hashes.values().copied().collect();
        if leaves.is_empty() {
            return Vec::new();
        }
        let mut levels = vec![leaves];
        while levels.last().map_or(0, Vec::len) > 1 {
            let current = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(Self::node_hash(&current[i], &current[i + 1]));
                    i += 2;
                } else {
                    next.push(current[i]); // carry odd node up unchanged
                    i += 1;
                }
            }
            levels.push(next);
        }
        levels
    }

    /// Sibling authentication path for the leaf at `index`.
    fn authentication_path(levels: &[Vec<Hash256>], mut index: usize) -> Vec<Hash256> {
        let mut siblings = Vec::new();
        for level in &levels[..levels.len().saturating_sub(1)] {
            let sibling = index ^ 1;
            if sibling < level.len() {
                siblings.push(level[sibling]);
            }
            index /= 2;
        }
        siblings
    }

    /// Current Merkle root.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        if let Some(cached) = self.cached_root.get() {
            return cached;
        }
        let levels = self.levels();
        let root = match levels.last() {
            Some(top) if !top.is_empty() => MerkleRoot::from_hash(top[0]),
            _ => MerkleRoot::EMPTY,
        };
        self.cached_root.set(Some(root));
        root
    }

    /// Generate a Merkle proof for the given key.
    ///
    /// For a present key this is a **real inclusion proof** (sibling path +
    /// value). For an absent key it returns a non-inclusion result against the
    /// current root.
    ///
    /// # Errors
    /// Currently infallible; the `Result` allows future error propagation.
    pub fn prove(&self, key: &StorageKey) -> StorageResult<Option<MerkleProof>> {
        // Find the leaf index and value in one pass over the sorted keys.
        let mut found: Option<(usize, StorageValue)> = None;
        for (index, (k, value)) in self.entries.iter().enumerate() {
            if k == &key.0 {
                found = Some((index, value.clone()));
                break;
            }
        }

        if let Some((index, value)) = found {
            let levels = self.levels();
            let siblings = Self::authentication_path(&levels, index);
            Ok(Some(MerkleProof {
                key: key.clone(),
                value,
                siblings,
                root: self.root(),
                is_inclusion: true,
            }))
        } else {
            Ok(Some(MerkleProof {
                key: key.clone(),
                value: StorageValue::EMPTY,
                siblings: Vec::new(),
                root: self.root(),
                is_inclusion: false,
            }))
        }
    }

    /// Verify a Merkle inclusion proof against its embedded root.
    ///
    /// Delegates to the canonical [`MerkleProof::verify`] so the prover and any
    /// verifier (e.g. a client) share one implementation.
    #[must_use]
    pub fn verify(proof: &MerkleProof) -> bool {
        proof.verify()
    }
}

impl Default for MerkleProver {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(bytes: &[u8]) -> StorageKey {
        StorageKey::from_bytes(bytes.to_vec())
    }
    fn v(bytes: &[u8]) -> StorageValue {
        StorageValue::from_bytes(bytes.to_vec())
    }

    #[test]
    fn prover_root_changes_after_insert() {
        let mut prover = MerkleProver::new();
        let root_before = prover.root();
        prover.insert(&k(&[1, 2, 3]), v(&[42]));
        assert_ne!(prover.root(), root_before);
    }

    #[test]
    fn prove_returns_inclusion_for_present_key() {
        let mut prover = MerkleProver::new();
        prover.insert(&k(&[7, 8, 9]), v(&[99]));
        let proof = prover.prove(&k(&[7, 8, 9])).unwrap().unwrap();
        assert!(proof.is_inclusion);
    }

    #[test]
    fn prove_returns_exclusion_for_absent_key() {
        let prover = MerkleProver::new();
        let proof = prover.prove(&k(&[1])).unwrap().unwrap();
        assert!(!proof.is_inclusion);
    }

    #[test]
    fn real_inclusion_proof_verifies() {
        // Populate several entries so the tree has real depth.
        let mut prover = MerkleProver::new();
        for i in 0..7u8 {
            prover.insert(&k(&[i]), v(&[i, i, i]));
        }
        // Every present key must produce a proof that verifies against the root.
        for i in 0..7u8 {
            let proof = prover.prove(&k(&[i])).unwrap().unwrap();
            assert!(proof.is_inclusion);
            assert!(MerkleProver::verify(&proof), "proof for key {i} must verify");
        }
    }

    #[test]
    fn tampered_value_breaks_verification() {
        let mut prover = MerkleProver::new();
        for i in 0..5u8 {
            prover.insert(&k(&[i]), v(&[i]));
        }
        let mut proof = prover.prove(&k(&[2])).unwrap().unwrap();
        // Flip the value — the proof must no longer verify against the root.
        proof.value = v(&[0xFF]);
        assert!(!MerkleProver::verify(&proof));
    }

    #[test]
    fn proof_from_one_tree_fails_against_different_root() {
        let mut a = MerkleProver::new();
        for i in 0..4u8 {
            a.insert(&k(&[i]), v(&[i]));
        }
        let proof = a.prove(&k(&[1])).unwrap().unwrap();

        // A different set → different root; the old proof must not verify.
        let mut b = MerkleProver::new();
        for i in 0..4u8 {
            b.insert(&k(&[i]), v(&[i + 100]));
        }
        let stale = MerkleProof { root: b.root(), ..proof };
        assert!(!MerkleProver::verify(&stale));
    }

    #[test]
    fn single_entry_proof_verifies() {
        let mut prover = MerkleProver::new();
        prover.insert(&k(&[1]), v(&[1]));
        let proof = prover.prove(&k(&[1])).unwrap().unwrap();
        assert!(proof.siblings.is_empty()); // root == leaf
        assert!(MerkleProver::verify(&proof));
    }
}
