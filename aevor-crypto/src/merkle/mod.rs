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
            let sibling = if pos.is_multiple_of(2) { pos + 1 } else { pos - 1 };
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
/// A real sparse Merkle tree keyed by `BLAKE3(key)` over a fixed depth of 256.
///
/// Every key maps to a fixed leaf position (the bits of its hash), so an
/// insert/update touches only the **O(depth)** nodes on that key's root-to-leaf
/// path — independent of how many other keys are present. Empty subtrees use
/// precomputed default hashes, so the tree is stored sparsely (only occupied
/// paths). Membership proofs are also O(depth). This is the O(log n)-interior
/// structure for incremental and proof-heavy workloads (contrast the
/// sorted-leaf `MerkleProver`, which is O(n) to rebuild but optimal for a
/// single large batch commit).
pub struct SparseMerkleTree {
    values: std::collections::BTreeMap<Vec<u8>, StorageValue>,
    /// Occupied node hashes keyed by (depth, 256-bit prefix with lower bits 0).
    nodes: std::collections::HashMap<(usize, [u8; 32]), Hash256>,
    /// `defaults[h]` = hash of an empty subtree of height `h` (0 = empty leaf).
    defaults: Vec<Hash256>,
    root: Hash256,
}

/// Fixed tree depth (bits of the key hash).
const SMT_DEPTH: usize = 256;

impl SparseMerkleTree {
    /// Create an empty sparse Merkle tree.
    #[must_use]
    pub fn new() -> Self {
        // Precompute empty-subtree hashes: defaults[0] is the empty leaf,
        // defaults[h] = node(defaults[h-1], defaults[h-1]).
        let mut defaults = Vec::with_capacity(SMT_DEPTH + 1);
        defaults.push(Hash256([0u8; 32]));
        for h in 1..=SMT_DEPTH {
            let child = defaults[h - 1];
            defaults.push(aevor_core::storage::merkle_node_hash(&child, &child));
        }
        let root = defaults[SMT_DEPTH];
        Self {
            values: std::collections::BTreeMap::new(),
            nodes: std::collections::HashMap::new(),
            defaults,
            root,
        }
    }

    fn position(key: &[u8]) -> [u8; 32] {
        let mut h = crate::hash::Blake3Hasher::new();
        h.update(key);
        h.finalize().0 .0
    }

    fn bit_at(pos: &[u8; 32], d: usize) -> u8 {
        (pos[d / 8] >> (7 - (d % 8))) & 1
    }

    /// `pos` with all bits at index >= `d` cleared (the depth-`d` prefix).
    fn prefix(pos: &[u8; 32], d: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        let full = d / 8;
        out[..full].copy_from_slice(&pos[..full]);
        if full < 32 {
            let rem = d % 8;
            if rem != 0 {
                let mask = 0xFFu8 << (8 - rem);
                out[full] = pos[full] & mask;
            }
        }
        out
    }

    fn set_bit(mut prefix: [u8; 32], d: usize, val: u8) -> [u8; 32] {
        let byte = d / 8;
        let shift = 7 - (d % 8);
        prefix[byte] = (prefix[byte] & !(1 << shift)) | (val << shift);
        prefix
    }

    fn recompute_path(&mut self, pos: &[u8; 32], leaf: Hash256) {
        // Set the leaf, then walk up recomputing only this path's nodes.
        self.nodes.insert((SMT_DEPTH, *pos), leaf);
        let mut cur = leaf;
        for d in (0..SMT_DEPTH).rev() {
            let path_bit = Self::bit_at(pos, d);
            let sibling_prefix = Self::set_bit(Self::prefix(pos, d), d, 1 - path_bit);
            let sibling = self
                .nodes
                .get(&(d + 1, sibling_prefix))
                .copied()
                .unwrap_or(self.defaults[SMT_DEPTH - (d + 1)]);
            let (left, right) = if path_bit == 0 { (cur, sibling) } else { (sibling, cur) };
            cur = aevor_core::storage::merkle_node_hash(&left, &right);
            self.nodes.insert((d, Self::prefix(pos, d)), cur);
        }
        self.root = cur;
    }

    /// Insert or update a key-value pair in O(depth).
    pub fn insert(&mut self, key: &StorageKey, value: StorageValue) {
        let pos = Self::position(&key.0);
        let leaf = aevor_core::storage::merkle_leaf_hash(&key.0, &value.0);
        self.values.insert(key.0.clone(), value);
        self.recompute_path(&pos, leaf);
    }

    /// Remove a key in O(depth) (its leaf reverts to the empty default).
    pub fn remove(&mut self, key: &StorageKey) {
        if self.values.remove(&key.0).is_none() {
            return;
        }
        let pos = Self::position(&key.0);
        self.nodes.remove(&(SMT_DEPTH, pos));
        // Recompute the path with the leaf back to its empty default.
        let empty_leaf = self.defaults[0];
        let mut cur = empty_leaf;
        for d in (0..SMT_DEPTH).rev() {
            let path_bit = Self::bit_at(&pos, d);
            let sibling_prefix = Self::set_bit(Self::prefix(&pos, d), d, 1 - path_bit);
            let sibling = self
                .nodes
                .get(&(d + 1, sibling_prefix))
                .copied()
                .unwrap_or(self.defaults[SMT_DEPTH - (d + 1)]);
            let (left, right) = if path_bit == 0 { (cur, sibling) } else { (sibling, cur) };
            let is_default = cur == self.defaults[SMT_DEPTH - (d + 1)]
                && sibling == self.defaults[SMT_DEPTH - (d + 1)];
            cur = aevor_core::storage::merkle_node_hash(&left, &right);
            let prefix = Self::prefix(&pos, d);
            if is_default {
                self.nodes.remove(&(d, prefix));
            } else {
                self.nodes.insert((d, prefix), cur);
            }
        }
        self.root = cur;
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &StorageKey) -> Option<&StorageValue> {
        self.values.get(&key.0)
    }

    /// Current root hash.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot::from_hash(self.root)
    }

    /// Generate an O(depth) membership proof for a present key.
    ///
    /// Returns the leaf value and the 256 sibling hashes from leaf to root. The
    /// direction at each level is implied by `BLAKE3(key)`, so a verifier needs
    /// only the key (see [`verify`](Self::verify)).
    #[must_use]
    pub fn prove(&self, key: &StorageKey) -> Option<MerkleProof> {
        let value = self.values.get(&key.0)?.clone();
        let pos = Self::position(&key.0);
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        for d in (0..SMT_DEPTH).rev() {
            let path_bit = Self::bit_at(&pos, d);
            let sibling_prefix = Self::set_bit(Self::prefix(&pos, d), d, 1 - path_bit);
            let sibling = self
                .nodes
                .get(&(d + 1, sibling_prefix))
                .copied()
                .unwrap_or(self.defaults[SMT_DEPTH - (d + 1)]);
            siblings.push(sibling);
        }
        Some(MerkleProof {
            key: key.clone(),
            value,
            siblings,
            root: self.root(),
            is_inclusion: true,
        })
    }

    /// Verify a proof produced by [`prove`](Self::prove): walk `BLAKE3(key)`
    /// from leaf to root, combining with each sibling on the correct side, and
    /// check the recomputed root. O(depth), constant in tree size.
    #[must_use]
    pub fn verify(proof: &MerkleProof) -> bool {
        if !proof.is_inclusion || proof.siblings.len() != SMT_DEPTH {
            return false;
        }
        let pos = Self::position(&proof.key.0);
        let mut cur = aevor_core::storage::merkle_leaf_hash(&proof.key.0, &proof.value.0);
        // siblings[0] is the leaf-level sibling (depth 256), up to the root.
        for (i, sibling) in proof.siblings.iter().enumerate() {
            let d = SMT_DEPTH - 1 - i; // depth of the parent being formed
            let path_bit = Self::bit_at(&pos, d);
            let (left, right) = if path_bit == 0 { (cur, *sibling) } else { (*sibling, cur) };
            cur = aevor_core::storage::merkle_node_hash(&left, &right);
        }
        cur == proof.root.0
    }

    /// Number of entries in this tree.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.values.len()
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

#[cfg(test)]
mod smt_tests {
    use super::SparseMerkleTree;
    use aevor_core::storage::{StorageKey, StorageValue};

    fn k(b: &[u8]) -> StorageKey { StorageKey(b.to_vec()) }
    fn v(b: &[u8]) -> StorageValue { StorageValue(b.to_vec()) }

    #[test]
    fn smt_insert_prove_verify_roundtrip() {
        let mut t = SparseMerkleTree::new();
        t.insert(&k(b"alice"), v(b"100"));
        t.insert(&k(b"bob"), v(b"200"));
        t.insert(&k(b"carol"), v(b"300"));

        let proof = t.prove(&k(b"bob")).unwrap();
        assert!(SparseMerkleTree::verify(&proof), "valid membership proof verifies");
        assert_eq!(proof.value.0, b"200");

        let mut bad = proof.clone();
        bad.value = v(b"999");
        assert!(!SparseMerkleTree::verify(&bad), "wrong value rejected");

        assert!(t.prove(&k(b"dave")).is_none(), "absent key has no proof");
    }

    #[test]
    fn smt_update_changes_root_and_proof() {
        let mut t = SparseMerkleTree::new();
        t.insert(&k(b"x"), v(b"1"));
        let r1 = t.root();
        t.insert(&k(b"x"), v(b"2"));
        assert_ne!(r1.0, t.root().0, "update changes root");
        let proof = t.prove(&k(b"x")).unwrap();
        assert_eq!(proof.value.0, b"2");
        assert!(SparseMerkleTree::verify(&proof));
    }

    #[test]
    fn smt_remove_reverts_root() {
        let mut t = SparseMerkleTree::new();
        let empty = t.root();
        t.insert(&k(b"a"), v(b"1"));
        assert_ne!(t.root().0, empty.0);
        t.remove(&k(b"a"));
        assert_eq!(t.root().0, empty.0, "removing the only key reverts to empty root");
        assert!(t.prove(&k(b"a")).is_none());
    }

    #[test]
    fn smt_order_independent_root() {
        let mut t1 = SparseMerkleTree::new();
        for (kk, vv) in [(b"a".as_slice(), b"1".as_slice()), (b"b", b"2"), (b"c", b"3")] {
            t1.insert(&k(kk), v(vv));
        }
        let mut t2 = SparseMerkleTree::new();
        for (kk, vv) in [(b"c".as_slice(), b"3".as_slice()), (b"a", b"1"), (b"b", b"2")] {
            t2.insert(&k(kk), v(vv));
        }
        assert_eq!(t1.root().0, t2.root().0, "root independent of insert order");
    }
}
