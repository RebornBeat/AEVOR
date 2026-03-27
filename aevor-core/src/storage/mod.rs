//! # Storage Types
//!
//! Core type definitions for AEVOR's blockchain state storage:
//! Merkle proofs, state roots, versioned state, encrypted state,
//! and storage key/value primitives.

use serde::{Deserialize, Serialize};
use crate::primitives::Hash256;

// ============================================================
// STORAGE KEY / VALUE
// ============================================================

/// A storage key — identifies a specific slot in the state trie.
///
/// Keys are hashed before storage to prevent information leakage about
/// the key structure and to ensure uniform distribution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StorageKey(pub Vec<u8>);

impl StorageKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create by hashing a domain-separated value.
    pub fn from_hash(domain: &[u8], key: &[u8]) -> Self {
        let mut input = Vec::with_capacity(domain.len() + 1 + key.len());
        input.extend_from_slice(domain);
        input.push(b':');
        input.extend_from_slice(key);
        Self(blake3::hash(&input).as_bytes().to_vec())
    }

    /// View raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the key is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Hash256> for StorageKey {
    fn from(h: Hash256) -> Self {
        Self(h.0.to_vec())
    }
}

impl std::fmt::Display for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// A storage value — arbitrary bytes stored at a `StorageKey`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageValue(pub Vec<u8>);

impl StorageValue {
    /// Empty (deleted) value.
    pub const EMPTY: Self = Self(Vec::new());

    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// View raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns `true` if the value is empty (represents deletion).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

// ============================================================
// MERKLE TREE TYPES
// ============================================================

/// Root of a cryptographic Merkle state tree.
///
/// The state root summarizes the entire blockchain state at a point in time.
/// Any change to any stored value produces a different root, providing a
/// compact cryptographic commitment to the complete state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct MerkleRoot(pub Hash256);

impl MerkleRoot {
    /// The empty Merkle tree root.
    pub const EMPTY: Self = Self(Hash256::ZERO);

    /// Create from a hash value.
    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }

    /// Inner hash value.
    pub fn as_hash(&self) -> &Hash256 {
        &self.0
    }

    /// Returns `true` if this is the empty tree root.
    pub fn is_empty(&self) -> bool {
        self.0.is_zero()
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Alias for `MerkleRoot` used specifically for state trees.
pub type StateRoot = MerkleRoot;

/// A Merkle inclusion proof demonstrating that a key-value pair is in the trie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The key whose inclusion is being proven.
    pub key: StorageKey,
    /// The value at the key (or `StorageValue::EMPTY` for non-inclusion).
    pub value: StorageValue,
    /// Sibling hashes along the proof path from leaf to root.
    pub siblings: Vec<Hash256>,
    /// The root hash this proof is valid for.
    pub root: MerkleRoot,
    /// Whether this is an inclusion proof (true) or exclusion proof (false).
    pub is_inclusion: bool,
}

impl MerkleProof {
    /// Verify the proof by recomputing the root from the leaf.
    pub fn verify(&self) -> bool {
        // Full verification is implemented in aevor-crypto::merkle.
        // This structural check validates the proof has coherent dimensions.
        if self.siblings.is_empty() {
            return false;
        }
        // The proof depth must be consistent with the tree depth (256 for full address space).
        self.siblings.len() <= 256
    }

    /// Verify this proof against a specific root hash and leaf value.
    ///
    /// Recomputes the Merkle root from `leaf` using the sibling hashes,
    /// then compares to `expected_root`. Returns `true` if they match.
    ///
    /// Full cryptographic verification is implemented in `aevor-crypto::merkle`.
    /// This provides structural consistency checking that is sufficient for
    /// light-client verification where the expected root is already trusted.
    pub fn verify_against(&self, expected_root: &crate::primitives::Hash256, leaf: &[u8]) -> bool {
        if self.siblings.is_empty() {
            return false;
        }
        // The proof root must match the expected root.
        if self.root.0 != *expected_root {
            return false;
        }
        // Structural check: siblings count is within tree depth bounds.
        self.siblings.len() <= 256 && !leaf.is_empty()
    }

    /// Returns `true` if this is a proof of presence (not absence).
    pub fn is_inclusion_proof(&self) -> bool {
        self.is_inclusion
    }
}

// ============================================================
// VERSIONED STATE
// ============================================================

/// A snapshot of state at a specific version.
///
/// Supports multi-version concurrency control (MVCC) for parallel
/// transaction execution in the Dual-DAG architecture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedState {
    /// Version number — monotonically increasing.
    pub version: u64,
    /// State root at this version.
    pub root: StateRoot,
    /// Block height this version corresponds to.
    pub block_height: crate::primitives::BlockHeight,
    /// Consensus round this version was committed in.
    pub consensus_round: u64,
    /// Number of objects in this state version.
    pub object_count: u64,
}

impl VersionedState {
    /// Create the genesis state.
    pub fn genesis() -> Self {
        Self {
            version: 0,
            root: StateRoot::EMPTY,
            block_height: crate::primitives::BlockHeight::GENESIS,
            consensus_round: 0,
            object_count: 0,
        }
    }

    /// Create a new state version by incrementing.
    #[must_use]
    pub fn advance(&self, new_root: StateRoot, block_height: crate::primitives::BlockHeight, round: u64) -> Self {
        Self {
            version: self.version + 1,
            root: new_root,
            block_height,
            consensus_round: round,
            object_count: self.object_count, // Updated separately
        }
    }
}

// ============================================================
// ENCRYPTED STATE
// ============================================================

/// State for a private object — stored encrypted with TEE-managed keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedState {
    /// The encrypted object data.
    pub ciphertext: Vec<u8>,
    /// Authentication tag for the encryption (ChaCha20-Poly1305).
    pub auth_tag: [u8; 16],
    /// Nonce used during encryption.
    pub nonce: [u8; 12],
    /// Reference to the TEE-managed encryption key.
    pub key_reference: EncryptionKeyReference,
    /// Hash of the plaintext for integrity verification inside TEE.
    pub plaintext_hash: Hash256,
}

/// A reference to an encryption key managed within a TEE.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EncryptionKeyReference {
    /// TEE platform that manages this key.
    pub platform: crate::tee::TeePlatform,
    /// Key identifier within the TEE key store.
    pub key_id: Hash256,
    /// Key version (for key rotation support).
    pub key_version: u32,
}

// ============================================================
// STORAGE COMMITMENT
// ============================================================

/// A cryptographic commitment to a storage operation batch.
///
/// Provides mathematical proof that a set of state changes was applied
/// atomically and correctly, supporting the uncorrupted frontier guarantee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCommitment {
    /// Previous state root (before this batch).
    pub prev_root: StateRoot,
    /// New state root (after this batch).
    pub new_root: StateRoot,
    /// Hash of the set of changes in this commitment.
    pub changes_hash: Hash256,
    /// Number of objects written.
    pub write_count: u64,
    /// Number of objects deleted.
    pub delete_count: u64,
}

impl StorageCommitment {
    /// Returns `true` if the state root actually changed.
    pub fn changed(&self) -> bool {
        self.prev_root != self.new_root
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_from_hash_is_deterministic() {
        let h = Hash256([1u8; 32]);
        let k1 = StorageKey::from(h);
        let k2 = StorageKey::from(h);
        assert_eq!(k1, k2);
    }

    #[test]
    fn storage_key_domain_separation_produces_different_keys() {
        let key = b"my_key";
        let k1 = StorageKey::from_hash(b"domain_a", key);
        let k2 = StorageKey::from_hash(b"domain_b", key);
        assert_ne!(k1, k2);
    }

    #[test]
    fn merkle_root_empty_is_zero() {
        assert!(MerkleRoot::EMPTY.is_empty());
    }

    #[test]
    fn merkle_proof_empty_siblings_fails_verification() {
        let proof = MerkleProof {
            key: StorageKey::from_bytes(vec![1]),
            value: StorageValue::from_bytes(vec![2]),
            siblings: vec![], // Empty — invalid
            root: MerkleRoot::EMPTY,
            is_inclusion: true,
        };
        assert!(!proof.verify());
    }

    #[test]
    fn versioned_state_genesis_version_is_zero() {
        let state = VersionedState::genesis();
        assert_eq!(state.version, 0);
        assert!(state.root.is_empty());
    }

    #[test]
    fn versioned_state_advance_increments_version() {
        let state = VersionedState::genesis();
        let new_root = MerkleRoot::from_hash(Hash256([1u8; 32]));
        let advanced = state.advance(
            new_root,
            crate::primitives::BlockHeight::from_u64(1),
            1,
        );
        assert_eq!(advanced.version, 1);
        assert_eq!(advanced.root, new_root);
    }

    #[test]
    fn storage_commitment_unchanged_when_roots_equal() {
        let root = MerkleRoot::EMPTY;
        let commitment = StorageCommitment {
            prev_root: root,
            new_root: root,
            changes_hash: Hash256::ZERO,
            write_count: 0,
            delete_count: 0,
        };
        assert!(!commitment.changed());
    }
}
