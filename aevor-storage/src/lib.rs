//! # AEVOR Storage: Core Blockchain State Management
//!
//! `aevor-storage` provides the foundational state persistence layer for AEVOR's
//! blockchain infrastructure. This crate manages **core blockchain state only** —
//! application storage services (aevor-compute storage, enterprise data lakes, etc.)
//! are implemented as applications that use these infrastructure primitives.
//!
//! ## Architectural Boundary
//!
//! This crate owns:
//! - Object state: blockchain object data with version tracking
//! - Merkle state trees: cryptographic integrity proofs for all state
//! - Transaction receipts and execution results
//! - Block headers and attestations for the Macro-DAG
//! - Validator information and consensus state
//! - Encrypted state for private objects
//!
//! Application storage (user files, enterprise databases, CDN content) belongs in
//! higher-level service crates that use these primitives through well-defined interfaces.
//!
//! ## Privacy-Aware Storage
//!
//! Objects with `PrivacyLevel::Private` or higher are stored in encrypted form with
//! encryption keys managed within TEE environments. The storage layer enforces privacy
//! boundaries without understanding the semantic content of encrypted objects.
//!
//! ## Mathematical Integrity
//!
//! All state is committed to a cryptographic Merkle tree. Every state transition produces
//! a new `StateRoot` with a verifiable proof chain back to genesis, providing mathematical
//! guarantees about state integrity without requiring re-execution.
//!
//! ## Parallel Access
//!
//! The storage layer is designed for concurrent access patterns matching the Dual-DAG
//! parallel execution model. Object-level locking with optimistic concurrency control
//! prevents conflicts without creating sequential bottlenecks.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Object store: core blockchain object CRUD with version tracking.
pub mod objects;

/// Merkle state tree: incremental Merkle tree for state root computation.
pub mod merkle;

/// Versioned state: multi-version concurrency control for parallel access.
pub mod versioned;

/// Encrypted state: TEE-key-protected storage for private objects.
pub mod encrypted;

/// Transaction store: receipt and execution result persistence.
pub mod transactions;

/// Block store: block header and attestation storage for the Macro-DAG.
pub mod blocks;

/// Validator state: validator information, stake, and performance records.
pub mod validators;

/// Indexing: secondary indexes for efficient object and transaction queries.
pub mod indexing;

/// Cache layer: multi-level cache for hot-path performance optimization.
pub mod cache;

/// State snapshots: full state snapshots for checkpoint creation and sync.
pub mod snapshots;

/// Pruning: efficient old state pruning while maintaining proof availability.
pub mod pruning;

/// Storage backend abstraction: RocksDB, memory (testing), and pluggable backends.
pub mod backend;

// ============================================================
// PRELUDE
// ============================================================

/// Storage prelude — all essential storage types.
///
/// ```rust
/// use aevor_storage::prelude::*;
/// ```
pub mod prelude {
    pub use crate::objects::{
        ObjectStore, ObjectRecord, ObjectVersion, ObjectMetadata,
        ObjectQuery, ObjectBatch, ObjectUpdateResult,
    };
    pub use crate::merkle::{
        MerkleTree, MerkleNode, MerkleProof, MerkleRoot,
        IncrementalMerkleTree, SparseMerkleTree, MerkleProver,
    };
    pub use crate::versioned::{
        VersionedState, StateVersion, VersionedObjectStore,
        OptimisticLock, ConcurrencyControl, ConflictResolution,
    };
    pub use crate::encrypted::{
        EncryptedObjectStore, EncryptedRecord, EncryptionContext,
        TeeKeyReference, EncryptedStateRoot,
    };
    pub use crate::transactions::{
        TransactionStore, TransactionReceipt, ExecutionReceipt,
        ReceiptQuery, ReceiptBatch,
    };
    pub use crate::blocks::{
        BlockStore, BlockRecord, StoredAttestation,
        BlockQuery, BlockIndex,
    };
    pub use crate::validators::{
        ValidatorStore, ValidatorRecord, StakeRecord, PerformanceRecord,
    };
    pub use crate::indexing::{
        IndexManager, SecondaryIndex, IndexQuery, IndexResult,
        OwnerIndex, TypeIndex, PrivacyIndex,
    };
    pub use crate::cache::{
        StorageCache, CacheConfig, CacheMetrics, CachePolicy,
        HotObjectCache, StateRootCache,
    };
    pub use crate::snapshots::{
        StateSnapshot, SnapshotCreator, SnapshotLoader, SnapshotMetadata,
        CheckpointSnapshot,
    };
    pub use crate::backend::{
        StorageBackend, BackendConfig, RocksDbBackend, MemoryBackend,
        WriteOptions, ReadOptions,
    };
    pub use crate::{StorageError, StorageResult};
}

// ============================================================
// RE-EXPORTS FROM aevor-core
// ============================================================

pub use aevor_core::storage::{
    EncryptedState, MerkleProof, MerkleRoot, StateRoot, StorageCommitment,
    StorageKey, StorageValue, VersionedState,
};

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from storage operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum StorageError {
    /// Object with the given key was not found.
    #[error("object not found: {key}")]
    NotFound {
        /// Storage key that was not found.
        key: String,
    },

    /// Optimistic concurrency conflict: object was modified by a concurrent operation.
    #[error("version conflict on object {object_id}: expected version {expected}, found {actual}")]
    VersionConflict {
        /// Identifier of the conflicted object.
        object_id: String,
        /// Version the caller expected.
        expected: u64,
        /// Actual version found in storage.
        actual: u64,
    },

    /// Merkle proof verification failed.
    #[error("Merkle proof verification failed for key {key}")]
    InvalidMerkleProof {
        /// Storage key whose proof failed.
        key: String,
    },

    /// Storage backend error.
    #[error("backend error: {0}")]
    BackendError(String),

    /// Encryption or decryption of private object failed.
    #[error("encryption error for object {object_id}: {reason}")]
    EncryptionError {
        /// Identifier of the object.
        object_id: String,
        /// Reason for failure.
        reason: String,
    },

    /// Object is too large to store.
    #[error("object too large: {size_bytes} bytes exceeds limit of {limit_bytes} bytes")]
    ObjectTooLarge {
        /// Actual size of the object.
        size_bytes: usize,
        /// Maximum allowed size.
        limit_bytes: usize,
    },

    /// Snapshot creation or loading failed.
    #[error("snapshot error: {0}")]
    SnapshotError(String),

    /// Index operation failed.
    #[error("index error: {0}")]
    IndexError(String),
}

/// Convenience alias for storage results.
pub type StorageResult<T> = Result<T, StorageError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum size of a single stored object in bytes (16 MiB).
pub const MAX_OBJECT_SIZE_BYTES: usize = 16_777_216;

/// Maximum batch size for bulk operations.
pub const MAX_BATCH_SIZE: usize = 10_000;

/// Default LRU cache capacity in object count.
pub const DEFAULT_CACHE_CAPACITY: usize = 1_000_000;

/// State tree depth (determines maximum address space).
pub const MERKLE_TREE_DEPTH: usize = 256;

/// Storage key prefix for objects.
pub const OBJECT_KEY_PREFIX: &[u8] = b"obj:";

/// Storage key prefix for transactions.
pub const TX_KEY_PREFIX: &[u8] = b"tx:";

/// Storage key prefix for blocks.
pub const BLOCK_KEY_PREFIX: &[u8] = b"blk:";

/// Storage key prefix for validators.
pub const VALIDATOR_KEY_PREFIX: &[u8] = b"val:";

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_size_limit_is_reasonable() {
        assert_eq!(MAX_OBJECT_SIZE_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn key_prefixes_are_distinct() {
        assert_ne!(OBJECT_KEY_PREFIX, TX_KEY_PREFIX);
        assert_ne!(TX_KEY_PREFIX, BLOCK_KEY_PREFIX);
        assert_ne!(BLOCK_KEY_PREFIX, VALIDATOR_KEY_PREFIX);
    }

    #[test]
    fn merkle_tree_depth_supports_full_address_space() {
        assert_eq!(MERKLE_TREE_DEPTH, 256);
    }
}
