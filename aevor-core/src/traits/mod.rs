//! # Core Behavioral Traits
//!
//! Foundational traits that define the expected behavior of all AEVOR types.
//! Every significant type in the system implements the appropriate subset of
//! these traits, enabling generic code to operate across the full type space
//! while maintaining the security and performance invariants required for
//! genuine trilemma transcendence.

use crate::error::AevorResult;
use crate::primitives::Hash256;

// ============================================================
// MATHEMATICAL VERIFICATION
// ============================================================

/// Implemented by types that carry a cryptographic correctness proof.
///
/// `MathematicallyVerifiable` guarantees are not probabilistic — they are
/// deterministic: the verification either succeeds completely or fails.
pub trait MathematicallyVerifiable {
    /// Verify the mathematical correctness of this value.
    ///
    /// Returns `Ok(())` if verification passes, `Err(...)` with a descriptive
    /// error if any aspect of the proof is invalid.
    ///
    /// # Errors
    /// Returns an error if any part of the cryptographic proof fails to verify.
    fn verify_mathematically(&self) -> AevorResult<()>;

    /// Returns `true` if verification would succeed without actually running it.
    ///
    /// Lighter-weight check — use when full proof re-verification is too costly.
    fn is_mathematically_valid(&self) -> bool {
        self.verify_mathematically().is_ok()
    }
}

// ============================================================
// VERIFIABLE
// ============================================================

/// Implemented by types that can validate their own internal consistency.
///
/// Distinct from `MathematicallyVerifiable` — `Verifiable` checks structural
/// validity (fields are within bounds, required fields are present), while
/// `MathematicallyVerifiable` checks cryptographic proof validity.
pub trait Verifiable {
    /// Verify structural validity of this value.
    ///
    /// # Errors
    /// Returns an error if any field is out of bounds or required data is missing.
    fn verify(&self) -> AevorResult<()>;

    /// Returns `true` if the value is structurally valid.
    fn is_valid(&self) -> bool {
        self.verify().is_ok()
    }
}

// ============================================================
// TEE COMPATIBLE
// ============================================================

/// Implemented by types that can be safely operated on within a TEE enclave.
///
/// TEE-compatible types must be serializable to/from a flat byte representation
/// suitable for secure channel transmission, and must declare any TEE platform
/// requirements they impose.
pub trait TeeCompatible {
    /// Serialize this value for transmission through a TEE secure channel.
    ///
    /// # Errors
    /// Returns an error if the value cannot be serialized to the TEE wire format.
    fn to_tee_bytes(&self) -> AevorResult<Vec<u8>>;

    /// Deserialize from TEE secure channel bytes.
    ///
    /// # Errors
    /// Returns an error if the bytes are malformed or represent an incompatible version.
    fn from_tee_bytes(bytes: &[u8]) -> AevorResult<Self>
    where
        Self: Sized;

    /// Returns the minimum TEE security level required to operate on this value.
    fn required_tee_platform(&self) -> Option<crate::tee::TeePlatform> {
        None // No specific platform required by default
    }
}

// ============================================================
// BLOCKCHAIN OBJECT
// ============================================================

/// Implemented by objects stored in the AEVOR state tree.
///
/// Every storable object has a stable identity, a content hash, and a
/// privacy policy that governs access to it.
pub trait BlockchainObject: Verifiable + Serializable {
    /// The unique identifier for this object in the state tree.
    fn object_id(&self) -> crate::primitives::ObjectId;

    /// The privacy level of this object.
    fn privacy_level(&self) -> crate::privacy::PrivacyLevel;

    /// The content hash of this object's current state.
    fn content_hash(&self) -> Hash256;

    /// Whether this object is mutable (can be written after creation).
    fn is_mutable(&self) -> bool {
        true
    }
}

// ============================================================
// PARALLELIZABLE
// ============================================================

/// Implemented by operations that can be executed in parallel.
///
/// Central to the Dual-DAG architecture — every transaction and contract
/// execution declares its conflict set so the scheduler can determine which
/// operations are safe to run concurrently.
pub trait Parallelizable {
    /// The set of object identifiers this operation reads from.
    ///
    /// Operations with overlapping read sets but non-overlapping write sets
    /// can be safely parallelized.
    fn read_set(&self) -> Vec<crate::primitives::ObjectId>;

    /// The set of object identifiers this operation writes to.
    ///
    /// Operations with overlapping write sets must be serialized.
    fn write_set(&self) -> Vec<crate::primitives::ObjectId>;

    /// Returns `true` if this operation conflicts with `other` and cannot
    /// be executed in parallel.
    fn conflicts_with(&self, other: &Self) -> bool
    where
        Self: Sized,
    {
        let my_writes = self.write_set();
        let other_reads = other.read_set();
        let other_writes = other.write_set();

        // Conflict if: I write something other reads or writes
        my_writes.iter().any(|w| {
            other_reads.contains(w) || other_writes.contains(w)
        })
    }

    /// Returns `true` if this operation has no state dependencies and
    /// can always run in parallel with anything.
    fn is_fully_independent(&self) -> bool {
        self.read_set().is_empty() && self.write_set().is_empty()
    }
}

// ============================================================
// PRIVACY AWARE
// ============================================================

/// Implemented by types that carry privacy metadata.
///
/// Privacy-aware types can communicate their confidentiality requirements
/// to the execution scheduler and TEE allocator.
pub trait PrivacyAware {
    /// The privacy level of this value.
    fn privacy_level(&self) -> crate::privacy::PrivacyLevel;

    /// Whether operating on this value requires TEE execution.
    fn requires_tee(&self) -> bool {
        self.privacy_level().requires_tee()
    }

    /// The privacy context required to access this value.
    fn required_privacy_context(&self) -> crate::privacy::PrivacyContext {
        crate::privacy::PrivacyContext::public()
    }
}

// ============================================================
// ATTESTABLE
// ============================================================

/// Implemented by types that can be cryptographically attested by a TEE.
///
/// Attestable types participate in the Proof of Uncorruption mechanism —
/// their execution inside a TEE can be proven to external verifiers.
pub trait Attestable {
    /// Generate an attestation commitment for this value.
    ///
    /// The commitment is suitable for inclusion in a TEE attestation report's
    /// user data field, binding this value to the TEE execution.
    ///
    /// # Errors
    /// Returns an error if the TEE is unavailable or commitment generation fails.
    fn attestation_commitment(&self) -> AevorResult<Hash256>;

    /// Verify an attestation commitment matches this value.
    ///
    /// # Errors
    /// Returns an error if commitment recomputation fails.
    fn verify_attestation_commitment(&self, commitment: &Hash256) -> AevorResult<bool> {
        Ok(&self.attestation_commitment()? == commitment)
    }
}

// ============================================================
// COMMITTABLE
// ============================================================

/// Implemented by types that support cryptographic commitment schemes.
///
/// A commitment is a hash that binds a value without revealing it.
/// Commitments can be opened later to prove the original value.
pub trait Committable {
    /// Create a binding, hiding commitment to this value.
    ///
    /// # Errors
    /// Returns an error if the commitment scheme fails (e.g. hash function error).
    fn commit(&self, randomness: &[u8; 32]) -> AevorResult<Hash256>;

    /// Verify that a commitment was created from this value.
    ///
    /// # Errors
    /// Returns an error if verification computation fails.
    fn verify_commitment(&self, commitment: &Hash256, randomness: &[u8; 32]) -> AevorResult<bool>;
}

// ============================================================
// EXECUTABLE
// ============================================================

/// Implemented by operations that can be executed in the AEVOR VM.
pub trait Executable {
    /// The result type produced by executing this operation.
    type Output;

    /// The context required to execute this operation.
    type Context;

    /// Execute this operation in the given context.
    ///
    /// # Errors
    /// Returns an error if execution fails (gas exhausted, VM fault, TEE error).
    fn execute(&self, ctx: &Self::Context) -> AevorResult<Self::Output>;

    /// Estimate the gas cost of executing this operation without executing it.
    ///
    /// # Errors
    /// Returns an error if gas estimation is not possible for this operation.
    fn estimate_gas(&self) -> AevorResult<crate::primitives::GasAmount>;
}

// ============================================================
// METERED
// ============================================================

/// Implemented by operations that have a measurable resource cost.
pub trait Metered {
    /// The actual gas consumed by this operation (after execution).
    fn gas_consumed(&self) -> crate::primitives::GasAmount;

    /// The computational complexity class of this operation.
    fn complexity_class(&self) -> ComplexityClass {
        ComplexityClass::Constant
    }
}

/// Computational complexity class for gas estimation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComplexityClass {
    /// O(1) — fixed cost.
    Constant,
    /// O(log n) — logarithmic in input size.
    Logarithmic,
    /// O(n) — linear in input size.
    Linear,
    /// O(n log n) — quasi-linear.
    QuasiLinear,
    /// O(n²) — quadratic (use sparingly).
    Quadratic,
}

// ============================================================
// SERIALIZABLE
// ============================================================

/// Implemented by all types that must be deterministically serialized for
/// hashing, signing, and storage.
///
/// Uses canonical serialization (BCS — Binary Canonical Serialization) to
/// ensure the same logical value always produces the same byte sequence
/// across all platforms, languages, and time.
pub trait Serializable {
    /// Serialize to canonical bytes.
    ///
    /// # Errors
    /// Returns an error if the value cannot be encoded (e.g. contains non-serializable data).
    fn to_canonical_bytes(&self) -> AevorResult<Vec<u8>>;

    /// Deserialize from canonical bytes.
    ///
    /// # Errors
    /// Returns an error if the bytes are malformed, truncated, or incompatible.
    fn from_canonical_bytes(bytes: &[u8]) -> AevorResult<Self>
    where
        Self: Sized;

    /// Compute the canonical hash (BLAKE3 of canonical bytes).
    ///
    /// # Errors
    /// Returns an error if serialization fails (same conditions as `to_canonical_bytes`).
    fn canonical_hash(&self) -> AevorResult<Hash256> {
        let bytes = self.to_canonical_bytes()?;
        Ok(Hash256(*blake3::hash(&bytes).as_bytes()))
    }
}

// ============================================================
// STATE ACCESSIBLE
// ============================================================

/// Implemented by types that can read and write the blockchain state.
pub trait StateAccessible {
    /// Read a value from storage by key.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails or the key is inaccessible.
    fn read_state(&self, key: &crate::storage::StorageKey) -> AevorResult<crate::storage::StorageValue>;

    /// Write a value to storage.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails or the write is rejected.
    fn write_state(
        &mut self,
        key: crate::storage::StorageKey,
        value: crate::storage::StorageValue,
    ) -> AevorResult<()>;

    /// Delete a value from storage.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails.
    fn delete_state(&mut self, key: &crate::storage::StorageKey) -> AevorResult<()>;
}

// ============================================================
// NETWORK PROPAGATABLE
// ============================================================

/// Implemented by types that can be broadcast across the P2P network.
pub trait NetworkPropagatable: Serializable {
    /// The maximum allowed serialized size for network transmission in bytes.
    fn max_propagation_size_bytes() -> usize;

    /// Topic string for network routing (e.g., "tx", "block", "attestation").
    fn propagation_topic(&self) -> &'static str;

    /// Whether this message requires TEE-verified propagation.
    fn requires_verified_propagation(&self) -> bool {
        false
    }
}

// ============================================================
// CROSS PLATFORM CONSISTENT
// ============================================================

/// Implemented by computations that must produce identical results on all
/// TEE platforms (SGX, SEV, `TrustZone`, Keystone, Nitro).
///
/// Cross-platform consistency is fundamental to the `PoU` consensus mechanism —
/// if validators on different TEE hardware reach different results for the
/// same computation, the system cannot achieve mathematical certainty.
pub trait CrossPlatformConsistent {
    /// Verify that this computation would produce the same result on all
    /// supported TEE platforms.
    ///
    /// # Errors
    /// Returns an error if cross-platform verification fails or is unavailable.
    fn verify_cross_platform_consistency(&self) -> AevorResult<()>;

    /// The expected computation hash that all platforms should agree on.
    fn expected_computation_hash(&self) -> Hash256;
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test struct for trait default implementations
    struct TestOp {
        reads: Vec<crate::primitives::ObjectId>,
        writes: Vec<crate::primitives::ObjectId>,
    }

    impl Parallelizable for TestOp {
        fn read_set(&self) -> Vec<crate::primitives::ObjectId> {
            self.reads.clone()
        }
        fn write_set(&self) -> Vec<crate::primitives::ObjectId> {
            self.writes.clone()
        }
    }

    #[test]
    fn independent_op_has_no_conflicts() {
        let op = TestOp { reads: vec![], writes: vec![] };
        assert!(op.is_fully_independent());
    }

    #[test]
    fn write_write_conflict_detected() {
        let id = crate::primitives::ObjectId::from_hash(Hash256([1u8; 32]));
        let a = TestOp { reads: vec![], writes: vec![id] };
        let b = TestOp { reads: vec![], writes: vec![id] };
        assert!(a.conflicts_with(&b));
    }

    #[test]
    fn write_read_conflict_detected() {
        let id = crate::primitives::ObjectId::from_hash(Hash256([2u8; 32]));
        let writer = TestOp { reads: vec![], writes: vec![id] };
        let reader = TestOp { reads: vec![id], writes: vec![] };
        assert!(writer.conflicts_with(&reader));
    }

    #[test]
    fn read_read_no_conflict() {
        let id = crate::primitives::ObjectId::from_hash(Hash256([3u8; 32]));
        let r1 = TestOp { reads: vec![id], writes: vec![] };
        let r2 = TestOp { reads: vec![id], writes: vec![] };
        assert!(!r1.conflicts_with(&r2));
    }

    #[test]
    fn complexity_class_ordering() {
        // Constant < Linear (ordinal position)
        assert_eq!(ComplexityClass::Constant, ComplexityClass::Constant);
    }
}
