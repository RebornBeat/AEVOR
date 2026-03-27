//! # Error Types
//!
//! Unified error hierarchy for all AEVOR infrastructure crates.
//! Every subsystem error variant is represented here so higher-level
//! code can handle the complete error space through a single type.

use serde::{Deserialize, Serialize};

// ============================================================
// UNIFIED ERROR TYPE
// ============================================================

/// The unified AEVOR error type covering all infrastructure subsystems.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum AevorError {
    /// Consensus subsystem errors.
    #[error("consensus: {0}")]
    Consensus(#[from] ConsensusError),

    /// Cryptographic operation errors.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    /// VM execution errors.
    #[error("execution: {0}")]
    Execution(#[from] ExecutionError),

    /// Network communication errors.
    #[error("network: {0}")]
    Network(#[from] NetworkError),

    /// Privacy boundary and confidentiality errors.
    #[error("privacy: {0}")]
    Privacy(#[from] PrivacyError),

    /// Storage and state management errors.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    /// TEE platform and attestation errors.
    #[error("tee: {0}")]
    Tee(#[from] TeeError),

    /// Input validation errors.
    #[error("validation: {0}")]
    Validation(#[from] ValidationError),

    /// Economic primitive errors.
    #[error("economic: {0}")]
    Economic(#[from] EconomicError),

    /// Serialization and deserialization errors.
    #[error("serialization: {0}")]
    Serialization(String),

    /// Internal invariant violation — indicates a bug, not a user error.
    #[error("internal invariant violated: {0}")]
    InternalInvariant(String),
}

/// Convenience type alias — the standard `Result` for AEVOR operations.
pub type AevorResult<T> = Result<T, AevorError>;

// ============================================================
// SUBSYSTEM ERROR TYPES
// ============================================================

/// Errors from the Proof of Uncorruption consensus subsystem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ConsensusError {
    /// Not enough validators participated to reach the requested security level.
    #[error("insufficient participation: {actual_pct:.1}% < {required_pct:.1}% for {level}")]
    InsufficientParticipation {
        /// Actual participation as percentage.
        actual_pct: u32,
        /// Required participation as percentage.
        required_pct: u32,
        /// Security level name.
        level: String,
    },

    /// TEE attestation verification failed.
    #[error("attestation verification failed: {reason}")]
    AttestationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Byzantine behavior detected from a validator.
    #[error("Byzantine behavior from {validator}: {behavior}")]
    ByzantineBehavior {
        /// Validator identifier.
        validator: String,
        /// Behavior description.
        behavior: String,
    },

    /// Consensus round timed out.
    #[error("round {round} timed out after {elapsed_ms}ms")]
    RoundTimeout {
        /// Round number.
        round: u64,
        /// Elapsed time in milliseconds.
        elapsed_ms: u64,
    },

    /// Invalid block proposal.
    #[error("invalid proposal: {reason}")]
    InvalidProposal {
        /// Reason.
        reason: String,
    },

    /// Frontier corruption detected.
    #[error("frontier corruption: {description}")]
    FrontierCorruption {
        /// Description.
        description: String,
    },
}

/// Errors from cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CryptoError {
    /// Signature did not verify.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Key material is invalid or malformed.
    #[error("invalid key: {reason}")]
    InvalidKey {
        /// Reason.
        reason: String,
    },

    /// Zero-knowledge proof rejected.
    #[error("proof verification failed ({system})")]
    ProofVerificationFailed {
        /// Proof system name.
        system: String,
    },

    /// Symmetric encryption or decryption error.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Hash computation error.
    #[error("hash error: {0}")]
    HashError(String),

    /// Commitment scheme error.
    #[error("commitment error: {0}")]
    CommitmentError(String),

    /// Random number generation failed.
    #[error("RNG failure: {0}")]
    RngFailure(String),
}

/// Errors from VM execution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ExecutionError {
    /// Transaction ran out of gas.
    #[error("out of gas: used {used}, limit {limit}")]
    GasLimitExceeded {
        /// Gas consumed.
        used: u64,
        /// Gas limit.
        limit: u64,
    },

    /// Smart contract aborted.
    #[error("contract aborted with code {code}: {message}")]
    ContractAbort {
        /// Abort code.
        code: u64,
        /// Message.
        message: String,
    },

    /// Move resource / type safety violation.
    #[error("Move type error: {0}")]
    TypeViolation(String),

    /// Call stack depth exceeded.
    #[error("call stack overflow at depth {depth}")]
    StackOverflow {
        /// Depth at overflow.
        depth: u32,
    },

    /// Unauthorized object access.
    #[error("unauthorized access to object {object_id}")]
    UnauthorizedAccess {
        /// Object identifier.
        object_id: String,
    },

    /// TEE required but unavailable.
    #[error("TEE required but unavailable: {reason}")]
    TeeUnavailable {
        /// Reason.
        reason: String,
    },

    /// Bytecode verification failed.
    #[error("bytecode verification: {0}")]
    BytecodeVerification(String),
}

/// Errors from network communication.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NetworkError {
    /// Peer connection failed.
    #[error("connection to {peer} failed: {reason}")]
    ConnectionFailed {
        /// Peer identifier or address.
        peer: String,
        /// Reason.
        reason: String,
    },

    /// No route to destination.
    #[error("routing failed to {destination}: {reason}")]
    RoutingFailed {
        /// Destination.
        destination: String,
        /// Reason.
        reason: String,
    },

    /// Block propagation timed out.
    #[error("propagation timeout for block {block_hash}")]
    PropagationTimeout {
        /// Block hash.
        block_hash: String,
    },

    /// Protocol version mismatch.
    #[error("protocol incompatibility with {peer}")]
    ProtocolIncompatible {
        /// Peer identifier.
        peer: String,
    },

    /// Bandwidth limit exceeded.
    #[error("bandwidth limit exceeded")]
    BandwidthExceeded,
}

/// Errors related to privacy boundaries and confidentiality.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PrivacyError {
    /// Attempted access across a privacy boundary without authorization.
    #[error("privacy boundary violation: {description}")]
    BoundaryViolation {
        /// Description of the violation.
        description: String,
    },

    /// Selective disclosure failed to produce required proof.
    #[error("selective disclosure failed: {reason}")]
    DisclosureFailed {
        /// Reason.
        reason: String,
    },

    /// TEE isolation could not be established for a private operation.
    #[error("TEE isolation failed for private operation: {reason}")]
    IsolationFailed {
        /// Reason.
        reason: String,
    },

    /// Privacy policy incompatibility between interacting objects.
    #[error("privacy policy incompatibility: {description}")]
    PolicyIncompatibility {
        /// Description.
        description: String,
    },
}

/// Errors from storage operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum StorageError {
    /// Key not found in storage.
    #[error("not found: {key}")]
    NotFound {
        /// Storage key.
        key: String,
    },

    /// Optimistic concurrency conflict.
    #[error("version conflict on {object_id}: expected {expected}, found {actual}")]
    VersionConflict {
        /// Object identifier.
        object_id: String,
        /// Expected version.
        expected: u64,
        /// Actual version found.
        actual: u64,
    },

    /// Merkle proof verification failed.
    #[error("invalid Merkle proof for {key}")]
    InvalidMerkleProof {
        /// Key.
        key: String,
    },

    /// Storage backend error.
    #[error("backend error: {0}")]
    BackendError(String),

    /// Encryption error for a private object.
    #[error("encryption error for {object_id}: {reason}")]
    EncryptionError {
        /// Object identifier.
        object_id: String,
        /// Reason.
        reason: String,
    },

    /// Object exceeds size limit.
    #[error("object too large: {size_bytes} > {limit_bytes}")]
    ObjectTooLarge {
        /// Actual size.
        size_bytes: usize,
        /// Size limit.
        limit_bytes: usize,
    },
}

/// Errors from TEE platform operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum TeeError {
    /// Requested platform is not available on this hardware.
    #[error("TEE platform unavailable: {platform}")]
    PlatformUnavailable {
        /// Platform name.
        platform: String,
    },

    /// Attestation generation or verification failed.
    #[error("attestation failed: {reason}")]
    AttestationFailed {
        /// Reason.
        reason: String,
    },

    /// Memory isolation could not be established.
    #[error("isolation failed: {reason}")]
    IsolationFailed {
        /// Reason.
        reason: String,
    },

    /// TEE service allocation failed.
    #[error("service allocation failed: {reason}")]
    AllocationFailed {
        /// Reason.
        reason: String,
    },

    /// TEE integrity violation detected.
    #[error("TEE integrity violation")]
    IntegrityViolation,

    /// Cross-platform consistency verification failed.
    #[error("cross-platform consistency violation: {description}")]
    ConsistencyViolation {
        /// Description.
        description: String,
    },
}

/// Errors from input validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ValidationError {
    /// A required field is absent.
    #[error("missing required field: {field}")]
    MissingField {
        /// Field name.
        field: String,
    },

    /// A value is outside its valid range.
    #[error("value out of range: {field} = {value}")]
    OutOfRange {
        /// Field name.
        field: String,
        /// Provided value as string.
        value: String,
    },

    /// A field has an invalid format.
    #[error("invalid format for {field}: {reason}")]
    InvalidFormat {
        /// Field name.
        field: String,
        /// Reason.
        reason: String,
    },

    /// Two fields are mutually inconsistent.
    #[error("constraint violation: {description}")]
    ConstraintViolation {
        /// Description.
        description: String,
    },

    /// Signature or cryptographic proof on a submitted item is invalid.
    #[error("invalid signature on {item}")]
    InvalidSignature {
        /// Item that was not properly signed.
        item: String,
    },
}

/// Errors from economic primitive operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum EconomicError {
    /// Insufficient balance to complete the operation.
    #[error("insufficient balance: have {available}, need {required}")]
    InsufficientBalance {
        /// Available balance.
        available: u128,
        /// Required balance.
        required: u128,
    },

    /// Arithmetic overflow in balance calculation.
    #[error("balance overflow")]
    Overflow,

    /// Arithmetic underflow in balance calculation.
    #[error("balance underflow")]
    Underflow,

    /// Stake is below the minimum required.
    #[error("stake too low: {stake} < {minimum}")]
    StakeTooLow {
        /// Provided stake.
        stake: u128,
        /// Minimum required.
        minimum: u128,
    },

    /// Fee calculation produced an unexpected result.
    #[error("fee calculation error: {0}")]
    FeeCalculationError(String),
}

// ============================================================
// CONVENIENCE CONSTRUCTORS
// ============================================================

impl AevorError {
    /// Create an internal invariant error. Use only for bugs — not user errors.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::InternalInvariant(msg.into())
    }

    /// Create a serialization error.
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }

    /// Returns `true` if this error indicates a transient failure that may
    /// succeed on retry.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            AevorError::Network(
                NetworkError::ConnectionFailed { .. } | NetworkError::PropagationTimeout { .. }
            ) | AevorError::Consensus(ConsensusError::RoundTimeout { .. })
        )
    }

    /// Returns `true` if this error represents a security violation.
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            AevorError::Consensus(ConsensusError::ByzantineBehavior { .. })
                | AevorError::Tee(TeeError::IntegrityViolation)
                | AevorError::Privacy(PrivacyError::BoundaryViolation { .. })
                | AevorError::Validation(ValidationError::InvalidSignature { .. })
        )
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_from_consensus_wraps_correctly() {
        let consensus_err = ConsensusError::RoundTimeout {
            round: 42,
            elapsed_ms: 5000,
        };
        let aevor_err: AevorError = consensus_err.into();
        assert!(matches!(aevor_err, AevorError::Consensus(_)));
        assert!(aevor_err.is_transient());
    }

    #[test]
    fn byzantine_behavior_is_security_violation() {
        let err: AevorError = ConsensusError::ByzantineBehavior {
            validator: "v1".into(),
            behavior: "double-sign".into(),
        }
        .into();
        assert!(err.is_security_violation());
    }

    #[test]
    fn tee_integrity_violation_is_security_violation() {
        let err: AevorError = TeeError::IntegrityViolation.into();
        assert!(err.is_security_violation());
    }

    #[test]
    fn connection_failure_is_transient() {
        let err: AevorError = NetworkError::ConnectionFailed {
            peer: "peer1".into(),
            reason: "timeout".into(),
        }
        .into();
        assert!(err.is_transient());
    }

    #[test]
    fn internal_error_is_not_transient_and_not_security() {
        let err = AevorError::internal("invariant broken");
        assert!(!err.is_transient());
        assert!(!err.is_security_violation());
    }

    #[test]
    fn insufficient_balance_error_displays_values() {
        let err = EconomicError::InsufficientBalance {
            available: 100,
            required: 200,
        };
        let s = err.to_string();
        assert!(s.contains("100"));
        assert!(s.contains("200"));
    }
}
