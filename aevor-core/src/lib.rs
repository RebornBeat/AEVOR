//! # AEVOR Core: Revolutionary Blockchain Foundation
//!
//! `aevor-core` provides the complete type system, mathematical primitives, and coordination
//! infrastructure that enables AEVOR's genuine blockchain trilemma transcendence. Every type,
//! trait, and abstraction in this crate is designed to enable security, decentralization, and
//! scalability to reinforce each other through sophisticated mathematical coordination rather
//! than forcing trade-offs between these properties.
//!
//! ## Architectural Philosophy
//!
//! This crate embodies the principle that infrastructure capabilities must be separated from
//! application policies. Every type here is a primitive that applications compose in unlimited
//! ways — never embedding specific business logic, organizational policies, or economic models
//! that would constrain innovation.
//!
//! ## Performance Principles
//!
//! No artificial performance ceilings exist here. Throughput characteristics emerge from
//! hardware capabilities, network topology, and computational resources — never from
//! architectural constraints. All types enable maximum parallel execution through
//! dependency-based coordination rather than sequential assumptions.
//!
//! ## Mathematical Certainty
//!
//! All consensus-critical types provide mathematical verification through TEE attestation
//! rather than probabilistic assumptions. [`ConsensusTimestamp`] and [`LogicalSequence`]
//! use blockchain consensus time authority rather than external clock dependencies that
//! would create coordination bottlenecks or security vulnerabilities.
//!
//! ## Cross-Platform Consistency
//!
//! Every type behaves identically across Intel SGX, AMD SEV, ARM `TrustZone`,
//! RISC-V Keystone, and AWS Nitro Enclaves while enabling platform-specific optimization
//! that enhances performance without compromising behavioral consistency.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Primitive types: hashes, addresses, amounts, identifiers.
pub mod primitives;

/// Privacy architecture: object-level policies, selective disclosure, cross-privacy coordination.
pub mod privacy;

/// Consensus types: timestamps, security levels, attestation, finality proofs.
pub mod consensus;

/// Execution types: contexts, results, parallel plans, dependency tracking.
pub mod execution;

/// Network types: topology, peer identifiers, geographic distribution.
pub mod network;

/// Storage types: state roots, Merkle proofs, versioned and encrypted state.
pub mod storage;

/// Economic primitives: balances, fees, stakes, rewards.
pub mod economics;

/// Error types: all error variants and the unified `AevorResult` alias.
pub mod error;

/// Core traits: the behavioral contracts that every AEVOR component implements.
pub mod traits;

/// Cryptographic type abstractions: proofs, signatures, attestations, commitments.
pub mod crypto;

/// TEE platform types: platform variants, attestation reports, isolation boundaries.
pub mod tee;

/// Validator types: capabilities, roles, performance, commitment.
pub mod validator;

/// Transaction types: signed transactions, receipts, status, inputs/outputs.
pub mod transaction;

/// Block types: headers, proofs, attestations, Macro-DAG and Micro-DAG entries.
pub mod block;

/// State types: world state, uncorrupted frontier, state transitions.
pub mod state;

/// Protocol types: version negotiation, epochs, checkpoints.
pub mod protocol;

/// Coordination types: dependency graphs, parallel lanes, synchronization points.
pub mod coordination;

// ============================================================
// PRELUDE
// ============================================================

/// The AEVOR Core prelude — import this for immediate access to all essential types.
///
/// ```rust
/// use aevor_core::prelude::*;
/// ```
pub mod prelude {
    // Primitive types
    pub use crate::primitives::{
        Address, Amount, BlockHash, BlockHeight, BlockNumber, ChainId, ContractAddress,
        CryptoHash, EpochNumber, GasAmount, GasPrice, Hash256, Hash512, Nonce,
        ObjectId, PublicKey, SecretKey, Signature, TransactionHash, ValidatorId,
        ValidatorIndex, ValidatorWeight,
    };

    // Privacy types
    pub use crate::privacy::{
        AccessPolicy, ConfidentialityLevel, CrossPrivacyCoordination, PrivacyBoundary,
        PrivacyContext, PrivacyLevel, PrivacyPolicy, SelectiveDisclosure,
        MixedPrivacyExecution, PrivacyPreservingProof,
    };

    // Consensus types
    pub use crate::consensus::{
        AttestationEvidence, ByzantineFaultProof, ConsensusRound, ConsensusState,
        ConsensusTimestamp, DeterministicFinality, ExecutionAttestation,
        FinalityProof, LogicalSequence, MathematicalCertainty, ProofOfUncorruption,
        SecurityLevel, ValidatorSet, ValidationResult, VerificationProof,
        TeeAttestationPlatform,
    };

    // Execution types
    pub use crate::execution::{
        ContractExecution, ExecutionContext, ExecutionEnvironment, ExecutionResult,
        ObjectDependency, ParallelExecutionPlan, TeeExecutionContext,
        TransactionExecution, ExecutionPath, ExecutionLane, ObjectAccessTracker,
        DependencyType, StateChange, ExecutionEvent, ExecutionLog,
    };

    // Network types
    pub use crate::network::{
        GeographicRegion, NetworkTopology, NodeId, PeerId, SubnetId,
        NetworkAddress, NetworkProtocol, ConnectionMetadata, TopologyMetrics,
        SubnetPermissionPolicy, SubnetConnectivity,
    };

    // Storage types
    pub use crate::storage::{
        MerkleProof, MerkleRoot, StateRoot, StorageKey, StorageValue,
        VersionedState, EncryptedState, StorageCommitment,
    };

    // Economic types
    pub use crate::economics::{
        Balance, Fee, FeePolicy, RewardDistribution, Stake, StakeAmount,
        ValidatorReward, EconomicPrimitive,
    };

    // Error types
    pub use crate::error::{
        AevorError, AevorResult, ConsensusError, CryptoError,
        ExecutionError, NetworkError, PrivacyError, StorageError, TeeError,
        ValidationError, EconomicError,
    };

    // Core traits
    pub use crate::traits::{
        Attestable, BlockchainObject, Committable, CrossPlatformConsistent,
        Executable, MathematicallyVerifiable, Metered, NetworkPropagatable,
        Parallelizable, PrivacyAware, Serializable, StateAccessible,
        TeeCompatible, Verifiable,
    };

    // Crypto types
    pub use crate::crypto::{
        AggregateSignature, BlsSignature, CommitmentOpening, CommitmentProof,
        CommitmentScheme, CrossPlatformAttestation, CryptoProof, CryptoProofType,
        ProvingSystem, SecurityClaims, ZeroKnowledgeProof,
    };

    // TEE types
    pub use crate::tee::{
        AttestationReport, EnclaveIdentity, PlatformCapabilities,
        TeeIsolationBoundary, TeePlatform, TeeServiceType, TeeVersion,
    };

    // Validator types
    pub use crate::validator::{
        ValidatorCapabilities, ValidatorCommitment, ValidatorInfo,
        ValidatorPerformance, ValidatorRole, ValidatorStatus,
    };

    // Transaction types
    pub use crate::transaction::{
        SignedTransaction, Transaction, TransactionInput, TransactionOutput,
        TransactionReceipt, TransactionStatus, TransactionType,
    };

    // Block types
    pub use crate::block::{
        Block, BlockAttestation, BlockHeader, BlockProof, BlockStatus,
        MacroDagBlock, MicroDagEntry,
    };

    // State types
    pub use crate::state::{
        GlobalState, NetworkFrontier, StateTransition, StateVersion,
        UncorruptedFrontier, WorldState,
    };

    // Protocol types
    pub use crate::protocol::{
        CheckpointInfo, ConsensusRoundInfo, NetworkEpoch, ProtocolVersion,
    };

    // Coordination types
    pub use crate::coordination::{
        CoordinationContext, DependencyGraph, ParallelCoordination,
        SynchronizationPoint,
    };
}

// ============================================================
// FLAT RE-EXPORTS AT CRATE ROOT
// ============================================================

pub use primitives::{
    Address, Amount, BlockHash, BlockHeight, BlockNumber, ChainId,
    ContractAddress, CryptoHash, EpochNumber, GasAmount, GasPrice,
    Hash256, Hash512, Nonce, ObjectId, PublicKey, SecretKey, Signature,
    TransactionHash, ValidatorId, ValidatorIndex, ValidatorWeight,
};

pub use error::{AevorError, AevorResult};

pub use traits::{
    Attestable, BlockchainObject, MathematicallyVerifiable,
    Parallelizable, PrivacyAware, TeeCompatible, Verifiable,
};

pub use consensus::SecurityLevel;
pub use privacy::PrivacyLevel;
pub use tee::TeePlatform;

// ============================================================
// CRATE-WIDE CONSTANTS
// ============================================================

/// Number of progressive security levels in the Security Level Accelerator.
pub const MAX_SECURITY_LEVELS: usize = 4;

/// Minimum validator participation fraction for minimal security (2%).
pub const MIN_VALIDATOR_PARTICIPATION_MINIMAL: f64 = 0.02;

/// Minimum validator participation fraction for basic security (10%).
pub const MIN_VALIDATOR_PARTICIPATION_BASIC: f64 = 0.10;

/// Minimum validator participation fraction for strong security (33%).
pub const MIN_VALIDATOR_PARTICIPATION_STRONG: f64 = 0.33;

/// Minimum validator participation fraction for full security (67%).
pub const MIN_VALIDATOR_PARTICIPATION_FULL: f64 = 0.67;

/// Confirmation time ceiling for minimal security in milliseconds.
pub const CONFIRMATION_MS_MINIMAL_MAX: u64 = 50;

/// Confirmation time ceiling for basic security in milliseconds.
pub const CONFIRMATION_MS_BASIC_MAX: u64 = 200;

/// Confirmation time ceiling for strong security in milliseconds.
pub const CONFIRMATION_MS_STRONG_MAX: u64 = 800;

/// Confirmation time ceiling for full security in milliseconds.
pub const CONFIRMATION_MS_FULL_MAX: u64 = 1_000;

/// Number of supported TEE hardware platforms.
pub const SUPPORTED_TEE_PLATFORMS: usize = 5;

/// Number of object-level privacy levels in the mixed privacy architecture.
pub const MAX_PRIVACY_LEVELS: usize = 4;

/// Major version of the AEVOR wire protocol.
pub const PROTOCOL_VERSION_MAJOR: u32 = 1;

/// Minor version of the AEVOR wire protocol.
pub const PROTOCOL_VERSION_MINOR: u32 = 1;

/// Patch version of the AEVOR wire protocol.
pub const PROTOCOL_VERSION_PATCH: u32 = 0;

/// Size in bytes of a SHA-256 / BLAKE3 hash output.
pub const HASH_256_SIZE: usize = 32;

/// Size in bytes of a SHA-512 hash output.
pub const HASH_512_SIZE: usize = 64;

/// Size in bytes of a canonical AEVOR address.
pub const ADDRESS_SIZE: usize = 32;

/// Maximum serialized transaction size (1 MiB). This is a safety bound,
/// not a throughput ceiling — throughput scales with hardware and topology.
pub const MAX_TRANSACTION_SIZE_BYTES: usize = 1_048_576;

/// Maximum serialized block size (128 MiB).
pub const MAX_BLOCK_SIZE_BYTES: usize = 134_217_728;

/// Number of consensus rounds that constitute one epoch.
pub const EPOCH_DURATION_ROUNDS: u64 = 1_000;

/// Maximum depth for cross-contract call recursion.
pub const MAX_CALL_DEPTH: u32 = 128;

/// BLS12-381 public key size in bytes.
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;

/// BLS12-381 signature size in bytes (G2 point).
pub const BLS_SIGNATURE_SIZE: usize = 96;

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_participation_thresholds_are_ordered() {
        assert!(MIN_VALIDATOR_PARTICIPATION_MINIMAL < MIN_VALIDATOR_PARTICIPATION_BASIC);
        assert!(MIN_VALIDATOR_PARTICIPATION_BASIC < MIN_VALIDATOR_PARTICIPATION_STRONG);
        assert!(MIN_VALIDATOR_PARTICIPATION_STRONG < MIN_VALIDATOR_PARTICIPATION_FULL);
        assert!(MIN_VALIDATOR_PARTICIPATION_FULL < 1.0);
    }

    #[test]
    fn confirmation_ceilings_are_ordered() {
        assert!(CONFIRMATION_MS_MINIMAL_MAX < CONFIRMATION_MS_BASIC_MAX);
        assert!(CONFIRMATION_MS_BASIC_MAX < CONFIRMATION_MS_STRONG_MAX);
        assert!(CONFIRMATION_MS_STRONG_MAX <= CONFIRMATION_MS_FULL_MAX);
    }

    #[test]
    fn hash_and_address_sizes_are_correct() {
        assert_eq!(HASH_256_SIZE, 32);
        assert_eq!(HASH_512_SIZE, 64);
        assert_eq!(ADDRESS_SIZE, 32);
    }

    #[test]
    fn security_and_platform_counts_are_correct() {
        assert_eq!(MAX_SECURITY_LEVELS, 4);
        assert_eq!(SUPPORTED_TEE_PLATFORMS, 5);
        assert_eq!(MAX_PRIVACY_LEVELS, 4);
    }

    #[test]
    fn bls_constants_are_correct() {
        assert_eq!(BLS_PUBLIC_KEY_SIZE, 48);
        assert_eq!(BLS_SIGNATURE_SIZE, 96);
    }
}
