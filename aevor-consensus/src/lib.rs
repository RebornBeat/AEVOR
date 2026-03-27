//! # AEVOR Consensus: Proof of Uncorruption
//!
//! `aevor-consensus` implements AEVOR's Proof of Uncorruption (`PoU`) consensus mechanism,
//! which provides **mathematical certainty through deterministic security** rather than
//! probabilistic assumptions requiring multiple confirmations.
//!
//! ## Revolutionary Consensus Paradigm
//!
//! Traditional consensus mechanisms (`PoW`, `PoS`, BFT) reduce the *probability* of incorrect
//! outcomes through economic incentives and repeated verification. `PoU` provides
//! **mathematical proof** of execution correctness through TEE attestation, eliminating
//! uncertainty entirely and enabling immediate finality.
//!
//! ## Progressive Security Levels
//!
//! Rather than forcing a single security/latency trade-off, `PoU` provides four progressive
//! levels that scale validator participation and confirmation time based on application needs:
//!
//! | Level | Validators | Latency | Use Case |
//! |-------|-----------|---------|----------|
//! | Minimal | 2–3% | 20–50ms | Micropayments, gaming |
//! | Basic | 10–20% | 100–200ms | Standard transactions |
//! | Strong | >33% | 500–800ms | High-value operations |
//! | Full | >67% | <1s | Critical / institutional |
//!
//! All four levels provide **mathematical security** through TEE attestation — the difference
//! is the breadth of validator participation providing Byzantine fault tolerance.
//!
//! ## Blockchain Consensus Time Authority
//!
//! All temporal coordination uses blockchain consensus time (`ConsensusTimestamp`) with
//! logical sequencing rather than external clock synchronization. This eliminates external
//! timing authority dependencies that would create coordination bottlenecks or attack vectors.
//!
//! ## Cross-Platform Consistency
//!
//! Consensus operations produce identical results across Intel SGX, AMD SEV, ARM `TrustZone`,
//! RISC-V Keystone, and AWS Nitro Enclaves through mathematical verification of execution
//! correctness, not platform-specific synchronization.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Core PoU consensus engine: round management, proposal, attestation collection.
pub mod engine;

/// Validator set management: membership, weight calculation, rotation.
pub mod validator_set;

/// Security Level Accelerator: progressive security with BLS aggregation.
pub mod security_levels;

/// TEE attestation integration: collection, verification, mathematical proof assembly.
pub mod attestation;

/// Slashing and accountability: graduated penalties with mathematical verification.
pub mod slashing;

/// Uncorrupted frontier tracking: state progression verification.
pub mod frontier;

/// Checkpoint creation and verification: epoch boundaries and long-range protection.
pub mod checkpoint;

/// Byzantine fault detection: real-time corruption identification and isolation.
pub mod byzantine;

/// Economic accountability: reward distribution, penalty application.
pub mod economics;

/// Round timing: logical sequencing with blockchain consensus time authority.
pub mod timing;

/// Finality: mathematical certainty proofs and commitment generation.
pub mod finality;

// ============================================================
// PRELUDE
// ============================================================

/// Consensus prelude — all essential consensus types.
///
/// ```rust
/// use aevor_consensus::prelude::*;
/// ```
pub mod prelude {
    pub use crate::engine::{
        ConsensusEngine, ConsensusRound, ConsensusState, RoundResult,
        ProposalMessage, AttestationCollection,
    };
    pub use crate::validator_set::{
        ValidatorSet, ValidatorEntry, ValidatorWeight, ValidatorRotation,
        ValidatorSetUpdate, WeightedValidatorSelection,
    };
    pub use crate::security_levels::{
        SecurityLevel, SecurityLevelConfig, SecurityLevelAccelerator,
        MinimalSecurity, BasicSecurity, StrongSecurity, FullSecurity,
        ValidatorParticipation, ParticipationThreshold,
    };
    pub use crate::attestation::{
        AttestationEvidence, AttestationCollector, AttestationVerifier,
        ExecutionAttestation, CrossPlatformAttestationSet, TeeAttestationPlatform,
        MathematicalCertaintyProof,
    };
    pub use crate::slashing::{
        SlashingMechanism, SlashingEvidence, SlashingPenalty, SlashingProof,
        DoubleSignEvidence, EquivocationEvidence, LivenessViolation,
    };
    pub use crate::frontier::{
        FrontierState, FrontierAdvancement, UncorruptedFrontierVerifier,
        FrontierProof, FrontierCorruption,
    };
    pub use crate::checkpoint::{
        Checkpoint, CheckpointInfo, CheckpointCreator, CheckpointVerifier,
        EpochBoundary, LongRangeProtection,
    };
    pub use crate::byzantine::{
        ByzantineDetector, ByzantineEvidence, ByzantineIsolation,
        CorruptionProof, MisbehaviorType,
    };
    pub use crate::finality::{
        FinalityProof, DeterministicFinality, MathematicalCertainty,
        FinalityGadget, ImmediateFinalityConfirmation,
    };
    pub use crate::timing::{
        ConsensusTimestamp, LogicalSequence, BlockReference, EpochReference,
        ConsensusClock, RoundDuration,
    };
    pub use crate::{ConsensusError, ConsensusResult};
}

// ============================================================
// RE-EXPORTS FROM aevor-core
// ============================================================

pub use aevor_core::consensus::{
    ConsensusRound, ConsensusState, ConsensusTimestamp, DeterministicFinality,
    ExecutionAttestation, FinalityProof, LogicalSequence, MathematicalCertainty,
    ProofOfUncorruption, SecurityLevel, TeeAttestationPlatform, ValidationResult,
    ValidatorSet, VerificationProof,
};

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from consensus operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ConsensusError {
    /// Insufficient validator participation for the requested security level.
    #[error("insufficient validator participation: {actual:.1}% < {required:.1}% for {level}")]
    InsufficientParticipation {
        /// Actual participation fraction (0.0–1.0).
        actual: f64,
        /// Required participation fraction.
        required: f64,
        /// Security level that was requested.
        level: String,
    },

    /// TEE attestation verification failed.
    #[error("attestation verification failed: {reason}")]
    AttestationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Byzantine behavior detected from a validator.
    #[error("Byzantine behavior from validator {validator_id}: {behavior}")]
    ByzantineBehavior {
        /// Identifier of the misbehaving validator.
        validator_id: String,
        /// Description of the misbehavior.
        behavior: String,
    },

    /// Consensus round timed out without reaching finality.
    #[error("consensus round {round} timed out after {elapsed_ms}ms")]
    RoundTimeout {
        /// Round number that timed out.
        round: u64,
        /// Elapsed time in milliseconds.
        elapsed_ms: u64,
    },

    /// Invalid block proposal received.
    #[error("invalid proposal: {reason}")]
    InvalidProposal {
        /// Reason the proposal is invalid.
        reason: String,
    },

    /// Frontier corruption detected.
    #[error("frontier corruption detected: {description}")]
    FrontierCorruption {
        /// Description of the corruption.
        description: String,
    },

    /// Slashing evidence is invalid or insufficient.
    #[error("invalid slashing evidence: {reason}")]
    InvalidSlashingEvidence {
        /// Reason the evidence is invalid.
        reason: String,
    },
}

/// Convenience alias for consensus results.
pub type ConsensusResult<T> = Result<T, ConsensusError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Minimum fraction of validators for minimal security level.
pub const MINIMAL_SECURITY_THRESHOLD: f64 = 0.02;

/// Minimum fraction of validators for basic security level.
pub const BASIC_SECURITY_THRESHOLD: f64 = 0.10;

/// Minimum fraction of validators for strong security level (Byzantine fault tolerance).
pub const STRONG_SECURITY_THRESHOLD: f64 = 0.33;

/// Minimum fraction of validators for full security level.
pub const FULL_SECURITY_THRESHOLD: f64 = 0.67;

/// Maximum confirmation time for minimal security in milliseconds.
pub const MINIMAL_CONFIRMATION_MS: u64 = 50;

/// Maximum confirmation time for basic security in milliseconds.
pub const BASIC_CONFIRMATION_MS: u64 = 200;

/// Maximum confirmation time for strong security in milliseconds.
pub const STRONG_CONFIRMATION_MS: u64 = 800;

/// Maximum confirmation time for full security in milliseconds.
pub const FULL_CONFIRMATION_MS: u64 = 1_000;

/// Number of consensus rounds per epoch.
pub const ROUNDS_PER_EPOCH: u64 = 1_000;

/// Maximum validators that can be Byzantine before network failure (strictly < 1/3).
///
/// BFT consensus requires f < n/3 Byzantine faults. This constant is set to 0.32
/// (slightly below 1/3 ≈ 0.333) to maintain a clear strict-less-than relationship
/// with `STRONG_SECURITY_THRESHOLD` (0.33), ensuring the invariant:
/// `MAX_BYZANTINE_FRACTION < STRONG_SECURITY_THRESHOLD`.
pub const MAX_BYZANTINE_FRACTION: f64 = 0.32;

/// Slashing penalty for double-signing (fraction of stake).
pub const DOUBLE_SIGN_SLASH_FRACTION: f64 = 0.05;

/// Slashing penalty for liveness violation (fraction of stake, per epoch).
pub const LIVENESS_SLASH_FRACTION: f64 = 0.001;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_thresholds_are_ordered() {
        assert!(MINIMAL_SECURITY_THRESHOLD < BASIC_SECURITY_THRESHOLD);
        assert!(BASIC_SECURITY_THRESHOLD < STRONG_SECURITY_THRESHOLD);
        assert!(STRONG_SECURITY_THRESHOLD < FULL_SECURITY_THRESHOLD);
        assert!(FULL_SECURITY_THRESHOLD < 1.0);
    }

    #[test]
    fn confirmation_times_are_ordered() {
        assert!(MINIMAL_CONFIRMATION_MS < BASIC_CONFIRMATION_MS);
        assert!(BASIC_CONFIRMATION_MS < STRONG_CONFIRMATION_MS);
        assert!(STRONG_CONFIRMATION_MS <= FULL_CONFIRMATION_MS);
    }

    #[test]
    fn byzantine_threshold_is_below_strong_security() {
        // Strong security requires >33% honest — Byzantine tolerance is <33%
        assert!(MAX_BYZANTINE_FRACTION < STRONG_SECURITY_THRESHOLD);
    }
}
