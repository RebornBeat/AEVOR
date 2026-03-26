//! # Consensus Types
//!
//! Type definitions for AEVOR's Proof of Uncorruption consensus mechanism,
//! including security levels, timestamps, attestation evidence, finality proofs,
//! and validator set management.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::primitives::{
    Address, BlockHash, BlockHeight, EpochNumber, Hash256,
    PublicKey, Signature, ValidatorId, ValidatorIndex, ValidatorWeight,
};

// ============================================================
// SECURITY LEVEL
// ============================================================

/// Progressive security levels for the Security Level Accelerator.
///
/// Higher levels require more validator participation and take longer to
/// confirm, but provide stronger Byzantine fault tolerance guarantees.
/// **All levels provide mathematical security** — the difference is the
/// breadth of the validator participation providing the guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityLevel {
    /// 2–3% of validators, 20–50ms confirmation.
    /// Use for: micropayments, gaming, low-value operations.
    Minimal = 0,

    /// 10–20% of validators, 100–200ms confirmation.
    /// Use for: standard transactions, routine smart contracts.
    Basic = 1,

    /// >33% of validators, 500–800ms confirmation (Byzantine fault tolerant).
    /// Use for: high-value transactions, enterprise operations.
    Strong = 2,

    /// >67% of validators, <1s confirmation.
    /// Use for: critical operations, large financial transfers.
    Full = 3,
}

impl SecurityLevel {
    /// Minimum validator participation fraction required for this level.
    pub fn min_participation(&self) -> f64 {
        match self {
            Self::Minimal => 0.02,
            Self::Basic => 0.10,
            Self::Strong => 0.33,
            Self::Full => 0.67,
        }
    }

    /// Maximum expected confirmation time in milliseconds.
    pub fn max_confirmation_ms(&self) -> u64 {
        match self {
            Self::Minimal => 50,
            Self::Basic => 200,
            Self::Strong => 800,
            Self::Full => 1_000,
        }
    }

    /// Returns `true` if this level provides Byzantine fault tolerance
    /// (requires >33% honest validator participation).
    pub fn is_byzantine_fault_tolerant(&self) -> bool {
        matches!(self, Self::Strong | Self::Full)
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::Basic => "Basic",
            Self::Strong => "Strong",
            Self::Full => "Full",
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Basic
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================
// CONSENSUS TIMESTAMP
// ============================================================

/// A temporal reference derived from blockchain consensus — never from external clocks.
///
/// Uses the consensus round number and logical sequence for ordering.
/// This eliminates external timing authority dependencies and the
/// synchronization bottlenecks they create.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct ConsensusTimestamp {
    /// Consensus round when this timestamp was established.
    pub round: u64,
    /// Logical sequence number within the round.
    pub sequence: u64,
    /// Block height at which this timestamp is anchored.
    pub block_height: u64,
}

impl ConsensusTimestamp {
    /// Create from round, sequence, and block height.
    pub const fn new(round: u64, sequence: u64, block_height: u64) -> Self {
        Self { round, sequence, block_height }
    }

    /// Genesis timestamp (round 0, sequence 0, height 0).
    pub const GENESIS: Self = Self { round: 0, sequence: 0, block_height: 0 };

    /// Returns `true` if this timestamp strictly precedes `other` in causal order.
    pub fn precedes(&self, other: &Self) -> bool {
        if self.round != other.round {
            return self.round < other.round;
        }
        if self.block_height != other.block_height {
            return self.block_height < other.block_height;
        }
        self.sequence < other.sequence
    }
}

impl std::fmt::Display for ConsensusTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "round:{}/seq:{}/h:{}", self.round, self.sequence, self.block_height)
    }
}

// ============================================================
// LOGICAL SEQUENCE
// ============================================================

/// Dependency-based logical ordering without external timing.
///
/// Enables parallel execution by expressing causal dependencies explicitly
/// rather than relying on wall-clock time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalSequence {
    /// Monotonically increasing sequence number.
    pub number: u64,
    /// Transactions this sequence number causally follows.
    pub dependencies: Vec<Hash256>,
    /// Parallel group identifier — same-group operations can execute concurrently.
    pub parallel_group: u32,
}

impl LogicalSequence {
    /// Create a new logical sequence number.
    pub fn new(number: u64, dependencies: Vec<Hash256>, parallel_group: u32) -> Self {
        Self { number, dependencies, parallel_group }
    }

    /// Create an independent sequence (no dependencies, any group).
    pub fn independent(number: u64) -> Self {
        Self {
            number,
            dependencies: Vec::new(),
            parallel_group: 0,
        }
    }

    /// Returns `true` if this sequence has no dependencies (can run in any order).
    pub fn is_independent(&self) -> bool {
        self.dependencies.is_empty()
    }
}

// ============================================================
// BLOCK REFERENCE
// ============================================================

/// A reference to a specific block used for temporal anchoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockReference {
    /// Hash of the referenced block.
    pub block_hash: BlockHash,
    /// Height of the referenced block.
    pub block_height: BlockHeight,
    /// Consensus round of the referenced block.
    pub consensus_round: u64,
}

impl BlockReference {
    /// Create a new block reference.
    pub fn new(hash: BlockHash, height: BlockHeight, round: u64) -> Self {
        Self {
            block_hash: hash,
            block_height: height,
            consensus_round: round,
        }
    }
}

// ============================================================
// CONSENSUS ROUND
// ============================================================

/// A consensus round — the basic unit of consensus progression.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusRound {
    /// Round number.
    pub number: u64,
    /// Epoch this round belongs to.
    pub epoch: EpochNumber,
    /// Block height at the start of this round.
    pub start_height: BlockHeight,
    /// Blocks produced in this round.
    pub blocks: Vec<BlockHash>,
    /// Security level achieved in this round.
    pub security_level: SecurityLevel,
    /// Timestamp this round was established.
    pub timestamp: ConsensusTimestamp,
}

// ============================================================
// CONSENSUS STATE
// ============================================================

/// The current state of the consensus engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ConsensusState {
    /// Initializing — not yet ready to participate in consensus.
    #[default]
    Initializing,
    /// Syncing — catching up to the current network state.
    Syncing,
    /// Proposing — producing or waiting for a block proposal.
    Proposing,
    /// Voting — collecting validator votes/attestations.
    Voting,
    /// Finalizing — achieving finality for the current round.
    Finalizing,
    /// Finalized — the current round has reached finality.
    Finalized,
    /// Halted — consensus paused (e.g., due to detected corruption).
    Halted,
}

// ============================================================
// VALIDATOR SET
// ============================================================

/// The set of active validators for a given epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// The epoch this validator set is active for.
    pub epoch: EpochNumber,
    /// Validators indexed by their identifier.
    pub validators: HashMap<ValidatorId, ValidatorEntry>,
    /// Total voting weight of all validators.
    pub total_weight: ValidatorWeight,
    /// Threshold weights for each security level.
    pub security_thresholds: SecurityThresholds,
}

impl ValidatorSet {
    /// Compute the fraction of total weight held by a set of validators.
    pub fn participation_fraction(&self, validators: &[ValidatorId]) -> f64 {
        if self.total_weight.as_u64() == 0 {
            return 0.0;
        }
        let participating_weight: u64 = validators
            .iter()
            .filter_map(|id| self.validators.get(id))
            .map(|v| v.weight.as_u64())
            .sum();
        participating_weight as f64 / self.total_weight.as_u64() as f64
    }

    /// Check if a set of validators meets the threshold for a security level.
    pub fn meets_security_level(
        &self,
        validators: &[ValidatorId],
        level: SecurityLevel,
    ) -> bool {
        let fraction = self.participation_fraction(validators);
        fraction >= level.min_participation()
    }
}

/// A single entry in the validator set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    /// Validator identifier (public key hash).
    pub id: ValidatorId,
    /// Validator's public signing key.
    pub public_key: PublicKey,
    /// Voting weight proportional to stake.
    pub weight: ValidatorWeight,
    /// Index in the validator set (for bitmap operations).
    pub index: ValidatorIndex,
    /// Validator's staking address.
    pub stake_address: Address,
    /// Whether this validator is currently active.
    pub is_active: bool,
}

/// Pre-computed weight thresholds for each security level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecurityThresholds {
    /// Minimum weight for Minimal security.
    pub minimal: ValidatorWeight,
    /// Minimum weight for Basic security.
    pub basic: ValidatorWeight,
    /// Minimum weight for Strong security.
    pub strong: ValidatorWeight,
    /// Minimum weight for Full security.
    pub full: ValidatorWeight,
}

// ============================================================
// TEE ATTESTATION
// ============================================================

/// Platform identifier for cross-platform attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeAttestationPlatform {
    /// Intel Software Guard Extensions.
    IntelSgx,
    /// AMD Secure Encrypted Virtualization.
    AmdSev,
    /// ARM TrustZone.
    ArmTrustZone,
    /// RISC-V Keystone.
    RiscvKeystone,
    /// AWS Nitro Enclaves.
    AwsNitro,
}

impl std::fmt::Display for TeeAttestationPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntelSgx => write!(f, "Intel-SGX"),
            Self::AmdSev => write!(f, "AMD-SEV"),
            Self::ArmTrustZone => write!(f, "ARM-TrustZone"),
            Self::RiscvKeystone => write!(f, "RISC-V-Keystone"),
            Self::AwsNitro => write!(f, "AWS-Nitro"),
        }
    }
}

/// Attestation evidence from a TEE platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Platform that generated this attestation.
    pub platform: TeeAttestationPlatform,
    /// Raw attestation report bytes from the platform.
    pub raw_report: Vec<u8>,
    /// Measurement of the executing code (MRENCLAVE or equivalent).
    pub code_measurement: Hash256,
    /// Attestation nonce to prevent replay attacks.
    pub nonce: [u8; 32],
    /// Whether the platform is in production mode (not debug).
    pub is_production: bool,
    /// Platform security version number.
    pub svn: u32,
}

/// TEE execution attestation linking a specific execution to its proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionAttestation {
    /// Evidence from the TEE platform.
    pub evidence: AttestationEvidence,
    /// Hash of the execution inputs that were attested.
    pub input_hash: Hash256,
    /// Hash of the execution outputs that were attested.
    pub output_hash: Hash256,
    /// Transaction hash this attestation covers.
    pub transaction_hash: Hash256,
    /// Validator that produced this attestation.
    pub validator_id: ValidatorId,
    /// Validator signature over the attestation.
    pub validator_signature: Signature,
}

// ============================================================
// PROOF TYPES
// ============================================================

/// Mathematical certainty — the result of successful PoU consensus.
///
/// Provides cryptographic proof that a transaction or block has been
/// finalized with mathematical certainty through TEE attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MathematicalCertainty {
    /// The item (transaction or block) that has been finalized.
    pub item_hash: Hash256,
    /// Proof of finality.
    pub finality_proof: FinalityProof,
    /// Security level that was achieved.
    pub security_level: SecurityLevel,
    /// Timestamp of finalization.
    pub timestamp: ConsensusTimestamp,
}

/// Proof of finality for a block or transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Validator signatures contributing to this finality proof.
    pub signatures: Vec<ValidatorSignature>,
    /// Aggregated BLS signature over all validator signatures.
    pub aggregate_signature: Vec<u8>,
    /// Bitmap indicating which validators in the set signed.
    pub participant_bitmap: Vec<u8>,
    /// Total voting weight that signed.
    pub total_weight: ValidatorWeight,
    /// Security level achieved by this proof.
    pub security_level: SecurityLevel,
}

/// A single validator's signature contribution to a finality proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator identifier.
    pub validator_id: ValidatorId,
    /// Validator index in the set.
    pub index: ValidatorIndex,
    /// BLS signature.
    pub signature: Vec<u8>,
    /// TEE attestation if this signature included TEE verification.
    pub tee_attestation: Option<ExecutionAttestation>,
}

/// Deterministic finality guarantee.
pub type DeterministicFinality = MathematicalCertainty;

/// A proof that a specific computation was correct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationProof {
    /// What is being verified.
    pub subject: Hash256,
    /// Proof bytes.
    pub proof: Vec<u8>,
    /// TEE attestations supporting this proof.
    pub attestations: Vec<AttestationEvidence>,
}

/// The top-level Proof of Uncorruption marker type.
///
/// Wraps a `MathematicalCertainty` with additional PoU-specific metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfUncorruption {
    /// The mathematical certainty proof.
    pub certainty: MathematicalCertainty,
    /// Validators whose TEE attestations contributed.
    pub attesting_validators: Vec<ValidatorId>,
    /// Combined attestation from all contributing TEE enclaves.
    pub combined_attestation: Hash256,
}

// ============================================================
// BYZANTINE FAULT EVIDENCE
// ============================================================

/// Evidence of Byzantine behavior from a validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByzantineFaultProof {
    /// Validator who exhibited Byzantine behavior.
    pub offender: ValidatorId,
    /// Type of Byzantine fault.
    pub fault_type: ByzantineFaultType,
    /// First conflicting evidence item.
    pub evidence_a: Vec<u8>,
    /// Second conflicting evidence item (for equivocation).
    pub evidence_b: Option<Vec<u8>>,
    /// Consensus timestamp when this fault occurred.
    pub timestamp: ConsensusTimestamp,
}

/// Types of Byzantine faults detectable by PoU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ByzantineFaultType {
    /// Validator signed two different blocks at the same height.
    Equivocation,
    /// Validator sent conflicting votes in the same round.
    ConflictingVote,
    /// Validator produced invalid TEE attestation.
    InvalidAttestation,
    /// Validator signed a block with invalid state.
    InvalidStateSignature,
}

// ============================================================
// VALIDATION RESULT
// ============================================================

/// Result of validating a block or transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether validation passed.
    pub is_valid: bool,
    /// Error description if validation failed.
    pub error: Option<String>,
    /// Warnings (validation passed but with concerns).
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a successful validation result.
    pub fn valid() -> Self {
        Self { is_valid: true, error: None, warnings: Vec::new() }
    }

    /// Create a failed validation result.
    pub fn invalid(error: impl Into<String>) -> Self {
        Self { is_valid: false, error: Some(error.into()), warnings: Vec::new() }
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_level_thresholds_are_ordered() {
        assert!(SecurityLevel::Minimal.min_participation() < SecurityLevel::Basic.min_participation());
        assert!(SecurityLevel::Basic.min_participation() < SecurityLevel::Strong.min_participation());
        assert!(SecurityLevel::Strong.min_participation() < SecurityLevel::Full.min_participation());
    }

    #[test]
    fn security_level_bft_threshold() {
        assert!(!SecurityLevel::Minimal.is_byzantine_fault_tolerant());
        assert!(!SecurityLevel::Basic.is_byzantine_fault_tolerant());
        assert!(SecurityLevel::Strong.is_byzantine_fault_tolerant());
        assert!(SecurityLevel::Full.is_byzantine_fault_tolerant());
    }

    #[test]
    fn consensus_timestamp_genesis_is_zero() {
        assert_eq!(ConsensusTimestamp::GENESIS.round, 0);
        assert_eq!(ConsensusTimestamp::GENESIS.sequence, 0);
    }

    #[test]
    fn consensus_timestamp_precedes() {
        let a = ConsensusTimestamp::new(1, 0, 10);
        let b = ConsensusTimestamp::new(2, 0, 11);
        assert!(a.precedes(&b));
        assert!(!b.precedes(&a));
    }

    #[test]
    fn logical_sequence_independence() {
        let seq = LogicalSequence::independent(42);
        assert!(seq.is_independent());
        assert_eq!(seq.number, 42);
    }

    #[test]
    fn validation_result_constructors() {
        assert!(ValidationResult::valid().is_valid);
        assert!(!ValidationResult::invalid("bad").is_valid);
    }

    #[test]
    fn security_level_display() {
        assert_eq!(SecurityLevel::Full.to_string(), "Full");
        assert_eq!(SecurityLevel::Minimal.to_string(), "Minimal");
    }
}
