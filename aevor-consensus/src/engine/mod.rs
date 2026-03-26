//! Core PoU consensus engine: round management, proposals, attestation collection.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHash, BlockHeight, Hash256, ValidatorId};
use aevor_core::consensus::{
    ConsensusTimestamp, FinalityProof, SecurityLevel, ValidationResult,
};

/// Current state of the consensus engine.
pub use aevor_core::consensus::ConsensusState;

/// A completed consensus round with its outcome.
pub use aevor_core::consensus::ConsensusRound;

/// Result of processing a single consensus round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundResult {
    /// Round number that was processed.
    pub round: u64,
    /// Blocks finalized during this round.
    pub finalized_blocks: Vec<BlockHash>,
    /// Security level achieved.
    pub security_level: SecurityLevel,
    /// How long the round took in milliseconds.
    pub duration_ms: u64,
    /// Fraction of stake that participated (0–100).
    pub participation_pct: u8,
    /// Finality proof if full security was achieved.
    pub finality_proof: Option<FinalityProof>,
    /// Validation result for this round.
    pub validation: ValidationResult,
}

impl RoundResult {
    /// Returns `true` if this round reached the required security level.
    pub fn is_successful(&self) -> bool {
        self.validation.is_valid
    }

    /// Returns `true` if a finality proof was produced.
    pub fn is_finalized(&self) -> bool { self.finality_proof.is_some() }
}

/// A block proposal message broadcast by a validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalMessage {
    /// Validator that produced this proposal.
    pub proposer: ValidatorId,
    /// Hash of the proposed block.
    pub block_hash: BlockHash,
    /// Height of the proposed block.
    pub block_height: BlockHeight,
    /// Round this proposal belongs to.
    pub round: u64,
    /// Consensus timestamp of this proposal.
    pub timestamp: ConsensusTimestamp,
    /// Proposer's signature over (block_hash ‖ round ‖ timestamp).
    pub signature: aevor_core::primitives::Signature,
    /// TEE attestation proving execution correctness.
    pub tee_attestation: Option<aevor_core::consensus::ExecutionAttestation>,
}

impl ProposalMessage {
    /// BLAKE3 hash of the proposal contents (for deduplication).
    pub fn content_hash(&self) -> Hash256 {
        use aevor_core::primitives::Hash256;
        let mut data = self.block_hash.0.to_vec();
        data.extend_from_slice(&self.round.to_le_bytes());
        data.extend_from_slice(&self.block_height.0.to_le_bytes());
        // Full hash computed by aevor-crypto in production
        Hash256::ZERO // Placeholder — full impl uses Blake3Hasher
    }
}

/// Accumulates attestations from validators for a specific block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationCollection {
    /// Block being attested.
    pub block_hash: BlockHash,
    /// Attestations collected so far.
    pub attestations: Vec<aevor_core::block::BlockAttestation>,
    /// Minimum security level required for this collection.
    pub required_security_level: SecurityLevel,
    /// Total weight of attestations collected.
    pub current_weight: aevor_core::primitives::ValidatorWeight,
    /// Total possible weight (full validator set).
    pub total_weight: aevor_core::primitives::ValidatorWeight,
}

impl AttestationCollection {
    /// Create a new empty attestation collection.
    pub fn new(
        block_hash: BlockHash,
        required_security_level: SecurityLevel,
        total_weight: aevor_core::primitives::ValidatorWeight,
    ) -> Self {
        Self {
            block_hash,
            attestations: Vec::new(),
            required_security_level,
            current_weight: aevor_core::primitives::ValidatorWeight::ZERO,
            total_weight,
        }
    }

    /// Add an attestation with its weight.
    pub fn add(
        &mut self,
        attestation: aevor_core::block::BlockAttestation,
        weight: aevor_core::primitives::ValidatorWeight,
    ) {
        self.attestations.push(attestation);
        self.current_weight = aevor_core::primitives::ValidatorWeight::from_u64(
            self.current_weight.as_u64().saturating_add(weight.as_u64())
        );
    }

    /// Fraction of total weight that has attested (0.0–1.0).
    pub fn participation_fraction(&self) -> f64 {
        if self.total_weight.as_u64() == 0 { return 0.0; }
        self.current_weight.as_u64() as f64 / self.total_weight.as_u64() as f64
    }

    /// Returns `true` if the required security level has been reached.
    pub fn meets_required_level(&self) -> bool {
        self.participation_fraction() >= self.required_security_level.min_participation()
    }

    /// Build a `ValidationResult` from the current state.
    pub fn to_validation_result(&self) -> ValidationResult {
        if self.meets_required_level() {
            ValidationResult::valid()
        } else {
            ValidationResult::invalid("insufficient participation")
        }
    }
}

/// The main Proof of Uncorruption consensus engine.
pub struct ConsensusEngine {
    current_round: u64,
    state: ConsensusState,
    security_level: SecurityLevel,
}

impl ConsensusEngine {
    /// Create a new consensus engine with the given security level target.
    pub fn new(security_level: SecurityLevel) -> Self {
        Self {
            current_round: 0,
            state: ConsensusState::Initializing,
            security_level,
        }
    }

    /// Current consensus round number.
    pub fn current_round(&self) -> u64 { self.current_round }
    /// Current engine state.
    pub fn state(&self) -> ConsensusState { self.state }
    /// Target security level.
    pub fn security_level(&self) -> SecurityLevel { self.security_level }

    /// Advance to the next round.
    pub fn advance_round(&mut self) {
        self.current_round += 1;
        self.state = ConsensusState::Proposing;
    }

    /// Produce a `RoundResult` from a completed collection.
    pub fn finalize_round(
        &mut self,
        collection: &AttestationCollection,
        duration_ms: u64,
    ) -> RoundResult {
        let validation = collection.to_validation_result();
        let finalized = if collection.meets_required_level() {
            vec![collection.block_hash]
        } else {
            vec![]
        };
        RoundResult {
            round: self.current_round,
            finalized_blocks: finalized,
            security_level: self.security_level,
            duration_ms,
            participation_pct: (collection.participation_fraction() * 100.0) as u8,
            finality_proof: None, // Built by BLS aggregation in production
            validation,
        }
    }
}
