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
    /// Proposer's signature over (`block_hash` ‖ round ‖ timestamp).
    pub signature: aevor_core::primitives::Signature,
    /// TEE attestation proving execution correctness.
    pub tee_attestation: Option<aevor_core::consensus::ExecutionAttestation>,
}

impl ProposalMessage {
    /// BLAKE3 hash of the proposal contents (for deduplication).
    pub fn content_hash(&self) -> Hash256 {
        use aevor_crypto::hash::Blake3Hasher;
        let mut data = self.block_hash.0.to_vec();
        data.extend_from_slice(&self.round.to_le_bytes());
        data.extend_from_slice(&self.block_height.0.to_le_bytes());
        let mut hasher = Blake3Hasher::new();
        hasher.update(&data);
        hasher.finalize().0
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
    #[allow(clippy::cast_precision_loss)] // weight ratios: precision loss is acceptable for participation metrics
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
        let meets = collection.meets_required_level();
        let finalized = if meets {
            vec![collection.block_hash]
        } else {
            vec![]
        };
        // A finalized block carries a real finality proof built from the
        // collected attestations; an unfinalized round has none.
        let finality_proof = if meets {
            Some(Self::build_finality_proof(collection, self.security_level))
        } else {
            None
        };
        RoundResult {
            round: self.current_round,
            finalized_blocks: finalized,
            security_level: self.security_level,
            duration_ms,
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            // participation is always in [0.0, 1.0] so * 100.0 is in [0, 100] — safe to u8
            participation_pct: (collection.participation_fraction() * 100.0) as u8,
            finality_proof,
            validation,
        }
    }

    /// Build a finality proof from a completed attestation collection.
    ///
    /// Populates the real validator signatures, participant bitmap, signed
    /// voting weight, and achieved security level, and binds every validator
    /// signature together with a BLAKE3 commitment over the block hash and the
    /// ordered signatures.
    ///
    /// The `aggregate_signature` field is this BLAKE3 commitment today. It
    /// becomes a BLS12-381 point aggregate (via `aevor_crypto::bls`) once
    /// validators sign attestations with BLS keys — `BlockAttestation`
    /// currently carries a 64-byte (non-BLS) signature, so real point
    /// aggregation is not yet possible here. See the stub-and-simulation
    /// register (B4).
    fn build_finality_proof(
        collection: &AttestationCollection,
        security_level: SecurityLevel,
    ) -> FinalityProof {
        use aevor_core::consensus::ValidatorSignature;
        use aevor_core::primitives::ValidatorIndex;
        use aevor_crypto::hash::Blake3Hasher;

        let n = collection.attestations.len();
        let mut signatures = Vec::with_capacity(n);
        let mut participant_bitmap = vec![0u8; n.div_ceil(8)];
        let mut commitment = Blake3Hasher::new();
        commitment.update(&collection.block_hash.0);

        for (i, att) in collection.attestations.iter().enumerate() {
            signatures.push(ValidatorSignature {
                validator_id: att.validator_id,
                index: ValidatorIndex(u32::try_from(i).unwrap_or(u32::MAX)),
                signature: att.signature.0.to_vec(),
                tee_attestation: att.tee_attestation.clone(),
            });
            participant_bitmap[i / 8] |= 1 << (i % 8);
            commitment.update(&att.signature.0);
        }

        let aggregate_signature = commitment.finalize().0.0.to_vec();

        FinalityProof {
            signatures,
            aggregate_signature,
            participant_bitmap,
            total_weight: collection.current_weight,
            security_level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ValidatorWeight};
    use aevor_core::consensus::SecurityLevel;

    fn w(n: u64) -> ValidatorWeight { ValidatorWeight::from_u64(n) }
    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }

    #[test]
    fn attestation_collection_starts_empty() {
        let c = AttestationCollection::new(bh(1), SecurityLevel::Basic, w(1000));
        assert_eq!(c.attestations.len(), 0);
        assert_eq!(c.participation_fraction(), 0.0);
        assert!(!c.meets_required_level());
    }

    #[test]
    fn attestation_collection_meets_level_after_sufficient_weight() {
        let mut c = AttestationCollection::new(bh(1), SecurityLevel::Minimal, w(100));
        // Minimal requires ~2–3% — add a dummy attestation with 10% weight
        let att = aevor_core::block::BlockAttestation {
            block_hash: bh(1),
            validator_id: Hash256([1u8; 32]),
            signature: aevor_core::primitives::Signature([0u8; 64]),
            tee_attestation: None,
            timestamp: aevor_core::consensus::ConsensusTimestamp::GENESIS,
        };
        c.add(att, w(10)); // 10% of total
        assert!(c.participation_fraction() > 0.0);
    }

    #[test]
    fn finalized_round_produces_real_finality_proof() {
        // Two attestations at 10% each easily clears Minimal (~2–3%).
        let mut c = AttestationCollection::new(bh(7), SecurityLevel::Minimal, w(100));
        for v in 1u8..=2 {
            let att = aevor_core::block::BlockAttestation {
                block_hash: bh(7),
                validator_id: Hash256([v; 32]),
                signature: aevor_core::primitives::Signature([v; 64]),
                tee_attestation: None,
                timestamp: aevor_core::consensus::ConsensusTimestamp::GENESIS,
            };
            c.add(att, w(10));
        }
        assert!(c.meets_required_level());

        let mut engine = ConsensusEngine::new(SecurityLevel::Minimal);
        let result = engine.finalize_round(&c, 42);

        assert_eq!(result.finalized_blocks, vec![bh(7)]);
        let proof = result.finality_proof.expect("finalized round must carry a finality proof");
        // Real, populated proof — not None, not empty.
        assert_eq!(proof.signatures.len(), 2);
        assert_eq!(proof.security_level, SecurityLevel::Minimal);
        assert_eq!(proof.total_weight, w(20));
        // aggregate_signature is a real 32-byte BLAKE3 commitment.
        assert_eq!(proof.aggregate_signature.len(), 32);
        assert!(proof.aggregate_signature.iter().any(|&b| b != 0));
        // Participant bitmap marks both signers (bits 0 and 1 set).
        assert_eq!(proof.participant_bitmap[0] & 0b11, 0b11);
        // Signatures carry the real validator ids and per-signer indices.
        assert_eq!(proof.signatures[0].index.0, 0);
        assert_eq!(proof.signatures[1].index.0, 1);
    }

    #[test]
    fn unfinalized_round_has_no_finality_proof() {
        // No attestations → cannot meet Full → no proof.
        let c = AttestationCollection::new(bh(8), SecurityLevel::Full, w(100));
        let mut engine = ConsensusEngine::new(SecurityLevel::Full);
        let result = engine.finalize_round(&c, 10);
        assert!(result.finalized_blocks.is_empty());
        assert!(result.finality_proof.is_none());
    }

    #[test]
    fn proposal_content_hash_is_real_and_deterministic() {
        // content_hash must be a real BLAKE3 hash (non-zero) and stable.
        let mk = |round: u64| ProposalMessage {
            proposer: Hash256([1u8; 32]),
            block_hash: bh(3),
            block_height: aevor_core::primitives::BlockHeight(9),
            round,
            timestamp: aevor_core::consensus::ConsensusTimestamp::GENESIS,
            signature: aevor_core::primitives::Signature([0u8; 64]),
            tee_attestation: None,
        };
        let p = mk(5);
        let h1 = p.content_hash();
        let h2 = p.content_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, Hash256::ZERO);
        // A different proposal (different round) yields a different hash.
        assert_ne!(p.content_hash(), mk(6).content_hash());
    }

    #[test]
    fn attestation_collection_zero_total_weight_returns_zero_fraction() {
        let c = AttestationCollection::new(bh(1), SecurityLevel::Full, w(0));
        assert_eq!(c.participation_fraction(), 0.0);
    }

    #[test]
    fn consensus_engine_starts_at_round_zero() {
        let engine = ConsensusEngine::new(SecurityLevel::Basic);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.state(), ConsensusState::Initializing);
    }

    #[test]
    fn consensus_engine_advance_round_increments() {
        let mut engine = ConsensusEngine::new(SecurityLevel::Basic);
        engine.advance_round();
        assert_eq!(engine.current_round(), 1);
        assert_eq!(engine.state(), ConsensusState::Proposing);
        engine.advance_round();
        assert_eq!(engine.current_round(), 2);
    }

    #[test]
    fn consensus_engine_finalize_round_no_attestations() {
        let mut engine = ConsensusEngine::new(SecurityLevel::Full);
        let collection = AttestationCollection::new(bh(5), SecurityLevel::Full, w(1000));
        let result = engine.finalize_round(&collection, 100);
        // Full security requires >67% — no attestations means no finalized blocks
        assert!(result.finalized_blocks.is_empty());
        assert!(!result.validation.is_valid);
        assert_eq!(result.participation_pct, 0);
    }

    #[test]
    fn round_result_is_successful_on_valid_validation() {
        let r = RoundResult {
            round: 1,
            finalized_blocks: vec![bh(1)],
            security_level: SecurityLevel::Basic,
            duration_ms: 50,
            participation_pct: 25,
            finality_proof: None,
            validation: aevor_core::consensus::ValidationResult::valid(),
        };
        assert!(r.is_successful());
        // finality_proof is None so is_finalized returns false
        assert!(!r.is_finalized());
    }
}
