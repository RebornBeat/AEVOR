//! Validator slashing for Byzantine behavior.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Amount, ValidatorId};

/// Evidence for a slashing event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub offender: ValidatorId,
    pub evidence_type: SlashingEvidenceType,
    pub evidence_a: Vec<u8>,
    pub evidence_b: Option<Vec<u8>>,
    pub timestamp: aevor_core::consensus::ConsensusTimestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingEvidenceType {
    DoubleSign,
    InvalidAttestation,
    Equivocation,
    Liveness,
}

/// The computed penalty for a slashing event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingPenalty {
    pub offender: ValidatorId,
    pub slash_amount: Amount,
    pub jail_epochs: u64,
    pub tombstone: bool,
}

/// Cryptographic proof that a slashing penalty is justified.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingProof {
    pub evidence: SlashingEvidence,
    pub penalty: SlashingPenalty,
    pub proof_hash: aevor_core::primitives::Hash256,
}

/// Evidence of double-signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator: ValidatorId,
    pub block_a: aevor_core::primitives::BlockHash,
    pub block_b: aevor_core::primitives::BlockHash,
    pub height: aevor_core::primitives::BlockHeight,
    pub sig_a: aevor_core::primitives::Signature,
    pub sig_b: aevor_core::primitives::Signature,
}

/// Evidence of equivocation (conflicting votes in same round).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub validator: ValidatorId,
    pub round: u64,
    pub vote_a: Vec<u8>,
    pub vote_b: Vec<u8>,
}

/// Liveness violation (extended downtime).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LivenessViolation {
    pub validator: ValidatorId,
    pub missed_rounds: u64,
    pub from_epoch: aevor_core::primitives::EpochNumber,
    pub to_epoch: aevor_core::primitives::EpochNumber,
}

/// Processes slashing evidence and computes penalties.
pub struct SlashingMechanism {
    double_sign_pct: u32,
    liveness_pct_per_epoch: u32,
}

impl SlashingMechanism {
    /// Create a slashing mechanism.
    ///
    /// - `double_sign_pct`: percentage of stake slashed for double-signing (basis points, e.g. 500 = 5%)
    /// - `liveness_pct_per_epoch`: percentage of stake slashed per missed epoch (basis points)
    pub fn new(double_sign_pct: u32, liveness_pct_per_epoch: u32) -> Self {
        Self { double_sign_pct, liveness_pct_per_epoch }
    }

    /// The double-sign penalty in basis points (100 = 1%).
    pub fn double_sign_penalty_bps(&self) -> u32 { self.double_sign_pct }

    /// The per-epoch liveness penalty in basis points.
    pub fn liveness_penalty_bps(&self) -> u32 { self.liveness_pct_per_epoch }

    /// Compute the slash amount for a double-sign infraction.
    pub fn double_sign_slash(&self, stake: aevor_core::primitives::Amount) -> aevor_core::primitives::Amount {
        aevor_core::primitives::Amount::from_nano(
            stake.as_nano() * self.double_sign_pct as u128 / 10_000
        )
    }

    /// Compute the slash amount for `epochs_missed` consecutive missed epochs.
    pub fn liveness_slash(&self, stake: aevor_core::primitives::Amount, epochs_missed: u64) -> aevor_core::primitives::Amount {
        aevor_core::primitives::Amount::from_nano(
            stake.as_nano() * self.liveness_pct_per_epoch as u128 * epochs_missed as u128 / 10_000
        )
    }
}
