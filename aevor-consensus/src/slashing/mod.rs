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
            stake.as_nano() * u128::from(self.double_sign_pct) / 10_000
        )
    }

    /// Compute the slash amount for `epochs_missed` consecutive missed epochs.
    pub fn liveness_slash(&self, stake: aevor_core::primitives::Amount, epochs_missed: u64) -> aevor_core::primitives::Amount {
        aevor_core::primitives::Amount::from_nano(
            stake.as_nano() * u128::from(self.liveness_pct_per_epoch) * u128::from(epochs_missed) / 10_000
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Amount;

    #[test]
    fn double_sign_slash_is_percentage_of_stake() {
        let m = SlashingMechanism::new(500, 10); // 5% double-sign, 0.1% liveness
        let stake = Amount::from_nano(1_000_000_000_000); // 1000 AEVOR
        let slash = m.double_sign_slash(stake);
        // 5% of 1000 = 50 AEVOR = 50_000_000_000 nAVR
        assert_eq!(slash.as_nano(), 50_000_000_000);
    }

    #[test]
    fn liveness_slash_scales_with_epochs_missed() {
        let m = SlashingMechanism::new(500, 100); // 1% per epoch
        let stake = Amount::from_nano(1_000_000_000_000);
        let slash_1 = m.liveness_slash(stake, 1);
        let slash_3 = m.liveness_slash(stake, 3);
        assert_eq!(slash_3.as_nano(), slash_1.as_nano() * 3);
    }

    #[test]
    fn penalty_accessors_match_constructor() {
        let m = SlashingMechanism::new(250, 50);
        assert_eq!(m.double_sign_penalty_bps(), 250);
        assert_eq!(m.liveness_penalty_bps(), 50);
    }

    #[test]
    fn zero_stake_slash_is_zero() {
        let m = SlashingMechanism::new(500, 100);
        assert_eq!(m.double_sign_slash(Amount::ZERO).as_nano(), 0);
        assert_eq!(m.liveness_slash(Amount::ZERO, 5).as_nano(), 0);
    }

    #[test]
    fn attestation_collector_reaches_required_count() {
        use aevor_core::consensus::AttestationEvidence;
        use aevor_core::primitives::Hash256;
        let target = Hash256([1u8; 32]);
        let mut collector = super::super::attestation::AttestationCollector::new(target, 2);
        assert!(!collector.is_complete());
        let ev = AttestationEvidence {
            platform: aevor_core::consensus::TeeAttestationPlatform::IntelSgx,
            raw_report: vec![1],
            code_measurement: Hash256([1u8; 32]),
            nonce: [0u8; 32],
            is_production: false,
            svn: 0,
        };
        collector.add(ev.clone());
        assert!(!collector.is_complete());
        collector.add(ev);
        assert!(collector.is_complete());
        assert_eq!(collector.count(), 2);
    }
}
