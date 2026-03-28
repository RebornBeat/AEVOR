//! Validator slashing for Byzantine behavior.
//!
//! Slashing penalties are graduated — severity matches violation impact:
//! - `Minor`: technical failures without malicious intent → reduced rewards
//! - `Moderate`: poor operational practices, repeated failures → stake reduction
//! - `Serious`: malicious behavior or gross negligence → severe slash + jail
//!
//! All penalties are computed from mathematical evidence (TEE attestation),
//! never from subjective evaluation or social consensus.

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

/// Graduated violation severity — matches economic consequence to actual harm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Technical failures without malicious intent (hardware failures, software bugs).
    /// Consequence: temporary reward reduction; no stake slash.
    Minor,
    /// Poor operational practices or repeated failures without direct security threat.
    /// Consequence: moderate stake slash; extended monitoring.
    Moderate,
    /// Malicious behavior or gross negligence threatening network security.
    /// Consequence: severe stake slash; jail; potential tombstone.
    Serious,
}

impl ViolationSeverity {
    /// Penalty multiplier in basis points for stake slashing (0 = no stake slash).
    pub fn stake_slash_bps(&self) -> u32 {
        match self {
            Self::Minor => 0,        // Reward reduction only — no stake slash
            Self::Moderate => 100,   // 1% stake slash
            Self::Serious => 500,    // 5% stake slash
        }
    }

    /// Jail duration in epochs (0 = no jail).
    pub fn jail_epochs(&self) -> u64 {
        match self {
            Self::Minor => 0,
            Self::Moderate => 14,    // ~2 weeks
            Self::Serious => 100,    // ~100 days
        }
    }

    /// Whether this severity results in a tombstone (permanent exclusion).
    pub fn tombstones(&self) -> bool {
        matches!(self, Self::Serious)
    }
}

/// Maps evidence types to their canonical violation severity.
pub struct SeverityClassifier;

impl SeverityClassifier {
    /// Classify a slashing evidence type to its violation severity.
    pub fn classify(evidence_type: SlashingEvidenceType) -> ViolationSeverity {
        match evidence_type {
            SlashingEvidenceType::Liveness => ViolationSeverity::Minor,
            SlashingEvidenceType::InvalidAttestation => ViolationSeverity::Moderate,
            SlashingEvidenceType::Equivocation => ViolationSeverity::Serious,
            SlashingEvidenceType::DoubleSign => ViolationSeverity::Serious,
        }
    }
}

/// Graduated slashing policy — computes penalty from evidence type and validator stake.
pub struct GraduatedSlashingPolicy {
    pub mechanism: SlashingMechanism,
}

impl GraduatedSlashingPolicy {
    /// Create a graduated slashing policy using the given underlying mechanism.
    pub fn new(mechanism: SlashingMechanism) -> Self { Self { mechanism } }

    /// Compute the graduated penalty for a given evidence type and stake.
    pub fn compute(&self, evidence_type: SlashingEvidenceType, stake: Amount) -> SlashingPenalty {
        let severity = SeverityClassifier::classify(evidence_type);
        let slash_amount = if severity.stake_slash_bps() == 0 {
            Amount::ZERO
        } else {
            Amount::from_nano(
                stake.as_nano() * u128::from(severity.stake_slash_bps()) / 10_000
            )
        };
        // Use a zero validator_id placeholder — real usage gets ID from evidence
        SlashingPenalty {
            offender: aevor_core::primitives::Hash256::ZERO,
            slash_amount,
            jail_epochs: severity.jail_epochs(),
            tombstone: severity.tombstones(),
        }
    }
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

    fn stake(nano: u128) -> Amount { Amount::from_nano(nano) }

    // ── SlashingMechanism ──────────────────────────────────────────────────

    #[test]
    fn double_sign_slash_is_percentage_of_stake() {
        let m = SlashingMechanism::new(500, 10); // 5% double-sign, 0.1% liveness
        let slash = m.double_sign_slash(stake(1_000_000_000_000)); // 1000 AEVOR
        assert_eq!(slash.as_nano(), 50_000_000_000); // 5% = 50 AEVOR
    }

    #[test]
    fn liveness_slash_scales_with_epochs_missed() {
        let m = SlashingMechanism::new(500, 100); // 1% per epoch
        let slash_1 = m.liveness_slash(stake(1_000_000_000_000), 1);
        let slash_3 = m.liveness_slash(stake(1_000_000_000_000), 3);
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

    // ── ViolationSeverity ─────────────────────────────────────────────────
    // Whitepaper §9.1: graduated accountability matches penalty severity to violation significance

    #[test]
    fn violation_severity_ordering_minor_lt_moderate_lt_serious() {
        assert!(ViolationSeverity::Minor < ViolationSeverity::Moderate);
        assert!(ViolationSeverity::Moderate < ViolationSeverity::Serious);
    }

    #[test]
    fn minor_violation_has_no_stake_slash() {
        assert_eq!(ViolationSeverity::Minor.stake_slash_bps(), 0);
        assert_eq!(ViolationSeverity::Minor.jail_epochs(), 0);
        assert!(!ViolationSeverity::Minor.tombstones());
    }

    #[test]
    fn serious_violation_tombstones_and_jails_longest() {
        assert!(ViolationSeverity::Serious.tombstones());
        assert!(ViolationSeverity::Serious.jail_epochs() > ViolationSeverity::Moderate.jail_epochs());
        assert!(ViolationSeverity::Serious.stake_slash_bps() > ViolationSeverity::Moderate.stake_slash_bps());
    }

    // ── SeverityClassifier ────────────────────────────────────────────────

    #[test]
    fn liveness_classified_as_minor() {
        assert_eq!(SeverityClassifier::classify(SlashingEvidenceType::Liveness), ViolationSeverity::Minor);
    }

    #[test]
    fn double_sign_classified_as_serious() {
        assert_eq!(SeverityClassifier::classify(SlashingEvidenceType::DoubleSign), ViolationSeverity::Serious);
        assert_eq!(SeverityClassifier::classify(SlashingEvidenceType::Equivocation), ViolationSeverity::Serious);
    }

    #[test]
    fn invalid_attestation_classified_as_moderate() {
        assert_eq!(SeverityClassifier::classify(SlashingEvidenceType::InvalidAttestation), ViolationSeverity::Moderate);
    }

    // ── GraduatedSlashingPolicy ───────────────────────────────────────────

    #[test]
    fn graduated_policy_liveness_produces_no_slash() {
        let policy = GraduatedSlashingPolicy::new(SlashingMechanism::new(500, 100));
        let penalty = policy.compute(SlashingEvidenceType::Liveness, stake(1_000_000_000_000));
        assert_eq!(penalty.slash_amount.as_nano(), 0);
        assert_eq!(penalty.jail_epochs, 0);
        assert!(!penalty.tombstone);
    }

    #[test]
    fn graduated_policy_double_sign_produces_severe_penalty() {
        let policy = GraduatedSlashingPolicy::new(SlashingMechanism::new(500, 100));
        let penalty = policy.compute(SlashingEvidenceType::DoubleSign, stake(1_000_000_000_000));
        assert!(penalty.slash_amount.as_nano() > 0);
        assert!(penalty.jail_epochs > 0);
        assert!(penalty.tombstone);
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
