//! Security-layer slashing coordination.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Amount, ValidatorId};
pub use aevor_consensus::slashing::SlashingEvidence;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingDecision { pub validator: ValidatorId, pub slash_amount: Amount, pub jail_epochs: u64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub validator: ValidatorId,
    pub epoch: aevor_core::primitives::EpochNumber,
    pub amount_slashed: Amount,
    pub reason: String,
}

pub struct PenaltyCalculator { double_sign_pct: u32 }
impl PenaltyCalculator {
    pub fn new(double_sign_pct: u32) -> Self { Self { double_sign_pct } }
    pub fn calculate(&self, stake: Amount) -> Amount {
        Amount::from_nano(stake.as_nano() * u128::from(self.double_sign_pct) / 10_000)
    }
}

pub struct SlashingCoordinator { records: Vec<SlashingRecord> }
impl SlashingCoordinator {
    pub fn new() -> Self { Self { records: Vec::new() } }
    pub fn record(&mut self, r: SlashingRecord) { self.records.push(r); }
    pub fn slash_count_for(&self, v: &ValidatorId) -> usize {
        self.records.iter().filter(|r| &r.validator == v).count()
    }
}
impl Default for SlashingCoordinator { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Amount, EpochNumber, Hash256};

    #[test]
    fn penalty_calculator_percentage_of_stake() {
        let calc = PenaltyCalculator::new(500); // 5%
        let stake = Amount::from_nano(1_000_000_000_000);
        let penalty = calc.calculate(stake);
        assert_eq!(penalty.as_nano(), 50_000_000_000); // 5% of 1000 AEVOR
    }

    #[test]
    fn penalty_zero_for_zero_stake() {
        let calc = PenaltyCalculator::new(500);
        assert_eq!(calc.calculate(Amount::ZERO).as_nano(), 0);
    }

    #[test]
    fn coordinator_records_and_counts() {
        let mut coord = SlashingCoordinator::new();
        let v = Hash256([1u8; 32]);
        coord.record(SlashingRecord {
            validator: v,
            epoch: EpochNumber(1),
            amount_slashed: Amount::from_nano(100),
            reason: "double-sign".into(),
        });
        coord.record(SlashingRecord {
            validator: v,
            epoch: EpochNumber(2),
            amount_slashed: Amount::from_nano(50),
            reason: "liveness".into(),
        });
        assert_eq!(coord.slash_count_for(&v), 2);
    }

    #[test]
    fn coordinator_zero_for_unknown_validator() {
        let coord = SlashingCoordinator::new();
        let v = Hash256([9u8; 32]);
        assert_eq!(coord.slash_count_for(&v), 0);
    }

    #[test]
    fn slashing_decision_fields() {
        let v = Hash256([2u8; 32]);
        let d = SlashingDecision {
            validator: v,
            slash_amount: Amount::from_nano(200),
            jail_epochs: 10,
        };
        assert_eq!(d.jail_epochs, 10);
        assert_eq!(d.slash_amount.as_nano(), 200);
    }
}
