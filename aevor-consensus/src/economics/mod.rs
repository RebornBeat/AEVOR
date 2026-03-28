//! Consensus economics: reward calculation and distribution logic.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Amount, EpochNumber, ValidatorId};

/// Reward for a validator in one epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusReward {
    pub validator: ValidatorId,
    pub epoch: EpochNumber,
    pub consensus_reward: Amount,
    pub tee_service_reward: Amount,
    pub performance_multiplier_pct: u32,
}

impl ConsensusReward {
    pub fn total(&self) -> Amount {
        self.consensus_reward.checked_add(self.tee_service_reward).unwrap_or(Amount::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Amount, EpochNumber, Hash256};

    fn reward(consensus: u128, tee: u128) -> ConsensusReward {
        ConsensusReward {
            validator: Hash256::ZERO,
            epoch: EpochNumber(1),
            consensus_reward: Amount::from_nano(consensus),
            tee_service_reward: Amount::from_nano(tee),
            performance_multiplier_pct: 100,
        }
    }

    #[test]
    fn consensus_reward_total_sums_components() {
        let r = reward(1_000_000_000, 200_000_000);
        assert_eq!(r.total().as_nano(), 1_200_000_000u128);
    }

    #[test]
    fn tee_service_reward_is_nonzero() {
        // Whitepaper §7.9: validators are rewarded for TEE service provision
        let r = reward(1_000, 500);
        assert!(r.tee_service_reward.as_nano() > 0);
    }

    #[test]
    fn total_reward_when_no_tee_service_equals_consensus_only() {
        let r = reward(5_000, 0);
        assert_eq!(r.total().as_nano(), 5_000u128);
    }

    #[test]
    fn performance_multiplier_stored() {
        // Whitepaper §7.9: performance-based rewards provide additional compensation
        let r = ConsensusReward {
            validator: Hash256::ZERO,
            epoch: EpochNumber(1),
            consensus_reward: Amount::from_nano(1_000),
            tee_service_reward: Amount::from_nano(100),
            performance_multiplier_pct: 120, // 20% bonus
        };
        assert_eq!(r.performance_multiplier_pct, 120);
        // Total excludes the multiplier (multiplier applied externally by reward dist)
        assert_eq!(r.total().as_nano(), 1_100u128);
    }

    #[test]
    fn total_reward_zero_when_both_zero() {
        let r = reward(0, 0);
        assert_eq!(r.total().as_nano(), 0);
    }
}
