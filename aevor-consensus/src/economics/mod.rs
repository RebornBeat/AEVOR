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
