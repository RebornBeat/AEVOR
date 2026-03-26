//! Validator-coordinated rate limiting.
use serde::{Deserialize, Serialize};
use aevor_core::primitives::ValidatorId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRateRecord { pub validator: ValidatorId, pub address: String, pub timestamp_round: u64 }
pub struct ValidatorCoordinator { quorum: usize }
impl ValidatorCoordinator {
    pub fn new(quorum: usize) -> Self { Self { quorum } }
    pub fn has_consensus(&self, votes: usize) -> bool { votes >= self.quorum }
}
