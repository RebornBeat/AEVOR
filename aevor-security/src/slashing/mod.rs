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
        Amount::from_nano(stake.as_nano() * self.double_sign_pct as u128 / 10_000)
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

cat > /home/claude/aevor/aevor-security/src/metrics/mod.rs << 'RUST'
//! Security metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SecurityMetrics {
    pub threats_detected: u64, pub threats_mitigated: u64, pub slashing_events: u64,
}
