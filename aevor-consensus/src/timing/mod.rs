//! Consensus timing: blockchain-derived timestamps, logical sequences.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{ConsensusTimestamp, LogicalSequence, BlockReference};
use aevor_core::primitives::{BlockHeight, EpochNumber};

/// A reference to an epoch (for temporal anchoring without wall-clock time).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochReference {
    pub epoch: EpochNumber,
    pub start_height: BlockHeight,
    pub start_round: u64,
}

/// Consensus-derived clock (no external time sources).
pub struct ConsensusClock {
    current_round: u64,
    current_sequence: u64,
    current_height: u64,
}

impl ConsensusClock {
    pub fn new() -> Self { Self { current_round: 0, current_sequence: 0, current_height: 0 } }

    pub fn now(&self) -> ConsensusTimestamp {
        ConsensusTimestamp::new(self.current_round, self.current_sequence, self.current_height)
    }

    pub fn advance_round(&mut self) {
        self.current_round += 1;
        self.current_sequence = 0;
    }

    pub fn advance_sequence(&mut self) {
        self.current_sequence += 1;
    }
}

impl Default for ConsensusClock {
    fn default() -> Self { Self::new() }
}

/// Duration of a consensus round.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RoundDuration {
    pub round: u64,
    pub started_at: ConsensusTimestamp,
    pub ended_at: Option<ConsensusTimestamp>,
    pub duration_ms: u64,
}

impl RoundDuration {
    pub fn is_complete(&self) -> bool { self.ended_at.is_some() }
}
