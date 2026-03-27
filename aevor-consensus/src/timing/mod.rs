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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{BlockHeight, EpochNumber};
    use aevor_core::consensus::ConsensusTimestamp;

    #[test]
    fn consensus_clock_starts_at_zero() {
        let clock = ConsensusClock::new();
        let ts = clock.now();
        assert_eq!(ts, ConsensusTimestamp::new(0, 0, 0));
    }

    #[test]
    fn consensus_clock_advance_round_resets_sequence() {
        let mut clock = ConsensusClock::default();
        clock.advance_sequence();
        clock.advance_sequence();
        assert_eq!(clock.now(), ConsensusTimestamp::new(0, 2, 0));
        clock.advance_round();
        // After round advance, sequence resets to 0
        assert_eq!(clock.now(), ConsensusTimestamp::new(1, 0, 0));
    }

    #[test]
    fn consensus_clock_advance_sequence_increments() {
        let mut clock = ConsensusClock::new();
        clock.advance_sequence();
        clock.advance_sequence();
        clock.advance_sequence();
        assert_eq!(clock.now(), ConsensusTimestamp::new(0, 3, 0));
    }

    #[test]
    fn consensus_clock_multiple_rounds() {
        let mut clock = ConsensusClock::new();
        clock.advance_round();
        clock.advance_round();
        clock.advance_sequence();
        assert_eq!(clock.now(), ConsensusTimestamp::new(2, 1, 0));
    }

    #[test]
    fn epoch_reference_stores_fields() {
        let er = EpochReference {
            epoch: EpochNumber(5),
            start_height: BlockHeight(1000),
            start_round: 200,
        };
        assert_eq!(er.epoch.0, 5);
        assert_eq!(er.start_height.0, 1000);
        assert_eq!(er.start_round, 200);
    }

    #[test]
    fn round_duration_complete_when_ended_at_set() {
        let ts = ConsensusTimestamp::new(1, 0, 0);
        let mut rd = RoundDuration { round: 1, started_at: ts, ended_at: None, duration_ms: 0 };
        assert!(!rd.is_complete());
        rd.ended_at = Some(ConsensusTimestamp::new(2, 0, 0));
        rd.duration_ms = 500;
        assert!(rd.is_complete());
    }
}
