//! Cross-round pipelining: keep the producing pipeline full by not blocking a
//! round's application on the previous round's finality certificate.
//!
//! **Applies to both engine modes** — monolithic and sharded alike. It is a
//! round-*lifecycle* optimization, independent of how state is partitioned, so it
//! lives here in the round layer rather than inside sharding.
//!
//! Within a round the bottleneck is production (~11k tx/s per core); finality is
//! an O(1) BLS aggregation. A round's authenticated state is known at **apply**
//! (the root is computed before the round's finality certificate is aggregated and
//! gossiped), so the next round can produce and apply immediately while earlier
//! rounds' finality certificates are still settling. This hides finality latency
//! under production: applied state advances at production rate, and finality trails
//! by the pipeline depth. A round is *committed* (irreversible) once its
//! certificate lands; a bounded number of applied-but-not-yet-committed rounds sit
//! in the pipeline.

use crate::engine::LaneRoundOutcome;

/// A finality certificate covering one round. The aggregate BLS signature is
/// produced by the consensus layer; this records which round it commits and the
/// state root it attests to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityCertificate {
    /// The block height this certificate commits.
    pub height: u64,
    /// The authenticated state root committed at that height.
    pub state_root: [u8; 32],
}

#[derive(Clone, Debug)]
struct PendingRound {
    height: u64,
    state_root: [u8; 32],
}

/// A pipeline of applied-but-not-yet-finalized rounds. Application advances at
/// production rate; finality certificates trail by up to `depth` rounds, so the
/// producer never blocks on finality gossip.
pub struct RoundPipeline {
    depth: usize,
    pending: std::collections::VecDeque<PendingRound>,
    finalized: u64,
}

impl RoundPipeline {
    /// A pipeline that keeps up to `depth` rounds in flight before the oldest must
    /// finalize (depth is clamped to at least 1).
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self { depth: depth.max(1), pending: std::collections::VecDeque::new(), finalized: 0 }
    }

    /// Record an applied round. The state has already advanced (the caller applied
    /// the round); this enqueues it for finality. If the pipeline is now deeper than
    /// `depth`, the oldest round finalizes and its certificate is returned — that is
    /// the round whose finality overlapped the newer rounds' production.
    pub fn record_applied(&mut self, height: u64, outcome: &LaneRoundOutcome) -> Option<FinalityCertificate> {
        self.pending.push_back(PendingRound { height, state_root: outcome.state_root.0 .0 });
        if self.pending.len() > self.depth {
            return self.commit_oldest();
        }
        None
    }

    /// Finalize the oldest pending round, returning its certificate.
    fn commit_oldest(&mut self) -> Option<FinalityCertificate> {
        let round = self.pending.pop_front()?;
        self.finalized = self.finalized.max(round.height);
        Some(FinalityCertificate { height: round.height, state_root: round.state_root })
    }

    /// Finalize all remaining pending rounds in order (e.g. at shutdown or a
    /// checkpoint), draining the pipeline.
    pub fn drain(&mut self) -> Vec<FinalityCertificate> {
        let mut out = Vec::with_capacity(self.pending.len());
        while let Some(cert) = self.commit_oldest() {
            out.push(cert);
        }
        out
    }

    /// Rounds applied but not yet committed (in flight).
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The highest height whose finality certificate has been produced.
    #[must_use]
    pub fn last_finalized_height(&self) -> u64 {
        self.finalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::storage::MerkleRoot;

    fn outcome(root: u8) -> LaneRoundOutcome {
        LaneRoundOutcome {
            ordered_lanes: vec![],
            state_root: MerkleRoot(Hash256([root; 32])),
            lanes_applied: 1,
            objects_applied: 1,
        }
    }

    #[test]
    fn finality_trails_application_by_depth() {
        let mut p = RoundPipeline::new(2);
        // Apply rounds 1,2 — within depth, nothing finalizes yet.
        assert!(p.record_applied(1, &outcome(1)).is_none());
        assert!(p.record_applied(2, &outcome(2)).is_none());
        assert_eq!(p.pending_len(), 2);
        assert_eq!(p.last_finalized_height(), 0, "finality trails while pipeline fills");
        // Applying round 3 pushes the pipeline over depth → round 1 finalizes.
        let cert = p.record_applied(3, &outcome(3)).expect("oldest commits");
        assert_eq!(cert.height, 1);
        assert_eq!(cert.state_root, [1u8; 32]);
        assert_eq!(p.last_finalized_height(), 1);
        assert_eq!(p.pending_len(), 2, "still two in flight");
    }

    #[test]
    fn drain_finalizes_remaining_in_order() {
        let mut p = RoundPipeline::new(3);
        for h in 1..=5u64 {
            p.record_applied(h, &outcome(u8::try_from(h).unwrap()));
        }
        // depth 3: rounds 1,2 already finalized (5 applied - depth 3); 3,4,5 pending.
        assert_eq!(p.last_finalized_height(), 2);
        let remaining = p.drain();
        let heights: Vec<u64> = remaining.iter().map(|c| c.height).collect();
        assert_eq!(heights, vec![3, 4, 5], "drained in order");
        assert_eq!(p.last_finalized_height(), 5);
        assert_eq!(p.pending_len(), 0);
    }

    #[test]
    fn depth_one_finalizes_each_round_immediately_behind() {
        let mut p = RoundPipeline::new(1);
        assert!(p.record_applied(1, &outcome(1)).is_none());
        // Second apply commits the first (only one may be in flight).
        let cert = p.record_applied(2, &outcome(2)).unwrap();
        assert_eq!(cert.height, 1);
    }
}
