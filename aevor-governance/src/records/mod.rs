//! Governance history and audit trail.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::consensus::ConsensusTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionRecord { pub proposal_id: Hash256, pub decision: String, pub timestamp: ConsensusTimestamp }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteRecord { pub proposal_id: Hash256, pub vote_count: usize, pub tally: crate::voting::VoteTally }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoricalGovernance { pub decisions: Vec<DecisionRecord>, pub total_proposals: usize }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceAuditTrail { pub entries: Vec<DecisionRecord> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceRecord { pub id: Hash256, pub record_type: String, pub data: Vec<u8> }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::consensus::ConsensusTimestamp;

    fn pid(n: u8) -> Hash256 { Hash256([n; 32]) }

    #[test]
    fn decision_record_stores_fields() {
        let r = DecisionRecord { proposal_id: pid(1), decision: "Passed".into(), timestamp: ConsensusTimestamp::new(10, 0, 100) };
        assert_eq!(r.decision, "Passed");
    }

    #[test]
    fn historical_governance_tracks_total() {
        let h = HistoricalGovernance { decisions: vec![], total_proposals: 42 };
        assert_eq!(h.total_proposals, 42);
    }

    #[test]
    fn governance_record_stores_type_and_data() {
        let r = GovernanceRecord { id: pid(5), record_type: "ParameterChange".into(), data: vec![1, 2, 3] };
        assert_eq!(r.record_type, "ParameterChange");
        assert!(!r.data.is_empty());
    }
}
