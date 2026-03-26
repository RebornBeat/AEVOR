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
