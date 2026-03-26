//! Governance proposals.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Hash256, Address, BlockHeight};
use aevor_core::consensus::ConsensusTimestamp;

pub type ProposalId = Hash256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalType { ParameterChange, ProtocolUpgrade, TreasurySpend, ValidatorSetChange, TextProposal }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus { Pending, Active, Passed, Failed, Vetoed, Expired, Executed }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalContent { pub title: String, pub description: String, pub payload: Vec<u8> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: ProposalId, pub proposer: Address, pub proposal_type: ProposalType,
    pub status: ProposalStatus, pub content: ProposalContent,
    pub submitted_at: ConsensusTimestamp, pub voting_ends_at: ConsensusTimestamp,
}
impl Proposal {
    pub fn is_active(&self) -> bool { matches!(self.status, ProposalStatus::Active) }
    pub fn is_final(&self) -> bool { matches!(self.status, ProposalStatus::Passed | ProposalStatus::Failed | ProposalStatus::Vetoed | ProposalStatus::Expired) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalLifecycle { pub proposal: Proposal, pub history: Vec<(ConsensusTimestamp, ProposalStatus)> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalExecution { pub proposal_id: ProposalId, pub executed_at: ConsensusTimestamp, pub success: bool }
