//! Governance proposals.
//!
//! Governance proposals are infrastructure capability primitives — the proposal
//! system provides lifecycle management for any governance decision, but the
//! content of proposals (what parameters change, what upgrades are applied) is
//! application-layer policy decided by community vote.

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
    /// Block height at which voting ends (used for light client verification).
    pub voting_ends_at_height: BlockHeight,
}
impl Proposal {
    pub fn is_active(&self) -> bool { matches!(self.status, ProposalStatus::Active) }
    pub fn is_final(&self) -> bool { matches!(self.status, ProposalStatus::Passed | ProposalStatus::Failed | ProposalStatus::Vetoed | ProposalStatus::Expired) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalLifecycle { pub proposal: Proposal, pub history: Vec<(ConsensusTimestamp, ProposalStatus)> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalExecution { pub proposal_id: ProposalId, pub executed_at: ConsensusTimestamp, pub success: bool }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, BlockHeight, Hash256};
    use aevor_core::consensus::ConsensusTimestamp;

    fn pid(n: u8) -> ProposalId { Hash256([n; 32]) }
    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn ts(r: u64) -> ConsensusTimestamp { ConsensusTimestamp::new(r, 0, r) }

    fn proposal(ptype: ProposalType, status: ProposalStatus) -> Proposal {
        Proposal {
            id: pid(1),
            proposer: addr(1),
            proposal_type: ptype,
            status,
            content: ProposalContent {
                title: "Test Proposal".into(),
                description: "description".into(),
                payload: vec![],
            },
            submitted_at: ts(100),
            voting_ends_at: ts(200),
            voting_ends_at_height: BlockHeight(200),
        }
    }

    // ── Proposal lifecycle state machine ──────────────────────────────────
    // Whitepaper: "democratic governance primitives for infrastructure parameter management"

    #[test]
    fn active_proposal_is_active_not_final() {
        let p = proposal(ProposalType::ParameterChange, ProposalStatus::Active);
        assert!(p.is_active());
        assert!(!p.is_final());
    }

    #[test]
    fn pending_proposal_is_not_active_not_final() {
        let p = proposal(ProposalType::TextProposal, ProposalStatus::Pending);
        assert!(!p.is_active());
        assert!(!p.is_final());
    }

    #[test]
    fn passed_proposal_is_final_not_active() {
        let p = proposal(ProposalType::ProtocolUpgrade, ProposalStatus::Passed);
        assert!(!p.is_active());
        assert!(p.is_final());
    }

    #[test]
    fn all_terminal_statuses_are_final() {
        for status in [ProposalStatus::Passed, ProposalStatus::Failed,
                       ProposalStatus::Vetoed, ProposalStatus::Expired] {
            let p = proposal(ProposalType::TextProposal, status);
            assert!(p.is_final(), "status {:?} should be final", status);
        }
    }

    #[test]
    fn executed_status_is_not_final_via_is_final() {
        // Executed is after Passed — it's a separate terminal state
        let p = proposal(ProposalType::TreasurySpend, ProposalStatus::Executed);
        assert!(!p.is_final()); // Executed ≠ Passed|Failed|Vetoed|Expired
        assert!(!p.is_active());
    }

    // ── ProposalType coverage ─────────────────────────────────────────────
    // All governance domains are reachable through this single proposal system

    #[test]
    fn all_proposal_types_constructable() {
        for ptype in [
            ProposalType::ParameterChange,
            ProposalType::ProtocolUpgrade,
            ProposalType::TreasurySpend,
            ProposalType::ValidatorSetChange,
            ProposalType::TextProposal,
        ] {
            let p = proposal(ptype, ProposalStatus::Pending);
            assert_eq!(p.proposal_type, ptype);
        }
    }

    // ── ProposalExecution ─────────────────────────────────────────────────

    #[test]
    fn proposal_execution_records_success() {
        let exec = ProposalExecution {
            proposal_id: pid(7),
            executed_at: ts(300),
            success: true,
        };
        assert!(exec.success);
        assert_eq!(exec.proposal_id, pid(7));
    }

    #[test]
    fn proposal_lifecycle_history_is_ordered() {
        let p = proposal(ProposalType::ParameterChange, ProposalStatus::Passed);
        let lifecycle = ProposalLifecycle {
            proposal: p,
            history: vec![
                (ts(100), ProposalStatus::Pending),
                (ts(101), ProposalStatus::Active),
                (ts(200), ProposalStatus::Passed),
            ],
        };
        assert_eq!(lifecycle.history.len(), 3);
        // Timestamps are monotonically increasing
        assert!(lifecycle.history[0].0.precedes(&lifecycle.history[1].0));
        assert!(lifecycle.history[1].0.precedes(&lifecycle.history[2].0));
    }
}
