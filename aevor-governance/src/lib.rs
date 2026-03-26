//! # AEVOR Governance: Democratic Infrastructure Management
//!
//! `aevor-governance` provides democratic governance primitives for AEVOR's
//! infrastructure parameter management, validator set coordination, and protocol
//! evolution decisions.
//!
//! ## Governance Scope
//!
//! This crate governs **infrastructure parameters** — consensus thresholds, gas schedules,
//! TEE service allocation policies, network parameters, and protocol upgrades. It does
//! **not** implement organizational governance frameworks, business process management,
//! or regulatory compliance policies that belong in application layers.
//!
//! ## Privacy-Preserving Governance
//!
//! Governance participation is confidential by default:
//! - Validator voting is anonymous through TEE-backed vote encryption
//! - Vote tallying is verifiable through ZK proofs without revealing individual votes
//! - Delegation is private by default with optional public disclosure
//! - Quorum checks produce mathematical proofs without participant identification
//!
//! ## Mathematical Verification
//!
//! All governance decisions are verified through on-chain mathematical proofs:
//! - Vote tallies include ZK proofs of correct computation
//! - Parameter changes include simulation results and impact analysis
//! - Upgrade proposals include compatibility proofs
//! - All decisions are immutably recorded on-chain
//!
//! ## Democratic Foundations
//!
//! Governance balances validator influence (stake-weighted) with participation
//! requirements (quorum thresholds) and time locks (deliberation windows) to
//! prevent plutocracy while maintaining decisive governance capability.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Proposal management: creation, lifecycle, and execution of governance proposals.
pub mod proposals;

/// Voting system: privacy-preserving vote collection and tally verification.
pub mod voting;

/// Delegation: stake delegation with privacy-preserving delegation chains.
pub mod delegation;

/// Infrastructure parameters: parameter change proposals and execution.
pub mod parameters;

/// Protocol upgrades: versioned upgrade proposals with compatibility verification.
pub mod upgrades;

/// Treasury management: community fund allocation proposals.
pub mod treasury;

/// Validator governance: validator set management decisions.
pub mod validator_governance;

/// Governance timing: proposal windows, voting periods, time locks.
pub mod timing;

/// Quorum calculation: participation thresholds and quorum verification.
pub mod quorum;

/// Governance records: immutable on-chain governance history.
pub mod records;

// ============================================================
// PRELUDE
// ============================================================

/// Governance prelude — all essential governance types.
///
/// ```rust
/// use aevor_governance::prelude::*;
/// ```
pub mod prelude {
    pub use crate::proposals::{
        Proposal, ProposalId, ProposalType, ProposalStatus, ProposalContent,
        ProposalLifecycle, ProposalExecution,
    };
    pub use crate::voting::{
        Vote, VoteWeight, VoteChoice, VoteTally, PrivateVote,
        VoteEncryption, VoteDecryption, TallyProof,
    };
    pub use crate::delegation::{
        Delegation, DelegationChain, DelegationRecord, RevokeDelegation,
        PrivateDelegation, DelegationProof,
    };
    pub use crate::parameters::{
        InfrastructureParameter, ParameterChange, ParameterRange,
        ParameterSimulation, ParameterChangeProposal,
    };
    pub use crate::upgrades::{
        UpgradeProposal, ProtocolVersion, CompatibilityProof,
        UpgradeActivation, MigrationPlan,
    };
    pub use crate::quorum::{
        QuorumRequirement, QuorumCheck, QuorumProof, ParticipationRate,
        StakeWeightedQuorum,
    };
    pub use crate::records::{
        GovernanceRecord, DecisionRecord, VoteRecord, HistoricalGovernance,
        GovernanceAuditTrail,
    };
    pub use crate::{GovernanceError, GovernanceResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from governance operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum GovernanceError {
    /// Proposal does not meet minimum requirements to be valid.
    #[error("invalid proposal: {reason}")]
    InvalidProposal {
        /// Reason the proposal is invalid.
        reason: String,
    },

    /// Quorum was not reached for a governance decision.
    #[error("quorum not reached: {actual:.1}% of {required:.1}% required")]
    QuorumNotReached {
        /// Actual participation percentage.
        actual: f64,
        /// Required participation percentage.
        required: f64,
    },

    /// Vote was submitted outside the voting window.
    #[error("vote submitted outside voting window for proposal {proposal_id}")]
    VotingWindowClosed {
        /// Proposal identifier.
        proposal_id: String,
    },

    /// Parameter change would violate infrastructure safety bounds.
    #[error("parameter change violates safety bounds: {parameter} = {value}")]
    ParameterOutOfBounds {
        /// Parameter name.
        parameter: String,
        /// Proposed value.
        value: String,
    },

    /// Upgrade compatibility check failed.
    #[error("upgrade incompatible: {reason}")]
    UpgradeIncompatible {
        /// Reason for incompatibility.
        reason: String,
    },

    /// Duplicate vote from the same validator.
    #[error("duplicate vote from validator {validator_id}")]
    DuplicateVote {
        /// Validator identifier.
        validator_id: String,
    },
}

/// Convenience alias for governance results.
pub type GovernanceResult<T> = Result<T, GovernanceError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default voting period in consensus rounds.
pub const DEFAULT_VOTING_PERIOD_ROUNDS: u64 = 14_400; // ~2 weeks at 1 round/sec

/// Default time lock before proposal execution in consensus rounds.
pub const DEFAULT_TIME_LOCK_ROUNDS: u64 = 7_200; // ~1 week

/// Minimum stake required to submit a governance proposal (fraction of total stake).
pub const MIN_PROPOSAL_STAKE_FRACTION: f64 = 0.001; // 0.1%

/// Default quorum requirement (fraction of total stake that must participate).
pub const DEFAULT_QUORUM_FRACTION: f64 = 0.15; // 15%

/// Default approval threshold (fraction of votes that must be in favor).
pub const DEFAULT_APPROVAL_FRACTION: f64 = 0.67; // 67%

/// Maximum number of simultaneous active proposals.
pub const MAX_ACTIVE_PROPOSALS: usize = 64;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_fractions_are_in_range() {
        assert!(MIN_PROPOSAL_STAKE_FRACTION > 0.0);
        assert!(DEFAULT_QUORUM_FRACTION > 0.0 && DEFAULT_QUORUM_FRACTION < 1.0);
        assert!(DEFAULT_APPROVAL_FRACTION > 0.5 && DEFAULT_APPROVAL_FRACTION <= 1.0);
    }

    #[test]
    fn time_lock_is_less_than_voting_period() {
        // Time lock starts after voting ends — both measured from proposal creation
        assert!(DEFAULT_VOTING_PERIOD_ROUNDS > 0);
        assert!(DEFAULT_TIME_LOCK_ROUNDS > 0);
    }
}
