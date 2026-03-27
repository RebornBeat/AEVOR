//! # Blockchain State Types
//!
//! The global state of the AEVOR blockchain: the world state (all objects),
//! account states, state transitions, the uncorrupted frontier, and
//! state snapshots for checkpointing.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::primitives::{
    Address, BlockHash, BlockHeight, Hash256, ObjectId,
};
use crate::consensus::{ConsensusTimestamp, SecurityLevel};
use crate::storage::{MerkleRoot, StateRoot};

// ============================================================
// STATE VERSION
// ============================================================

/// Identifies a specific version of the global state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct StateVersion {
    /// Monotonically increasing version number.
    pub number: u64,
    /// State root at this version.
    pub root: StateRoot,
    /// Block height corresponding to this version.
    pub block_height: BlockHeight,
}

impl StateVersion {
    /// Genesis state version.
    pub fn genesis() -> Self {
        Self {
            number: 0,
            root: MerkleRoot::EMPTY,
            block_height: BlockHeight::GENESIS,
        }
    }

    /// Create the next version.
    #[must_use]
    pub fn advance(&self, new_root: StateRoot, block_height: BlockHeight) -> Self {
        Self {
            number: self.number + 1,
            root: new_root,
            block_height,
        }
    }
}

impl std::fmt::Display for StateVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}@h{}({})", self.number, self.block_height, self.root)
    }
}

// ============================================================
// WORLD STATE
// ============================================================

/// The complete world state of the AEVOR blockchain.
///
/// The world state is the set of all objects that currently exist in the
/// blockchain. It is cryptographically committed to by the state root in
/// each block header, enabling any node to verify any piece of state with
/// a Merkle proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldState {
    /// Current state version.
    pub version: StateVersion,
    /// The state root committing to all objects.
    pub root: StateRoot,
    /// Total number of objects in state.
    pub object_count: u64,
    /// Total supply of AEVOR tokens in circulation.
    pub total_supply: crate::primitives::Amount,
    /// Latest finalized block height.
    pub finalized_height: BlockHeight,
    /// Consensus timestamp of the last finalized block.
    pub last_finalized_timestamp: ConsensusTimestamp,
}

impl WorldState {
    /// Create the genesis world state.
    pub fn genesis(initial_supply: crate::primitives::Amount) -> Self {
        Self {
            version: StateVersion::genesis(),
            root: MerkleRoot::EMPTY,
            object_count: 0,
            total_supply: initial_supply,
            finalized_height: BlockHeight::GENESIS,
            last_finalized_timestamp: ConsensusTimestamp::GENESIS,
        }
    }

    /// Returns `true` if this world state has no objects (empty/genesis).
    pub fn is_empty(&self) -> bool {
        self.object_count == 0
    }
}

// ============================================================
// GLOBAL STATE
// ============================================================

/// Extended global state including all protocol-level tracked values.
///
/// `GlobalState` extends `WorldState` with the additional protocol state
/// needed to drive consensus, validator management, governance, and economics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalState {
    /// The world state (objects).
    pub world_state: WorldState,
    /// Current epoch number.
    pub current_epoch: crate::primitives::EpochNumber,
    /// Number of active validators.
    pub active_validator_count: u32,
    /// Total staked amount across all validators.
    pub total_staked: crate::primitives::Amount,
    /// Current base fee per gas unit.
    pub base_fee: crate::primitives::GasPrice,
    /// Uncorrupted frontier state.
    pub uncorrupted_frontier: UncorruptedFrontier,
    /// Pending governance proposals count.
    pub pending_proposals: u32,
}

impl GlobalState {
    /// Get the current state version.
    pub fn state_version(&self) -> StateVersion {
        self.world_state.version
    }

    /// Get the current state root.
    pub fn state_root(&self) -> StateRoot {
        self.world_state.root
    }
}

// ============================================================
// UNCORRUPTED FRONTIER
// ============================================================

/// The uncorrupted frontier — the set of blocks at the leading edge of
/// the blockchain that have been validated but may not yet be fully finalized.
///
/// The uncorrupted frontier is what distinguishes AEVOR from simple longest-chain
/// consensus. A block enters the frontier when it receives sufficient TEE
/// attestations to guarantee it was not produced by Byzantine validators.
/// The frontier advances as new blocks are attested and older blocks reach
/// their required finality threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncorruptedFrontier {
    /// Blocks that are on the frontier (attested but not fully finalized).
    pub frontier_blocks: Vec<BlockHash>,
    /// Security level of the current frontier.
    pub security_level: SecurityLevel,
    /// Latest state root on the frontier.
    pub frontier_root: StateRoot,
    /// Consensus timestamp of the frontier.
    pub frontier_timestamp: ConsensusTimestamp,
    /// Total attestation weight covering this frontier.
    pub attestation_weight: crate::primitives::ValidatorWeight,
}

impl UncorruptedFrontier {
    /// Returns the number of blocks on the current frontier.
    pub fn width(&self) -> usize {
        self.frontier_blocks.len()
    }

    /// Returns `true` if the frontier has reached at least the requested security level.
    pub fn meets_security_level(&self, required: SecurityLevel) -> bool {
        self.security_level >= required
    }

    /// Returns `true` if the frontier is a single canonical block (no forks).
    pub fn is_canonical(&self) -> bool {
        self.frontier_blocks.len() == 1
    }
}

// ============================================================
// NETWORK FRONTIER
// ============================================================

/// The network-level frontier tracking progress across all subnets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFrontier {
    /// The mainnet frontier.
    pub mainnet_frontier: UncorruptedFrontier,
    /// Subnet frontiers by subnet identifier.
    pub subnet_frontiers: HashMap<crate::network::SubnetId, UncorruptedFrontier>,
    /// Cross-chain bridge frontiers.
    pub bridge_frontiers: HashMap<String, Hash256>,
}

impl NetworkFrontier {
    /// Returns `true` if all tracked frontiers have reached the given security level.
    pub fn all_meet_security_level(&self, required: SecurityLevel) -> bool {
        if !self.mainnet_frontier.meets_security_level(required) {
            return false;
        }
        self.subnet_frontiers
            .values()
            .all(|f| f.meets_security_level(required))
    }
}

// ============================================================
// STATE TRANSITION
// ============================================================

/// A verified state transition: from one state version to the next.
///
/// State transitions are the atomic unit of state change in AEVOR.
/// Each transaction produces a state transition, and block finalization
/// atomically commits all transitions in the block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransition {
    /// The state version before this transition.
    pub from_version: StateVersion,
    /// The state version after this transition.
    pub to_version: StateVersion,
    /// The transaction that caused this transition.
    pub caused_by: crate::primitives::TransactionHash,
    /// Objects that changed (added, modified, or deleted).
    pub changed_objects: Vec<ObjectId>,
    /// Hash of the complete set of changes.
    pub changes_hash: Hash256,
    /// Whether this transition was executed inside a TEE.
    pub tee_executed: bool,
    /// TEE attestation for this transition (if `tee_executed`).
    pub tee_attestation: Option<crate::consensus::ExecutionAttestation>,
}

impl StateTransition {
    /// Returns `true` if this transition had no state changes (no-op).
    pub fn is_noop(&self) -> bool {
        self.from_version.root == self.to_version.root
    }

    /// Number of objects changed by this transition.
    pub fn change_count(&self) -> usize {
        self.changed_objects.len()
    }
}

// ============================================================
// ACCOUNT STATE
// ============================================================

/// State of a single account address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    /// The account address.
    pub address: Address,
    /// Current balance.
    pub balance: crate::primitives::Amount,
    /// Current nonce.
    pub nonce: crate::primitives::Nonce,
    /// Objects owned by this account.
    pub owned_objects: Vec<ObjectId>,
    /// Whether this account has a deployed contract.
    pub has_contract: bool,
    /// Staked amount (if this is a validator address).
    pub staked_amount: crate::primitives::Amount,
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_version_genesis_is_zero() {
        let v = StateVersion::genesis();
        assert_eq!(v.number, 0);
        assert!(v.root.is_empty());
    }

    #[test]
    fn state_version_advances() {
        let v = StateVersion::genesis();
        let new_root = MerkleRoot::from_hash(Hash256([1u8; 32]));
        let v2 = v.advance(new_root, BlockHeight::from_u64(1));
        assert_eq!(v2.number, 1);
        assert_eq!(v2.root, new_root);
    }

    #[test]
    fn world_state_genesis_is_empty() {
        let ws = WorldState::genesis(crate::primitives::Amount::from_nano(1_000_000_000_000));
        assert!(ws.is_empty());
        assert_eq!(ws.object_count, 0);
    }

    #[test]
    fn uncorrupted_frontier_single_block_is_canonical() {
        let f = UncorruptedFrontier {
            frontier_blocks: vec![Hash256::ZERO],
            security_level: SecurityLevel::Basic,
            frontier_root: MerkleRoot::EMPTY,
            frontier_timestamp: ConsensusTimestamp::GENESIS,
            attestation_weight: crate::primitives::ValidatorWeight::ZERO,
        };
        assert!(f.is_canonical());
    }

    #[test]
    fn uncorrupted_frontier_multiple_blocks_not_canonical() {
        let f = UncorruptedFrontier {
            frontier_blocks: vec![Hash256::ZERO, Hash256([1u8; 32])],
            security_level: SecurityLevel::Basic,
            frontier_root: MerkleRoot::EMPTY,
            frontier_timestamp: ConsensusTimestamp::GENESIS,
            attestation_weight: crate::primitives::ValidatorWeight::ZERO,
        };
        assert!(!f.is_canonical());
        assert_eq!(f.width(), 2);
    }

    #[test]
    fn state_transition_noop_detection() {
        let _root = MerkleRoot::EMPTY;
        let v = StateVersion::genesis();
        let t = StateTransition {
            from_version: v,
            to_version: v, // Same version = no-op
            caused_by: Hash256::ZERO,
            changed_objects: vec![],
            changes_hash: Hash256::ZERO,
            tee_executed: false,
            tee_attestation: None,
        };
        assert!(t.is_noop());
    }
}
