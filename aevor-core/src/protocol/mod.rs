//! # Protocol Types
//!
//! Protocol versioning, epoch management, checkpoint tracking, and
//! consensus round information.

use serde::{Deserialize, Serialize};
use crate::primitives::{BlockHash, BlockHeight, EpochNumber, Hash256};
use crate::consensus::{ConsensusTimestamp, SecurityLevel};
use crate::storage::StateRoot;

// ============================================================
// PROTOCOL VERSION
// ============================================================

/// AEVOR protocol version.
///
/// The protocol version governs which features are active, what message
/// formats are accepted, and what consensus rules apply. Protocol upgrades
/// are coordinated through governance and activate at specific epoch boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version — breaking consensus changes.
    pub major: u16,
    /// Minor version — backwards-compatible feature additions.
    pub minor: u16,
    /// Patch version — bug fixes and minor improvements.
    pub patch: u16,
}

impl ProtocolVersion {
    /// Create a new protocol version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    /// AEVOR v1.0.0 — initial mainnet protocol.
    pub const V1_0_0: Self = Self::new(1, 0, 0);

    /// Returns `true` if this version is backwards-compatible with `other`.
    ///
    /// Versions are backwards-compatible when they share the same major version.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Returns `true` if this is a newer version than `other`.
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self > other
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::V1_0_0
    }
}

// ============================================================
// NETWORK EPOCH
// ============================================================

/// A network epoch — a fixed-length period for validator set rotation and rewards.
///
/// AEVOR uses epochs to:
/// 1. Rotate the active validator set (new validators join, others leave)
/// 2. Distribute accumulated rewards
/// 3. Activate protocol upgrades
/// 4. Checkpoint the global state for fast sync
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEpoch {
    /// Epoch number.
    pub number: EpochNumber,
    /// Block height where this epoch began.
    pub start_height: BlockHeight,
    /// Block height where this epoch ended (None if current).
    pub end_height: Option<BlockHeight>,
    /// State root at the start of this epoch.
    pub start_state_root: StateRoot,
    /// State root at the end of this epoch (None if current).
    pub end_state_root: Option<StateRoot>,
    /// Protocol version active during this epoch.
    pub protocol_version: ProtocolVersion,
    /// Number of active validators during this epoch.
    pub validator_count: u32,
    /// Consensus timestamp of epoch start.
    pub start_timestamp: ConsensusTimestamp,
    /// Total rewards distributed at epoch end.
    pub total_rewards: Option<crate::primitives::Amount>,
}

impl NetworkEpoch {
    /// Returns `true` if this is the current (incomplete) epoch.
    pub fn is_current(&self) -> bool {
        self.end_height.is_none()
    }

    /// Returns `true` if this epoch has been completed.
    pub fn is_complete(&self) -> bool {
        self.end_height.is_some() && self.end_state_root.is_some()
    }
}

// ============================================================
// CHECKPOINT INFO
// ============================================================

/// Information about a consensus checkpoint.
///
/// Checkpoints are periodically-committed state snapshots that enable:
/// 1. Fast sync — new nodes can start from a checkpoint instead of genesis
/// 2. State pruning — blocks before the checkpoint can be pruned
/// 3. Finality anchoring — checkpoints provide absolute finality
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// Unique hash of this checkpoint.
    pub checkpoint_hash: Hash256,
    /// Block height this checkpoint is for.
    pub height: BlockHeight,
    /// Epoch number at this checkpoint.
    pub epoch: EpochNumber,
    /// State root at this checkpoint.
    pub state_root: StateRoot,
    /// Consensus timestamp of this checkpoint.
    pub timestamp: ConsensusTimestamp,
    /// Security level achieved for this checkpoint.
    pub security_level: SecurityLevel,
    /// Finality proof for this checkpoint.
    pub finality_proof: crate::consensus::FinalityProof,
    /// Protocol version at this checkpoint.
    pub protocol_version: ProtocolVersion,
}

impl CheckpointInfo {
    /// Returns `true` if this checkpoint has full security.
    pub fn is_fully_secure(&self) -> bool {
        self.security_level >= SecurityLevel::Full
    }
}

// ============================================================
// CONSENSUS ROUND INFO
// ============================================================

/// Information about a completed consensus round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusRoundInfo {
    /// Round number.
    pub round: u64,
    /// Epoch this round belongs to.
    pub epoch: EpochNumber,
    /// Blocks finalized in this round.
    pub finalized_blocks: Vec<BlockHash>,
    /// Number of transactions finalized in this round.
    pub transaction_count: u64,
    /// Security level achieved.
    pub security_level: SecurityLevel,
    /// Duration of this round in milliseconds.
    pub duration_ms: u64,
    /// Validator participation rate (0–100).
    pub participation_pct: u8,
    /// Timestamp of this round.
    pub timestamp: ConsensusTimestamp,
}

impl ConsensusRoundInfo {
    /// Returns `true` if this round achieved Byzantine fault tolerance.
    pub fn is_byzantine_fault_tolerant(&self) -> bool {
        self.security_level.is_byzantine_fault_tolerant()
    }

    /// Returns `true` if validator participation was sufficient for full security.
    pub fn is_fully_participated(&self) -> bool {
        self.participation_pct >= 67
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_ordering() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v2 = ProtocolVersion::new(1, 1, 0);
        let v3 = ProtocolVersion::new(2, 0, 0);
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3.is_newer_than(&v1));
    }

    #[test]
    fn protocol_version_compatibility() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v1_1 = ProtocolVersion::new(1, 5, 0);
        let v2 = ProtocolVersion::new(2, 0, 0);
        assert!(v1.is_compatible_with(&v1_1));
        assert!(!v1.is_compatible_with(&v2));
    }

    #[test]
    fn protocol_version_display() {
        assert_eq!(ProtocolVersion::V1_0_0.to_string(), "1.0.0");
    }

    #[test]
    fn network_epoch_current_has_no_end() {
        let epoch = NetworkEpoch {
            number: EpochNumber::from_u64(1),
            start_height: BlockHeight::from_u64(100),
            end_height: None,
            start_state_root: crate::storage::MerkleRoot::EMPTY,
            end_state_root: None,
            protocol_version: ProtocolVersion::V1_0_0,
            validator_count: 100,
            start_timestamp: ConsensusTimestamp::GENESIS,
            total_rewards: None,
        };
        assert!(epoch.is_current());
        assert!(!epoch.is_complete());
    }

    #[test]
    fn consensus_round_bft_check() {
        let round = ConsensusRoundInfo {
            round: 1,
            epoch: EpochNumber::GENESIS,
            finalized_blocks: vec![],
            transaction_count: 1000,
            security_level: SecurityLevel::Strong,
            duration_ms: 300,
            participation_pct: 70,
            timestamp: ConsensusTimestamp::GENESIS,
        };
        assert!(round.is_byzantine_fault_tolerant());
        assert!(round.is_fully_participated());
    }

    #[test]
    fn checkpoint_full_security_check() {
        use crate::consensus::FinalityProof;
        let cp = CheckpointInfo {
            checkpoint_hash: Hash256::ZERO,
            height: BlockHeight::from_u64(1000),
            epoch: EpochNumber::from_u64(10),
            state_root: crate::storage::MerkleRoot::EMPTY,
            timestamp: ConsensusTimestamp::GENESIS,
            security_level: SecurityLevel::Full,
            finality_proof: FinalityProof {
                signatures: vec![],
                aggregate_signature: vec![],
                participant_bitmap: vec![],
                total_weight: crate::primitives::ValidatorWeight::ZERO,
                security_level: SecurityLevel::Full,
            },
            protocol_version: ProtocolVersion::V1_0_0,
        };
        assert!(cp.is_fully_secure());
    }
}
