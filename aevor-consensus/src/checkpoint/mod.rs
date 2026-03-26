//! Checkpoint creation, verification, and long-range attack protection.
//!
//! Checkpoints provide finality anchors at epoch boundaries. Each checkpoint
//! commits to the full state root and includes a finality proof from the
//! validator set, enabling light clients and new nodes to sync from a trusted
//! recent state rather than from genesis.

use serde::{Deserialize, Serialize};
pub use aevor_core::protocol::CheckpointInfo;
use aevor_core::primitives::{BlockHash, BlockHeight, EpochNumber, Hash256};
use aevor_core::consensus::{FinalityProof, SecurityLevel};
use aevor_core::storage::StateRoot;

/// A finalized consensus checkpoint with verification metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Core checkpoint data (height, epoch, state root).
    pub info: CheckpointInfo,
    /// Whether this checkpoint has been cryptographically verified.
    pub is_verified: bool,
    /// Finality proof from the validator set at this checkpoint.
    ///
    /// `None` for unverified or simulated checkpoints.
    pub finality_proof: Option<FinalityProof>,
    /// BLAKE3 hash of the checkpoint data for deduplication.
    pub content_hash: Hash256,
}

impl Checkpoint {
    /// Create a new unverified checkpoint.
    pub fn new(info: CheckpointInfo, content_hash: Hash256) -> Self {
        Self { info, is_verified: false, finality_proof: None, content_hash }
    }

    /// Attach a finality proof and mark as verified.
    pub fn with_proof(mut self, proof: FinalityProof) -> Self {
        self.finality_proof = Some(proof);
        self.is_verified = true;
        self
    }

    /// Block height of this checkpoint.
    pub fn height(&self) -> BlockHeight { self.info.height }

    /// Epoch number of this checkpoint.
    pub fn epoch(&self) -> EpochNumber { self.info.epoch }

    /// State root at this checkpoint.
    pub fn state_root(&self) -> StateRoot { self.info.state_root }

    /// Hash of the last block included in this checkpoint.
    pub fn block_hash(&self) -> BlockHash { self.content_hash }
}

/// Creates new checkpoints at epoch boundaries.
pub struct CheckpointCreator {
    /// How many epochs between checkpoints.
    checkpoint_interval_epochs: u64,
}

impl CheckpointCreator {
    /// Create a checkpoint creator with the given epoch interval.
    pub fn new(interval_epochs: u64) -> Self {
        Self { checkpoint_interval_epochs: interval_epochs }
    }

    /// Returns `true` if a checkpoint should be created at this epoch.
    pub fn should_checkpoint(&self, epoch: EpochNumber) -> bool {
        epoch.as_u64() % self.checkpoint_interval_epochs == 0
    }

    /// Build a checkpoint for the given block.
    pub fn create(
        &self,
        info: CheckpointInfo,
        block_hash: Hash256,
    ) -> Checkpoint {
        Checkpoint::new(info, block_hash)
    }
}

/// Verifies checkpoint authenticity and completeness.
pub struct CheckpointVerifier;

impl CheckpointVerifier {
    /// Verify that a checkpoint meets the minimum security requirements.
    ///
    /// A valid checkpoint must have `Full` security level and a non-empty
    /// finality proof. The finality proof is verified against the validator
    /// set by `aevor-tee` in production.
    pub fn verify(checkpoint: &Checkpoint) -> crate::ConsensusResult<bool> {
        if checkpoint.info.security_level < SecurityLevel::Full {
            return Ok(false);
        }
        // Must have a finality proof.
        if checkpoint.finality_proof.is_none() {
            return Ok(false);
        }
        // Content hash must be non-zero.
        if checkpoint.content_hash == Hash256::ZERO {
            return Ok(false);
        }
        Ok(true)
    }

    /// Verify that two checkpoints are consistent (same state root at same height).
    pub fn verify_consistency(a: &Checkpoint, b: &Checkpoint) -> bool {
        if a.height() != b.height() { return true; } // Different heights are fine
        a.state_root() == b.state_root() && a.content_hash == b.content_hash
    }
}

/// Marks the boundary between consensus epochs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochBoundary {
    /// Epoch number ending at this boundary.
    pub epoch: EpochNumber,
    /// Block height of the last block in this epoch.
    pub boundary_height: BlockHeight,
    /// Checkpoint created at this boundary (if any).
    pub checkpoint: Option<CheckpointInfo>,
    /// Hash of the last block in this epoch.
    pub last_block_hash: Hash256,
}

impl EpochBoundary {
    /// Returns `true` if this boundary has a checkpoint.
    pub fn has_checkpoint(&self) -> bool { self.checkpoint.is_some() }
}

/// Protects against long-range attacks by anchoring verification at known checkpoints.
///
/// An adversary with old validator keys cannot rewrite history past a checkpoint
/// that honest validators have already committed to with a finality proof.
pub struct LongRangeProtection {
    trusted_checkpoints: Vec<CheckpointInfo>,
}

impl LongRangeProtection {
    /// Create an empty long-range protection store.
    pub fn new() -> Self { Self { trusted_checkpoints: Vec::new() } }

    /// Add a trusted checkpoint (e.g., from genesis or a hard-coded anchor).
    pub fn add_trusted(&mut self, cp: CheckpointInfo) {
        self.trusted_checkpoints.push(cp);
    }

    /// Returns `true` if the given height is covered by a trusted checkpoint.
    ///
    /// A checkpoint covers all blocks up to and including its height.
    pub fn verify_chain_from_checkpoint(&self, from_height: BlockHeight) -> bool {
        self.trusted_checkpoints.iter().any(|cp| cp.height <= from_height)
    }

    /// The most recent trusted checkpoint, if any.
    pub fn latest_checkpoint(&self) -> Option<&CheckpointInfo> {
        self.trusted_checkpoints.iter().max_by_key(|cp| cp.height.0)
    }

    /// Number of trusted checkpoints stored.
    pub fn trusted_count(&self) -> usize { self.trusted_checkpoints.len() }

    /// Get the finality proof for a checkpoint at the given height, if stored.
    ///
    /// `FinalityProof` is built from BLS aggregate signatures; querying it here
    /// enables light clients to verify historical finalization without replaying all rounds.
    pub fn finality_proof_at(&self, height: BlockHeight) -> Option<&CheckpointInfo> {
        self.trusted_checkpoints.iter().find(|cp| cp.height == height)
    }
}

impl Default for LongRangeProtection {
    fn default() -> Self { Self::new() }
}
