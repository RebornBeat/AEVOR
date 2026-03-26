//! # Block Types
//!
//! Block structures for AEVOR's Dual-DAG architecture:
//! Micro-DAG entries for transaction-level parallelism and
//! Macro-DAG blocks for concurrent block production with validator diversity.

use serde::{Deserialize, Serialize};
use crate::primitives::{
    Address, BlockHash, BlockHeight, Hash256, TransactionHash, ValidatorId,
};
use crate::consensus::{
    ConsensusTimestamp, FinalityProof, SecurityLevel, ValidationResult,
};
use crate::storage::StateRoot;

// ============================================================
// BLOCK STATUS
// ============================================================

/// Current status of a block in the Dual-DAG lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockStatus {
    /// Proposed — waiting for attestations from validators.
    Proposed,
    /// Attesting — collecting validator attestations.
    Attesting,
    /// Certified — received sufficient attestations for Minimal security.
    Certified,
    /// Finalized — achieved the requested security level.
    Finalized,
    /// Rejected — failed validation or attestation collection.
    Rejected,
}

impl BlockStatus {
    /// Returns `true` if this block has achieved finality at any level.
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized)
    }

    /// Returns `true` if this block is still being processed.
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Proposed | Self::Attesting)
    }
}

// ============================================================
// BLOCK HEADER
// ============================================================

/// The header of an AEVOR block — used for light client verification.
///
/// Block headers contain all metadata needed to verify block linkage,
/// state transitions, and consensus without requiring the full block body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// This block's hash.
    pub hash: BlockHash,
    /// Parent block hash (None for genesis).
    pub parent_hash: Option<BlockHash>,
    /// Block height (sequential from genesis = 0).
    pub height: BlockHeight,
    /// Consensus round that produced this block.
    pub consensus_round: u64,
    /// Consensus timestamp (derived from consensus, not wall clock).
    pub timestamp: ConsensusTimestamp,
    /// Validator that proposed this block.
    pub proposer: ValidatorId,
    /// State root after applying all transactions in this block.
    pub state_root: StateRoot,
    /// Root of the transaction Merkle tree for this block.
    pub transaction_root: Hash256,
    /// Root of the receipts Merkle tree for this block.
    pub receipt_root: Hash256,
    /// Number of transactions in this block.
    pub transaction_count: u32,
    /// Total gas consumed by all transactions in this block.
    pub gas_used: crate::primitives::GasAmount,
    /// Gas limit for this block.
    pub gas_limit: crate::primitives::GasAmount,
    /// Security level achieved for this block.
    pub security_level: SecurityLevel,
}

impl BlockHeader {
    /// Returns `true` if this is the genesis block header.
    pub fn is_genesis(&self) -> bool {
        self.height == BlockHeight::GENESIS && self.parent_hash.is_none()
    }
}

// ============================================================
// BLOCK PROOF
// ============================================================

/// Cryptographic proof that a block was validly produced and finalized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockProof {
    /// The block this is a proof for.
    pub block_hash: BlockHash,
    /// Finality proof (aggregated validator signatures).
    pub finality_proof: FinalityProof,
    /// TEE attestations from validators that attested this block.
    pub tee_attestations: Vec<crate::consensus::ExecutionAttestation>,
    /// Security level achieved.
    pub security_level: SecurityLevel,
}

// ============================================================
// BLOCK ATTESTATION
// ============================================================

/// An attestation from a single validator for a block.
///
/// Validators produce attestations after verifying a block's correctness
/// inside their TEE enclave, providing mathematical certainty that the
/// block was honestly produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockAttestation {
    /// Hash of the block being attested.
    pub block_hash: BlockHash,
    /// Validator producing this attestation.
    pub validator_id: ValidatorId,
    /// Validator's signature over the block hash.
    pub signature: crate::primitives::Signature,
    /// TEE attestation proving this was computed inside a TEE.
    pub tee_attestation: Option<crate::consensus::ExecutionAttestation>,
    /// When this attestation was produced.
    pub timestamp: ConsensusTimestamp,
}

// ============================================================
// MICRO DAG ENTRY
// ============================================================

/// An entry in the Micro-DAG — enables transaction-level parallelism.
///
/// The Micro-DAG represents individual transactions as vertices with edges
/// encoding their causal dependencies. Transactions without edges between
/// them can be executed in parallel, achieving the 200,000+ TPS throughput.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroDagEntry {
    /// The transaction this entry represents.
    pub transaction_hash: TransactionHash,
    /// Direct causal predecessors in the DAG.
    pub parents: Vec<TransactionHash>,
    /// Execution lane assigned by the scheduler.
    pub execution_lane: crate::execution::ExecutionLane,
    /// Objects this transaction reads.
    pub read_set: Vec<crate::primitives::ObjectId>,
    /// Objects this transaction writes.
    pub write_set: Vec<crate::primitives::ObjectId>,
    /// Privacy level of this transaction's execution.
    pub privacy_level: crate::privacy::PrivacyLevel,
    /// Whether this transaction requires TEE execution.
    pub requires_tee: bool,
    /// Validation result for this transaction.
    pub validation: ValidationResult,
}

impl MicroDagEntry {
    /// Returns `true` if this entry has no parent dependencies (can execute first).
    pub fn is_dag_root(&self) -> bool {
        self.parents.is_empty()
    }

    /// Returns `true` if this entry conflicts with `other` (cannot parallelize).
    pub fn conflicts_with(&self, other: &Self) -> bool {
        // Write-read or write-write conflict on any shared object
        self.write_set.iter().any(|w| {
            other.read_set.contains(w) || other.write_set.contains(w)
        })
    }
}

// ============================================================
// MACRO DAG BLOCK
// ============================================================

/// A block in the Macro-DAG — enables concurrent block production.
///
/// The Macro-DAG allows multiple validators to produce blocks concurrently
/// without a single leader bottleneck. Blocks reference their parents in
/// the DAG (previous blocks they build on), and the uncorrupted frontier
/// advances as attestations are collected.
///
/// Blocks from different validators can be produced in the same consensus
/// round as long as they don't conflict on the same state. The Macro-DAG
/// merges these concurrent blocks into a consistent total order at finality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacroDagBlock {
    /// This block's header.
    pub header: BlockHeader,
    /// Parent blocks in the Macro-DAG (typically 1–4).
    pub dag_parents: Vec<BlockHash>,
    /// Transactions in this block (ordered for execution).
    pub transactions: Vec<TransactionHash>,
    /// Micro-DAG entries for all transactions in this block.
    pub micro_dag: Vec<MicroDagEntry>,
    /// Attestations collected for this block.
    pub attestations: Vec<BlockAttestation>,
    /// Block proof (populated after finality is achieved).
    pub proof: Option<BlockProof>,
    /// Current status of this block.
    pub status: BlockStatus,
}

impl MacroDagBlock {
    /// Returns `true` if this block has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.status.is_finalized() && self.proof.is_some()
    }

    /// Number of transactions in this block.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Number of attestations collected.
    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    /// Returns `true` if the Micro-DAG has parallel execution paths.
    pub fn has_parallel_execution(&self) -> bool {
        // Multiple root entries in the Micro-DAG means parallel execution
        self.micro_dag.iter().filter(|e| e.is_dag_root()).count() > 1
    }
}

// ============================================================
// BLOCK (UNIFIED)
// ============================================================

/// A unified block type that wraps the Macro-DAG block with additional metadata.
///
/// This is the top-level block type used in APIs and storage — it provides
/// a stable interface regardless of the underlying Dual-DAG implementation details.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The core Macro-DAG block.
    pub inner: MacroDagBlock,
    /// Block size in bytes.
    pub size_bytes: u32,
    /// Total fees paid for all transactions.
    pub total_fees: crate::primitives::Amount,
    /// Address where block rewards are sent.
    pub reward_address: Address,
}

impl Block {
    /// The block's header.
    pub fn header(&self) -> &BlockHeader {
        &self.inner.header
    }

    /// The block's hash.
    pub fn hash(&self) -> BlockHash {
        self.inner.header.hash
    }

    /// The block's height.
    pub fn height(&self) -> BlockHeight {
        self.inner.header.height
    }

    /// Number of transactions.
    pub fn transaction_count(&self) -> usize {
        self.inner.transaction_count()
    }

    /// Returns `true` if this block is finalized.
    pub fn is_finalized(&self) -> bool {
        self.inner.is_finalized()
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_status_finalized_detection() {
        assert!(BlockStatus::Finalized.is_finalized());
        assert!(!BlockStatus::Proposed.is_finalized());
        assert!(!BlockStatus::Rejected.is_finalized());
    }

    #[test]
    fn block_status_in_progress() {
        assert!(BlockStatus::Proposed.is_in_progress());
        assert!(BlockStatus::Attesting.is_in_progress());
        assert!(!BlockStatus::Finalized.is_in_progress());
    }

    #[test]
    fn micro_dag_entry_root_detection() {
        let entry = MicroDagEntry {
            transaction_hash: Hash256::ZERO,
            parents: vec![],
            execution_lane: crate::execution::ExecutionLane::SEQUENTIAL,
            read_set: vec![],
            write_set: vec![],
            privacy_level: crate::privacy::PrivacyLevel::Public,
            requires_tee: false,
            validation: ValidationResult::valid(),
        };
        assert!(entry.is_dag_root());
    }

    #[test]
    fn micro_dag_conflict_detection() {
        let obj_id = crate::primitives::ObjectId::from_hash(Hash256([1u8; 32]));

        let writer = MicroDagEntry {
            transaction_hash: Hash256([1u8; 32]),
            parents: vec![],
            execution_lane: crate::execution::ExecutionLane::SEQUENTIAL,
            read_set: vec![],
            write_set: vec![obj_id],
            privacy_level: crate::privacy::PrivacyLevel::Public,
            requires_tee: false,
            validation: ValidationResult::valid(),
        };
        let reader = MicroDagEntry {
            transaction_hash: Hash256([2u8; 32]),
            parents: vec![],
            execution_lane: crate::execution::ExecutionLane::SEQUENTIAL,
            read_set: vec![obj_id],
            write_set: vec![],
            privacy_level: crate::privacy::PrivacyLevel::Public,
            requires_tee: false,
            validation: ValidationResult::valid(),
        };
        assert!(writer.conflicts_with(&reader));
    }

    #[test]
    fn block_header_genesis_detection() {
        let header = BlockHeader {
            hash: Hash256::ZERO,
            parent_hash: None,
            height: BlockHeight::GENESIS,
            consensus_round: 0,
            timestamp: ConsensusTimestamp::GENESIS,
            proposer: Hash256::ZERO,
            state_root: crate::storage::MerkleRoot::EMPTY,
            transaction_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            transaction_count: 0,
            gas_used: crate::primitives::GasAmount::ZERO,
            gas_limit: crate::primitives::GasAmount::from_u64(10_000_000),
            security_level: SecurityLevel::Full,
        };
        assert!(header.is_genesis());
    }
}
