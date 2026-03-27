//! Micro-DAG: transaction-level parallelism through dependency tracking.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Hash256, ObjectId, TransactionHash};
use aevor_core::execution::ExecutionLane;
use aevor_core::privacy::PrivacyLevel;
pub use aevor_core::block::MicroDagEntry;

/// A complete Micro-DAG for a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MicroDag {
    pub entries: Vec<MicroDagEntry>,
    pub parallel_groups: Vec<Vec<TransactionHash>>,
    pub max_parallelism: usize,
}

impl MicroDag {
    /// Number of transactions in this Micro-DAG.
    pub fn transaction_count(&self) -> usize { self.entries.len() }

    /// Transactions with no incoming edges (can execute first).
    pub fn root_entries(&self) -> Vec<&MicroDagEntry> {
        self.entries.iter().filter(|e| e.is_dag_root()).collect()
    }

    /// Returns `true` if all transactions are conflict-free (100% parallelism).
    pub fn is_fully_parallel(&self) -> bool {
        self.entries.iter().all(MicroDagEntry::is_dag_root)
    }

    /// A `Hash256` commitment to the DAG structure (XOR of all tx hashes).
    ///
    /// Used for deduplication and DAG root verification. Full Merkle tree
    /// computation is done by `aevor-crypto` in production.
    pub fn dag_hash(&self) -> Hash256 {
        let mut root = [0u8; 32];
        for entry in &self.entries {
            for (i, b) in entry.transaction_hash.0.iter().enumerate() {
                root[i] ^= b;
            }
        }
        Hash256(root)
    }
}

/// A directed dependency edge between two transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: TransactionHash,
    pub to: TransactionHash,
    pub conflicting_object: ObjectId,
    pub edge_type: aevor_core::execution::DependencyType,
}

/// The complete set of conflicting transactions for a given transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictSet {
    pub transaction: TransactionHash,
    pub conflicts_with: Vec<TransactionHash>,
    pub conflict_objects: Vec<ObjectId>,
}

/// Analyzes a Micro-DAG to extract execution properties.
pub struct MicroDagAnalyzer;

impl MicroDagAnalyzer {
    #[allow(clippy::cast_precision_loss)] // DAG parallelism ratio: precision loss acceptable
    pub fn compute_parallelism(dag: &MicroDag) -> f64 {
        if dag.entries.is_empty() { return 1.0; }
        dag.entries.iter().filter(|e| e.is_dag_root()).count() as f64
            / dag.entries.len() as f64
    }
}

/// A set of transactions that can all execute in parallel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelExecutionSet {
    pub transactions: Vec<TransactionHash>,
    pub lane: ExecutionLane,
    pub no_conflicts_verified: bool,
}

/// Access pattern of a transaction (read/write sets).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectAccessPattern {
    pub transaction: TransactionHash,
    pub reads: Vec<ObjectId>,
    pub writes: Vec<ObjectId>,
    pub privacy_level: PrivacyLevel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, TransactionHash};

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn empty_dag_hash_is_zero() {
        let dag = MicroDag { entries: vec![], parallel_groups: vec![], max_parallelism: 0 };
        assert_eq!(dag.dag_hash(), Hash256([0u8; 32]));
    }

    #[test]
    fn dag_hash_differs_for_different_tx_sets() {
        use aevor_core::block::MicroDagEntry;
        use aevor_core::consensus::ValidationResult;
        use aevor_core::privacy::PrivacyLevel;
        let entry_a = MicroDagEntry {
            transaction_hash: tx(1),
            parents: vec![],
            execution_lane: aevor_core::execution::ExecutionLane(0),
            read_set: vec![],
            write_set: vec![],
            privacy_level: PrivacyLevel::Public,
            requires_tee: false,
            validation: ValidationResult::valid(),
        };
        let entry_b = MicroDagEntry {
            transaction_hash: tx(2),
            parents: vec![],
            execution_lane: aevor_core::execution::ExecutionLane(0),
            read_set: vec![],
            write_set: vec![],
            privacy_level: PrivacyLevel::Public,
            requires_tee: false,
            validation: ValidationResult::valid(),
        };
        let dag_a = MicroDag { entries: vec![entry_a], parallel_groups: vec![], max_parallelism: 1 };
        let dag_b = MicroDag { entries: vec![entry_b], parallel_groups: vec![], max_parallelism: 1 };
        assert_ne!(dag_a.dag_hash(), dag_b.dag_hash());
    }

    #[test]
    fn conflict_edge_sequential_for_write_after_write() {
        use super::super::conflict::ConflictEdge;
        use aevor_core::primitives::ObjectId;
        use aevor_core::execution::DependencyType;
        let edge = ConflictEdge::new(tx(1), tx(2), ObjectId(Hash256([3u8; 32])), DependencyType::WriteAfterWrite);
        assert!(edge.requires_sequential());
    }

    #[test]
    fn conflict_edge_not_sequential_for_read_after_write() {
        use super::super::conflict::ConflictEdge;
        use aevor_core::primitives::ObjectId;
        use aevor_core::execution::DependencyType;
        let edge = ConflictEdge::new(tx(1), tx(2), ObjectId(Hash256([3u8; 32])), DependencyType::ReadAfterWrite);
        assert!(!edge.requires_sequential());
    }
}
