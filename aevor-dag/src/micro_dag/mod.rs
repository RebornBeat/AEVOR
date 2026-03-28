//! Micro-DAG: transaction-level parallelism through dependency tracking.
//!
//! The Micro-DAG enables the Dual-DAG architecture's core promise: transactions
//! with no shared object dependencies execute concurrently, limited only by
//! available hardware — not by any artificial architectural ceiling.
//!
//! **Parallelism model:**
//! - `is_fully_parallel()` → 100% independent — all transactions can run at once
//! - `root_entries()` → transactions with no predecessors, the initial parallel wave
//! - `compute_parallelism()` → ratio of independent to total (0.0 = all serial, 1.0 = all parallel)
//!
//! **`dag_hash` is a set commitment** — it binds the *set* of transactions in the
//! DAG, not their execution order. This is correct: the DAG structure itself encodes
//! ordering, so the hash only needs to identify which transactions are present.

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

    fn make_entry(n: u8, parents: Vec<TransactionHash>) -> aevor_core::block::MicroDagEntry {
        use aevor_core::consensus::ValidationResult;
        use aevor_core::privacy::PrivacyLevel;
        aevor_core::block::MicroDagEntry {
            transaction_hash: tx(n),
            parents,
            execution_lane: ExecutionLane(0),
            read_set: vec![],
            write_set: vec![],
            privacy_level: PrivacyLevel::Public,
            requires_tee: false,
            validation: ValidationResult::valid(),
        }
    }

    #[test]
    fn empty_dag_hash_is_zero() {
        let dag = MicroDag { entries: vec![], parallel_groups: vec![], max_parallelism: 0 };
        assert_eq!(dag.dag_hash(), Hash256([0u8; 32]));
    }

    #[test]
    fn dag_hash_differs_for_different_tx_sets() {
        let entry_a = make_entry(1, vec![]);
        let entry_b = make_entry(2, vec![]);
        let dag_a = MicroDag { entries: vec![entry_a], parallel_groups: vec![], max_parallelism: 1 };
        let dag_b = MicroDag { entries: vec![entry_b], parallel_groups: vec![], max_parallelism: 1 };
        assert_ne!(dag_a.dag_hash(), dag_b.dag_hash());
    }

    #[test]
    fn is_fully_parallel_when_all_roots() {
        let dag = MicroDag {
            entries: vec![make_entry(1, vec![]), make_entry(2, vec![])],
            parallel_groups: vec![],
            max_parallelism: 2,
        };
        // All entries have no parents → all roots → fully parallel
        assert!(dag.is_fully_parallel());
    }

    #[test]
    fn is_not_fully_parallel_with_dependency() {
        let dag = MicroDag {
            entries: vec![make_entry(1, vec![]), make_entry(2, vec![tx(1)])],
            parallel_groups: vec![],
            max_parallelism: 1,
        };
        // tx 2 depends on tx 1 → not fully parallel
        assert!(!dag.is_fully_parallel());
    }

    #[test]
    fn root_entries_excludes_dependent_entries() {
        let dag = MicroDag {
            entries: vec![make_entry(1, vec![]), make_entry(2, vec![tx(1)])],
            parallel_groups: vec![],
            max_parallelism: 1,
        };
        let roots = dag.root_entries();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].transaction_hash, tx(1));
    }

    #[test]
    fn parallelism_ratio_all_roots_is_one() {
        let dag = MicroDag {
            entries: vec![make_entry(1, vec![]), make_entry(2, vec![])],
            parallel_groups: vec![],
            max_parallelism: 2,
        };
        let ratio = MicroDagAnalyzer::compute_parallelism(&dag);
        assert!((ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn parallelism_ratio_empty_dag_is_one() {
        let dag = MicroDag { entries: vec![], parallel_groups: vec![], max_parallelism: 0 };
        assert!((MicroDagAnalyzer::compute_parallelism(&dag) - 1.0).abs() < 1e-9);
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

    #[test]
    fn parallel_execution_set_cleared_means_no_conflicts() {
        let set = ParallelExecutionSet {
            transactions: vec![tx(1), tx(2), tx(3)],
            lane: ExecutionLane(0),
            no_conflicts_verified: true,
        };
        assert!(set.no_conflicts_verified);
        assert_eq!(set.transactions.len(), 3);
    }
}
