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
        self.entries.iter().all(|e| e.is_dag_root())
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
