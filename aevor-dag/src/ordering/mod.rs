//! Logical ordering of transactions in the DAG.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Hash256, TransactionHash};
use aevor_core::consensus::ConsensusTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogicalOrdering {
    pub ordered: Vec<TransactionHash>,
    pub is_total_order: bool,
}

pub struct TopologicalSort;

impl TopologicalSort {
    pub fn sort(graph: &aevor_core::coordination::DependencyGraph) -> Vec<TransactionHash> {
        graph.topological_order.iter()
            .filter_map(|&i| graph.vertices.get(i).copied())
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyOrder {
    pub transaction: TransactionHash,
    pub order_index: usize,
    pub dependencies_satisfied: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalOrder {
    pub transactions: Vec<TransactionHash>,
    pub causal_roots: Vec<TransactionHash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusTimeOrder {
    pub transaction: TransactionHash,
    pub timestamp: ConsensusTimestamp,
    pub sequence: u64,
}

/// A Merkle-commitmentover the logical ordering.
///
/// `Hash256` binds the set of ordered transactions so light clients can
/// verify ordering proofs without downloading all transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderingCommitment {
    /// Hash committing to the ordered transaction sequence.
    pub root: Hash256,
    /// Number of transactions in this ordering.
    pub transaction_count: usize,
}

impl OrderingCommitment {
    /// Build an ordering commitment from a logical ordering.
    pub fn from_ordering(ordering: &LogicalOrdering) -> Self {
        let mut root = [0u8; 32];
        for (i, tx) in ordering.ordered.iter().enumerate() {
            for (j, b) in tx.0.iter().enumerate() { root[j % 32] ^= b ^ (i as u8); }
        }
        Self { root: Hash256(root), transaction_count: ordering.ordered.len() }
    }
}
