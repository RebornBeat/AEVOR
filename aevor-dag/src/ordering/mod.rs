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
    ///
    /// **Note on commutativity:** The current implementation uses XOR over all
    /// `(tx_byte XOR position_byte)` values. Because XOR is commutative and
    /// associative, this produces the **same hash for any permutation of the same
    /// transaction set** — it is a set commitment, not an ordering commitment.
    /// A production implementation should use a position-dependent hash (e.g.
    /// hash-of-concatenation or Merkle tree) to distinguish orderings.
    pub fn from_ordering(ordering: &LogicalOrdering) -> Self {
        let mut root = [0u8; 32];
        for (i, tx) in ordering.ordered.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)] // position index mixed into hash — truncation is intentional
            let i_byte = i as u8;
            for (j, b) in tx.0.iter().enumerate() { root[j % 32] ^= b ^ i_byte; }
        }
        Self { root: Hash256(root), transaction_count: ordering.ordered.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, TransactionHash};

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn ordering_commitment_empty_ordering_is_zero_root() {
        let ordering = LogicalOrdering { ordered: vec![], is_total_order: true };
        let commit = OrderingCommitment::from_ordering(&ordering);
        assert_eq!(commit.root, Hash256::ZERO);
        assert_eq!(commit.transaction_count, 0);
    }

    #[test]
    fn ordering_commitment_nonzero_with_transactions() {
        let ordering = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: true };
        let commit = OrderingCommitment::from_ordering(&ordering);
        assert_ne!(commit.root, Hash256::ZERO);
        assert_eq!(commit.transaction_count, 2);
    }

    #[test]
    fn ordering_commitment_is_set_commitment_not_order_sensitive() {
        // XOR is commutative — the current implementation produces the same
        // commitment for any permutation of the same transaction set.
        // This is a known limitation documented on from_ordering.
        let o1 = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: true };
        let o2 = LogicalOrdering { ordered: vec![tx(2), tx(1)], is_total_order: true };
        let c1 = OrderingCommitment::from_ordering(&o1);
        let c2 = OrderingCommitment::from_ordering(&o2);
        assert_eq!(c1.root, c2.root); // same set → same commitment
        assert_eq!(c1.transaction_count, c2.transaction_count);
    }

    #[test]
    fn ordering_commitment_differs_for_different_sets() {
        // Different *sets* of transactions do produce different commitments.
        let o1 = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: true };
        let o2 = LogicalOrdering { ordered: vec![tx(3), tx(4)], is_total_order: true };
        let c1 = OrderingCommitment::from_ordering(&o1);
        let c2 = OrderingCommitment::from_ordering(&o2);
        assert_ne!(c1.root, c2.root);
    }

    #[test]
    fn dependency_order_fields() {
        let d = DependencyOrder {
            transaction: tx(5),
            order_index: 3,
            dependencies_satisfied: true,
        };
        assert_eq!(d.transaction, tx(5));
        assert_eq!(d.order_index, 3);
        assert!(d.dependencies_satisfied);
    }

    #[test]
    fn causal_order_roots_and_transactions() {
        let co = CausalOrder {
            transactions: vec![tx(1), tx(2), tx(3)],
            causal_roots: vec![tx(1)],
        };
        assert_eq!(co.transactions.len(), 3);
        assert_eq!(co.causal_roots.len(), 1);
    }
}
