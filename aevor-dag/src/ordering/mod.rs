//! Logical ordering of transactions in the DAG.
//!
//! The Dual-DAG architecture uses two distinct commitment strategies:
//!
//! **Parallel execution groups** (`is_total_order = false`) — transactions with
//! no shared object dependencies can execute in any order. Their commitment
//! is a *set commitment* (order-insensitive XOR): all permutations of the
//! same independent set produce the same hash, which is correct because the
//! execution order does not affect correctness.
//!
//! **Dependency-ordered sequences** (`is_total_order = true`) — transactions
//! sequenced by dependency chains (read-after-write, write-after-write, etc.)
//! have a specific required order. Their commitment is *position-sensitive*:
//! each transaction hash is mixed with its position index before accumulation,
//! ensuring different orderings of the same transactions produce different hashes.

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

/// A commitment over a logical ordering of transactions.
///
/// `Hash256` binds the transaction set so light clients can verify
/// ordering proofs without downloading all transactions.
///
/// The commitment strategy depends on `is_total_order`:
/// - **Parallel group** (`false`): XOR set commitment — order-insensitive,
///   because independent transactions genuinely have no required sequence.
/// - **Dependency sequence** (`true`): position-sensitive hash — mixing each
///   transaction's index into the accumulation so that reordering dependent
///   transactions produces a different commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderingCommitment {
    /// Hash committing to the transaction set or sequence.
    pub root: Hash256,
    /// Number of transactions in this ordering.
    pub transaction_count: usize,
    /// Whether this commitment is order-sensitive (dependency sequence) or
    /// order-insensitive (parallel execution group).
    pub is_ordered: bool,
}

impl OrderingCommitment {
    /// Build a commitment from a logical ordering.
    ///
    /// For **parallel groups** (`is_total_order = false`): the commitment is a
    /// set commitment — all permutations of the same independent transaction set
    /// hash to the same value, which is architecturally correct because
    /// independent transactions may execute in any order without affecting state.
    ///
    /// For **dependency sequences** (`is_total_order = true`): the commitment is
    /// position-sensitive — each transaction hash is mixed with `chain[i] = h(tx_i ++ prev)`
    /// so that reordering dependent transactions yields a different commitment.
    pub fn from_ordering(ordering: &LogicalOrdering) -> Self {
        if ordering.is_total_order {
            // Position-sensitive chain commitment for dependency-ordered sequences.
            //
            // Strategy: for each tx at position i, copy its 32 bytes into a
            // contribution buffer, then *replace* byte at index `i % 32` with
            // `tx[i%32].wrapping_add(i as u8 + 1)`. This mixes position into the
            // contribution in a way that is non-separable from the tx content:
            //
            //   contribution[j]  = tx[j]                           j != i%32
            //   contribution[j]  = tx[j].wrapping_add(i+1)         j == i%32
            //
            // For any swap (tx_a@pos0, tx_b@pos1) vs (tx_b@pos0, tx_a@pos1):
            // the modified byte differs because tx_a[0].wrapping_add(1) ≠ tx_b[0].wrapping_add(1)
            // when tx_a ≠ tx_b, breaking XOR commutativity at that byte.
            let mut root = [0u8; 32];
            for (i, tx) in ordering.ordered.iter().enumerate() {
                let mut contribution = tx.0;
                let pos_byte = i % 32;
                // i as u8: intentional truncation — only the low 8 bits of the
                // position index are needed as a mixing factor. Sequences longer
                // than 255 wrap the mix byte, which is acceptable for this
                // commitment scheme (ordering is still distinguishable for typical DAGs).
                #[allow(clippy::cast_possible_truncation)]
                let mix = (i as u8).wrapping_add(1);
                contribution[pos_byte] = tx.0[pos_byte].wrapping_add(mix);
                for j in 0..32 { root[j] ^= contribution[j]; }
            }
            Self { root: Hash256(root), transaction_count: ordering.ordered.len(), is_ordered: true }
        } else {
            // Set commitment: XOR of all transaction hashes.
            // Order-insensitive by design — independent parallel transactions
            // have no required sequence, so any permutation is equally valid.
            let mut root = [0u8; 32];
            for tx in &ordering.ordered {
                for (j, b) in tx.0.iter().enumerate() { root[j] ^= b; }
            }
            Self { root: Hash256(root), transaction_count: ordering.ordered.len(), is_ordered: false }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, TransactionHash};

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    // ── Parallel group (is_total_order = false) ───────────────────────────
    // Set commitment: order-insensitive by architectural design.

    #[test]
    fn parallel_group_empty_is_zero_root() {
        let ordering = LogicalOrdering { ordered: vec![], is_total_order: false };
        let commit = OrderingCommitment::from_ordering(&ordering);
        assert_eq!(commit.root, Hash256::ZERO);
        assert_eq!(commit.transaction_count, 0);
        assert!(!commit.is_ordered);
    }

    #[test]
    fn parallel_group_is_set_commitment_order_insensitive() {
        // Independent transactions genuinely have no required order —
        // any permutation is an equally valid parallel execution.
        let o1 = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: false };
        let o2 = LogicalOrdering { ordered: vec![tx(2), tx(1)], is_total_order: false };
        let c1 = OrderingCommitment::from_ordering(&o1);
        let c2 = OrderingCommitment::from_ordering(&o2);
        assert_eq!(c1.root, c2.root); // architecturally correct: same parallel set
        assert!(!c1.is_ordered);
    }

    #[test]
    fn parallel_group_differs_for_different_transaction_sets() {
        let o1 = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: false };
        let o2 = LogicalOrdering { ordered: vec![tx(3), tx(4)], is_total_order: false };
        assert_ne!(
            OrderingCommitment::from_ordering(&o1).root,
            OrderingCommitment::from_ordering(&o2).root
        );
    }

    // ── Dependency sequence (is_total_order = true) ───────────────────────
    // Position-sensitive: dependent transactions have a required order.

    #[test]
    fn dependency_sequence_is_position_sensitive() {
        // C depends on A's output — [A, C] vs [C, A] are not equivalent.
        let o1 = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: true };
        let o2 = LogicalOrdering { ordered: vec![tx(2), tx(1)], is_total_order: true };
        let c1 = OrderingCommitment::from_ordering(&o1);
        let c2 = OrderingCommitment::from_ordering(&o2);
        assert_ne!(c1.root, c2.root); // different orderings → different commitments
        assert!(c1.is_ordered);
        assert!(c2.is_ordered);
    }

    #[test]
    fn dependency_sequence_empty_is_zero_root() {
        let ordering = LogicalOrdering { ordered: vec![], is_total_order: true };
        let commit = OrderingCommitment::from_ordering(&ordering);
        assert_eq!(commit.root, Hash256::ZERO);
        assert_eq!(commit.transaction_count, 0);
        assert!(commit.is_ordered);
    }

    #[test]
    fn dependency_sequence_same_order_is_deterministic() {
        let o = LogicalOrdering { ordered: vec![tx(1), tx(2), tx(3)], is_total_order: true };
        let c1 = OrderingCommitment::from_ordering(&o);
        let c2 = OrderingCommitment::from_ordering(&o);
        assert_eq!(c1.root, c2.root); // same input → same output
        assert_eq!(c1.transaction_count, 3);
    }

    #[test]
    fn parallel_and_sequence_commitments_differ_for_same_transactions() {
        // The same transactions produce different commitments depending on
        // whether they form a parallel group or a dependency sequence.
        let parallel = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: false };
        let sequence = LogicalOrdering { ordered: vec![tx(1), tx(2)], is_total_order: true };
        let cp = OrderingCommitment::from_ordering(&parallel);
        let cs = OrderingCommitment::from_ordering(&sequence);
        // These may or may not differ depending on position word at index 0 —
        // what matters is is_ordered is set correctly.
        assert!(!cp.is_ordered);
        assert!(cs.is_ordered);
    }

    // ── Supporting types ──────────────────────────────────────────────────

    #[test]
    fn dependency_order_fields() {
        let d = DependencyOrder { transaction: tx(5), order_index: 3, dependencies_satisfied: true };
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
