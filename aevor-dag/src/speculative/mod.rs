//! Pre-execution conflict resolution for the Micro-DAG.
//!
//! AEVOR does NOT use speculative execution with rollback. Instead, the Micro-DAG
//! performs dependency analysis **before** any transaction begins execution. Transactions
//! that would conflict are **rejected at the scheduler** — no state is ever executed
//! speculatively and no committed state is ever unwound.
//!
//! This module provides the types used to track and report pre-execution conflict
//! analysis results, feeding into the scheduler's accept/reject decisions.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;

/// The outcome of pre-execution conflict analysis for a transaction.
///
/// The scheduler evaluates this before any execution begins. `Accepted` transactions
/// are safe to execute in parallel; `Rejected` transactions are returned to the sender.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreExecutionDecision {
    /// The transaction being evaluated.
    pub transaction: TransactionHash,
    /// Whether this transaction was accepted for execution.
    pub accepted: bool,
    /// Reason for rejection, if any. `None` for accepted transactions.
    pub rejection_reason: Option<String>,
}

impl PreExecutionDecision {
    /// Create an accepted decision.
    pub fn accept(transaction: TransactionHash) -> Self {
        Self { transaction, accepted: true, rejection_reason: None }
    }

    /// Create a rejected decision with a reason.
    pub fn reject(transaction: TransactionHash, reason: impl Into<String>) -> Self {
        Self { transaction, accepted: false, rejection_reason: Some(reason.into()) }
    }
}

/// A set of transactions that have been evaluated for pre-execution conflicts
/// and are ready for parallel execution — all accepted, none conflicting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictFreeSet {
    /// Transactions cleared for parallel execution.
    pub transactions: Vec<TransactionHash>,
}

impl ConflictFreeSet {
    /// Create a new conflict-free set.
    pub fn new(transactions: Vec<TransactionHash>) -> Self { Self { transactions } }
    /// Number of transactions cleared for parallel execution.
    pub fn len(&self) -> usize { self.transactions.len() }
    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool { self.transactions.is_empty() }
}

/// Batch of pre-execution decisions — accepts and rejections from one scheduling round.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PreExecutionBatch {
    /// Decisions made in this batch.
    pub decisions: Vec<PreExecutionDecision>,
}

impl PreExecutionBatch {
    /// Add a decision to this batch.
    pub fn push(&mut self, d: PreExecutionDecision) { self.decisions.push(d); }
    /// Number of accepted transactions in this batch.
    pub fn accepted_count(&self) -> usize { self.decisions.iter().filter(|d| d.accepted).count() }
    /// Number of rejected transactions in this batch.
    pub fn rejected_count(&self) -> usize { self.decisions.iter().filter(|d| !d.accepted).count() }
    /// Extract all accepted transactions as a conflict-free set.
    pub fn accepted_set(&self) -> ConflictFreeSet {
        ConflictFreeSet::new(
            self.decisions.iter().filter(|d| d.accepted).map(|d| d.transaction).collect()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn pre_execution_decision_accept() {
        let d = PreExecutionDecision::accept(tx(1));
        assert!(d.accepted);
        assert!(d.rejection_reason.is_none());
        assert_eq!(d.transaction, tx(1));
    }

    #[test]
    fn pre_execution_decision_reject_stores_reason() {
        let d = PreExecutionDecision::reject(tx(2), "write-write conflict on obj 0xAB");
        assert!(!d.accepted);
        assert!(d.rejection_reason.as_deref().unwrap().contains("write-write"));
    }

    #[test]
    fn conflict_free_set_len_and_is_empty() {
        let empty = ConflictFreeSet::new(vec![]);
        assert!(empty.is_empty());
        let set = ConflictFreeSet::new(vec![tx(1), tx(2)]);
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn pre_execution_batch_counts_accepts_and_rejects() {
        let mut batch = PreExecutionBatch::default();
        batch.push(PreExecutionDecision::accept(tx(1)));
        batch.push(PreExecutionDecision::accept(tx(2)));
        batch.push(PreExecutionDecision::reject(tx(3), "conflict"));
        assert_eq!(batch.accepted_count(), 2);
        assert_eq!(batch.rejected_count(), 1);
    }

    #[test]
    fn pre_execution_batch_accepted_set_contains_only_accepted() {
        let mut batch = PreExecutionBatch::default();
        batch.push(PreExecutionDecision::accept(tx(1)));
        batch.push(PreExecutionDecision::reject(tx(2), "conflict"));
        let set = batch.accepted_set();
        assert_eq!(set.len(), 1);
        assert_eq!(set.transactions[0], tx(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn pre_execution_decision_accept() {
        let d = PreExecutionDecision::accept(tx(1));
        assert!(d.accepted);
        assert!(d.rejection_reason.is_none());
        assert_eq!(d.transaction, tx(1));
    }

    #[test]
    fn pre_execution_decision_reject_stores_reason() {
        let d = PreExecutionDecision::reject(tx(2), "write-write conflict on obj 0xAB");
        assert!(!d.accepted);
        assert!(d.rejection_reason.as_deref().unwrap().contains("write-write"));
    }

    #[test]
    fn conflict_free_set_len_and_is_empty() {
        let empty = ConflictFreeSet::new(vec![]);
        assert!(empty.is_empty());
        let set = ConflictFreeSet::new(vec![tx(1), tx(2)]);
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn pre_execution_batch_counts_accepts_and_rejects() {
        let mut batch = PreExecutionBatch::default();
        batch.push(PreExecutionDecision::accept(tx(1)));
        batch.push(PreExecutionDecision::accept(tx(2)));
        batch.push(PreExecutionDecision::reject(tx(3), "conflict"));
        assert_eq!(batch.accepted_count(), 2);
        assert_eq!(batch.rejected_count(), 1);
    }

    #[test]
    fn pre_execution_batch_accepted_set_contains_only_accepted() {
        let mut batch = PreExecutionBatch::default();
        batch.push(PreExecutionDecision::accept(tx(1)));
        batch.push(PreExecutionDecision::reject(tx(2), "write-write conflict"));
        let set = batch.accepted_set();
        assert_eq!(set.len(), 1);
        assert_eq!(set.transactions[0], tx(1));
    }

    #[test]
    fn rejected_transaction_never_appears_in_accepted_set() {
        // Architectural invariant: rejection is permanent for this scheduling round.
        // The conflicting transaction never executed — no state was touched.
        let mut batch = PreExecutionBatch::default();
        batch.push(PreExecutionDecision::reject(tx(5), "pre-execution conflict"));
        let set = batch.accepted_set();
        assert!(set.is_empty());
        assert!(!set.transactions.contains(&tx(5)));
    }

    #[test]
    fn all_accepted_batch_is_fully_parallel() {
        let mut batch = PreExecutionBatch::default();
        for i in 0..10u8 { batch.push(PreExecutionDecision::accept(tx(i))); }
        assert_eq!(batch.accepted_count(), 10);
        assert_eq!(batch.rejected_count(), 0);
        assert_eq!(batch.accepted_set().len(), 10);
    }
}
