//! Pre-execution conflict analysis for the execution pipeline.
//!
//! AEVOR does NOT use speculative execution. Conflicts are detected by
//! `ConflictDetector` + `DependencyAnalyzer` **before** any transaction begins
//! execution. This module provides metrics and analysis types for tracking
//! the pre-execution rejection pipeline.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;

/// Result of pre-execution conflict analysis for a single transaction.
///
/// `accepted` means the transaction is safe to schedule for parallel execution.
/// `false` means it was rejected before execution due to a detected conflict —
/// no execution occurred and no state was modified.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictAnalysisResult {
    /// Whether the transaction was accepted (no pre-execution conflict).
    pub accepted: bool,
    /// The conflicting transaction, if any was identified.
    pub conflicting_tx: Option<TransactionHash>,
}

impl ConflictAnalysisResult {
    /// Create an accepted result.
    pub fn accepted() -> Self { Self { accepted: true, conflicting_tx: None } }
    /// Create a rejected result identifying the conflicting transaction.
    pub fn rejected(conflicting_tx: TransactionHash) -> Self {
        Self { accepted: false, conflicting_tx: Some(conflicting_tx) }
    }
}

/// Metrics for the pre-execution conflict analysis pipeline.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ConflictAnalysisMetrics {
    /// Total transactions analyzed.
    pub analyzed_count: u64,
    /// Total transactions accepted (no conflict).
    pub accepted_count: u64,
    /// Total transactions rejected (conflict detected before execution).
    pub rejected_count: u64,
}

impl ConflictAnalysisMetrics {
    /// Rejection rate as a fraction [0.0, 1.0].
    #[allow(clippy::cast_precision_loss)]
    pub fn rejection_rate(&self) -> f64 {
        if self.analyzed_count == 0 { 0.0 }
        else { self.rejected_count as f64 / self.analyzed_count as f64 }
    }
}

// Keep SpeculativeMetrics as a type alias for backward compatibility with any
// code that still references it — it now tracks conflict analysis, not speculation.
/// Metrics alias — now tracks pre-execution conflict analysis, not speculative execution.
pub type SpeculativeMetrics = ConflictAnalysisMetrics;

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn conflict_analysis_result_accepted() {
        let r = ConflictAnalysisResult::accepted();
        assert!(r.accepted);
        assert!(r.conflicting_tx.is_none());
    }

    #[test]
    fn conflict_analysis_result_rejected_stores_conflicting_tx() {
        let r = ConflictAnalysisResult::rejected(tx(5));
        assert!(!r.accepted);
        assert_eq!(r.conflicting_tx, Some(tx(5)));
    }

    #[test]
    fn metrics_default_zero() {
        let m = ConflictAnalysisMetrics::default();
        assert_eq!(m.analyzed_count, 0);
        assert_eq!(m.accepted_count, 0);
        assert_eq!(m.rejected_count, 0);
        assert_eq!(m.rejection_rate(), 0.0);
    }

    #[test]
    fn metrics_rejection_rate_calculation() {
        let m = ConflictAnalysisMetrics { analyzed_count: 10, accepted_count: 8, rejected_count: 2 };
        assert!((m.rejection_rate() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn speculative_metrics_alias_works() {
        // SpeculativeMetrics is now an alias for ConflictAnalysisMetrics
        let m = SpeculativeMetrics::default();
        assert_eq!(m.analyzed_count, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::storage::MerkleRoot;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn speculative_executor_add_and_count() {
        let mut exec = SpeculativeExecutor::new();
        exec.add(tx(1), vec![]);
        exec.add(tx(2), vec![]);
        assert_eq!(exec.pending_count(), 2);
    }

    #[test]
    fn speculative_executor_commit_all_drains_pending() {
        let mut exec = SpeculativeExecutor::default();
        exec.add(tx(1), vec![]);
        let changes = exec.commit_all().unwrap();
        assert_eq!(exec.pending_count(), 0);
        let _ = changes; // changes may be empty in stub
    }

    #[test]
    fn conflict_detection_result_no_conflict() {
        let r = ConflictDetectionResult { has_conflict: false, conflicting_tx: None };
        assert!(!r.has_conflict);
        assert!(r.conflicting_tx.is_none());
    }

    #[test]
    fn conflict_detection_result_with_conflict() {
        let r = ConflictDetectionResult { has_conflict: true, conflicting_tx: Some(tx(5)) };
        assert!(r.has_conflict);
        assert_eq!(r.conflicting_tx, Some(tx(5)));
    }

    #[test]
    fn speculative_context_stores_base_root() {
        let ctx = SpeculativeContext { base_root: MerkleRoot::EMPTY };
        assert_eq!(ctx.base_root, MerkleRoot::EMPTY);
    }

    #[test]
    fn commit_or_rollback_stores_decision() {
        let c = CommitOrRollback { commit: true, reason: "no conflicts".into() };
        assert!(c.commit);
        let r = CommitOrRollback { commit: false, reason: "write-write conflict".into() };
        assert!(!r.commit);
    }
}
