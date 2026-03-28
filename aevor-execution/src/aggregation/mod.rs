//! Parallel result aggregation.
//!
//! After the Dual-DAG executes transactions across parallel lanes, results are
//! aggregated here. Aggregation is unbounded — there is no artificial cap on
//! how many parallel results can be merged in a single batch.

use serde::{Deserialize, Serialize};
use aevor_core::execution::{ExecutionResult, StateChange};
use aevor_core::primitives::{GasAmount, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedReceipt { pub transaction_count: usize, pub total_gas: GasAmount, pub state_root: Hash256 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionSummary { pub receipts: Vec<AggregatedReceipt>, pub success_count: usize, pub failure_count: usize }

pub struct ConsistencyCheck;
impl ConsistencyCheck {
    pub fn check(results: &[ExecutionResult]) -> bool { results.iter().all(|r| r.success) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelResultSet {
    /// Execution results for each transaction in this parallel batch.
    pub results: Vec<ExecutionResult>,
    /// Whether all results are mutually consistent (no conflicting state changes).
    pub all_consistent: bool,
    /// Merged state changes from all consistent executions in this set.
    pub merged_changes: Vec<StateChange>,
}

impl ParallelResultSet {
    /// Collect all state changes from successful executions.
    pub fn successful_changes(&self) -> Vec<&StateChange> {
        self.merged_changes.iter().collect()
    }
}

pub struct ResultAggregator;
impl ResultAggregator {
    /// Aggregate a slice of execution results into a single receipt.
    pub fn aggregate(results: &[ExecutionResult]) -> AggregatedReceipt {
        let total_gas: u64 = results.iter().map(|r| r.gas_consumed.as_u64()).sum();
        AggregatedReceipt {
            transaction_count: results.len(),
            total_gas: GasAmount::from_u64(total_gas),
            state_root: Hash256::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::execution::{ExecutionLog, ExecutionResult};
    use aevor_core::primitives::GasAmount;

    fn success(gas: u64) -> ExecutionResult {
        ExecutionResult::success(GasAmount::from_u64(gas), vec![], ExecutionLog::default(), vec![])
    }

    fn failure(gas: u64) -> ExecutionResult {
        ExecutionResult::failure(GasAmount::from_u64(gas), "revert")
    }

    // ── ConsistencyCheck ────────────────────────────────────────────────

    #[test]
    fn consistency_check_all_successful() {
        let results = vec![success(1000), success(2000), success(500)];
        assert!(ConsistencyCheck::check(&results));
    }

    #[test]
    fn consistency_check_any_failure_returns_false() {
        let results = vec![success(1000), failure(500), success(2000)];
        assert!(!ConsistencyCheck::check(&results));
    }

    #[test]
    fn consistency_check_empty_set_is_consistent() {
        assert!(ConsistencyCheck::check(&[]));
    }

    // ── ResultAggregator ────────────────────────────────────────────────

    #[test]
    fn aggregator_sums_gas_correctly() {
        let results = vec![success(1_000), success(2_000), success(3_000)];
        let receipt = ResultAggregator::aggregate(&results);
        assert_eq!(receipt.transaction_count, 3);
        assert_eq!(receipt.total_gas.as_u64(), 6_000);
    }

    #[test]
    fn aggregator_empty_batch_is_zero() {
        let receipt = ResultAggregator::aggregate(&[]);
        assert_eq!(receipt.transaction_count, 0);
        assert_eq!(receipt.total_gas.as_u64(), 0);
    }

    #[test]
    fn aggregator_includes_failed_gas_in_total() {
        // Failed txs still consume gas up to their actual usage
        let results = vec![success(5_000), failure(1_000)];
        let receipt = ResultAggregator::aggregate(&results);
        assert_eq!(receipt.transaction_count, 2);
        assert_eq!(receipt.total_gas.as_u64(), 6_000);
    }

    // ── ParallelResultSet ────────────────────────────────────────────────

    #[test]
    fn parallel_result_set_successful_changes_from_merged() {
        let set = ParallelResultSet {
            results: vec![success(1_000)],
            all_consistent: true,
            merged_changes: vec![],
        };
        assert_eq!(set.successful_changes().len(), 0);
        assert!(set.all_consistent);
    }

    #[test]
    fn parallel_result_set_inconsistent_marked_correctly() {
        let set = ParallelResultSet {
            results: vec![success(1_000), success(2_000)],
            all_consistent: false, // conflict detected between lanes
            merged_changes: vec![],
        };
        assert!(!set.all_consistent);
    }

    // ── ExecutionSummary ─────────────────────────────────────────────────

    #[test]
    fn execution_summary_counts_match() {
        let summary = ExecutionSummary {
            receipts: vec![
                ResultAggregator::aggregate(&[success(1_000)]),
                ResultAggregator::aggregate(&[failure(500)]),
            ],
            success_count: 1,
            failure_count: 1,
        };
        assert_eq!(summary.success_count + summary.failure_count, 2);
        assert_eq!(summary.receipts.len(), 2);
    }
}
