//! Parallel result aggregation.

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
