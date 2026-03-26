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
pub struct ParallelResultSet { pub results: Vec<ExecutionResult>, pub all_consistent: bool }

pub struct ResultAggregator;
impl ResultAggregator {
    pub fn aggregate(results: Vec<ExecutionResult>) -> AggregatedReceipt {
        let total_gas: u64 = results.iter().map(|r| r.gas_consumed.as_u64()).sum();
        AggregatedReceipt {
            transaction_count: results.len(),
            total_gas: GasAmount::from_u64(total_gas),
            state_root: Hash256::ZERO,
        }
    }
}
