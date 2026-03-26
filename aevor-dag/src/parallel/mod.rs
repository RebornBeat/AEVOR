//! Parallel execution lane assignment from DAG analysis.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;
use aevor_core::execution::ExecutionLane;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelLane {
    pub lane: ExecutionLane,
    pub transactions: Vec<TransactionHash>,
    pub dependencies_on_lanes: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaneAssignment {
    pub transaction: TransactionHash,
    pub lane: ExecutionLane,
}

pub struct WorkloadDistributor;

impl WorkloadDistributor {
    pub fn distribute(
        transactions: Vec<TransactionHash>,
        lane_count: usize,
    ) -> Vec<ParallelLane> {
        let per_lane = (transactions.len() + lane_count - 1) / lane_count;
        transactions
            .chunks(per_lane.max(1))
            .enumerate()
            .map(|(i, chunk)| ParallelLane {
                lane: ExecutionLane::new(i as u32),
                transactions: chunk.to_vec(),
                dependencies_on_lanes: Vec::new(),
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelismFactor {
    pub total_transactions: usize,
    pub parallel_transactions: usize,
    pub factor: f64,
}

impl ParallelismFactor {
    pub fn compute(total: usize, serial: usize) -> Self {
        let parallel = total.saturating_sub(serial);
        let factor = if total == 0 { 1.0 } else { 1.0 + parallel as f64 / total as f64 };
        Self { total_transactions: total, parallel_transactions: parallel, factor }
    }
}

pub struct ConcurrencyEstimator;

impl ConcurrencyEstimator {
    pub fn estimate(dag: &crate::micro_dag::MicroDag) -> usize {
        dag.root_entries().len().max(1)
    }
}
