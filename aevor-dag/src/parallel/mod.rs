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
        transactions: &[TransactionHash],
        lane_count: usize,
    ) -> Vec<ParallelLane> {
        let per_lane = transactions.len().div_ceil(lane_count);
        transactions
            .chunks(per_lane.max(1))
            .enumerate()
            .map(|(i, chunk)| ParallelLane {
                lane: ExecutionLane(u32::try_from(i).unwrap_or(u32::MAX)),
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
    #[allow(clippy::cast_precision_loss)] // parallelism ratio: precision loss acceptable
    pub fn compute(total: usize, serial: usize) -> Self {
        let parallel = total.saturating_sub(serial);
        let factor = if total == 0 { 1.0 } else { 1.0 + parallel as f64 / total as f64 };
        Self { total_transactions: total, parallel_transactions: parallel, factor }
    }
}

/// Estimates the minimum available concurrency for a Micro-DAG batch.
///
/// Returns the number of root entries — transactions that can start executing
/// immediately with no predecessors. This is a lower bound on achievable
/// parallelism: deeper parallel groups within the DAG provide additional
/// concurrency that is not counted here. The true parallelism scales with
/// the size of independent transaction sets, unbounded by architecture.
pub struct ConcurrencyEstimator;

impl ConcurrencyEstimator {
    /// Minimum concurrency: root entries (no incoming dependencies).
    pub fn estimate(dag: &crate::micro_dag::MicroDag) -> usize {
        dag.root_entries().len().max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, TransactionHash};

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn distribute_single_lane_gets_all_transactions() {
        let txs = vec![tx(1), tx(2), tx(3)];
        let lanes = WorkloadDistributor::distribute(&txs, 1);
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0].transactions.len(), 3);
        assert_eq!(lanes[0].lane.id(), 0);
    }

    #[test]
    fn distribute_even_split_across_lanes() {
        let txs: Vec<TransactionHash> = (1..=4).map(tx).collect();
        let lanes = WorkloadDistributor::distribute(&txs, 2);
        assert_eq!(lanes.len(), 2);
        assert_eq!(lanes[0].transactions.len(), 2);
        assert_eq!(lanes[1].transactions.len(), 2);
        assert_eq!(lanes[0].lane.id(), 0);
        assert_eq!(lanes[1].lane.id(), 1);
    }

    #[test]
    fn distribute_more_lanes_than_transactions() {
        let txs = vec![tx(1), tx(2)];
        let lanes = WorkloadDistributor::distribute(&txs, 5);
        // Each tx goes to its own lane; only 2 lanes produced
        assert_eq!(lanes.len(), 2);
        for lane in &lanes {
            assert_eq!(lane.transactions.len(), 1);
        }
    }

    #[test]
    fn distribute_preserves_all_transactions() {
        let txs: Vec<TransactionHash> = (0..=9).map(tx).collect();
        let lanes = WorkloadDistributor::distribute(&txs, 3);
        let total: usize = lanes.iter().map(|l| l.transactions.len()).sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn distribute_no_dependencies_initially() {
        let txs = vec![tx(1), tx(2)];
        let lanes = WorkloadDistributor::distribute(&txs, 2);
        assert!(lanes.iter().all(|l| l.dependencies_on_lanes.is_empty()));
    }

    #[test]
    fn parallelism_factor_all_parallel() {
        // 0 serial transactions → factor = 1.0 + n/n = 2.0
        let pf = ParallelismFactor::compute(10, 0);
        assert_eq!(pf.parallel_transactions, 10);
        assert!((pf.factor - 2.0).abs() < 1e-9);
    }

    #[test]
    fn parallelism_factor_all_serial() {
        // All 10 serial → 0 parallel → factor = 1.0 + 0/10 = 1.0
        let pf = ParallelismFactor::compute(10, 10);
        assert_eq!(pf.parallel_transactions, 0);
        assert!((pf.factor - 1.0).abs() < 1e-9);
    }

    #[test]
    fn parallelism_factor_zero_total_returns_one() {
        let pf = ParallelismFactor::compute(0, 0);
        assert!((pf.factor - 1.0).abs() < 1e-9);
    }
}
