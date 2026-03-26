//! DAG performance metrics.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DagMetrics {
    pub total_transactions: u64,
    pub parallel_transactions: u64,
    pub serial_transactions: u64,
    pub avg_parallelism_factor: f64,
    pub conflict_rate: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierRate {
    pub blocks_per_round: f64,
    pub txs_per_second: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelismMetrics {
    pub lanes_used: usize,
    pub avg_lane_utilization: f64,
    pub max_concurrent_txs: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThroughputMeasurement {
    pub period_ms: u64,
    pub transactions: u64,
    pub tps: f64,
}

impl ThroughputMeasurement {
    pub fn compute(transactions: u64, period_ms: u64) -> Self {
        let tps = if period_ms == 0 { 0.0 } else { transactions as f64 / (period_ms as f64 / 1000.0) };
        Self { period_ms, transactions, tps }
    }
}
