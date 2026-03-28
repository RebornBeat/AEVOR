//! DAG performance metrics.
//!
//! These types **observe and report** throughput — they never impose ceilings.
//! The Dual-DAG architecture is designed to scale with available computational
//! resources; any numbers seen here are measurements of what occurred, not limits
//! on what is possible.

use serde::{Deserialize, Serialize};

/// Aggregate metrics for a completed DAG execution batch.
///
/// All counters are observations — no field here constrains future throughput.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DagMetrics {
    pub total_transactions: u64,
    pub parallel_transactions: u64,
    pub serial_transactions: u64,
    pub avg_parallelism_factor: f64,
    pub conflict_rate: f64,
}

impl DagMetrics {
    /// Fraction of transactions that executed in parallel (0.0–1.0).
    ///
    /// A value approaching 1.0 indicates a nearly conflict-free workload
    /// where throughput scales linearly with available lanes.
    #[allow(clippy::cast_precision_loss)]
    pub fn parallel_fraction(&self) -> f64 {
        if self.total_transactions == 0 { return 0.0; }
        self.parallel_transactions as f64 / self.total_transactions as f64
    }
}

/// Observed block and transaction rate for a frontier advancement period.
///
/// `txs_per_second` reports actual throughput — AEVOR imposes no upper bound.
/// The Dual-DAG frontier can advance as fast as hardware and network allow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierRate {
    pub blocks_per_round: f64,
    /// Observed transactions per second. This is a measurement, not a limit.
    pub txs_per_second: f64,
}

/// Lane utilization metrics for a parallel execution batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelismMetrics {
    /// Number of execution lanes active during this batch.
    pub lanes_used: usize,
    /// Average fraction of capacity used per lane (0.0–1.0).
    pub avg_lane_utilization: f64,
    /// Peak number of transactions executing concurrently.
    /// Unbounded — grows with available processing resources.
    pub max_concurrent_txs: usize,
}

/// A throughput measurement over a fixed time window.
///
/// This struct records observed performance. There is no maximum `tps` value —
/// AEVOR's parallel architecture scales with computational resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThroughputMeasurement {
    pub period_ms: u64,
    pub transactions: u64,
    /// Observed transactions per second — a measurement, not a ceiling.
    pub tps: f64,
}

impl ThroughputMeasurement {
    #[allow(clippy::cast_precision_loss)] // TPS calculation: u64→f64 precision loss acceptable
    pub fn compute(transactions: u64, period_ms: u64) -> Self {
        let tps = if period_ms == 0 { 0.0 } else { transactions as f64 / (period_ms as f64 / 1000.0) };
        Self { period_ms, transactions, tps }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throughput_measurement_zero_period_returns_zero_tps() {
        let m = ThroughputMeasurement::compute(1_000, 0);
        assert_eq!(m.tps, 0.0);
    }

    #[test]
    fn throughput_measurement_computes_correctly() {
        // 1000 txs in 500ms = 2000 tps
        let m = ThroughputMeasurement::compute(1_000, 500);
        assert!((m.tps - 2000.0).abs() < 1e-6);
        assert_eq!(m.transactions, 1_000);
        assert_eq!(m.period_ms, 500);
    }

    #[test]
    fn throughput_measurement_has_no_upper_bound() {
        // Any throughput value should be representable — no ceiling
        let m = ThroughputMeasurement::compute(u64::MAX / 2, 1);
        assert!(m.tps > 0.0); // simply must not overflow or panic
    }

    #[test]
    fn dag_metrics_parallel_fraction_zero_for_empty() {
        let m = DagMetrics::default();
        assert_eq!(m.parallel_fraction(), 0.0);
    }

    #[test]
    fn dag_metrics_parallel_fraction_all_parallel() {
        let m = DagMetrics {
            total_transactions: 100,
            parallel_transactions: 100,
            serial_transactions: 0,
            avg_parallelism_factor: 100.0,
            conflict_rate: 0.0,
        };
        assert!((m.parallel_fraction() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn dag_metrics_parallel_fraction_mixed() {
        let m = DagMetrics {
            total_transactions: 100,
            parallel_transactions: 80,
            serial_transactions: 20,
            avg_parallelism_factor: 5.0,
            conflict_rate: 0.2,
        };
        assert!((m.parallel_fraction() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn parallelism_metrics_lanes_and_concurrent_txs_are_unbounded() {
        // max_concurrent_txs has type usize — no artificial ceiling
        let pm = ParallelismMetrics {
            lanes_used: usize::MAX / 2,
            avg_lane_utilization: 0.95,
            max_concurrent_txs: usize::MAX / 2,
        };
        assert!(pm.lanes_used > 0);
        assert!(pm.max_concurrent_txs > 0);
    }
}
