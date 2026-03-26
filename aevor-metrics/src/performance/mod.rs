//! Performance metrics: TPS, latency, parallelism.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThroughputMetric { pub period_ms: u64, pub transactions: u64, pub tps: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyMetric { pub p50_ms: f64, pub p95_ms: f64, pub p99_ms: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelismMetric { pub lanes: usize, pub utilization_pct: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasMetric { pub avg_per_tx: u64, pub total_block: u64, pub utilization_pct: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerformanceSummary { pub throughput: ThroughputMetric, pub latency: LatencyMetric, pub parallelism: ParallelismMetric }
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TpsReading { pub tps: f64, pub timestamp_round: u64 }
