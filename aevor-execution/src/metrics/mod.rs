//! Execution pipeline metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExecutionMetrics { pub total_executed: u64, pub success_rate: f64, pub avg_gas: u64, pub avg_latency_ms: f64 }
