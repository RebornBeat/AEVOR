//! Network metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NetworkMetricSummary { pub peer_count: usize, pub avg_latency_ms: u32, pub bytes_per_sec: u64 }
