//! TEE operation metrics.
use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeMetrics { pub platform: TeePlatform, pub requests: u64, pub avg_latency_ms: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationLatency { pub platform: TeePlatform, pub avg_ms: f64, pub p99_ms: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionOverhead { pub platform: TeePlatform, pub overhead_pct: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformUtilization { pub platform: TeePlatform, pub utilization_pct: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeSummary { pub platforms: Vec<TeeMetrics>, pub total_requests: u64 }
