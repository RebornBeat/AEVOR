//! Network performance metrics.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NetworkMetrics {
    pub connected_peers: usize,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub avg_latency_ms: u32,
    pub block_propagation_ms: u32,
    pub tx_propagation_ms: u32,
}
