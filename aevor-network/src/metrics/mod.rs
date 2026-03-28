//! Network performance metrics.
//!
//! All fields are observations — no field here imposes a throughput ceiling.

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

impl NetworkMetrics {
    /// Total bytes transferred (sent + received).
    pub fn total_bytes(&self) -> u64 { self.bytes_sent.saturating_add(self.bytes_recv) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_metrics_default_zero() {
        let m = NetworkMetrics::default();
        assert_eq!(m.connected_peers, 0);
        assert_eq!(m.bytes_sent, 0);
        assert_eq!(m.total_bytes(), 0);
    }

    #[test]
    fn total_bytes_sums_sent_and_recv() {
        let m = NetworkMetrics { bytes_sent: 1_000, bytes_recv: 2_000, ..Default::default() };
        assert_eq!(m.total_bytes(), 3_000);
    }

    #[test]
    fn total_bytes_saturates_on_overflow() {
        let m = NetworkMetrics { bytes_sent: u64::MAX, bytes_recv: 1, ..Default::default() };
        assert_eq!(m.total_bytes(), u64::MAX); // no panic, saturates
    }
}
