//! RDMA-style zero-copy block propagation.
//!
//! High-throughput block propagation between validators uses memory-mapped
//! transport to avoid kernel-space copies for large block payloads.

use serde::{Deserialize, Serialize};

/// Configuration for RDMA-style transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdmaConfig {
    /// Maximum transfer unit size in bytes.
    pub mtu: usize,
    /// Number of pre-allocated send buffers.
    pub send_buffer_count: usize,
    /// Number of pre-allocated receive buffers.
    pub recv_buffer_count: usize,
}

impl Default for RdmaConfig {
    fn default() -> Self {
        Self { mtu: 4096, send_buffer_count: 256, recv_buffer_count: 256 }
    }
}

/// A zero-copy scatter-gather I/O descriptor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScatterGatherEntry {
    /// Byte offset into the shared memory region.
    pub offset: u64,
    /// Length of this segment.
    pub length: u32,
}

/// Statistics for the RDMA transport layer.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RdmaStats {
    /// Total bytes transferred without kernel copy.
    pub zero_copy_bytes: u64,
    /// Number of completions processed.
    pub completions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdma_config_default_nonzero_mtu_and_buffers() {
        let cfg = RdmaConfig::default();
        assert!(cfg.mtu > 0);
        assert!(cfg.send_buffer_count > 0);
        assert!(cfg.recv_buffer_count > 0);
    }

    #[test]
    fn rdma_config_custom_values() {
        let cfg = RdmaConfig { mtu: 65536, send_buffer_count: 1024, recv_buffer_count: 1024 };
        assert_eq!(cfg.mtu, 65536);
        assert_eq!(cfg.send_buffer_count, 1024);
    }

    #[test]
    fn scatter_gather_entry_stores_offset_and_length() {
        let sg = ScatterGatherEntry { offset: 4096, length: 512 };
        assert_eq!(sg.offset, 4096);
        assert_eq!(sg.length, 512);
    }

    #[test]
    fn rdma_stats_default_zero() {
        let stats = RdmaStats::default();
        assert_eq!(stats.zero_copy_bytes, 0);
        assert_eq!(stats.completions, 0);
    }

    #[test]
    fn rdma_stats_accumulate() {
        let stats = RdmaStats { zero_copy_bytes: 1_000_000, completions: 42 };
        assert_eq!(stats.zero_copy_bytes, 1_000_000);
        assert_eq!(stats.completions, 42);
    }
}
