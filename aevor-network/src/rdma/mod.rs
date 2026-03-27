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
