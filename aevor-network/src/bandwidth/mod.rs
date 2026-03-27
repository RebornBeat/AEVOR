//! Bandwidth management: rate limiting, shaping, and utilization tracking.

use serde::{Deserialize, Serialize};

/// Current bandwidth utilization snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BandwidthUtilization {
    /// Outbound bytes per second.
    pub out_bps: u64,
    /// Inbound bytes per second.
    pub in_bps: u64,
    /// Peak outbound observed.
    pub peak_out_bps: u64,
    /// Utilization as a fraction of capacity (0.0–1.0).
    pub utilization_fraction: f64,
}

/// Token-bucket rate limiter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    /// Maximum bytes per second allowed.
    pub max_bps: u64,
    /// Burst allowance in bytes.
    pub burst_bytes: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self { max_bps: 100 * 1024 * 1024, burst_bytes: 10 * 1024 * 1024 }
    }
}

/// Traffic shaper for outbound connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficShaper {
    /// Per-peer rate limit configuration.
    pub per_peer_config: RateLimiterConfig,
    /// Global rate limit across all peers.
    pub global_config: RateLimiterConfig,
}
