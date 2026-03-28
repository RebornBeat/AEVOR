//! Bandwidth management: rate limiting, shaping, and utilization tracking.
//!
//! All limits here are configurable per-node resource budgets — not network
//! throughput ceilings. Aggregate network throughput is unbounded.

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

impl BandwidthUtilization {
    /// Returns `true` if utilization is above 90% (high-utilization threshold).
    pub fn is_high(&self) -> bool { self.utilization_fraction > 0.90 }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_config_default_nonzero() {
        let cfg = RateLimiterConfig::default();
        assert!(cfg.max_bps > 0);
        assert!(cfg.burst_bytes > 0);
        assert!(cfg.burst_bytes < cfg.max_bps); // burst < 1 second of max
    }

    #[test]
    fn bandwidth_utilization_default_zero() {
        let u = BandwidthUtilization::default();
        assert_eq!(u.out_bps, 0);
        assert_eq!(u.utilization_fraction, 0.0);
        assert!(!u.is_high());
    }

    #[test]
    fn bandwidth_utilization_high_above_90_percent() {
        let u = BandwidthUtilization { utilization_fraction: 0.95, ..Default::default() };
        assert!(u.is_high());
    }

    #[test]
    fn bandwidth_utilization_not_high_at_90_percent() {
        let u = BandwidthUtilization { utilization_fraction: 0.90, ..Default::default() };
        assert!(!u.is_high()); // boundary: > 0.90 required
    }

    #[test]
    fn traffic_shaper_per_peer_can_differ_from_global() {
        let shaper = TrafficShaper {
            per_peer_config: RateLimiterConfig { max_bps: 10 * 1024 * 1024, burst_bytes: 1024 * 1024 },
            global_config: RateLimiterConfig::default(),
        };
        assert!(shaper.global_config.max_bps > shaper.per_peer_config.max_bps);
    }
}
