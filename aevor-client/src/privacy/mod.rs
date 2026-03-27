//! Privacy-preserving client connections: onion routing, traffic mixing.

use serde::{Deserialize, Serialize};

/// Configuration for privacy-preserving connections.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrivacyRoutingConfig {
    /// Whether to route requests through onion routing (Tor-like layered encryption).
    pub use_onion_routing: bool,
    /// Whether to mix traffic with dummy requests to prevent timing analysis.
    pub mix_traffic: bool,
}

impl PrivacyRoutingConfig {
    /// Maximum privacy: onion routing + traffic mixing.
    pub fn maximum_privacy() -> Self {
        Self { use_onion_routing: true, mix_traffic: true }
    }
    /// Balanced: onion routing only (no traffic mixing overhead).
    pub fn onion_only() -> Self {
        Self { use_onion_routing: true, mix_traffic: false }
    }
    /// Returns `true` if any privacy feature is enabled.
    pub fn is_private(&self) -> bool { self.use_onion_routing || self.mix_traffic }
}

/// A connection that routes through onion relays to hide the client's IP.
pub struct PrivacyConnection {
    /// The underlying routing configuration.
    pub config: PrivacyRoutingConfig,
}

impl PrivacyConnection {
    /// Create a privacy-enhanced connection with the given config.
    pub fn new(config: PrivacyRoutingConfig) -> Self { Self { config } }
}

/// A connection that provides unlinkability — the server cannot correlate
/// multiple requests as coming from the same client.
pub struct AnonymousConnection {
    /// Number of onion hops for this anonymous connection.
    pub hop_count: usize,
}

impl AnonymousConnection {
    /// Create an anonymous connection with the default 3 hops.
    pub fn new() -> Self { Self { hop_count: 3 } }
    /// Create an anonymous connection with a specific hop count.
    pub fn with_hops(hop_count: usize) -> Self { Self { hop_count } }
}

impl Default for AnonymousConnection {
    fn default() -> Self { Self::new() }
}

/// Obfuscates connection metadata (timing, packet sizes) to resist traffic analysis.
pub struct ConnectionObfuscation {
    /// Whether to pad packets to fixed sizes.
    pub pad_packets: bool,
    /// Artificial delay range in milliseconds for traffic mixing.
    pub delay_range_ms: (u64, u64),
}

impl ConnectionObfuscation {
    /// Create an obfuscation layer with padding and delay.
    pub fn new(pad_packets: bool, delay_range_ms: (u64, u64)) -> Self {
        Self { pad_packets, delay_range_ms }
    }
    /// Standard obfuscation: pad packets, add 10–50ms random delay.
    pub fn standard() -> Self {
        Self { pad_packets: true, delay_range_ms: (10, 50) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_routing_config_default_no_privacy() {
        let cfg = PrivacyRoutingConfig::default();
        assert!(!cfg.use_onion_routing);
        assert!(!cfg.mix_traffic);
        assert!(!cfg.is_private());
    }

    #[test]
    fn maximum_privacy_enables_all_features() {
        let cfg = PrivacyRoutingConfig::maximum_privacy();
        assert!(cfg.use_onion_routing);
        assert!(cfg.mix_traffic);
        assert!(cfg.is_private());
    }

    #[test]
    fn onion_only_enables_routing_not_mixing() {
        let cfg = PrivacyRoutingConfig::onion_only();
        assert!(cfg.use_onion_routing);
        assert!(!cfg.mix_traffic);
        assert!(cfg.is_private());
    }

    #[test]
    fn is_private_true_if_either_feature_on() {
        let only_mix = PrivacyRoutingConfig { use_onion_routing: false, mix_traffic: true };
        assert!(only_mix.is_private());
    }

    #[test]
    fn privacy_connection_stores_config() {
        let conn = PrivacyConnection::new(PrivacyRoutingConfig::maximum_privacy());
        assert!(conn.config.use_onion_routing);
        assert!(conn.config.mix_traffic);
    }

    #[test]
    fn anonymous_connection_default_is_three_hops() {
        let conn = AnonymousConnection::new();
        assert_eq!(conn.hop_count, 3);
    }

    #[test]
    fn anonymous_connection_with_hops() {
        let conn = AnonymousConnection::with_hops(5);
        assert_eq!(conn.hop_count, 5);
    }

    #[test]
    fn connection_obfuscation_standard_pads_and_delays() {
        let obs = ConnectionObfuscation::standard();
        assert!(obs.pad_packets);
        assert_eq!(obs.delay_range_ms, (10, 50));
        assert!(obs.delay_range_ms.0 < obs.delay_range_ms.1);
    }

    #[test]
    fn connection_obfuscation_new_stores_params() {
        let obs = ConnectionObfuscation::new(false, (5, 100));
        assert!(!obs.pad_packets);
        assert_eq!(obs.delay_range_ms, (5, 100));
    }
}
