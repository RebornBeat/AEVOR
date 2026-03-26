//! Privacy-preserving client connections: onion routing, traffic mixing.

use serde::{Deserialize, Serialize};

/// Configuration for privacy-preserving connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyRoutingConfig {
    /// Whether to route requests through onion routing (Tor-like layered encryption).
    pub use_onion_routing: bool,
    /// Whether to mix traffic with dummy requests to prevent timing analysis.
    pub mix_traffic: bool,
}

impl Default for PrivacyRoutingConfig {
    fn default() -> Self {
        Self { use_onion_routing: false, mix_traffic: false }
    }
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
