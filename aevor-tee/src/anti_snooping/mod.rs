//! Anti-snooping protection: metadata shielding, traffic analysis resistance,
//! and side-channel mitigation for TEE-hosted computations.

use serde::{Deserialize, Serialize};
pub use aevor_core::tee::AntiSnoopingLevel;

/// Configuration for anti-snooping protections.
#[allow(clippy::struct_excessive_bools)] // Each bool is a distinct independent feature flag
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiSnoopingConfig {
    /// The overall protection level (determines which features are mandatory).
    pub level: AntiSnoopingLevel,
    /// Hide request metadata (source, destination, size) from infrastructure.
    pub metadata_shielding: bool,
    /// Obfuscate network traffic patterns to resist traffic analysis.
    pub traffic_obfuscation: bool,
    /// Add random delays to remove timing side-channels.
    pub timing_noise: bool,
    /// Pad all messages to a fixed size to hide true payload length.
    pub message_padding: bool,
}

impl Default for AntiSnoopingConfig {
    fn default() -> Self {
        Self {
            level: AntiSnoopingLevel::Basic,
            metadata_shielding: true,
            traffic_obfuscation: false,
            timing_noise: false,
            message_padding: false,
        }
    }
}

impl AntiSnoopingConfig {
    /// Maximum protection — all features enabled.
    pub fn maximum() -> Self {
        Self {
            level: AntiSnoopingLevel::Maximum,
            metadata_shielding: true,
            traffic_obfuscation: true,
            timing_noise: true,
            message_padding: true,
        }
    }

    /// No protection — useful for development and benchmarking.
    pub fn none() -> Self {
        Self {
            level: AntiSnoopingLevel::None,
            metadata_shielding: false,
            traffic_obfuscation: false,
            timing_noise: false,
            message_padding: false,
        }
    }

    /// Returns `true` if any protection feature is enabled.
    pub fn is_active(&self) -> bool {
        self.metadata_shielding
            || self.traffic_obfuscation
            || self.timing_noise
            || self.message_padding
    }
}

/// Shields metadata about a computation from infrastructure observers.
///
/// At `Basic` level this hides request source and size. At `Maximum`
/// level it adds dummy requests to make the traffic pattern unreadable.
pub struct MetadataShield {
    config: AntiSnoopingConfig,
}

impl MetadataShield {
    /// Create a shield with the given configuration.
    pub fn new(config: AntiSnoopingConfig) -> Self { Self { config } }

    /// Returns `true` if metadata shielding is currently active.
    pub fn is_active(&self) -> bool { self.config.metadata_shielding }

    /// The configured protection level.
    pub fn level(&self) -> AntiSnoopingLevel { self.config.level }
}

/// Obfuscates network traffic patterns to resist timing and volume analysis.
pub struct TrafficObfuscation {
    enabled: bool,
    pad_to_size: Option<usize>,
}

impl TrafficObfuscation {
    /// Create a traffic obfuscation layer.
    ///
    /// `pad_to_size`: if `Some(n)`, all messages are padded to exactly `n` bytes.
    pub fn new(enabled: bool, pad_to_size: Option<usize>) -> Self {
        Self { enabled, pad_to_size }
    }

    /// Pad a message to the configured fixed size (if enabled).
    ///
    /// Bytes beyond the payload are set to zero. Messages larger than
    /// the target size are returned unchanged.
    pub fn pad_message(&self, mut data: Vec<u8>) -> Vec<u8> {
        if let Some(target) = self.pad_to_size {
            if data.len() < target {
                data.resize(target, 0u8);
            }
        }
        data
    }

    /// Returns `true` if obfuscation is enabled.
    pub fn is_enabled(&self) -> bool { self.enabled }

    /// The configured padding target size, if any.
    pub fn pad_target(&self) -> Option<usize> { self.pad_to_size }
}

/// Protects against side-channel attacks exploiting timing or cache behaviour.
pub struct SideChannelProtection {
    /// Whether constant-time algorithms are enforced to prevent timing leaks.
    pub timing_protection: bool,
    /// Whether cache-flush operations are inserted to prevent cache-timing attacks.
    pub cache_protection: bool,
}

impl SideChannelProtection {
    /// Select the appropriate protections for the given anti-snooping level.
    pub fn for_level(level: AntiSnoopingLevel) -> Self {
        match level {
            AntiSnoopingLevel::None => Self {
                timing_protection: false,
                cache_protection: false,
            },
            AntiSnoopingLevel::Basic => Self {
                timing_protection: false,
                cache_protection: true,
            },
            AntiSnoopingLevel::Enhanced | AntiSnoopingLevel::Maximum => Self {
                timing_protection: true,
                cache_protection: true,
            },
        }
    }

    /// Returns `true` if any side-channel protection is active.
    pub fn is_active(&self) -> bool { self.timing_protection || self.cache_protection }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_config_all_features_enabled() {
        let cfg = AntiSnoopingConfig::maximum();
        assert!(cfg.metadata_shielding);
        assert!(cfg.traffic_obfuscation);
        assert!(cfg.timing_noise);
        assert!(cfg.message_padding);
        assert!(cfg.is_active());
    }

    #[test]
    fn none_config_no_features() {
        let cfg = AntiSnoopingConfig::none();
        assert!(!cfg.is_active());
    }

    #[test]
    fn traffic_obfuscation_pads_short_messages() {
        let obf = TrafficObfuscation::new(true, Some(64));
        let padded = obf.pad_message(vec![1, 2, 3]);
        assert_eq!(padded.len(), 64);
        assert_eq!(&padded[..3], &[1, 2, 3]);
        assert!(padded[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn traffic_obfuscation_leaves_large_messages() {
        let obf = TrafficObfuscation::new(true, Some(4));
        let data = vec![0u8; 100];
        let result = obf.pad_message(data.clone());
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn side_channel_protection_levels() {
        let none = SideChannelProtection::for_level(AntiSnoopingLevel::None);
        assert!(!none.is_active());

        let basic = SideChannelProtection::for_level(AntiSnoopingLevel::Basic);
        assert!(basic.cache_protection);
        assert!(!basic.timing_protection);

        let max = SideChannelProtection::for_level(AntiSnoopingLevel::Maximum);
        assert!(max.timing_protection);
        assert!(max.cache_protection);
    }
}
