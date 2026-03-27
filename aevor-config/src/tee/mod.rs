//! TEE platform and attestation configuration.

use serde::{Deserialize, Serialize};
use aevor_core::tee::{AntiSnoopingLevel, TeePlatform, TeeServiceType};

/// TEE platform and attestation configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeConfig {
    /// Platform selection preference.
    pub platform_preference: PlatformPreference,
    /// Attestation configuration.
    pub attestation: TeeAttestationConfig,
    /// Isolation configuration.
    pub isolation: TeeIsolationConfig,
    /// TEE service offering configuration.
    pub services: Vec<TeeServiceConfig>,
    /// Whether TEE is required for validator operation.
    pub required_for_validator: bool,
    /// Whether to fail startup if TEE is unavailable.
    pub fail_if_unavailable: bool,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            platform_preference: PlatformPreference::Auto,
            attestation: TeeAttestationConfig::default(),
            isolation: TeeIsolationConfig::default(),
            services: Vec::new(),
            required_for_validator: true,
            fail_if_unavailable: false,
        }
    }
}

/// TEE platform selection preference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PlatformPreference {
    /// Automatically select the best available platform.
    #[default]
    Auto,
    /// Prefer a specific platform.
    Prefer(TeePlatform),
    /// Require a specific platform.
    Require(TeePlatform),
    /// Use any available platform.
    Any,
}

/// TEE attestation configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeAttestationConfig {
    /// Attestation mode.
    pub mode: AttestationMode,
    /// Attestation service URL (for DCAP or similar).
    pub service_url: Option<String>,
    /// Whether to require production mode attestation.
    pub require_production: bool,
    /// Minimum security version number.
    pub min_svn: u32,
    /// Attestation cache TTL in seconds.
    pub cache_ttl_s: u64,
    /// Whether to verify attestations from all participating validators.
    pub verify_peer_attestations: bool,
}

impl Default for TeeAttestationConfig {
    fn default() -> Self {
        Self {
            mode: AttestationMode::Local,
            service_url: None,
            require_production: false, // False for dev/test
            min_svn: 0,
            cache_ttl_s: 3600,
            verify_peer_attestations: true,
        }
    }
}

/// How TEE attestations are generated and verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttestationMode {
    /// Generate and verify locally (requires hardware TEE).
    #[default]
    Local,
    /// Use a remote attestation service.
    Remote,
    /// Simulation mode (for development — not production).
    Simulation,
    /// Multi-TEE cross-platform attestation.
    CrossPlatform,
}

/// TEE memory isolation configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeIsolationConfig {
    /// Anti-snooping level.
    pub anti_snooping_level: AntiSnoopingLevel,
    /// Maximum memory allocated to TEE in bytes.
    pub max_memory_bytes: usize,
    /// Whether to use encrypted memory.
    pub use_encrypted_memory: bool,
    /// Whether to protect against timing side-channels.
    pub timing_protection: bool,
}

impl Default for TeeIsolationConfig {
    fn default() -> Self {
        Self {
            anti_snooping_level: AntiSnoopingLevel::Basic,
            max_memory_bytes: 256 * 1024 * 1024,
            use_encrypted_memory: true,
            timing_protection: false,
        }
    }
}

/// Configuration for a TEE service this node offers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeServiceConfig {
    /// Type of service offered.
    pub service_type: TeeServiceType,
    /// Maximum concurrent service requests.
    pub max_concurrent: usize,
    /// Allocated memory for this service in bytes.
    pub memory_bytes: usize,
    /// Price per request in nanoAEVOR.
    pub price_per_request: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::tee::{TeePlatform, TeeServiceType};

    #[test]
    fn tee_config_default_required_for_validator_not_fail_if_unavailable() {
        let cfg = TeeConfig::default();
        assert!(cfg.required_for_validator);
        assert!(!cfg.fail_if_unavailable);
        assert!(cfg.services.is_empty());
        assert_eq!(cfg.platform_preference, PlatformPreference::Auto);
    }

    #[test]
    fn platform_preference_default_is_auto() {
        let p = PlatformPreference::default();
        assert_eq!(p, PlatformPreference::Auto);
    }

    #[test]
    fn platform_preference_prefer_stores_platform() {
        let p = PlatformPreference::Prefer(TeePlatform::IntelSgx);
        assert_eq!(p, PlatformPreference::Prefer(TeePlatform::IntelSgx));
        assert_ne!(p, PlatformPreference::Auto);
    }

    #[test]
    fn attestation_config_default_is_local_no_production() {
        let cfg = TeeAttestationConfig::default();
        assert_eq!(cfg.mode, AttestationMode::Local);
        assert!(!cfg.require_production);
        assert!(cfg.service_url.is_none());
        assert!(cfg.verify_peer_attestations);
        assert_eq!(cfg.min_svn, 0);
    }

    #[test]
    fn attestation_mode_simulation_is_not_local() {
        assert_ne!(AttestationMode::Simulation, AttestationMode::Local);
        assert_ne!(AttestationMode::Remote, AttestationMode::CrossPlatform);
    }

    #[test]
    fn isolation_config_default_uses_encrypted_memory() {
        let cfg = TeeIsolationConfig::default();
        assert!(cfg.use_encrypted_memory);
        assert!(cfg.max_memory_bytes > 0);
        assert!(!cfg.timing_protection);
    }

    #[test]
    fn tee_service_config_stores_all_fields() {
        let svc = TeeServiceConfig {
            service_type: TeeServiceType::Compute,
            max_concurrent: 8,
            memory_bytes: 64 * 1024 * 1024,
            price_per_request: 1_000_000,
        };
        assert!(matches!(svc.service_type, TeeServiceType::Compute));
        assert_eq!(svc.max_concurrent, 8);
        assert_eq!(svc.price_per_request, 1_000_000);
    }
}
