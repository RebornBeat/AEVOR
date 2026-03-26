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
