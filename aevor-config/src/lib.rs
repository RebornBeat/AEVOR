//! # AEVOR Config: Multi-Network Configuration Management
//!
//! `aevor-config` provides configuration primitives that enable AEVOR deployments across
//! permissionless public networks, permissioned enterprise subnets, and hybrid scenarios.
//! This crate strictly provides *capability configuration* — never embedding organizational
//! policies, business logic, or regulatory compliance rules that belong in application layers.
//!
//! ## Architectural Boundary
//!
//! Configuration here controls *what infrastructure can do*, not *how applications should
//! behave*. Network parameters, TEE platform preferences, privacy capability levels, and
//! consensus settings are all infrastructure concerns. Economic models, governance rules,
//! and compliance strategies are application concerns that this crate enables but never
//! implements.
//!
//! ## Cross-Platform Consistency
//!
//! All configuration types serialize identically across Intel SGX, AMD SEV, ARM TrustZone,
//! RISC-V Keystone, and AWS Nitro Enclaves, ensuring that configuration files are portable
//! across deployment environments without modification.
//!
//! ## Validation
//!
//! Every configuration struct implements validation that checks structural correctness and
//! internal consistency. Validation never enforces organizational policies — only technical
//! feasibility constraints.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Network configuration: type, topology, genesis, peer discovery.
pub mod network;

/// TEE platform configuration: platform selection, attestation settings, isolation levels.
pub mod tee;

/// Privacy capability configuration: default levels, selective disclosure, cross-privacy rules.
pub mod privacy;

/// Consensus parameter configuration: security thresholds, round timing, validator sets.
pub mod consensus;

/// Economic primitive configuration: fee schedules, staking parameters, reward curves.
pub mod economics;

/// Deployment configuration: network type selection, subnet parameters, bridge settings.
pub mod deployment;

/// Configuration validation: structural correctness checks without policy enforcement.
pub mod validation;

/// Built-in defaults for all supported deployment scenarios.
pub mod defaults;

/// Environment-based configuration loading (env vars, config files, CLI overrides).
pub mod loader;

// ============================================================
// PRELUDE
// ============================================================

/// Configuration prelude — import for immediate access to all configuration types.
///
/// ```rust
/// use aevor_config::prelude::*;
/// ```
pub mod prelude {
    pub use crate::network::{
        NetworkConfig, NetworkType, GenesisConfig, PeerDiscoveryConfig,
        TopologyConfig, SubnetConfig, BridgeConfig,
    };
    pub use crate::tee::{
        TeeConfig, TeeAttestationConfig, TeeIsolationConfig, PlatformPreference,
        AttestationMode, TeeServiceConfig,
    };
    pub use crate::privacy::{
        PrivacyConfig, DefaultPrivacyLevel, SelectiveDisclosureConfig,
        CrossPrivacyConfig, AntiSnoopingConfig,
    };
    pub use crate::consensus::{
        ConsensusConfig, SecurityLevelConfig, ValidatorSetConfig,
        FinalityConfig, RoundTimingConfig, AttestationConfig,
    };
    pub use crate::economics::{
        EconomicsConfig, FeeConfig, StakingConfig, RewardConfig, SlashingConfig,
    };
    pub use crate::deployment::{
        DeploymentConfig, DeploymentMode, SubnetDeploymentConfig,
        HybridDeploymentConfig, EnterpriseSubnetConfig,
    };
    pub use crate::validation::{ConfigValidation, ConfigValidationError, ValidationResult};
    pub use crate::defaults::{
        mainnet_defaults, testnet_defaults, devnet_defaults, enterprise_subnet_defaults,
    };
    pub use crate::loader::{ConfigLoader, ConfigSource, ConfigOverride};
    pub use crate::{AevorConfig, ConfigError, ConfigResult};
}

// ============================================================
// TOP-LEVEL CONFIG AGGREGATE
// ============================================================

use serde::{Deserialize, Serialize};

/// Complete AEVOR node configuration aggregating all subsystem configs.
///
/// This is the root configuration type loaded at node startup. All fields
/// have sensible defaults via `Default` / the `defaults` module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AevorConfig {
    /// Network identity and topology configuration.
    pub network: network::NetworkConfig,

    /// TEE platform and attestation configuration.
    pub tee: tee::TeeConfig,

    /// Privacy capability defaults and policies.
    pub privacy: privacy::PrivacyConfig,

    /// Consensus parameter configuration.
    pub consensus: consensus::ConsensusConfig,

    /// Economic primitive configuration.
    pub economics: economics::EconomicsConfig,

    /// Deployment mode and subnet configuration.
    pub deployment: deployment::DeploymentConfig,
}

impl AevorConfig {
    /// Validate all subsystem configurations for internal consistency.
    ///
    /// This checks structural and technical feasibility only — never
    /// organizational or policy correctness.
    pub fn validate(&self) -> ConfigResult<()> {
        validation::validate_full_config(self)
    }

    /// Load configuration from the given sources with optional overrides.
    pub fn load(sources: &[loader::ConfigSource]) -> ConfigResult<Self> {
        loader::ConfigLoader::new(sources).load()
    }
}

impl Default for AevorConfig {
    fn default() -> Self {
        defaults::mainnet_defaults()
    }
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors that can occur during configuration loading or validation.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required configuration field is missing.
    #[error("missing required configuration field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: String,
    },

    /// A configuration value is outside its valid range.
    #[error("configuration value out of range: {field} = {value}, expected {constraint}")]
    OutOfRange {
        /// Field name.
        field: String,
        /// Provided value as string.
        value: String,
        /// Constraint description.
        constraint: String,
    },

    /// Two configuration fields are mutually inconsistent.
    #[error("conflicting configuration: {description}")]
    Conflict {
        /// Human-readable description of the conflict.
        description: String,
    },

    /// Configuration file could not be read or parsed.
    #[error("configuration parse error: {0}")]
    ParseError(String),

    /// IO error while reading configuration source.
    #[error("configuration IO error: {0}")]
    IoError(String),

    /// Requested TEE platform is not available on this hardware.
    #[error("TEE platform not available: {platform}")]
    TeePlatformUnavailable {
        /// Platform name.
        platform: String,
    },
}

/// Convenience alias for configuration results.
pub type ConfigResult<T> = Result<T, ConfigError>;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let config = AevorConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn testnet_defaults_validate() {
        let config = defaults::testnet_defaults();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn devnet_defaults_validate() {
        let config = defaults::devnet_defaults();
        assert!(config.validate().is_ok());
    }
}
