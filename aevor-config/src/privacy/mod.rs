//! Privacy capability defaults and cross-privacy coordination configuration.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::{PrivacyLevel, CrossPrivacyDisclosureMode};
use aevor_core::tee::AntiSnoopingLevel;

/// Privacy capability and policy configuration for the node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Default privacy level for new objects (if not specified by the application).
    pub default_level: DefaultPrivacyLevel,
    /// Selective disclosure configuration.
    pub selective_disclosure: SelectiveDisclosureConfig,
    /// Cross-privacy boundary coordination configuration.
    pub cross_privacy: CrossPrivacyConfig,
    /// Anti-snooping protection configuration.
    pub anti_snooping: AntiSnoopingConfig,
    /// Whether privacy features are enabled on this node.
    pub enabled: bool,
    /// Whether to enforce privacy policies strictly (reject policy violations).
    pub strict_enforcement: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            default_level: DefaultPrivacyLevel::default(),
            selective_disclosure: SelectiveDisclosureConfig::default(),
            cross_privacy: CrossPrivacyConfig::default(),
            anti_snooping: AntiSnoopingConfig::default(),
            enabled: true,
            strict_enforcement: true,
        }
    }
}

/// Default privacy level for new objects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefaultPrivacyLevel {
    /// The default level applied when no explicit level is specified.
    pub level: PrivacyLevel,
    /// Whether to inherit privacy level from calling context.
    pub inherit_from_context: bool,
    /// Whether to escalate to Private when TEE is available.
    pub escalate_with_tee: bool,
}

impl Default for DefaultPrivacyLevel {
    fn default() -> Self {
        Self {
            level: PrivacyLevel::Public,
            inherit_from_context: true,
            escalate_with_tee: false,
        }
    }
}

/// Selective disclosure configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosureConfig {
    /// Whether selective disclosure is enabled globally.
    pub enabled: bool,
    /// Whether to require ZK proofs for all selective disclosures.
    pub require_zk_proof: bool,
    /// Maximum number of disclosable fields per object.
    pub max_disclosable_fields: usize,
    /// Whether to cache disclosure proofs.
    pub cache_proofs: bool,
    /// Proof cache TTL in seconds.
    pub proof_cache_ttl_s: u64,
}

impl Default for SelectiveDisclosureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_zk_proof: false,
            max_disclosable_fields: 32,
            cache_proofs: true,
            proof_cache_ttl_s: 300,
        }
    }
}

/// Cross-privacy boundary coordination configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossPrivacyConfig {
    /// Whether cross-privacy operations are allowed.
    pub allowed: bool,
    /// Default disclosure mode for cross-privacy operations.
    pub default_disclosure_mode: CrossPrivacyDisclosureMode,
    /// Whether to require explicit authorization for boundary crossings.
    pub require_explicit_auth: bool,
    /// Whether to audit all cross-privacy operations.
    pub audit_crossings: bool,
}

impl Default for CrossPrivacyConfig {
    fn default() -> Self {
        Self {
            allowed: true,
            default_disclosure_mode: CrossPrivacyDisclosureMode::CommitmentOnly,
            require_explicit_auth: true,
            audit_crossings: true,
        }
    }
}

/// Anti-snooping protection configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiSnoopingConfig {
    /// Anti-snooping level for confidential operations.
    pub level: AntiSnoopingLevel,
    /// Whether to obfuscate network traffic patterns.
    pub traffic_obfuscation: bool,
    /// Whether to pad messages to uniform sizes.
    pub message_padding: bool,
    /// Whether to use dummy traffic for cover.
    pub cover_traffic: bool,
}

impl Default for AntiSnoopingConfig {
    fn default() -> Self {
        Self {
            level: AntiSnoopingLevel::Basic,
            traffic_obfuscation: false,
            message_padding: false,
            cover_traffic: false,
        }
    }
}
