//! Consensus parameter configuration.

use serde::{Deserialize, Serialize};
use aevor_core::consensus::SecurityLevel;

/// Consensus parameter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Security level configuration per operation type.
    pub security_levels: SecurityLevelConfig,
    /// Validator set management configuration.
    pub validator_set: ValidatorSetConfig,
    /// Finality configuration.
    pub finality: FinalityConfig,
    /// Round timing configuration.
    pub round_timing: RoundTimingConfig,
    /// Attestation configuration.
    pub attestation: AttestationConfig,
    /// Minimum stake required to become a validator in nanoAEVOR.
    pub min_validator_stake: u128,
    /// Maximum number of validators in the active set.
    pub max_validators: usize,
    /// Number of blocks per epoch.
    pub blocks_per_epoch: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            security_levels: SecurityLevelConfig::default(),
            validator_set: ValidatorSetConfig::default(),
            finality: FinalityConfig::default(),
            round_timing: RoundTimingConfig::default(),
            attestation: AttestationConfig::default(),
            min_validator_stake: 100_000 * 1_000_000_000u128, // 100,000 AEVOR
            max_validators: 256,
            blocks_per_epoch: 10_000,
        }
    }
}

/// Security level thresholds and timing configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityLevelConfig {
    /// Default security level for standard transactions.
    pub default_level: SecurityLevel,
    /// Security level for governance operations.
    pub governance_level: SecurityLevel,
    /// Security level for bridge operations.
    pub bridge_level: SecurityLevel,
    /// Security level for validator operations.
    pub validator_level: SecurityLevel,
    /// Whether to allow per-transaction security level requests.
    pub allow_custom_levels: bool,
}

impl Default for SecurityLevelConfig {
    fn default() -> Self {
        Self {
            default_level: SecurityLevel::Basic,
            governance_level: SecurityLevel::Full,
            bridge_level: SecurityLevel::Strong,
            validator_level: SecurityLevel::Strong,
            allow_custom_levels: true,
        }
    }
}

/// Validator set management configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSetConfig {
    /// Whether the validator set can change dynamically.
    pub dynamic_set: bool,
    /// Epochs of notice required to join the validator set.
    pub join_notice_epochs: u64,
    /// Epochs of notice required to leave the validator set.
    pub leave_notice_epochs: u64,
    /// Unbonding period in epochs after unstaking.
    pub unbonding_epochs: u64,
    /// Whether to weight validators by stake.
    pub stake_weighted: bool,
}

impl Default for ValidatorSetConfig {
    fn default() -> Self {
        Self {
            dynamic_set: true,
            join_notice_epochs: 1,
            leave_notice_epochs: 1,
            unbonding_epochs: 14,
            stake_weighted: true,
        }
    }
}

/// Finality achievement configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Whether progressive finality (multi-level) is enabled.
    pub progressive_finality: bool,
    /// Timeout for Minimal finality in milliseconds.
    pub minimal_timeout_ms: u64,
    /// Timeout for Basic finality in milliseconds.
    pub basic_timeout_ms: u64,
    /// Timeout for Strong finality in milliseconds.
    pub strong_timeout_ms: u64,
    /// Timeout for Full finality in milliseconds.
    pub full_timeout_ms: u64,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            progressive_finality: true,
            minimal_timeout_ms: 50,
            basic_timeout_ms: 200,
            strong_timeout_ms: 800,
            full_timeout_ms: 1_000,
        }
    }
}

/// Consensus round timing configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundTimingConfig {
    /// Maximum time to wait for block proposals in milliseconds.
    pub proposal_timeout_ms: u64,
    /// Maximum time to wait for votes in milliseconds.
    pub vote_timeout_ms: u64,
    /// Maximum time for a complete consensus round in milliseconds.
    pub round_timeout_ms: u64,
    /// Number of rounds before switching to a new proposer.
    pub proposer_rotation_rounds: u64,
}

impl Default for RoundTimingConfig {
    fn default() -> Self {
        Self {
            proposal_timeout_ms: 100,
            vote_timeout_ms: 200,
            round_timeout_ms: 500,
            proposer_rotation_rounds: 1,
        }
    }
}

/// TEE attestation collection configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Whether TEE attestation is required for block finality.
    pub required_for_finality: bool,
    /// Minimum number of TEE attestations required.
    pub min_attestations: usize,
    /// Whether to collect attestations in parallel.
    pub parallel_collection: bool,
    /// Attestation collection timeout in milliseconds.
    pub collection_timeout_ms: u64,
    /// Whether to aggregate attestations into a single proof.
    pub aggregate_attestations: bool,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            required_for_finality: true,
            min_attestations: 1,
            parallel_collection: true,
            collection_timeout_ms: 500,
            aggregate_attestations: true,
        }
    }
}
