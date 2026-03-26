//! Economic primitive configuration.

use serde::{Deserialize, Serialize};

/// Economic primitive configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EconomicsConfig {
    /// Fee configuration.
    pub fee: FeeConfig,
    /// Staking configuration.
    pub staking: StakingConfig,
    /// Reward distribution configuration.
    pub reward: RewardConfig,
    /// Slashing configuration.
    pub slashing: SlashingConfig,
    /// Initial token supply in nanoAEVOR.
    pub initial_supply_nano: u128,
    /// Maximum total supply in nanoAEVOR (0 = uncapped).
    pub max_supply_nano: u128,
    /// Annual inflation rate in basis points (100 = 1%).
    pub annual_inflation_bps: u32,
}

impl Default for EconomicsConfig {
    fn default() -> Self {
        Self {
            fee: FeeConfig::default(),
            staking: StakingConfig::default(),
            reward: RewardConfig::default(),
            slashing: SlashingConfig::default(),
            initial_supply_nano: 1_000_000_000 * 1_000_000_000u128,
            max_supply_nano: 10_000_000_000 * 1_000_000_000u128,
            annual_inflation_bps: 500, // 5%
        }
    }
}

/// Fee calculation configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Whether fees are enabled (false = feeless, for permissioned subnets).
    pub enabled: bool,
    /// Base fee per gas unit in nanoAEVOR.
    pub base_fee_nano: u64,
    /// Minimum gas price in nanoAEVOR.
    pub min_gas_price_nano: u64,
    /// Block gas limit.
    pub block_gas_limit: u64,
    /// Target block utilization (basis points, 5000 = 50%).
    pub target_utilization_bps: u32,
    /// Fee adjustment factor per block (basis points).
    pub fee_adjustment_bps: u32,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_fee_nano: 1_000,
            min_gas_price_nano: 100,
            block_gas_limit: 30_000_000,
            target_utilization_bps: 5_000,
            fee_adjustment_bps: 125,
        }
    }
}

/// Staking parameter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum stake to become a validator in nanoAEVOR.
    pub min_validator_stake_nano: u128,
    /// Minimum delegation amount in nanoAEVOR.
    pub min_delegation_nano: u128,
    /// Maximum validators a single delegator can stake with.
    pub max_delegations_per_address: usize,
    /// Unbonding period in epochs.
    pub unbonding_epochs: u64,
    /// Whether liquid staking is supported.
    pub liquid_staking: bool,
}

impl Default for StakingConfig {
    fn default() -> Self {
        Self {
            min_validator_stake_nano: 100_000 * 1_000_000_000u128,
            min_delegation_nano: 1_000_000_000u128, // 1 AEVOR
            max_delegations_per_address: 16,
            unbonding_epochs: 14,
            liquid_staking: false,
        }
    }
}

/// Reward distribution configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Fraction of block rewards going to validators (basis points).
    pub validator_share_bps: u32,
    /// Fraction of block rewards going to TEE service providers (basis points).
    pub tee_service_share_bps: u32,
    /// Fraction of block rewards going to protocol treasury (basis points).
    pub treasury_share_bps: u32,
    /// Performance multiplier range (max, in basis points above 10000).
    pub max_performance_bonus_bps: u32,
    /// Reward distribution frequency in epochs.
    pub distribution_frequency_epochs: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            validator_share_bps: 7_000,  // 70%
            tee_service_share_bps: 2_000, // 20%
            treasury_share_bps: 1_000,   // 10%
            max_performance_bonus_bps: 10_000, // 2x max
            distribution_frequency_epochs: 1,
        }
    }
}

/// Slashing penalty configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Whether slashing is enabled.
    pub enabled: bool,
    /// Penalty for double-signing (basis points of stake).
    pub double_sign_penalty_bps: u32,
    /// Penalty for downtime (basis points of stake per epoch).
    pub downtime_penalty_bps: u32,
    /// Penalty for invalid TEE attestation (basis points of stake).
    pub invalid_attestation_penalty_bps: u32,
    /// Jail duration in epochs for double-signing.
    pub double_sign_jail_epochs: u64,
    /// Whether evidence can be submitted by any validator.
    pub open_evidence_submission: bool,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            double_sign_penalty_bps: 500,   // 5%
            downtime_penalty_bps: 10,        // 0.1% per epoch
            invalid_attestation_penalty_bps: 100, // 1%
            double_sign_jail_epochs: 100,
            open_evidence_submission: true,
        }
    }
}
