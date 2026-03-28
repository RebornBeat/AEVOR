//! # Economic Primitives
//!
//! Infrastructure-level economic types: balances, fees, stakes, rewards,
//! and fee policies. These are primitives — applications implement
//! specific economic models using these as building blocks.

use serde::{Deserialize, Serialize};
use crate::primitives::{Address, Amount, EpochNumber, ValidatorId, ValidatorWeight};

// ============================================================
// BALANCE
// ============================================================

/// An account balance record with owner attribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Address that owns this balance.
    pub owner: Address,
    /// Current balance in nanoAEVOR.
    pub amount: Amount,
    /// Nonce preventing replay attacks on balance operations.
    pub nonce: u64,
    /// Block height of last balance change.
    pub last_updated_height: u64,
}

impl Balance {
    /// Create a zero balance for an address.
    pub fn zero(owner: Address) -> Self {
        Self {
            owner,
            amount: Amount::ZERO,
            nonce: 0,
            last_updated_height: 0,
        }
    }

    /// Returns `true` if the balance can cover `amount`.
    pub fn can_afford(&self, amount: Amount) -> bool {
        self.amount >= amount
    }

    /// Attempt to subtract `amount` from the balance.
    /// Returns `None` if the balance is insufficient.
    pub fn debit(&mut self, amount: Amount) -> Option<Amount> {
        self.amount = self.amount.checked_sub(amount)?;
        self.nonce += 1;
        Some(amount)
    }

    /// Add `amount` to the balance.
    /// Returns `None` on overflow.
    pub fn credit(&mut self, amount: Amount) -> Option<Amount> {
        self.amount = self.amount.checked_add(amount)?;
        Some(amount)
    }
}

// ============================================================
// FEE
// ============================================================

/// A transaction fee specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    /// Maximum fee the user is willing to pay (gas limit × gas price cap).
    pub max_fee: Amount,
    /// Actual fee paid (computed from gas used × effective gas price).
    pub paid_fee: Amount,
    /// Gas limit for this transaction.
    pub gas_limit: crate::primitives::GasAmount,
    /// Maximum gas price the user accepts.
    pub max_gas_price: crate::primitives::GasPrice,
}

impl Fee {
    /// Create a fee specification with the given limits.
    pub fn new(
        gas_limit: crate::primitives::GasAmount,
        max_gas_price: crate::primitives::GasPrice,
    ) -> Self {
        let max_fee = max_gas_price.total_fee(gas_limit).unwrap_or(Amount::ZERO);
        Self {
            max_fee,
            paid_fee: Amount::ZERO,
            gas_limit,
            max_gas_price,
        }
    }

    /// Create a fee-free specification (for permissioned subnets with feeless operation).
    pub fn free() -> Self {
        Self {
            max_fee: Amount::ZERO,
            paid_fee: Amount::ZERO,
            gas_limit: crate::primitives::GasAmount::from_u64(u64::MAX),
            max_gas_price: crate::primitives::GasPrice::ZERO,
        }
    }

    /// Returns `true` if this is a zero-fee (free) transaction.
    pub fn is_free(&self) -> bool {
        self.max_gas_price == crate::primitives::GasPrice::ZERO
    }
}

// ============================================================
// FEE POLICY
// ============================================================

/// Fee policy for a network or subnet.
///
/// Determines how transaction fees are calculated and distributed.
/// This is an infrastructure primitive — specific fee models are
/// implemented as policies in higher-level crates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeePolicy {
    /// No fees — for permissioned subnets.
    Free,

    /// Dynamic market-based fees (EIP-1559 style).
    MarketBased {
        /// Current base fee in nanoAEVOR per gas unit.
        base_fee: crate::primitives::GasPrice,
        /// Maximum fee multiplier above base fee.
        max_multiplier: u32,
    },

    /// Fixed fee schedule — specific operation types have fixed costs.
    Fixed {
        /// Transfer fee in nanoAEVOR.
        transfer_fee: Amount,
        /// Smart contract invocation fee per gas unit.
        per_gas_fee: crate::primitives::GasPrice,
    },
}

impl FeePolicy {
    /// Estimate the fee for a given gas amount under this policy.
    pub fn estimate_fee(&self, gas: crate::primitives::GasAmount) -> Amount {
        match self {
            Self::Free => Amount::ZERO,
            Self::MarketBased { base_fee, .. } => {
                base_fee.total_fee(gas).unwrap_or(Amount::ZERO)
            }
            Self::Fixed { per_gas_fee, .. } => {
                per_gas_fee.total_fee(gas).unwrap_or(Amount::ZERO)
            }
        }
    }
}

// ============================================================
// STAKE
// ============================================================

/// A validator stake record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stake {
    /// The staking address.
    pub staker: Address,
    /// The validator this stake is delegated to.
    pub validator: ValidatorId,
    /// Total staked amount.
    pub amount: Amount,
    /// Voting weight derived from this stake.
    pub weight: ValidatorWeight,
    /// Epoch when this stake becomes effective.
    pub active_since_epoch: EpochNumber,
    /// Epoch when this stake will be unlocked (if unstaking is pending).
    pub unlock_epoch: Option<EpochNumber>,
    /// Whether this stake is currently active and voting.
    pub is_active: bool,
}

impl Stake {
    /// Create a new stake record.
    pub fn new(
        staker: Address,
        validator: ValidatorId,
        amount: Amount,
        active_since_epoch: EpochNumber,
    ) -> Self {
        let weight = ValidatorWeight::from_u64(
            u64::try_from(amount.as_nano() / 1_000_000_000).unwrap_or(u64::MAX)
        );
        Self {
            staker,
            validator,
            amount,
            weight,
            active_since_epoch,
            unlock_epoch: None,
            is_active: true,
        }
    }

    /// Initiate unstaking — sets the unlock epoch.
    pub fn begin_unstaking(&mut self, current_epoch: EpochNumber, unbonding_periods: u64) {
        let unlock = EpochNumber::from_u64(
            current_epoch.as_u64().saturating_add(unbonding_periods)
        );
        self.unlock_epoch = Some(unlock);
        self.is_active = false;
    }

    /// Returns `true` if the stake can be withdrawn in `current_epoch`.
    pub fn is_withdrawable(&self, current_epoch: EpochNumber) -> bool {
        self.unlock_epoch
            .is_some_and(|unlock| current_epoch >= unlock)
    }
}

/// Staking amount type alias.
pub type StakeAmount = Amount;

// ============================================================
// REWARD DISTRIBUTION
// ============================================================

/// A reward distribution event for validators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardDistribution {
    /// Epoch this reward covers.
    pub epoch: EpochNumber,
    /// Total rewards distributed this epoch.
    pub total_rewards: Amount,
    /// Per-validator reward breakdown.
    pub validator_rewards: Vec<ValidatorReward>,
    /// Block height when rewards were distributed.
    pub distribution_height: u64,
}

/// Reward for a single validator in an epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorReward {
    /// Validator receiving the reward.
    pub validator_id: ValidatorId,
    /// Consensus participation reward.
    pub consensus_reward: Amount,
    /// TEE service provision reward.
    pub tee_service_reward: Amount,
    /// Total reward.
    pub total_reward: Amount,
    /// Performance multiplier applied (0.0–2.0 as fixed-point × 100).
    pub performance_multiplier_pct: u32,
}

impl ValidatorReward {
    /// Compute total reward from components.
    pub fn compute_total(&mut self) {
        self.total_reward = self
            .consensus_reward
            .checked_add(self.tee_service_reward)
            .unwrap_or(Amount::ZERO);
    }
}

/// Comprehensive capability score for validator delegation decisions.
///
/// Enables delegators to make informed decisions based on objective
/// performance metrics rather than marketing or social influence.
/// Whitepaper §9.2: "sophisticated delegation management enables informed
/// decision-making through comprehensive validator assessment."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationCapabilityScore {
    /// Validator identifier.
    pub validator: ValidatorId,
    /// TEE infrastructure quality (0–100). Reflects hardware diversity,
    /// platform coverage, and redundancy across all 5 TEE platforms.
    pub tee_infrastructure_score: u8,
    /// Mathematical verification accuracy (0–100). Reflects attestation
    /// quality and consensus participation accuracy.
    pub mathematical_verification_score: u8,
    /// Operational excellence (0–100). Reflects uptime, response latency,
    /// security compliance, and protocol update adoption speed.
    pub operational_excellence_score: u8,
    /// TEE service quality (0–100). Reflects service availability,
    /// performance benchmarking, and user satisfaction metrics.
    pub tee_service_quality_score: u8,
    /// Geographic distribution contribution (0–100). Rewards validators
    /// in underserved regions that improve network resilience.
    pub geographic_contribution_score: u8,
}

impl DelegationCapabilityScore {
    /// Compute the composite score as a weighted average (0–100).
    #[allow(clippy::cast_possible_truncation)]
    pub fn composite(&self) -> u8 {
        let sum = u32::from(self.tee_infrastructure_score) * 25
            + u32::from(self.mathematical_verification_score) * 30
            + u32::from(self.operational_excellence_score) * 20
            + u32::from(self.tee_service_quality_score) * 15
            + u32::from(self.geographic_contribution_score) * 10;
        (sum / 100) as u8
    }

    /// Returns `true` if this validator meets the minimum threshold for delegation.
    pub fn meets_threshold(&self, min_composite: u8) -> bool {
        self.composite() >= min_composite
    }
}

/// Economic coordination across multiple subnet deployments.
///
/// Enables diverse economic models across public networks, permissioned
/// enterprise subnets, and hybrid deployments while maintaining economic
/// interoperability. Whitepaper §9.5: "multi-network economic coordination
/// enables diverse economic models across different network types."
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossSubnetEconomics {
    /// Source subnet identifier.
    pub source_subnet: String,
    /// Destination subnet identifier.
    pub destination_subnet: String,
    /// Fee policy applied at the source subnet.
    pub source_fee_policy: FeePolicy,
    /// Fee policy applied at the destination subnet.
    pub destination_fee_policy: FeePolicy,
    /// Whether cross-subnet asset transfers are enabled.
    pub asset_transfer_enabled: bool,
    /// Whether governance decisions are coordinated across subnets.
    pub governance_coordination: bool,
}

impl CrossSubnetEconomics {
    /// Create a cross-subnet economics configuration.
    pub fn new(source: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            source_subnet: source.into(),
            destination_subnet: destination.into(),
            source_fee_policy: FeePolicy::MarketBased {
                base_fee: crate::primitives::GasPrice(1_000),
                max_multiplier: 10,
            },
            destination_fee_policy: FeePolicy::Free,
            asset_transfer_enabled: true,
            governance_coordination: false,
        }
    }

    /// Returns `true` if this configuration spans a public-to-permissioned bridge.
    pub fn is_public_to_permissioned(&self) -> bool {
        !matches!(self.source_fee_policy, FeePolicy::Free)
            && matches!(self.destination_fee_policy, FeePolicy::Free)
    }
}

/// Marker trait for types that represent economic values.
///
/// Used by higher-level crates to constrain economic policy implementations.
pub trait EconomicPrimitive: Clone + std::fmt::Debug + serde::Serialize {}

impl EconomicPrimitive for Amount {}
impl EconomicPrimitive for Fee {}
impl EconomicPrimitive for Stake {}
impl EconomicPrimitive for ValidatorReward {}
impl EconomicPrimitive for DelegationCapabilityScore {}
impl EconomicPrimitive for CrossSubnetEconomics {}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Address, Amount, EpochNumber, GasAmount, GasPrice, Hash256};

    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn nano(n: u128) -> Amount { Amount::from_nano(n) }
    fn gas(n: u64) -> GasAmount { GasAmount::from_u64(n) }

    // ── Balance — economic primitive ──────────────────────────────────────
    // Whitepaper: "account management, balance tracking, transfer mechanisms"

    #[test]
    fn balance_debit_success() {
        let mut bal = Balance::zero(Address::ZERO);
        bal.credit(Amount::ONE_AEVOR).unwrap();
        let debited = bal.debit(Amount::ONE_AEVOR);
        assert!(debited.is_some());
        assert!(bal.amount.is_zero());
    }

    #[test]
    fn balance_debit_insufficient_returns_none() {
        let mut bal = Balance::zero(Address::ZERO);
        let result = bal.debit(Amount::ONE_NANO);
        assert!(result.is_none());
        assert!(bal.amount.is_zero()); // unchanged — double-spend prevented
    }

    #[test]
    fn balance_credit_overflow_returns_none() {
        let mut bal = Balance::zero(Address::ZERO);
        bal.amount = Amount(u128::MAX);
        let result = bal.credit(Amount::ONE_NANO);
        assert!(result.is_none());
    }

    #[test]
    fn balance_nonce_increments_on_debit() {
        let mut bal = Balance::zero(addr(1));
        bal.credit(nano(1_000)).unwrap();
        assert_eq!(bal.nonce, 0);
        bal.debit(nano(100)).unwrap();
        assert_eq!(bal.nonce, 1); // replay attack protection
        bal.debit(nano(100)).unwrap();
        assert_eq!(bal.nonce, 2);
    }

    #[test]
    fn balance_can_afford_boundary() {
        let mut bal = Balance::zero(addr(1));
        bal.credit(nano(500)).unwrap();
        assert!(bal.can_afford(nano(500)));
        assert!(bal.can_afford(nano(499)));
        assert!(!bal.can_afford(nano(501)));
    }

    // ── Fee — feeless and market-based primitives ─────────────────────────
    // Whitepaper: "Fee::free() for permissioned subnets with feeless operation"

    #[test]
    fn fee_free_has_zero_max_fee() {
        let f = Fee::free();
        assert!(f.is_free());
        assert!(f.max_fee.is_zero());
        assert!(f.paid_fee.is_zero());
    }

    #[test]
    fn fee_new_computes_max_fee() {
        let f = Fee::new(gas(21_000), GasPrice(1_000));
        assert!(!f.is_free());
        assert!(!f.max_fee.is_zero()); // 21_000 × 1_000 nanoAEVOR
    }

    // ── FeePolicy — any economic model ────────────────────────────────────
    // Whitepaper: "economic primitives that enable any economic model"

    #[test]
    fn fee_policy_free_estimates_zero() {
        let policy = FeePolicy::Free;
        assert!(policy.estimate_fee(gas(1_000_000)).is_zero());
    }

    #[test]
    fn fee_policy_market_based_scales_with_gas() {
        let policy = FeePolicy::MarketBased { base_fee: GasPrice(100), max_multiplier: 10 };
        let fee_small = policy.estimate_fee(gas(1_000));
        let fee_large = policy.estimate_fee(gas(10_000));
        assert!(fee_large.as_nano() > fee_small.as_nano());
    }

    #[test]
    fn fee_policy_fixed_scales_with_gas() {
        let policy = FeePolicy::Fixed {
            transfer_fee: nano(500),
            per_gas_fee: GasPrice(50),
        };
        let fee = policy.estimate_fee(gas(1_000));
        assert!(!fee.is_zero());
    }

    // ── Stake — staking lifecycle ─────────────────────────────────────────
    // Whitepaper: "staking requirements that demand significant capital commitments"

    #[test]
    fn stake_active_on_creation() {
        let stake = Stake::new(addr(1), Hash256::ZERO, Amount::ONE_AEVOR, EpochNumber::GENESIS);
        assert!(stake.is_active);
        assert!(stake.unlock_epoch.is_none());
    }

    #[test]
    fn stake_begins_inactive_when_unstaking() {
        let mut stake = Stake::new(
            Address::ZERO, Hash256::ZERO, Amount::ONE_AEVOR, EpochNumber::GENESIS,
        );
        assert!(stake.is_active);
        stake.begin_unstaking(EpochNumber::GENESIS, 14);
        assert!(!stake.is_active);
        assert!(!stake.is_withdrawable(EpochNumber::GENESIS));
        assert!(stake.is_withdrawable(EpochNumber::from_u64(14)));
    }

    #[test]
    fn stake_not_withdrawable_before_unlock() {
        let mut stake = Stake::new(addr(1), Hash256::ZERO, nano(100), EpochNumber(5));
        stake.begin_unstaking(EpochNumber(5), 14);
        assert!(!stake.is_withdrawable(EpochNumber(10))); // 10 < 5+14=19
        assert!(stake.is_withdrawable(EpochNumber(19)));  // exactly at unlock
    }

    #[test]
    fn stake_weight_derived_from_amount() {
        let s1 = Stake::new(addr(1), Hash256::ZERO, nano(1_000_000_000), EpochNumber(1)); // 1 AEVOR
        let s2 = Stake::new(addr(2), Hash256::ZERO, nano(2_000_000_000), EpochNumber(1)); // 2 AEVOR
        assert!(s2.weight.as_u64() > s1.weight.as_u64());
    }

    // ── ValidatorReward — TEE service rewards ─────────────────────────────
    // Whitepaper: "validators rewarded for TEE service provision"

    #[test]
    fn validator_reward_compute_total() {
        let mut reward = ValidatorReward {
            validator_id: Hash256::ZERO,
            consensus_reward: nano(1_000_000_000),
            tee_service_reward: nano(500_000_000),
            total_reward: Amount::ZERO,
            performance_multiplier_pct: 100,
        };
        reward.compute_total();
        assert_eq!(reward.total_reward.as_nano(), 1_500_000_000u128);
    }

    #[test]
    fn validator_reward_tee_service_component_present() {
        let reward = ValidatorReward {
            validator_id: Hash256::ZERO,
            consensus_reward: nano(1_000),
            tee_service_reward: nano(500), // non-zero TEE reward
            total_reward: nano(1_500),
            performance_multiplier_pct: 100,
        };
        assert!(reward.tee_service_reward.as_nano() > 0);
    }

    // ── DelegationCapabilityScore ─────────────────────────────────────────
    // Whitepaper §9.2: comprehensive validator assessment for informed delegation

    #[test]
    fn delegation_capability_composite_weighted_correctly() {
        let score = DelegationCapabilityScore {
            validator: Hash256::ZERO,
            tee_infrastructure_score: 100,
            mathematical_verification_score: 100,
            operational_excellence_score: 100,
            tee_service_quality_score: 100,
            geographic_contribution_score: 100,
        };
        assert_eq!(score.composite(), 100);
    }

    #[test]
    fn delegation_capability_low_scores_produce_low_composite() {
        let score = DelegationCapabilityScore {
            validator: Hash256::ZERO,
            tee_infrastructure_score: 20,
            mathematical_verification_score: 20,
            operational_excellence_score: 20,
            tee_service_quality_score: 20,
            geographic_contribution_score: 20,
        };
        assert_eq!(score.composite(), 20);
    }

    #[test]
    fn delegation_capability_meets_threshold() {
        let score = DelegationCapabilityScore {
            validator: Hash256::ZERO,
            tee_infrastructure_score: 80,
            mathematical_verification_score: 90,
            operational_excellence_score: 85,
            tee_service_quality_score: 75,
            geographic_contribution_score: 60,
        };
        assert!(score.meets_threshold(80)); // composite should be ~84
        assert!(!score.meets_threshold(95));
    }

    // ── CrossSubnetEconomics ──────────────────────────────────────────────
    // Whitepaper §9.5: diverse economic models across network types

    #[test]
    fn cross_subnet_economics_new_defaults_asset_transfer_enabled() {
        let cfg = CrossSubnetEconomics::new("mainnet", "enterprise-subnet-1");
        assert!(cfg.asset_transfer_enabled);
        assert!(!cfg.governance_coordination);
        assert_eq!(cfg.source_subnet, "mainnet");
    }

    #[test]
    fn cross_subnet_public_to_permissioned_detection() {
        let cfg = CrossSubnetEconomics::new("mainnet", "enterprise");
        // source = MarketBased (public), destination = Free (permissioned)
        assert!(cfg.is_public_to_permissioned());
    }

    #[test]
    fn cross_subnet_both_free_not_public_to_permissioned() {
        let mut cfg = CrossSubnetEconomics::new("subnet-a", "subnet-b");
        cfg.source_fee_policy = FeePolicy::Free;
        cfg.destination_fee_policy = FeePolicy::Free;
        assert!(!cfg.is_public_to_permissioned());
    }
}
