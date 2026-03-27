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

// ============================================================
// ECONOMIC PRIMITIVE TRAIT
// ============================================================

/// Marker trait for types that represent economic values.
///
/// Used by higher-level crates to constrain economic policy implementations.
pub trait EconomicPrimitive: Clone + std::fmt::Debug + serde::Serialize {}

impl EconomicPrimitive for Amount {}
impl EconomicPrimitive for Fee {}
impl EconomicPrimitive for Stake {}
impl EconomicPrimitive for ValidatorReward {}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(bal.amount.is_zero()); // Unchanged
    }

    #[test]
    fn balance_credit_overflow_returns_none() {
        let mut bal = Balance::zero(Address::ZERO);
        bal.amount = Amount(u128::MAX);
        let result = bal.credit(Amount::ONE_NANO);
        assert!(result.is_none());
    }

    #[test]
    fn fee_free_has_zero_max_fee() {
        let f = Fee::free();
        assert!(f.is_free());
        assert!(f.max_fee.is_zero());
    }

    #[test]
    fn fee_policy_free_estimates_zero() {
        let policy = FeePolicy::Free;
        let gas = crate::primitives::GasAmount::from_u64(1_000_000);
        assert!(policy.estimate_fee(gas).is_zero());
    }

    #[test]
    fn stake_begins_inactive_when_unstaking() {
        let mut stake = Stake::new(
            Address::ZERO,
            crate::primitives::Hash256::ZERO,
            Amount::ONE_AEVOR,
            EpochNumber::GENESIS,
        );
        assert!(stake.is_active);
        stake.begin_unstaking(EpochNumber::GENESIS, 14);
        assert!(!stake.is_active);
        assert!(!stake.is_withdrawable(EpochNumber::GENESIS));
        assert!(stake.is_withdrawable(EpochNumber::from_u64(14)));
    }

    #[test]
    fn validator_reward_compute_total() {
        let mut reward = ValidatorReward {
            validator_id: crate::primitives::Hash256::ZERO,
            consensus_reward: Amount::from_nano(1_000_000_000),
            tee_service_reward: Amount::from_nano(500_000_000),
            total_reward: Amount::ZERO,
            performance_multiplier_pct: 100,
        };
        reward.compute_total();
        assert_eq!(reward.total_reward.as_nano(), 1_500_000_000);
    }
}
