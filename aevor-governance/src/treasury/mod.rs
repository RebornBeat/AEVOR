//! Protocol treasury: on-chain fund management for ecosystem development.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Amount};

/// Current balance of the protocol treasury.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryBalance {
    /// Funds available for immediate spending via governance vote.
    pub available: Amount,
    /// Funds reserved for approved-but-not-yet-executed spends.
    pub reserved: Amount,
}

impl TreasuryBalance {
    /// Total treasury balance (available + reserved).
    pub fn total(&self) -> Amount {
        Amount::from_nano(self.available.as_nano().saturating_add(self.reserved.as_nano()))
    }

    /// Returns `true` if the treasury can cover the requested amount.
    pub fn can_fund(&self, requested: Amount) -> bool {
        self.available.as_nano() >= requested.as_nano()
    }
}

/// A proposal to spend treasury funds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasurySpend {
    /// Amount to spend from the treasury.
    pub amount: Amount,
    /// Recipient address.
    pub recipient: Address,
    /// Human-readable description of the spend purpose.
    pub description: String,
}

impl TreasurySpend {
    /// Create a new treasury spend proposal.
    pub fn new(amount: Amount, recipient: Address, description: impl Into<String>) -> Self {
        Self { amount, recipient, description: description.into() }
    }
}

/// Manages the on-chain treasury lifecycle.
pub struct TreasuryManager {
    balance: TreasuryBalance,
    pending_spends: Vec<TreasurySpend>,
}

impl TreasuryManager {
    /// Create a new treasury manager with the given initial balance.
    pub fn new(available: Amount) -> Self {
        Self {
            balance: TreasuryBalance { available, reserved: Amount::ZERO },
            pending_spends: Vec::new(),
        }
    }

    /// Current treasury balance.
    pub fn balance(&self) -> &TreasuryBalance { &self.balance }

    /// Queue a treasury spend (pending governance approval).
    pub fn queue_spend(&mut self, spend: TreasurySpend) -> bool {
        if !self.balance.can_fund(spend.amount) {
            return false;
        }
        // Reserve the funds.
        let reserved = self.balance.reserved.as_nano().saturating_add(spend.amount.as_nano());
        let available = self.balance.available.as_nano().saturating_sub(spend.amount.as_nano());
        self.balance.available = Amount::from_nano(available);
        self.balance.reserved = Amount::from_nano(reserved);
        self.pending_spends.push(spend);
        true
    }

    /// Number of pending spend proposals.
    pub fn pending_count(&self) -> usize { self.pending_spends.len() }
}
