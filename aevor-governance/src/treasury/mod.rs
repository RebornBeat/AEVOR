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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Amount};

    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn nano(n: u128) -> Amount { Amount::from_nano(n) }

    #[test]
    fn treasury_balance_total_is_sum() {
        let b = TreasuryBalance { available: nano(7_000), reserved: nano(3_000) };
        assert_eq!(b.total().as_nano(), 10_000u128);
    }

    #[test]
    fn treasury_balance_can_fund_exact_amount() {
        let b = TreasuryBalance { available: nano(5_000), reserved: Amount::ZERO };
        assert!(b.can_fund(nano(5_000)));
        assert!(b.can_fund(nano(1)));
        assert!(!b.can_fund(nano(5_001)));
    }

    #[test]
    fn treasury_spend_new_stores_fields() {
        let spend = TreasurySpend::new(nano(100), addr(1), "grant");
        assert_eq!(spend.amount.as_nano(), 100u128);
        assert_eq!(spend.recipient, addr(1));
        assert_eq!(spend.description, "grant");
    }

    #[test]
    fn treasury_manager_queue_spend_reserves_funds() {
        let mut mgr = TreasuryManager::new(nano(10_000));
        let spend = TreasurySpend::new(nano(3_000), addr(1), "dev grant");
        assert!(mgr.queue_spend(spend));
        assert_eq!(mgr.balance().available.as_nano(), 7_000u128);
        assert_eq!(mgr.balance().reserved.as_nano(), 3_000u128);
        assert_eq!(mgr.pending_count(), 1);
    }

    #[test]
    fn treasury_manager_queue_spend_rejects_if_insufficient_funds() {
        let mut mgr = TreasuryManager::new(nano(100));
        let spend = TreasurySpend::new(nano(200), addr(1), "too expensive");
        assert!(!mgr.queue_spend(spend));
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.balance().available.as_nano(), 100u128);
    }

    #[test]
    fn treasury_manager_multiple_queued_spends() {
        let mut mgr = TreasuryManager::new(nano(10_000));
        mgr.queue_spend(TreasurySpend::new(nano(1_000), addr(1), "grant 1"));
        mgr.queue_spend(TreasurySpend::new(nano(2_000), addr(2), "grant 2"));
        assert_eq!(mgr.pending_count(), 2);
        assert_eq!(mgr.balance().available.as_nano(), 7_000u128);
        assert_eq!(mgr.balance().reserved.as_nano(), 3_000u128);
    }
}
