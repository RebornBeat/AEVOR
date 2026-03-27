//! Address cooldown management.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Address;
use crate::{FaucetError, FaucetResult, DEFAULT_COOLDOWN_SECONDS};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CooldownStatus { Active { remaining_seconds: u64 }, Expired }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CooldownEntry { pub address: Address, pub started_at_unix: u64, pub duration_seconds: u64 }
impl CooldownEntry {
    pub fn is_expired(&self, now_unix: u64) -> bool { now_unix >= self.started_at_unix + self.duration_seconds }
    pub fn remaining_seconds(&self, now_unix: u64) -> u64 {
        let end = self.started_at_unix + self.duration_seconds;
        end.saturating_sub(now_unix)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressCooldown { pub entry: Option<CooldownEntry> }

pub struct CooldownTracker { entries: std::collections::HashMap<[u8; 32], CooldownEntry>, duration: u64 }
impl CooldownTracker {
    pub fn new(duration_seconds: u64) -> Self { Self { entries: std::collections::HashMap::new(), duration: duration_seconds } }
    /// Create a tracker with the library's default cooldown duration.
    pub fn default_duration() -> Self { Self::new(DEFAULT_COOLDOWN_SECONDS) }
    pub fn start(&mut self, address: Address, now_unix: u64) {
        self.entries.insert(address.0, CooldownEntry { address, started_at_unix: now_unix, duration_seconds: self.duration });
    }
    /// Check whether `address` is in cooldown at `now_unix`.
    ///
    /// # Errors
    /// Returns `FaucetError::AddressInCooldown` if the address has an active
    /// (unexpired) cooldown entry.
    pub fn check(&self, address: &Address, now_unix: u64) -> FaucetResult<()> {
        if let Some(entry) = self.entries.get(&address.0) {
            if !entry.is_expired(now_unix) {
                return Err(FaucetError::AddressInCooldown {
                    address: hex::encode(address.0),
                    remaining_seconds: entry.remaining_seconds(now_unix),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Address;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    #[test]
    fn entry_not_expired_during_cooldown() {
        let entry = CooldownEntry { address: addr(1), started_at_unix: 1000, duration_seconds: 3600 };
        assert!(!entry.is_expired(2000)); // only 1000s elapsed, need 3600
    }

    #[test]
    fn entry_expired_after_duration() {
        let entry = CooldownEntry { address: addr(1), started_at_unix: 1000, duration_seconds: 3600 };
        assert!(entry.is_expired(4600)); // 3600s elapsed
    }

    #[test]
    fn remaining_seconds_before_expiry() {
        let entry = CooldownEntry { address: addr(1), started_at_unix: 1000, duration_seconds: 3600 };
        assert_eq!(entry.remaining_seconds(2000), 2600); // 4600 - 2000
    }

    #[test]
    fn remaining_seconds_after_expiry_is_zero() {
        let entry = CooldownEntry { address: addr(1), started_at_unix: 1000, duration_seconds: 60 };
        assert_eq!(entry.remaining_seconds(5000), 0);
    }

    #[test]
    fn tracker_allows_address_not_in_cooldown() {
        let tracker = CooldownTracker::new(3600);
        assert!(tracker.check(&addr(1), 1000).is_ok());
    }

    #[test]
    fn tracker_blocks_address_in_cooldown() {
        let mut tracker = CooldownTracker::new(3600);
        tracker.start(addr(1), 1000);
        let err = tracker.check(&addr(1), 2000).unwrap_err();
        match err {
            FaucetError::AddressInCooldown { remaining_seconds, .. } => {
                assert_eq!(remaining_seconds, 2600);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn tracker_allows_after_expiry() {
        let mut tracker = CooldownTracker::new(3600);
        tracker.start(addr(1), 1000);
        assert!(tracker.check(&addr(1), 5000).is_ok()); // 4000s > 3600s
    }
}
