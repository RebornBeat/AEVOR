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
        if now_unix >= end { 0 } else { end - now_unix }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressCooldown { pub entry: Option<CooldownEntry> }

pub struct CooldownTracker { entries: std::collections::HashMap<[u8; 32], CooldownEntry>, duration: u64 }
impl CooldownTracker {
    pub fn new(duration_seconds: u64) -> Self { Self { entries: std::collections::HashMap::new(), duration: duration_seconds } }
    pub fn start(&mut self, address: Address, now_unix: u64) {
        self.entries.insert(address.0, CooldownEntry { address, started_at_unix: now_unix, duration_seconds: self.duration });
    }
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
