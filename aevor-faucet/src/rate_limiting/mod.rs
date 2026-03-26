//! Decentralized rate limiting via validator consensus.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Address;
use crate::FaucetResult;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitRecord {
    pub address: Address,
    pub last_request_unix: u64,
    pub request_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitCheck { pub address: Address, pub cooldown_seconds: u64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitState { pub records: Vec<RateLimitRecord> }
impl RateLimitState {
    pub fn new() -> Self { Self { records: Vec::new() } }
    pub fn get(&self, addr: &Address) -> Option<&RateLimitRecord> {
        self.records.iter().find(|r| &r.address == addr)
    }
}
impl Default for RateLimitState { fn default() -> Self { Self::new() } }

pub struct ValidatorRateConsensus { validators_required: usize }
impl ValidatorRateConsensus {
    pub fn new(validators_required: usize) -> Self { Self { validators_required } }
    pub fn quorum(&self) -> usize { self.validators_required }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RateLimitResult {
    Allowed,
    Denied { retry_after_seconds: u64 },
}
