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
    /// Check whether `address` is rate-limited, returning a `FaucetResult`.
    ///
    /// # Errors
    /// Returns `FaucetError::ConsensusFailure` if the address has exceeded the
    /// allowed request count confirmed by the validator quorum.
    pub fn check_rate_limit(&self, state: &RateLimitState, address: &Address) -> FaucetResult<()> {
        if let Some(record) = state.get(address) {
            if record.request_count > self.validators_required as u64 {
                return Err(crate::FaucetError::ConsensusFailure {
                    reason: format!("rate limit exceeded for {address:?}"),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RateLimitResult {
    Allowed,
    Denied { retry_after_seconds: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Address;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    fn record(n: u8, count: u64) -> RateLimitRecord {
        RateLimitRecord { address: addr(n), last_request_unix: 1_000, request_count: count }
    }

    #[test]
    fn rate_limit_state_empty_on_new() {
        let state = RateLimitState::new();
        assert!(state.get(&addr(1)).is_none());
    }

    #[test]
    fn rate_limit_state_get_finds_record() {
        let mut state = RateLimitState::default();
        state.records.push(record(1, 3));
        assert_eq!(state.get(&addr(1)).unwrap().request_count, 3);
        assert!(state.get(&addr(2)).is_none());
    }

    #[test]
    fn validator_rate_consensus_quorum() {
        let vrc = ValidatorRateConsensus::new(3);
        assert_eq!(vrc.quorum(), 3);
    }

    #[test]
    fn check_rate_limit_passes_under_threshold() {
        let vrc = ValidatorRateConsensus::new(10);
        let mut state = RateLimitState::new();
        state.records.push(record(1, 5)); // 5 < 10
        assert!(vrc.check_rate_limit(&state, &addr(1)).is_ok());
    }

    #[test]
    fn check_rate_limit_fails_over_threshold() {
        let vrc = ValidatorRateConsensus::new(3);
        let mut state = RateLimitState::new();
        state.records.push(record(1, 5)); // 5 > 3
        assert!(vrc.check_rate_limit(&state, &addr(1)).is_err());
    }

    #[test]
    fn check_rate_limit_passes_for_unknown_address() {
        let vrc = ValidatorRateConsensus::new(3);
        let state = RateLimitState::new(); // no records
        assert!(vrc.check_rate_limit(&state, &addr(99)).is_ok());
    }

    #[test]
    fn rate_limit_result_denied_carries_retry_time() {
        let r = RateLimitResult::Denied { retry_after_seconds: 300 };
        assert!(matches!(r, RateLimitResult::Denied { retry_after_seconds: 300 }));
    }
}
