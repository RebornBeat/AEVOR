//! API rate limiting.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimit { pub requests_per_minute: u64, pub burst: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitPolicy { pub unauthenticated_rpm: u64, pub authenticated_rpm: u64 }
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RateLimitResult { Allowed, Limited { retry_after_ms: u64 } }

pub struct RateLimiter { policy: RateLimitPolicy }
impl RateLimiter {
    pub fn new(policy: RateLimitPolicy) -> Self { Self { policy } }
    pub fn check(&self, _key: &str, authenticated: bool) -> RateLimitResult {
        let _ = if authenticated { self.policy.authenticated_rpm } else { self.policy.unauthenticated_rpm };
        RateLimitResult::Allowed
    }
}

pub struct FairRateLimiter { limiter: RateLimiter }
impl FairRateLimiter {
    pub fn new(policy: RateLimitPolicy) -> Self { Self { limiter: RateLimiter::new(policy) } }
    pub fn check(&self, key: &str, authenticated: bool) -> RateLimitResult {
        self.limiter.check(key, authenticated)
    }
}
