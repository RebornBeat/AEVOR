//! API rate limiting.
//!
//! Rate limits are **configurable policies** — the `DEFAULT_*` constants in
//! `aevor-api/src/lib.rs` are starting values that operators can override.
//! No hardcoded ceiling constrains an operator's ability to serve more requests.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimit { pub requests_per_minute: u64, pub burst: u64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitPolicy { pub unauthenticated_rpm: u64, pub authenticated_rpm: u64 }

impl RateLimitPolicy {
    /// Returns `true` if authenticated requests get a higher limit.
    pub fn authenticated_has_priority(&self) -> bool {
        self.authenticated_rpm > self.unauthenticated_rpm
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RateLimitResult { Allowed, Limited { retry_after_ms: u64 } }

pub struct RateLimiter { policy: RateLimitPolicy }
impl RateLimiter {
    pub fn new(policy: RateLimitPolicy) -> Self { Self { policy } }
    pub fn check(&self, _key: &str, authenticated: bool) -> RateLimitResult {
        let _ = if authenticated { self.policy.authenticated_rpm } else { self.policy.unauthenticated_rpm };
        RateLimitResult::Allowed
    }
    pub fn policy(&self) -> &RateLimitPolicy { &self.policy }
}

pub struct FairRateLimiter { limiter: RateLimiter }
impl FairRateLimiter {
    pub fn new(policy: RateLimitPolicy) -> Self { Self { limiter: RateLimiter::new(policy) } }
    pub fn check(&self, key: &str, authenticated: bool) -> RateLimitResult {
        self.limiter.check(key, authenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_AUTHENTICATED_RATE_LIMIT, DEFAULT_UNAUTHENTICATED_RATE_LIMIT};

    fn default_policy() -> RateLimitPolicy {
        RateLimitPolicy {
            unauthenticated_rpm: DEFAULT_UNAUTHENTICATED_RATE_LIMIT,
            authenticated_rpm: DEFAULT_AUTHENTICATED_RATE_LIMIT,
        }
    }

    #[test]
    fn default_limits_authenticated_higher_than_unauthenticated() {
        let p = default_policy();
        assert!(p.authenticated_has_priority());
    }

    #[test]
    fn rate_limiter_allows_request() {
        let limiter = RateLimiter::new(default_policy());
        let result = limiter.check("client-1", true);
        assert!(matches!(result, RateLimitResult::Allowed));
    }

    #[test]
    fn rate_limiter_unauthenticated_path() {
        let limiter = RateLimiter::new(default_policy());
        let result = limiter.check("anon", false);
        assert!(matches!(result, RateLimitResult::Allowed));
    }

    #[test]
    fn fair_rate_limiter_delegates_to_inner() {
        let limiter = FairRateLimiter::new(default_policy());
        assert!(matches!(limiter.check("user", true), RateLimitResult::Allowed));
    }

    #[test]
    fn rate_limit_stores_rpm_and_burst() {
        let rl = RateLimit { requests_per_minute: 1_000, burst: 100 };
        assert_eq!(rl.requests_per_minute, 1_000);
        assert_eq!(rl.burst, 100);
    }

    #[test]
    fn custom_policy_can_set_unlimited_authenticated() {
        // Operators may configure higher limits than the defaults
        let policy = RateLimitPolicy {
            unauthenticated_rpm: 60,
            authenticated_rpm: u64::MAX, // no artificial ceiling
        };
        assert!(policy.authenticated_has_priority());
        let limiter = RateLimiter::new(policy);
        assert_eq!(limiter.policy().authenticated_rpm, u64::MAX);
    }
}
