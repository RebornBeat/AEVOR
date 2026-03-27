//! API middleware stack.
use crate::rate_limiting::FairRateLimiter;

#[derive(Clone)]
pub struct MiddlewareStack { pub rate_limiter: Option<std::sync::Arc<FairRateLimiter>>, pub cors: bool }

pub struct MiddlewareBuilder { stack: MiddlewareStack }
impl MiddlewareBuilder {
    pub fn new() -> Self { Self { stack: MiddlewareStack { rate_limiter: None, cors: false } } }
    #[must_use]
    pub fn with_rate_limiter(mut self, rl: FairRateLimiter) -> Self {
        self.stack.rate_limiter = Some(std::sync::Arc::new(rl)); self
    }
    #[must_use]
    pub fn with_request_logging(self, _enabled: bool) -> Self { self }
    #[must_use]
    pub fn with_cors(mut self, enabled: bool, _origins: Vec<String>) -> Self {
        self.stack.cors = enabled; self
    }
    pub fn build(self) -> MiddlewareStack { self.stack }
}

impl Default for MiddlewareBuilder {
    fn default() -> Self { Self::new() }
}

impl MiddlewareStack {
    pub fn builder() -> MiddlewareBuilder { MiddlewareBuilder::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limiting::{FairRateLimiter, RateLimitPolicy};

    fn policy() -> RateLimitPolicy {
        RateLimitPolicy { unauthenticated_rpm: 60, authenticated_rpm: 300 }
    }

    #[test]
    fn builder_default_has_no_rate_limiter_no_cors() {
        let stack = MiddlewareBuilder::default().build();
        assert!(stack.rate_limiter.is_none());
        assert!(!stack.cors);
    }

    #[test]
    fn builder_with_cors_enabled() {
        let stack = MiddlewareBuilder::new()
            .with_cors(true, vec!["https://example.com".into()])
            .build();
        assert!(stack.cors);
    }

    #[test]
    fn builder_with_cors_disabled() {
        let stack = MiddlewareBuilder::new()
            .with_cors(false, vec![])
            .build();
        assert!(!stack.cors);
    }

    #[test]
    fn builder_with_rate_limiter_sets_it() {
        let rl = FairRateLimiter::new(policy());
        let stack = MiddlewareBuilder::new()
            .with_rate_limiter(rl)
            .build();
        assert!(stack.rate_limiter.is_some());
    }

    #[test]
    fn builder_request_logging_is_passthrough() {
        let stack = MiddlewareBuilder::new()
            .with_request_logging(true)
            .build();
        assert!(stack.rate_limiter.is_none());
    }

    #[test]
    fn middleware_stack_builder_method() {
        let stack = MiddlewareStack::builder().build();
        assert!(!stack.cors);
    }
}
