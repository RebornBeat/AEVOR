//! API middleware stack.
use crate::rate_limiting::FairRateLimiter;

#[derive(Clone)]
pub struct MiddlewareStack { pub rate_limiter: Option<std::sync::Arc<FairRateLimiter>>, pub cors: bool }

pub struct MiddlewareBuilder { stack: MiddlewareStack }
impl MiddlewareBuilder {
    pub fn new() -> Self { Self { stack: MiddlewareStack { rate_limiter: None, cors: false } } }
    pub fn with_rate_limiter(mut self, rl: FairRateLimiter) -> Self {
        self.stack.rate_limiter = Some(std::sync::Arc::new(rl)); self
    }
    pub fn with_request_logging(self, _enabled: bool) -> Self { self }
    pub fn with_cors(mut self, enabled: bool, _origins: Vec<String>) -> Self {
        self.stack.cors = enabled; self
    }
    pub fn build(self) -> MiddlewareStack { self.stack }
}

impl MiddlewareStack {
    pub fn builder() -> MiddlewareBuilder { MiddlewareBuilder::new() }
}
