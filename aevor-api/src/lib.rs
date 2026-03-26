//! # AEVOR API: Infrastructure Primitive Access
//!
//! `aevor-api` exposes all of AEVOR's revolutionary infrastructure capabilities
//! through well-designed APIs, enabling external ecosystem development without
//! implementing comprehensive development environments or external service integrations.
//!
//! ## Architectural Boundary
//!
//! This crate provides **API access to infrastructure primitives**. It does not:
//! - Implement comprehensive SDKs with application scaffolding
//! - Provide IDE integration or debugging tools
//! - Embed external service integrations (notification services, cloud APIs)
//! - Implement organizational management frameworks
//!
//! External tools, SDKs, and integrations access these APIs to build whatever
//! they need — the infrastructure remains focused on capability provision.
//!
//! ## API Surface
//!
//! **REST API**: Standard HTTP/JSON for broad compatibility and easy integration.
//! **gRPC API**: High-performance binary protocol for production validators and SDKs.
//! **WebSocket API**: Real-time subscriptions for live transaction and block feeds.
//! **GraphQL API**: Flexible querying for analytics and explorer tools.
//!
//! ## Mixed Privacy API Coordination
//!
//! API responses respect object privacy levels automatically. Public objects are
//! returned in clear text; private objects return only what the requesting key is
//! authorized to see through selective disclosure mechanisms.
//!
//! ## Multi-Network Support
//!
//! A single API server can serve multiple network types (mainnet, testnet, permissioned
//! subnets) with configuration-driven routing and network-specific authentication.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// REST API: HTTP/JSON endpoints for transactions, queries, and subscriptions.
pub mod rest;

/// gRPC API: high-performance binary protocol for production integrations.
pub mod grpc;

/// WebSocket API: real-time event subscriptions and streaming queries.
pub mod websocket;

/// GraphQL API: flexible query interface for analytics and exploration.
pub mod graphql;

/// API request and response types: shared types across all API protocols.
pub mod types;

/// Authentication: API key management, JWT tokens, TEE-backed authentication.
pub mod auth;

/// Rate limiting: fair access controls without discriminatory filtering.
pub mod rate_limiting;

/// Middleware: logging, tracing, error handling, CORS, compression.
pub mod middleware;

/// API versioning: backward-compatible version negotiation.
pub mod versioning;

/// Privacy-aware responses: automatic privacy level enforcement in responses.
pub mod privacy_responses;

/// Multi-network routing: request routing across network types.
pub mod network_routing;

// ============================================================
// PRELUDE
// ============================================================

/// API prelude — all essential API types.
///
/// ```rust
/// use aevor_api::prelude::*;
/// ```
pub mod prelude {
    pub use crate::rest::{
        RestServer, RestConfig, RestRouter, RestHandler,
        JsonResponse, JsonRequest, ErrorResponse,
    };
    pub use crate::grpc::{
        GrpcServer, GrpcConfig, AevorService, TransactionService,
        QueryService, ConsensusService, ValidatorService,
    };
    pub use crate::websocket::{
        WsServer, WsConfig, Subscription, SubscriptionFilter,
        EventStream, LiveFeed,
    };
    pub use crate::types::{
        ApiTransaction, ApiBlock, ApiObject, ApiValidator, ApiQuery,
        ApiReceipt, ApiError, Pagination, SortOrder,
    };
    pub use crate::auth::{
        ApiAuth, ApiKey, JwtToken, TeeBackedAuth, AuthMiddleware,
        PermissionScope,
    };
    pub use crate::rate_limiting::{
        RateLimiter, RateLimit, RateLimitPolicy, RateLimitResult,
        FairRateLimiter,
    };
    pub use crate::privacy_responses::{
        PrivacyAwareSerializer, PrivacyFilteredResponse, AuthorizedView,
        SelectiveDisclosureResponse,
    };
    pub use crate::network_routing::{
        NetworkRouter, NetworkSelector, MultiNetworkApi, SubnetRouting,
    };
    pub use crate::{ApiError as ApiErr, ApiResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from API operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ApiError {
    /// Request authentication failed.
    #[error("authentication failed: {reason}")]
    AuthenticationFailed {
        /// Reason for authentication failure.
        reason: String,
    },

    /// Caller is not authorized to access the requested resource.
    #[error("not authorized to access {resource}")]
    NotAuthorized {
        /// Resource that access was denied for.
        resource: String,
    },

    /// Rate limit exceeded.
    #[error("rate limit exceeded: {limit} requests per {window_seconds}s")]
    RateLimitExceeded {
        /// Request rate limit.
        limit: u64,
        /// Rate limit window in seconds.
        window_seconds: u64,
    },

    /// Requested resource was not found.
    #[error("not found: {resource}")]
    NotFound {
        /// Resource that was not found.
        resource: String,
    },

    /// Request payload is invalid.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// Reason the request is invalid.
        reason: String,
    },

    /// Internal infrastructure error.
    #[error("internal error: {0}")]
    InternalError(String),

    /// API version not supported.
    #[error("API version {version} not supported")]
    UnsupportedVersion {
        /// Requested version.
        version: String,
    },
}

/// Convenience alias for API results.
pub type ApiResult<T> = Result<T, ApiError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default REST API port.
pub const DEFAULT_REST_PORT: u16 = 8731;

/// Default gRPC API port.
pub const DEFAULT_GRPC_PORT: u16 = 8730;

/// Default WebSocket port.
pub const DEFAULT_WS_PORT: u16 = 8733;

/// Default GraphQL port.
pub const DEFAULT_GRAPHQL_PORT: u16 = 8734;

/// Maximum request body size in bytes (10 MiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 10_485_760;

/// Default rate limit for unauthenticated requests (requests per minute).
pub const DEFAULT_UNAUTHENTICATED_RATE_LIMIT: u64 = 60;

/// Default rate limit for authenticated requests (requests per minute).
pub const DEFAULT_AUTHENTICATED_RATE_LIMIT: u64 = 1_000;

/// Maximum WebSocket subscriptions per connection.
pub const MAX_WS_SUBSCRIPTIONS_PER_CONNECTION: usize = 100;

/// Current API version string.
pub const API_VERSION: &str = "v1";

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_distinct() {
        let ports = [
            DEFAULT_REST_PORT,
            DEFAULT_GRPC_PORT,
            DEFAULT_WS_PORT,
            DEFAULT_GRAPHQL_PORT,
        ];
        for i in 0..ports.len() {
            for j in (i + 1)..ports.len() {
                assert_ne!(ports[i], ports[j]);
            }
        }
    }

    #[test]
    fn authenticated_rate_limit_exceeds_unauthenticated() {
        assert!(DEFAULT_AUTHENTICATED_RATE_LIMIT > DEFAULT_UNAUTHENTICATED_RATE_LIMIT);
    }
}
