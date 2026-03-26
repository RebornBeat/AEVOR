//! # AEVOR Client: Infrastructure Connection Management
//!
//! `aevor-client` provides connection and authentication primitives for interacting
//! with AEVOR infrastructure. This crate offers the foundational transport and
//! authentication layer — not a comprehensive SDK.
//!
//! ## Architectural Boundary
//!
//! This crate provides **connection primitives** only:
//! - Transport connections (REST, gRPC, WebSocket, GraphQL)
//! - Authentication (API keys, JWT, TEE-backed identity)
//! - Request signing and response verification
//! - Basic retry and reconnection logic
//!
//! Comprehensive SDK functionality (application scaffolding, contract deployment
//! helpers, transaction builders with business logic, testing frameworks) belongs
//! in external ecosystem projects that compose these primitives.
//!
//! ## Connection Types
//!
//! **Validator Connection**: High-performance gRPC connection for transaction
//! submission and block queries, optimized for production applications.
//!
//! **Light Client Connection**: Minimal connection for wallets and mobile apps,
//! verifying only the data it needs through Merkle proofs.
//!
//! **Archive Connection**: Connection to archive nodes for historical data queries.
//!
//! ## Multi-Network Support
//!
//! A single client instance can manage connections to multiple networks
//! simultaneously — mainnet, testnet, and permissioned subnets — with
//! network-tagged requests ensuring correct routing.
//!
//! ## Privacy-Preserving Connections
//!
//! Connections can be routed through privacy-preserving channels that prevent
//! infrastructure providers from correlating requests with client IP addresses
//! or building usage profiles.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Connection management: establishing and maintaining infrastructure connections.
pub mod connection;

/// Authentication: API key, JWT, and TEE-backed identity for connection auth.
pub mod auth;

/// Transaction submission: signing and submitting transactions to the network.
pub mod transaction;

/// Query interface: querying blockchain state, objects, and events.
pub mod query;

/// Subscription: event subscription and live feed management.
pub mod subscription;

/// Light client: minimal verification client for wallets and mobile.
pub mod light_client;

/// Multi-network: managing connections across multiple network types.
pub mod multi_network;

/// Privacy connections: privacy-preserving connection routing.
pub mod privacy;

/// Request signing: cryptographic signing of API requests.
pub mod signing;

/// Response verification: Merkle proof and attestation verification.
pub mod verification;

// ============================================================
// PRELUDE
// ============================================================

/// Client prelude — all essential client connection types.
///
/// ```rust
/// use aevor_client::prelude::*;
/// ```
pub mod prelude {
    pub use crate::connection::{
        AevorConnection, ConnectionConfig, ConnectionStatus, ConnectionPool,
        ValidatorConnection, ArchiveConnection, ConnectionBuilder,
    };
    pub use crate::auth::{
        ClientAuth, ApiKeyAuth, JwtAuth, TeeBackedClientAuth,
        AuthCredentials, AuthToken, AuthRefresh,
    };
    pub use crate::transaction::{
        TransactionClient, SignedTransactionRequest, SubmitResult,
        TransactionStatus, TransactionPoller,
    };
    pub use crate::query::{
        QueryClient, ObjectQuery, BlockQuery, ValidatorQuery,
        QueryResult, QueryPagination,
    };
    pub use crate::subscription::{
        SubscriptionClient, EventSubscription, BlockSubscription,
        TransactionSubscription, EventFilter, LiveEvent,
    };
    pub use crate::light_client::{
        LightClient, LightClientConfig, HeaderSyncState, MerkleVerifiedResponse,
        LightClientProof,
    };
    pub use crate::multi_network::{
        MultiNetworkClient, NetworkHandle, NetworkId as ClientNetworkId,
        NetworkSelector,
    };
    pub use crate::privacy::{
        PrivacyConnection, AnonymousConnection, ConnectionObfuscation,
        PrivacyRoutingConfig,
    };
    pub use crate::signing::{
        RequestSigner, SigningKey, SignedRequest, SignatureAlgorithm,
    };
    pub use crate::verification::{
        ResponseVerifier, MerkleVerifier, AttestationVerifier as ClientAttestationVerifier,
        VerifiedResponse,
    };
    pub use crate::{ClientError, ClientResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from client connection operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ClientError {
    /// Connection to infrastructure endpoint failed.
    #[error("connection failed to {endpoint}: {reason}")]
    ConnectionFailed {
        /// Endpoint that could not be reached.
        endpoint: String,
        /// Reason for failure.
        reason: String,
    },

    /// Authentication with the infrastructure failed.
    #[error("authentication failed: {reason}")]
    AuthenticationFailed {
        /// Reason for authentication failure.
        reason: String,
    },

    /// Request timed out waiting for response.
    #[error("request timeout after {timeout_ms}ms")]
    RequestTimeout {
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Response verification failed (Merkle proof or attestation invalid).
    #[error("response verification failed: {reason}")]
    VerificationFailed {
        /// Reason verification failed.
        reason: String,
    },

    /// Network is not reachable or not configured.
    #[error("network not available: {network}")]
    NetworkUnavailable {
        /// Network identifier.
        network: String,
    },

    /// All connection pool entries are exhausted.
    #[error("connection pool exhausted")]
    PoolExhausted,

    /// Transaction submission was rejected by the node.
    #[error("transaction rejected: {reason}")]
    TransactionRejected {
        /// Reason for rejection.
        reason: String,
    },

    /// A response from the node was malformed or failed deserialization.
    #[error("invalid response: {reason}")]
    InvalidResponse {
        /// Description of what was wrong with the response.
        reason: String,
    },

    /// A subscription was closed unexpectedly.
    #[error("subscription closed: {reason}")]
    SubscriptionClosed {
        /// Reason the subscription was closed.
        reason: String,
    },
}

/// Convenience alias for client results.
pub type ClientResult<T> = Result<T, ClientError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default connection timeout in milliseconds.
pub const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 5_000;

/// Default request timeout in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// Default connection pool size per endpoint.
pub const DEFAULT_POOL_SIZE: usize = 10;

/// Maximum reconnection attempts before failing permanently.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 5;

/// Initial reconnection delay in milliseconds (exponential backoff base).
pub const INITIAL_RECONNECT_DELAY_MS: u64 = 100;

/// Maximum reconnection delay in milliseconds.
pub const MAX_RECONNECT_DELAY_MS: u64 = 30_000;

/// Default page size for paginated queries.
pub const DEFAULT_PAGE_SIZE: usize = 100;

/// Maximum page size for paginated queries.
pub const MAX_PAGE_SIZE: usize = 1_000;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_values_are_ordered() {
        assert!(DEFAULT_CONNECTION_TIMEOUT_MS < DEFAULT_REQUEST_TIMEOUT_MS);
    }

    #[test]
    fn reconnect_delays_are_ordered() {
        assert!(INITIAL_RECONNECT_DELAY_MS < MAX_RECONNECT_DELAY_MS);
    }

    #[test]
    fn page_sizes_are_ordered() {
        assert!(DEFAULT_PAGE_SIZE <= MAX_PAGE_SIZE);
    }
}
