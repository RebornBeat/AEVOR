//! Client authentication: API keys, JWT tokens, and TEE-backed identity.

use serde::{Deserialize, Serialize};

/// Static API key authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKeyAuth {
    /// The raw API key string.
    pub key: String,
}

impl ApiKeyAuth {
    /// Create a new API key authenticator.
    pub fn new(key: impl Into<String>) -> Self { Self { key: key.into() } }
    /// Returns `true` if the key is non-empty.
    pub fn is_valid(&self) -> bool { !self.key.is_empty() }
}

/// Short-lived JWT bearer token authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtAuth {
    /// The encoded JWT string (header.payload.signature).
    pub token: String,
}

impl JwtAuth {
    /// Create a JWT authenticator from a token string.
    pub fn new(token: impl Into<String>) -> Self { Self { token: token.into() } }
    /// Returns `true` if the token string is non-empty.
    pub fn is_valid(&self) -> bool { !self.token.is_empty() }
}

/// TEE-backed client authentication using enclave attestation.
///
/// The client proves it is running inside a genuine TEE enclave before
/// being granted access to privacy-sensitive endpoints.
pub struct TeeBackedClientAuth {
    /// Platform the client TEE is running on.
    pub platform: aevor_core::tee::TeePlatform,
}

impl TeeBackedClientAuth {
    /// Create a TEE-backed authenticator for the given platform.
    pub fn new(platform: aevor_core::tee::TeePlatform) -> Self { Self { platform } }
}

/// Combined credential bundle — holds whichever auth method is configured.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthCredentials {
    /// Static API key (if using key-based auth).
    pub api_key: Option<String>,
    /// JWT token (if using token-based auth).
    pub jwt: Option<String>,
}

impl AuthCredentials {
    /// Create credentials with an API key.
    pub fn from_api_key(key: impl Into<String>) -> Self {
        Self { api_key: Some(key.into()), jwt: None }
    }
    /// Create credentials with a JWT token.
    pub fn from_jwt(token: impl Into<String>) -> Self {
        Self { api_key: None, jwt: Some(token.into()) }
    }
    /// Returns `true` if any credential is present.
    pub fn is_empty(&self) -> bool { self.api_key.is_none() && self.jwt.is_none() }
}

/// A live authentication token returned after a successful auth handshake.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthToken {
    /// The bearer token string to include in request headers.
    pub token: String,
    /// Unix timestamp (seconds) at which this token expires.
    pub expires_at: u64,
}

impl AuthToken {
    /// Returns `true` if the token has not yet expired.
    pub fn is_valid(&self, now_unix: u64) -> bool {
        !self.token.is_empty() && now_unix < self.expires_at
    }
}

/// Request to refresh an expired token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthRefresh {
    /// The old (expired or near-expiry) token to exchange.
    pub old_token: String,
}

/// Client-side authentication facade.
pub struct ClientAuth;

impl ClientAuth {
    /// Create API key credentials from a raw key string.
    pub fn from_api_key(key: String) -> ApiKeyAuth { ApiKeyAuth { key } }
    /// Create JWT credentials from a token string.
    pub fn from_jwt(token: String) -> JwtAuth { JwtAuth { token } }
}
