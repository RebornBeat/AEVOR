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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_valid_when_non_empty() {
        assert!(ApiKeyAuth::new("my-secret-key").is_valid());
        assert!(!ApiKeyAuth::new("").is_valid());
    }

    #[test]
    fn jwt_auth_valid_when_non_empty() {
        assert!(JwtAuth::new("header.payload.sig").is_valid());
        assert!(!JwtAuth::new("").is_valid());
    }

    #[test]
    fn auth_credentials_from_api_key() {
        let creds = AuthCredentials::from_api_key("sk-123");
        assert_eq!(creds.api_key.as_deref(), Some("sk-123"));
        assert!(creds.jwt.is_none());
        assert!(!creds.is_empty());
    }

    #[test]
    fn auth_credentials_from_jwt() {
        let creds = AuthCredentials::from_jwt("eyJ...");
        assert!(creds.api_key.is_none());
        assert_eq!(creds.jwt.as_deref(), Some("eyJ..."));
        assert!(!creds.is_empty());
    }

    #[test]
    fn auth_credentials_empty_when_both_none() {
        let creds = AuthCredentials { api_key: None, jwt: None };
        assert!(creds.is_empty());
    }

    #[test]
    fn auth_token_valid_before_expiry() {
        let token = AuthToken { token: "tok".into(), expires_at: 1_000_000 };
        assert!(token.is_valid(999_999));
        assert!(!token.is_valid(1_000_000)); // at expiry = expired
        assert!(!token.is_valid(1_000_001));
    }

    #[test]
    fn auth_token_invalid_when_empty() {
        let token = AuthToken { token: String::new(), expires_at: u64::MAX };
        assert!(!token.is_valid(0));
    }

    #[test]
    fn client_auth_from_api_key() {
        let auth = ClientAuth::from_api_key("key-abc".into());
        assert_eq!(auth.key, "key-abc");
        assert!(auth.is_valid());
    }

    #[test]
    fn client_auth_from_jwt() {
        let auth = ClientAuth::from_jwt("jwt-token".into());
        assert_eq!(auth.token, "jwt-token");
        assert!(auth.is_valid());
    }
}
