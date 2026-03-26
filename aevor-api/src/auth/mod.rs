//! API authentication.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKey { pub key: String, pub scopes: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtToken { pub token: String, pub expires_at: u64 }
pub struct TeeBackedAuth;
pub struct AuthMiddleware;
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum PermissionScope { Read, Write, Admin, Validator }

pub struct ApiAuth;
impl ApiAuth {
    pub fn validate_key(key: &ApiKey) -> bool { !key.key.is_empty() }
}
