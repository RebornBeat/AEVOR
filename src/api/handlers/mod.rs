use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum::Extension;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::api::ApiContext;
use crate::core::block::{Block, BlockStatus};
use crate::core::object::ObjectID;
use crate::core::transaction::{Transaction, TransactionStatus};
use crate::error::AevorError;

mod block;
mod health;
mod object;
mod transaction;
mod validator;

// Re-export handler functions
pub use block::{get_block, get_blocks, get_uncorrupted_chains};
pub use health::health_check;
pub use object::{get_object, get_objects};
pub use transaction::{get_transaction, get_transactions, submit_transaction};
pub use validator::{get_validator, get_validators};

/// Response format for API endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the request was successful
    pub success: bool,
    
    /// Response data (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    
    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Creates a successful response with data
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    /// Creates a successful response with no data
    pub fn success_empty() -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            error: None,
        }
    }
    
    /// Creates an error response
    pub fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Represents the chain status response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainStatus {
    /// Current block height
    pub height: u64,
    
    /// Latest block hash
    pub latest_block_hash: String,
    
    /// Latest uncorrupted block hash
    pub latest_uncorrupted_hash: String,
    
    /// Number of pending transactions
    pub pending_tx_count: usize,
    
    /// Consensus status
    pub consensus: ConsensusStatus,
    
    /// Chain ID
    pub chain_id: String,
    
    /// Software version
    pub version: String,
    
    /// Network name
    pub network: String,
    
    /// Number of active validators
    pub validator_count: usize,
    
    /// Node uptime in seconds
    pub uptime: u64,
    
    /// Current transactions per second
    pub tps: f64,
}

/// Represents the consensus status
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// Consensus algorithm
    pub algorithm: String,
    
    /// Number of uncorrupted chains
    pub uncorrupted_chain_count: usize,
    
    /// Finality delay (in blocks)
    pub finality_delay: u64,
    
    /// Synchronization status
    pub synchronized: bool,
    
    /// Whether this node is a validator
    pub is_validator: bool,
}

/// Common pagination parameters
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: usize,
    
    /// Number of items per page
    #[serde(default = "default_limit")]
    pub limit: usize,
}

/// Block filtering parameters
#[derive(Debug, Deserialize)]
pub struct BlockFilterParams {
    /// Minimum block height
    pub min_height: Option<u64>,
    
    /// Maximum block height
    pub max_height: Option<u64>,
    
    /// Block status
    pub status: Option<BlockStatus>,
    
    /// Validator ID
    pub validator: Option<String>,
}

/// Transaction filtering parameters
#[derive(Debug, Deserialize)]
pub struct TransactionFilterParams {
    /// Transaction status
    pub status: Option<TransactionStatus>,
    
    /// Sender address
    pub sender: Option<String>,
    
    /// Block hash
    pub block: Option<String>,
    
    /// Minimum timestamp (seconds since epoch)
    pub min_timestamp: Option<u64>,
    
    /// Maximum timestamp (seconds since epoch)
    pub max_timestamp: Option<u64>,
}

/// Object filtering parameters
#[derive(Debug, Deserialize)]
pub struct ObjectFilterParams {
    /// Object type
    pub object_type: Option<String>,
    
    /// Owner address
    pub owner: Option<String>,
    
    /// Whether to include deleted objects
    #[serde(default)]
    pub include_deleted: bool,
}

// Default values for pagination
fn default_page() -> usize {
    1
}

fn default_limit() -> usize {
    10
}

/// Get chain status handler
pub async fn get_chain_status(
    Extension(context): Extension<ApiContext>,
) -> impl IntoResponse {
    debug!("Handling get_chain_status request");
    
    // Get required information from blockchain
    match context.blockchain.get_status().await {
        Ok(status) => {
            let response = ApiResponse::success(status);
            Json(response).into_response()
        }
        Err(e) => {
            error!("Failed to get chain status: {}", e);
            let response = ApiResponse::<()>::error(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

// Handle AevorError in responses
impl IntoResponse for AevorError {
    fn into_response(self) -> Response {
        let status = match self {
            AevorError::Validation(_) => StatusCode::BAD_REQUEST,
            AevorError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AevorError::Authorization(_) => StatusCode::FORBIDDEN,
            AevorError::API(_) => StatusCode::BAD_REQUEST,
            AevorError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        let response = ApiResponse::<()>::error(self.to_string());
        (status, Json(response)).into_response()
    }
}
