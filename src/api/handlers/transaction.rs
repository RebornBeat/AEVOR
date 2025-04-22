use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum::Extension;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::api::ApiContext;
use crate::api::handlers::{ApiResponse, PaginationParams, TransactionFilterParams};
use crate::core::transaction::{Transaction, TransactionStatus, TransactionType};
use crate::core::transaction::security::SecurityLevel;

/// Response for the get_transactions endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionsResponse {
    /// List of transactions
    pub transactions: Vec<TransactionInfo>,
    
    /// Total number of transactions matching the filter
    pub total: usize,
    
    /// Current page
    pub page: usize,
    
    /// Number of items per page
    pub limit: usize,
}

/// Transaction information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// Transaction hash
    pub hash: String,
    
    /// Sender address (hex-encoded)
    pub sender: String,
    
    /// Transaction nonce
    pub nonce: u64,
    
    /// Gas limit
    pub gas_limit: u64,
    
    /// Gas price
    pub gas_price: u64,
    
    /// Transaction type
    pub transaction_type: TransactionType,
    
    /// Transaction status
    pub status: TransactionStatus,
    
    /// Current security level
    pub security_level: SecurityLevel,
    
    /// Transaction creation timestamp
    pub created_at: u64,
    
    /// Block inclusion timestamp (if included)
    pub included_at: Option<u64>,
    
    /// Execution timestamp (if executed)
    pub executed_at: Option<u64>,
    
    /// Gas used (if executed)
    pub gas_used: Option<u64>,
    
    /// Error message (if failed)
    pub error: Option<String>,
    
    /// Block hash (if included)
    pub block_hash: Option<String>,
    
    /// Number of validator confirmations
    pub confirmation_count: usize,
    
    /// Transaction data summary
    pub data_summary: String,
}

/// Request for submitting a transaction
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    /// Transaction bytes (hex-encoded)
    pub transaction: String,
    
    /// Whether to wait for confirmation
    #[serde(default)]
    pub wait_for_confirmation: bool,
    
    /// Minimum security level to wait for
    #[serde(default)]
    pub min_security_level: Option<SecurityLevel>,
    
    /// Maximum wait time in milliseconds
    #[serde(default = "default_max_wait_ms")]
    pub max_wait_ms: u64,
}

fn default_max_wait_ms() -> u64 {
    5000 // 5 seconds
}

/// Response for submitting a transaction
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    /// Transaction hash
    pub hash: String,
    
    /// Transaction status
    pub status: TransactionStatus,
    
    /// Current security level (if waited for confirmation)
    pub security_level: Option<SecurityLevel>,
    
    /// Error message (if submission failed)
    pub error: Option<String>,
}

/// Handler for getting transactions with pagination and filtering
pub async fn get_transactions(
    Extension(context): Extension<ApiContext>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<TransactionFilterParams>,
) -> impl IntoResponse {
    debug!("Handling get_transactions request: page={}, limit={}", pagination.page, pagination.limit);
    
    // Validate pagination parameters
    if pagination.page == 0 {
        let response = ApiResponse::<()>::error("Page number must be greater than 0");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    if pagination.limit == 0 || pagination.limit > 100 {
        let response = ApiResponse::<()>::error("Limit must be between 1 and 100");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    // Convert filter parameters
    let sender_bytes = match filter.sender {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid sender address format");
                    return (StatusCode::BAD_REQUEST, Json(response)).into_response();
                }
            }
        },
        None => None,
    };
    
    let block_hash = match filter.block {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid block hash format");
                    return (StatusCode::BAD_REQUEST, Json(response)).into_response();
                }
            }
        },
        None => None,
    };
    
    // Fetch transactions from the blockchain
    let result = context.blockchain.get_transactions(
        pagination.page,
        pagination.limit,
        filter.status,
        sender_bytes,
        block_hash,
        filter.min_timestamp,
        filter.max_timestamp,
    ).await;
    
    match result {
        Ok((transactions, total)) => {
            // Convert transactions to API format
            let tx_infos = transactions.into_iter().map(transaction_to_info).collect();
            
            // Create response
            let response = TransactionsResponse {
                transactions: tx_infos,
                total,
                page: pagination.page,
                limit: pagination.limit,
            };
            
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Failed to get transactions: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))).into_response()
        }
    }
}

/// Handler for getting a specific transaction by hash
pub async fn get_transaction(
    Extension(context): Extension<ApiContext>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    debug!("Handling get_transaction request for: {}", hash_hex);
    
    // Decode the transaction hash
    let hash = match hex::decode(&hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid transaction hash format");
            return (StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };
    
    // Fetch the transaction from the blockchain
    let result = context.blockchain.get_transaction(&hash).await;
    
    match result {
        Ok(Some(transaction)) => {
            // Convert transaction to API format
            let tx_info = transaction_to_info(transaction);
            
            Json(ApiResponse::success(tx_info)).into_response()
        }
        Ok(None) => {
            let response = ApiResponse::<()>::error("Transaction not found");
            (StatusCode::NOT_FOUND, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed to get transaction: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))).into_response()
        }
    }
}

/// Handler for submitting a new transaction
pub async fn submit_transaction(
    Extension(context): Extension<ApiContext>,
    Json(request): Json<SubmitTransactionRequest>,
) -> impl IntoResponse {
    debug!("Handling submit_transaction request");
    
    // Decode the transaction bytes
    let tx_bytes = match hex::decode(&request.transaction) {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid transaction format");
            return (StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };
    
    // Parse the transaction
    let transaction = match Transaction::from_bytes(&tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            let response = ApiResponse::<()>::error(format!("Failed to parse transaction: {}", e));
            return (StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };
    
    // Submit the transaction to the blockchain
    let result = if request.wait_for_confirmation {
        // Wait for the transaction to be confirmed
        context.blockchain.submit_transaction_and_wait(
            transaction,
            request.min_security_level,
            std::time::Duration::from_millis(request.max_wait_ms),
        ).await
    } else {
        // Just submit the transaction without waiting
        context.blockchain.submit_transaction(transaction).await.map(|(hash, _)| (hash, None, None))
    };
    
    match result {
        Ok((hash, status, security_level)) => {
            // Create response
            let response = SubmitTransactionResponse {
                hash: hex::encode(hash),
                status: status.unwrap_or(TransactionStatus::Pending),
                security_level,
                error: None,
            };
            
            (StatusCode::ACCEPTED, Json(ApiResponse::success(response))).into_response()
        }
        Err(e) => {
            error!("Failed to submit transaction: {}", e);
            let status_code = match e {
                crate::error::AevorError::Validation(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            let response = SubmitTransactionResponse {
                hash: String::new(),
                status: TransactionStatus::Failed,
                security_level: None,
                error: Some(e.to_string()),
            };
            
            (status_code, Json(ApiResponse::success(response))).into_response()
        }
    }
}

/// Convert a Transaction to TransactionInfo for API responses
fn transaction_to_info(tx: Transaction) -> TransactionInfo {
    // Create a summary of the transaction data
    let data_summary = format!("{:?}", tx.data()); // This would be more sophisticated in a real implementation
    
    TransactionInfo {
        hash: hex::encode(tx.hash()),
        sender: hex::encode(tx.sender()),
        nonce: tx.nonce(),
        gas_limit: tx.gas_limit(),
        gas_price: tx.gas_price(),
        transaction_type: tx.transaction_type(),
        status: tx.status(),
        security_level: tx.security_level(),
        created_at: tx.created_at(),
        included_at: tx.included_at(),
        executed_at: tx.executed_at(),
        gas_used: tx.gas_used(),
        error: tx.error().cloned(),
        block_hash: None, // This would come from the blockchain in a real implementation
        confirmation_count: tx.confirmation_count(),
        data_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{Transaction, TransactionType, TransactionData};
    use crate::core::transaction::data::TransferData;
    use std::sync::Arc;
    use axum::http::Request;
    use axum::Router;
    use hyper::Body;
    use tower::ServiceExt;
    
    // Create a test transaction
    fn create_test_transaction() -> Transaction {
        let sender = vec![1, 2, 3, 4];
        let recipient = vec![5, 6, 7, 8];
        let amount = 100;
        let data = TransactionData::Transfer(TransferData {
            recipient,
            amount,
        });
        
        Transaction::new(
            sender,
            1, // nonce
            100000, // gas_limit
            1, // gas_price
            TransactionType::Transfer,
            data,
            vec![9, 10, 11, 12], // chain_id
        )
    }
    
    // Mock implementations would be added here for complete testing
}
