use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum::Extension;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::api::ApiContext;
use crate::api::handlers::{ApiResponse, BlockFilterParams, PaginationParams};
use crate::core::block::{Block, BlockStatus};

/// Response for the get_blocks endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct BlocksResponse {
    /// List of blocks
    pub blocks: Vec<BlockInfo>,
    
    /// Total number of blocks matching the filter
    pub total: usize,
    
    /// Current page
    pub page: usize,
    
    /// Number of items per page
    pub limit: usize,
}

/// Block information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block hash
    pub hash: String,
    
    /// Block height
    pub height: u64,
    
    /// Block timestamp
    pub timestamp: u64,
    
    /// Block status
    pub status: BlockStatus,
    
    /// Number of transactions
    pub transaction_count: usize,
    
    /// Validator ID (hex-encoded)
    pub validator: String,
    
    /// Block execution time in milliseconds (if executed)
    pub execution_time_ms: Option<u64>,
    
    /// Total gas used (if executed)
    pub gas_used: Option<u64>,
    
    /// Block size in bytes
    pub size: usize,
    
    /// Reference height (for topological ordering)
    pub reference_height: u64,
    
    /// Number of parent blocks
    pub parent_count: usize,
    
    /// Parent block hashes
    pub parent_hashes: Vec<String>,
    
    /// Number of validator confirmations
    pub confirmation_count: usize,
}

/// Response for the get_uncorrupted_chains endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct UncorruptedChainsResponse {
    /// List of uncorrupted chains
    pub chains: Vec<UncorruptedChainInfo>,
    
    /// Current main chain ID
    pub current_chain_id: String,
}

/// Uncorrupted chain information
#[derive(Debug, Serialize, Deserialize)]
pub struct UncorruptedChainInfo {
    /// Chain ID
    pub id: String,
    
    /// Number of blocks in the chain
    pub block_count: usize,
    
    /// Latest block hash
    pub latest_block_hash: String,
    
    /// Latest block height
    pub latest_height: u64,
    
    /// Genesis block hash
    pub genesis_block_hash: String,
    
    /// Creation timestamp
    pub creation_time: u64,
}

/// Handler for getting blocks with pagination and filtering
pub async fn get_blocks(
    Extension(context): Extension<ApiContext>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<BlockFilterParams>,
) -> impl IntoResponse {
    debug!("Handling get_blocks request: page={}, limit={}", pagination.page, pagination.limit);
    
    // Validate pagination parameters
    if pagination.page == 0 {
        let response = ApiResponse::<()>::error("Page number must be greater than 0");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    if pagination.limit == 0 || pagination.limit > 100 {
        let response = ApiResponse::<()>::error("Limit must be between 1 and 100");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    // Convert validator hex string to bytes if provided
    let validator_bytes = match filter.validator {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid validator ID format");
                    return (StatusCode::BAD_REQUEST, Json(response)).into_response();
                }
            }
        },
        None => None,
    };
    
    // Fetch blocks from the blockchain
    let result = context.blockchain.get_blocks(
        pagination.page,
        pagination.limit,
        filter.min_height,
        filter.max_height,
        filter.status,
        validator_bytes,
    ).await;
    
    match result {
        Ok((blocks, total)) => {
            // Convert blocks to API format
            let block_infos = blocks.into_iter().map(block_to_info).collect();
            
            // Create response
            let response = BlocksResponse {
                blocks: block_infos,
                total,
                page: pagination.page,
                limit: pagination.limit,
            };
            
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Failed to get blocks: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))).into_response()
        }
    }
}

/// Handler for getting a specific block by hash or height
pub async fn get_block(
    Extension(context): Extension<ApiContext>,
    Path(hash_or_height): Path<String>,
) -> impl IntoResponse {
    debug!("Handling get_block request for: {}", hash_or_height);
    
    // Determine if the parameter is a hash or height
    let result = if let Ok(height) = hash_or_height.parse::<u64>() {
        // It's a height
        context.blockchain.get_block_by_height(height).await
    } else {
        // It's a hash (try to decode from hex)
        match hex::decode(&hash_or_height) {
            Ok(hash) => context.blockchain.get_block(&hash).await,
            Err(_) => {
                let response = ApiResponse::<()>::error("Invalid block hash format");
                return (StatusCode::BAD_REQUEST, Json(response)).into_response();
            }
        }
    };
    
    match result {
        Ok(Some(block)) => {
            // Convert block to API format
            let block_info = block_to_info(block);
            
            Json(ApiResponse::success(block_info)).into_response()
        }
        Ok(None) => {
            let response = ApiResponse::<()>::error("Block not found");
            (StatusCode::NOT_FOUND, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed to get block: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))).into_response()
        }
    }
}

/// Handler for getting uncorrupted chains
pub async fn get_uncorrupted_chains(
    Extension(context): Extension<ApiContext>,
) -> impl IntoResponse {
    debug!("Handling get_uncorrupted_chains request");
    
    // Get uncorrupted chains from consensus manager
    let result = context.consensus.get_uncorrupted_chains().await;
    
    match result {
        Ok((chains, current_chain_id)) => {
            // Convert chains to API format
            let chain_infos = chains.into_iter().map(|chain| {
                UncorruptedChainInfo {
                    id: chain.id.clone(),
                    block_count: chain.blocks.len(),
                    latest_block_hash: hex::encode(&chain.latest_block_hash),
                    latest_height: chain.latest_height,
                    genesis_block_hash: hex::encode(&chain.genesis_block_hash),
                    creation_time: chain.creation_time,
                }
            }).collect();
            
            // Create response
            let response = UncorruptedChainsResponse {
                chains: chain_infos,
                current_chain_id,
            };
            
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Failed to get uncorrupted chains: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))).into_response()
        }
    }
}

/// Convert a Block to BlockInfo for API responses
fn block_to_info(block: Block) -> BlockInfo {
    BlockInfo {
        hash: hex::encode(block.hash()),
        height: block.height(),
        timestamp: block.timestamp(),
        status: block.status(),
        transaction_count: block.transaction_count(),
        validator: hex::encode(block.validator()),
        execution_time_ms: block.executed_at().map(|_| 0), // Real impl would calculate this
        gas_used: block.gas_used(),
        size: block.size(),
        reference_height: block.reference_height(),
        parent_count: block.parent_count(),
        parent_hashes: block.previous_hashes().iter().map(hex::encode).collect(),
        confirmation_count: block.confirmation_count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::{Block, BlockHeader, BlockBuilder};
    use crate::consensus::{Manager as ConsensusManager, UncorruptedChain};
    use crate::core::Blockchain;
    use crate::execution::Engine as ExecutionEngine;
    use std::sync::Arc;
    use axum::http::Request;
    use axum::Router;
    use axum::body::Body;
    use hyper::StatusCode;
    use tower::ServiceExt;
    
    // Mock implementations for testing
    struct MockBlockchain;
    struct MockConsensusManager;
    struct MockExecutionEngine;
    
    #[async_trait::async_trait]
    impl Blockchain for MockBlockchain {
        async fn get_blocks(
            &self,
            page: usize,
            limit: usize,
            min_height: Option<u64>,
            max_height: Option<u64>,
            status: Option<BlockStatus>,
            validator: Option<Vec<u8>>,
        ) -> crate::error::Result<(Vec<Block>, usize)> {
            // Return some mock blocks
            let blocks = vec![
                create_test_block(1),
                create_test_block(2),
            ];
            
            Ok((blocks, 2))
        }
        
        async fn get_block(&self, hash: &[u8]) -> crate::error::Result<Option<Block>> {
            // Return a mock block if hash starts with 01
            if hash.starts_with(&[1]) {
                Ok(Some(create_test_block(1)))
            } else {
                Ok(None)
            }
        }
        
        async fn get_block_by_height(&self, height: u64) -> crate::error::Result<Option<Block>> {
            // Return a mock block if height is 1
            if height == 1 {
                Ok(Some(create_test_block(1)))
            } else {
                Ok(None)
            }
        }
    }
    
    #[async_trait::async_trait]
    impl ConsensusManager for MockConsensusManager {
        async fn get_uncorrupted_chains(&self) -> crate::error::Result<(Vec<UncorruptedChain>, String)> {
            // Return some mock chains
            let chain = UncorruptedChain {
                id: "chain1".to_string(),
                blocks: vec![(vec![1; 32], create_test_block(1))].into_iter().collect(),
                blocks_by_height: vec![(1, vec![vec![1; 32]].into_iter().collect())].into_iter().collect(),
                latest_block_hash: vec![1; 32],
                latest_height: 1,
                genesis_block_hash: vec![0; 32],
                creation_time: 1000000,
            };
            
            Ok((vec![chain], "chain1".to_string()))
        }
    }
    
    impl ExecutionEngine for MockExecutionEngine {
        // Implement required methods for testing
    }
    
    // Helper function to create a test block
    fn create_test_block(height: u64) -> Block {
        BlockBuilder::new()
            .height(height)
            .previous_hash(vec![0; 32])
            .reference_height(height)
            .validator(vec![1, 2, 3, 4])
            .build()
            .unwrap()
    }
    
    #[tokio::test]
    async fn test_get_blocks() {
        // Create a test context
        let context = ApiContext {
            blockchain: Arc::new(MockBlockchain),
            consensus: Arc::new(MockConsensusManager),
            execution: Arc::new(MockExecutionEngine),
            config: Arc::new(crate::config::ApiConfig::default()),
        };
        
        // Create a test router
        let app = Router::new()
            .route("/blocks", axum::routing::get(get_blocks))
            .layer(axum::Extension(context));
        
        // Create a request
        let request = Request::builder()
            .uri("/blocks?page=1&limit=10")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        
        // Send the request
        let response = app.oneshot(request).await.unwrap();
        
        // Check the response
        assert_eq!(response.status(), StatusCode::OK);
        
        // Extract and parse the response body
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        let response: ApiResponse<BlocksResponse> = serde_json::from_str(&body_str).unwrap();
        
        // Validate the response
        assert!(response.success);
        let blocks_response = response.data.unwrap();
        assert_eq!(blocks_response.blocks.len(), 2);
        assert_eq!(blocks_response.total, 2);
        assert_eq!(blocks_response.page, 1);
        assert_eq!(blocks_response.limit, 10);
    }
    
    // More tests would be implemented for other endpoints
}
