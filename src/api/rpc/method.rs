use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, error, info};

use crate::api::ApiContext;
use crate::api::rpc::{RpcRequest, RpcResponse, create_rpc_success, create_rpc_error, parse_params, params_to_map, aevor_error_to_rpc_error, error_codes};
use crate::core::block::BlockStatus;
use crate::core::object::ObjectID;
use crate::core::transaction::TransactionStatus;

// =================== Chain Methods ===================

/// Handler for the chain_getStatus RPC method
pub async fn chain_get_status(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling chain_getStatus RPC request");
    
    // This method doesn't require any parameters
    
    // Get chain status from the blockchain
    match context.blockchain.get_status().await {
        Ok(status) => create_rpc_success(status, request.id),
        Err(e) => {
            error!("Failed to get chain status: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the chain_getBlock RPC method
#[derive(Debug, Deserialize)]
struct GetBlockParams {
    /// Block hash or height
    hash_or_height: String,
}

/// Handler for the chain_getBlock RPC method
pub async fn chain_get_block(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling chain_getBlock RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetBlockParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Try to parse as a block height
    let result = if let Ok(height) = params.hash_or_height.parse::<u64>() {
        context.blockchain.get_block_by_height(height).await
    } else {
        // Try to parse as a block hash
        match hex::decode(&params.hash_or_height) {
            Ok(hash) => context.blockchain.get_block_by_hash(&hash).await,
            Err(_) => return create_rpc_error(
                error_codes::INVALID_PARAMS,
                "Invalid block hash format".to_string(),
                None,
                request.id,
            ),
        }
    };
    
    match result {
        Ok(Some(block)) => {
            // Convert block to JSON format
            let block_json = json!({
                "hash": hex::encode(block.hash()),
                "height": block.height(),
                "timestamp": block.timestamp(),
                "status": block.status(),
                "transaction_count": block.transaction_count(),
                "validator": hex::encode(block.validator()),
                "execution_time_ms": block.executed_at().map(|_| 0), // Placeholder
                "gas_used": block.gas_used(),
                "size": block.size(),
                "reference_height": block.reference_height(),
                "parent_count": block.parent_count(),
                "parent_hashes": block.previous_hashes().iter()
                    .map(|hash| hex::encode(hash))
                    .collect::<Vec<String>>(),
                "confirmation_count": block.confirmation_count(),
                "transactions": block.transactions().iter()
                    .map(|tx| hex::encode(tx.hash()))
                    .collect::<Vec<String>>(),
            });
            
            create_rpc_success(block_json, request.id)
        },
        Ok(None) => create_rpc_error(
            error_codes::SERVER_ERROR,
            "Block not found".to_string(),
            None,
            request.id,
        ),
        Err(e) => {
            error!("Failed to get block: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the chain_getBlocks RPC method
#[derive(Debug, Deserialize)]
struct GetBlocksParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    page: usize,
    
    /// Number of items per page
    #[serde(default = "default_limit")]
    limit: usize,
    
    /// Minimum block height
    min_height: Option<u64>,
    
    /// Maximum block height
    max_height: Option<u64>,
    
    /// Block status
    status: Option<BlockStatus>,
    
    /// Validator ID (hex-encoded)
    validator: Option<String>,
}

// Default values for pagination
fn default_page() -> usize {
    1
}

fn default_limit() -> usize {
    10
}

/// Handler for the chain_getBlocks RPC method
pub async fn chain_get_blocks(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling chain_getBlocks RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetBlocksParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Validate pagination parameters
    if params.page == 0 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Page number must be greater than 0".to_string(),
            None,
            request.id,
        );
    }
    
    if params.limit == 0 || params.limit > 100 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Limit must be between 1 and 100".to_string(),
            None,
            request.id,
        );
    }
    
    // Convert validator hex string to bytes if provided
    let validator_bytes = match params.validator {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => return create_rpc_error(
                    error_codes::INVALID_PARAMS,
                    "Invalid validator ID format".to_string(),
                    None,
                    request.id,
                ),
            }
        },
        None => None,
    };
    
    // Fetch blocks from the blockchain
    match context.blockchain.get_blocks(
        params.page,
        params.limit,
        params.min_height,
        params.max_height,
        params.status,
        validator_bytes,
    ).await {
        Ok((blocks, total)) => {
            // Convert blocks to JSON format
            let block_jsons = blocks.into_iter().map(|block| {
                json!({
                    "hash": hex::encode(block.hash()),
                    "height": block.height(),
                    "timestamp": block.timestamp(),
                    "status": block.status(),
                    "transaction_count": block.transaction_count(),
                    "validator": hex::encode(block.validator()),
                    "execution_time_ms": block.executed_at().map(|_| 0), // Placeholder
                    "gas_used": block.gas_used(),
                    "size": block.size(),
                    "reference_height": block.reference_height(),
                    "parent_count": block.parent_count(),
                    "parent_hashes": block.previous_hashes().iter()
                        .map(|hash| hex::encode(hash))
                        .collect::<Vec<String>>(),
                    "confirmation_count": block.confirmation_count(),
                })
            }).collect::<Vec<Value>>();
            
            // Create response
            let response = json!({
                "blocks": block_jsons,
                "total": total,
                "page": params.page,
                "limit": params.limit,
            });
            
            create_rpc_success(response, request.id)
        },
        Err(e) => {
            error!("Failed to get blocks: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Handler for the chain_getUncorruptedChains RPC method
pub async fn chain_get_uncorrupted_chains(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling chain_getUncorruptedChains RPC request");
    
    // This method doesn't require any parameters
    
    // Get uncorrupted chains from the consensus manager
    match context.consensus.get_uncorrupted_chains().await {
        Ok((chains, current_chain_id)) => {
            // Convert chains to JSON format
            let chain_jsons = chains.into_iter()
                .map(|chain| {
                    json!({
                        "id": chain.id,
                        "block_count": chain.blocks.len(),
                        "latest_block_hash": hex::encode(&chain.latest_block_hash),
                        "latest_height": chain.latest_height,
                        "genesis_block_hash": hex::encode(&chain.genesis_block_hash),
                        "creation_time": chain.creation_time,
                    })
                })
                .collect::<Vec<Value>>();
            
            // Create response
            let response = json!({
                "chains": chain_jsons,
                "current_chain_id": current_chain_id.unwrap_or_default(),
            });
            
            create_rpc_success(response, request.id)
        },
        Err(e) => {
            error!("Failed to get uncorrupted chains: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

// =================== Transaction Methods ===================

/// Parameters for the tx_getTransaction RPC method
#[derive(Debug, Deserialize)]
struct GetTransactionParams {
    /// Transaction hash (hex-encoded)
    hash: String,
}

/// Handler for the tx_getTransaction RPC method
pub async fn tx_get_transaction(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling tx_getTransaction RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetTransactionParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Convert hash to bytes
    let tx_hash = match hex::decode(&params.hash) {
        Ok(hash) => hash,
        Err(_) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Invalid transaction hash format".to_string(),
            None,
            request.id,
        ),
    };
    
    // Get transaction from the blockchain
    match context.blockchain.get_transaction(&tx_hash).await {
        Ok(Some(tx)) => {
            // Convert transaction to JSON format
            let tx_json = json!({
                "hash": hex::encode(tx.hash()),
                "sender": hex::encode(tx.sender()),
                "nonce": tx.nonce(),
                "gas_limit": tx.gas_limit(),
                "gas_price": tx.gas_price(),
                "transaction_type": tx.transaction_type(),
                "status": tx.status(),
                "privacy_level": tx.privacy_level(),
                "security_level": tx.security_level(),
                "created_at": tx.created_at(),
                "included_at": tx.included_at(),
                "executed_at": tx.executed_at(),
                "gas_used": tx.gas_used(),
                "error": tx.error(),
                "confirmation_count": tx.confirmation_count(),
                "chain_id": hex::encode(tx.chain_id()),
                "data": serde_json::to_value(tx.data()).unwrap_or(Value::Null),
            });
            
            create_rpc_success(tx_json, request.id)
        },
        Ok(None) => create_rpc_error(
            error_codes::SERVER_ERROR,
            "Transaction not found".to_string(),
            None,
            request.id,
        ),
        Err(e) => {
            error!("Failed to get transaction: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the tx_getTransactions RPC method
#[derive(Debug, Deserialize)]
struct GetTransactionsParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    page: usize,
    
    /// Number of items per page
    #[serde(default = "default_limit")]
    limit: usize,
    
    /// Transaction status
    status: Option<TransactionStatus>,
    
    /// Sender address (hex-encoded)
    sender: Option<String>,
    
    /// Block hash (hex-encoded)
    block_hash: Option<String>,
    
    /// Transaction type
    transaction_type: Option<String>,
}

/// Handler for the tx_getTransactions RPC method
pub async fn tx_get_transactions(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling tx_getTransactions RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetTransactionsParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Validate pagination parameters
    if params.page == 0 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Page number must be greater than 0".to_string(),
            None,
            request.id,
        );
    }
    
    if params.limit == 0 || params.limit > 100 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Limit must be between 1 and 100".to_string(),
            None,
            request.id,
        );
    }
    
    // Convert sender hex string to bytes if provided
    let sender_bytes = match params.sender {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => return create_rpc_error(
                    error_codes::INVALID_PARAMS,
                    "Invalid sender address format".to_string(),
                    None,
                    request.id,
                ),
            }
        },
        None => None,
    };
    
    // Convert block hash hex string to bytes if provided
    let block_hash_bytes = match params.block_hash {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => return create_rpc_error(
                    error_codes::INVALID_PARAMS,
                    "Invalid block hash format".to_string(),
                    None,
                    request.id,
                ),
            }
        },
        None => None,
    };
    
    // Parse transaction type if provided
    let tx_type = match params.transaction_type {
        Some(ref type_str) => {
            match crate::core::transaction::TransactionType::from_str(type_str) {
                Some(tx_type) => Some(tx_type),
                None => return create_rpc_error(
                    error_codes::INVALID_PARAMS,
                    format!("Invalid transaction type: {}", type_str),
                    None,
                    request.id,
                ),
            }
        },
        None => None,
    };
    
    // Fetch transactions from the blockchain
    match context.blockchain.get_transactions(
        params.page,
        params.limit,
        params.status,
        sender_bytes,
        block_hash_bytes,
        tx_type,
    ).await {
        Ok((transactions, total)) => {
            // Convert transactions to JSON format
            let tx_jsons = transactions.into_iter().map(|tx| {
                json!({
                    "hash": hex::encode(tx.hash()),
                    "sender": hex::encode(tx.sender()),
                    "nonce": tx.nonce(),
                    "gas_limit": tx.gas_limit(),
                    "gas_price": tx.gas_price(),
                    "transaction_type": tx.transaction_type(),
                    "status": tx.status(),
                    "security_level": tx.security_level(),
                    "created_at": tx.created_at(),
                    "included_at": tx.included_at(),
                    "gas_used": tx.gas_used(),
                    "confirmation_count": tx.confirmation_count(),
                })
            }).collect::<Vec<_>>();
            
            // Create response
            let response = json!({
                "transactions": tx_jsons,
                "total": total,
                "page": params.page,
                "limit": params.limit,
            });
            
            create_rpc_success(response, request.id)
        },
        Err(e) => {
            error!("Failed to get transactions: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the tx_submitTransaction RPC method
#[derive(Debug, Deserialize)]
struct SubmitTransactionParams {
    /// Transaction data (hex-encoded)
    data: String,
}

/// Handler for the tx_submitTransaction RPC method
pub async fn tx_submit_transaction(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling tx_submitTransaction RPC request");
    
    // Parse parameters
    let params = match parse_params::<SubmitTransactionParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Decode transaction data
    let tx_data = match hex::decode(&params.data) {
        Ok(data) => data,
        Err(_) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Invalid transaction data format".to_string(),
            None,
            request.id,
        ),
    };
    
    // Submit transaction to the blockchain
    match context.blockchain.submit_transaction(&tx_data).await {
        Ok(tx_hash) => {
            // Create response
            let response = json!({
                "hash": hex::encode(tx_hash),
                "status": "accepted",
            });
            
            create_rpc_success(response, request.id)
        },
        Err(e) => {
            error!("Failed to submit transaction: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

// =================== Object Methods ===================

/// Parameters for the object_getObject RPC method
#[derive(Debug, Deserialize)]
struct GetObjectParams {
    /// Object ID (hex-encoded)
    id: String,
}

/// Handler for the object_getObject RPC method
pub async fn object_get_object(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling object_getObject RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetObjectParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Decode object ID
    let object_id_bytes = match hex::decode(&params.id) {
        Ok(bytes) => bytes,
        Err(_) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Invalid object ID format".to_string(),
            None,
            request.id,
        ),
    };
    
    let object_id = ObjectID(object_id_bytes);
    
    // Get object from the blockchain
    match context.blockchain.get_object(&object_id).await {
        Ok(Some(object)) => {
            // Convert object to JSON format
            let object_json = json!({
                "id": hex::encode(&object.id().0),
                "object_type": object.object_type(),
                "status": object.status(),
                "owner": hex::encode(object.owner()),
                "version": object.version().number(),
                "created_by": object.version().created_by().map(hex::encode),
                "privacy_level": object.privacy_level(),
                "data_size": object.data().len(),
                "metadata": object.metadata().iter()
                    .map(|(k, v)| (k.clone(), hex::encode(v)))
                    .collect::<std::collections::HashMap<_, _>>(),
                "references": object.references().iter()
                    .map(|ref_id| hex::encode(&ref_id.0))
                    .collect::<Vec<_>>(),
                "capabilities": object.capabilities(),
                "in_superposition": object.is_in_superposition(),
                "security_level": object.security_level(),
                "created_at": object.created_at(),
                "updated_at": object.updated_at(),
            });
            
            create_rpc_success(object_json, request.id)
        },
        Ok(None) => create_rpc_error(
            error_codes::SERVER_ERROR,
            "Object not found".to_string(),
            None,
            request.id,
        ),
        Err(e) => {
            error!("Failed to get object: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the object_getObjects RPC method
#[derive(Debug, Deserialize)]
struct GetObjectsParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    page: usize,
    
    /// Number of items per page
    #[serde(default = "default_limit")]
    limit: usize,
    
    /// Object status
    status: Option<u8>,
    
    /// Owner address (hex-encoded)
    owner: Option<String>,
    
    /// Object type
    object_type: Option<u16>,
}

/// Handler for the object_getObjects RPC method
pub async fn object_get_objects(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling object_getObjects RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetObjectsParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Validate pagination parameters
    if params.page == 0 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Page number must be greater than 0".to_string(),
            None,
            request.id,
        );
    }
    
    if params.limit == 0 || params.limit > 100 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Limit must be between 1 and 100".to_string(),
            None,
            request.id,
        );
    }
    
    // Convert owner hex string to bytes if provided
    let owner_bytes = match params.owner {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => return create_rpc_error(
                    error_codes::INVALID_PARAMS,
                    "Invalid owner address format".to_string(),
                    None,
                    request.id,
                ),
            }
        },
        None => None,
    };
    
    // Fetch objects from the blockchain
    match context.blockchain.get_objects(
        params.page,
        params.limit,
        params.status,
        owner_bytes,
        params.object_type,
    ).await {
        Ok((objects, total)) => {
            // Convert objects to JSON format
            let object_jsons = objects.into_iter().map(|object| {
                json!({
                    "id": hex::encode(&object.id().0),
                    "object_type": object.object_type(),
                    "status": object.status(),
                    "owner": hex::encode(object.owner()),
                    "version": object.version().number(),
                    "privacy_level": object.privacy_level(),
                    "data_size": object.data().len(),
                    "in_superposition": object.is_in_superposition(),
                    "created_at": object.created_at(),
                    "updated_at": object.updated_at(),
                })
            }).collect::<Vec<_>>();
            
            // Create response
            let response = json!({
                "objects": object_jsons,
                "total": total,
                "page": params.page,
                "limit": params.limit,
            });
            
            create_rpc_success(response, request.id)
        },
        Err(e) => {
            error!("Failed to get objects: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the object_getSuperpositionedObject RPC method
#[derive(Debug, Deserialize)]
struct GetSuperpositionedObjectParams {
    /// Object ID (hex-encoded)
    id: String,
}

/// Handler for the object_getSuperpositionedObject RPC method
pub async fn object_get_superpositioned_object(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling object_getSuperpositionedObject RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetSuperpositionedObjectParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Decode object ID
    let object_id_bytes = match hex::decode(&params.id) {
        Ok(bytes) => bytes,
        Err(_) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Invalid object ID format".to_string(),
            None,
            request.id,
        ),
    };
    
    let object_id = ObjectID(object_id_bytes);
    
    // Get superpositioned object from the consensus manager
    match context.consensus.get_superpositioned_object(&object_id).await {
        Ok(Some(object)) => {
            // Check if the object is actually in superposition
            if !object.is_in_superposition() {
                return create_rpc_error(
                    error_codes::SERVER_ERROR,
                    "Object is not in superposition".to_string(),
                    None,
                    request.id,
                );
            }
            
            // Get the superpositioned states
            let superposition = object.superpositioned_states().unwrap();
            
            // Convert superpositioned states to JSON
            let states_json = superposition.potential_states().iter().map(|state| {
                json!({
                    "index": state.index,
                    "hash": hex::encode(&state.hash),
                    "tx_hash": hex::encode(&state.tx_hash),
                    "timestamp": state.timestamp,
                    "validator_confirmations": superposition.signature_count(state.index),
                })
            }).collect::<Vec<_>>();
            
            // Create response
            let response = json!({
                "id": hex::encode(&object.id().0),
                "object_type": object.object_type(),
                "status": object.status(),
                "owner": hex::encode(object.owner()),
                "potential_states": states_json,
                "is_finalized": superposition.is_finalized(),
                "finalized_state_index": superposition.finalized_state().map(|s| s.index),
                "creation_time": superposition.creation_time(),
                "finalization_deadline": superposition.finalization_deadline(),
                "is_expired": superposition.is_expired(),
            });
            
            create_rpc_success(response, request.id)
        },
        Ok(None) => create_rpc_error(
            error_codes::SERVER_ERROR,
            "Object not found".to_string(),
            None,
            request.id,
        ),
        Err(e) => {
            error!("Failed to get superpositioned object: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

// =================== Validator Methods ===================

/// Parameters for the validator_getValidators RPC method
#[derive(Debug, Deserialize)]
struct GetValidatorsParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    page: usize,
    
    /// Number of items per page
    #[serde(default = "default_limit")]
    limit: usize,
    
    /// Filter for active validators only
    #[serde(default)]
    active_only: bool,
}

/// Handler for the validator_getValidators RPC method
pub async fn validator_get_validators(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling validator_getValidators RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetValidatorsParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Validate pagination parameters
    if params.page == 0 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Page number must be greater than 0".to_string(),
            None,
            request.id,
        );
    }
    
    if params.limit == 0 || params.limit > 100 {
        return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Limit must be between 1 and 100".to_string(),
            None,
            request.id,
        );
    }
    
    // Fetch validators from the consensus manager
    match context.consensus.get_validators(
        params.page,
        params.limit,
        params.active_only,
    ).await {
        Ok((validators, total)) => {
            // Convert validators to JSON format
            let validator_jsons = validators.into_iter().map(|validator| {
                json!({
                    "id": hex::encode(&validator.id),
                    "name": validator.name,
                    "public_key": hex::encode(&validator.public_key),
                    "stake": validator.stake,
                    "active": validator.active,
                    "last_seen": validator.last_seen,
                    "metrics": {
                        "blocks_validated": validator.metrics.blocks_validated,
                        "blocks_produced": validator.metrics.blocks_produced,
                        "validations_missed": validator.metrics.validations_missed,
                        "validation_errors": validator.metrics.validation_errors,
                        "avg_validation_latency_ms": validator.metrics.avg_validation_latency_ms,
                        "uptime_percentage": validator.metrics.uptime_percentage,
                    }
                })
            }).collect::<Vec<_>>();
            
            // Create response
            let response = json!({
                "validators": validator_jsons,
                "total": total,
                "page": params.page,
                "limit": params.limit,
            });
            
            create_rpc_success(response, request.id)
        },
        Err(e) => {
            error!("Failed to get validators: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}

/// Parameters for the validator_getValidator RPC method
#[derive(Debug, Deserialize)]
struct GetValidatorParams {
    /// Validator ID (hex-encoded)
    id: String,
}

/// Handler for the validator_getValidator RPC method
pub async fn validator_get_validator(
    context: ApiContext,
    request: RpcRequest,
) -> RpcResponse {
    debug!("Handling validator_getValidator RPC request");
    
    // Parse parameters
    let params = match parse_params::<GetValidatorParams>(request.params) {
        Ok(params) => params,
        Err(e) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            e.to_string(),
            None,
            request.id,
        ),
    };
    
    // Decode validator ID
    let validator_id = match hex::decode(&params.id) {
        Ok(bytes) => bytes,
        Err(_) => return create_rpc_error(
            error_codes::INVALID_PARAMS,
            "Invalid validator ID format".to_string(),
            None,
            request.id,
        ),
    };
    
    // Get validator from the consensus manager
    match context.consensus.get_validator(&validator_id).await {
        Ok(Some(validator)) => {
            // Convert validator to JSON format
            let validator_json = json!({
                "id": hex::encode(&validator.id),
                "name": validator.name,
                "public_key": hex::encode(&validator.public_key),
                "stake": validator.stake,
                "active": validator.active,
                "last_seen": validator.last_seen,
                "metrics": {
                    "blocks_validated": validator.metrics.blocks_validated,
                    "blocks_produced": validator.metrics.blocks_produced,
                    "validations_missed": validator.metrics.validations_missed,
                    "validation_errors": validator.metrics.validation_errors,
                    "avg_validation_latency_ms": validator.metrics.avg_validation_latency_ms,
                    "uptime_percentage": validator.metrics.uptime_percentage,
                }
            });
            
            create_rpc_success(validator_json, request.id)
        },
        Ok(None) => create_rpc_error(
            error_codes::SERVER_ERROR,
            "Validator not found".to_string(),
            None,
            request.id,
        ),
        Err(e) => {
            error!("Failed to get validator: {}", e);
            aevor_error_to_rpc_error(e, request.id)
        }
    }
}
