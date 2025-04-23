use axum::extract::Extension;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, Map, Number};
use tracing::{debug, error, info};

use crate::api::ApiContext;
use crate::core::object::ObjectID;
use crate::error::{AevorError, Result};

mod methods;

// Re-export methods
pub use methods::*;

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    /// JSON-RPC version (should be "2.0")
    pub jsonrpc: String,
    
    /// Method name
    pub method: String,
    
    /// Method parameters
    pub params: Option<Value>,
    
    /// Request ID
    pub id: Value,
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    /// JSON-RPC version
    pub jsonrpc: String,
    
    /// Response result (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    
    /// Response error (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    
    /// Request ID
    pub id: Value,
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// Error code
    pub code: i32,
    
    /// Error message
    pub message: String,
    
    /// Additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Standard JSON-RPC error codes
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const SERVER_ERROR: i32 = -32000;
    
    // Aevor-specific error codes
    pub const TRANSACTION_ERROR: i32 = -32100;
    pub const VALIDATION_ERROR: i32 = -32101;
    pub const CONSENSUS_ERROR: i32 = -32102;
    pub const EXECUTION_ERROR: i32 = -32103;
    pub const STORAGE_ERROR: i32 = -32104;
}

/// Handler for JSON-RPC requests
pub async fn handle_rpc_request(
    Extension(context): Extension<ApiContext>,
    Json(request): Json<RpcRequest>,
) -> impl IntoResponse {
    debug!("Handling RPC request: method={}", request.method);
    
    // Validate JSON-RPC version
    if request.jsonrpc != "2.0" {
        let response = create_rpc_error(
            error_codes::INVALID_REQUEST,
            "Invalid JSON-RPC version. Expected 2.0".to_string(),
            None,
            request.id,
        );
        return Json(response).into_response();
    }
    
    // Handle the request based on the method
    let response = match request.method.as_str() {
        // Chain methods
        "chain_getStatus" => chain_get_status(context, request).await,
        "chain_getBlock" => chain_get_block(context, request).await,
        "chain_getBlocks" => chain_get_blocks(context, request).await,
        "chain_getUncorruptedChains" => chain_get_uncorrupted_chains(context, request).await,
        
        // Transaction methods
        "tx_getTransaction" => tx_get_transaction(context, request).await,
        "tx_getTransactions" => tx_get_transactions(context, request).await,
        "tx_submitTransaction" => tx_submit_transaction(context, request).await,
        
        // Object methods
        "object_getObject" => object_get_object(context, request).await,
        "object_getObjects" => object_get_objects(context, request).await,
        "object_getSuperpositionedObject" => object_get_superpositioned_object(context, request).await,
        
        // Validator methods
        "validator_getValidators" => validator_get_validators(context, request).await,
        "validator_getValidator" => validator_get_validator(context, request).await,
        
        // Method not found
        _ => {
            error!("RPC method not found: {}", request.method);
            create_rpc_error(
                error_codes::METHOD_NOT_FOUND,
                format!("Method not found: {}", request.method),
                None,
                request.id,
            )
        }
    };
    
    Json(response).into_response()
}

/// Creates a successful RPC response
pub fn create_rpc_success<T: Serialize>(result: T, id: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
        error: None,
        id,
    }
}

/// Creates an error RPC response
pub fn create_rpc_error(code: i32, message: String, data: Option<Value>, id: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(RpcError {
            code,
            message,
            data,
        }),
        id,
    }
}

/// Helper function to parse parameters as a specific type
pub fn parse_params<T: for<'de> Deserialize<'de>>(params: Option<Value>) -> Result<T> {
    match params {
        Some(params) => serde_json::from_value(params)
            .map_err(|e| AevorError::api(format!("Invalid parameters: {}", e))),
        None => Err(AevorError::api("Parameters required but not provided")),
    }
}

/// Helper function to convert parameters to a map
pub fn params_to_map(params: Option<Value>) -> Result<Map<String, Value>> {
    match params {
        Some(Value::Object(map)) => Ok(map),
        Some(_) => Err(AevorError::api("Parameters must be an object")),
        None => Ok(Map::new()),
    }
}

/// Convert AevorError to RPC error
pub fn aevor_error_to_rpc_error(error: AevorError, id: Value) -> RpcResponse {
    let (code, message) = match error {
        AevorError::Validation(_) => (error_codes::VALIDATION_ERROR, error.to_string()),
        AevorError::Blockchain(_) => (error_codes::TRANSACTION_ERROR, error.to_string()),
        AevorError::Consensus(_) => (error_codes::CONSENSUS_ERROR, error.to_string()),
        AevorError::Execution(_) => (error_codes::EXECUTION_ERROR, error.to_string()),
        AevorError::Storage(_) => (error_codes::STORAGE_ERROR, error.to_string()),
        _ => (error_codes::INTERNAL_ERROR, error.to_string()),
    };
    
    create_rpc_error(code, message, None, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_create_rpc_success() {
        let result = json!({
            "key": "value",
            "number": 42
        });
        let id = json!(1);
        
        let response = create_rpc_success(result, id.clone());
        
        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, id);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }
    
    #[test]
    fn test_create_rpc_error() {
        let id = json!(1);
        
        let response = create_rpc_error(
            error_codes::METHOD_NOT_FOUND,
            "Method not found".to_string(),
            None,
            id.clone(),
        );
        
        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, id);
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        
        let error = response.error.unwrap();
        assert_eq!(error.code, error_codes::METHOD_NOT_FOUND);
        assert_eq!(error.message, "Method not found");
        assert!(error.data.is_none());
    }
    
    #[test]
    fn test_parse_params() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct TestParams {
            key: String,
            value: i32,
        }
        
        let params = json!({
            "key": "test",
            "value": 42
        });
        
        let result: TestParams = parse_params(Some(params)).unwrap();
        assert_eq!(result.key, "test");
        assert_eq!(result.value, 42);
        
        // Test with missing params
        let result: Result<TestParams> = parse_params(None);
        assert!(result.is_err());
        
        // Test with invalid params
        let params = json!({
            "key": "test",
            "value": "not a number"
        });
        
        let result: Result<TestParams> = parse_params(Some(params));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_params_to_map() {
        let params = json!({
            "key1": "value1",
            "key2": 42
        });
        
        let map = params_to_map(Some(params)).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("key1").unwrap(), &json!("value1"));
        assert_eq!(map.get("key2").unwrap(), &json!(42));
        
        // Test with non-object params
        let params = json!([1, 2, 3]);
        let result = params_to_map(Some(params));
        assert!(result.is_err());
        
        // Test with null params
        let map = params_to_map(None).unwrap();
        assert_eq!(map.len(), 0);
    }
}
