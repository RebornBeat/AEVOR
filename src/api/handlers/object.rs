use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum::Extension;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::api::ApiContext;
use crate::api::handlers::{ApiResponse, ObjectFilterParams, PaginationParams};
use crate::core::object::{Object, ObjectID, ObjectStatus, ObjectType};

/// Response for the get_objects endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectsResponse {
    /// List of objects
    pub objects: Vec<ObjectInfo>,
    
    /// Total number of objects matching the filter
    pub total: usize,
    
    /// Current page
    pub page: usize,
    
    /// Number of items per page
    pub limit: usize,
}

/// Object information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectInfo {
    /// Object ID (hex-encoded)
    pub id: String,
    
    /// Object type
    pub object_type: ObjectType,
    
    /// Object status
    pub status: ObjectStatus,
    
    /// Owner (hex-encoded)
    pub owner: String,
    
    /// Object version
    pub version: u64,
    
    /// Data size in bytes
    pub data_size: usize,
    
    /// Whether the object is in superposition
    pub in_superposition: bool,
    
    /// Number of potential states (if in superposition)
    pub potential_state_count: Option<usize>,
    
    /// Number of references to other objects
    pub reference_count: usize,
    
    /// Number of capabilities
    pub capability_count: usize,
    
    /// Privacy level (0 = public, 1 = private)
    pub privacy_level: u8,
    
    /// Whether the object is encrypted
    pub encrypted: bool,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Last updated timestamp
    pub updated_at: u64,
    
    /// Security level (0-3)
    pub security_level: u8,
    
    /// Metadata keys (if requested)
    pub metadata_keys: Option<Vec<String>>,
}

/// Detailed object information with full data and metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectDetail {
    /// Basic object info
    #[serde(flatten)]
    pub info: ObjectInfo,
    
    /// Object data (base64-encoded)
    pub data: Option<String>,
    
    /// Object metadata (if available)
    pub metadata: Option<serde_json::Value>,
    
    /// Reference IDs (hex-encoded)
    pub references: Vec<String>,
    
    /// Object capabilities
    pub capabilities: Vec<String>,
    
    /// Transaction that created this object version
    pub created_by_tx: Option<String>,
    
    /// Previous version transaction hash
    pub previous_version_tx: Option<String>,
    
    /// Superposition states (if in superposition)
    pub superposition_states: Option<Vec<SuperpositionStateInfo>>,
}

/// Information about a superpositioned state
#[derive(Debug, Serialize, Deserialize)]
pub struct SuperpositionStateInfo {
    /// State index
    pub index: usize,
    
    /// State hash (hex-encoded)
    pub hash: String,
    
    /// Transaction that created this state (hex-encoded)
    pub tx_hash: String,
    
    /// Number of validator confirmations
    pub confirmation_count: usize,
    
    /// State timestamp
    pub timestamp: u64,
}

/// Handler for getting objects with pagination and filtering
pub async fn get_objects(
    Extension(context): Extension<ApiContext>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<ObjectFilterParams>,
) -> impl IntoResponse {
    debug!("Handling get_objects request: page={}, limit={}", pagination.page, pagination.limit);
    
    // Validate pagination parameters
    if pagination.page == 0 {
        let response = ApiResponse::<()>::error("Page number must be greater than 0");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    if pagination.limit == 0 || pagination.limit > 100 {
        let response = ApiResponse::<()>::error("Limit must be between 1 and 100");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    // Convert owner hex string to bytes if provided
    let owner_bytes = match filter.owner {
        Some(ref hex) => {
            match hex::decode(hex) {
                Ok(bytes) => Some(bytes),
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid owner address format");
                    return (StatusCode::BAD_REQUEST, Json(response)).into_response();
                }
            }
        },
        None => None,
    };
    
    // Convert object type string to enum if provided
    let object_type = match filter.object_type {
        Some(ref type_str) => {
            match parse_object_type(type_str) {
                Some(ot) => Some(ot),
                None => {
                    let response = ApiResponse::<()>::error("Invalid object type");
                    return (StatusCode::BAD_REQUEST, Json(response)).into_response();
                }
            }
        },
        None => None,
    };
    
    // Fetch objects from the blockchain
    let result = context.blockchain.get_objects(
        pagination.page,
        pagination.limit,
        object_type,
        owner_bytes,
        filter.include_deleted,
    ).await;
    
    match result {
        Ok((objects, total)) => {
            // Convert objects to API format
            let object_infos = objects.into_iter().map(object_to_info).collect();
            
            // Create response
            let response = ObjectsResponse {
                objects: object_infos,
                total,
                page: pagination.page,
                limit: pagination.limit,
            };
            
            Json(ApiResponse::success(response)).into_response()
        },
        Err(e) => {
            error!("Failed to get objects: {}", e);
            let response = ApiResponse::<()>::error(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

/// Handler for getting a specific object by ID
pub async fn get_object(
    Extension(context): Extension<ApiContext>,
    Path(id_str): Path<String>,
    Query(params): Query<GetObjectParams>,
) -> impl IntoResponse {
    debug!("Handling get_object request: id={}", id_str);
    
    // Convert ID string to ObjectID
    let object_id = match hex::decode(&id_str) {
        Ok(bytes) => ObjectID(bytes),
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid object ID format");
            return (StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };
    
    // Fetch object from the blockchain
    let result = context.blockchain.get_object(&object_id).await;
    
    match result {
        Ok(Some(object)) => {
            // Convert to detailed object info
            let object_detail = object_to_detail(object, params.include_data, params.include_metadata);
            
            Json(ApiResponse::success(object_detail)).into_response()
        },
        Ok(None) => {
            let response = ApiResponse::<()>::error("Object not found");
            (StatusCode::NOT_FOUND, Json(response)).into_response()
        },
        Err(e) => {
            error!("Failed to get object: {}", e);
            let response = ApiResponse::<()>::error(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

/// Parameters for the get_object endpoint
#[derive(Debug, Deserialize)]
pub struct GetObjectParams {
    /// Whether to include object data in the response
    #[serde(default)]
    pub include_data: bool,
    
    /// Whether to include object metadata in the response
    #[serde(default)]
    pub include_metadata: bool,
}

/// Convert an Object to ObjectInfo for API responses
fn object_to_info(object: Object) -> ObjectInfo {
    ObjectInfo {
        id: hex::encode(object.id().0.clone()),
        object_type: object.object_type(),
        status: object.status(),
        owner: hex::encode(object.owner().to_vec()),
        version: object.version().number(),
        data_size: object.data().len(),
        in_superposition: object.is_in_superposition(),
        potential_state_count: if object.is_in_superposition() {
            Some(object.superpositioned_states().unwrap().state_count())
        } else {
            None
        },
        reference_count: object.references().len(),
        capability_count: object.capabilities().len(),
        privacy_level: object.privacy_level(),
        encrypted: object.encryption_key_hint().is_some(),
        created_at: object.version().created_at(),
        updated_at: object.updated_at(),
        security_level: object.security_level(),
        metadata_keys: Some(object.metadata().keys().cloned().collect()),
    }
}

/// Convert an Object to ObjectDetail for API responses
fn object_to_detail(object: Object, include_data: bool, include_metadata: bool) -> ObjectDetail {
    // First get the basic info
    let info = object_to_info(object.clone());
    
    // Get data if requested
    let data = if include_data {
        Some(base64::encode(object.data()))
    } else {
        None
    };
    
    // Get metadata if requested
    let metadata = if include_metadata {
        let metadata_map: serde_json::Map<String, serde_json::Value> = object
            .metadata()
            .iter()
            .map(|(k, v)| {
                let value = match serde_json::from_slice(v) {
                    Ok(json) => json,
                    Err(_) => serde_json::Value::String(base64::encode(v)),
                };
                (k.clone(), value)
            })
            .collect();
        
        Some(serde_json::Value::Object(metadata_map))
    } else {
        None
    };
    
    // Get references
    let references = object.references()
        .iter()
        .map(|r| hex::encode(&r.0))
        .collect();
    
    // Get transaction info from the version
    let created_by_tx = if !object.version().created_by().is_empty() {
        Some(hex::encode(object.version().created_by()))
    } else {
        None
    };
    
    let previous_version_tx = object.version().previous_version()
        .map(|pv| hex::encode(pv));
    
    // Get superposition states if in superposition
    let superposition_states = if object.is_in_superposition() {
        let states = object.superpositioned_states().unwrap();
        let state_infos = states.potential_states()
            .iter()
            .map(|state| {
                SuperpositionStateInfo {
                    index: state.index,
                    hash: hex::encode(&state.hash),
                    tx_hash: hex::encode(&state.tx_hash),
                    confirmation_count: states.signature_count(state.index),
                    timestamp: state.timestamp,
                }
            })
            .collect();
        
        Some(state_infos)
    } else {
        None
    };
    
    ObjectDetail {
        info,
        data,
        metadata,
        references,
        capabilities: object.capabilities().to_vec(),
        created_by_tx,
        previous_version_tx,
        superposition_states,
    }
}

/// Parse an object type from a string
fn parse_object_type(type_str: &str) -> Option<ObjectType> {
    match type_str.to_lowercase().as_str() {
        "regular" => Some(ObjectType::Regular),
        "contract" => Some(ObjectType::Contract),
        "package" => Some(ObjectType::Package),
        "token" => Some(ObjectType::Token),
        "nft" => Some(ObjectType::NFT),
        _ => {
            // Check if it's a custom type in the format "custom-X"
            if type_str.starts_with("custom-") {
                if let Ok(num) = type_str[7..].parse::<u16>() {
                    return Some(ObjectType::Custom(num));
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::object::ObjectVersion;
    
    #[test]
    fn test_parse_object_type() {
        assert_eq!(parse_object_type("regular"), Some(ObjectType::Regular));
        assert_eq!(parse_object_type("contract"), Some(ObjectType::Contract));
        assert_eq!(parse_object_type("package"), Some(ObjectType::Package));
        assert_eq!(parse_object_type("token"), Some(ObjectType::Token));
        assert_eq!(parse_object_type("nft"), Some(ObjectType::NFT));
        assert_eq!(parse_object_type("custom-123"), Some(ObjectType::Custom(123)));
        assert_eq!(parse_object_type("invalid"), None);
    }
    
    #[test]
    fn test_object_to_info() {
        // Create a test object
        let mut object = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        object.set_data(vec![5, 6, 7, 8]);
        object.add_capability("test_capability".to_string());
        
        // Convert to info
        let info = object_to_info(object);
        
        // Check fields
        assert_eq!(info.object_type, ObjectType::Regular);
        assert_eq!(info.status, ObjectStatus::Created);
        assert_eq!(info.owner, hex::encode(&[1, 2, 3, 4]));
        assert_eq!(info.version, 0);
        assert_eq!(info.data_size, 4); // [5,6,7,8]
        assert!(!info.in_superposition);
        assert_eq!(info.potential_state_count, None);
        assert_eq!(info.reference_count, 0);
        assert_eq!(info.capability_count, 1);
        assert_eq!(info.privacy_level, 0);
        assert!(!info.encrypted);
        assert_eq!(info.security_level, 0);
        assert_eq!(info.metadata_keys.unwrap().len(), 0);
    }
}
