use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum::Extension;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::api::ApiContext;
use crate::api::handlers::{ApiResponse, PaginationParams};
use crate::consensus::validation::Validator;

/// Response for the get_validators endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorsResponse {
    /// List of validators
    pub validators: Vec<ValidatorInfo>,
    
    /// Total number of validators
    pub total: usize,
    
    /// Current page
    pub page: usize,
    
    /// Number of items per page
    pub limit: usize,
}

/// Validator information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator ID (hex-encoded)
    pub id: String,
    
    /// Validator name
    pub name: String,
    
    /// Validator public key (hex-encoded)
    pub public_key: String,
    
    /// Validator stake amount
    pub stake: u64,
    
    /// Whether the validator is active
    pub active: bool,
    
    /// Last seen timestamp
    pub last_seen: u64,
    
    /// Number of blocks validated
    pub blocks_validated: u64,
    
    /// Number of blocks produced
    pub blocks_produced: u64,
    
    /// Number of validations missed
    pub validations_missed: u64,
    
    /// Number of validation errors
    pub validation_errors: u64,
    
    /// Average validation latency in milliseconds
    pub avg_validation_latency_ms: u64,
    
    /// Uptime percentage (0-100)
    pub uptime_percentage: f64,
    
    /// Commission rate percentage (0-100)
    pub commission_rate: u8,
    
    /// Total delegated stake
    pub delegated_stake: u64,
    
    /// Number of delegators
    pub delegator_count: u32,
}

/// Filter parameters for validators
#[derive(Debug, Deserialize)]
pub struct ValidatorFilterParams {
    /// Filter by active status
    pub active: Option<bool>,
    
    /// Minimum stake amount
    pub min_stake: Option<u64>,
    
    /// Maximum stake amount
    pub max_stake: Option<u64>,
    
    /// Whether to sort by stake (default is false, sorts by id)
    #[serde(default)]
    pub sort_by_stake: bool,
    
    /// Whether to sort in descending order
    #[serde(default)]
    pub descending: bool,
}

/// Handler for getting all validators with pagination and filtering
pub async fn get_validators(
    Extension(context): Extension<ApiContext>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<ValidatorFilterParams>,
) -> impl IntoResponse {
    debug!("Handling get_validators request: page={}, limit={}", pagination.page, pagination.limit);
    
    // Validate pagination parameters
    if pagination.page == 0 {
        let response = ApiResponse::<()>::error("Page number must be greater than 0");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    if pagination.limit == 0 || pagination.limit > 100 {
        let response = ApiResponse::<()>::error("Limit must be between 1 and 100");
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    // Fetch validators from the consensus manager
    let result = context.consensus.get_validators(
        pagination.page,
        pagination.limit,
        filter.active,
        filter.min_stake,
        filter.max_stake,
        filter.sort_by_stake,
        filter.descending,
    ).await;
    
    match result {
        Ok((validators, total)) => {
            // Convert validators to API format
            let validator_infos = validators.into_iter().map(validator_to_info).collect();
            
            // Create response
            let response = ValidatorsResponse {
                validators: validator_infos,
                total,
                page: pagination.page,
                limit: pagination.limit,
            };
            
            Json(ApiResponse::success(response)).into_response()
        },
        Err(e) => {
            error!("Failed to get validators: {}", e);
            let response = ApiResponse::<()>::error(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

/// Handler for getting a specific validator by ID
pub async fn get_validator(
    Extension(context): Extension<ApiContext>,
    Path(validator_id): Path<String>,
) -> impl IntoResponse {
    debug!("Handling get_validator request: id={}", validator_id);
    
    // Convert validator ID from hex to bytes
    let validator_bytes = match hex::decode(&validator_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = ApiResponse::<()>::error("Invalid validator ID format");
            return (StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };
    
    // Fetch validator from the consensus manager
    let result = context.consensus.get_validator(&validator_bytes).await;
    
    match result {
        Ok(Some(validator)) => {
            // Convert validator to API format
            let validator_info = validator_to_info(validator);
            
            // Return success response
            Json(ApiResponse::success(validator_info)).into_response()
        },
        Ok(None) => {
            // Validator not found
            let response = ApiResponse::<()>::error("Validator not found");
            (StatusCode::NOT_FOUND, Json(response)).into_response()
        },
        Err(e) => {
            // Internal error
            error!("Failed to get validator: {}", e);
            let response = ApiResponse::<()>::error(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

/// Converts a core Validator to an API ValidatorInfo
fn validator_to_info(validator: Validator) -> ValidatorInfo {
    ValidatorInfo {
        id: hex::encode(&validator.id),
        name: validator.name,
        public_key: hex::encode(&validator.public_key),
        stake: validator.stake,
        active: validator.active,
        last_seen: validator.last_seen,
        blocks_validated: validator.metrics.blocks_validated,
        blocks_produced: validator.metrics.blocks_produced,
        validations_missed: validator.metrics.validations_missed,
        validation_errors: validator.metrics.validation_errors,
        avg_validation_latency_ms: validator.metrics.avg_validation_latency_ms,
        uptime_percentage: validator.metrics.uptime_percentage,
        commission_rate: validator.commission_rate,
        delegated_stake: validator.delegated_stake,
        delegator_count: validator.delegator_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::body::Body;
    use tower::ServiceExt;
    use hyper::Request;
    use axum::Router;
    use std::sync::Arc;
    
    // Mock validator for testing
    fn create_mock_validator(id: u8) -> Validator {
        Validator {
            id: vec![id],
            name: format!("Validator {}", id),
            public_key: vec![100 + id],
            stake: 1000 * (id as u64),
            active: true,
            last_seen: 1234567890,
            metrics: crate::consensus::validation::ValidatorMetrics {
                blocks_validated: 100,
                blocks_produced: 50,
                validations_missed: 5,
                validation_errors: 2,
                avg_validation_latency_ms: 200,
                uptime_percentage: 99.5,
            },
            commission_rate: 10,
            delegated_stake: 5000,
            delegator_count: 25,
        }
    }
    
    // Test that validator_to_info works correctly
    #[test]
    fn test_validator_to_info() {
        let validator = create_mock_validator(1);
        let info = validator_to_info(validator.clone());
        
        assert_eq!(info.id, hex::encode(&validator.id));
        assert_eq!(info.name, validator.name);
        assert_eq!(info.public_key, hex::encode(&validator.public_key));
        assert_eq!(info.stake, validator.stake);
        assert_eq!(info.active, validator.active);
        assert_eq!(info.last_seen, validator.last_seen);
        assert_eq!(info.blocks_validated, validator.metrics.blocks_validated);
        assert_eq!(info.blocks_produced, validator.metrics.blocks_produced);
        assert_eq!(info.validations_missed, validator.metrics.validations_missed);
        assert_eq!(info.validation_errors, validator.metrics.validation_errors);
        assert_eq!(info.avg_validation_latency_ms, validator.metrics.avg_validation_latency_ms);
        assert_eq!(info.uptime_percentage, validator.metrics.uptime_percentage);
        assert_eq!(info.commission_rate, validator.commission_rate);
        assert_eq!(info.delegated_stake, validator.delegated_stake);
        assert_eq!(info.delegator_count, validator.delegator_count);
    }
}
