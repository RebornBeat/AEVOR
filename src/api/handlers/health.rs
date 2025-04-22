use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::handlers::ApiResponse;

/// Response for the health check endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether the node is healthy
    pub healthy: bool,
    
    /// Current server timestamp
    pub timestamp: u64,
    
    /// Software version
    pub version: String,
    
    /// Node uptime in seconds
    pub uptime: u64,
    
    /// Memory usage in megabytes
    pub memory_usage_mb: f64,
    
    /// CPU usage percentage
    pub cpu_usage: f64,
    
    /// Disk usage percentage
    pub disk_usage: f64,
}

/// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    // Get current timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Calculate system metrics
    // In a real implementation, these would come from actual system monitoring
    let uptime = std::process::id() as u64 % 3600; // This is a stub; real implementation would use actual uptime
    let memory_usage_mb = 512.0; // Stub value
    let cpu_usage = 25.0; // Stub value
    let disk_usage = 45.0; // Stub value
    
    // Create the health status response
    let health_status = HealthStatus {
        healthy: true,
        timestamp: now,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime,
        memory_usage_mb,
        cpu_usage,
        disk_usage,
    };
    
    // Return the response
    (StatusCode::OK, Json(ApiResponse::success(health_status)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::Response;
    use axum::body::Body;
    use tower::ServiceExt;
    use hyper::Request;
    use axum::Router;
    
    #[tokio::test]
    async fn test_health_check() {
        // Create a test router with the health check endpoint
        let app = Router::new().route("/health", axum::routing::get(health_check));
        
        // Create a request to the health check endpoint
        let request = Request::builder()
            .uri("/health")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        
        // Send the request to the router
        let response = app.oneshot(request).await.unwrap();
        
        // Check that the response has a 200 status code
        assert_eq!(response.status(), StatusCode::OK);
        
        // Extract the response body
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        
        // Parse the response body
        let response: ApiResponse<HealthStatus> = serde_json::from_str(&body_str).unwrap();
        
        // Check that the response is successful
        assert!(response.success);
        
        // Check that the health status contains the expected fields
        let health_status = response.data.unwrap();
        assert!(health_status.healthy);
        assert_eq!(health_status.version, env!("CARGO_PKG_VERSION"));
    }
}
