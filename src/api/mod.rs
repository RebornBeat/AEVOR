use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};

use crate::config::ApiConfig;
use crate::consensus::Manager as ConsensusManager;
use crate::core::Blockchain;
use crate::error::{AevorError, Result};
use crate::execution::Engine as ExecutionEngine;

pub mod handlers;
pub mod rpc;
pub mod websocket;

/// Context shared across API handlers
#[derive(Clone)]
pub struct ApiContext {
    /// Blockchain instance
    pub blockchain: Arc<Blockchain>,
    
    /// Consensus manager
    pub consensus: Arc<ConsensusManager>,
    
    /// Execution engine
    pub execution: Arc<ExecutionEngine>,
    
    /// API configuration
    pub config: Arc<ApiConfig>,
}

/// API server for the Aevor blockchain
pub struct Server {
    /// API context
    context: ApiContext,
    
    /// Server configuration
    config: Arc<ApiConfig>,
    
    /// HTTP server handle
    http_server: Option<JoinHandle<()>>,
    
    /// HTTP server shutdown signal
    http_shutdown: Option<oneshot::Sender<()>>,
    
    /// WebSocket server handle
    ws_server: Option<JoinHandle<()>>,
    
    /// WebSocket server shutdown signal
    ws_shutdown: Option<oneshot::Sender<()>>,
    
    /// JSON-RPC server handle
    jsonrpc_server: Option<JoinHandle<()>>,
    
    /// JSON-RPC server shutdown signal
    jsonrpc_shutdown: Option<oneshot::Sender<()>>,
}

impl Server {
    /// Creates a new API server
    pub fn new(
        config: Arc<ApiConfig>,
        blockchain: Arc<Blockchain>,
        consensus: Arc<ConsensusManager>,
        execution: Arc<ExecutionEngine>,
    ) -> Result<Self> {
        let context = ApiContext {
            blockchain,
            consensus,
            execution,
            config: config.clone(),
        };
        
        Ok(Self {
            context,
            config,
            http_server: None,
            http_shutdown: None,
            ws_server: None,
            ws_shutdown: None,
            jsonrpc_server: None,
            jsonrpc_shutdown: None,
        })
    }
    
    /// Starts the API server
    pub async fn start(&mut self) -> Result<()> {
        // Start HTTP server if enabled
        if self.config.http_enabled {
            self.start_http_server().await?;
        }
        
        // Start WebSocket server if enabled
        if self.config.ws_enabled {
            self.start_ws_server().await?;
        }
        
        // Start JSON-RPC server if enabled
        if self.config.jsonrpc_enabled {
            self.start_jsonrpc_server().await?;
        }
        
        Ok(())
    }
    
    /// Starts the HTTP API server
    async fn start_http_server(&mut self) -> Result<()> {
        // Create the shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.http_shutdown = Some(shutdown_tx);
        
        // Create the API router
        let router = create_http_router(self.context.clone())?;
        
        // Get the HTTP address
        let addr: SocketAddr = format!("{}:{}", self.config.http_addr, self.config.http_port)
            .parse()
            .map_err(|e| AevorError::api(format!("Failed to parse HTTP address: {}", e)))?;
        
        // Start the server
        info!("Starting HTTP API server on {}", addr);
        
        let handle = tokio::spawn(async move {
            // Start the server
            let server = axum::Server::bind(&addr)
                .serve(router.into_make_service())
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                    debug!("HTTP API server shutdown signal received");
                });
            
            // Wait for the server to complete
            if let Err(e) = server.await {
                error!("HTTP API server error: {}", e);
            }
            
            info!("HTTP API server stopped");
        });
        
        self.http_server = Some(handle);
        
        Ok(())
    }
    
    /// Starts the WebSocket server
    async fn start_ws_server(&mut self) -> Result<()> {
        // Create the shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.ws_shutdown = Some(shutdown_tx);
        
        // Create the WebSocket server
        let ws_server = websocket::WebSocketServer::new(self.context.clone());
        
        // Get the WebSocket address
        let addr: SocketAddr = format!("{}:{}", self.config.http_addr, self.config.ws_port)
            .parse()
            .map_err(|e| AevorError::api(format!("Failed to parse WebSocket address: {}", e)))?;
        
        // Start the server
        info!("Starting WebSocket server on {}", addr);
        
        let handle = tokio::spawn(async move {
            // Start the server
            let server = axum::Server::bind(&addr)
                .serve(
                    Router::new()
                        .route("/ws", axum::routing::get(websocket::ws_handler))
                        .layer(
                            ServiceBuilder::new()
                                .layer(
                                    CorsLayer::new()
                                        .allow_origin(Any)
                                        .allow_methods(Any)
                                        .allow_headers(Any),
                                )
                                .layer(TraceLayer::new_for_http())
                                .layer(axum::Extension(ws_server.clone())),
                        )
                        .into_make_service(),
                )
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                    debug!("WebSocket server shutdown signal received");
                });
            
            // Wait for the server to complete
            if let Err(e) = server.await {
                error!("WebSocket server error: {}", e);
            }
            
            info!("WebSocket server stopped");
        });
        
        self.ws_server = Some(handle);
        
        Ok(())
    }
    
    /// Starts the JSON-RPC server
    async fn start_jsonrpc_server(&mut self) -> Result<()> {
        // Create the shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.jsonrpc_shutdown = Some(shutdown_tx);
        
        // Get the JSON-RPC address
        let addr: SocketAddr = format!("{}:{}", self.config.http_addr, self.config.jsonrpc_port)
            .parse()
            .map_err(|e| AevorError::api(format!("Failed to parse JSON-RPC address: {}", e)))?;
        
        // Create the API router for JSON-RPC
        let router = create_jsonrpc_router(self.context.clone())?;
        
        // Start the server
        info!("Starting JSON-RPC server on {}", addr);
        
        let handle = tokio::spawn(async move {
            // Start the server
            let server = axum::Server::bind(&addr)
                .serve(router.into_make_service())
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                    debug!("JSON-RPC server shutdown signal received");
                });
            
            // Wait for the server to complete
            if let Err(e) = server.await {
                error!("JSON-RPC server error: {}", e);
            }
            
            info!("JSON-RPC server stopped");
        });
        
        self.jsonrpc_server = Some(handle);
        
        Ok(())
    }
    
    /// Stops the API server
    pub async fn stop(&self) -> Result<()> {
        // Stop HTTP server if running
        if let Some(tx) = &self.http_shutdown {
            let _ = tx.send(());
        }
        
        // Stop WebSocket server if running
        if let Some(tx) = &self.ws_shutdown {
            let _ = tx.send(());
        }
        
        // Stop JSON-RPC server if running
        if let Some(tx) = &self.jsonrpc_shutdown {
            let _ = tx.send(());
        }
        
        // Wait for all servers to stop (with timeout)
        let timeout = Duration::from_secs(5);
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            let http_done = self.http_server.is_none() || self.http_server.as_ref().unwrap().is_finished();
            let ws_done = self.ws_server.is_none() || self.ws_server.as_ref().unwrap().is_finished();
            let jsonrpc_done = self.jsonrpc_server.is_none() || self.jsonrpc_server.as_ref().unwrap().is_finished();
            
            if http_done && ws_done && jsonrpc_done {
                break;
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        if start.elapsed() >= timeout {
            error!("Timeout waiting for API servers to stop");
            return Err(AevorError::api("Timeout waiting for API servers to stop"));
        }
        
        info!("All API servers stopped");
        Ok(())
    }
    
    /// Checks if the API server is running
    pub fn is_running(&self) -> bool {
        (self.config.http_enabled && self.http_server.is_some()) ||
        (self.config.ws_enabled && self.ws_server.is_some()) ||
        (self.config.jsonrpc_enabled && self.jsonrpc_server.is_some())
    }
}

/// Creates the HTTP API router
fn create_http_router(context: ApiContext) -> Result<Router> {
    // Create the router
    let router = Router::new()
        // Add health check route
        .route("/health", axum::routing::get(handlers::health_check))
        // Add API routes
        .route("/api/v1/status", axum::routing::get(handlers::get_chain_status))
        .route("/api/v1/blocks", axum::routing::get(handlers::get_blocks))
        .route("/api/v1/blocks/:hash_or_height", axum::routing::get(handlers::get_block))
        .route("/api/v1/transactions", axum::routing::get(handlers::get_transactions))
        .route("/api/v1/transactions", axum::routing::post(handlers::submit_transaction))
        .route("/api/v1/transactions/:hash", axum::routing::get(handlers::get_transaction))
        .route("/api/v1/objects", axum::routing::get(handlers::get_objects))
        .route("/api/v1/objects/:id", axum::routing::get(handlers::get_object))
        .route("/api/v1/uncorrupted-chains", axum::routing::get(handlers::get_uncorrupted_chains))
        .route("/api/v1/validators", axum::routing::get(handlers::get_validators))
        .route("/api/v1/validators/:id", axum::routing::get(handlers::get_validator))
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                .layer(TraceLayer::new_for_http())
                .layer(axum::Extension(context.clone())),
        );
    
    Ok(router)
}

/// Creates the JSON-RPC router
fn create_jsonrpc_router(context: ApiContext) -> Result<Router> {
    // Create the router
    let router = Router::new()
        .route("/", axum::routing::post(rpc::handle_rpc_request))
        .layer(
            ServiceBuilder::new()
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                .layer(TraceLayer::new_for_http())
                .layer(axum::Extension(context.clone())),
        );
    
    Ok(router)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AevorConfig, ApiConfig};
    use std::sync::Arc;
    
    // Mock implementations for testing
    struct MockBlockchain;
    struct MockConsensusManager;
    struct MockExecutionEngine;
    
    impl Blockchain for MockBlockchain {
        // Implement required methods for testing
    }
    
    impl ConsensusManager for MockConsensusManager {
        // Implement required methods for testing
    }
    
    impl ExecutionEngine for MockExecutionEngine {
        // Implement required methods for testing
    }
    
    #[tokio::test]
    async fn test_api_server_creation() {
        let config = Arc::new(ApiConfig {
            http_enabled: false,
            http_addr: "127.0.0.1".to_string(),
            http_port: 8080,
            ws_enabled: false,
            ws_port: 8081,
            jsonrpc_enabled: false,
            jsonrpc_port: 8082,
            cors_enabled: true,
            cors_allowed_origins: vec!["*".to_string()],
            rate_limit_enabled: true,
            rate_limit_requests_per_min: 600,
            auth_enabled: false,
            api_keys: vec![],
        });
        
        let blockchain = Arc::new(MockBlockchain);
        let consensus = Arc::new(MockConsensusManager);
        let execution = Arc::new(MockExecutionEngine);
        
        let server = Server::new(config, blockchain, consensus, execution);
        assert!(server.is_ok());
    }
}
