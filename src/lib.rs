// Aevor V1 Blockchain Library
//
// This crate implements the Aevor blockchain platform, featuring a revolutionary
// Dual-DAG Proof of Uncorruption (PoU) consensus mechanism with Security Level
// Acceleration for high performance and strong security guarantees.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![warn(future_incompatible)]
#![allow(clippy::module_inception)]

//! # Aevor Blockchain
//!
//! Aevor is a high-performance blockchain platform built around a revolutionary
//! Dual-DAG Proof of Uncorruption (PoU) consensus mechanism with Security Level Acceleration.
//!
//! ## Core Features
//!
//! - **Dual-DAG Architecture**: Two complementary directed acyclic graphs for maximum parallelism
//! - **Proof of Uncorruption**: Novel consensus focused on execution integrity
//! - **Security Level Acceleration**: Progressive security guarantees from milliseconds to sub-second
//! - **TEE Integration**: Hardware-backed security for transaction execution
//! - **Transaction-Level Superposition**: Enables speculative execution for high throughput
//!
//! ## Performance
//!
//! - 200,000+ TPS sustained throughput
//! - 1,000,000+ TPS burst capacity
//! - Minimal Security: 20-50ms
//! - Full Security: <1s
//!
//! ## Modules
//!
//! - `api`: API server and interfaces
//! - `cli`: Command-line interface
//! - `config`: Configuration management
//! - `consensus`: Consensus mechanisms (PoU, Security Accelerator)
//! - `core`: Core blockchain data structures
//! - `crypto`: Cryptographic primitives
//! - `execution`: Transaction execution and validation
//! - `networking`: P2P networking layer
//! - `storage`: Persistent storage
//! - `utils`: Utility functions and types
//! - `vm`: Virtual machine for smart contracts
//! - `wallet`: Wallet and account management

// Re-export crate error types
pub use crate::error::{AevorError, Result, TEEResult, to_internal_err};

// Core modules
pub mod api;
pub mod cli;
pub mod config;
pub mod consensus;
pub mod core;
pub mod crypto;
pub mod error;
pub mod execution;
pub mod networking;
pub mod storage;
pub mod utils;
pub mod vm;
pub mod wallet;

/// Current version of the Aevor blockchain platform
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Type alias for Arc<T> used throughout the codebase
pub type Arc<T> = std::sync::Arc<T>;

/// Type alias for RwLock<T> that uses parking_lot implementation
pub type RwLock<T> = parking_lot::RwLock<T>;

/// Type alias for Mutex<T> that uses parking_lot implementation
pub type Mutex<T> = parking_lot::Mutex<T>;

/// Type alias for Async Mutex<T> that uses tokio implementation
pub type AsyncMutex<T> = tokio::sync::Mutex<T>;

/// Type alias for Async RwLock<T> that uses tokio implementation
pub type AsyncRwLock<T> = tokio::sync::RwLock<T>;

/// Common result type for async operations
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Initializes the Aevor platform with the given configuration.
///
/// This function should be called before using any Aevor functionality.
/// It sets up logging, loads configuration, and initializes all subsystems.
///
/// # Arguments
///
/// * `config` - The configuration to use
///
/// # Returns
///
/// A result containing an initialized Aevor node if successful
///
/// # Examples
///
/// ```no_run
/// use aevor::config::AevorConfig;
/// use std::sync::Arc;
///
/// async fn example() {
///     let config = AevorConfig::default();
///     let node = aevor::init(Arc::new(config)).await.unwrap();
///     // Use the node...
/// }
/// ```
pub async fn init(config: Arc<config::AevorConfig>) -> Result<Node> {
    // Initialize the node with the given configuration
    Node::new(config).await
}

/// Represents a running Aevor blockchain node
#[derive(Debug)]
pub struct Node {
    /// Node configuration
    pub config: Arc<config::AevorConfig>,
    
    /// API server handle (if enabled)
    pub api_server: Option<api::Server>,
    
    /// Storage subsystem
    pub storage: Arc<storage::Storage>,
    
    /// Blockchain instance
    pub blockchain: Arc<core::Blockchain>,
    
    /// Consensus manager
    pub consensus: Arc<consensus::Manager>,
    
    /// Execution engine
    pub execution: Arc<execution::Engine>,
    
    /// Network manager
    pub network: Arc<networking::Manager>,
    
    /// Virtual machine manager
    pub vm: Arc<vm::Manager>,
    
    /// Shutdown signal
    shutdown: Arc<tokio::sync::watch::Sender<bool>>,
}

impl Node {
    /// Creates a new node with the given configuration
    pub async fn new(config: Arc<config::AevorConfig>) -> Result<Self> {
        // Initialize all node components
        
        // Create shutdown signal
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let shutdown = Arc::new(shutdown_tx);
        
        // Initialize storage first
        let storage = Arc::new(storage::Storage::new(&config.storage)?);
        
        // Initialize the blockchain with storage
        let blockchain = Arc::new(core::Blockchain::new(config.clone(), storage.clone())?);
        
        // Initialize the virtual machine
        let vm = Arc::new(vm::Manager::new(config.clone())?);
        
        // Initialize the execution engine
        let execution = Arc::new(execution::Engine::new(
            config.clone(),
            blockchain.clone(),
            vm.clone(),
        )?);
        
        // Initialize consensus
        let consensus = Arc::new(consensus::Manager::new(
            config.clone(),
            blockchain.clone(),
            execution.clone(),
        )?);
        
        // Initialize networking
        let network = Arc::new(networking::Manager::new(
            config.clone(),
            blockchain.clone(),
            consensus.clone(),
        )?);
        
        // Initialize API server if enabled
        let api_server = if config.api.http_enabled || config.api.ws_enabled || config.api.jsonrpc_enabled {
            Some(api::Server::new(
                config.clone(),
                blockchain.clone(),
                consensus.clone(),
                execution.clone(),
            )?)
        } else {
            None
        };
        
        Ok(Self {
            config,
            api_server,
            storage,
            blockchain,
            consensus,
            execution,
            network,
            vm,
            shutdown,
        })
    }
    
    /// Starts the node and all its components
    pub async fn start(&mut self) -> Result<()> {
        // Start storage (if needed)
        self.storage.start().await?;
        
        // Start the blockchain component
        self.blockchain.start().await?;
        
        // Start virtual machine
        self.vm.start().await?;
        
        // Start execution engine
        self.execution.start().await?;
        
        // Start consensus
        self.consensus.start().await?;
        
        // Start networking
        self.network.start().await?;
        
        // Start API server if it exists
        if let Some(api_server) = &mut self.api_server {
            api_server.start().await?;
        }
        
        Ok(())
    }
    
    /// Stops the node and all its components
    pub async fn stop(&self) -> Result<()> {
        // Signal shutdown
        let _ = self.shutdown.send(true);
        
        // Stop API server first if it exists
        if let Some(api_server) = &self.api_server {
            api_server.stop().await?;
        }
        
        // Stop networking
        self.network.stop().await?;
        
        // Stop consensus
        self.consensus.stop().await?;
        
        // Stop execution engine
        self.execution.stop().await?;
        
        // Stop virtual machine
        self.vm.stop().await?;
        
        // Stop blockchain
        self.blockchain.stop().await?;
        
        // Stop storage last
        self.storage.stop().await?;
        
        Ok(())
    }
    
    /// Checks if the node is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.borrow().clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Signal shutdown when the node is dropped
        let _ = self.shutdown.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::AevorConfig;
    
    #[tokio::test]
    async fn test_node_creation() {
        let config = Arc::new(AevorConfig::default());
        let result = Node::new(config).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_init_function() {
        let config = Arc::new(AevorConfig::default());
        let result = init(config).await;
        assert!(result.is_ok());
    }
}
