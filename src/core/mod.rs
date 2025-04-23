// Core module for the Aevor blockchain
//
// This module contains the fundamental data structures and types used throughout the
// Aevor blockchain platform, including blocks, transactions, objects, and state management.

/// Block structures and utilities
pub mod block;

/// Transaction structures and utilities
pub mod transaction;

/// Object model for state management
pub mod object;

/// Merkle tree implementations for state verification
pub mod merkle;

/// State management
pub mod state;

// Re-export key types for easier access
pub use block::{Block, BlockHeader, BlockStatus, ProofOfUncorruptionData, ParallelChainReference};
pub use transaction::{Transaction, TransactionData, TransactionType, TransactionStatus, SecurityLevel};
pub use object::{Object, ObjectID, ObjectStatus, ObjectType, ObjectVersion};
pub use merkle::{MerkleTree, MerkleProof, MerkleMap};

/// Represents the core blockchain structure
pub struct Blockchain {
    /// Configuration for this blockchain
    config: crate::Arc<crate::config::AevorConfig>,
    
    /// Storage system
    storage: crate::Arc<crate::storage::Storage>,
    
    /// Current global state
    state: crate::Arc<crate::RwLock<state::GlobalState>>,
    
    /// Current uncorrupted blocks
    uncorrupted_blocks: crate::Arc<crate::RwLock<block::UncorruptedBlocks>>,
    
    /// Chain metadata
    metadata: crate::Arc<crate::RwLock<ChainMetadata>>,
}

// Implementation will be filled out in separate file
impl Blockchain {
    /// Creates a new blockchain instance
    pub fn new(
        config: crate::Arc<crate::config::AevorConfig>,
        storage: crate::Arc<crate::storage::Storage>,
    ) -> crate::error::Result<Self> {
        // This is a placeholder implementation that will be replaced with a full implementation
        Ok(Self {
            config,
            storage,
            state: crate::Arc::new(crate::RwLock::new(state::GlobalState::new())),
            uncorrupted_blocks: crate::Arc::new(crate::RwLock::new(block::UncorruptedBlocks::new())),
            metadata: crate::Arc::new(crate::RwLock::new(ChainMetadata::new())),
        })
    }
    
    /// Starts the blockchain
    pub async fn start(&self) -> crate::error::Result<()> {
        // Placeholder implementation
        Ok(())
    }
    
    /// Stops the blockchain
    pub async fn stop(&self) -> crate::error::Result<()> {
        // Placeholder implementation
        Ok(())
    }
}

/// Metadata for the blockchain
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    /// Chain identifier
    pub id: Vec<u8>,
    
    /// Chain name
    pub name: String,
    
    /// Genesis block hash
    pub genesis_hash: Option<Vec<u8>>,
    
    /// Current height of the chain
    pub current_height: u64,
    
    /// Latest block hash
    pub latest_block_hash: Option<Vec<u8>>,
    
    /// Latest finalized block hash
    pub latest_finalized_block_hash: Option<Vec<u8>>,
    
    /// Latest uncorrupted block hash
    pub latest_uncorrupted_block_hash: Option<Vec<u8>>,
    
    /// Chain creation timestamp
    pub created_at: u64,
}

impl ChainMetadata {
    /// Creates new chain metadata
    pub fn new() -> Self {
        Self {
            id: vec![],
            name: "Aevor Chain".to_string(),
            genesis_hash: None,
            current_height: 0,
            latest_block_hash: None,
            latest_finalized_block_hash: None,
            latest_uncorrupted_block_hash: None,
            created_at: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
    
    /// Sets the genesis block hash
    pub fn set_genesis_hash(&mut self, hash: Vec<u8>) {
        self.genesis_hash = Some(hash);
    }
    
    /// Sets the latest block hash and height
    pub fn update_latest_block(&mut self, hash: Vec<u8>, height: u64) {
        self.latest_block_hash = Some(hash);
        self.current_height = height;
    }
    
    /// Sets the latest finalized block hash
    pub fn set_latest_finalized_block_hash(&mut self, hash: Vec<u8>) {
        self.latest_finalized_block_hash = Some(hash);
    }
    
    /// Sets the latest uncorrupted block hash
    pub fn set_latest_uncorrupted_block_hash(&mut self, hash: Vec<u8>) {
        self.latest_uncorrupted_block_hash = Some(hash);
    }
}

/// Placeholder for UncorruptedBlocks structure until fully implemented
pub mod block {
    /// Tracks uncorrupted blocks in the chain
    #[derive(Debug)]
    pub struct UncorruptedBlocks {
        // Will be filled in with implementation later
    }
    
    impl UncorruptedBlocks {
        /// Creates a new UncorruptedBlocks tracker
        pub fn new() -> Self {
            Self {}
        }
    }
}
