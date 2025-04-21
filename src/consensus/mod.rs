use std::sync::Arc;
use std::time::Duration;

use crate::config::AevorConfig;
use crate::core::{Block, Blockchain, Transaction};
use crate::error::Result;
use crate::execution::Engine as ExecutionEngine;

pub mod dag_manager;
pub mod finality;
pub mod pou;
pub mod security_accelerator;
pub mod superposition;
pub mod validation;

use dag_manager::DAGManager;
use finality::FinalityManager;
use pou::ProofOfUncorruption;
use security_accelerator::SecurityAccelerator;
use superposition::SuperpositionManager;
use validation::ValidationManager;

/// Manager for Aevor consensus mechanisms
///
/// This manager coordinates the operation of Aevor's consensus components:
/// - Proof of Uncorruption (PoU) for execution integrity
/// - Security Level Accelerator for progressive finality
/// - Dual-DAG structure for concurrent execution and block production
/// - Validation for transaction and block verification
/// - Superposition for speculative execution
#[derive(Debug)]
pub struct Manager {
    /// Configuration
    pub config: Arc<AevorConfig>,
    
    /// Blockchain instance
    pub blockchain: Arc<Blockchain>,
    
    /// Execution engine
    pub execution_engine: Arc<ExecutionEngine>,
    
    /// DAG Manager
    pub dag_manager: Arc<DAGManager>,
    
    /// Proof of Uncorruption
    pub pou: Arc<ProofOfUncorruption>,
    
    /// Security Level Accelerator
    pub security_accelerator: Arc<SecurityAccelerator>,
    
    /// Finality Manager
    pub finality_manager: Arc<FinalityManager>,
    
    /// Validation Manager
    pub validation_manager: Arc<ValidationManager>,
    
    /// Superposition Manager
    pub superposition_manager: Arc<SuperpositionManager>,
    
    /// Whether this node is a validator
    pub is_validator: bool,
    
    /// Running state
    running: bool,
    
    /// Shutdown signal
    shutdown: Arc<tokio::sync::watch::Sender<bool>>,
}

impl Manager {
    /// Creates a new consensus manager
    pub fn new(
        config: Arc<AevorConfig>,
        blockchain: Arc<Blockchain>,
        execution_engine: Arc<ExecutionEngine>,
    ) -> Result<Self> {
        let is_validator = config.node.is_validator;
        
        // Create shutdown signal
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let shutdown = Arc::new(shutdown_tx);
        
        // Create DAG Manager
        let dag_manager = Arc::new(DAGManager::new(
            config.clone(),
            blockchain.clone(),
        )?);
        
        // Create Proof of Uncorruption
        let pou = Arc::new(ProofOfUncorruption::new(
            config.clone(),
            blockchain.clone(),
        )?);
        
        // Create Validation Manager
        let validation_manager = Arc::new(ValidationManager::new(
            config.clone(),
            blockchain.clone(),
        )?);
        
        // Create Security Level Accelerator
        let security_accelerator = Arc::new(SecurityAccelerator::new(
            config.clone(),
            validation_manager.clone(),
        )?);
        
        // Create Finality Manager
        let finality_manager = Arc::new(FinalityManager::new(
            config.clone(),
            validation_manager.clone(),
        )?);
        
        // Create Superposition Manager
        let superposition_manager = Arc::new(SuperpositionManager::new(
            config.clone(),
        )?);
        
        Ok(Self {
            config,
            blockchain,
            execution_engine,
            dag_manager,
            pou,
            security_accelerator,
            finality_manager,
            validation_manager,
            superposition_manager,
            is_validator,
            running: false,
            shutdown,
        })
    }
    
    /// Starts the consensus manager
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }
        
        // Start DAG Manager
        self.dag_manager.start().await?;
        
        // Start Proof of Uncorruption
        self.pou.start().await?;
        
        // Start Validation Manager
        self.validation_manager.start().await?;
        
        // Start Security Level Accelerator
        self.security_accelerator.start().await?;
        
        // Start Finality Manager
        self.finality_manager.start().await?;
        
        // Start Superposition Manager
        self.superposition_manager.start().await?;
        
        self.running = true;
        
        Ok(())
    }
    
    /// Stops the consensus manager
    pub async fn stop(&self) -> Result<()> {
        // Signal shutdown
        let _ = self.shutdown.send(true);
        
        // Stop Superposition Manager
        self.superposition_manager.stop().await?;
        
        // Stop Finality Manager
        self.finality_manager.stop().await?;
        
        // Stop Security Level Accelerator
        self.security_accelerator.stop().await?;
        
        // Stop Validation Manager
        self.validation_manager.stop().await?;
        
        // Stop Proof of Uncorruption
        self.pou.stop().await?;
        
        // Stop DAG Manager
        self.dag_manager.stop().await?;
        
        Ok(())
    }
    
    /// Processes a new block
    pub async fn process_block(&self, block: Block) -> Result<()> {
        // DAG Manager integrates the block into the DAG
        self.dag_manager.process_block(block.clone()).await?;
        
        // Validation Manager validates the block
        self.validation_manager.validate_block(block.clone()).await?;
        
        // PoU checks the uncorruption proof
        self.pou.verify_block(block.clone()).await?;
        
        // Finality Manager checks if the block can be finalized
        self.finality_manager.process_block(block.clone()).await?;
        
        Ok(())
    }
    
    /// Processes a new transaction
    pub async fn process_transaction(&self, transaction: Transaction) -> Result<()> {
        // Validation Manager validates the transaction
        self.validation_manager.validate_transaction(transaction.clone()).await?;
        
        // Security Accelerator processes the transaction for progressive finality
        self.security_accelerator.process_transaction(transaction.clone()).await?;
        
        Ok(())
    }
    
    /// Gets the current security level of a transaction
    pub async fn get_transaction_security_level(&self, tx_hash: &[u8]) -> Result<u8> {
        self.security_accelerator.get_transaction_security_level(tx_hash).await
    }
    
    /// Checks if the consensus manager is running
    pub fn is_running(&self) -> bool {
        self.running
    }
    
    /// Creates a new block
    pub async fn create_block(&self) -> Result<Block> {
        if !self.is_validator {
            return Err(crate::error::AevorError::validation("Node is not a validator"));
        }
        
        // DAG Manager creates a new block based on the uncorrupted frontier
        self.dag_manager.create_block().await
    }
    
    /// Gets the current uncorrupted frontier
    pub async fn get_uncorrupted_frontier(&self) -> Result<Vec<Vec<u8>>> {
        self.pou.get_uncorrupted_frontier().await
    }
    
    /// Gets the finalized block hashes
    pub async fn get_finalized_blocks(&self) -> Result<Vec<Vec<u8>>> {
        self.finality_manager.get_finalized_blocks().await
    }
    
    /// Checks if a block has reached a specific security level
    pub async fn has_block_reached_security_level(&self, block_hash: &[u8], level: u8) -> Result<bool> {
        self.security_accelerator.has_block_reached_security_level(block_hash, level).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{Transaction, TransactionType, TransactionData, data::TransferData};
    use crate::core::block::BlockBuilder;
    use std::sync::Arc;
    
    // Helper function to create a test transaction
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
    
    // Helper function to create a test block
    fn create_test_block(height: u64, previous_hash: Vec<u8>) -> Block {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        
        BlockBuilder::new()
            .height(height)
            .previous_hash(previous_hash)
            .reference_height(height)
            .validator(validator)
            .transaction(tx)
            .build()
            .unwrap()
    }
    
    #[tokio::test]
    async fn test_consensus_manager_creation() {
        // For testing, we mock the dependent components
        let config = Arc::new(AevorConfig::default());
        let blockchain = Arc::new(Blockchain::new(config.clone(), Arc::new(crate::storage::Storage::new(&config.storage).unwrap())).unwrap());
        let execution_engine = Arc::new(ExecutionEngine::new(config.clone(), blockchain.clone(), Arc::new(crate::vm::Manager::new(config.clone()).unwrap())).unwrap());
        
        let result = Manager::new(config, blockchain, execution_engine);
        assert!(result.is_ok());
    }
}
