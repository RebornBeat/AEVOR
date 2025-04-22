/*!
# Execution Module

This module handles the execution of transactions in the Aevor blockchain. It
provides the core functionality for transaction processing, including:

- Transaction execution and validation
- Trusted Execution Environment (TEE) integration
- Transaction superposition for parallel execution
- WebAssembly virtual machine for smart contracts
- Execution context management

The execution module is designed to maximize parallelism while maintaining
security through the Proof of Uncorruption model.
*/

use std::sync::Arc;

use crate::core::Transaction;
use crate::error::Result;

pub mod context;
pub mod engine;
pub mod prefetch;
pub mod tee;
pub mod validator;
pub mod wasm;

pub use context::ExecutionContext;
pub use engine::{ExecutionEngine, ExecutionResult, ExecutionReceipt, ExecutionStats, ExecutionMode};

/// Manager for the execution subsystem
pub struct Engine {
    /// Internal execution engine
    engine: Arc<ExecutionEngine>,
}

impl Engine {
    /// Creates a new execution engine
    pub fn new(
        config: Arc<crate::config::AevorConfig>,
        state: Arc<crate::core::GlobalState>,
        vm_manager: Arc<crate::vm::Manager>,
    ) -> Result<Self> {
        let engine = Arc::new(ExecutionEngine::new(config, state, vm_manager)?);
        
        Ok(Self {
            engine,
        })
    }
    
    /// Executes a transaction
    pub async fn execute_transaction(&self, transaction: Transaction) -> Result<ExecutionResult> {
        self.engine.execute_transaction(transaction).await
    }
    
    /// Executes a batch of transactions
    pub async fn execute_batch(&self, transactions: Vec<Transaction>) -> Result<Vec<ExecutionResult>> {
        self.engine.execute_batch(transactions).await
    }
    
    /// Gets the execution statistics
    pub fn get_statistics(&self) -> ExecutionStats {
        self.engine.get_statistics()
    }
    
    /// Resets the execution statistics
    pub fn reset_statistics(&self) {
        self.engine.reset_statistics();
    }
    
    /// Checks if the engine supports TEE
    pub fn supports_tee(&self) -> bool {
        self.engine.is_tee_enabled()
    }
    
    /// Checks if the engine supports superposition
    pub fn supports_superposition(&self) -> bool {
        self.engine.is_superposition_enabled()
    }
    
    /// Starts the execution engine and related services
    pub async fn start(&self) -> Result<()> {
        // Start background services
        Ok(())
    }
    
    /// Stops the execution engine and related services
    pub async fn stop(&self) -> Result<()> {
        // Stop background services
        Ok(())
    }
}

/// Execution options for transaction processing
#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    /// Execution mode
    pub mode: ExecutionMode,
    
    /// Whether to use TEE
    pub use_tee: bool,
    
    /// Whether to use superposition
    pub use_superposition: bool,
    
    /// Maximum gas to use
    pub max_gas: Option<u64>,
    
    /// Whether to commit results to state
    pub commit: bool,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::Standard,
            use_tee: true,
            use_superposition: true,
            max_gas: None,
            commit: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AevorConfig;
    use crate::core::{GlobalState, Transaction, TransactionType, TransactionData};
    use crate::core::transaction::data::TransferData;
    
    /// Creates a test execution engine
    async fn create_test_engine() -> Engine {
        let config = Arc::new(AevorConfig::default());
        let state = Arc::new(GlobalState::new().unwrap());
        let vm_manager = Arc::new(crate::vm::Manager::new(config.clone()).unwrap());
        
        Engine::new(config, state, vm_manager).unwrap()
    }
    
    /// Creates a test transfer transaction
    fn create_test_transfer_transaction() -> Transaction {
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
    
    #[tokio::test]
    async fn test_execution_engine_creation() {
        let engine = create_test_engine().await;
        assert!(engine.supports_superposition());
    }
    
    #[tokio::test]
    async fn test_execution_engine_start_stop() {
        let engine = create_test_engine().await;
        
        // Start and stop the engine
        assert!(engine.start().await.is_ok());
        assert!(engine.stop().await.is_ok());
    }
}
