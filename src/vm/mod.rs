use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use crate::config::VmConfig;
use crate::core::object::ObjectID;
use crate::error::{AevorError, Result};

pub mod bytecode;
pub mod move_vm;
pub mod runtime;

use bytecode::Module;
use move_vm::MoveVM;
use runtime::{ExecutionContext, ExecutionResult, Runtime};

/// VM Manager coordinates virtual machine instances and provides a unified interface
/// for executing smart contracts.
pub struct Manager {
    /// Configuration for the VM
    config: Arc<VmConfig>,
    
    /// Move VM Instance
    move_vm: Arc<MoveVM>,
    
    /// VM Runtime
    runtime: Arc<Runtime>,
    
    /// Indicates if the VM is running
    running: bool,
}

impl Manager {
    /// Creates a new VM Manager with the given configuration
    pub fn new(config: Arc<VmConfig>) -> Result<Self> {
        // Initialize the Move VM
        let move_vm = Arc::new(MoveVM::new(&config)?);
        
        // Initialize the runtime
        let runtime = Arc::new(Runtime::new(&config)?);
        
        Ok(Self {
            config,
            move_vm,
            runtime,
            running: false,
        })
    }
    
    /// Starts the VM Manager
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }
        
        // Start the Move VM
        self.move_vm.start().await?;
        
        // Start the runtime
        self.runtime.start().await?;
        
        self.running = true;
        Ok(())
    }
    
    /// Stops the VM Manager
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }
        
        // Stop the runtime
        self.runtime.stop().await?;
        
        // Stop the Move VM
        self.move_vm.stop().await?;
        
        self.running = false;
        Ok(())
    }
    
    /// Deploys a smart contract module
    pub async fn deploy_module(&self, module: Module, context: ExecutionContext) -> Result<ExecutionResult> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        // Deploy the module to the Move VM
        self.move_vm.deploy_module(module, context).await
    }
    
    /// Executes a function in a deployed smart contract
    pub async fn execute_function(
        &self,
        contract_id: ObjectID,
        function: &str,
        args: Vec<Vec<u8>>,
        context: ExecutionContext,
    ) -> Result<ExecutionResult> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        // Execute the function using the Move VM
        self.move_vm.execute_function(contract_id, function, args, context).await
    }
    
    /// Executes a function in a deployed smart contract using the TEE environment
    pub async fn execute_function_in_tee(
        &self,
        contract_id: ObjectID,
        function: &str,
        args: Vec<Vec<u8>>,
        context: ExecutionContext,
    ) -> Result<ExecutionResult> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        // Create a TEE execution context
        let mut tee_context = context;
        tee_context.set_tee_execution(true);
        
        // Execute the function using the Move VM in TEE mode
        self.move_vm.execute_function(contract_id, function, args, tee_context).await
    }
    
    /// Gets a deployed module by ID
    pub async fn get_module(&self, module_id: &str) -> Result<Option<Module>> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        self.move_vm.get_module(module_id).await
    }
    
    /// Checks if a module with the given ID exists
    pub async fn has_module(&self, module_id: &str) -> Result<bool> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        self.move_vm.has_module(module_id).await
    }
    
    /// Lists all deployed modules
    pub async fn list_modules(&self) -> Result<Vec<String>> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        self.move_vm.list_modules().await
    }
    
    /// Gets the VM configuration
    pub fn config(&self) -> &VmConfig {
        &self.config
    }
    
    /// Gets a reference to the Move VM
    pub fn move_vm(&self) -> &MoveVM {
        &self.move_vm
    }
    
    /// Gets a reference to the VM runtime
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }
    
    /// Checks if the VM is running
    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl fmt::Debug for Manager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VMManager")
            .field("config", &self.config)
            .field("running", &self.running)
            .finish()
    }
}

/// VM Resource Usage Metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMResourceUsage {
    /// Memory usage in bytes
    pub memory_bytes: usize,
    
    /// CPU time in milliseconds
    pub cpu_time_ms: u64,
    
    /// Storage access count
    pub storage_access_count: u64,
    
    /// Gas used
    pub gas_used: u64,
}

/// VM Execution Statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMExecutionStats {
    /// Total number of transactions executed
    pub total_transactions: u64,
    
    /// Number of successful transactions
    pub successful_transactions: u64,
    
    /// Number of failed transactions
    pub failed_transactions: u64,
    
    /// Average gas used per transaction
    pub avg_gas_used: u64,
    
    /// Average execution time in milliseconds
    pub avg_execution_time_ms: u64,
    
    /// Total gas used
    pub total_gas_used: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Helper function to create a test VM config
    fn create_test_config() -> Arc<VmConfig> {
        Arc::new(VmConfig {
            max_memory_bytes: 128 * 1024 * 1024, // 128 MB
            max_execution_time_ms: 5000,
            gas_limit: 10_000_000,
            gas_price: 1,
            gas_metering_enabled: true,
            debug_enabled: true,
            jit_enabled: true,
            max_contract_size: 1024 * 1024, // 1 MB
            max_function_name_length: 256,
            max_parameter_count: 32,
            max_call_depth: 10,
        })
    }
    
    #[tokio::test]
    async fn test_vm_manager_lifecycle() {
        let config = create_test_config();
        
        // Create a VM manager
        let mut manager = Manager::new(config).expect("Failed to create VM manager");
        assert!(!manager.is_running());
        
        // Start the VM manager
        manager.start().await.expect("Failed to start VM manager");
        assert!(manager.is_running());
        
        // Stop the VM manager
        manager.stop().await.expect("Failed to stop VM manager");
        assert!(!manager.is_running());
    }
}
