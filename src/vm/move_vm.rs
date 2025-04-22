use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use wasmer::{Store, Module as WasmerModule, Instance};

use crate::config::VmConfig;
use crate::core::object::ObjectID;
use crate::error::{AevorError, Result};
use crate::vm::bytecode::Module;
use crate::vm::runtime::{ExecutionContext, ExecutionResult, Runtime};

/// Configuration for the Move virtual machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMConfig {
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    
    /// Maximum execution time in milliseconds
    pub max_execution_time_ms: u64,
    
    /// Gas limit for VM execution
    pub gas_limit: u64,
    
    /// Gas price in nano tokens
    pub gas_price: u64,
    
    /// Whether gas metering is enabled
    pub gas_metering_enabled: bool,
    
    /// Whether debugging is enabled
    pub debug_enabled: bool,
}

/// Gas costs for Move VM operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCosts {
    /// Cost per instruction executed
    pub instruction_cost: u64,
    
    /// Cost per byte of memory allocated
    pub memory_cost: u64,
    
    /// Cost per byte of storage accessed
    pub storage_cost: u64,
    
    /// Cost per byte of network access
    pub network_cost: u64,
}

impl Default for GasCosts {
    fn default() -> Self {
        Self {
            instruction_cost: 1,
            memory_cost: 1,
            storage_cost: 10,
            network_cost: 50,
        }
    }
}

/// Move virtual machine implementation
pub struct MoveVM {
    /// VM configuration
    config: VMConfig,
    
    /// WebAssembly store for runtime
    store: Arc<RwLock<Store>>,
    
    /// Compiled modules cache
    modules: Arc<RwLock<HashMap<String, WasmerModule>>>,
    
    /// Module instances cache
    instances: Arc<RwLock<HashMap<String, Instance>>>,
    
    /// VM runtime
    runtime: Arc<RwLock<Runtime>>,
    
    /// Gas used in the last execution
    gas_used: Arc<RwLock<u64>>,
    
    /// Gas costs
    gas_costs: GasCosts,
    
    /// Running state
    running: bool,
}

impl MoveVM {
    /// Create a new Move VM instance
    pub fn new(config: &VmConfig) -> Result<Self> {
        // Create WebAssembly store
        let store = Store::default();
        
        // Create VM runtime
        let runtime = Runtime::new(config)?;
        
        Ok(Self {
            config: VMConfig {
                max_memory_bytes: config.max_memory_bytes,
                max_execution_time_ms: config.max_execution_time_ms,
                gas_limit: config.gas_limit,
                gas_price: config.gas_price,
                gas_metering_enabled: config.gas_metering_enabled,
                debug_enabled: config.debug_enabled,
            },
            store: Arc::new(RwLock::new(store)),
            modules: Arc::new(RwLock::new(HashMap::new())),
            instances: Arc::new(RwLock::new(HashMap::new())),
            runtime: Arc::new(RwLock::new(runtime)),
            gas_used: Arc::new(RwLock::new(0)),
            gas_costs: GasCosts::default(),
            running: false,
        })
    }
    
    /// Start the Move VM
    pub async fn start(&self) -> Result<()> {
        // Initialize the runtime
        let mut runtime_guard = self.runtime.write().unwrap();
        runtime_guard.start().await?;
        
        // Mark as running
        let this = unsafe { &mut *(self as *const Self as *mut Self) };
        this.running = true;
        
        Ok(())
    }
    
    /// Stop the Move VM
    pub async fn stop(&self) -> Result<()> {
        // Stop the runtime
        let mut runtime_guard = self.runtime.write().unwrap();
        runtime_guard.stop().await?;
        
        // Mark as not running
        let this = unsafe { &mut *(self as *const Self as *mut Self) };
        this.running = false;
        
        Ok(())
    }
    
    /// Deploy a module to the VM
    pub async fn deploy_module(&self, module: Module, context: ExecutionContext) -> Result<ExecutionResult> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        // Check if module already exists
        {
            let modules = self.modules.read().unwrap();
            if modules.contains_key(&module.id()) {
                return Err(AevorError::vm(format!("Module {} already exists", module.id())));
            }
        }
        
        // Compile the module
        let wasmer_module = self.compile_module(&module)?;
        
        // Create execution context for deployment
        let mut deploy_context = context;
        deploy_context.set_operation("deploy_module");
        deploy_context.set_module_name(&module.name);
        
        // Store module in cache
        {
            let mut modules = self.modules.write().unwrap();
            modules.insert(module.id(), wasmer_module);
        }
        
        // Create execution result
        let result = ExecutionResult {
            success: true,
            return_value: None,
            gas_used: 0, // Deployment gas cost calculation would go here
            execution_time_ms: 0,
            logs: vec![format!("Deployed module {}", module.id())],
            created_objects: vec![],
            modified_objects: vec![],
            deleted_objects: vec![],
        };
        
        Ok(result)
    }
    
    /// Execute a function in a deployed module
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
        
        // Get contract object from context
        let contract_object = context.get_object(&contract_id)?;
        
        // Extract module ID from contract object
        let module_id = match contract_object.get_metadata("module_id") {
            Some(id) => String::from_utf8_lossy(id).to_string(),
            None => return Err(AevorError::vm("Contract object does not have a module_id")),
        };
        
        // Check if module exists
        let instance = {
            let instances = self.instances.read().unwrap();
            match instances.get(&module_id) {
                Some(instance) => instance.clone(),
                None => {
                    // Try to instantiate the module
                    let modules = self.modules.read().unwrap();
                    let wasmer_module = match modules.get(&module_id) {
                        Some(module) => module.clone(),
                        None => return Err(AevorError::vm(format!("Module {} not found", module_id))),
                    };
                    
                    drop(instances);
                    drop(modules);
                    
                    // Instantiate the module
                    let instance = self.instantiate_module(&wasmer_module)?;
                    
                    // Cache the instance
                    let mut instances = self.instances.write().unwrap();
                    instances.insert(module_id.clone(), instance.clone());
                    
                    instance
                }
            }
        };
        
        // Reset gas used
        *self.gas_used.write().unwrap() = 0;
        
        // Create execution context for function call
        let mut call_context = context;
        call_context.set_operation("execute_function");
        call_context.set_module_name(&module_id);
        call_context.set_function_name(function);
        
        // Get runtime
        let runtime = self.runtime.read().unwrap();
        
        // Execute the function
        let start_time = std::time::Instant::now();
        let result = runtime.execute(&instance, function, &args, &call_context)?;
        let execution_time = start_time.elapsed();
        
        // Get gas used
        let gas_used = *self.gas_used.read().unwrap();
        
        // Create execution result
        let result = ExecutionResult {
            success: result.success,
            return_value: result.return_value,
            gas_used,
            execution_time_ms: execution_time.as_millis() as u64,
            logs: result.logs,
            created_objects: result.created_objects,
            modified_objects: result.modified_objects,
            deleted_objects: result.deleted_objects,
        };
        
        Ok(result)
    }
    
    /// Get a module from cache by ID
    pub async fn get_module(&self, module_id: &str) -> Result<Option<Module>> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        // In a real implementation, this would retrieve the Module struct
        // from storage or by reconstructing it from the Wasmer module
        // For now, we'll just return None
        Ok(None)
    }
    
    /// Check if a module exists
    pub async fn has_module(&self, module_id: &str) -> Result<bool> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        let modules = self.modules.read().unwrap();
        Ok(modules.contains_key(module_id))
    }
    
    /// List all module IDs
    pub async fn list_modules(&self) -> Result<Vec<String>> {
        if !self.running {
            return Err(AevorError::vm("VM is not running"));
        }
        
        let modules = self.modules.read().unwrap();
        Ok(modules.keys().cloned().collect())
    }
    
    /// Compile a module to WebAssembly
    fn compile_module(&self, module: &Module) -> Result<WasmerModule> {
        // In a real implementation, this would:
        // 1. Convert Move bytecode to WebAssembly or compile directly
        // 2. Use Wasmer to compile the WebAssembly
        
        // For this implementation, we'll create a simple "dummy" module
        // that just returns the input arguments
        
        // This is a simplification - real implementation would actually
        // compile the Move bytecode to WebAssembly
        
        let store = self.store.read().unwrap();
        
        // Create a dummy Wasm module that exports a function for each function in the module
        let mut wasm_code = Vec::new();
        
        // In a real implementation, this would be the actual compilation
        // For now, we'll just return an error since we can't create a real module
        return Err(AevorError::vm("Module compilation not implemented"));
    }
    
    /// Instantiate a WebAssembly module
    fn instantiate_module(&self, module: &WasmerModule) -> Result<Instance> {
        // In a real implementation, this would:
        // 1. Create an import object with host functions
        // 2. Instantiate the module with the import object
        
        // For this implementation, we'll just return an error
        Err(AevorError::vm("Module instantiation not implemented"))
    }
    
    /// Get the VM configuration
    pub fn config(&self) -> &VMConfig {
        &self.config
    }
    
    /// Set gas costs
    pub fn set_gas_costs(&mut self, gas_costs: GasCosts) {
        self.gas_costs = gas_costs;
    }
    
    /// Get gas costs
    pub fn gas_costs(&self) -> &GasCosts {
        &self.gas_costs
    }
    
    /// Get the gas used in the last execution
    pub fn gas_used(&self) -> u64 {
        *self.gas_used.read().unwrap()
    }
    
    /// Get the gas limit
    pub fn gas_limit(&self) -> u64 {
        self.config.gas_limit
    }
    
    /// Set the gas limit
    pub fn set_gas_limit(&mut self, gas_limit: u64) {
        self.config.gas_limit = gas_limit;
    }
    
    /// Check if the VM is running
    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl fmt::Debug for MoveVM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MoveVM")
            .field("config", &self.config)
            .field("gas_costs", &self.gas_costs)
            .field("running", &self.running)
            .field("module_count", &self.modules.read().unwrap().len())
            .field("instance_count", &self.instances.read().unwrap().len())
            .finish()
    }
}

/// Move value types that can be passed to/from WebAssembly
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MoveValue {
    /// Boolean value
    Bool(bool),
    
    /// 8-bit unsigned integer
    U8(u8),
    
    /// 64-bit unsigned integer
    U64(u64),
    
    /// 128-bit unsigned integer
    U128(u128),
    
    /// Address (account address)
    Address(Vec<u8>),
    
    /// Vector of values
    Vector(Vec<MoveValue>),
    
    /// Struct
    Struct(Vec<MoveValue>),
}

impl MoveValue {
    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            MoveValue::Bool(b) => vec![if *b { 1 } else { 0 }],
            MoveValue::U8(n) => vec![*n],
            MoveValue::U64(n) => n.to_le_bytes().to_vec(),
            MoveValue::U128(n) => n.to_le_bytes().to_vec(),
            MoveValue::Address(bytes) => bytes.clone(),
            MoveValue::Vector(values) => {
                let mut result = Vec::new();
                // Add length first (little endian u32)
                let len = values.len() as u32;
                result.extend_from_slice(&len.to_le_bytes());
                // Add each value
                for value in values {
                    let bytes = value.to_bytes();
                    // Add length of value
                    let value_len = bytes.len() as u32;
                    result.extend_from_slice(&value_len.to_le_bytes());
                    // Add value bytes
                    result.extend(bytes);
                }
                result
            },
            MoveValue::Struct(fields) => {
                let mut result = Vec::new();
                // Add number of fields (little endian u32)
                let len = fields.len() as u32;
                result.extend_from_slice(&len.to_le_bytes());
                // Add each field
                for field in fields {
                    let bytes = field.to_bytes();
                    // Add length of field
                    let field_len = bytes.len() as u32;
                    result.extend_from_slice(&field_len.to_le_bytes());
                    // Add field bytes
                    result.extend(bytes);
                }
                result
            },
        }
    }
    
    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8], value_type: &str) -> Result<Self> {
        match value_type {
            "bool" => {
                if bytes.len() != 1 {
                    return Err(AevorError::vm(format!("Invalid bool byte length: {}", bytes.len())));
                }
                Ok(MoveValue::Bool(bytes[0] != 0))
            },
            "u8" => {
                if bytes.len() != 1 {
                    return Err(AevorError::vm(format!("Invalid u8 byte length: {}", bytes.len())));
                }
                Ok(MoveValue::U8(bytes[0]))
            },
            "u64" => {
                if bytes.len() != 8 {
                    return Err(AevorError::vm(format!("Invalid u64 byte length: {}", bytes.len())));
                }
                let mut array = [0u8; 8];
                array.copy_from_slice(bytes);
                Ok(MoveValue::U64(u64::from_le_bytes(array)))
            },
            "u128" => {
                if bytes.len() != 16 {
                    return Err(AevorError::vm(format!("Invalid u128 byte length: {}", bytes.len())));
                }
                let mut array = [0u8; 16];
                array.copy_from_slice(bytes);
                Ok(MoveValue::U128(u128::from_le_bytes(array)))
            },
            "address" => {
                Ok(MoveValue::Address(bytes.to_vec()))
            },
            _ if value_type.starts_with("vector<") => {
                if bytes.len() < 4 {
                    return Err(AevorError::vm("Invalid vector bytes"));
                }
                
                let mut offset = 0;
                
                // Read vector length
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bytes[offset..offset+4]);
                let len = u32::from_le_bytes(len_bytes) as usize;
                offset += 4;
                
                // Parse inner type
                let inner_type = &value_type[7..value_type.len()-1];
                
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    if offset + 4 > bytes.len() {
                        return Err(AevorError::vm("Invalid vector element length"));
                    }
                    
                    // Read element length
                    let mut elem_len_bytes = [0u8; 4];
                    elem_len_bytes.copy_from_slice(&bytes[offset..offset+4]);
                    let elem_len = u32::from_le_bytes(elem_len_bytes) as usize;
                    offset += 4;
                    
                    if offset + elem_len > bytes.len() {
                        return Err(AevorError::vm("Invalid vector element bytes"));
                    }
                    
                    // Parse element
                    let elem = MoveValue::from_bytes(&bytes[offset..offset+elem_len], inner_type)?;
                    values.push(elem);
                    offset += elem_len;
                }
                
                Ok(MoveValue::Vector(values))
            },
            _ => {
                // Assume it's a struct type
                if bytes.len() < 4 {
                    return Err(AevorError::vm("Invalid struct bytes"));
                }
                
                let mut offset = 0;
                
                // Read struct field count
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bytes[offset..offset+4]);
                let len = u32::from_le_bytes(len_bytes) as usize;
                offset += 4;
                
                // We'd need field type information to properly parse structs
                // For this implementation, we'll parse generic field values
                
                let mut fields = Vec::with_capacity(len);
                for _ in 0..len {
                    if offset + 4 > bytes.len() {
                        return Err(AevorError::vm("Invalid struct field length"));
                    }
                    
                    // Read field length
                    let mut field_len_bytes = [0u8; 4];
                    field_len_bytes.copy_from_slice(&bytes[offset..offset+4]);
                    let field_len = u32::from_le_bytes(field_len_bytes) as usize;
                    offset += 4;
                    
                    if offset + field_len > bytes.len() {
                        return Err(AevorError::vm("Invalid struct field bytes"));
                    }
                    
                    // Parse field as u64 by default (this is a simplification)
                    let field_value = if field_len == 8 {
                        let mut array = [0u8; 8];
                        array.copy_from_slice(&bytes[offset..offset+8]);
                        MoveValue::U64(u64::from_le_bytes(array))
                    } else {
                        // Treat as address for any other size
                        MoveValue::Address(bytes[offset..offset+field_len].to_vec())
                    };
                    
                    fields.push(field_value);
                    offset += field_len;
                }
                
                Ok(MoveValue::Struct(fields))
            },
        }
    }
}

/// Utility functions for Move VM values
pub struct MoveUtil;

impl MoveUtil {
    /// Convert WebAssembly value to Move value
    pub fn wasm_to_move(bytes: &[u8], value_type: &str) -> Result<MoveValue> {
        MoveValue::from_bytes(bytes, value_type)
    }
    
    /// Convert Move value to WebAssembly value
    pub fn move_to_wasm(value: &MoveValue) -> Vec<u8> {
        value.to_bytes()
    }
    
    /// Parse function arguments from bytes into Move values
    pub fn parse_args(args: &[Vec<u8>], arg_types: &[String]) -> Result<Vec<MoveValue>> {
        if args.len() != arg_types.len() {
            return Err(AevorError::vm(format!(
                "Argument count mismatch: expected {}, got {}",
                arg_types.len(),
                args.len()
            )));
        }
        
        let mut move_args = Vec::with_capacity(args.len());
        for (i, arg) in args.iter().enumerate() {
            let arg_type = &arg_types[i];
            let move_arg = MoveValue::from_bytes(arg, arg_type)?;
            move_args.push(move_arg);
        }
        
        Ok(move_args)
    }
    
    /// Serialize Move values to bytes
    pub fn serialize_values(values: &[MoveValue]) -> Vec<Vec<u8>> {
        values.iter().map(|v| v.to_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_move_value_serialization() {
        // Test bool
        let bool_value = MoveValue::Bool(true);
        let bool_bytes = bool_value.to_bytes();
        assert_eq!(bool_bytes, vec![1]);
        let bool_value2 = MoveValue::from_bytes(&bool_bytes, "bool").unwrap();
        assert_eq!(bool_value, bool_value2);
        
        // Test u8
        let u8_value = MoveValue::U8(42);
        let u8_bytes = u8_value.to_bytes();
        assert_eq!(u8_bytes, vec![42]);
        let u8_value2 = MoveValue::from_bytes(&u8_bytes, "u8").unwrap();
        assert_eq!(u8_value, u8_value2);
        
        // Test u64
        let u64_value = MoveValue::U64(12345);
        let u64_bytes = u64_value.to_bytes();
        assert_eq!(u64_bytes, 12345u64.to_le_bytes());
        let u64_value2 = MoveValue::from_bytes(&u64_bytes, "u64").unwrap();
        assert_eq!(u64_value, u64_value2);
        
        // Test u128
        let u128_value = MoveValue::U128(98765432101234);
        let u128_bytes = u128_value.to_bytes();
        assert_eq!(u128_bytes, 98765432101234u128.to_le_bytes());
        let u128_value2 = MoveValue::from_bytes(&u128_bytes, "u128").unwrap();
        assert_eq!(u128_value, u128_value2);
        
        // Test address
        let address_value = MoveValue::Address(vec![1, 2, 3, 4, 5]);
        let address_bytes = address_value.to_bytes();
        assert_eq!(address_bytes, vec![1, 2, 3, 4, 5]);
        let address_value2 = MoveValue::from_bytes(&address_bytes, "address").unwrap();
        assert_eq!(address_value, address_value2);
        
        // Test vector
        let vector_value = MoveValue::Vector(vec![
            MoveValue::U64(1),
            MoveValue::U64(2),
            MoveValue::U64(3),
        ]);
        let vector_bytes = vector_value.to_bytes();
        let vector_value2 = MoveValue::from_bytes(&vector_bytes, "vector<u64>").unwrap();
        assert_eq!(vector_value, vector_value2);
    }
    
    #[test]
    fn test_move_util_parsing() {
        let arg_types = vec!["u64".to_string(), "address".to_string()];
        let args = vec![
            123456u64.to_le_bytes().to_vec(),
            vec![1, 2, 3, 4, 5],
        ];
        
        let move_args = MoveUtil::parse_args(&args, &arg_types).unwrap();
        assert_eq!(move_args.len(), 2);
        assert_eq!(move_args[0], MoveValue::U64(123456));
        assert_eq!(move_args[1], MoveValue::Address(vec![1, 2, 3, 4, 5]));
        
        // Test serialization
        let serialized = MoveUtil::serialize_values(&move_args);
        assert_eq!(serialized.len(), 2);
        assert_eq!(serialized[0], 123456u64.to_le_bytes());
        assert_eq!(serialized[1], vec![1, 2, 3, 4, 5]);
    }
}
