/*!
# Execution Validator

This module provides the execution validator functionality for the Aevor blockchain.
It validates the execution of transactions to ensure they adhere to the blockchain's
rules and that their execution is correct according to the Proof of Uncorruption model.

The validator performs multiple checks, including:
- Transaction input validation
- Object access validation
- Execution result validation
- Uncorruption proof generation and verification

It works in conjunction with the TEE (Trusted Execution Environment) to provide
hardware-backed security guarantees.
*/

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::consensus::pou::ProofOfUncorruption;
use crate::core::{GlobalState, Object, ObjectID, Transaction, TransactionStatus, TransactionType};
use crate::core::transaction::ValidationStatus;
use crate::error::{AevorError, Result};
use crate::execution::{ExecutionContext, ExecutionResult, ExecutionReceipt, ExecutionStats};
use crate::execution::wasm::WasmExecutor;

/// The execution validator ensures the execution of transactions is valid
pub struct ExecutionValidator {
    /// Global state for accessing blockchain data
    state: Arc<GlobalState>,
    
    /// WebAssembly executor for contract validation
    wasm_executor: WasmExecutor,
    
    /// Validator identifier
    validator_id: String,
    
    /// Cache of validated execution results
    validation_cache: Mutex<HashMap<Vec<u8>, ValidationResult>>,
    
    /// Generation of uncorruption proofs enabled
    uncorruption_proofs_enabled: bool,
    
    /// Proof of Uncorruption component (optional)
    pou: Option<Arc<ProofOfUncorruption>>,
}

/// Result of a validation operation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Was the validation successful
    pub success: bool,
    
    /// Error message if validation failed
    pub error: Option<String>,
    
    /// Time taken to validate in milliseconds
    pub validation_time_ms: u64,
    
    /// Validator ID that performed the validation
    pub validator_id: String,
    
    /// Timestamp of the validation
    pub timestamp: u64,
    
    /// Uncorruption proof, if generated
    pub uncorruption_proof: Option<Vec<u8>>,
    
    /// Execution statistics, if validation was successful
    pub execution_stats: Option<ExecutionStats>,
}

impl ExecutionValidator {
    /// Creates a new execution validator
    pub fn new(state: Arc<GlobalState>, wasm_executor: WasmExecutor, validator_id: String) -> Self {
        Self {
            state,
            wasm_executor,
            validator_id,
            validation_cache: Mutex::new(HashMap::new()),
            uncorruption_proofs_enabled: true,
            pou: None,
        }
    }
    
    /// Creates a new execution validator with Proof of Uncorruption component
    pub fn new_with_pou(
        state: Arc<GlobalState>,
        wasm_executor: WasmExecutor,
        validator_id: String,
        pou: Arc<ProofOfUncorruption>,
    ) -> Self {
        Self {
            state,
            wasm_executor,
            validator_id,
            validation_cache: Mutex::new(HashMap::new()),
            uncorruption_proofs_enabled: true,
            pou: Some(pou),
        }
    }
    
    /// Validates the execution of a transaction
    pub fn validate_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<ValidationResult> {
        // Check cache first
        let tx_hash = tx.hash();
        
        // Check if we've already validated this transaction
        if let Some(cached_result) = self.validation_cache.lock().unwrap().get(&tx_hash) {
            return Ok(cached_result.clone());
        }
        
        // Start validation timer
        let start_time = Instant::now();
        
        // Perform the validation
        let validation_result = self.perform_transaction_validation(tx, result);
        
        // Calculate validation time
        let validation_time_ms = start_time.elapsed().as_millis() as u64;
        
        // Create validation result
        let result = match validation_result {
            Ok(stats) => {
                // Generate uncorruption proof if enabled
                let uncorruption_proof = if self.uncorruption_proofs_enabled {
                    Some(self.generate_uncorruption_proof(tx, result)?)
                } else {
                    None
                };
                
                ValidationResult {
                    success: true,
                    error: None,
                    validation_time_ms,
                    validator_id: self.validator_id.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    uncorruption_proof,
                    execution_stats: Some(stats),
                }
            },
            Err(err) => {
                ValidationResult {
                    success: false,
                    error: Some(err.to_string()),
                    validation_time_ms,
                    validator_id: self.validator_id.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    uncorruption_proof: None,
                    execution_stats: None,
                }
            }
        };
        
        // Cache the result
        self.validation_cache.lock().unwrap().insert(tx_hash, result.clone());
        
        Ok(result)
    }
    
    /// Performs the actual validation of a transaction
    fn perform_transaction_validation(&self, tx: &Transaction, result: &ExecutionResult) -> Result<ExecutionStats> {
        // Step 1: Validate transaction basic properties
        tx.validate_basic()?;
        
        // Step 2: Validate that transaction status matches result status
        if tx.status() == TransactionStatus::Pending && result.status != TransactionStatus::Success {
            return Err(AevorError::validation(format!(
                "Transaction status mismatch: expected Success, got {:?}", 
                result.status
            )));
        }
        
        // Step 3: Validate gas usage
        if let Some(gas_used) = result.gas_used {
            if gas_used > tx.gas_limit() {
                return Err(AevorError::validation(format!(
                    "Gas usage exceeds limit: {} > {}", 
                    gas_used, 
                    tx.gas_limit()
                )));
            }
        }
        
        // Step 4: Validate transaction type-specific rules
        match tx.transaction_type() {
            TransactionType::Transfer => self.validate_transfer_transaction(tx, result)?,
            TransactionType::Publish => self.validate_publish_transaction(tx, result)?,
            TransactionType::Call => self.validate_call_transaction(tx, result)?,
            TransactionType::Create => self.validate_create_transaction(tx, result)?,
            TransactionType::Delete => self.validate_delete_transaction(tx, result)?,
            TransactionType::Governance => self.validate_governance_transaction(tx, result)?,
            _ => {
                // For other transaction types, apply generic validation rules
                self.validate_object_accesses(tx, result)?;
            }
        }
        
        // Step 5: Validate execution receipt if present
        if let Some(receipt) = &result.receipt {
            // Verify receipt signature
            if !self.verify_receipt_signature(receipt) {
                return Err(AevorError::validation("Invalid execution receipt signature"));
            }
            
            // Verify receipt matches transaction hash
            if receipt.tx_hash != tx.hash() {
                return Err(AevorError::validation("Execution receipt transaction hash mismatch"));
            }
            
            // Verify TEE attestation if present
            if let Some(attestation) = &receipt.tee_attestation {
                if !self.verify_tee_attestation(attestation) {
                    return Err(AevorError::validation("Invalid TEE attestation in execution receipt"));
                }
            }
        }
        
        // Create execution stats
        let stats = ExecutionStats {
            transactions_processed: 1,
            transactions_successful: if result.status == TransactionStatus::Success { 1 } else { 0 },
            transactions_failed: if result.status != TransactionStatus::Success { 1 } else { 0 },
            gas_used: result.gas_used.unwrap_or(0),
            execution_time_ms: result.execution_time_ms,
            objects_created: result.created_objects.len(),
            objects_modified: result.modified_objects.len(),
            objects_deleted: result.deleted_objects.len(),
            superpositioned_objects: result.superpositioned_objects.len(),
        };
        
        Ok(stats)
    }
    
    /// Validates object accesses in a transaction
    fn validate_object_accesses(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Check that all objects in the read and write sets are accessed properly
        let declared_reads: HashSet<&ObjectID> = tx.read_set().iter().collect();
        let declared_writes: HashSet<&ObjectID> = tx.write_set().iter().collect();
        
        let actual_modified: HashSet<&ObjectID> = result.modified_objects.iter().collect();
        
        // Ensure all modified objects were declared in the write set
        for obj_id in &actual_modified {
            if !declared_writes.contains(obj_id) {
                return Err(AevorError::validation(format!(
                    "Object {} was modified but not declared in write set", 
                    hex::encode(&obj_id.0)
                )));
            }
        }
        
        // Check for modifications to read-only objects
        for obj_id in &declared_reads {
            if declared_writes.contains(obj_id) {
                continue; // Skip objects that are in both read and write sets
            }
            
            if actual_modified.contains(obj_id) {
                return Err(AevorError::validation(format!(
                    "Read-only object {} was modified", 
                    hex::encode(&obj_id.0)
                )));
            }
        }
        
        Ok(())
    }
    
    /// Validates a transfer transaction
    fn validate_transfer_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Ensure basic access validation passes
        self.validate_object_accesses(tx, result)?;
        
        // Additional transfer-specific validation
        if let crate::core::transaction::TransactionData::Transfer(data) = tx.data() {
            // Validate sender has sufficient balance
            let sender_account = self.get_account_for_address(&tx.sender())?;
            
            // Validate recipient exists or was created
            let recipient_exists = self.state.object_exists(&ObjectID(data.recipient.clone()));
            let recipient_created = result.created_objects.iter().any(|obj_id| obj_id.0 == data.recipient);
            
            if !recipient_exists && !recipient_created {
                return Err(AevorError::validation("Transfer recipient does not exist"));
            }
        }
        
        Ok(())
    }
    
    /// Validates a publish transaction
    fn validate_publish_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Ensure basic access validation passes
        self.validate_object_accesses(tx, result)?;
        
        // Additional publish-specific validation
        if let crate::core::transaction::TransactionData::Publish(data) = tx.data() {
            // Validate at least one object was created
            if result.created_objects.is_empty() {
                return Err(AevorError::validation("Publish transaction must create at least one object"));
            }
            
            // Validate contract bytecode is valid
            // In a real implementation, this would validate the bytecode format
            if data.bytecode.is_empty() {
                return Err(AevorError::validation("Contract bytecode cannot be empty"));
            }
        }
        
        Ok(())
    }
    
    /// Validates a call transaction
    fn validate_call_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Ensure basic access validation passes
        self.validate_object_accesses(tx, result)?;
        
        // Additional call-specific validation
        if let crate::core::transaction::TransactionData::Call(data) = tx.data() {
            // Validate contract exists
            if !self.state.object_exists(&data.contract) {
                return Err(AevorError::validation("Contract does not exist"));
            }
            
            // For read-only calls, ensure no objects were modified
            if !data.state_changes {
                if !result.modified_objects.is_empty() {
                    return Err(AevorError::validation("Read-only call modified objects"));
                }
            }
        }
        
        Ok(())
    }
    
    /// Validates a create transaction
    fn validate_create_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Ensure basic access validation passes
        self.validate_object_accesses(tx, result)?;
        
        // Additional create-specific validation
        if let crate::core::transaction::TransactionData::Create(_) = tx.data() {
            // Validate at least one object was created
            if result.created_objects.is_empty() {
                return Err(AevorError::validation("Create transaction must create at least one object"));
            }
        }
        
        Ok(())
    }
    
    /// Validates a delete transaction
    fn validate_delete_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Ensure basic access validation passes
        self.validate_object_accesses(tx, result)?;
        
        // Additional delete-specific validation
        if let crate::core::transaction::TransactionData::Delete(data) = tx.data() {
            // Validate object was deleted
            if !result.deleted_objects.contains(&data.object_id) {
                return Err(AevorError::validation("Delete transaction did not delete the specified object"));
            }
            
            // Validate object existed before deletion
            if !self.state.object_exists(&data.object_id) && 
               !result.modified_objects.contains(&data.object_id) {
                return Err(AevorError::validation("Cannot delete non-existent object"));
            }
        }
        
        Ok(())
    }
    
    /// Validates a governance transaction
    fn validate_governance_transaction(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Ensure basic access validation passes
        self.validate_object_accesses(tx, result)?;
        
        // Additional governance-specific validation
        if let crate::core::transaction::TransactionData::Governance(data) = tx.data() {
            // In a real implementation, this would validate governance-specific rules
            // For now, we just perform basic validation
            if data.params.is_empty() {
                return Err(AevorError::validation("Governance parameters cannot be empty"));
            }
        }
        
        Ok(())
    }
    
    /// Generates an uncorruption proof for a transaction execution
    fn generate_uncorruption_proof(&self, tx: &Transaction, result: &ExecutionResult) -> Result<Vec<u8>> {
        // In a real implementation, this would generate a cryptographic proof
        // that the execution was uncorrupted.
        
        // For now, we'll just create a placeholder
        let mut proof = Vec::new();
        
        // Add transaction hash
        proof.extend_from_slice(&tx.hash());
        
        // Add execution hash if available
        proof.extend_from_slice(&result.execution_hash);
        
        // Add validator ID
        proof.extend_from_slice(self.validator_id.as_bytes());
        
        // Add timestamp
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        proof.extend_from_slice(&timestamp.to_le_bytes());
        
        // In a real implementation, we would sign this proof
        // let signature = sign_data(&proof, &validator_private_key);
        // proof.extend_from_slice(&signature);
        
        Ok(proof)
    }
    
    /// Validates an execution context
    pub fn validate_context(&self, context: &ExecutionContext) -> Result<ValidationResult> {
        // Start validation timer
        let start_time = Instant::now();
        
        // Perform the validation
        let validation_result = self.perform_context_validation(context);
        
        // Calculate validation time
        let validation_time_ms = start_time.elapsed().as_millis() as u64;
        
        // Create validation result
        let result = match validation_result {
            Ok(stats) => {
                // Generate uncorruption proof if enabled
                let uncorruption_proof = if self.uncorruption_proofs_enabled {
                    Some(self.generate_context_uncorruption_proof(context)?)
                } else {
                    None
                };
                
                ValidationResult {
                    success: true,
                    error: None,
                    validation_time_ms,
                    validator_id: self.validator_id.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    uncorruption_proof,
                    execution_stats: Some(stats),
                }
            },
            Err(err) => {
                ValidationResult {
                    success: false,
                    error: Some(err.to_string()),
                    validation_time_ms,
                    validator_id: self.validator_id.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    uncorruption_proof: None,
                    execution_stats: None,
                }
            }
        };
        
        Ok(result)
    }
    
    /// Performs validation of an execution context
    fn perform_context_validation(&self, context: &ExecutionContext) -> Result<ExecutionStats> {
        // Validate context ID
        if context.id().is_empty() {
            return Err(AevorError::validation("Execution context ID is empty"));
        }
        
        // Validate resource limits
        let limits = context.limits();
        if limits.max_memory_bytes == 0 {
            return Err(AevorError::validation("Memory limit is zero"));
        }
        if limits.max_time_ms == 0 {
            return Err(AevorError::validation("Time limit is zero"));
        }
        
        // Validate resource usage is within limits
        let usage = context.resource_usage();
        if usage.memory_bytes > limits.max_memory_bytes {
            return Err(AevorError::validation(format!(
                "Memory usage exceeds limit: {} > {}", 
                usage.memory_bytes, 
                limits.max_memory_bytes
            )));
        }
        if usage.instructions > limits.max_instructions {
            return Err(AevorError::validation(format!(
                "Instruction count exceeds limit: {} > {}", 
                usage.instructions, 
                limits.max_instructions
            )));
        }
        if usage.objects_created > limits.max_objects_created {
            return Err(AevorError::validation(format!(
                "Created objects count exceeds limit: {} > {}", 
                usage.objects_created, 
                limits.max_objects_created
            )));
        }
        if usage.objects_modified > limits.max_objects_modified {
            return Err(AevorError::validation(format!(
                "Modified objects count exceeds limit: {} > {}", 
                usage.objects_modified, 
                limits.max_objects_modified
            )));
        }
        
        // Create execution stats
        let stats = ExecutionStats {
            transactions_processed: 1,
            transactions_successful: 1,
            transactions_failed: 0,
            gas_used: usage.instructions, // Use instructions as gas estimate
            execution_time_ms: usage.execution_time_ms,
            objects_created: usage.created_objects.len(),
            objects_modified: usage.modified_objects.len(),
            objects_deleted: usage.deleted_objects.len(),
            superpositioned_objects: 0, // Context doesn't track this directly
        };
        
        Ok(stats)
    }
    
    /// Generates an uncorruption proof for an execution context
    fn generate_context_uncorruption_proof(&self, context: &ExecutionContext) -> Result<Vec<u8>> {
        // In a real implementation, this would generate a cryptographic proof
        // that the context execution was uncorrupted.
        
        // For now, we'll just create a placeholder
        let mut proof = Vec::new();
        
        // Add context ID
        proof.extend_from_slice(context.id().as_bytes());
        
        // Add object hashes
        for (obj_id, obj) in context.objects() {
            proof.extend_from_slice(&obj_id.0);
            
            // Generate object hash and add it
            // In a real implementation, this would be a proper hash function
            let obj_hash = obj.calculate_hash();
            proof.extend_from_slice(&obj_hash);
        }
        
        // Add validator ID
        proof.extend_from_slice(self.validator_id.as_bytes());
        
        // Add timestamp
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        proof.extend_from_slice(&timestamp.to_le_bytes());
        
        // In a real implementation, we would sign this proof
        // let signature = sign_data(&proof, &validator_private_key);
        // proof.extend_from_slice(&signature);
        
        Ok(proof)
    }
    
    /// Gets an account object for an address
    fn get_account_for_address(&self, address: &[u8]) -> Result<Object> {
        // In a real implementation, this would fetch the account object
        // For now, we'll return a dummy object
        let object_id = ObjectID(address.to_vec());
        
        match self.state.get_object(&object_id) {
            Some(obj) => Ok(obj.clone()),
            None => Err(AevorError::validation(format!("Account does not exist: {}", hex::encode(address))))
        }
    }
    
    /// Verifies a receipt signature
    fn verify_receipt_signature(&self, receipt: &ExecutionReceipt) -> bool {
        // In a real implementation, this would verify the signature
        // For now, we'll just return true
        true
    }
    
    /// Verifies a TEE attestation
    fn verify_tee_attestation(&self, attestation: &[u8]) -> bool {
        // In a real implementation, this would verify the TEE attestation
        // For now, we'll just return true if the attestation is not empty
        !attestation.is_empty()
    }
    
    /// Clears the validation cache
    pub fn clear_cache(&mut self) {
        self.validation_cache.lock().unwrap().clear();
    }
    
    /// Gets the validator ID
    pub fn get_validator_id(&self) -> &str {
        &self.validator_id
    }
    
    /// Checks if uncorruption proofs are enabled
    pub fn are_uncorruption_proofs_enabled(&self) -> bool {
        self.uncorruption_proofs_enabled
    }
    
    /// Sets whether uncorruption proofs are enabled
    pub fn set_uncorruption_proofs_enabled(&mut self, enabled: bool) {
        self.uncorruption_proofs_enabled = enabled;
    }
    
    /// Gets the associated Proof of Uncorruption component
    pub fn get_pou(&self) -> Option<Arc<ProofOfUncorruption>> {
        self.pou.clone()
    }
    
    /// Sets the associated Proof of Uncorruption component
    pub fn set_pou(&mut self, pou: Arc<ProofOfUncorruption>) {
        self.pou = Some(pou);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{TransactionBuilder, TransactionData};
    use crate::core::transaction::data::TransferData;
    use crate::execution::context::{ExecutionContext, ResourceLimits, ResourceUsage};
    
    /// Creates a test validator
    fn create_test_validator() -> ExecutionValidator {
        let state = Arc::new(GlobalState::new().unwrap());
        let wasm_executor = WasmExecutor::new().unwrap();
        let validator_id = "test-validator".to_string();
        
        ExecutionValidator::new(state, wasm_executor, validator_id)
    }
    
    /// Creates a test transaction
    fn create_test_transaction() -> Transaction {
        let sender = vec![1, 2, 3, 4];
        let recipient = vec![5, 6, 7, 8];
        let amount = 100;
        
        let data = TransactionData::Transfer(TransferData {
            recipient,
            amount,
        });
        
        TransactionBuilder::new()
            .sender(sender)
            .nonce(1)
            .gas_limit(100000)
            .gas_price(1)
            .data(data)
            .chain_id(vec![9, 10, 11, 12])
            .build()
            .unwrap()
    }
    
    /// Creates a test execution result
    fn create_test_execution_result() -> ExecutionResult {
        ExecutionResult {
            tx_hash: vec![1, 2, 3, 4],
            status: TransactionStatus::Success,
            gas_used: Some(50000),
            execution_time_ms: 100,
            created_objects: vec![],
            modified_objects: vec![],
            deleted_objects: vec![],
            superpositioned_objects: vec![],
            error: None,
            receipt: None,
            execution_hash: vec![5, 6, 7, 8],
        }
    }
    
    /// Creates a test execution context
    fn create_test_execution_context() -> ExecutionContext {
        let limits = ResourceLimits {
            max_memory_bytes: 1024 * 1024, // 1 MB
            max_time_ms: 1000,             // 1 second
            max_storage_bytes: 1024 * 1024, // 1 MB
            max_instructions: 1_000_000,
            max_objects_created: 10,
            max_objects_modified: 10,
        };
        
        let mut context = ExecutionContext::new(limits);
        
        // Add some resource usage
        let resource_usage = ResourceUsage {
            memory_bytes: 512 * 1024,      // 512 KB
            storage_bytes: 256 * 1024,     // 256 KB
            instructions: 500_000,
            objects_created: 2,
            objects_modified: 3,
            execution_time_ms: 500,
            modified_objects: vec![],
            created_objects: vec![],
            deleted_objects: vec![],
            logs: vec![],
        };
        
        // Set usage via reflection (not ideal but works for tests)
        unsafe {
            let usage_ptr = &context as *const ExecutionContext as *mut ExecutionContext;
            let usage_ref = &mut (*usage_ptr).resource_usage;
            *usage_ref = resource_usage;
        }
        
        context
    }
    
    #[test]
    fn test_validator_creation() {
        let validator = create_test_validator();
        assert_eq!(validator.get_validator_id(), "test-validator");
        assert!(validator.are_uncorruption_proofs_enabled());
    }
    
    #[test]
    fn test_validate_transaction() {
        let validator = create_test_validator();
        let tx = create_test_transaction();
        let result = create_test_execution_result();
        
        let validation_result = validator.validate_transaction(&tx, &result).unwrap();
        assert!(validation_result.success);
        assert!(validation_result.error.is_none());
        assert!(validation_result.validation_time_ms > 0);
        assert_eq!(validation_result.validator_id, "test-validator");
        assert!(validation_result.timestamp > 0);
        assert!(validation_result.uncorruption_proof.is_some());
        assert!(validation_result.execution_stats.is_some());
    }
    
    #[test]
    fn test_validate_context() {
        let validator = create_test_validator();
        let context = create_test_execution_context();
        
        let validation_result = validator.validate_context(&context).unwrap();
        assert!(validation_result.success);
        assert!(validation_result.error.is_none());
        assert!(validation_result.validation_time_ms > 0);
        assert_eq!(validation_result.validator_id, "test-validator");
        assert!(validation_result.timestamp > 0);
        assert!(validation_result.uncorruption_proof.is_some());
        assert!(validation_result.execution_stats.is_some());
    }
    
    #[test]
    fn test_uncorruption_proofs() {
        let mut validator = create_test_validator();
        let tx = create_test_transaction();
        let result = create_test_execution_result();
        
        // With proofs enabled
        let validation_result = validator.validate_transaction(&tx, &result).unwrap();
        assert!(validation_result.uncorruption_proof.is_some());
        
        // Disable proofs
        validator.set_uncorruption_proofs_enabled(false);
        assert!(!validator.are_uncorruption_proofs_enabled());
        
        // With proofs disabled
        let validation_result = validator.validate_transaction(&tx, &result).unwrap();
        assert!(validation_result.uncorruption_proof.is_none());
    }
    
    #[test]
    fn test_validation_cache() {
        let mut validator = create_test_validator();
        let tx = create_test_transaction();
        let result = create_test_execution_result();
        
        // First validation
        let first_result = validator.validate_transaction(&tx, &result).unwrap();
        
        // Second validation should use the cache
        let second_result = validator.validate_transaction(&tx, &result).unwrap();
        
        // Results should be identical
        assert_eq!(first_result.success, second_result.success);
        assert_eq!(first_result.error, second_result.error);
        assert_eq!(first_result.validation_time_ms, second_result.validation_time_ms);
        assert_eq!(first_result.validator_id, second_result.validator_id);
        assert_eq!(first_result.timestamp, second_result.timestamp);
        
        // Clear cache
        validator.clear_cache();
        
        // Third validation should not use the cache
        let third_result = validator.validate_transaction(&tx, &result).unwrap();
        
        // Time and timestamp should be different
        assert_ne!(first_result.timestamp, third_result.timestamp);
    }
}
