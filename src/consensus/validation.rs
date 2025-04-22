use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use std::fmt;

use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::config::AevorConfig;
use crate::core::{Block, Blockchain, Transaction, Object, ObjectID};
use crate::core::transaction::{TransactionStatus, ValidationStatus};
use crate::core::block::BlockStatus;
use crate::crypto::signature::{Signature, SignatureAlgorithm};
use crate::error::{AevorError, Result};

/// Result of validating a transaction or block
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Validation status
    pub status: ValidationStatus,
    
    /// Error message (if validation failed)
    pub error: Option<String>,
    
    /// Validator that performed the validation
    pub validator_id: Vec<u8>,
    
    /// Validator signature on the validation result
    pub signature: Vec<u8>,
    
    /// Timestamp when the validation was completed
    pub timestamp: u64,
    
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// Security level associated with this validation
    pub security_level: u8,
    
    /// TEE attestation (if available)
    pub tee_attestation: Option<Vec<u8>>,
}

impl ValidationResult {
    /// Creates a new validation result
    pub fn new(
        status: ValidationStatus,
        validator_id: Vec<u8>,
        private_key: &[u8],
    ) -> Result<Self> {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        
        // Create a signature over the validation data
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&(status as u8).to_le_bytes());
        data_to_sign.extend_from_slice(&validator_id);
        data_to_sign.extend_from_slice(&timestamp.to_le_bytes());
        
        let signature = Signature::sign(SignatureAlgorithm::ED25519, private_key, &data_to_sign)
            .map_err(|e| AevorError::crypto("Signing failed".into(), e.to_string(), None))?;
        
        Ok(Self {
            status,
            error: None,
            validator_id,
            signature: signature.value().to_vec(),
            timestamp,
            execution_time_ms: 0,
            security_level: 0,
            tee_attestation: None,
        })
    }
    
    /// Creates a validation result with an error
    pub fn with_error(
        status: ValidationStatus,
        error: String,
        validator_id: Vec<u8>,
        private_key: &[u8],
    ) -> Result<Self> {
        let mut result = Self::new(status, validator_id, private_key)?;
        result.error = Some(error);
        Ok(result)
    }
    
    /// Creates a validation result with execution time
    pub fn with_execution_time(mut self, execution_time_ms: u64) -> Self {
        self.execution_time_ms = execution_time_ms;
        self
    }
    
    /// Creates a validation result with security level
    pub fn with_security_level(mut self, security_level: u8) -> Self {
        self.security_level = security_level;
        self
    }
    
    /// Creates a validation result with TEE attestation
    pub fn with_tee_attestation(mut self, attestation: Vec<u8>) -> Self {
        self.tee_attestation = Some(attestation);
        self
    }
    
    /// Verifies the signature on this validation result
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool> {
        // Recreate the data that was signed
        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&(self.status as u8).to_le_bytes());
        data_to_verify.extend_from_slice(&self.validator_id);
        data_to_verify.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Create a signature object
        let signature = Signature::new(SignatureAlgorithm::ED25519, self.signature.clone())?;
        
        // Verify the signature
        signature.verify(public_key, &data_to_verify)
            .map_err(|e| AevorError::crypto("Signature verification failed".into(), e.to_string(), None))
    }
}

/// Represents a transaction validation request
#[derive(Debug, Clone)]
pub struct TransactionValidationRequest {
    /// Transaction to validate
    pub transaction: Transaction,
    
    /// Priority of this request (higher = more important)
    pub priority: u8,
    
    /// Deadline for validation
    pub deadline: u64,
    
    /// Requester ID
    pub requester: Vec<u8>,
}

/// Represents a block validation request
#[derive(Debug, Clone)]
pub struct BlockValidationRequest {
    /// Block to validate
    pub block: Block,
    
    /// Priority of this request (higher = more important)
    pub priority: u8,
    
    /// Deadline for validation
    pub deadline: u64,
    
    /// Requester ID
    pub requester: Vec<u8>,
}

/// Manager for transaction and block validation
#[derive(Debug)]
pub struct ValidationManager {
    /// Blockchain reference
    blockchain: Arc<Blockchain>,
    
    /// Configuration
    config: Arc<AevorConfig>,
    
    /// Validator key
    validator_key: Vec<u8>,
    
    /// Validator private key
    private_key: Vec<u8>,
    
    /// Transaction validation results by transaction hash
    transaction_results: Arc<RwLock<HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>>>>,
    
    /// Block validation results by block hash
    block_results: Arc<RwLock<HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>>>>,
    
    /// Object validation results by object ID
    object_results: Arc<RwLock<HashMap<ObjectID, HashMap<Vec<u8>, ValidationResult>>>>,
    
    /// Minimum number of validators required for consensus
    min_validators: usize,
    
    /// Validation threshold percentage (0-100)
    validation_threshold: u8,
    
    /// Pending transaction validation requests
    pending_tx_validations: Arc<RwLock<Vec<TransactionValidationRequest>>>,
    
    /// Pending block validation requests
    pending_block_validations: Arc<RwLock<Vec<BlockValidationRequest>>>,
    
    /// Maximum concurrent validations
    max_concurrent_validations: usize,
    
    /// Current number of active validations
    active_validations: Arc<RwLock<usize>>,
    
    /// TEE support enabled
    tee_enabled: bool,
    
    /// Whether the service is running
    running: Arc<RwLock<bool>>,
    
    /// Task handles
    task_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl ValidationManager {
    /// Creates a new validation manager
    pub fn new(
        config: Arc<AevorConfig>,
        blockchain: Arc<Blockchain>,
    ) -> Result<Self> {
        // In a real implementation, these keys would be loaded from secure storage
        // For now, we'll generate a simple key for testing
        let validator_key = vec![1, 2, 3, 4]; // Would be the validator's public key
        let private_key = vec![5, 6, 7, 8]; // Would be the validator's private key
        
        let min_validators = config.consensus.min_validators;
        let validation_threshold = config.consensus.validation_threshold;
        let max_concurrent_validations = config.consensus.validator.max_parallel_validations;
        let tee_enabled = config.consensus.pou.use_tee;
        
        Ok(Self {
            blockchain,
            config,
            validator_key,
            private_key,
            transaction_results: Arc::new(RwLock::new(HashMap::new())),
            block_results: Arc::new(RwLock::new(HashMap::new())),
            object_results: Arc::new(RwLock::new(HashMap::new())),
            min_validators,
            validation_threshold,
            pending_tx_validations: Arc::new(RwLock::new(Vec::new())),
            pending_block_validations: Arc::new(RwLock::new(Vec::new())),
            max_concurrent_validations,
            active_validations: Arc::new(RwLock::new(0)),
            tee_enabled,
            running: Arc::new(RwLock::new(false)),
            task_handles: Arc::new(RwLock::new(Vec::new())),
        })
    }
    
    /// Starts the validation manager
    pub async fn start(&self) -> Result<()> {
        // Check if already running
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        *running = true;
        
        // Start the validation worker tasks
        let mut task_handles = self.task_handles.write().await;
        
        // Transaction validation worker
        let tx_worker = {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.transaction_validation_worker().await;
            })
        };
        task_handles.push(tx_worker);
        
        // Block validation worker
        let block_worker = {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.block_validation_worker().await;
            })
        };
        task_handles.push(block_worker);
        
        // Cleanup worker (clean up old validation results)
        let cleanup_worker = {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.cleanup_worker().await;
            })
        };
        task_handles.push(cleanup_worker);
        
        Ok(())
    }
    
    /// Stops the validation manager
    pub async fn stop(&self) -> Result<()> {
        // Set running flag to false
        let mut running = self.running.write().await;
        *running = false;
        
        // Abort all task handles
        let mut task_handles = self.task_handles.write().await;
        for handle in task_handles.drain(..) {
            handle.abort();
        }
        
        Ok(())
    }
    
    /// Validates a transaction
    pub async fn validate_transaction(&self, transaction: Transaction) -> Result<ValidationResult> {
        // Check if the transaction is already validated
        let tx_hash = transaction.hash();
        let results = self.transaction_results.read().await;
        if let Some(validator_results) = results.get(&tx_hash) {
            if let Some(result) = validator_results.get(&self.validator_key) {
                return Ok(result.clone());
            }
        }
        drop(results);
        
        // Start validation timer
        let start_time = std::time::Instant::now();
        
        // Perform basic validation
        transaction.validate_basic()?;
        
        // TODO: In a full implementation, perform more comprehensive validation
        // like checking account balances, transaction dependencies, etc.
        
        // Set transaction as valid
        let status = ValidationStatus::Valid;
        
        // Create validation result
        let execution_time = start_time.elapsed().as_millis() as u64;
        let mut result = ValidationResult::new(
            status,
            self.validator_key.clone(),
            &self.private_key,
        )?
        .with_execution_time(execution_time);
        
        // Set security level based on validation count
        result.security_level = self.calculate_security_level(&tx_hash).await;
        
        // Add TEE attestation if enabled
        if self.tee_enabled {
            // In a real implementation, this would be an actual TEE attestation
            let attestation = vec![42; 32]; // Dummy attestation
            result = result.with_tee_attestation(attestation);
        }
        
        // Store the result
        let mut results = self.transaction_results.write().await;
        let validator_results = results
            .entry(tx_hash.clone())
            .or_insert_with(HashMap::new);
        validator_results.insert(self.validator_key.clone(), result.clone());
        
        Ok(result)
    }
    
    /// Validates a block
    pub async fn validate_block(&self, block: Block) -> Result<ValidationResult> {
        // Check if the block is already validated
        let block_hash = block.hash();
        let results = self.block_results.read().await;
        if let Some(validator_results) = results.get(&block_hash) {
            if let Some(result) = validator_results.get(&self.validator_key) {
                return Ok(result.clone());
            }
        }
        drop(results);
        
        // Start validation timer
        let start_time = std::time::Instant::now();
        
        // Perform basic validation
        block.validate_basic()?;
        
        // Validate block references
        self.validate_block_references(&block).await?;
        
        // Validate all transactions in the block
        for tx in block.transactions() {
            self.validate_transaction(tx.clone()).await?;
        }
        
        // Set block as valid
        let status = ValidationStatus::Valid;
        
        // Create validation result
        let execution_time = start_time.elapsed().as_millis() as u64;
        let mut result = ValidationResult::new(
            status,
            self.validator_key.clone(),
            &self.private_key,
        )?
        .with_execution_time(execution_time);
        
        // Set security level based on validation count
        result.security_level = self.calculate_block_security_level(&block_hash).await;
        
        // Add TEE attestation if enabled
        if self.tee_enabled {
            // In a real implementation, this would be an actual TEE attestation
            let attestation = vec![42; 32]; // Dummy attestation
            result = result.with_tee_attestation(attestation);
        }
        
        // Store the result
        let mut results = self.block_results.write().await;
        let validator_results = results
            .entry(block_hash.clone())
            .or_insert_with(HashMap::new);
        validator_results.insert(self.validator_key.clone(), result.clone());
        
        Ok(result)
    }
    
    /// Validates an object state
    pub async fn validate_object(&self, object: Object) -> Result<ValidationResult> {
        // Check if the object is already validated
        let object_id = object.id().clone();
        let results = self.object_results.read().await;
        if let Some(validator_results) = results.get(&object_id) {
            if let Some(result) = validator_results.get(&self.validator_key) {
                return Ok(result.clone());
            }
        }
        drop(results);
        
        // Start validation timer
        let start_time = std::time::Instant::now();
        
        // Perform validation (check if the object is in a valid state)
        if !object.is_valid() {
            return ValidationResult::with_error(
                ValidationStatus::Invalid,
                "Object is in an invalid state".to_string(),
                self.validator_key.clone(),
                &self.private_key,
            );
        }
        
        // Set object as valid
        let status = ValidationStatus::Valid;
        
        // Create validation result
        let execution_time = start_time.elapsed().as_millis() as u64;
        let mut result = ValidationResult::new(
            status,
            self.validator_key.clone(),
            &self.private_key,
        )?
        .with_execution_time(execution_time);
        
        // Add TEE attestation if enabled
        if self.tee_enabled {
            // In a real implementation, this would be an actual TEE attestation
            let attestation = vec![42; 32]; // Dummy attestation
            result = result.with_tee_attestation(attestation);
        }
        
        // Store the result
        let mut results = self.object_results.write().await;
        let validator_results = results
            .entry(object_id.clone())
            .or_insert_with(HashMap::new);
        validator_results.insert(self.validator_key.clone(), result.clone());
        
        Ok(result)
    }
    
    /// Submits a transaction validation request
    pub async fn submit_transaction_validation_request(&self, request: TransactionValidationRequest) -> Result<()> {
        let mut pending = self.pending_tx_validations.write().await;
        pending.push(request);
        
        // Sort by priority (higher first) and then by deadline (earlier first)
        pending.sort_by(|a, b| {
            b.priority.cmp(&a.priority).then_with(|| a.deadline.cmp(&b.deadline))
        });
        
        Ok(())
    }
    
    /// Submits a block validation request
    pub async fn submit_block_validation_request(&self, request: BlockValidationRequest) -> Result<()> {
        let mut pending = self.pending_block_validations.write().await;
        pending.push(request);
        
        // Sort by priority (higher first) and then by deadline (earlier first)
        pending.sort_by(|a, b| {
            b.priority.cmp(&a.priority).then_with(|| a.deadline.cmp(&b.deadline))
        });
        
        Ok(())
    }
    
    /// Get transaction validation results
    pub async fn get_transaction_validation_results(&self, tx_hash: &[u8]) -> Option<HashMap<Vec<u8>, ValidationResult>> {
        let results = self.transaction_results.read().await;
        results.get(tx_hash).cloned()
    }
    
    /// Get block validation results
    pub async fn get_block_validation_results(&self, block_hash: &[u8]) -> Option<HashMap<Vec<u8>, ValidationResult>> {
        let results = self.block_results.read().await;
        results.get(block_hash).cloned()
    }
    
    /// Get object validation results
    pub async fn get_object_validation_results(&self, object_id: &ObjectID) -> Option<HashMap<Vec<u8>, ValidationResult>> {
        let results = self.object_results.read().await;
        results.get(object_id).cloned()
    }
    
    /// Check if a transaction has been validated by this validator
    pub async fn is_transaction_validated_by_me(&self, tx_hash: &[u8]) -> bool {
        let results = self.transaction_results.read().await;
        if let Some(validator_results) = results.get(tx_hash) {
            validator_results.contains_key(&self.validator_key)
        } else {
            false
        }
    }
    
    /// Check if a block has been validated by this validator
    pub async fn is_block_validated_by_me(&self, block_hash: &[u8]) -> bool {
        let results = self.block_results.read().await;
        if let Some(validator_results) = results.get(block_hash) {
            validator_results.contains_key(&self.validator_key)
        } else {
            false
        }
    }
    
    /// Check if an object has been validated by this validator
    pub async fn is_object_validated_by_me(&self, object_id: &ObjectID) -> bool {
        let results = self.object_results.read().await;
        if let Some(validator_results) = results.get(object_id) {
            validator_results.contains_key(&self.validator_key)
        } else {
            false
        }
    }
    
    /// Check if a transaction has reached validation threshold
    pub async fn is_transaction_validated(&self, tx_hash: &[u8]) -> bool {
        let validation_count = self.get_transaction_validation_count(tx_hash).await;
        let threshold = self.calculate_validation_threshold().await;
        
        validation_count >= threshold
    }
    
    /// Check if a block has reached validation threshold
    pub async fn is_block_validated(&self, block_hash: &[u8]) -> bool {
        let validation_count = self.get_block_validation_count(block_hash).await;
        let threshold = self.calculate_validation_threshold().await;
        
        validation_count >= threshold
    }
    
    /// Check if an object has reached validation threshold
    pub async fn is_object_validated(&self, object_id: &ObjectID) -> bool {
        let validation_count = self.get_object_validation_count(object_id).await;
        let threshold = self.calculate_validation_threshold().await;
        
        validation_count >= threshold
    }
    
    /// Get the number of validators that have validated a transaction
    pub async fn get_transaction_validation_count(&self, tx_hash: &[u8]) -> usize {
        let results = self.transaction_results.read().await;
        if let Some(validator_results) = results.get(tx_hash) {
            validator_results.len()
        } else {
            0
        }
    }
    
    /// Get the number of validators that have validated a block
    pub async fn get_block_validation_count(&self, block_hash: &[u8]) -> usize {
        let results = self.block_results.read().await;
        if let Some(validator_results) = results.get(block_hash) {
            validator_results.len()
        } else {
            0
        }
    }
    
    /// Get the number of validators that have validated an object
    pub async fn get_object_validation_count(&self, object_id: &ObjectID) -> usize {
        let results = self.object_results.read().await;
        if let Some(validator_results) = results.get(object_id) {
            validator_results.len()
        } else {
            0
        }
    }
    
    /// Calculate the validation threshold (number of validators needed)
    async fn calculate_validation_threshold(&self) -> usize {
        // TODO: In a real implementation, this would be based on the total number of active validators
        let total_validators = 4; // Placeholder
        let threshold_percentage = self.validation_threshold as usize;
        
        let threshold = (total_validators * threshold_percentage) / 100;
        std::cmp::max(threshold, self.min_validators)
    }
    
    /// Calculate the security level for a transaction based on validation count
    async fn calculate_security_level(&self, tx_hash: &[u8]) -> u8 {
        let validation_count = self.get_transaction_validation_count(tx_hash).await;
        
        // These thresholds should correspond to the Security Level Accelerator's levels
        // In a real implementation, these would be based on the total validator count
        if validation_count >= 3 { // Full security (>2/3 validators)
            3
        } else if validation_count >= 2 { // Strong security (>1/3 validators)
            2
        } else if validation_count >= 1 { // Basic security (10-20% validators)
            1
        } else { // Minimal security (single validator)
            0
        }
    }
    
    /// Calculate the security level for a block based on validation count
    async fn calculate_block_security_level(&self, block_hash: &[u8]) -> u8 {
        let validation_count = self.get_block_validation_count(block_hash).await;
        
        // These thresholds should correspond to the Security Level Accelerator's levels
        // In a real implementation, these would be based on the total validator count
        if validation_count >= 3 { // Full security (>2/3 validators)
            3
        } else if validation_count >= 2 { // Strong security (>1/3 validators)
            2
        } else if validation_count >= 1 { // Basic security (10-20% validators)
            1
        } else { // Minimal security (single validator)
            0
        }
    }
    
    /// Validate block references
    async fn validate_block_references(&self, block: &Block) -> Result<()> {
        // Skip genesis block (height 0)
        if block.height() == 0 {
            return Ok(());
        }
        
        // Validate that all parent blocks exist
        for parent_hash in block.previous_hashes() {
            // Check if the parent block exists
            if !self.blockchain.has_block(parent_hash).await? {
                return Err(AevorError::validation(format!("Parent block {} not found", hex::encode(parent_hash))));
            }
            
            // Check that parent blocks are at a lower height
            let parent_block = self.blockchain.get_block(parent_hash).await?;
            if parent_block.height() >= block.height() {
                return Err(AevorError::validation(format!("Parent block height ({}) not less than current block height ({})", parent_block.height(), block.height())));
            }
        }
        
        // Validate reference height
        let max_parent_height = self.get_max_parent_height(block).await?;
        if block.reference_height() <= max_parent_height {
            return Err(AevorError::validation(format!("Block reference height ({}) must be greater than max parent height ({})", block.reference_height(), max_parent_height)));
        }
        
        Ok(())
    }
    
    /// Get the maximum height of parent blocks
    async fn get_max_parent_height(&self, block: &Block) -> Result<u64> {
        let mut max_height = 0;
        
        for parent_hash in block.previous_hashes() {
            let parent_block = self.blockchain.get_block(parent_hash).await?;
            max_height = std::cmp::max(max_height, parent_block.height());
        }
        
        Ok(max_height)
    }
    
    /// Transaction validation worker task
    async fn transaction_validation_worker(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        
        while *self.running.read().await {
            interval.tick().await;
            
            // Check if we can process more validations
            let active_validations = *self.active_validations.read().await;
            if active_validations >= self.max_concurrent_validations {
                continue;
            }
            
            // Get the next transaction validation request
            let request = {
                let mut pending = self.pending_tx_validations.write().await;
                if pending.is_empty() {
                    continue;
                }
                pending.remove(0)
            };
            
            // Increment active validations
            *self.active_validations.write().await += 1;
            
            // Process the validation request
            let self_clone = self.clone();
            tokio::spawn(async move {
                let tx_hash = request.transaction.hash();
                
                // Check if this transaction is already validated by us
                if self_clone.is_transaction_validated_by_me(&tx_hash).await {
                    // Decrement active validations
                    *self_clone.active_validations.write().await -= 1;
                    return;
                }
                
                // Perform validation with timeout
                let validation_result = match timeout(
                    Duration::from_millis(1000),
                    self_clone.validate_transaction(request.transaction),
                ).await {
                    Ok(result) => result,
                    Err(_) => {
                        // Timeout occurred
                        let result = ValidationResult::with_error(
                            ValidationStatus::Timeout,
                            "Validation timed out".to_string(),
                            self_clone.validator_key.clone(),
                            &self_clone.private_key,
                        );
                        
                        match result {
                            Ok(r) => Ok(r),
                            Err(e) => Err(e),
                        }
                    }
                };
                
                // Log the validation result
                match &validation_result {
                    Ok(result) => {
                        if result.status == ValidationStatus::Valid {
                            println!("Transaction {} validated successfully", hex::encode(&tx_hash));
                        } else {
                            println!("Transaction {} validation failed: {:?}", hex::encode(&tx_hash), result.status);
                        }
                    }
                    Err(e) => {
                        println!("Transaction {} validation error: {}", hex::encode(&tx_hash), e);
                    }
                }
                
                // Decrement active validations
                *self_clone.active_validations.write().await -= 1;
            });
        }
    }
    
    /// Block validation worker task
    async fn block_validation_worker(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        
        while *self.running.read().await {
            interval.tick().await;
            
            // Check if we can process more validations
            let active_validations = *self.active_validations.read().await;
            if active_validations >= self.max_concurrent_validations {
                continue;
            }
            
            // Get the next block validation request
            let request = {
                let mut pending = self.pending_block_validations.write().await;
                if pending.is_empty() {
                    continue;
                }
                pending.remove(0)
            };
            
            // Increment active validations
            *self.active_validations.write().await += 1;
            
            // Process the validation request
            let self_clone = self.clone();
            tokio::spawn(async move {
                let block_hash = request.block.hash();
                
                // Check if this block is already validated by us
                if self_clone.is_block_validated_by_me(&block_hash).await {
                    // Decrement active validations
                    *self_clone.active_validations.write().await -= 1;
                    return;
                }
                
                // Perform validation with timeout
                let validation_result = match timeout(
                    Duration::from_millis(5000), // Blocks take longer to validate
                    self_clone.validate_block(request.block),
                ).await {
                    Ok(result) => result,
                    Err(_) => {
                        // Timeout occurred
                        let result = ValidationResult::with_error(
                            ValidationStatus::Timeout,
                            "Validation timed out".to_string(),
                            self_clone.validator_key.clone(),
                            &self_clone.private_key,
                        );
                        
                        match result {
                            Ok(r) => Ok(r),
                            Err(e) => Err(e),
                        }
                    }
                };
                
                // Log the validation result
                match &validation_result {
                    Ok(result) => {
                        if result.status == ValidationStatus::Valid {
                            println!("Block {} validated successfully", hex::encode(&block_hash));
                        } else {
                            println!("Block {} validation failed: {:?}", hex::encode(&block_hash), result.status);
                        }
                    }
                    Err(e) => {
                        println!("Block {} validation error: {}", hex::encode(&block_hash), e);
                    }
                }
                
                // Decrement active validations
                *self_clone.active_validations.write().await -= 1;
            });
        }
    }
    
    /// Cleanup worker task
    async fn cleanup_worker(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Run every 5 minutes
        
        while *self.running.read().await {
            interval.tick().await;
            
            // Get current timestamp
            let now = chrono::Utc::now().timestamp_millis() as u64;
            
            // Cleanup transaction results older than 24 hours
            {
                let mut results = self.transaction_results.write().await;
                results.retain(|_, validator_results| {
                    validator_results.values().any(|result| now - result.timestamp < 24 * 60 * 60 * 1000)
                });
            }
            
            // Cleanup block results older than 1 week
            {
                let mut results = self.block_results.write().await;
                results.retain(|_, validator_results| {
                    validator_results.values().any(|result| now - result.timestamp < 7 * 24 * 60 * 60 * 1000)
                });
            }
            
            // Cleanup object results older than 24 hours
            {
                let mut results = self.object_results.write().await;
                results.retain(|_, validator_results| {
                    validator_results.values().any(|result| now - result.timestamp < 24 * 60 * 60 * 1000)
                });
            }
        }
    }
    
    /// Get all validation results for a transaction
    pub async fn get_all_transaction_validation_results(&self) -> HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>> {
        self.transaction_results.read().await.clone()
    }
    
    /// Get all validation results for blocks
    pub async fn get_all_block_validation_results(&self) -> HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>> {
        self.block_results.read().await.clone()
    }
    
    /// Get all validation results for objects
    pub async fn get_all_object_validation_results(&self) -> HashMap<ObjectID, HashMap<Vec<u8>, ValidationResult>> {
        self.object_results.read().await.clone()
    }
    
    /// Get validator ID
    pub fn get_validator_id(&self) -> &[u8] {
        &self.validator_key
    }
    
    /// Check if TEE is enabled
    pub fn is_tee_enabled(&self) -> bool {
        self.tee_enabled
    }
    
    /// Get pending transaction validation count
    pub async fn get_pending_tx_validation_count(&self) -> usize {
        self.pending_tx_validations.read().await.len()
    }
    
    /// Get pending block validation count
    pub async fn get_pending_block_validation_count(&self) -> usize {
        self.pending_block_validations.read().await.len()
    }
    
    /// Get active validation count
    pub async fn get_active_validation_count(&self) -> usize {
        *self.active_validations.read().await
    }
}

impl Clone for ValidationManager {
    fn clone(&self) -> Self {
        Self {
            blockchain: self.blockchain.clone(),
            config: self.config.clone(),
            validator_key: self.validator_key.clone(),
            private_key: self.private_key.clone(),
            transaction_results: self.transaction_results.clone(),
            block_results: self.block_results.clone(),
            object_results: self.object_results.clone(),
            min_validators: self.min_validators,
            validation_threshold: self.validation_threshold,
            pending_tx_validations: self.pending_tx_validations.clone(),
            pending_block_validations: self.pending_block_validations.clone(),
            max_concurrent_validations: self.max_concurrent_validations,
            active_validations: self.active_validations.clone(),
            tee_enabled: self.tee_enabled,
            running: self.running.clone(),
            task_handles: self.task_handles.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{Transaction, TransactionType, TransactionData, data::TransferData};
    use crate::core::block::BlockBuilder;
    
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
    async fn test_validation_result_creation() {
        let validator_id = vec![1, 2, 3, 4];
        let private_key = vec![5, 6, 7, 8]; // Not a real private key
        
        let result = ValidationResult::new(ValidationStatus::Valid, validator_id.clone(), &private_key);
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.status, ValidationStatus::Valid);
        assert_eq!(result.validator_id, validator_id);
        assert!(result.error.is_none());
    }
    
    #[tokio::test]
    async fn test_validation_manager_creation() {
        let config = Arc::new(AevorConfig::default());
        let blockchain = Arc::new(Blockchain::new(config.clone(), Arc::new(crate::storage::Storage::new(&config.storage).unwrap())).unwrap());
        
        let manager = ValidationManager::new(config, blockchain);
        assert!(manager.is_ok());
    }
    
    #[tokio::test]
    async fn test_transaction_validation() {
        let config = Arc::new(AevorConfig::default());
        let blockchain = Arc::new(Blockchain::new(config.clone(), Arc::new(crate::storage::Storage::new(&config.storage).unwrap())).unwrap());
        
        let manager = ValidationManager::new(config, blockchain).unwrap();
        let tx = create_test_transaction();
        
        let result = manager.validate_transaction(tx.clone()).await;
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.status, ValidationStatus::Valid);
        
        // Verify that the transaction is now validated
        assert!(manager.is_transaction_validated_by_me(&tx.hash()).await);
    }
    
    #[tokio::test]
    async fn test_block_validation() {
        let config = Arc::new(AevorConfig::default());
        let storage = Arc::new(crate::storage::Storage::new(&config.storage).unwrap());
        let blockchain = Arc::new(Blockchain::new(config.clone(), storage).unwrap());
        
        // Create and store a genesis block
        let genesis = create_test_block(0, vec![0; 32]);
        blockchain.add_block(genesis.clone()).await.unwrap();
        
        // Create a block that references the genesis block
        let block = create_test_block(1, genesis.hash());
        
        let manager = ValidationManager::new(config, blockchain).unwrap();
        let result = manager.validate_block(block.clone()).await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status, ValidationStatus::Valid);
        
        // Verify that the block is now validated
        assert!(manager.is_block_validated_by_me(&block.hash()).await);
    }
    
    #[tokio::test]
    async fn test_validation_count() {
        let config = Arc::new(AevorConfig::default());
        let blockchain = Arc::new(Blockchain::new(config.clone(), Arc::new(crate::storage::Storage::new(&config.storage).unwrap())).unwrap());
        
        let manager = ValidationManager::new(config, blockchain).unwrap();
        let tx = create_test_transaction();
        
        // Initially, validation count should be 0
        assert_eq!(manager.get_transaction_validation_count(&tx.hash()).await, 0);
        
        // After validation, count should be 1
        manager.validate_transaction(tx.clone()).await.unwrap();
        assert_eq!(manager.get_transaction_validation_count(&tx.hash()).await, 1);
    }
}
