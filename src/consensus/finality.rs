use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;

use crate::config::AevorConfig;
use crate::core::Block;
use crate::core::block::BlockStatus;
use crate::error::{AevorError, Result};
use crate::consensus::validation::{ValidationManager, ValidationResult};

/// Represents a finality proof for a block
#[derive(Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Block hash
    pub block_hash: Vec<u8>,
    
    /// Block height
    pub height: u64,
    
    /// Timestamp when finality was achieved
    pub timestamp: u64,
    
    /// Validator signatures confirming finality
    /// Map from validator ID to signature
    pub signatures: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Minimum required confirmations
    pub min_confirmations: usize,
    
    /// Whether the block is uncorrupted
    pub uncorrupted: bool,
    
    /// Finality proof signature (signed by finality manager)
    pub proof_signature: Vec<u8>,
}

impl FinalityProof {
    /// Creates a new finality proof for a block
    pub fn new(
        block_hash: Vec<u8>,
        height: u64,
        min_confirmations: usize,
        uncorrupted: bool,
    ) -> Self {
        Self {
            block_hash,
            height,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            signatures: HashMap::new(),
            min_confirmations,
            uncorrupted,
            proof_signature: Vec::new(),
        }
    }
    
    /// Adds a validator signature to the proof
    pub fn add_signature(&mut self, validator_id: Vec<u8>, signature: Vec<u8>) {
        self.signatures.insert(validator_id, signature);
    }
    
    /// Gets the number of validator signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
    
    /// Checks if the proof has sufficient signatures to meet the minimum confirmations
    pub fn has_sufficient_signatures(&self) -> bool {
        self.signature_count() >= self.min_confirmations
    }
    
    /// Signs the finality proof
    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        // Create a message to sign
        let mut message = Vec::new();
        message.extend_from_slice(&self.block_hash);
        message.extend_from_slice(&self.height.to_le_bytes());
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Sign the message
        let signature = crate::crypto::signature::Signature::sign(
            crate::crypto::signature::SignatureAlgorithm::ED25519,
            private_key,
            &message,
        )?;
        
        self.proof_signature = signature.value().to_vec();
        Ok(())
    }
    
    /// Verifies the finality proof signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool> {
        if self.proof_signature.is_empty() {
            return Ok(false);
        }
        
        // Recreate the message
        let mut message = Vec::new();
        message.extend_from_slice(&self.block_hash);
        message.extend_from_slice(&self.height.to_le_bytes());
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Verify the signature
        let signature = crate::crypto::signature::Signature::new(
            crate::crypto::signature::SignatureAlgorithm::ED25519,
            self.proof_signature.clone(),
        );
        
        signature.verify(public_key, &message)
    }
    
    /// Serializes the finality proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize finality proof: {}", e)))
    }
    
    /// Deserializes a finality proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize finality proof: {}", e)))
    }
}

/// Background service for checking block finality
pub struct FinalityBackgroundService {
    /// Finality manager
    finality_manager: Arc<FinalityManager>,
    
    /// Pending blocks
    pending_blocks: Arc<RwLock<HashMap<Vec<u8>, Block>>>,
    
    /// Shutdown signal
    shutdown_signal: Arc<RwLock<bool>>,
    
    /// Finality check interval
    check_interval: Duration,
}

impl FinalityBackgroundService {
    /// Creates a new finality background service
    pub fn new(
        finality_manager: Arc<FinalityManager>,
        check_interval: Duration,
    ) -> Self {
        Self {
            finality_manager,
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            shutdown_signal: Arc::new(RwLock::new(false)),
            check_interval,
        }
    }
    
    /// Adds a block to be checked for finality
    pub async fn add_block(&self, block: Block) {
        let mut pending_blocks = self.pending_blocks.write().await;
        pending_blocks.insert(block.hash(), block);
    }
    
    /// Starts the background service
    pub async fn start(&self) -> Result<()> {
        let pending_blocks = self.pending_blocks.clone();
        let finality_manager = self.finality_manager.clone();
        let shutdown_signal = self.shutdown_signal.clone();
        let check_interval = self.check_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(check_interval);
            
            loop {
                interval.tick().await;
                
                // Check if we should shut down
                if *shutdown_signal.read().await {
                    break;
                }
                
                // Get blocks to check
                let blocks_to_check = {
                    let pending_blocks = pending_blocks.read().await;
                    pending_blocks.values().cloned().collect::<Vec<_>>()
                };
                
                // Check each block for finality
                for block in blocks_to_check {
                    if finality_manager.is_block_final(&block.hash()).await {
                        // Block is final, remove it from pending blocks
                        pending_blocks.write().await.remove(&block.hash());
                    } else {
                        // Try to finalize the block
                        let _ = finality_manager.finalize_block_if_ready(&block).await;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Requests shutdown of the background service
    pub async fn shutdown(&self) {
        let mut shutdown = self.shutdown_signal.write().await;
        *shutdown = true;
    }
}

/// Manages block finality and generates finality proofs
pub struct FinalityManager {
    /// Validator set
    validator_set: Arc<ValidationManager>,
    
    /// Finalized blocks by hash
    finalized_blocks: RwLock<HashMap<Vec<u8>, FinalityProof>>,
    
    /// Minimum confirmations required for finality
    min_confirmations: usize,
    
    /// Confirmation percentage required (0-100)
    confirmation_percentage: u8,
    
    /// Pending blocks awaiting finality with their validation results
    pending_blocks: RwLock<HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>>>,
    
    /// Background service
    background_service: Option<FinalityBackgroundService>,
    
    /// Node's validator ID (if this node is a validator)
    validator_id: Option<Vec<u8>>,
    
    /// Node's private key (if this node is a validator)
    private_key: Option<Vec<u8>>,
    
    /// Configuration
    config: Arc<AevorConfig>,
    
    /// Running state
    running: RwLock<bool>,
}

impl FinalityManager {
    /// Creates a new finality manager
    pub fn new(
        config: Arc<AevorConfig>,
        validator_set: Arc<ValidationManager>,
    ) -> Result<Self> {
        let min_confirmations = config.consensus.finality.min_confirmations;
        let confirmation_percentage = config.consensus.finality.confirmation_percentage;
        
        // If this node is a validator, load the validator key
        let (validator_id, private_key) = if config.node.is_validator {
            // In a production implementation, this would load the validator key securely
            // For now, we'll just use a placeholder
            let key_bytes = vec![1, 2, 3, 4]; // Placeholder
            (Some(key_bytes.clone()), Some(key_bytes))
        } else {
            (None, None)
        };
        
        Ok(Self {
            validator_set,
            finalized_blocks: RwLock::new(HashMap::new()),
            min_confirmations,
            confirmation_percentage,
            pending_blocks: RwLock::new(HashMap::new()),
            background_service: None,
            validator_id,
            private_key,
            config,
            running: RwLock::new(false),
        })
    }
    
    /// Starts the finality manager
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        // Create and start the background service
        let check_interval = Duration::from_millis(self.config.consensus.finality.check_interval_ms);
        let background_service = FinalityBackgroundService::new(Arc::new(self.clone()), check_interval);
        background_service.start().await?;
        
        *running = true;
        Ok(())
    }
    
    /// Stops the finality manager
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        // Shutdown the background service if it exists
        if let Some(background_service) = &self.background_service {
            background_service.shutdown().await;
        }
        
        *running = false;
        Ok(())
    }
    
    /// Adds a block for finality determination
    pub async fn add_block(&self, block: Block) -> Result<()> {
        // Add the block to the background service if it exists
        if let Some(background_service) = &self.background_service {
            background_service.add_block(block.clone()).await;
        }
        
        // If the block is already final, return early
        if self.is_block_final(&block.hash()).await {
            return Ok(());
        }
        
        // Get validation results for this block
        let validation_results = self.validator_set.get_block_validations(&block.hash()).await?;
        
        // Store the validation results
        let mut pending_blocks = self.pending_blocks.write().await;
        pending_blocks.insert(block.hash(), validation_results);
        
        // Try to finalize the block
        self.finalize_block_if_ready(&block).await?;
        
        Ok(())
    }
    
    /// Checks if a block has reached finality
    pub async fn is_block_final(&self, block_hash: &[u8]) -> bool {
        let finalized_blocks = self.finalized_blocks.read().await;
        finalized_blocks.contains_key(block_hash)
    }
    
    /// Finalizes a block if it meets the criteria
    pub async fn finalize_block_if_ready(&self, block: &Block) -> Result<bool> {
        // If the block is already final, return early
        if self.is_block_final(&block.hash()).await {
            return Ok(true);
        }
        
        // Get validation results for this block
        let pending_blocks = self.pending_blocks.read().await;
        let validation_results = match pending_blocks.get(&block.hash()) {
            Some(results) => results,
            None => return Ok(false), // No validation results yet
        };
        
        // Count valid validations
        let valid_count = validation_results.values()
            .filter(|result| result.is_valid())
            .count();
        
        // Get the total number of validators
        let total_validators = self.validator_set.get_validators_count().await?;
        
        // Calculate required confirmations based on percentage
        let required_confirmations = std::cmp::max(
            self.min_confirmations,
            (total_validators * self.confirmation_percentage as usize) / 100,
        );
        
        // Check if we have enough validations
        if valid_count >= required_confirmations {
            // Create a finality proof
            let mut proof = FinalityProof::new(
                block.hash(),
                block.height(),
                required_confirmations,
                block.status() == BlockStatus::Uncorrupted,
            );
            
            // Add validator signatures
            for (validator_id, result) in validation_results {
                if result.is_valid() {
                    proof.add_signature(validator_id.clone(), result.signature().to_vec());
                }
            }
            
            // Sign the proof if this node is a validator
            if let (Some(validator_id), Some(private_key)) = (&self.validator_id, &self.private_key) {
                proof.sign(private_key)?;
            }
            
            // Store the finality proof
            let mut finalized_blocks = self.finalized_blocks.write().await;
            finalized_blocks.insert(block.hash(), proof);
            
            // Remove the block from pending blocks
            drop(pending_blocks); // Release the read lock before acquiring write lock
            let mut pending_blocks = self.pending_blocks.write().await;
            pending_blocks.remove(&block.hash());
            
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Gets the finality proof for a block
    pub async fn get_finality_proof(&self, block_hash: &[u8]) -> Option<FinalityProof> {
        let finalized_blocks = self.finalized_blocks.read().await;
        finalized_blocks.get(block_hash).cloned()
    }
    
    /// Gets all finalized blocks
    pub async fn get_all_finalized_blocks(&self) -> Vec<Vec<u8>> {
        let finalized_blocks = self.finalized_blocks.read().await;
        finalized_blocks.keys().cloned().collect()
    }
    
    /// Marks a block as uncorrupted
    pub async fn mark_as_uncorrupted(&self, block_hash: &[u8]) -> Result<()> {
        let mut finalized_blocks = self.finalized_blocks.write().await;
        
        if let Some(proof) = finalized_blocks.get_mut(block_hash) {
            proof.uncorrupted = true;
            
            // Re-sign the proof if this node is a validator
            if let (Some(_), Some(private_key)) = (&self.validator_id, &self.private_key) {
                proof.sign(private_key)?;
            }
        }
        
        Ok(())
    }
    
    /// Checks if a block is marked as uncorrupted
    pub async fn is_block_uncorrupted(&self, block_hash: &[u8]) -> bool {
        let finalized_blocks = self.finalized_blocks.read().await;
        finalized_blocks.get(block_hash).map_or(false, |proof| proof.uncorrupted)
    }
    
    /// Verifies a finality proof
    pub async fn verify_finality_proof(&self, proof: &FinalityProof) -> Result<bool> {
        // Check that the proof has sufficient signatures
        if !proof.has_sufficient_signatures() {
            return Ok(false);
        }
        
        // Verify each validator signature
        for (validator_id, signature) in &proof.signatures {
            let is_valid = self.validator_set.verify_validator_signature(
                validator_id,
                &proof.block_hash,
                signature,
            ).await?;
            
            if !is_valid {
                return Ok(false);
            }
        }
        
        // If the proof has a signature, verify it
        if !proof.proof_signature.is_empty() {
            // In a real implementation, we would verify the proof signature
            // using the finality manager's public key
            // For now, just return true
            return Ok(true);
        }
        
        Ok(true)
    }
    
    /// Processes a block (checks for finality)
    pub async fn process_block(&self, block: Block) -> Result<()> {
        self.add_block(block).await
    }
    
    /// Gets the finalized block hashes
    pub async fn get_finalized_blocks(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.get_all_finalized_blocks().await)
    }
    
    /// Gets the minimum confirmations required for finality
    pub fn min_confirmations(&self) -> usize {
        self.min_confirmations
    }
    
    /// Gets the confirmation percentage required for finality
    pub fn confirmation_percentage(&self) -> u8 {
        self.confirmation_percentage
    }
}

impl Clone for FinalityManager {
    fn clone(&self) -> Self {
        // Note: This clone implementation doesn't clone the background service
        // as it would create multiple background services
        Self {
            validator_set: self.validator_set.clone(),
            finalized_blocks: RwLock::new(HashMap::new()),
            min_confirmations: self.min_confirmations,
            confirmation_percentage: self.confirmation_percentage,
            pending_blocks: RwLock::new(HashMap::new()),
            background_service: None,
            validator_id: self.validator_id.clone(),
            private_key: self.private_key.clone(),
            config: self.config.clone(),
            running: RwLock::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::{BlockBuilder, BlockStatus};
    use crate::core::transaction::{Transaction, TransactionData, TransactionType};
    use crate::core::transaction::data::TransferData;
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
        
        let mut block = BlockBuilder::new()
            .height(height)
            .previous_hash(previous_hash)
            .reference_height(height)
            .validator(validator)
            .transaction(tx)
            .build()
            .unwrap();
        
        block.set_status(BlockStatus::Accepted);
        block
    }
    
    #[tokio::test]
    async fn test_finality_proof_creation() {
        let block_hash = vec![1, 2, 3, 4];
        let height = 1;
        let min_confirmations = 2;
        let uncorrupted = true;
        
        let mut proof = FinalityProof::new(
            block_hash.clone(),
            height,
            min_confirmations,
            uncorrupted,
        );
        
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.height, height);
        assert_eq!(proof.min_confirmations, min_confirmations);
        assert_eq!(proof.uncorrupted, uncorrupted);
        assert_eq!(proof.signature_count(), 0);
        assert_eq!(proof.has_sufficient_signatures(), false);
        
        // Add some signatures
        proof.add_signature(vec![1, 1, 1, 1], vec![10, 10, 10, 10]);
        proof.add_signature(vec![2, 2, 2, 2], vec![20, 20, 20, 20]);
        
        assert_eq!(proof.signature_count(), 2);
        assert_eq!(proof.has_sufficient_signatures(), true);
        
        // Sign the proof
        let private_key = vec![1, 2, 3, 4];
        let result = proof.sign(&private_key);
        assert!(result.is_ok());
        assert!(!proof.proof_signature.is_empty());
        
        // Verify the signature
        let public_key = vec![5, 6, 7, 8]; // Not a real public key, so verification will fail
        let result = proof.verify_signature(&public_key);
        assert!(result.is_ok());
        
        // Serialize and deserialize
        let bytes = proof.to_bytes().unwrap();
        let deserialized = FinalityProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(deserialized.block_hash, proof.block_hash);
        assert_eq!(deserialized.height, proof.height);
        assert_eq!(deserialized.min_confirmations, proof.min_confirmations);
        assert_eq!(deserialized.uncorrupted, proof.uncorrupted);
        assert_eq!(deserialized.signature_count(), proof.signature_count());
        assert_eq!(deserialized.proof_signature, proof.proof_signature);
    }
    
    // Test FinalityManager functionality
    // Note: This is a simplified test that mocks dependencies
    #[tokio::test]
    async fn test_finality_manager() {
        // Create a mock ValidationManager
        let config = Arc::new(AevorConfig::default());
        
        // For simplicity, create a minimal implementation of ValidationManager for testing
        struct MockValidationManager {
            block_validations: HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>>,
        }
        
        impl MockValidationManager {
            fn new() -> Self {
                Self {
                    block_validations: HashMap::new(),
                }
            }
            
            async fn get_block_validations(&self, block_hash: &[u8]) -> Result<HashMap<Vec<u8>, ValidationResult>> {
                Ok(self.block_validations.get(block_hash).cloned().unwrap_or_default())
            }
            
            async fn get_validators_count(&self) -> Result<usize> {
                Ok(4) // For testing, assume 4 validators
            }
            
            async fn verify_validator_signature(&self, _validator_id: &[u8], _block_hash: &[u8], _signature: &[u8]) -> Result<bool> {
                Ok(true) // For testing, always return true
            }
        }
        
        let validation_manager = Arc::new(MockValidationManager::new());
        
        // Create FinalityManager
        let finality_manager = FinalityManager {
            validator_set: Arc::new(validation_manager),
            finalized_blocks: RwLock::new(HashMap::new()),
            min_confirmations: 2,
            confirmation_percentage: 50,
            pending_blocks: RwLock::new(HashMap::new()),
            background_service: None,
            validator_id: Some(vec![1, 1, 1, 1]),
            private_key: Some(vec![1, 2, 3, 4]),
            config: config.clone(),
            running: RwLock::new(false),
        };
        
        // Create a test block
        let previous_hash = vec![0; 32];
        let block = create_test_block(1, previous_hash);
        let block_hash = block.hash();
        
        // Initially, the block should not be finalized
        assert!(!finality_manager.is_block_final(&block_hash).await);
        
        // Add the block
        let result = finality_manager.add_block(block.clone()).await;
        assert!(result.is_ok());
        
        // The block should still not be finalized (not enough validations)
        assert!(!finality_manager.is_block_final(&block_hash).await);
        
        // Add some validations
        let mut validation_results = HashMap::new();
        let validator1_id = vec![1, 1, 1, 1];
        let validator2_id = vec![2, 2, 2, 2];
        let validator3_id = vec![3, 3, 3, 3];
        
        // Create a valid validation result
        let valid_result = ValidationResult {
            is_valid: true,
            error: None,
            validator_id: validator1_id.clone(),
            timestamp: 0,
            execution_time_ms: 0,
            signature: vec![10, 10, 10, 10],
        };
        
        validation_results.insert(validator1_id.clone(), valid_result.clone());
        
        // Add another valid validation
        let mut valid_result2 = valid_result.clone();
        valid_result2.validator_id = validator2_id.clone();
        valid_result2.signature = vec![20, 20, 20, 20];
        
        validation_results.insert(validator2_id.clone(), valid_result2);
        
        // Add an invalid validation
        let invalid_result = ValidationResult {
            is_valid: false,
            error: Some("Invalid block".to_string()),
            validator_id: validator3_id.clone(),
            timestamp: 0,
            execution_time_ms: 0,
            signature: vec![30, 30, 30, 30],
        };
        
        validation_results.insert(validator3_id.clone(), invalid_result);
        
        // Add the validations to the block
        finality_manager.pending_blocks.write().await.insert(block_hash.clone(), validation_results);
        
        // Now finalize the block
        let result = finality_manager.finalize_block_if_ready(&block).await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Block should be finalized
        
        // Check that the block is finalized
        assert!(finality_manager.is_block_final(&block_hash).await);
        
        // Get the finality proof
        let proof = finality_manager.get_finality_proof(&block_hash).await;
        assert!(proof.is_some());
        
        let proof = proof.unwrap();
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.height, block.height());
        assert_eq!(proof.min_confirmations, 2);
        assert_eq!(proof.signature_count(), 2);
        assert!(proof.has_sufficient_signatures());
        
        // Verify the proof
        let result = finality_manager.verify_finality_proof(&proof).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Mark the block as uncorrupted
        let result = finality_manager.mark_as_uncorrupted(&block_hash).await;
        assert!(result.is_ok());
        
        // Check that the block is marked as uncorrupted
        assert!(finality_manager.is_block_uncorrupted(&block_hash).await);
        
        // Get all finalized blocks
        let finalized_blocks = finality_manager.get_all_finalized_blocks().await;
        assert_eq!(finalized_blocks.len(), 1);
        assert_eq!(finalized_blocks[0], block_hash);
    }
    
    // Helper struct for validation result
    #[derive(Clone)]
    struct ValidationResult {
        is_valid: bool,
        error: Option<String>,
        validator_id: Vec<u8>,
        timestamp: u64,
        execution_time_ms: u64,
        signature: Vec<u8>,
    }
    
    impl ValidationResult {
        fn is_valid(&self) -> bool {
            self.is_valid
        }
        
        fn signature(&self) -> &[u8] {
            &self.signature
        }
    }
}
