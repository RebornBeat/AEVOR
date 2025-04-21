use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, info, trace, warn};

use crate::config::AevorConfig;
use crate::core::transaction::{SecurityLevel, Transaction};
use crate::core::block::Block;
use crate::consensus::validation::{ValidationManager, ValidationResult, ValidationStatus};
use crate::crypto::bls::BLSSignatureAggregator;
use crate::error::{AevorError, Result};
use crate::networking::topology::NetworkTopology;

/// Security accelerator for progressive transaction finality
///
/// The Security Level Accelerator provides tiered validation with
/// progressive security guarantees from milliseconds to sub-second timeframes.
#[derive(Debug)]
pub struct SecurityAccelerator {
    /// Configuration
    config: Arc<AevorConfig>,
    
    /// Validation manager reference
    validation_manager: Arc<ValidationManager>,
    
    /// BLS signature aggregator for efficient signature aggregation
    bls_aggregator: BLSSignatureAggregator,
    
    /// Network topology for validator selection
    network_topology: NetworkTopology,
    
    /// Transaction security levels
    /// Maps transaction hash -> security level
    transaction_security_levels: RwLock<HashMap<Vec<u8>, SecurityLevel>>,
    
    /// Block security levels
    /// Maps block hash -> security level
    block_security_levels: RwLock<HashMap<Vec<u8>, SecurityLevel>>,
    
    /// Transactions being processed for security level acceleration
    /// Maps transaction hash -> transaction
    active_transactions: RwLock<HashMap<Vec<u8>, Transaction>>,
    
    /// Blocks being processed for security level acceleration
    /// Maps block hash -> block
    active_blocks: RwLock<HashMap<Vec<u8>, Block>>,
    
    /// Validator selection cache
    /// Maps (security level, transaction hash) -> selected validator IDs
    validator_selection_cache: RwLock<HashMap<(SecurityLevel, Vec<u8>), HashSet<Vec<u8>>>>,
    
    /// Tracks when to refresh validator selections
    validator_selection_refresh: Mutex<HashMap<Vec<u8>, u64>>,
    
    /// Security level thresholds (percentage of validators required for each level)
    security_level_thresholds: [u8; 4],
    
    /// Signature bundle cache (aggregated signatures for each security level)
    /// Maps (transaction hash, security_level) -> aggregated signature
    signature_bundles: RwLock<HashMap<(Vec<u8>, SecurityLevel), Vec<u8>>>,
    
    /// Running state
    running: Mutex<bool>,
    
    /// Shutdown channel
    shutdown: tokio::sync::watch::Receiver<bool>,
    
    /// Background task handles
    task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl SecurityAccelerator {
    /// Creates a new security accelerator
    pub fn new(
        config: Arc<AevorConfig>,
        validation_manager: Arc<ValidationManager>,
    ) -> Result<Self> {
        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        
        // Set security level thresholds from config
        let security_level_thresholds = [
            config.consensus.security_accelerator.minimal_security_validators_pct,
            config.consensus.security_accelerator.basic_security_validators_pct,
            config.consensus.security_accelerator.strong_security_validators_pct,
            config.consensus.security_accelerator.full_security_validators_pct,
        ];
        
        // Create BLS signature aggregator
        let bls_aggregator = BLSSignatureAggregator::new()?;
        
        // Create network topology
        let network_topology = NetworkTopology::new(config.clone())?;
        
        Ok(Self {
            config,
            validation_manager,
            bls_aggregator,
            network_topology,
            transaction_security_levels: RwLock::new(HashMap::new()),
            block_security_levels: RwLock::new(HashMap::new()),
            active_transactions: RwLock::new(HashMap::new()),
            active_blocks: RwLock::new(HashMap::new()),
            validator_selection_cache: RwLock::new(HashMap::new()),
            validator_selection_refresh: Mutex::new(HashMap::new()),
            security_level_thresholds,
            signature_bundles: RwLock::new(HashMap::new()),
            running: Mutex::new(false),
            shutdown: shutdown_rx,
            task_handles: Mutex::new(Vec::new()),
        })
    }
    
    /// Starts the security accelerator
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.lock();
        if *running {
            return Ok(());
        }
        
        info!("Starting Security Accelerator");
        
        // Start background tasks
        let task_handle = self.start_background_tasks().await?;
        
        // Store task handle
        self.task_handles.lock().push(task_handle);
        
        *running = true;
        
        Ok(())
    }
    
    /// Stops the security accelerator
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.lock();
        if !*running {
            return Ok(());
        }
        
        info!("Stopping Security Accelerator");
        
        // Wait for all background tasks to complete
        for handle in self.task_handles.lock().drain(..) {
            if let Err(e) = handle.await {
                error!("Error stopping Security Accelerator task: {}", e);
            }
        }
        
        *running = false;
        
        Ok(())
    }
    
    /// Starts background tasks for security level acceleration
    async fn start_background_tasks(&self) -> Result<tokio::task::JoinHandle<()>> {
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown.clone();
        
        // Clone weak references to self components
        let transaction_security_levels = Arc::new(self.transaction_security_levels.clone());
        let block_security_levels = Arc::new(self.block_security_levels.clone());
        let active_transactions = Arc::new(self.active_transactions.clone());
        let active_blocks = Arc::new(self.active_blocks.clone());
        let validation_manager = self.validation_manager.clone();

        // Create and spawn the background task
        let handle = tokio::spawn(async move {
            info!("Starting Security Accelerator background tasks");
            
            // Define interval based on config
            let check_interval = Duration::from_millis(
                config.consensus.security_accelerator.security_check_interval_ms
            );
            let mut interval = time::interval(check_interval);
            
            // Run until shutdown signal
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("Security Accelerator background tasks shutting down");
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        // Check and update security levels
                        Self::check_security_levels(
                            transaction_security_levels.clone(),
                            block_security_levels.clone(),
                            active_transactions.clone(),
                            active_blocks.clone(),
                            validation_manager.clone(),
                        ).await;
                    }
                }
            }
            
            info!("Security Accelerator background tasks stopped");
        });
        
        Ok(handle)
    }
    
    /// Background task to check and update security levels
    async fn check_security_levels(
        transaction_security_levels: Arc<RwLock<HashMap<Vec<u8>, SecurityLevel>>>,
        block_security_levels: Arc<RwLock<HashMap<Vec<u8>, SecurityLevel>>>,
        active_transactions: Arc<RwLock<HashMap<Vec<u8>, Transaction>>>,
        active_blocks: Arc<RwLock<HashMap<Vec<u8>, Block>>>,
        validation_manager: Arc<ValidationManager>,
    ) {
        // Process transactions
        let tx_hashes: Vec<Vec<u8>> = active_transactions.read().keys().cloned().collect();
        for tx_hash in tx_hashes {
            // Get current security level
            let current_level = transaction_security_levels
                .read()
                .get(&tx_hash)
                .cloned()
                .unwrap_or(SecurityLevel::Minimal);
            
            // If the transaction is already at Full security, skip it
            if current_level == SecurityLevel::Full {
                continue;
            }
            
            // Check if the transaction has reached a higher security level
            if let Ok(validation_count) = validation_manager.get_validation_count_for_transaction(&tx_hash) {
                // Calculate new security level based on validation count and thresholds
                let new_level = Self::determine_security_level_from_count(
                    validation_count, 
                    validation_manager.validator_count()
                );
                
                // If security level has increased, update it
                if new_level > current_level {
                    debug!(
                        "Transaction {:?} security level upgraded: {:?} -> {:?}",
                        hex::encode(&tx_hash), current_level, new_level
                    );
                    
                    // Update security level
                    transaction_security_levels.write().insert(tx_hash.clone(), new_level);
                    
                    // Update transaction status if needed
                    if let Some(tx) = active_transactions.read().get(&tx_hash) {
                        let mut transaction = tx.clone();
                        transaction.set_security_level(new_level);
                        active_transactions.write().insert(tx_hash, transaction);
                    }
                }
            }
        }
        
        // Process blocks
        let block_hashes: Vec<Vec<u8>> = active_blocks.read().keys().cloned().collect();
        for block_hash in block_hashes {
            // Get current security level
            let current_level = block_security_levels
                .read()
                .get(&block_hash)
                .cloned()
                .unwrap_or(SecurityLevel::Minimal);
            
            // If the block is already at Full security, skip it
            if current_level == SecurityLevel::Full {
                continue;
            }
            
            // Check if the block has reached a higher security level
            if let Ok(validation_count) = validation_manager.get_validation_count_for_block(&block_hash) {
                // Calculate new security level based on validation count and thresholds
                let new_level = Self::determine_security_level_from_count(
                    validation_count, 
                    validation_manager.validator_count()
                );
                
                // If security level has increased, update it
                if new_level > current_level {
                    debug!(
                        "Block {:?} security level upgraded: {:?} -> {:?}",
                        hex::encode(&block_hash), current_level, new_level
                    );
                    
                    // Update security level
                    block_security_levels.write().insert(block_hash, new_level);
                }
            }
        }
    }
    
    /// Determines the security level based on validation count and validator count
    pub fn determine_security_level_from_count(
        validation_count: usize,
        validator_count: usize,
    ) -> SecurityLevel {
        if validator_count == 0 {
            return SecurityLevel::Minimal;
        }
        
        let validation_percentage = (validation_count * 100) / validator_count;
        
        if validation_percentage >= 67 {
            SecurityLevel::Full
        } else if validation_percentage >= 34 {
            SecurityLevel::Strong
        } else if validation_percentage >= 10 {
            SecurityLevel::Basic
        } else if validation_count >= 1 {
            SecurityLevel::Minimal
        } else {
            SecurityLevel::Minimal // Default to minimal
        }
    }
    
    /// Processes a transaction for security level acceleration
    pub async fn process_transaction(&self, transaction: Transaction) -> Result<()> {
        let tx_hash = transaction.hash();
        
        // Add transaction to active transactions
        self.active_transactions.write().insert(tx_hash.clone(), transaction.clone());
        
        // Initialize security level to Minimal
        self.transaction_security_levels.write().insert(tx_hash.clone(), SecurityLevel::Minimal);
        
        // Request validations from appropriate validators based on security level
        self.request_validations_for_transaction(&tx_hash, transaction).await?;
        
        Ok(())
    }
    
    /// Processes a block for security level acceleration
    pub async fn process_block(&self, block: Block) -> Result<()> {
        let block_hash = block.hash();
        
        // Add block to active blocks
        self.active_blocks.write().insert(block_hash.clone(), block.clone());
        
        // Initialize security level to Minimal
        self.block_security_levels.write().insert(block_hash.clone(), SecurityLevel::Minimal);
        
        // Request validations from appropriate validators based on security level
        self.request_validations_for_block(&block_hash, block).await?;
        
        Ok(())
    }
    
    /// Request validations for a transaction from appropriate validators
    async fn request_validations_for_transaction(
        &self,
        tx_hash: &[u8],
        transaction: Transaction,
    ) -> Result<()> {
        // Get current security level
        let current_level = self.transaction_security_levels
            .read()
            .get(tx_hash)
            .cloned()
            .unwrap_or(SecurityLevel::Minimal);
        
        // Determine the next security level to target
        let target_level = current_level.next().unwrap_or(current_level);
        
        // Select validators for the target security level
        let validators = self.select_validators_for_security_level(tx_hash, target_level).await?;
        
        // Request validations from selected validators
        for validator_id in validators {
            self.validation_manager.request_transaction_validation(
                tx_hash.to_vec(),
                transaction.clone(),
                &validator_id,
            ).await?;
        }
        
        Ok(())
    }
    
    /// Request validations for a block from appropriate validators
    async fn request_validations_for_block(
        &self,
        block_hash: &[u8],
        block: Block,
    ) -> Result<()> {
        // Get current security level
        let current_level = self.block_security_levels
            .read()
            .get(block_hash)
            .cloned()
            .unwrap_or(SecurityLevel::Minimal);
        
        // Determine the next security level to target
        let target_level = current_level.next().unwrap_or(current_level);
        
        // Select validators for the target security level
        let validators = self.select_validators_for_security_level(block_hash, target_level).await?;
        
        // Request validations from selected validators
        for validator_id in validators {
            self.validation_manager.request_block_validation(
                block_hash.to_vec(),
                block.clone(),
                &validator_id,
            ).await?;
        }
        
        Ok(())
    }
    
    /// Selects validators for a specific security level
    async fn select_validators_for_security_level(
        &self,
        hash: &[u8],
        level: SecurityLevel,
    ) -> Result<HashSet<Vec<u8>>> {
        // Check cache first
        let cache_key = (level, hash.to_vec());
        {
            let selection_cache = self.validator_selection_cache.read();
            if let Some(validators) = selection_cache.get(&cache_key) {
                // Check if we need to refresh based on time
                let refresh_required = {
                    let refresh_map = self.validator_selection_refresh.lock();
                    if let Some(timestamp) = refresh_map.get(hash) {
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        now > *timestamp + self.config.consensus.security_accelerator.validator_refresh_interval_ms
                    } else {
                        false
                    }
                };
                
                if !refresh_required {
                    return Ok(validators.clone());
                }
            }
        }
        
        // Get all active validators
        let all_validators = self.validation_manager.get_active_validators()?;
        let total_validators = all_validators.len();
        
        // Determine how many validators we need for this security level
        let required_validators = self.calculate_required_validators(level, total_validators);
        
        // Use network topology to select validators with optimal distribution
        let selected_validators = self.network_topology.select_validators_for_validation(
            hash,
            &all_validators,
            required_validators,
            level,
        )?;
        
        // Cache the selection
        {
            let mut selection_cache = self.validator_selection_cache.write();
            selection_cache.insert(cache_key, selected_validators.clone());
            
            // Update refresh timestamp
            let mut refresh_map = self.validator_selection_refresh.lock();
            refresh_map.insert(
                hash.to_vec(),
                chrono::Utc::now().timestamp_millis() as u64,
            );
        }
        
        Ok(selected_validators)
    }
    
    /// Calculates the number of validators required for a security level
    fn calculate_required_validators(&self, level: SecurityLevel, total_validators: usize) -> usize {
        if total_validators == 0 {
            return 0;
        }
        
        // Get the percentage threshold for this level
        let percentage = match level {
            SecurityLevel::Minimal => self.security_level_thresholds[0],
            SecurityLevel::Basic => self.security_level_thresholds[1],
            SecurityLevel::Strong => self.security_level_thresholds[2],
            SecurityLevel::Full => self.security_level_thresholds[3],
        };
        
        // Calculate required number (ensure at least 1)
        let required = (total_validators * percentage as usize) / 100;
        std::cmp::max(1, required)
    }
    
    /// Gets the security level of a transaction
    pub async fn get_transaction_security_level(&self, tx_hash: &[u8]) -> Result<u8> {
        let security_levels = self.transaction_security_levels.read();
        
        let level = security_levels
            .get(tx_hash)
            .copied()
            .unwrap_or(SecurityLevel::Minimal);
        
        Ok(level as u8)
    }
    
    /// Gets the security level of a block
    pub async fn get_block_security_level(&self, block_hash: &[u8]) -> Result<u8> {
        let security_levels = self.block_security_levels.read();
        
        let level = security_levels
            .get(block_hash)
            .copied()
            .unwrap_or(SecurityLevel::Minimal);
        
        Ok(level as u8)
    }
    
    /// Checks if a transaction has reached a specific security level
    pub async fn has_transaction_reached_security_level(
        &self,
        tx_hash: &[u8],
        level: u8,
    ) -> Result<bool> {
        if level > 3 {
            return Err(AevorError::validation(format!("Invalid security level: {}", level)));
        }
        
        let security_level = SecurityLevel::from_u8(level)
            .ok_or_else(|| AevorError::validation(format!("Invalid security level: {}", level)))?;
        
        let current_level = self.transaction_security_levels
            .read()
            .get(tx_hash)
            .copied()
            .unwrap_or(SecurityLevel::Minimal);
        
        Ok(current_level >= security_level)
    }
    
    /// Checks if a block has reached a specific security level
    pub async fn has_block_reached_security_level(
        &self,
        block_hash: &[u8],
        level: u8,
    ) -> Result<bool> {
        if level > 3 {
            return Err(AevorError::validation(format!("Invalid security level: {}", level)));
        }
        
        let security_level = SecurityLevel::from_u8(level)
            .ok_or_else(|| AevorError::validation(format!("Invalid security level: {}", level)))?;
        
        let current_level = self.block_security_levels
            .read()
            .get(block_hash)
            .copied()
            .unwrap_or(SecurityLevel::Minimal);
        
        Ok(current_level >= security_level)
    }
    
    /// Handles a new validation result for a transaction
    pub async fn handle_transaction_validation(
        &self, 
        tx_hash: &[u8], 
        validator_id: &[u8], 
        result: ValidationResult
    ) -> Result<()> {
        // Only process successful validations
        if result.status != ValidationStatus::Valid {
            return Ok(());
        }
        
        // Get current security level
        let current_level = self.transaction_security_levels
            .read()
            .get(tx_hash)
            .copied()
            .unwrap_or(SecurityLevel::Minimal);
        
        // Add signature to the appropriate BLS signature bundle
        if self.config.consensus.security_accelerator.use_bls_aggregation {
            self.add_to_signature_bundle(tx_hash, validator_id, &result.signature, current_level).await?;
        }
        
        // Check if this validation allows progression to next security level
        let validation_count = self.validation_manager.get_validation_count_for_transaction(tx_hash)?;
        let validator_count = self.validation_manager.validator_count();
        
        let new_level = Self::determine_security_level_from_count(validation_count, validator_count);
        
        // If security level has increased, update it
        if new_level > current_level {
            debug!(
                "Transaction {:?} security level upgraded: {:?} -> {:?}",
                hex::encode(tx_hash), current_level, new_level
            );
            
            // Update security level
            self.transaction_security_levels.write().insert(tx_hash.to_vec(), new_level);
            
            // Update transaction security level
            if let Some(transaction) = self.active_transactions.read().get(tx_hash) {
                let mut tx = transaction.clone();
                tx.set_security_level(new_level);
                
                // Update active transaction
                self.active_transactions.write().insert(tx_hash.to_vec(), tx);
                
                // Request validations for next level if needed
                if let Some(next_level) = new_level.next() {
                    self.request_next_level_validations_for_transaction(tx_hash, next_level).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handles a new validation result for a block
    pub async fn handle_block_validation(
        &self, 
        block_hash: &[u8], 
        validator_id: &[u8], 
        result: ValidationResult
    ) -> Result<()> {
        // Only process successful validations
        if result.status != ValidationStatus::Valid {
            return Ok(());
        }
        
        // Get current security level
        let current_level = self.block_security_levels
            .read()
            .get(block_hash)
            .copied()
            .unwrap_or(SecurityLevel::Minimal);
        
        // Add signature to the appropriate BLS signature bundle
        if self.config.consensus.security_accelerator.use_bls_aggregation {
            self.add_to_signature_bundle(block_hash, validator_id, &result.signature, current_level).await?;
        }
        
        // Check if this validation allows progression to next security level
        let validation_count = self.validation_manager.get_validation_count_for_block(block_hash)?;
        let validator_count = self.validation_manager.validator_count();
        
        let new_level = Self::determine_security_level_from_count(validation_count, validator_count);
        
        // If security level has increased, update it
        if new_level > current_level {
            debug!(
                "Block {:?} security level upgraded: {:?} -> {:?}",
                hex::encode(block_hash), current_level, new_level
            );
            
            // Update security level
            self.block_security_levels.write().insert(block_hash.to_vec(), new_level);
            
            // Request validations for next level if needed
            if let Some(next_level) = new_level.next() {
                self.request_next_level_validations_for_block(block_hash, next_level).await?;
            }
        }
        
        Ok(())
    }
    
    /// Request validations for the next security level for a transaction
    async fn request_next_level_validations_for_transaction(
        &self,
        tx_hash: &[u8],
        next_level: SecurityLevel,
    ) -> Result<()> {
        // Don't proceed if the transaction doesn't exist
        let transaction = match self.active_transactions.read().get(tx_hash) {
            Some(tx) => tx.clone(),
            None => return Ok(()),
        };
        
        // Select validators for the next security level
        let validators = self.select_validators_for_security_level(tx_hash, next_level).await?;
        
        // Get validators that have already validated
        let validated_validators = self.validation_manager.get_validators_for_transaction(tx_hash)?;
        
        // Request validations from validators that haven't validated yet
        for validator_id in validators {
            if !validated_validators.contains(&validator_id) {
                self.validation_manager.request_transaction_validation(
                    tx_hash.to_vec(),
                    transaction.clone(),
                    &validator_id,
                ).await?;
            }
        }
        
        Ok(())
    }
    
    /// Request validations for the next security level for a block
    async fn request_next_level_validations_for_block(
        &self,
        block_hash: &[u8],
        next_level: SecurityLevel,
    ) -> Result<()> {
        // Don't proceed if the block doesn't exist
        let block = match self.active_blocks.read().get(block_hash) {
            Some(b) => b.clone(),
            None => return Ok(()),
        };
        
        // Select validators for the next security level
        let validators = self.select_validators_for_security_level(block_hash, next_level).await?;
        
        // Get validators that have already validated
        let validated_validators = self.validation_manager.get_validators_for_block(block_hash)?;
        
        // Request validations from validators that haven't validated yet
        for validator_id in validators {
            if !validated_validators.contains(&validator_id) {
                self.validation_manager.request_block_validation(
                    block_hash.to_vec(),
                    block.clone(),
                    &validator_id,
                ).await?;
            }
        }
        
        Ok(())
    }
    
    /// Adds a signature to the appropriate BLS signature bundle
    async fn add_to_signature_bundle(
        &self,
        hash: &[u8],
        validator_id: &[u8],
        signature: &[u8],
        level: SecurityLevel,
    ) -> Result<()> {
        let bundle_key = (hash.to_vec(), level);
        
        // Add signature to aggregator
        self.bls_aggregator.add_signature(hash, validator_id, signature)?;
        
        // Get aggregated signature for this security level
        let aggregated_signature = self.bls_aggregator.aggregate_signatures_for_message(hash)?;
        
        // Store the aggregated signature
        self.signature_bundles.write().insert(bundle_key, aggregated_signature);
        
        Ok(())
    }
    
    /// Gets the BLS signature bundle for a given hash and security level
    pub fn get_signature_bundle(&self, hash: &[u8], level: SecurityLevel) -> Option<Vec<u8>> {
        let bundles = self.signature_bundles.read();
        bundles.get(&(hash.to_vec(), level)).cloned()
    }
    
    /// Cleans up completed transactions and blocks
    pub async fn cleanup_completed(&self) -> Result<()> {
        // Clean up transactions that have reached Full security level
        let full_tx_hashes: Vec<Vec<u8>> = {
            let security_levels = self.transaction_security_levels.read();
            security_levels
                .iter()
                .filter(|(_, &level)| level == SecurityLevel::Full)
                .map(|(hash, _)| hash.clone())
                .collect()
        };
        
        for tx_hash in full_tx_hashes {
            // Remove from active transactions
            self.active_transactions.write().remove(&tx_hash);
            
            // Keep the security level for reference
        }
        
        // Clean up blocks that have reached Full security level
        let full_block_hashes: Vec<Vec<u8>> = {
            let security_levels = self.block_security_levels.read();
            security_levels
                .iter()
                .filter(|(_, &level)| level == SecurityLevel::Full)
                .map(|(hash, _)| hash.clone())
                .collect()
        };
        
        for block_hash in full_block_hashes {
            // Remove from active blocks
            self.active_blocks.write().remove(&block_hash);
            
            // Keep the security level for reference
        }
        
        Ok(())
    }
    
    /// Gets the aggregated BLS signature for a transaction at a specific security level
    pub async fn get_transaction_signature_bundle(
        &self,
        tx_hash: &[u8],
        level: SecurityLevel,
    ) -> Result<Option<Vec<u8>>> {
        let bundle = self.get_signature_bundle(tx_hash, level);
        Ok(bundle)
    }
    
    /// Gets the aggregated BLS signature for a block at a specific security level
    pub async fn get_block_signature_bundle(
        &self,
        block_hash: &[u8],
        level: SecurityLevel,
    ) -> Result<Option<Vec<u8>>> {
        let bundle = self.get_signature_bundle(block_hash, level);
        Ok(bundle)
    }
    
    /// Updates the network topology
    pub fn update_network_topology(&self, topology: NetworkTopology) {
        self.network_topology.update(topology);
        
        // Clear validator selection cache to force re-selection with new topology
        self.validator_selection_cache.write().clear();
    }
    
    /// Gets all transactions with their security levels
    pub fn get_all_transaction_security_levels(&self) -> HashMap<Vec<u8>, SecurityLevel> {
        self.transaction_security_levels.read().clone()
    }
    
    /// Gets all blocks with their security levels
    pub fn get_all_block_security_levels(&self) -> HashMap<Vec<u8>, SecurityLevel> {
        self.block_security_levels.read().clone()
    }
    
    /// Gets active transactions currently being processed
    pub fn get_active_transactions(&self) -> HashMap<Vec<u8>, Transaction> {
        self.active_transactions.read().clone()
    }
    
    /// Gets active blocks currently being processed
    pub fn get_active_blocks(&self) -> HashMap<Vec<u8>, Block> {
        self.active_blocks.read().clone()
    }
    
    /// Gets the count of transactions at each security level
    pub fn get_transaction_level_counts(&self) -> HashMap<SecurityLevel, usize> {
        let mut counts = HashMap::new();
        let security_levels = self.transaction_security_levels.read();
        
        for level in security_levels.values() {
            *counts.entry(*level).or_insert(0) += 1;
        }
        
        counts
    }
    
    /// Gets the count of blocks at each security level
    pub fn get_block_level_counts(&self) -> HashMap<SecurityLevel, usize> {
        let mut counts = HashMap::new();
        let security_levels = self.block_security_levels.read();
        
        for level in security_levels.values() {
            *counts.entry(*level).or_insert(0) += 1;
        }
        
        counts
    }
    
    /// Gets metrics about the security accelerator
    pub fn get_metrics(&self) -> SecurityAcceleratorMetrics {
        let tx_counts = self.get_transaction_level_counts();
        let block_counts = self.get_block_level_counts();
        
        let minimal_txs = tx_counts.get(&SecurityLevel::Minimal).cloned().unwrap_or(0);
        let basic_txs = tx_counts.get(&SecurityLevel::Basic).cloned().unwrap_or(0);
        let strong_txs = tx_counts.get(&SecurityLevel::Strong).cloned().unwrap_or(0);
        let full_txs = tx_counts.get(&SecurityLevel::Full).cloned().unwrap_or(0);
        
        let minimal_blocks = block_counts.get(&SecurityLevel::Minimal).cloned().unwrap_or(0);
        let basic_blocks = block_counts.get(&SecurityLevel::Basic).cloned().unwrap_or(0);
        let strong_blocks = block_counts.get(&SecurityLevel::Strong).cloned().unwrap_or(0);
        let full_blocks = block_counts.get(&SecurityLevel::Full).cloned().unwrap_or(0);
        
        SecurityAcceleratorMetrics {
            active_transactions: self.active_transactions.read().len(),
            active_blocks: self.active_blocks.read().len(),
            signature_bundles: self.signature_bundles.read().len(),
            minimal_security_transactions: minimal_txs,
            basic_security_transactions: basic_txs,
            strong_security_transactions: strong_txs,
            full_security_transactions: full_txs,
            minimal_security_blocks: minimal_blocks,
            basic_security_blocks: basic_blocks,
            strong_security_blocks: strong_blocks,
            full_security_blocks: full_blocks,
            validator_selection_cache_size: self.validator_selection_cache.read().len(),
        }
    }
    
    /// Reconfigures the security level thresholds
    pub fn reconfigure_thresholds(&mut self, thresholds: [u8; 4]) -> Result<()> {
        // Validate thresholds
        if thresholds[0] > 100 || thresholds[1] > 100 || thresholds[2] > 100 || thresholds[3] > 100 {
            return Err(AevorError::validation("Security level thresholds must be between 0 and 100"));
        }
        
        // Ensure thresholds are in ascending order
        if !(thresholds[0] <= thresholds[1] && thresholds[1] <= thresholds[2] && thresholds[2] <= thresholds[3]) {
            return Err(AevorError::validation("Security level thresholds must be in ascending order"));
        }
        
        // Update thresholds
        self.security_level_thresholds = thresholds;
        
        // Clear caches to force re-evaluation with new thresholds
        self.validator_selection_cache.write().clear();
        
        Ok(())
    }
    
    /// Forces a security level reevaluation for a transaction
    pub async fn reevaluate_transaction_security(&self, tx_hash: &[u8]) -> Result<()> {
        // Check if transaction exists
        if !self.active_transactions.read().contains_key(tx_hash) {
            return Err(AevorError::validation("Transaction not found"));
        }
        
        // Get validation count
        let validation_count = self.validation_manager.get_validation_count_for_transaction(tx_hash)?;
        let validator_count = self.validation_manager.validator_count();
        
        // Determine security level
        let new_level = Self::determine_security_level_from_count(validation_count, validator_count);
        
        // Update security level
        self.transaction_security_levels.write().insert(tx_hash.to_vec(), new_level);
        
        // Update transaction security level
        if let Some(transaction) = self.active_transactions.read().get(tx_hash) {
            let mut tx = transaction.clone();
            tx.set_security_level(new_level);
            
            // Update active transaction
            self.active_transactions.write().insert(tx_hash.to_vec(), tx);
        }
        
        Ok(())
    }
    
    /// Forces a security level reevaluation for a block
    pub async fn reevaluate_block_security(&self, block_hash: &[u8]) -> Result<()> {
        // Check if block exists
        if !self.active_blocks.read().contains_key(block_hash) {
            return Err(AevorError::validation("Block not found"));
        }
        
        // Get validation count
        let validation_count = self.validation_manager.get_validation_count_for_block(block_hash)?;
        let validator_count = self.validation_manager.validator_count();
        
        // Determine security level
        let new_level = Self::determine_security_level_from_count(validation_count, validator_count);
        
        // Update security level
        self.block_security_levels.write().insert(block_hash.to_vec(), new_level);
        
        Ok(())
    }
    
    /// Removes a transaction from the accelerator
    pub fn remove_transaction(&self, tx_hash: &[u8]) -> Result<()> {
        // Remove from active transactions
        self.active_transactions.write().remove(tx_hash);
        
        // Remove security level
        self.transaction_security_levels.write().remove(tx_hash);
        
        // Remove from validator selection cache
        let mut cache = self.validator_selection_cache.write();
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            cache.remove(&(level, tx_hash.to_vec()));
        }
        
        // Remove from signature bundles
        let mut bundles = self.signature_bundles.write();
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            bundles.remove(&(tx_hash.to_vec(), level));
        }
        
        // Remove from validator selection refresh
        self.validator_selection_refresh.lock().remove(tx_hash);
        
        Ok(())
    }
    
    /// Removes a block from the accelerator
    pub fn remove_block(&self, block_hash: &[u8]) -> Result<()> {
        // Remove from active blocks
        self.active_blocks.write().remove(block_hash);
        
        // Remove security level
        self.block_security_levels.write().remove(block_hash);
        
        // Remove from validator selection cache
        let mut cache = self.validator_selection_cache.write();
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            cache.remove(&(level, block_hash.to_vec()));
        }
        
        // Remove from signature bundles
        let mut bundles = self.signature_bundles.write();
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            bundles.remove(&(block_hash.to_vec(), level));
        }
        
        // Remove from validator selection refresh
        self.validator_selection_refresh.lock().remove(block_hash);
        
        Ok(())
    }
    
    /// Verifies a signature bundle for a transaction
    pub fn verify_transaction_signature_bundle(
        &self,
        tx_hash: &[u8],
        level: SecurityLevel,
        bundle: &[u8],
    ) -> Result<bool> {
        // Verify using BLS aggregator
        self.bls_aggregator.verify_aggregated_signature(tx_hash, bundle)
    }
    
    /// Verifies a signature bundle for a block
    pub fn verify_block_signature_bundle(
        &self,
        block_hash: &[u8],
        level: SecurityLevel,
        bundle: &[u8],
    ) -> Result<bool> {
        // Verify using BLS aggregator
        self.bls_aggregator.verify_aggregated_signature(block_hash, bundle)
    }
    
    /// Gets the minimum required validators for a security level
    pub fn get_required_validators_for_level(&self, level: SecurityLevel, total_validators: usize) -> usize {
        self.calculate_required_validators(level, total_validators)
    }
    
    /// Gets the security level thresholds
    pub fn get_security_level_thresholds(&self) -> [u8; 4] {
        self.security_level_thresholds
    }
    
    /// Processes a batch of transactions for security level acceleration
    pub async fn process_transaction_batch(&self, transactions: Vec<Transaction>) -> Result<()> {
        for transaction in transactions {
            self.process_transaction(transaction).await?;
        }
        
        Ok(())
    }
    
    /// Gets the recommended security level for a transaction value
    pub fn recommend_security_level_for_value(&self, value: u64) -> SecurityLevel {
        SecurityLevel::suggest_for_value(value)
    }
    
    /// Exports security accelerator state for persistence
    pub fn export_state(&self) -> SecurityAcceleratorState {
        SecurityAcceleratorState {
            transaction_security_levels: self.transaction_security_levels.read().clone(),
            block_security_levels: self.block_security_levels.read().clone(),
            signature_bundles: self.signature_bundles.read().clone(),
        }
    }
    
    /// Imports security accelerator state from persistence
    pub fn import_state(&self, state: SecurityAcceleratorState) -> Result<()> {
        // Update transaction security levels
        self.transaction_security_levels.write().extend(state.transaction_security_levels);
        
        // Update block security levels
        self.block_security_levels.write().extend(state.block_security_levels);
        
        // Update signature bundles
        self.signature_bundles.write().extend(state.signature_bundles);
        
        Ok(())
    }
}

/// Metrics about the security accelerator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAcceleratorMetrics {
    /// Number of active transactions
    pub active_transactions: usize,
    
    /// Number of active blocks
    pub active_blocks: usize,
    
    /// Number of signature bundles
    pub signature_bundles: usize,
    
    /// Number of transactions at Minimal security
    pub minimal_security_transactions: usize,
    
    /// Number of transactions at Basic security
    pub basic_security_transactions: usize,
    
    /// Number of transactions at Strong security
    pub strong_security_transactions: usize,
    
    /// Number of transactions at Full security
    pub full_security_transactions: usize,
    
    /// Number of blocks at Minimal security
    pub minimal_security_blocks: usize,
    
    /// Number of blocks at Basic security
    pub basic_security_blocks: usize,
    
    /// Number of blocks at Strong security
    pub strong_security_blocks: usize,
    
    /// Number of blocks at Full security
    pub full_security_blocks: usize,
    
    /// Size of validator selection cache
    pub validator_selection_cache_size: usize,
}

/// Security accelerator state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAcceleratorState {
    /// Transaction security levels
    pub transaction_security_levels: HashMap<Vec<u8>, SecurityLevel>,
    
    /// Block security levels
    pub block_security_levels: HashMap<Vec<u8>, SecurityLevel>,
    
    /// Signature bundles
    pub signature_bundles: HashMap<(Vec<u8>, SecurityLevel), Vec<u8>>,
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
    
    #[test]
    fn test_determine_security_level_from_count() {
        // Test with zero validators
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(0, 0),
            SecurityLevel::Minimal
        );
        
        // Test with 100 validators
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(0, 100),
            SecurityLevel::Minimal
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(1, 100),
            SecurityLevel::Minimal
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(9, 100),
            SecurityLevel::Minimal
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(10, 100),
            SecurityLevel::Basic
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(33, 100),
            SecurityLevel::Basic
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(34, 100),
            SecurityLevel::Strong
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(66, 100),
            SecurityLevel::Strong
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(67, 100),
            SecurityLevel::Full
        );
        assert_eq!(
            SecurityAccelerator::determine_security_level_from_count(100, 100),
            SecurityLevel::Full
        );
    }
    
    #[test]
    fn test_calculate_required_validators() {
        // Create a mock security accelerator
        let config = Arc::new(AevorConfig::default());
        let validation_manager = Arc::new(ValidationManager::new(
            config.clone(),
            Arc::new(crate::core::Blockchain::new(
                config.clone(),
                Arc::new(crate::storage::Storage::new(&config.storage).unwrap())
            ).unwrap())
        ).unwrap());
        
        let security_accelerator = SecurityAccelerator::new(
            config,
            validation_manager
        ).unwrap();
        
        // Test with zero validators
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Minimal, 0),
            0
        );
        
        // Test with 100 validators
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Minimal, 100),
            1 // At least 1
        );
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Basic, 100),
            15 // 15% of 100
        );
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Strong, 100),
            34 // 34% of 100
        );
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Full, 100),
            67 // 67% of 100
        );
        
        // Test with small validator set
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Minimal, 5),
            1 // At least 1
        );
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Basic, 5),
            1 // 15% of 5 is 0.75, rounds to 1
        );
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Strong, 5),
            1 // 34% of 5 is 1.7, rounds to 1
        );
        assert_eq!(
            security_accelerator.calculate_required_validators(SecurityLevel::Full, 5),
            3 // 67% of 5 is 3.35, rounds to 3
        );
    }
}
