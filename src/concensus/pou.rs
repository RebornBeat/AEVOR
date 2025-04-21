use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::config::AevorConfig;
use crate::core::{Block, Blockchain};
use crate::core::block::{BlockStatus, ParallelChainReference};
use crate::error::{AevorError, Result};
use crate::execution::tee::TEEManager;

/// Represents an uncorrupted blockchain in the PoU consensus
#[derive(Debug, Clone)]
pub struct UncorruptedChain {
    /// Chain identifier
    pub id: String,
    
    /// Blocks in the chain, indexed by their hash
    pub blocks: HashMap<Vec<u8>, Block>,
    
    /// Block hashes by height
    pub blocks_by_height: HashMap<u64, HashSet<Vec<u8>>>,
    
    /// Latest block hash
    pub latest_block_hash: Vec<u8>,
    
    /// Latest block height
    pub latest_height: u64,
    
    /// Genesis block hash
    pub genesis_block_hash: Vec<u8>,
    
    /// Creation timestamp
    pub creation_time: u64,
    
    /// Last update timestamp
    pub last_update_time: u64,
    
    /// Uncorruption confidence score (0-100)
    pub uncorruption_confidence: u8,
    
    /// Total validators that have confirmed this chain
    pub validator_confirmations: HashMap<Vec<u8>, Vec<u8>>, // validator_id -> signature
}

impl UncorruptedChain {
    /// Creates a new uncorrupted chain with a genesis block
    pub fn new(genesis_block: Block) -> Self {
        let genesis_hash = genesis_block.hash();
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let id = format!("chain-{}", hex::encode(&genesis_hash[0..4]));
        
        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash.clone(), genesis_block);
        
        let mut blocks_by_height = HashMap::new();
        let mut height_set = HashSet::new();
        height_set.insert(genesis_hash.clone());
        blocks_by_height.insert(0, height_set);
        
        Self {
            id,
            blocks,
            blocks_by_height,
            latest_block_hash: genesis_hash.clone(),
            latest_height: 0,
            genesis_block_hash: genesis_hash,
            creation_time: now,
            last_update_time: now,
            uncorruption_confidence: 100, // Genesis block is always uncorrupted
            validator_confirmations: HashMap::new(),
        }
    }
    
    /// Adds a block to the chain
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        let block_hash = block.hash();
        let height = block.height();
        
        // Check if the block already exists
        if self.blocks.contains_key(&block_hash) {
            return Ok(());
        }
        
        // Check if the block references this chain's blocks as parents
        let mut valid_parent = false;
        for parent_hash in block.previous_hashes() {
            if self.blocks.contains_key(parent_hash) {
                valid_parent = true;
                break;
            }
        }
        
        if !valid_parent {
            return Err(AevorError::validation(format!(
                "Block {} does not reference any block in chain {}",
                hex::encode(&block_hash), self.id
            )));
        }
        
        // Add the block
        self.blocks.insert(block_hash.clone(), block.clone());
        
        // Update blocks by height
        let height_set = self.blocks_by_height.entry(height).or_insert_with(HashSet::new);
        height_set.insert(block_hash.clone());
        
        // Update latest block info if needed
        if height > self.latest_height {
            self.latest_height = height;
            self.latest_block_hash = block_hash.clone();
        }
        
        // Update last update time
        self.last_update_time = chrono::Utc::now().timestamp_millis() as u64;
        
        // Add validator confirmations from the block
        for (validator_id, signature) in block.uncorruption_data().validator_confirmations() {
            self.validator_confirmations.insert(validator_id.clone(), signature.clone());
        }
        
        // Calculate uncorruption confidence based on validator confirmations
        self.recalculate_uncorruption_confidence();
        
        Ok(())
    }
    
    /// Gets a block by hash
    pub fn get_block(&self, block_hash: &[u8]) -> Option<&Block> {
        self.blocks.get(block_hash)
    }
    
    /// Gets blocks at a specific height
    pub fn get_blocks_at_height(&self, height: u64) -> Vec<&Block> {
        let mut result = Vec::new();
        
        if let Some(hashes) = self.blocks_by_height.get(&height) {
            for hash in hashes {
                if let Some(block) = self.blocks.get(hash) {
                    result.push(block);
                }
            }
        }
        
        result
    }
    
    /// Gets the chain from a specific block to genesis
    pub fn get_chain_to_genesis(&self, block_hash: &[u8]) -> Result<Vec<Block>> {
        let mut result = Vec::new();
        let mut current_hash = block_hash.to_vec();
        
        while current_hash != self.genesis_block_hash {
            let block = self.get_block(&current_hash)
                .ok_or_else(|| AevorError::consensus(format!(
                    "Block {} not found in chain {}",
                    hex::encode(&current_hash), self.id
                )))?;
                
            result.push(block.clone());
            
            // Move to the first parent
            if let Some(parent_hash) = block.previous_hashes().first() {
                current_hash = parent_hash.clone();
            } else {
                return Err(AevorError::consensus(format!(
                    "Block {} has no parents",
                    hex::encode(&current_hash)
                )));
            }
        }
        
        // Add the genesis block
        let genesis_block = self.get_block(&self.genesis_block_hash)
            .ok_or_else(|| AevorError::consensus("Genesis block not found"))?;
            
        result.push(genesis_block.clone());
        
        // Reverse the chain so genesis is first
        result.reverse();
        
        Ok(result)
    }
    
    /// Checks if the chain is valid (has no corruption)
    pub fn is_chain_valid(&self) -> bool {
        // Start from the genesis block
        let mut checked_blocks = HashSet::new();
        let mut queue = vec![self.genesis_block_hash.clone()];
        
        while let Some(block_hash) = queue.pop() {
            if checked_blocks.contains(&block_hash) {
                continue;
            }
            
            let block = match self.get_block(&block_hash) {
                Some(b) => b,
                None => return false, // Block not found
            };
            
            // Check block status
            if block.status() == BlockStatus::Rejected {
                return false; // Chain contains a rejected block
            }
            
            // Check block uncorruption proofs
            if !self.verify_block_uncorruption(block) {
                return false; // Block has invalid uncorruption proofs
            }
            
            // Mark as checked
            checked_blocks.insert(block_hash);
            
            // Enqueue all blocks that reference this block
            for (hash, child_block) in &self.blocks {
                if child_block.is_child_of(&block_hash) && !checked_blocks.contains(hash) {
                    queue.push(hash.clone());
                }
            }
        }
        
        true
    }
    
    /// Verifies a block's uncorruption proofs
    fn verify_block_uncorruption(&self, block: &Block) -> bool {
        // For genesis block, always return true
        if block.height() == 0 {
            return true;
        }
        
        // Check if block has TEE attestation
        let has_attestation = block.uncorruption_data().has_tee_attestation();
        
        // Check if block has enough validator confirmations
        let confirmation_count = block.confirmation_count();
        let has_confirmations = confirmation_count >= block.uncorruption_data().confirmation_threshold() as usize;
        
        // Verify uncorruption proof
        let has_valid_proof = block.uncorruption_data().verify_proof();
        
        // For a block to be uncorrupted, it must have:
        // 1. Valid TEE attestation OR enough validator confirmations
        // 2. Valid uncorruption proof
        (has_attestation || has_confirmations) && has_valid_proof
    }
    
    /// Recalculates the uncorruption confidence score
    fn recalculate_uncorruption_confidence(&mut self) {
        let total_blocks = self.blocks.len();
        if total_blocks == 0 {
            self.uncorruption_confidence = 0;
            return;
        }
        
        let mut uncorrupted_blocks = 0;
        
        for (_, block) in &self.blocks {
            if block.status() == BlockStatus::Uncorrupted || 
               block.status() == BlockStatus::Finalized ||
               self.verify_block_uncorruption(block) {
                uncorrupted_blocks += 1;
            }
        }
        
        // Calculate confidence percentage
        self.uncorruption_confidence = ((uncorrupted_blocks * 100) / total_blocks) as u8;
    }
    
    /// Gets the block count
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
    
    /// Gets all blocks in the chain
    pub fn get_all_blocks(&self) -> Vec<&Block> {
        self.blocks.values().collect()
    }
    
    /// Gets all block hashes
    pub fn get_all_block_hashes(&self) -> Vec<Vec<u8>> {
        self.blocks.keys().cloned().collect()
    }
    
    /// Gets validator confirmation count
    pub fn validator_confirmation_count(&self) -> usize {
        self.validator_confirmations.len()
    }
    
    /// Adds a validator confirmation
    pub fn add_validator_confirmation(&mut self, validator_id: Vec<u8>, signature: Vec<u8>) {
        self.validator_confirmations.insert(validator_id, signature);
        self.recalculate_uncorruption_confidence();
    }
    
    /// Checks if a specific validator has confirmed this chain
    pub fn is_confirmed_by(&self, validator_id: &[u8]) -> bool {
        self.validator_confirmations.contains_key(validator_id)
    }
    
    /// Gets the uncorruption confidence score
    pub fn uncorruption_confidence(&self) -> u8 {
        self.uncorruption_confidence
    }
    
    /// Serializes the chain to JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "block_count": self.block_count(),
            "latest_height": self.latest_height,
            "latest_block_hash": hex::encode(&self.latest_block_hash),
            "genesis_block_hash": hex::encode(&self.genesis_block_hash),
            "creation_time": self.creation_time,
            "last_update_time": self.last_update_time,
            "uncorruption_confidence": self.uncorruption_confidence,
            "validator_confirmation_count": self.validator_confirmation_count(),
        })
    }
}

/// Background service for PoU corruption detection
pub struct PoUBackgroundService {
    /// Proof of Uncorruption instance
    pou: Arc<ProofOfUncorruption>,
    
    /// Task handles
    tasks: Vec<JoinHandle<()>>,
    
    /// Shutdown signal
    shutdown: Arc<tokio::sync::watch::Sender<bool>>,
}

impl PoUBackgroundService {
    /// Creates a new background service
    pub fn new(pou: Arc<ProofOfUncorruption>) -> Self {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        
        Self {
            pou,
            tasks: Vec::new(),
            shutdown: Arc::new(shutdown_tx),
        }
    }
    
    /// Starts the background service
    pub async fn start(&mut self) -> Result<()> {
        let pou = self.pou.clone();
        let mut shutdown_rx = self.shutdown.subscribe();
        
        // Start corruption detection task
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check for corruption
                        if let Err(e) = pou.detect_corruption().await {
                            tracing::error!("Error in corruption detection: {}", e);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        
        self.tasks.push(handle);
        
        // Start parallel chain monitoring task
        let pou = self.pou.clone();
        let mut shutdown_rx = self.shutdown.subscribe();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Monitor and merge parallel chains
                        if let Err(e) = pou.monitor_parallel_chains().await {
                            tracing::error!("Error in parallel chain monitoring: {}", e);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        
        self.tasks.push(handle);
        
        // Start TEE attestation verification task
        let pou = self.pou.clone();
        let mut shutdown_rx = self.shutdown.subscribe();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Verify TEE attestations
                        if let Err(e) = pou.verify_tee_attestations().await {
                            tracing::error!("Error in TEE attestation verification: {}", e);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        
        self.tasks.push(handle);
        
        Ok(())
    }
    
    /// Shuts down the background service
    pub async fn shutdown(&self) -> Result<()> {
        // Signal shutdown
        let _ = self.shutdown.send(true);
        
        Ok(())
    }
}

/// Proof of Uncorruption (PoU) implementation
///
/// This component implements the Proof of Uncorruption consensus mechanism,
/// which focuses on validating execution integrity through TEE attestations.
/// It ensures that all transactions are executed correctly and maintains
/// an uncorrupted view of the blockchain history.
#[derive(Debug)]
pub struct ProofOfUncorruption {
    /// Configuration
    config: Arc<AevorConfig>,
    
    /// Blockchain instance
    blockchain: Arc<Blockchain>,
    
    /// All uncorrupted chains
    chains: crate::RwLock<HashMap<String, UncorruptedChain>>,
    
    /// History of uncorrupted chain states
    chain_history: crate::RwLock<HashMap<String, Vec<Vec<Block>>>>,
    
    /// Currently selected main chain
    current_chain: crate::RwLock<Option<String>>,
    
    /// Corruption detection interval
    corruption_check_interval: Duration,
    
    /// Last corruption check time
    last_corruption_check: AsyncMutex<Instant>,
    
    /// TEE Manager for attestation verification
    tee_manager: Option<Arc<TEEManager>>,
    
    /// Background service
    background_service: AsyncMutex<Option<PoUBackgroundService>>,
    
    /// Running state
    running: std::sync::atomic::AtomicBool,
}

impl ProofOfUncorruption {
    /// Creates a new ProofOfUncorruption instance
    pub fn new(
        config: Arc<AevorConfig>,
        blockchain: Arc<Blockchain>,
    ) -> Result<Self> {
        let corruption_check_interval = Duration::from_millis(
            config.consensus.pou.corruption_check_interval_ms
        );
        
        Ok(Self {
            config,
            blockchain,
            chains: crate::RwLock::new(HashMap::new()),
            chain_history: crate::RwLock::new(HashMap::new()),
            current_chain: crate::RwLock::new(None),
            corruption_check_interval,
            last_corruption_check: AsyncMutex::new(Instant::now()),
            tee_manager: None,
            background_service: AsyncMutex::new(None),
            running: std::sync::atomic::AtomicBool::new(false),
        })
    }
    
    /// Creates a new ProofOfUncorruption instance with a TEE manager
    pub fn with_tee_manager(
        config: Arc<AevorConfig>,
        blockchain: Arc<Blockchain>,
        tee_manager: Arc<TEEManager>,
    ) -> Result<Self> {
        let mut pou = Self::new(config, blockchain)?;
        pou.tee_manager = Some(tee_manager);
        Ok(pou)
    }
    
    /// Starts the ProofOfUncorruption service
    pub async fn start(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        
        // Initialize the uncorrupted chains
        self.initialize_chains().await?;
        
        // Start the background service
        let mut service = PoUBackgroundService::new(Arc::new(self.clone()));
        service.start().await?;
        
        let mut background_service = self.background_service.lock().await;
        *background_service = Some(service);
        
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        
        Ok(())
    }
    
    /// Stops the ProofOfUncorruption service
    pub async fn stop(&self) -> Result<()> {
        if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        
        // Stop the background service
        let mut background_service = self.background_service.lock().await;
        if let Some(service) = background_service.take() {
            service.shutdown().await?;
        }
        
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        
        Ok(())
    }
    
    /// Initializes the uncorrupted chains from the blockchain
    async fn initialize_chains(&self) -> Result<()> {
        // Get the genesis block
        let genesis_hash = self.blockchain.get_genesis_hash()?;
        let genesis_block = self.blockchain.get_block(&genesis_hash)?;
        
        // Create the main chain
        let chain = UncorruptedChain::new(genesis_block.clone());
        let chain_id = chain.id.clone();
        
        // Add all blocks from the blockchain
        let latest_height = self.blockchain.get_latest_height()?;
        
        for height in 1..=latest_height {
            let blocks = self.blockchain.get_blocks_by_height(height)?;
            
            for block in blocks {
                // Check if the block is valid and uncorrupted
                if block.status() == BlockStatus::Accepted ||
                    block.status() == BlockStatus::Finalized ||
                    block.status() == BlockStatus::Uncorrupted {
                    // Try to add to the chain
                    if let Err(e) = chain.add_block(block.clone()) {
                        // If it doesn't fit in the main chain, create a new parallel chain
                        tracing::debug!("Block doesn't fit in main chain, creating parallel chain: {}", e);
                        
                        // Find a parent block that exists in the chain
                        for parent_hash in block.previous_hashes() {
                            if let Some(parent_block) = self.blockchain.get_block(parent_hash) {
                                // Create a new chain with this parent as genesis
                                let parallel_chain_id = self.create_parallel_chain(parent_block.clone(), block.clone()).await?;
                                tracing::info!("Created parallel chain {} for block {}", 
                                    parallel_chain_id, hex::encode(&block.hash()));
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Store the chain
        let mut chains = self.chains.write();
        chains.insert(chain_id.clone(), chain);
        
        // Set as current chain
        let mut current_chain = self.current_chain.write();
        *current_chain = Some(chain_id);
        
        Ok(())
    }
    
    /// Creates a new uncorrupted chain
    pub async fn create_chain(&self, genesis_block: Block) -> Result<String> {
        let chain = UncorruptedChain::new(genesis_block);
        let chain_id = chain.id.clone();
        
        // Store the chain
        let mut chains = self.chains.write();
        chains.insert(chain_id.clone(), chain);
        
        Ok(chain_id)
    }
    
    /// Creates a parallel chain from a parent block
    async fn create_parallel_chain(&self, parent_block: Block, initial_block: Block) -> Result<String> {
        // Create a new chain with the parent block as genesis
        let chain_id = self.create_chain(parent_block).await?;
        
        // Add the initial block
        self.add_block(&chain_id, initial_block).await?;
        
        Ok(chain_id)
    }
    
    /// Adds a block to an uncorrupted chain
    pub async fn add_block(&self, chain_id: &str, block: Block) -> Result<()> {
        let mut chains = self.chains.write();
        
        let chain = chains.get_mut(chain_id)
            .ok_or_else(|| AevorError::consensus(format!("Chain {} not found", chain_id)))?;
        
        chain.add_block(block)
    }
    
    /// Verify the TEE attestation for a block
    pub async fn verify_attestation(&self, block: &Block) -> Result<bool> {
        if let Some(tee_manager) = &self.tee_manager {
            if let Some(attestation) = block.uncorruption_data().tee_attestation() {
                return tee_manager.verify_attestation(attestation).await;
            }
        }
        
        // If no TEE manager or no attestation, return true if the block has enough validator confirmations
        Ok(block.has_required_confirmations(self.config.consensus.validation_threshold as usize))
    }
    
    /// Verifies a block's uncorruption proofs
    pub async fn verify_block(&self, block: &Block) -> Result<bool> {
        // Verify TEE attestation if available
        let attestation_valid = self.verify_attestation(block).await?;
        
        // Check if the block has enough validator confirmations
        let has_confirmations = block.has_required_confirmations(self.config.consensus.validation_threshold as usize);
        
        // Verify uncorruption proof
        let has_valid_proof = block.uncorruption_data().verify_proof();
        
        // For a block to be uncorrupted, it must have:
        // 1. Valid TEE attestation OR enough validator confirmations
        // 2. Valid uncorruption proof
        Ok((attestation_valid || has_confirmations) && has_valid_proof)
    }
    
    /// Detects corruption in the chains
    pub async fn detect_corruption(&self) -> Result<bool> {
        // Update the last check time
        let mut last_check = self.last_corruption_check.lock().await;
        *last_check = Instant::now();
        
        let chains = self.chains.read();
        let mut corruption_detected = false;
        
        for (chain_id, chain) in chains.iter() {
            if !chain.is_chain_valid() {
                tracing::warn!("Corruption detected in chain {}", chain_id);
                corruption_detected = true;
                
                // Take a snapshot of the chain state before recovery
                let mut chain_history = self.chain_history.write();
                let history = chain_history.entry(chain_id.clone()).or_insert_with(Vec::new);
                history.push(chain.get_all_blocks().into_iter().cloned().collect());
                
                // In a real implementation, this would trigger recovery procedures
                // For now, we'll just log the corruption
            }
        }
        
        // If corruption was detected, trigger recovery
        if corruption_detected {
            self.recover_uncorrupted_chain().await?;
        }
        
        Ok(corruption_detected)
    }
    
    /// Monitors parallel chains for potential merging
    pub async fn monitor_parallel_chains(&self) -> Result<()> {
        let chains = self.chains.read();
        if chains.len() <= 1 {
            return Ok(());
        }
        
        // Check for potential chain merges
        let mut chain_pairs = Vec::new();
        
        for (id1, chain1) in chains.iter() {
            for (id2, chain2) in chains.iter() {
                if id1 == id2 {
                    continue;
                }
                
                // Check if chains can be merged
                if self.can_merge_chains(chain1, chain2) {
                    chain_pairs.push((id1.clone(), id2.clone()));
                }
            }
        }
        
        // Release the read lock before proceeding with merges
        drop(chains);
        
        // Merge the identified chains
        for (id1, id2) in chain_pairs {
            tracing::info!("Merging chains {} and {}", id1, id2);
            self.merge_chains(&id1, &id2).await?;
        }
        
        Ok(())
    }
    
    /// Checks if two chains can be merged
    fn can_merge_chains(&self, chain1: &UncorruptedChain, chain2: &UncorruptedChain) -> bool {
        // Check if the chains share any blocks
        for (hash, _) in &chain1.blocks {
            if chain2.blocks.contains_key(hash) {
                return true;
            }
        }
        
        // Check if any block in chain1 references a block in chain2 or vice versa
        for (_, block1) in &chain1.blocks {
            for parent_hash in block1.previous_hashes() {
                if chain2.blocks.contains_key(parent_hash) {
                    return true;
                }
            }
        }
        
        for (_, block2) in &chain2.blocks {
            for parent_hash in block2.previous_hashes() {
                if chain1.blocks.contains_key(parent_hash) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Merges two chains
    async fn merge_chains(&self, chain_id1: &str, chain_id2: &str) -> Result<String> {
        let mut chains = self.chains.write();
        
        // Get the chains
        let chain1 = chains.get(chain_id1).cloned()
            .ok_or_else(|| AevorError::consensus(format!("Chain {} not found", chain_id1)))?;
        
        let chain2 = chains.get(chain_id2).cloned()
            .ok_or_else(|| AevorError::consensus(format!("Chain {} not found", chain_id2)))?;
        
        // Create a new merged chain with the earlier genesis block
        let genesis_block = if chain1.creation_time <= chain2.creation_time {
            self.blockchain.get_block(&chain1.genesis_block_hash)?
        } else {
            self.blockchain.get_block(&chain2.genesis_block_hash)?
        };
        
        let merged_chain = UncorruptedChain::new(genesis_block);
        let merged_chain_id = merged_chain.id.clone();
        
        // Add all blocks from both chains
        let mut merged_chain = merged_chain;
        
        // Add blocks from chain1
        for (_, block) in &chain1.blocks {
            // Skip genesis block
            if block.height() > 0 {
                if let Err(e) = merged_chain.add_block(block.clone()) {
                    tracing::debug!("Failed to add block from chain1 to merged chain: {}", e);
                }
            }
        }
        
        // Add blocks from chain2
        for (_, block) in &chain2.blocks {
            // Skip genesis block
            if block.height() > 0 {
                if let Err(e) = merged_chain.add_block(block.clone()) {
                    tracing::debug!("Failed to add block from chain2 to merged chain: {}", e);
                }
            }
        }
        
        // Add validator confirmations from both chains
        for (validator_id, signature) in &chain1.validator_confirmations {
            merged_chain.add_validator_confirmation(validator_id.clone(), signature.clone());
        }
        
        for (validator_id, signature) in &chain2.validator_confirmations {
            if !merged_chain.is_confirmed_by(validator_id) {
                merged_chain.add_validator_confirmation(validator_id.clone(), signature.clone());
            }
        }
        
        // Store the merged chain
        chains.insert(merged_chain_id.clone(), merged_chain);
        
        // If either of the merged chains was the current chain, set the merged chain as current
        let current_chain_id = self.current_chain.read().clone();
        if let Some(current_id) = current_chain_id {
            if current_id == *chain_id1 || current_id == *chain_id2 {
                let mut current_chain = self.current_chain.write();
                *current_chain = Some(merged_chain_id.clone());
            }
        }
        
        // Remove the original chains
        chains.remove(chain_id1);
        chains.remove(chain_id2);
        
        Ok(merged_chain_id)
    }
    
    /// Recovers to the longest uncorrupted chain
    pub async fn recover_uncorrupted_chain(&self) -> Result<()> {
        let chains = self.chains.read();
        
        let mut best_chain_id = None;
        let mut best_chain_length = 0;
        let mut best_chain_confidence = 0;
        
        // Find the chain with the highest confidence and length
        for (chain_id, chain) in chains.iter() {
            if chain.is_chain_valid() {
                let chain_length = chain.latest_height as usize;
                let chain_confidence = chain.uncorruption_confidence() as usize;
                
                // Prioritize confidence, then length
                let score = chain_confidence * 1000 + chain_length;
                let best_score = best_chain_confidence * 1000 + best_chain_length;
                
                if score > best_score {
                    best_chain_id = Some(chain_id.clone());
                    best_chain_length = chain_length;
                    best_chain_confidence = chain_confidence;
                }
            }
        }
        
        // Release the read lock
        drop(chains);
        
        // Set the best chain as current
        if let Some(chain_id) = best_chain_id {
            let mut current_chain = self.current_chain.write();
            *current_chain = Some(chain_id.clone());
            
            tracing::info!("Recovered to uncorrupted chain {} with length {} and confidence {}",
                chain_id, best_chain_length, best_chain_confidence);
        } else {
            tracing::warn!("No valid uncorrupted chains found during recovery");
        }
        
        Ok(())
    }
    
    /// Verifies TEE attestations for all blocks
    pub async fn verify_tee_attestations(&self) -> Result<()> {
        if self.tee_manager.is_none() {
            return Ok(());
        }
        
        let chains = self.chains.read();
        
        for chain in chains.values() {
            for block in chain.get_all_blocks() {
                if block.uncorruption_data().has_tee_attestation() {
                    let attestation_valid = self.verify_attestation(block).await?;
                    
                    if !attestation_valid {
                        tracing::warn!("Invalid TEE attestation for block {}",
                            hex::encode(&block.hash()));
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Gets the current chain ID
    pub async fn get_current_chain(&self) -> Option<String> {
        self.current_chain.read().clone()
    }
    
    /// Sets the current chain
    pub async fn set_current_chain(&self, chain_id: &str) -> Result<()> {
        let chains = self.chains.read();
        
        if !chains.contains_key(chain_id) {
            return Err(AevorError::consensus(format!("Chain {} not found", chain_id)));
        }
        
        drop(chains);
        
        let mut current_chain = self.current_chain.write();
        *current_chain = Some(chain_id.to_string());
        
        Ok(())
    }
    
    /// Gets all chains
    pub async fn get_all_chains(&self) -> Vec<UncorruptedChain> {
        let chains = self.chains.read();
        chains.values().cloned().collect()
    }
    
    /// Gets a specific chain by ID
    pub async fn get_chain(&self, chain_id: &str) -> Option<UncorruptedChain> {
        let chains = self.chains.read();
        chains.get(chain_id).cloned()
    }
    
    /// Gets the uncorrupted frontier (hashes of the latest uncorrupted blocks)
    pub async fn get_uncorrupted_frontier(&self) -> Result<Vec<Vec<u8>>> {
        let current_chain_id = self.current_chain.read().clone();
        
        if let Some(chain_id) = current_chain_id {
            let chains = self.chains.read();
            
            if let Some(chain) = chains.get(&chain_id) {
                let mut frontier = Vec::new();
                
                // For now, just use the latest block hash
                frontier.push(chain.latest_block_hash.clone());
                
                return Ok(frontier);
            }
        }
        
        Err(AevorError::consensus("No current uncorrupted chain"))
    }
    
    /// Adds an uncorruption proof to a block
    pub async fn add_uncorruption_proof(&self, block_hash: &[u8], proof: Vec<u8>) -> Result<()> {
        let block = self.blockchain.get_block(block_hash)?;
        
        // Update the block's uncorruption data
        let mut updated_block = block.clone();
        updated_block.uncorruption_data_mut().set_uncorruption_proof(proof);
        
        // Update the block in the blockchain
        self.blockchain.update_block(updated_block.clone())?;
        
        // Update the block in all chains that contain it
        let mut chains = self.chains.write();
        
        for chain in chains.values_mut() {
            if let Some(block) = chain.get_block(block_hash) {
                chain.add_block(updated_block.clone())?;
            }
        }
        
        Ok(())
    }
    
    /// Marks a block as uncorrupted
    pub async fn mark_as_uncorrupted(&self, block_hash: &[u8]) -> Result<()> {
        let mut block = self.blockchain.get_block(block_hash)?;
        
        // Update the block status
        block.set_status(BlockStatus::Uncorrupted);
        
        // Update the block in the blockchain
        self.blockchain.update_block(block.clone())?;
        
        // Update the block in all chains that contain it
        let mut chains = self.chains.write();
        
        for chain in chains.values_mut() {
            if let Some(_) = chain.get_block(block_hash) {
                chain.add_block(block.clone())?;
            }
        }
        
        Ok(())
    }
    
    /// Checks if a block is marked as uncorrupted
    pub async fn is_block_uncorrupted(&self, block_hash: &[u8]) -> Result<bool> {
        let block = self.blockchain.get_block(block_hash)?;
        
        Ok(block.status() == BlockStatus::Uncorrupted)
    }
    
    /// Gets all uncorrupted blocks
    pub async fn get_uncorrupted_blocks(&self) -> Result<Vec<Block>> {
        let current_chain_id = self.current_chain.read().clone();
        
        if let Some(chain_id) = current_chain_id {
            let chains = self.chains.read();
            
            if let Some(chain) = chains.get(&chain_id) {
                let mut blocks = Vec::new();
                
                for block in chain.get_all_blocks() {
                    if block.status() == BlockStatus::Uncorrupted || 
                       chain.verify_block_uncorruption(block) {
                        blocks.push(block.clone());
                    }
                }
                
                return Ok(blocks);
            }
        }
        
        Err(AevorError::consensus("No current uncorrupted chain"))
    }
    
    /// Adds a validator confirmation to a block
    pub async fn add_validator_confirmation(&self, block_hash: &[u8], validator_id: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        let mut block = self.blockchain.get_block(block_hash)?;
        
        // Add the confirmation to the block
        block.add_validator_confirmation(validator_id.clone(), signature.clone());
        
        // Update the block in the blockchain
        self.blockchain.update_block(block.clone())?;
        
        // Update the block in all chains that contain it
        let mut chains = self.chains.write();
        
        for chain in chains.values_mut() {
            if let Some(_) = chain.get_block(block_hash) {
                chain.add_block(block.clone())?;
                
                // Also add the confirmation to the chain itself
                chain.add_validator_confirmation(validator_id.clone(), signature.clone());
            }
        }
        
        Ok(())
    }
    
    /// Creates a parallel chain reference for a block
    pub fn create_parallel_reference(&self, block_hash: &[u8], parallel_chain_id: &str) -> Result<ParallelChainReference> {
        let chains = self.chains.read();
        
        let chain = chains.get(parallel_chain_id)
            .ok_or_else(|| AevorError::consensus(format!("Chain {} not found", parallel_chain_id)))?;
        
        let reference = ParallelChainReference::new(
            parallel_chain_id.as_bytes().to_vec(),
            chain.latest_block_hash.clone(),
            chain.latest_height,
        );
        
        Ok(reference)
    }
}
