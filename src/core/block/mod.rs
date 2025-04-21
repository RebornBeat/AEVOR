use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::core::transaction::Transaction;
use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::crypto::signature::{Signature, SignatureAlgorithm};
use crate::error::{AevorError, Result};

mod header;
mod status;
mod reference;
mod uncorruption;

pub use header::BlockHeader;
pub use status::BlockStatus;
pub use reference::ParallelChainReference;
pub use uncorruption::ProofOfUncorruptionData;

/// Represents a block in the Aevor blockchain
///
/// Blocks in Aevor are organized in a macro-DAG structure, where each block
/// can reference multiple parent blocks. This enables concurrent block production
/// without leader bottlenecks and allows for natural fork resolution.
#[derive(Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header containing metadata
    header: BlockHeader,
    
    /// List of transactions included in the block
    transactions: Vec<Transaction>,
    
    /// Size of the block in bytes
    #[serde(skip)]
    size: Option<usize>,
    
    /// Hash of the entire block
    #[serde(skip)]
    hash: Option<Vec<u8>>,
    
    /// Block execution status
    status: BlockStatus,
    
    /// Reference height (for topological ordering)
    reference_height: u64,
    
    /// Additional references to parallel chains
    parallel_references: Vec<ParallelChainReference>,
    
    /// Validator that produced this block
    validator: Vec<u8>,
    
    /// Validator signature
    validator_signature: Option<Signature>,
    
    /// Uncorruption data for Proof of Uncorruption consensus
    uncorruption_data: ProofOfUncorruptionData,
    
    /// Block creation timestamp
    timestamp: u64,
    
    /// Block execution timestamp
    executed_at: Option<u64>,
    
    /// Total gas used by all transactions in the block
    gas_used: Option<u64>,
    
    /// Block metadata (arbitrary key-value pairs)
    metadata: HashMap<String, Vec<u8>>,
}

impl Block {
    /// Creates a new block with the given header and transactions
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        
        Self {
            header,
            transactions,
            size: None,
            hash: None,
            status: BlockStatus::Pending,
            reference_height: 0,
            parallel_references: Vec::new(),
            validator: Vec::new(),
            validator_signature: None,
            uncorruption_data: ProofOfUncorruptionData::new(),
            timestamp,
            executed_at: None,
            gas_used: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Gets the block hash
    pub fn hash(&self) -> Vec<u8> {
        // If we have a cached hash, return it
        if let Some(ref hash) = self.hash {
            return hash.clone();
        }
        
        // Otherwise, calculate the hash
        self.hash_with_algorithm(HashAlgorithm::SHA256).value
    }
    
    /// Updates the cached hash
    pub fn update_hash(&mut self) {
        let hash = self.hash();
        self.hash = Some(hash);
    }
    
    /// Gets the block header
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    
    /// Gets a mutable reference to the block header
    pub fn header_mut(&mut self) -> &mut BlockHeader {
        &mut self.header
    }
    
    /// Gets the transactions in the block
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
    
    /// Gets a mutable reference to the transactions
    pub fn transactions_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.transactions
    }
    
    /// Gets the number of transactions in the block
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
    
    /// Gets the block size in bytes
    pub fn size(&self) -> usize {
        if let Some(size) = self.size {
            size
        } else {
            self.calculate_size()
        }
    }
    
    /// Calculates the size of the block in bytes
    pub fn calculate_size(&self) -> usize {
        let serialized = bincode::serialize(self).unwrap_or_default();
        serialized.len()
    }
    
    /// Updates the cached size
    pub fn update_size(&mut self) {
        let size = self.calculate_size();
        self.size = Some(size);
    }
    
    /// Gets the block status
    pub fn status(&self) -> BlockStatus {
        self.status
    }
    
    /// Sets the block status
    pub fn set_status(&mut self, status: BlockStatus) {
        self.status = status;
    }
    
    /// Gets the reference height (for topological ordering)
    pub fn reference_height(&self) -> u64 {
        self.reference_height
    }
    
    /// Sets the reference height
    pub fn set_reference_height(&mut self, height: u64) {
        self.reference_height = height;
    }
    
    /// Gets the parallel chain references
    pub fn parallel_references(&self) -> &[ParallelChainReference] {
        &self.parallel_references
    }
    
    /// Adds a parallel chain reference
    pub fn add_parallel_reference(&mut self, reference: ParallelChainReference) {
        self.parallel_references.push(reference);
    }
    
    /// Gets the validator that produced this block
    pub fn validator(&self) -> &[u8] {
        &self.validator
    }
    
    /// Sets the validator
    pub fn set_validator(&mut self, validator: Vec<u8>) {
        self.validator = validator;
    }
    
    /// Gets the validator signature
    pub fn validator_signature(&self) -> Option<&Signature> {
        self.validator_signature.as_ref()
    }
    
    /// Signs the block with the validator's private key
    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        // Get the block hash
        let hash = self.hash();
        
        // Sign the hash
        let signature = Signature::sign(SignatureAlgorithm::ED25519, private_key, &hash)
            .map_err(|e| AevorError::crypto("Signing failed".into(), e.to_string(), None))?;
        
        self.validator_signature = Some(signature);
        Ok(())
    }
    
    /// Verifies the validator signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool> {
        // Check if the block is signed
        let signature = match &self.validator_signature {
            Some(sig) => sig,
            None => return Ok(false),
        };
        
        // Get the block hash
        let hash = self.hash();
        
        // Verify the signature
        signature.verify(public_key, &hash)
            .map_err(|e| AevorError::crypto("Signature verification failed".into(), e.to_string(), None))
    }
    
    /// Gets the uncorruption data
    pub fn uncorruption_data(&self) -> &ProofOfUncorruptionData {
        &self.uncorruption_data
    }
    
    /// Gets a mutable reference to the uncorruption data
    pub fn uncorruption_data_mut(&mut self) -> &mut ProofOfUncorruptionData {
        &mut self.uncorruption_data
    }
    
    /// Gets the block creation timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    
    /// Gets the block execution timestamp (if executed)
    pub fn executed_at(&self) -> Option<u64> {
        self.executed_at
    }
    
    /// Sets the block execution timestamp
    pub fn set_executed_at(&mut self, timestamp: u64) {
        self.executed_at = Some(timestamp);
    }
    
    /// Gets the total gas used by all transactions in the block
    pub fn gas_used(&self) -> Option<u64> {
        self.gas_used
    }
    
    /// Sets the total gas used
    pub fn set_gas_used(&mut self, gas: u64) {
        self.gas_used = Some(gas);
    }
    
    /// Gets the block metadata
    pub fn metadata(&self) -> &HashMap<String, Vec<u8>> {
        &self.metadata
    }
    
    /// Gets a specific metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }
    
    /// Adds metadata to the block
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
    }
    
    /// Gets the block height
    pub fn height(&self) -> u64 {
        self.header.height()
    }
    
    /// Gets the previous block hashes (parent blocks)
    pub fn previous_hashes(&self) -> &[Vec<u8>] {
        self.header.previous_hashes()
    }
    
    /// Adds a validator confirmation for the block's uncorruption
    pub fn add_validator_confirmation(&mut self, validator_id: Vec<u8>, signature: Vec<u8>) {
        self.uncorruption_data.add_validator_confirmation(validator_id, signature);
    }
    
    /// Gets the number of validator confirmations
    pub fn confirmation_count(&self) -> usize {
        self.uncorruption_data.confirmation_count()
    }
    
    /// Checks if the block has reached the required number of confirmations
    pub fn has_required_confirmations(&self, threshold: usize) -> bool {
        self.confirmation_count() >= threshold
    }
    
    /// Checks if this block is a direct child of the given parent block
    pub fn is_child_of(&self, parent_hash: &[u8]) -> bool {
        self.header.previous_hashes().iter().any(|hash| hash == parent_hash)
    }
    
    /// Checks if this block has multiple parents
    pub fn has_multiple_parents(&self) -> bool {
        self.header.previous_hashes().len() > 1
    }
    
    /// Gets the number of parent blocks
    pub fn parent_count(&self) -> usize {
        self.header.previous_hashes().len()
    }
    
    /// Adds a transaction to the block
    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push(transaction);
        self.size = None;  // Invalidate size cache
        self.hash = None;  // Invalidate hash cache
    }
    
    /// Checks if the block contains a specific transaction
    pub fn contains_transaction(&self, tx_hash: &[u8]) -> bool {
        self.transactions.iter().any(|tx| tx.hash() == tx_hash)
    }
    
    /// Gets a transaction by its hash
    pub fn get_transaction(&self, tx_hash: &[u8]) -> Option<&Transaction> {
        self.transactions.iter().find(|tx| tx.hash() == tx_hash)
    }
    
    /// Gets a mutable reference to a transaction by its hash
    pub fn get_transaction_mut(&mut self, tx_hash: &[u8]) -> Option<&mut Transaction> {
        self.transactions.iter_mut().find(|tx| tx.hash() == tx_hash)
    }
    
    /// Validates the basic properties of the block
    pub fn validate_basic(&self) -> Result<()> {
        // Validate header
        self.header.validate_basic()?;
        
        // Validate reference height
        if self.reference_height == 0 && self.height() > 0 {
            return Err(AevorError::validation("Reference height must be greater than 0 for non-genesis blocks"));
        }
        
        // Validate transactions
        if self.transactions.is_empty() {
            return Err(AevorError::validation("Block contains no transactions"));
        }
        
        for tx in &self.transactions {
            tx.validate_basic()?;
        }
        
        // Validate validator
        if self.validator.is_empty() {
            return Err(AevorError::validation("Validator is empty"));
        }
        
        Ok(())
    }
    
    /// Serializes the block to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize block: {}", e)))
    }
    
    /// Deserializes a block from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize block: {}", e)))
    }
}

impl Hashable for Block {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
        let mut hasher = CryptoHash::new_hasher(algorithm);
        
        // Hash header
        hasher.update(&self.header.hash_with_algorithm(algorithm).value);
        
        // Hash transaction hashes
        for tx in &self.transactions {
            hasher.update(&tx.hash());
        }
        
        // Hash reference height
        hasher.update(&self.reference_height.to_le_bytes());
        
        // Hash parallel references
        for reference in &self.parallel_references {
            hasher.update(&reference.chain_id);
            hasher.update(&reference.block_hash);
        }
        
        // Hash validator
        hasher.update(&self.validator);
        
        // Hash timestamp
        hasher.update(&self.timestamp.to_le_bytes());
        
        CryptoHash::new(algorithm, hasher.finalize())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = self.hash();
        
        f.debug_struct("Block")
            .field("hash", &hex::encode(&hash))
            .field("height", &self.height())
            .field("status", &self.status)
            .field("reference_height", &self.reference_height)
            .field("parent_count", &self.parent_count())
            .field("transaction_count", &self.transaction_count())
            .field("validator", &hex::encode(&self.validator))
            .field("timestamp", &self.timestamp)
            .field("confirmation_count", &self.confirmation_count())
            .field("size", &self.size())
            .finish()
    }
}

/// Builder for creating blocks
pub struct BlockBuilder {
    header_builder: header::BlockHeaderBuilder,
    transactions: Vec<Transaction>,
    reference_height: u64,
    parallel_references: Vec<ParallelChainReference>,
    validator: Option<Vec<u8>>,
    metadata: HashMap<String, Vec<u8>>,
}

impl BlockBuilder {
    /// Creates a new block builder
    pub fn new() -> Self {
        Self {
            header_builder: header::BlockHeaderBuilder::new(),
            transactions: Vec::new(),
            reference_height: 0,
            parallel_references: Vec::new(),
            validator: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Sets the block height
    pub fn height(mut self, height: u64) -> Self {
        self.header_builder = self.header_builder.height(height);
        self
    }
    
    /// Sets the reference height
    pub fn reference_height(mut self, reference_height: u64) -> Self {
        self.reference_height = reference_height;
        self
    }
    
    /// Adds a previous block hash (parent reference)
    pub fn previous_hash(mut self, previous_hash: Vec<u8>) -> Self {
        self.header_builder = self.header_builder.previous_hash(previous_hash);
        self
    }
    
    /// Sets the previous block hashes (parent references)
    pub fn previous_hashes(mut self, previous_hashes: Vec<Vec<u8>>) -> Self {
        self.header_builder = self.header_builder.previous_hashes(previous_hashes);
        self
    }
    
    /// Sets the state root
    pub fn state_root(mut self, state_root: Vec<u8>) -> Self {
        self.header_builder = self.header_builder.state_root(state_root);
        self
    }
    
    /// Sets the transactions
    pub fn transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }
    
    /// Adds a transaction
    pub fn transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }
    
    /// Adds a parallel chain reference
    pub fn parallel_reference(mut self, reference: ParallelChainReference) -> Self {
        self.parallel_references.push(reference);
        self
    }
    
    /// Sets the validator
    pub fn validator(mut self, validator: Vec<u8>) -> Self {
        self.validator = Some(validator);
        self
    }
    
    /// Adds metadata
    pub fn metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Builds the block
    pub fn build(self) -> Result<Block> {
        // Check required fields
        let validator = self.validator.ok_or_else(|| AevorError::validation("Validator is required"))?;
        
        // Calculate the transactions root
        let mut tx_hashes = Vec::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            tx_hashes.push(tx.hash());
        }
        let transactions_root = crate::core::merkle::calculate_merkle_root(&tx_hashes);
        
        // Build the header
        let header = self.header_builder
            .transactions_root(transactions_root)
            .build()?;
        
        // Create the block
        let mut block = Block::new(header, self.transactions);
        
        // Set additional fields
        block.set_reference_height(self.reference_height);
        block.set_validator(validator);
        
        // Add parallel references
        for reference in self.parallel_references {
            block.add_parallel_reference(reference);
        }
        
        // Add metadata
        for (key, value) in self.metadata {
            block.add_metadata(key, value);
        }
        
        // Update the size and hash
        block.update_size();
        block.update_hash();
        
        Ok(block)
    }
}

/// Helper function to create a simple block
pub fn create_simple_block(height: u64, previous_hash: Vec<u8>, validator: Vec<u8>, transactions: Vec<Transaction>) -> Result<Block> {
    BlockBuilder::new()
        .height(height)
        .previous_hash(previous_hash)
        .reference_height(height)
        .validator(validator)
        .transactions(transactions)
        .build()
}

/// Helper function to create a genesis block
pub fn create_genesis_block(validator: Vec<u8>, transactions: Vec<Transaction>) -> Result<Block> {
    let empty_hash = vec![0; 32];
    
    BlockBuilder::new()
        .height(0)
        .previous_hash(empty_hash.clone())
        .reference_height(0)
        .validator(validator)
        .transactions(transactions)
        .metadata("genesis".to_string(), b"Genesis block".to_vec())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{Transaction, TransactionType, TransactionData};
    use crate::core::transaction::data::TransferData;
    
    // Helper to create a test transaction
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
    
    #[test]
    fn test_block_creation() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        let height = 1;
        let previous_hash = vec![0; 32];
        
        let block = create_simple_block(height, previous_hash.clone(), validator.clone(), vec![tx.clone()])
            .expect("Failed to create block");
        
        assert_eq!(block.height(), height);
        assert_eq!(block.previous_hashes()[0], previous_hash);
        assert_eq!(block.validator(), &validator);
        assert_eq!(block.transactions().len(), 1);
        assert_eq!(block.transactions()[0].hash(), tx.hash());
        assert!(block.is_child_of(&previous_hash));
    }
    
    #[test]
    fn test_block_hash() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        let height = 1;
        let previous_hash = vec![0; 32];
        
        let block1 = create_simple_block(height, previous_hash.clone(), validator.clone(), vec![tx.clone()])
            .expect("Failed to create block");
        
        let hash1 = block1.hash();
        
        // Same block should have the same hash
        let hash2 = block1.hash();
        assert_eq!(hash1, hash2);
        
        // Different block should have different hash
        let block2 = create_simple_block(height + 1, hash1.clone(), validator.clone(), vec![tx.clone()])
            .expect("Failed to create block");
        
        let hash3 = block2.hash();
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_block_builder() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        let height = 1;
        let previous_hash = vec![0; 32];
        let reference_height = 1;
        
        let block = BlockBuilder::new()
            .height(height)
            .previous_hash(previous_hash.clone())
            .reference_height(reference_height)
            .validator(validator.clone())
            .transaction(tx.clone())
            .metadata("test".to_string(), b"Test block".to_vec())
            .build()
            .expect("Failed to create block");
        
        assert_eq!(block.height(), height);
        assert_eq!(block.previous_hashes()[0], previous_hash);
        assert_eq!(block.reference_height(), reference_height);
        assert_eq!(block.validator(), &validator);
        assert_eq!(block.transactions().len(), 1);
        assert_eq!(block.transactions()[0].hash(), tx.hash());
        assert_eq!(block.get_metadata("test"), Some(&b"Test block".to_vec()));
    }
    
    #[test]
    fn test_block_with_multiple_parents() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        let height = 2;
        let parent1 = vec![1; 32];
        let parent2 = vec![2; 32];
        
        let block = BlockBuilder::new()
            .height(height)
            .previous_hashes(vec![parent1.clone(), parent2.clone()])
            .reference_height(height)
            .validator(validator.clone())
            .transaction(tx.clone())
            .build()
            .expect("Failed to create block");
        
        assert_eq!(block.height(), height);
        assert_eq!(block.parent_count(), 2);
        assert!(block.has_multiple_parents());
        assert!(block.is_child_of(&parent1));
        assert!(block.is_child_of(&parent2));
    }
    
    #[test]
    fn test_block_validation() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        let height = 1;
        let previous_hash = vec![0; 32];
        
        let block = create_simple_block(height, previous_hash.clone(), validator.clone(), vec![tx.clone()])
            .expect("Failed to create block");
        
        // Valid block
        assert!(block.validate_basic().is_ok());
        
        // Invalid block (no transactions)
        let invalid_block = BlockBuilder::new()
            .height(height)
            .previous_hash(previous_hash.clone())
            .reference_height(height)
            .validator(validator.clone())
            .build();
        
        assert!(invalid_block.is_err());
    }
    
    #[test]
    fn test_genesis_block() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        
        let genesis = create_genesis_block(validator.clone(), vec![tx.clone()])
            .expect("Failed to create genesis block");
        
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.reference_height(), 0);
        assert_eq!(genesis.validator(), &validator);
        assert_eq!(genesis.transactions().len(), 1);
        assert_eq!(genesis.transactions()[0].hash(), tx.hash());
        assert_eq!(genesis.get_metadata("genesis"), Some(&b"Genesis block".to_vec()));
    }
    
    #[test]
    fn test_block_serialization() {
        let tx = create_test_transaction();
        let validator = vec![1, 2, 3, 4];
        let height = 1;
        let previous_hash = vec![0; 32];
        
        let block = create_simple_block(height, previous_hash.clone(), validator.clone(), vec![tx.clone()])
            .expect("Failed to create block");
        
        // Serialize to bytes
        let bytes = block.to_bytes().expect("Failed to serialize block");
        
        // Deserialize back
        let deserialized = Block::from_bytes(&bytes).expect("Failed to deserialize block");
        
        // Check they match
        assert_eq!(deserialized.hash(), block.hash());
        assert_eq!(deserialized.height(), block.height());
        assert_eq!(deserialized.transactions().len(), block.transactions().len());
        assert_eq!(deserialized.transactions()[0].hash(), block.transactions()[0].hash());
    }
}
