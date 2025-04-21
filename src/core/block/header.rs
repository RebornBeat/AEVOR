use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::error::{AevorError, Result};

/// Block header containing metadata about a block
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version
    version: u32,
    
    /// Block height
    height: u64,
    
    /// Timestamp when the block was created
    timestamp: u64,
    
    /// References to parent blocks (multiple in a DAG structure)
    previous_hashes: Vec<Vec<u8>>,
    
    /// Merkle root of all transaction hashes in the block
    transactions_root: Vec<u8>,
    
    /// Merkle root of state after applying the block
    state_root: Vec<u8>,
    
    /// Uncorruption root hash
    uncorruption_root: Vec<u8>,
    
    /// Extra data (arbitrary bytes)
    extra_data: Vec<u8>,
}

impl BlockHeader {
    /// Creates a new block header
    pub fn new(
        version: u32,
        height: u64,
        timestamp: u64,
        previous_hashes: Vec<Vec<u8>>,
        transactions_root: Vec<u8>,
        state_root: Vec<u8>,
    ) -> Self {
        Self {
            version,
            height,
            timestamp,
            previous_hashes,
            transactions_root,
            state_root,
            uncorruption_root: Vec::new(),
            extra_data: Vec::new(),
        }
    }
    
    /// Gets the block version
    pub fn version(&self) -> u32 {
        self.version
    }
    
    /// Gets the block height
    pub fn height(&self) -> u64 {
        self.height
    }
    
    /// Gets the block timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    
    /// Gets the previous block hashes (parent blocks)
    pub fn previous_hashes(&self) -> &[Vec<u8>] {
        &self.previous_hashes
    }
    
    /// Gets the transactions root
    pub fn transactions_root(&self) -> &[u8] {
        &self.transactions_root
    }
    
    /// Gets the state root
    pub fn state_root(&self) -> &[u8] {
        &self.state_root
    }
    
    /// Gets the uncorruption root
    pub fn uncorruption_root(&self) -> &[u8] {
        &self.uncorruption_root
    }
    
    /// Sets the uncorruption root
    pub fn set_uncorruption_root(&mut self, root: Vec<u8>) {
        self.uncorruption_root = root;
    }
    
    /// Gets the extra data
    pub fn extra_data(&self) -> &[u8] {
        &self.extra_data
    }
    
    /// Sets the extra data
    pub fn set_extra_data(&mut self, data: Vec<u8>) {
        self.extra_data = data;
    }
    
    /// Gets the primary parent hash (for compatibility with linear chains)
    pub fn primary_parent_hash(&self) -> Option<&Vec<u8>> {
        self.previous_hashes.first()
    }
    
    /// Gets the number of parent blocks
    pub fn parent_count(&self) -> usize {
        self.previous_hashes.len()
    }
    
    /// Validates the basic properties of the header
    pub fn validate_basic(&self) -> Result<()> {
        // Check version
        if self.version == 0 {
            return Err(AevorError::validation("Block version cannot be zero"));
        }
        
        // Non-genesis blocks must have at least one parent
        if self.height > 0 && self.previous_hashes.is_empty() {
            return Err(AevorError::validation("Non-genesis block must have at least one parent"));
        }
        
        // Check transaction root
        if self.transactions_root.is_empty() {
            return Err(AevorError::validation("Transactions root is empty"));
        }
        
        // Check state root
        if self.state_root.is_empty() {
            return Err(AevorError::validation("State root is empty"));
        }
        
        Ok(())
    }
}

impl Hashable for BlockHeader {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
        let mut hasher = CryptoHash::new_hasher(algorithm);
        
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        
        // Hash all previous hashes
        for hash in &self.previous_hashes {
            hasher.update(hash);
        }
        
        hasher.update(&self.transactions_root);
        hasher.update(&self.state_root);
        hasher.update(&self.uncorruption_root);
        hasher.update(&self.extra_data);
        
        CryptoHash::new(algorithm, hasher.finalize())
    }
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockHeader")
            .field("version", &self.version)
            .field("height", &self.height)
            .field("timestamp", &self.timestamp)
            .field("previous_hashes", &self.previous_hashes.iter().map(hex::encode).collect::<Vec<_>>())
            .field("transactions_root", &hex::encode(&self.transactions_root))
            .field("state_root", &hex::encode(&self.state_root))
            .field("uncorruption_root", &hex::encode(&self.uncorruption_root))
            .field("extra_data", &hex::encode(&self.extra_data))
            .finish()
    }
}

/// Builder for creating block headers
pub struct BlockHeaderBuilder {
    version: u32,
    height: Option<u64>,
    timestamp: u64,
    previous_hashes: Vec<Vec<u8>>,
    transactions_root: Option<Vec<u8>>,
    state_root: Option<Vec<u8>>,
    uncorruption_root: Option<Vec<u8>>,
    extra_data: Option<Vec<u8>>,
}

impl BlockHeaderBuilder {
    /// Creates a new block header builder
    pub fn new() -> Self {
        Self {
            version: 1,
            height: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            previous_hashes: Vec::new(),
            transactions_root: None,
            state_root: None,
            uncorruption_root: None,
            extra_data: None,
        }
    }
    
    /// Sets the block version
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
    
    /// Sets the block height
    pub fn height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }
    
    /// Sets the block timestamp
    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
    
    /// Adds a previous block hash (parent reference)
    pub fn previous_hash(mut self, previous_hash: Vec<u8>) -> Self {
        self.previous_hashes.push(previous_hash);
        self
    }
    
    /// Sets the previous block hashes (parent references)
    pub fn previous_hashes(mut self, previous_hashes: Vec<Vec<u8>>) -> Self {
        self.previous_hashes = previous_hashes;
        self
    }
    
    /// Sets the transactions root
    pub fn transactions_root(mut self, transactions_root: Vec<u8>) -> Self {
        self.transactions_root = Some(transactions_root);
        self
    }
    
    /// Sets the state root
    pub fn state_root(mut self, state_root: Vec<u8>) -> Self {
        self.state_root = Some(state_root);
        self
    }
    
    /// Sets the uncorruption root
    pub fn uncorruption_root(mut self, uncorruption_root: Vec<u8>) -> Self {
        self.uncorruption_root = Some(uncorruption_root);
        self
    }
    
    /// Sets the extra data
    pub fn extra_data(mut self, extra_data: Vec<u8>) -> Self {
        self.extra_data = Some(extra_data);
        self
    }
    
    /// Builds the block header
    pub fn build(self) -> Result<BlockHeader> {
        // Check required fields
        let height = self.height.ok_or_else(|| AevorError::validation("Block height is required"))?;
        let transactions_root = self.transactions_root.ok_or_else(|| AevorError::validation("Transactions root is required"))?;
        let state_root = self.state_root.ok_or_else(|| AevorError::validation("State root is required"))?;
        
        // Create the header
        let mut header = BlockHeader::new(
            self.version,
            height,
            self.timestamp,
            self.previous_hashes,
            transactions_root,
            state_root,
        );
        
        // Set optional fields
        if let Some(uncorruption_root) = self.uncorruption_root {
            header.set_uncorruption_root(uncorruption_root);
        }
        
        if let Some(extra_data) = self.extra_data {
            header.set_extra_data(extra_data);
        }
        
        // Validate the header
        header.validate_basic()?;
        
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_block_header_creation() {
        let version = 1;
        let height = 1;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let previous_hash = vec![0; 32];
        let transactions_root = vec![1; 32];
        let state_root = vec![2; 32];
        
        let header = BlockHeader::new(
            version,
            height,
            timestamp,
            vec![previous_hash.clone()],
            transactions_root.clone(),
            state_root.clone(),
        );
        
        assert_eq!(header.version(), version);
        assert_eq!(header.height(), height);
        assert_eq!(header.timestamp(), timestamp);
        assert_eq!(header.previous_hashes().len(), 1);
        assert_eq!(header.previous_hashes()[0], previous_hash);
        assert_eq!(header.transactions_root(), &transactions_root);
        assert_eq!(header.state_root(), &state_root);
        assert_eq!(header.uncorruption_root(), &Vec::<u8>::new());
        assert_eq!(header.extra_data(), &Vec::<u8>::new());
    }
    
    #[test]
    fn test_block_header_builder() {
        let version = 1;
        let height = 1;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let previous_hash = vec![0; 32];
        let transactions_root = vec![1; 32];
        let state_root = vec![2; 32];
        let uncorruption_root = vec![3; 32];
        let extra_data = vec![4; 32];
        
        let header = BlockHeaderBuilder::new()
            .version(version)
            .height(height)
            .timestamp(timestamp)
            .previous_hash(previous_hash.clone())
            .transactions_root(transactions_root.clone())
            .state_root(state_root.clone())
            .uncorruption_root(uncorruption_root.clone())
            .extra_data(extra_data.clone())
            .build()
            .expect("Failed to build header");
        
        assert_eq!(header.version(), version);
        assert_eq!(header.height(), height);
        assert_eq!(header.timestamp(), timestamp);
        assert_eq!(header.previous_hashes().len(), 1);
        assert_eq!(header.previous_hashes()[0], previous_hash);
        assert_eq!(header.transactions_root(), &transactions_root);
        assert_eq!(header.state_root(), &state_root);
        assert_eq!(header.uncorruption_root(), &uncorruption_root);
        assert_eq!(header.extra_data(), &extra_data);
    }
    
    #[test]
    fn test_block_header_hash() {
        let header1 = BlockHeaderBuilder::new()
            .height(1)
            .previous_hash(vec![0; 32])
            .transactions_root(vec![1; 32])
            .state_root(vec![2; 32])
            .build()
            .expect("Failed to build header");
        
        let hash1 = header1.hash_with_algorithm(HashAlgorithm::SHA256);
        
        // Same header should have the same hash
        let hash2 = header1.hash_with_algorithm(HashAlgorithm::SHA256);
        assert_eq!(hash1.value, hash2.value);
        
        // Different header should have different hash
        let header2 = BlockHeaderBuilder::new()
            .height(2)
            .previous_hash(hash1.value.clone())
            .transactions_root(vec![1; 32])
            .state_root(vec![2; 32])
            .build()
            .expect("Failed to build header");
        
        let hash3 = header2.hash_with_algorithm(HashAlgorithm::SHA256);
        assert_ne!(hash1.value, hash3.value);
    }
    
    #[test]
    fn test_block_header_validation() {
        // Valid header
        let valid_header = BlockHeaderBuilder::new()
            .height(1)
            .previous_hash(vec![0; 32])
            .transactions_root(vec![1; 32])
            .state_root(vec![2; 32])
            .build();
        
        assert!(valid_header.is_ok());
        
        // Invalid header (missing previous hash for non-genesis block)
        let invalid_header = BlockHeaderBuilder::new()
            .height(1)
            .transactions_root(vec![1; 32])
            .state_root(vec![2; 32])
            .build();
        
        assert!(invalid_header.is_err());
        
        // Invalid header (missing transactions root)
        let invalid_header = BlockHeaderBuilder::new()
            .height(1)
            .previous_hash(vec![0; 32])
            .state_root(vec![2; 32])
            .build();
        
        assert!(invalid_header.is_err());
        
        // Invalid header (missing state root)
        let invalid_header = BlockHeaderBuilder::new()
            .height(1)
            .previous_hash(vec![0; 32])
            .transactions_root(vec![1; 32])
            .build();
        
        assert!(invalid_header.is_err());
    }
    
    #[test]
    fn test_header_with_multiple_parents() {
        let parent1 = vec![1; 32];
        let parent2 = vec![2; 32];
        
        let header = BlockHeaderBuilder::new()
            .height(2)
            .previous_hashes(vec![parent1.clone(), parent2.clone()])
            .transactions_root(vec![1; 32])
            .state_root(vec![2; 32])
            .build()
            .expect("Failed to build header");
        
        assert_eq!(header.parent_count(), 2);
        assert_eq!(header.primary_parent_hash(), Some(&parent1));
        assert_eq!(header.previous_hashes()[0], parent1);
        assert_eq!(header.previous_hashes()[1], parent2);
    }
}
