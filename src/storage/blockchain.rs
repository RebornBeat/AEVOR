use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::core::block::{Block, BlockStatus};
use crate::core::transaction::Transaction;
use crate::error::{AevorError, Result};
use crate::storage::database::{Database, Transaction as DBTransaction};

/// Column family names for blockchain data
const BLOCKS_CF: &str = "blocks";
const BLOCK_HEIGHTS_CF: &str = "block_heights";
const TRANSACTIONS_CF: &str = "transactions";
const TX_BLOCK_CF: &str = "tx_block";
const BLOCK_STATUS_CF: &str = "block_status";
const BLOCKCHAIN_META_CF: &str = "blockchain_meta";
const TRANSACTION_RESULTS_CF: &str = "transaction_results";

/// Blockchain metadata keys
const LATEST_HEIGHT_KEY: &str = "latest_height";
const LATEST_HASH_KEY: &str = "latest_hash";
const LATEST_UNCORRUPTED_HASH_KEY: &str = "latest_uncorrupted_hash";
const GENESIS_HASH_KEY: &str = "genesis_hash";

/// Store for blockchain data including blocks and transactions
pub struct BlockchainStore {
    /// Database instance
    db: Arc<dyn Database>,
}

/// Represents the result of a transaction execution
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionResult {
    /// Whether the transaction was successful
    pub success: bool,
    
    /// Amount of gas used by the transaction
    pub gas_used: u64,
    
    /// Error message, if any
    pub error: Option<String>,
    
    /// Block hash containing this transaction
    pub block_hash: Vec<u8>,
    
    /// Block height containing this transaction
    pub block_height: u64,
    
    /// Transaction index within the block
    pub transaction_index: u32,
    
    /// Timestamp of execution
    pub timestamp: u64,
    
    /// Objects created by this transaction
    pub created_objects: Vec<Vec<u8>>,
    
    /// Objects modified by this transaction
    pub modified_objects: Vec<Vec<u8>>,
    
    /// Objects deleted by this transaction
    pub deleted_objects: Vec<Vec<u8>>,
    
    /// Security level achieved
    pub security_level: u8,
}

impl BlockchainStore {
    /// Creates a new BlockchainStore
    pub fn new(db: Arc<dyn Database>) -> Result<Self> {
        // Ensure all required column families exist
        let required_cfs = [
            BLOCKS_CF,
            BLOCK_HEIGHTS_CF,
            TRANSACTIONS_CF,
            TX_BLOCK_CF,
            BLOCK_STATUS_CF,
            BLOCKCHAIN_META_CF,
            TRANSACTION_RESULTS_CF,
        ];
        
        for cf in &required_cfs {
            if !db.column_family_exists(cf) {
                db.create_column_family(cf)?;
            }
        }
        
        Ok(Self { db })
    }
    
    /// Initializes the blockchain store
    pub async fn initialize(&self) -> Result<()> {
        // This is called during storage startup
        // Nothing specific to do for now, but could be used for initialization tasks
        Ok(())
    }
    
    /// Shuts down the blockchain store
    pub async fn shutdown(&self) -> Result<()> {
        // This is called during storage shutdown
        // Nothing specific to do for now, but could be used for cleanup tasks
        Ok(())
    }
    
    /// Stores a block
    pub fn store_block(&self, block: &Block) -> Result<()> {
        let block_hash = block.hash();
        let height = block.height();
        
        // Create a database transaction
        let mut tx = self.db.transaction();
        
        // Serialize the block
        let block_data = bincode::serialize(block)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize block: {}", e)))?;
        
        // Store the block by hash
        tx.put(BLOCKS_CF, &block_hash, &block_data)?;
        
        // Store the block hash by height
        tx.put(BLOCK_HEIGHTS_CF, &height.to_be_bytes(), &block_hash)?;
        
        // Store the block status
        let status_bytes = bincode::serialize(&block.status())
            .map_err(|e| AevorError::serialization(format!("Failed to serialize block status: {}", e)))?;
        tx.put(BLOCK_STATUS_CF, &block_hash, &status_bytes)?;
        
        // Update latest height and hash if this is a new high block
        if let Ok(current_height) = self.get_latest_height() {
            if height > current_height {
                tx.put(BLOCKCHAIN_META_CF, LATEST_HEIGHT_KEY.as_bytes(), &height.to_be_bytes())?;
                tx.put(BLOCKCHAIN_META_CF, LATEST_HASH_KEY.as_bytes(), &block_hash)?;
            }
        } else {
            // First block (genesis)
            tx.put(BLOCKCHAIN_META_CF, LATEST_HEIGHT_KEY.as_bytes(), &height.to_be_bytes())?;
            tx.put(BLOCKCHAIN_META_CF, LATEST_HASH_KEY.as_bytes(), &block_hash)?;
            tx.put(BLOCKCHAIN_META_CF, GENESIS_HASH_KEY.as_bytes(), &block_hash)?;
        }
        
        // If this is an uncorrupted block, update the latest uncorrupted hash
        if block.status() == BlockStatus::Uncorrupted {
            tx.put(BLOCKCHAIN_META_CF, LATEST_UNCORRUPTED_HASH_KEY.as_bytes(), &block_hash)?;
        }
        
        // Store all transactions in the block
        for (index, transaction) in block.transactions().iter().enumerate() {
            self.store_transaction_in_tx(&mut tx, transaction, &block_hash, height, index as u32)?;
        }
        
        // Execute the database transaction
        self.db.execute_transaction(tx)?;
        
        Ok(())
    }
    
    /// Stores a transaction within a database transaction
    fn store_transaction_in_tx(
        &self,
        tx: &mut DBTransaction,
        transaction: &Transaction,
        block_hash: &[u8],
        block_height: u64,
        transaction_index: u32,
    ) -> Result<()> {
        let tx_hash = transaction.hash();
        
        // Serialize the transaction
        let tx_data = bincode::serialize(transaction)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize transaction: {}", e)))?;
        
        // Store the transaction by hash
        tx.put(TRANSACTIONS_CF, &tx_hash, &tx_data)?;
        
        // Store the block reference for this transaction
        let tx_block_info = bincode::serialize(&(block_hash.to_vec(), block_height, transaction_index))
            .map_err(|e| AevorError::serialization(format!("Failed to serialize tx block info: {}", e)))?;
        
        tx.put(TX_BLOCK_CF, &tx_hash, &tx_block_info)?;
        
        Ok(())
    }
    
    /// Stores a transaction
    pub fn store_transaction(&self, transaction: &Transaction) -> Result<()> {
        let tx_hash = transaction.hash();
        
        // Serialize the transaction
        let tx_data = bincode::serialize(transaction)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize transaction: {}", e)))?;
        
        // Store the transaction by hash
        self.db.put(TRANSACTIONS_CF, &tx_hash, &tx_data)?;
        
        Ok(())
    }
    
    /// Gets a block by hash
    pub fn get_block(&self, hash: &[u8]) -> Result<Block> {
        let block_data = self.db.get(BLOCKS_CF, hash)?
            .ok_or_else(|| AevorError::storage(format!("Block not found with hash: {}", hex::encode(hash))))?;
        
        let block: Block = bincode::deserialize(&block_data)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize block: {}", e)))?;
        
        Ok(block)
    }
    
    /// Gets a block by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let hash = self.db.get(BLOCK_HEIGHTS_CF, &height.to_be_bytes())?
            .ok_or_else(|| AevorError::storage(format!("Block not found at height: {}", height)))?;
        
        self.get_block(&hash)
    }
    
    /// Gets a transaction by hash
    pub fn get_transaction(&self, hash: &[u8]) -> Result<Transaction> {
        let tx_data = self.db.get(TRANSACTIONS_CF, hash)?
            .ok_or_else(|| AevorError::storage(format!("Transaction not found with hash: {}", hex::encode(hash))))?;
        
        let transaction: Transaction = bincode::deserialize(&tx_data)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize transaction: {}", e)))?;
        
        Ok(transaction)
    }
    
    /// Gets the block containing a transaction
    pub fn get_transaction_block(&self, tx_hash: &[u8]) -> Result<Block> {
        let tx_block_info = self.db.get(TX_BLOCK_CF, tx_hash)?
            .ok_or_else(|| AevorError::storage(format!("Block info not found for transaction: {}", hex::encode(tx_hash))))?;
        
        let (block_hash, _, _): (Vec<u8>, u64, u32) = bincode::deserialize(&tx_block_info)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize tx block info: {}", e)))?;
        
        self.get_block(&block_hash)
    }
    
    /// Gets transaction information (block hash, height, and index)
    pub fn get_transaction_info(&self, tx_hash: &[u8]) -> Result<(Vec<u8>, u64, u32)> {
        let tx_block_info = self.db.get(TX_BLOCK_CF, tx_hash)?
            .ok_or_else(|| AevorError::storage(format!("Block info not found for transaction: {}", hex::encode(tx_hash))))?;
        
        let info: (Vec<u8>, u64, u32) = bincode::deserialize(&tx_block_info)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize tx block info: {}", e)))?;
        
        Ok(info)
    }
    
    /// Gets the latest block height
    pub fn get_latest_height(&self) -> Result<u64> {
        let height_bytes = self.db.get(BLOCKCHAIN_META_CF, LATEST_HEIGHT_KEY.as_bytes())?
            .ok_or_else(|| AevorError::storage("Latest height not found".to_string()))?;
        
        if height_bytes.len() != 8 {
            return Err(AevorError::storage("Invalid height format".to_string()));
        }
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&height_bytes);
        Ok(u64::from_be_bytes(bytes))
    }
    
    /// Sets the latest block height
    pub fn set_latest_height(&self, height: u64) -> Result<()> {
        self.db.put(BLOCKCHAIN_META_CF, LATEST_HEIGHT_KEY.as_bytes(), &height.to_be_bytes())?;
        Ok(())
    }
    
    /// Gets the latest block hash
    pub fn get_latest_hash(&self) -> Result<Vec<u8>> {
        let hash = self.db.get(BLOCKCHAIN_META_CF, LATEST_HASH_KEY.as_bytes())?
            .ok_or_else(|| AevorError::storage("Latest hash not found".to_string()))?;
        
        Ok(hash)
    }
    
    /// Sets the latest block hash
    pub fn set_latest_hash(&self, hash: &[u8]) -> Result<()> {
        self.db.put(BLOCKCHAIN_META_CF, LATEST_HASH_KEY.as_bytes(), hash)?;
        Ok(())
    }
    
    /// Gets the latest uncorrupted block hash
    pub fn get_latest_uncorrupted_hash(&self) -> Result<Vec<u8>> {
        let hash = self.db.get(BLOCKCHAIN_META_CF, LATEST_UNCORRUPTED_HASH_KEY.as_bytes())?
            .ok_or_else(|| AevorError::storage("Latest uncorrupted hash not found".to_string()))?;
        
        Ok(hash)
    }
    
    /// Sets the latest uncorrupted block hash
    pub fn set_latest_uncorrupted_hash(&self, hash: &[u8]) -> Result<()> {
        self.db.put(BLOCKCHAIN_META_CF, LATEST_UNCORRUPTED_HASH_KEY.as_bytes(), hash)?;
        Ok(())
    }
    
    /// Gets the genesis block hash
    pub fn get_genesis_hash(&self) -> Result<Vec<u8>> {
        let hash = self.db.get(BLOCKCHAIN_META_CF, GENESIS_HASH_KEY.as_bytes())?
            .ok_or_else(|| AevorError::storage("Genesis hash not found".to_string()))?;
        
        Ok(hash)
    }
    
    /// Updates the block status
    pub fn update_block_status(&self, block_hash: &[u8], status: BlockStatus) -> Result<()> {
        // Get the current block
        let mut block = self.get_block(block_hash)?;
        
        // Update the status
        block.set_status(status);
        
        // Serialize the status
        let status_bytes = bincode::serialize(&status)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize block status: {}", e)))?;
        
        // Update the status in the database
        self.db.put(BLOCK_STATUS_CF, block_hash, &status_bytes)?;
        
        // If this is an uncorrupted block, update the latest uncorrupted hash
        if status == BlockStatus::Uncorrupted {
            self.set_latest_uncorrupted_hash(block_hash)?;
        }
        
        // Store the updated block
        self.store_block(&block)?;
        
        Ok(())
    }
    
    /// Checks if a block exists
    pub fn block_exists(&self, hash: &[u8]) -> Result<bool> {
        Ok(self.db.exists(BLOCKS_CF, hash)?)
    }
    
    /// Checks if a transaction exists
    pub fn transaction_exists(&self, hash: &[u8]) -> Result<bool> {
        Ok(self.db.exists(TRANSACTIONS_CF, hash)?)
    }
    
    /// Stores the result of a transaction execution
    pub fn store_transaction_result(&self, tx_hash: &[u8], result: &TransactionResult) -> Result<()> {
        let result_data = bincode::serialize(result)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize transaction result: {}", e)))?;
        
        self.db.put(TRANSACTION_RESULTS_CF, tx_hash, &result_data)?;
        
        Ok(())
    }
    
    /// Gets the result of a transaction execution
    pub fn get_transaction_result(&self, tx_hash: &[u8]) -> Result<Option<TransactionResult>> {
        let result_data = match self.db.get(TRANSACTION_RESULTS_CF, tx_hash)? {
            Some(data) => data,
            None => return Ok(None),
        };
        
        let result: TransactionResult = bincode::deserialize(&result_data)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize transaction result: {}", e)))?;
        
        Ok(Some(result))
    }
    
    /// Gets blocks within a height range
    pub fn get_blocks_in_range(&self, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        
        for height in start_height..=end_height {
            match self.get_block_by_height(height) {
                Ok(block) => blocks.push(block),
                Err(e) => {
                    if let AevorError::Storage(_) = e {
                        // Block not found at this height, skip it
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        
        Ok(blocks)
    }
    
    /// Gets the uncorrupted chain starting from a specific block hash
    pub fn get_uncorrupted_chain(&self, starting_hash: &[u8]) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        let mut current_hash = starting_hash.to_vec();
        
        // First, check if the starting block exists and is uncorrupted
        let start_block = self.get_block(&current_hash)?;
        if start_block.status() != BlockStatus::Uncorrupted {
            return Err(AevorError::storage("Starting block is not uncorrupted".to_string()));
        }
        
        blocks.push(start_block);
        
        // Traverse parents until we reach the genesis block or a non-uncorrupted block
        while !current_hash.is_empty() {
            let block = self.get_block(&current_hash)?;
            
            // Get the parent hashes
            let parent_hashes = block.previous_hashes();
            if parent_hashes.is_empty() {
                // Reached genesis block
                break;
            }
            
            // We'll follow the first parent that's uncorrupted
            let mut found_uncorrupted_parent = false;
            
            for parent_hash in parent_hashes {
                if let Ok(parent_block) = self.get_block(parent_hash) {
                    if parent_block.status() == BlockStatus::Uncorrupted {
                        blocks.push(parent_block);
                        current_hash = parent_hash.to_vec();
                        found_uncorrupted_parent = true;
                        break;
                    }
                }
            }
            
            if !found_uncorrupted_parent {
                // No uncorrupted parent found
                break;
            }
        }
        
        // Reverse the blocks to have them in ascending order
        blocks.reverse();
        
        Ok(blocks)
    }
    
    /// Prunes blocks below a certain height
    pub async fn prune_blocks_below(&self, height_threshold: u64) -> Result<usize> {
        let mut pruned_count = 0;
        
        // Skip pruning if we're at or below the threshold
        let latest_height = self.get_latest_height()?;
        if latest_height <= height_threshold {
            return Ok(0);
        }
        
        // Get all blocks to prune
        let blocks_to_prune = self.get_blocks_in_range(0, height_threshold - 1)?;
        
        // Create a database transaction
        let mut tx = self.db.transaction();
        
        // Keep track of finalized blocks to preserve
        let mut finalized_hashes = HashSet::new();
        
        // First pass to identify finalized blocks
        for block in &blocks_to_prune {
            if block.status() == BlockStatus::Finalized {
                finalized_hashes.insert(block.hash());
            }
        }
        
        // Second pass to prune non-finalized blocks
        for block in blocks_to_prune {
            let block_hash = block.hash();
            
            // Skip finalized blocks
            if finalized_hashes.contains(&block_hash) {
                continue;
            }
            
            // Remove block and related data
            tx.delete(BLOCKS_CF, &block_hash)?;
            tx.delete(BLOCK_STATUS_CF, &block_hash)?;
            tx.delete(BLOCK_HEIGHTS_CF, &block.height().to_be_bytes())?;
            
            // Remove all transactions in the block
            for transaction in block.transactions() {
                let tx_hash = transaction.hash();
                tx.delete(TRANSACTIONS_CF, &tx_hash)?;
                tx.delete(TX_BLOCK_CF, &tx_hash)?;
                tx.delete(TRANSACTION_RESULTS_CF, &tx_hash)?;
            }
            
            pruned_count += 1;
        }
        
        // Execute the database transaction
        self.db.execute_transaction(tx)?;
        
        Ok(pruned_count)
    }
    
    /// Checks the blockchain store integrity
    pub async fn check_integrity(&self) -> Result<bool> {
        // Check that the latest height and hash are consistent
        let latest_height = match self.get_latest_height() {
            Ok(height) => height,
            Err(_) => return Ok(false), // No latest height means integrity check fails
        };
        
        let latest_hash = match self.get_latest_hash() {
            Ok(hash) => hash,
            Err(_) => return Ok(false), // No latest hash means integrity check fails
        };
        
        // Check that the block at the latest height has the latest hash
        let height_hash = match self.db.get(BLOCK_HEIGHTS_CF, &latest_height.to_be_bytes())? {
            Some(hash) => hash,
            None => return Ok(false), // No block at latest height means integrity check fails
        };
        
        if height_hash != latest_hash {
            return Ok(false); // Latest height and hash are inconsistent
        }
        
        // Check that the latest block exists
        let latest_block = match self.get_block(&latest_hash) {
            Ok(block) => block,
            Err(_) => return Ok(false), // Latest block doesn't exist
        };
        
        // Check that the latest block's height matches the latest height
        if latest_block.height() != latest_height {
            return Ok(false); // Latest block height is inconsistent
        }
        
        // Check that the genesis hash exists and points to a real block
        let genesis_hash = match self.get_genesis_hash() {
            Ok(hash) => hash,
            Err(_) => return Ok(false), // No genesis hash means integrity check fails
        };
        
        match self.get_block(&genesis_hash) {
            Ok(block) => {
                if block.height() != 0 {
                    return Ok(false); // Genesis block height is not 0
                }
            },
            Err(_) => return Ok(false), // Genesis block doesn't exist
        };
        
        // We passed all integrity checks
        Ok(true)
    }
    
    /// Gets the database instance
    pub fn db(&self) -> Arc<dyn Database> {
        self.db.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::{Block, BlockBuilder, BlockHeader, BlockStatus};
    use crate::core::transaction::{Transaction, TransactionData, TransactionType};
    use crate::core::transaction::data::TransferData;
    use crate::storage::database::MemoryDatabase;
    
    /// Creates a test transaction
    fn create_test_transaction(nonce: u64) -> Transaction {
        let sender = vec![1, 2, 3, 4];
        let recipient = vec![5, 6, 7, 8];
        let amount = 100;
        
        let data = TransactionData::Transfer(TransferData {
            recipient,
            amount,
        });
        
        Transaction::new(
            sender,
            nonce,
            100000, // gas_limit
            1,      // gas_price
            TransactionType::Transfer,
            data,
            vec![0, 0, 0, 1], // chain_id
        )
    }
    
    /// Creates a test block
    fn create_test_block(height: u64, previous_hash: Vec<u8>, transactions: Vec<Transaction>) -> Block {
        let validator = vec![1, 2, 3, 4];
        
        BlockBuilder::new()
            .height(height)
            .previous_hash(previous_hash)
            .reference_height(height)
            .validator(validator)
            .transactions(transactions)
            .build()
            .unwrap()
    }
    
    #[test]
    fn test_blockchain_store_basics() {
        // Create an in-memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the blockchain store
        let store = BlockchainStore::new(db).unwrap();
        
        // Create a test transaction
        let transaction = create_test_transaction(1);
        let tx_hash = transaction.hash();
        
        // Store the transaction
        store.store_transaction(&transaction).unwrap();
        
        // Check that the transaction exists
        assert!(store.transaction_exists(&tx_hash).unwrap());
        
        // Get the transaction
        let retrieved_tx = store.get_transaction(&tx_hash).unwrap();
        assert_eq!(retrieved_tx.hash(), tx_hash);
        
        // Create a test block
        let block = create_test_block(0, vec![0; 32], vec![transaction]);
        let block_hash = block.hash();
        
        // Store the block
        store.store_block(&block).unwrap();
        
        // Check that the block exists
        assert!(store.block_exists(&block_hash).unwrap());
        
        // Get the block
        let retrieved_block = store.get_block(&block_hash).unwrap();
        assert_eq!(retrieved_block.hash(), block_hash);
        
        // Get the block by height
        let retrieved_block_by_height = store.get_block_by_height(0).unwrap();
        assert_eq!(retrieved_block_by_height.hash(), block_hash);
        
        // Get the transaction block
        let transaction_block = store.get_transaction_block(&tx_hash).unwrap();
        assert_eq!(transaction_block.hash(), block_hash);
        
        // Get latest height
        let latest_height = store.get_latest_height().unwrap();
        assert_eq!(latest_height, 0);
        
        // Get latest hash
        let latest_hash = store.get_latest_hash().unwrap();
        assert_eq!(latest_hash, block_hash);
        
        // Get genesis hash
        let genesis_hash = store.get_genesis_hash().unwrap();
        assert_eq!(genesis_hash, block_hash);
    }
    
    #[test]
    fn test_blockchain_store_block_status() {
        // Create an in-memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the blockchain store
        let store = BlockchainStore::new(db).unwrap();
        
        // Create a test block
        let block = create_test_block(0, vec![0; 32], vec![create_test_transaction(1)]);
        let block_hash = block.hash();
        
        // Store the block
        store.store_block(&block).unwrap();
        
        // Update the block status
        store.update_block_status(&block_hash, BlockStatus::Finalized).unwrap();
        
        // Get the updated block
        let updated_block = store.get_block(&block_hash).unwrap();
        assert_eq!(updated_block.status(), BlockStatus::Finalized);
        
        // Update the block status to Uncorrupted
        store.update_block_status(&block_hash, BlockStatus::Uncorrupted).unwrap();
        
        // Get the updated block
        let updated_block = store.get_block(&block_hash).unwrap();
        assert_eq!(updated_block.status(), BlockStatus::Uncorrupted);
        
        // Check that the latest uncorrupted hash was updated
        let latest_uncorrupted_hash = store.get_latest_uncorrupted_hash().unwrap();
        assert_eq!(latest_uncorrupted_hash, block_hash);
    }
    
    #[test]
    fn test_blockchain_store_transaction_result() {
        // Create an in-memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the blockchain store
        let store = BlockchainStore::new(db).unwrap();
        
        // Create a test transaction
        let transaction = create_test_transaction(1);
        let tx_hash = transaction.hash();
        
        // Store the transaction
        store.store_transaction(&transaction).unwrap();
        
        // Create a transaction result
        let result = TransactionResult {
            success: true,
            gas_used: 50000,
            error: None,
            block_hash: vec![1; 32],
            block_height: 0,
            transaction_index: 0,
            timestamp: 123456789,
            created_objects: vec![vec![2; 32]],
            modified_objects: vec![vec![3; 32]],
            deleted_objects: vec![],
            security_level: 3,
        };
        
        // Store the transaction result
        store.store_transaction_result(&tx_hash, &result).unwrap();
        
        // Get the transaction result
        let retrieved_result = store.get_transaction_result(&tx_hash).unwrap().unwrap();
        assert_eq!(retrieved_result.success, result.success);
        assert_eq!(retrieved_result.gas_used, result.gas_used);
        assert_eq!(retrieved_result.error, result.error);
        assert_eq!(retrieved_result.block_hash, result.block_hash);
        assert_eq!(retrieved_result.block_height, result.block_height);
        assert_eq!(retrieved_result.transaction_index, result.transaction_index);
        assert_eq!(retrieved_result.timestamp, result.timestamp);
        assert_eq!(retrieved_result.created_objects, result.created_objects);
        assert_eq!(retrieved_result.modified_objects, result.modified_objects);
        assert_eq!(retrieved_result.deleted_objects, result.deleted_objects);
        assert_eq!(retrieved_result.security_level, result.security_level);
    }   
}
