use std::collections::HashMap;
use std::sync::Arc;

use crate::core::block::Block;
use crate::core::merkle::MerkleTree;
use crate::core::state::StateSnapshot;
use crate::error::{AevorError, Result};

use super::database::{Database, Transaction};

/// Column family names for the state store
const BLOCKS_CF: &str = "blocks";
const TRANSACTIONS_CF: &str = "transactions";
const BLOCK_HEIGHT_CF: &str = "block_height";
const TX_BLOCK_CF: &str = "tx_block";
const SNAPSHOTS_CF: &str = "snapshots";
const METADATA_CF: &str = "metadata";

/// Metadata keys
const CURRENT_HEIGHT_KEY: &str = "current_height";
const GENESIS_BLOCK_HASH_KEY: &str = "genesis_block_hash";
const LATEST_BLOCK_HASH_KEY: &str = "latest_block_hash";
const LATEST_FINALIZED_BLOCK_HASH_KEY: &str = "latest_finalized_block_hash";
const CREATION_TIME_KEY: &str = "creation_time";

/// Store for blockchain global state
pub struct StateStore {
    /// Database instance
    db: Arc<dyn Database>,
    
    /// Blocks column family name
    blocks_cf: String,
    
    /// Transactions column family name
    transactions_cf: String,
    
    /// Block height index column family name
    block_height_cf: String,
    
    /// Transaction block index column family name
    tx_block_cf: String,
    
    /// State snapshots column family name
    snapshots_cf: String,
    
    /// Metadata column family name
    metadata_cf: String,
    
    /// Cache of recent blocks (hash -> block)
    block_cache: parking_lot::RwLock<HashMap<Vec<u8>, Block>>,
    
    /// Cache of recent snapshots (height -> snapshot)
    snapshot_cache: parking_lot::RwLock<HashMap<u64, StateSnapshot>>,
    
    /// Cache size limit for blocks
    block_cache_limit: usize,
    
    /// Cache size limit for snapshots
    snapshot_cache_limit: usize,
}

/// Metadata for the blockchain
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainMetadata {
    /// Current block height
    pub current_height: u64,
    
    /// Genesis block hash
    pub genesis_block_hash: Vec<u8>,
    
    /// Latest block hash
    pub latest_block_hash: Vec<u8>,
    
    /// Latest finalized block hash
    pub latest_finalized_block_hash: Option<Vec<u8>>,
    
    /// Creation timestamp
    pub creation_time: u64,
}

impl StateStore {
    /// Creates a new state store with the given database
    pub fn new(db: Arc<dyn Database>) -> Result<Self> {
        // Ensure all required column families exist
        db.create_cf_if_not_exists(BLOCKS_CF)?;
        db.create_cf_if_not_exists(TRANSACTIONS_CF)?;
        db.create_cf_if_not_exists(BLOCK_HEIGHT_CF)?;
        db.create_cf_if_not_exists(TX_BLOCK_CF)?;
        db.create_cf_if_not_exists(SNAPSHOTS_CF)?;
        db.create_cf_if_not_exists(METADATA_CF)?;
        
        Ok(Self {
            db,
            blocks_cf: BLOCKS_CF.to_string(),
            transactions_cf: TRANSACTIONS_CF.to_string(),
            block_height_cf: BLOCK_HEIGHT_CF.to_string(),
            tx_block_cf: TX_BLOCK_CF.to_string(),
            snapshots_cf: SNAPSHOTS_CF.to_string(),
            metadata_cf: METADATA_CF.to_string(),
            block_cache: parking_lot::RwLock::new(HashMap::new()),
            snapshot_cache: parking_lot::RwLock::new(HashMap::new()),
            block_cache_limit: 1000, // Default cache limits
            snapshot_cache_limit: 100,
        })
    }
    
    /// Initializes the state store with a genesis block
    pub fn initialize(&self, genesis_block: &Block) -> Result<()> {
        // Check if we already have metadata (already initialized)
        if self.db.exists(METADATA_CF, CURRENT_HEIGHT_KEY.as_bytes())? {
            return Ok(());
        }
        
        // Generate a transaction to store everything atomically
        let mut tx = self.db.transaction();
        
        // Store the genesis block
        self.put_block_in_tx(&mut tx, genesis_block)?;
        
        // Initialize metadata with genesis block info
        let genesis_hash = genesis_block.hash();
        let metadata = ChainMetadata {
            current_height: 0,
            genesis_block_hash: genesis_hash.clone(),
            latest_block_hash: genesis_hash.clone(),
            latest_finalized_block_hash: None,
            creation_time: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Store the metadata
        self.put_metadata_in_tx(&mut tx, &metadata)?;
        
        // Create a genesis state snapshot
        let genesis_snapshot = StateSnapshot::new(
            0, // Genesis height
            Vec::new(), // Empty state root initially
            Vec::new(), // No objects initially
            Vec::new(), // No validators initially
        );
        
        // Store the genesis snapshot
        self.put_snapshot_in_tx(&mut tx, &genesis_snapshot)?;
        
        // Commit the transaction
        self.db.execute_transaction(tx)?;
        
        // Update the caches
        self.block_cache.write().insert(genesis_hash, genesis_block.clone());
        self.snapshot_cache.write().insert(0, genesis_snapshot);
        
        Ok(())
    }
    
    /// Stores a block
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let mut tx = self.db.transaction();
        self.put_block_in_tx(&mut tx, block)?;
        self.db.execute_transaction(tx)?;
        
        // Update the block cache
        self.block_cache.write().insert(block.hash(), block.clone());
        
        Ok(())
    }
    
    /// Stores a block within a transaction
    fn put_block_in_tx(&self, tx: &mut Transaction, block: &Block) -> Result<()> {
        let block_hash = block.hash();
        
        // Serialize the block
        let serialized_block = bincode::serialize(block)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize block: {}", e)))?;
        
        // Store the block by hash
        tx.put(&self.blocks_cf, &block_hash, &serialized_block);
        
        // Store the block hash by height
        let height_key = block.height().to_be_bytes();
        tx.put(&self.block_height_cf, &height_key, &block_hash);
        
        // Store each transaction in the block
        for transaction in block.transactions() {
            let tx_hash = transaction.hash();
            let serialized_tx = bincode::serialize(transaction)
                .map_err(|e| AevorError::serialization(format!("Failed to serialize transaction: {}", e)))?;
            
            // Store the transaction by hash
            tx.put(&self.transactions_cf, &tx_hash, &serialized_tx);
            
            // Store the block hash for this transaction
            tx.put(&self.tx_block_cf, &tx_hash, &block_hash);
        }
        
        // Update metadata if this is a new highest block
        self.update_metadata_for_block_in_tx(tx, block)?;
        
        Ok(())
    }
    
    /// Updates metadata when a new block is added
    fn update_metadata_for_block_in_tx(&self, tx: &mut Transaction, block: &Block) -> Result<()> {
        // Get current metadata
        let metadata = self.get_metadata()?;
        
        // Only update if the block height is greater than current height
        if block.height() > metadata.current_height {
            let new_metadata = ChainMetadata {
                current_height: block.height(),
                genesis_block_hash: metadata.genesis_block_hash,
                latest_block_hash: block.hash(),
                latest_finalized_block_hash: metadata.latest_finalized_block_hash,
                creation_time: metadata.creation_time,
            };
            
            self.put_metadata_in_tx(tx, &new_metadata)?;
        }
        
        Ok(())
    }
    
    /// Gets a block by hash
    pub fn get_block(&self, hash: &[u8]) -> Result<Option<Block>> {
        // Check the cache first
        if let Some(block) = self.block_cache.read().get(hash) {
            return Ok(Some(block.clone()));
        }
        
        // If not in cache, check the database
        if let Some(data) = self.db.get(&self.blocks_cf, hash)? {
            let block: Block = bincode::deserialize(&data)
                .map_err(|e| AevorError::deserialization(format!("Failed to deserialize block: {}", e)))?;
            
            // Update the cache
            self.block_cache.write().insert(hash.to_vec(), block.clone());
            
            // Trim the cache if it exceeds the limit
            self.trim_block_cache();
            
            return Ok(Some(block));
        }
        
        Ok(None)
    }
    
    /// Gets a block by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        // Convert height to bytes
        let height_key = height.to_be_bytes();
        
        // Get the block hash at this height
        if let Some(hash) = self.db.get(&self.block_height_cf, &height_key)? {
            return self.get_block(&hash);
        }
        
        Ok(None)
    }
    
    /// Gets a transaction by hash
    pub fn get_transaction(&self, hash: &[u8]) -> Result<Option<crate::core::transaction::Transaction>> {
        if let Some(data) = self.db.get(&self.transactions_cf, hash)? {
            let transaction: crate::core::transaction::Transaction = bincode::deserialize(&data)
                .map_err(|e| AevorError::deserialization(format!("Failed to deserialize transaction: {}", e)))?;
            
            return Ok(Some(transaction));
        }
        
        Ok(None)
    }
    
    /// Gets the block containing a transaction
    pub fn get_transaction_block(&self, tx_hash: &[u8]) -> Result<Option<Block>> {
        if let Some(block_hash) = self.db.get(&self.tx_block_cf, tx_hash)? {
            return self.get_block(&block_hash);
        }
        
        Ok(None)
    }
    
    /// Stores a state snapshot
    pub fn put_snapshot(&self, snapshot: &StateSnapshot) -> Result<()> {
        let mut tx = self.db.transaction();
        self.put_snapshot_in_tx(&mut tx, snapshot)?;
        self.db.execute_transaction(tx)?;
        
        // Update the snapshot cache
        self.snapshot_cache.write().insert(snapshot.height(), snapshot.clone());
        
        Ok(())
    }
    
    /// Stores a state snapshot within a transaction
    fn put_snapshot_in_tx(&self, tx: &mut Transaction, snapshot: &StateSnapshot) -> Result<()> {
        // Serialize the snapshot
        let serialized = bincode::serialize(snapshot)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize snapshot: {}", e)))?;
        
        // Use height as the key
        let height_key = snapshot.height().to_be_bytes();
        
        // Store the snapshot
        tx.put(&self.snapshots_cf, &height_key, &serialized);
        
        Ok(())
    }
    
    /// Gets a state snapshot by height
    pub fn get_snapshot(&self, height: u64) -> Result<Option<StateSnapshot>> {
        // Check the cache first
        if let Some(snapshot) = self.snapshot_cache.read().get(&height) {
            return Ok(Some(snapshot.clone()));
        }
        
        // If not in cache, check the database
        let height_key = height.to_be_bytes();
        if let Some(data) = self.db.get(&self.snapshots_cf, &height_key)? {
            let snapshot: StateSnapshot = bincode::deserialize(&data)
                .map_err(|e| AevorError::deserialization(format!("Failed to deserialize snapshot: {}", e)))?;
            
            // Update the cache
            self.snapshot_cache.write().insert(height, snapshot.clone());
            
            // Trim the cache if it exceeds the limit
            self.trim_snapshot_cache();
            
            return Ok(Some(snapshot));
        }
        
        Ok(None)
    }
    
    /// Gets the latest snapshot
    pub fn get_latest_snapshot(&self) -> Result<Option<StateSnapshot>> {
        let metadata = self.get_metadata()?;
        self.get_snapshot(metadata.current_height)
    }
    
    /// Sets the latest finalized block
    pub fn set_latest_finalized_block(&self, block_hash: Vec<u8>) -> Result<()> {
        let mut metadata = self.get_metadata()?;
        
        // Update the metadata
        metadata.latest_finalized_block_hash = Some(block_hash);
        
        // Store the updated metadata
        let mut tx = self.db.transaction();
        self.put_metadata_in_tx(&mut tx, &metadata)?;
        self.db.execute_transaction(tx)?;
        
        Ok(())
    }
    
    /// Gets the latest finalized block hash
    pub fn get_latest_finalized_block_hash(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.get_metadata()?.latest_finalized_block_hash)
    }
    
    /// Gets the latest finalized block
    pub fn get_latest_finalized_block(&self) -> Result<Option<Block>> {
        if let Some(hash) = self.get_latest_finalized_block_hash()? {
            return self.get_block(&hash);
        }
        
        Ok(None)
    }
    
    /// Gets the current block height
    pub fn get_current_height(&self) -> Result<u64> {
        Ok(self.get_metadata()?.current_height)
    }
    
    /// Gets the latest block hash
    pub fn get_latest_block_hash(&self) -> Result<Vec<u8>> {
        Ok(self.get_metadata()?.latest_block_hash)
    }
    
    /// Gets the latest block
    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        let hash = self.get_latest_block_hash()?;
        self.get_block(&hash)
    }
    
    /// Gets the chain metadata
    fn get_metadata(&self) -> Result<ChainMetadata> {
        if let Some(data) = self.db.get(&self.metadata_cf, CURRENT_HEIGHT_KEY.as_bytes())? {
            let metadata: ChainMetadata = bincode::deserialize(&data)
                .map_err(|e| AevorError::deserialization(format!("Failed to deserialize metadata: {}", e)))?;
            
            return Ok(metadata);
        }
        
        // If metadata doesn't exist, create default metadata
        let metadata = ChainMetadata {
            current_height: 0,
            genesis_block_hash: Vec::new(),
            latest_block_hash: Vec::new(),
            latest_finalized_block_hash: None,
            creation_time: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        Ok(metadata)
    }
    
    /// Stores the chain metadata
    fn put_metadata(&self, metadata: &ChainMetadata) -> Result<()> {
        let mut tx = self.db.transaction();
        self.put_metadata_in_tx(&mut tx, metadata)?;
        self.db.execute_transaction(tx)?;
        
        Ok(())
    }
    
    /// Stores the chain metadata within a transaction
    fn put_metadata_in_tx(&self, tx: &mut Transaction, metadata: &ChainMetadata) -> Result<()> {
        // Serialize the metadata
        let serialized = bincode::serialize(metadata)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize metadata: {}", e)))?;
        
        // Store the metadata
        tx.put(&self.metadata_cf, CURRENT_HEIGHT_KEY.as_bytes(), &serialized);
        
        Ok(())
    }
    
    /// Trims the block cache if it exceeds the limit
    fn trim_block_cache(&self) {
        let mut cache = self.block_cache.write();
        if cache.len() > self.block_cache_limit {
            // Simple LRU eviction: remove random entries until we're under the limit
            while cache.len() > self.block_cache_limit {
                if let Some(key) = cache.keys().next().cloned() {
                    cache.remove(&key);
                } else {
                    break;
                }
            }
        }
    }
    
    /// Trims the snapshot cache if it exceeds the limit
    fn trim_snapshot_cache(&self) {
        let mut cache = self.snapshot_cache.write();
        if cache.len() > self.snapshot_cache_limit {
            // Simple LRU eviction: remove random entries until we're under the limit
            while cache.len() > self.snapshot_cache_limit {
                if let Some(key) = cache.keys().next().copied() {
                    cache.remove(&key);
                } else {
                    break;
                }
            }
        }
    }
    
    /// Sets the cache limits
    pub fn set_cache_limits(&mut self, block_limit: usize, snapshot_limit: usize) {
        self.block_cache_limit = block_limit;
        self.snapshot_cache_limit = snapshot_limit;
        
        // Trigger cache trimming to apply new limits
        self.trim_block_cache();
        self.trim_snapshot_cache();
    }
    
    /// Gets a range of blocks by height
    pub fn get_blocks_in_range(&self, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        
        for height in start_height..=end_height {
            if let Some(block) = self.get_block_by_height(height)? {
                blocks.push(block);
            }
        }
        
        Ok(blocks)
    }
    
    /// Creates a state snapshot at the specified height
    pub async fn create_snapshot_at_height(&self, height: u64, state_root: Vec<u8>, objects: Vec<crate::core::object::Object>, validators: Vec<Vec<u8>>) -> Result<StateSnapshot> {
        // Create the snapshot
        let snapshot = StateSnapshot::new(height, state_root, objects, validators);
        
        // Store the snapshot
        self.put_snapshot(&snapshot)?;
        
        Ok(snapshot)
    }
    
    /// Initializes the state store asynchronously
    pub async fn initialize(&self) -> Result<()> {
        // This is a placeholder for async initialization logic
        // For now, we just call the sync version
        Ok(())
    }
    
    /// Shuts down the state store asynchronously
    pub async fn shutdown(&self) -> Result<()> {
        // This is a placeholder for async shutdown logic
        // For now, we just return Ok
        Ok(())
    }
    
    /// Prunes state below the given height
    pub async fn prune_state_below(&self, height: u64) -> Result<usize> {
        let mut count = 0;
        let mut tx = self.db.transaction();
        
        // Get all snapshot heights
        let snapshots: Vec<u64> = self.snapshot_cache.read().keys().copied().collect();
        
        // Prune snapshots below the height
        for snapshot_height in snapshots {
            if snapshot_height < height {
                let height_key = snapshot_height.to_be_bytes();
                tx.delete(&self.snapshots_cf, &height_key);
                count += 1;
            }
        }
        
        // Commit the transaction
        self.db.execute_transaction(tx)?;
        
        // Update the cache
        let mut cache = self.snapshot_cache.write();
        cache.retain(|&h, _| h >= height);
        
        Ok(count)
    }
    
    /// Checks the state store integrity
    pub async fn check_integrity(&self) -> Result<bool> {
        // Get the metadata
        let metadata = self.get_metadata()?;
        
        // Check that the genesis block exists
        if !metadata.genesis_block_hash.is_empty() && self.get_block(&metadata.genesis_block_hash)?.is_none() {
            return Ok(false);
        }
        
        // Check that the latest block exists
        if !metadata.latest_block_hash.is_empty() && self.get_block(&metadata.latest_block_hash)?.is_none() {
            return Ok(false);
        }
        
        // Check that the latest finalized block exists (if set)
        if let Some(hash) = &metadata.latest_finalized_block_hash {
            if self.get_block(hash)?.is_none() {
                return Ok(false);
            }
        }
        
        // Check that the latest snapshot exists
        if metadata.current_height > 0 && self.get_snapshot(metadata.current_height)?.is_none() {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Gets all snapshots in the specified range
    pub fn get_snapshots_in_range(&self, start_height: u64, end_height: u64) -> Result<Vec<StateSnapshot>> {
        let mut snapshots = Vec::new();
        
        for height in start_height..=end_height {
            if let Some(snapshot) = self.get_snapshot(height)? {
                snapshots.push(snapshot);
            }
        }
        
        Ok(snapshots)
    }
    
    /// Updates the state root at the given height
    pub fn update_state_root(&self, height: u64, state_root: Vec<u8>) -> Result<()> {
        if let Some(mut snapshot) = self.get_snapshot(height)? {
            // Update the state root
            snapshot.set_state_root(state_root);
            
            // Store the updated snapshot
            self.put_snapshot(&snapshot)?;
        }
        
        Ok(())
    }
    
    /// Gets the genesis block
    pub fn get_genesis_block(&self) -> Result<Option<Block>> {
        let metadata = self.get_metadata()?;
        
        if metadata.genesis_block_hash.is_empty() {
            return Ok(None);
        }
        
        self.get_block(&metadata.genesis_block_hash)
    }
    
    /// Creates a Merkle tree from the current state
    pub fn create_state_merkle_tree(&self) -> Result<MerkleTree> {
        // Get the latest snapshot
        let snapshot = match self.get_latest_snapshot()? {
            Some(snapshot) => snapshot,
            None => return Ok(MerkleTree::from_leaves(Vec::new())),
        };
        
        // Create a Merkle tree from the objects in the snapshot
        let object_hashes: Vec<Vec<u8>> = snapshot.objects().iter()
            .map(|obj| obj.calculate_hash())
            .collect();
        
        Ok(MerkleTree::from_leaves(object_hashes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::{Block, BlockBuilder};
    use crate::core::transaction::{Transaction, TransactionBuilder, TransactionType, TransactionData};
    use crate::core::transaction::data::TransferData;
    use crate::storage::database::{Database, MemoryDatabase};
    
    /// Creates a test block with the given height and parent hash
    fn create_test_block(height: u64, parent_hash: Vec<u8>, transactions: Vec<Transaction>) -> Block {
        BlockBuilder::new()
            .height(height)
            .previous_hash(parent_hash)
            .reference_height(height)
            .validator(vec![1, 2, 3, 4])
            .transactions(transactions)
            .build()
            .unwrap()
    }
    
    /// Creates a test transaction
    fn create_test_transaction() -> Transaction {
        let sender = vec![1, 2, 3, 4];
        let recipient = vec![5, 6, 7, 8];
        let amount = 100;
        
        TransactionBuilder::new()
            .sender(sender)
            .nonce(1)
            .gas_limit(100000)
            .gas_price(1)
            .data(TransactionData::Transfer(TransferData {
                recipient,
                amount,
            }))
            .chain_id(vec![9, 10, 11, 12])
            .build()
            .unwrap()
    }
    
    #[tokio::test]
    async fn test_state_store_initialization() {
        // Create a memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the state store
        let state_store = StateStore::new(db).unwrap();
        
        // Create a genesis block
        let genesis_block = create_test_block(0, vec![0; 32], vec![create_test_transaction()]);
        
        // Initialize the state store
        state_store.initialize(&genesis_block).unwrap();
        
        // Check that the genesis block was stored
        let stored_genesis = state_store.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(stored_genesis.hash(), genesis_block.hash());
        
        // Check that the metadata was initialized
        let metadata = state_store.get_metadata().unwrap();
        assert_eq!(metadata.current_height, 0);
        assert_eq!(metadata.genesis_block_hash, genesis_block.hash());
        assert_eq!(metadata.latest_block_hash, genesis_block.hash());
        assert!(metadata.latest_finalized_block_hash.is_none());
    }
    
    #[tokio::test]
    async fn test_block_storage_and_retrieval() {
        // Create a memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the state store
        let state_store = StateStore::new(db).unwrap();
        
        // Create a genesis block
        let genesis_block = create_test_block(0, vec![0; 32], vec![create_test_transaction()]);
        
        // Initialize the state store
        state_store.initialize(&genesis_block).unwrap();
        
        // Create and store a new block
        let block1 = create_test_block(1, genesis_block.hash(), vec![create_test_transaction()]);
        state_store.put_block(&block1).unwrap();
        
        // Retrieve the block by hash
        let retrieved_block = state_store.get_block(&block1.hash()).unwrap().unwrap();
        assert_eq!(retrieved_block.hash(), block1.hash());
        
        // Retrieve the block by height
        let retrieved_block = state_store.get_block_by_height(1).unwrap().unwrap();
        assert_eq!(retrieved_block.hash(), block1.hash());
        
        // Check that the metadata was updated
        let metadata = state_store.get_metadata().unwrap();
        assert_eq!(metadata.current_height, 1);
        assert_eq!(metadata.latest_block_hash, block1.hash());
    }
    
    #[tokio::test]
    async fn test_transaction_storage_and_retrieval() {
        // Create a memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the state store
        let state_store = StateStore::new(db).unwrap();
        
        // Create a transaction
        let transaction = create_test_transaction();
        let tx_hash = transaction.hash();
        
        // Create a block containing the transaction
        let block = create_test_block(0, vec![0; 32], vec![transaction]);
        
        // Initialize the state store
        state_store.initialize(&block).unwrap();
        
        // Retrieve the transaction
        let retrieved_tx = state_store.get_transaction(&tx_hash).unwrap().unwrap();
        assert_eq!(retrieved_tx.hash(), tx_hash);
        
        // Retrieve the block containing the transaction
        let retrieved_block = state_store.get_transaction_block(&tx_hash).unwrap().unwrap();
        assert_eq!(retrieved_block.hash(), block.hash());
    }
    
    #[tokio::test]
    async fn test_snapshot_storage_and_retrieval() {
        // Create a memory database
        let db = Arc::new(MemoryDatabase::new().unwrap());
        
        // Create the state store
        let state_store = StateStore::new(db).unwrap();
        
        // Create a genesis block
        let genesis_block = create_test_block(0, vec![0; 32], vec![create_test_transaction()]);
        
        // Initialize the state store
        state_store.initialize(&genesis_block).unwrap();
        
        // Create a snapshot
        let state_root = vec![1, 2, 3, 4];
        let objects = Vec::new();
        let validators = vec![vec![5, 6, 7, 8]];
        
        let snapshot = StateSnapshot::new(1, state_root.clone(), objects.clone(), validators.clone());
        
        // Store the snapshot
        state_store.put_snapshot(&snapshot).unwrap();
        
        // Retrieve the snapshot
        let retrieved_snapshot = state_store.get_snapshot(1).unwrap().unwrap();
        assert_eq!(retrieved_snapshot.height(), 1);
        assert_eq!(retrieved_snapshot.state_root(), &state_root);
        assert_eq!(retrieved_snapshot.validators(), &validators);
    }
}
