use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, Options, WriteBatch, WriteOptions};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::config::StorageConfig;
use crate::error::{AevorError, Result};

/// Error type for storage operations
#[derive(Error, Debug)]
pub enum StorageError {
    /// RocksDB error
    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    /// Column family not found
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),
    
    /// Invalid operation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    
    /// IO error
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    
    /// Other error
    #[error("Storage error: {0}")]
    Other(String),
}

/// Result type for storage operations
pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// Enum representing different column families (logical databases) in the storage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnFamily {
    /// Default column family
    Default,
    
    /// Blocks column family
    Blocks,
    
    /// Transactions column family
    Transactions,
    
    /// Objects column family
    Objects,
    
    /// Objects by owner (index) column family
    ObjectsByOwner,
    
    /// Objects by type (index) column family
    ObjectsByType,
    
    /// Superpositioned objects column family
    SuperpositionedObjects,
    
    /// Block height index column family
    BlockHeightIndex,
    
    /// Transaction block index column family
    TransactionBlockIndex,
    
    /// State snapshots column family
    StateSnapshots,
    
    /// Metadata column family
    Metadata,
    
    /// Validator data column family
    Validators,
    
    /// Chain data column family
    ChainData,
    
    /// Uncorrupted chain data column family
    UncorruptedChains,
    
    /// Custom column family
    Custom(String),
}

impl fmt::Display for ColumnFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ColumnFamily::Default => write!(f, "default"),
            ColumnFamily::Blocks => write!(f, "blocks"),
            ColumnFamily::Transactions => write!(f, "transactions"),
            ColumnFamily::Objects => write!(f, "objects"),
            ColumnFamily::ObjectsByOwner => write!(f, "objects_by_owner"),
            ColumnFamily::ObjectsByType => write!(f, "objects_by_type"),
            ColumnFamily::SuperpositionedObjects => write!(f, "superpositioned_objects"),
            ColumnFamily::BlockHeightIndex => write!(f, "block_height_index"),
            ColumnFamily::TransactionBlockIndex => write!(f, "transaction_block_index"),
            ColumnFamily::StateSnapshots => write!(f, "state_snapshots"),
            ColumnFamily::Metadata => write!(f, "metadata"),
            ColumnFamily::Validators => write!(f, "validators"),
            ColumnFamily::ChainData => write!(f, "chain_data"),
            ColumnFamily::UncorruptedChains => write!(f, "uncorrupted_chains"),
            ColumnFamily::Custom(name) => write!(f, "{}", name),
        }
    }
}

impl AsRef<str> for ColumnFamily {
    fn as_ref(&self) -> &str {
        match self {
            ColumnFamily::Default => "default",
            ColumnFamily::Blocks => "blocks",
            ColumnFamily::Transactions => "transactions",
            ColumnFamily::Objects => "objects",
            ColumnFamily::ObjectsByOwner => "objects_by_owner",
            ColumnFamily::ObjectsByType => "objects_by_type",
            ColumnFamily::SuperpositionedObjects => "superpositioned_objects",
            ColumnFamily::BlockHeightIndex => "block_height_index",
            ColumnFamily::TransactionBlockIndex => "transaction_block_index",
            ColumnFamily::StateSnapshots => "state_snapshots",
            ColumnFamily::Metadata => "metadata",
            ColumnFamily::Validators => "validators",
            ColumnFamily::ChainData => "chain_data",
            ColumnFamily::UncorruptedChains => "uncorrupted_chains",
            ColumnFamily::Custom(name) => name,
        }
    }
}

/// Trait for types that can be converted to a RocksDB column family
pub trait AsColumnFamily {
    /// Convert to a ColumnFamily enum
    fn as_column_family(&self) -> ColumnFamily;
}

impl AsColumnFamily for ColumnFamily {
    fn as_column_family(&self) -> ColumnFamily {
        *self
    }
}

impl AsColumnFamily for str {
    fn as_column_family(&self) -> ColumnFamily {
        match self {
            "default" => ColumnFamily::Default,
            "blocks" => ColumnFamily::Blocks,
            "transactions" => ColumnFamily::Transactions,
            "objects" => ColumnFamily::Objects,
            "objects_by_owner" => ColumnFamily::ObjectsByOwner,
            "objects_by_type" => ColumnFamily::ObjectsByType,
            "superpositioned_objects" => ColumnFamily::SuperpositionedObjects,
            "block_height_index" => ColumnFamily::BlockHeightIndex,
            "transaction_block_index" => ColumnFamily::TransactionBlockIndex,
            "state_snapshots" => ColumnFamily::StateSnapshots,
            "metadata" => ColumnFamily::Metadata,
            "validators" => ColumnFamily::Validators,
            "chain_data" => ColumnFamily::ChainData,
            "uncorrupted_chains" => ColumnFamily::UncorruptedChains,
            _ => ColumnFamily::Custom(self.to_string()),
        }
    }
}

impl AsColumnFamily for String {
    fn as_column_family(&self) -> ColumnFamily {
        self.as_str().as_column_family()
    }
}

/// Represents a database transaction for atomic batch operations
pub struct Transaction {
    /// RocksDB write batch
    pub batch: WriteBatch,
    
    /// Write options for the transaction
    pub write_options: WriteOptions,
}

impl Transaction {
    /// Creates a new transaction
    pub fn new() -> Self {
        let mut write_options = WriteOptions::default();
        write_options.set_sync(false); // Default to async writes for performance
        
        Self {
            batch: WriteBatch::default(),
            write_options,
        }
    }
    
    /// Sets whether the transaction should be synced to disk immediately
    pub fn set_sync(&mut self, sync: bool) -> &mut Self {
        self.write_options.set_sync(sync);
        self
    }
    
    /// Puts a key-value pair in the transaction
    pub fn put<K, V>(&mut self, cf: ColumnFamily, key: K, value: V) -> &mut Self
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.batch.put_cf(cf.to_string(), key, value);
        self
    }
    
    /// Puts a serializable object in the transaction
    pub fn put_object<K, V>(&mut self, cf: ColumnFamily, key: K, value: &V) -> StorageResult<&mut Self>
    where
        K: AsRef<[u8]>,
        V: Serialize,
    {
        let serialized = bincode::serialize(value)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.batch.put_cf(cf.to_string(), key, serialized);
        Ok(self)
    }
    
    /// Deletes a key-value pair from the transaction
    pub fn delete<K>(&mut self, cf: ColumnFamily, key: K) -> &mut Self
    where
        K: AsRef<[u8]>,
    {
        self.batch.delete_cf(cf.to_string(), key);
        self
    }
    
    /// Clears all operations in the transaction
    pub fn clear(&mut self) -> &mut Self {
        self.batch = WriteBatch::default();
        self
    }
    
    /// Returns the number of operations in the transaction
    pub fn len(&self) -> usize {
        self.batch.len()
    }
    
    /// Checks if the transaction is empty
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Database interface for storage operations
pub trait Database: Send + Sync {
    /// Gets a value from the database
    fn get<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>;
    
    /// Gets a deserialized object from the database
    fn get_object<K, V>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<Option<V>>
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned;
    
    /// Checks if a key exists in the database
    fn exists<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<bool>
    where
        K: AsRef<[u8]>;
    
    /// Puts a value into the database
    fn put<K, V>(&self, cf: impl AsColumnFamily, key: K, value: V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>;
    
    /// Puts a serializable object into the database
    fn put_object<K, V>(&self, cf: impl AsColumnFamily, key: K, value: &V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: Serialize,
    {
        let serialized = bincode::serialize(value)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.put(cf, key, serialized)
    }
    
    fn delete<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
    {
        let cf_handle = self.get_cf_handle(cf)?;
        self.db
            .delete_cf(cf_handle, key)
            .map_err(StorageError::from)
    }
    
    fn execute_transaction(&self, transaction: &Transaction) -> StorageResult<()> {
        self.db
            .write_opt(&transaction.batch, &transaction.write_options)
            .map_err(StorageError::from)
    }
    
    fn iterator(&self, cf: impl AsColumnFamily) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>> {
        let cf_handle = self.get_cf_handle(cf)?;
        let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
        
        // Wrap the RocksDB iterator in our own iterator that converts errors
        let wrapped_iter = iter.map(|result| {
            result
                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                .map_err(StorageError::from)
        });
        
        Ok(Box::new(wrapped_iter))
    }
    
    fn prefix_iterator<P>(&self, cf: impl AsColumnFamily, prefix: P) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>>
    where
        P: AsRef<[u8]>,
    {
        let cf_handle = self.get_cf_handle(cf)?;
        let prefix_bytes = prefix.as_ref().to_vec();
        
        let iter = self.db.prefix_iterator_cf(cf_handle, &prefix_bytes);
        
        // Wrap the RocksDB iterator in our own iterator that converts errors
        let wrapped_iter = iter.map(|result| {
            result
                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                .map_err(StorageError::from)
        });
        
        Ok(Box::new(wrapped_iter))
    }
    
    fn flush(&self) -> StorageResult<()> {
        // Flush all column families
        for (cf, _) in &self.column_families {
            let cf_handle = self.get_cf_handle(*cf)?;
            self.db.flush_cf(cf_handle)?;
        }
        
        Ok(())
    }
    
    fn compact(&self) -> StorageResult<()> {
        // Compact all column families
        for (cf, _) in &self.column_families {
            let cf_handle = self.get_cf_handle(*cf)?;
            self.db.compact_range_cf(cf_handle, None::<&[u8]>, None::<&[u8]>);
        }
        
        Ok(())
    }
    
    fn backup(&self, path: &Path) -> StorageResult<()> {
        // RocksDB has a built-in backup mechanism
        let backup_engine = rocksdb::backup::BackupEngine::open(
            &rocksdb::backup::BackupEngineOptions::default(),
            path,
        )?;
        
        backup_engine.create_new_backup(&self.db)?;
        
        Ok(())
    }
    
    fn check_integrity(&self) -> StorageResult<bool> {
        // Use RocksDB's built-in integrity checking
        for (cf, _) in &self.column_families {
            let cf_handle = self.get_cf_handle(*cf)?;
            
            // Create checkpoint in temporary directory
            let temp_dir = tempfile::tempdir().map_err(StorageError::IO)?;
            let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)?;
            checkpoint.create_checkpoint(temp_dir.path())?;
            
            // Open the checkpoint for verification
            let opts = Options::default();
            let db = DB::open_cf(
                &opts,
                temp_dir.path(),
                vec![cf.to_string()],
            )?;
            
            // Verify each column family
            let cf_handle = db.cf_handle(&cf.to_string())
                .ok_or_else(|| StorageError::ColumnFamilyNotFound(cf.to_string()))?;
            
            // Iterate through all keys to check if they can be read
            let iter = db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
            for result in iter {
                if result.is_err() {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    fn cf_handle(&self, cf: impl AsColumnFamily) -> StorageResult<String> {
        let cf_name = cf.as_column_family().to_string();
        if self.db.cf_handle(&cf_name).is_some() {
            Ok(cf_name)
        } else {
            Err(StorageError::ColumnFamilyNotFound(cf_name))
        }
    }
}

/// Memory database implementation for testing
pub struct MemoryDatabase {
    /// In-memory data stored by column family and key
    data: parking_lot::RwLock<std::collections::HashMap<String, std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
    
    /// Column families
    column_families: Vec<(ColumnFamily, String)>,
    
    /// Database configuration
    config: StorageConfig,
}

impl MemoryDatabase {
    /// Creates a new in-memory database
    pub fn new(config: &StorageConfig) -> Self {
        // Define the column families we want to use
        let column_families = vec![
            ColumnFamily::Default,
            ColumnFamily::Blocks,
            ColumnFamily::Transactions,
            ColumnFamily::Objects,
            ColumnFamily::ObjectsByOwner,
            ColumnFamily::ObjectsByType,
            ColumnFamily::SuperpositionedObjects,
            ColumnFamily::BlockHeightIndex,
            ColumnFamily::TransactionBlockIndex,
            ColumnFamily::StateSnapshots,
            ColumnFamily::Metadata,
            ColumnFamily::Validators,
            ColumnFamily::ChainData,
            ColumnFamily::UncorruptedChains,
        ];
        
        // Initialize data with empty hashmaps for each column family
        let mut data = std::collections::HashMap::new();
        for cf in &column_families {
            data.insert(cf.to_string(), std::collections::HashMap::new());
        }
        
        let cf_handles = column_families
            .into_iter()
            .map(|cf| (cf, cf.to_string()))
            .collect();
        
        Self {
            data: parking_lot::RwLock::new(data),
            column_families: cf_handles,
            config: config.clone(),
        }
    }
    
    /// Gets the inner data for a column family
    fn get_cf_data(&self, cf: impl AsColumnFamily) -> StorageResult<String> {
        let cf_name = cf.as_column_family().to_string();
        
        // Check if the column family exists
        if !self.data.read().contains_key(&cf_name) {
            return Err(StorageError::ColumnFamilyNotFound(cf_name));
        }
        
        Ok(cf_name)
    }
}

impl Database for MemoryDatabase {
    fn get<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        let cf_name = self.get_cf_data(cf)?;
        let data = self.data.read();
        
        let cf_data = data.get(&cf_name).unwrap();
        let key_bytes = key.as_ref().to_vec();
        
        Ok(cf_data.get(&key_bytes).cloned())
    }
    
    fn get_object<K, V>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<Option<V>>
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned,
    {
        let data = self.get(cf, key)?;
        
        match data {
            Some(bytes) => {
                let obj = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Deserialization(e.to_string()))?;
                Ok(Some(obj))
            }
            None => Ok(None),
        }
    }
    
    fn exists<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<bool>
    where
        K: AsRef<[u8]>,
    {
        let cf_name = self.get_cf_data(cf)?;
        let data = self.data.read();
        
        let cf_data = data.get(&cf_name).unwrap();
        let key_bytes = key.as_ref().to_vec();
        
        Ok(cf_data.contains_key(&key_bytes))
    }
    
    fn put<K, V>(&self, cf: impl AsColumnFamily, key: K, value: V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let cf_name = self.get_cf_data(cf)?;
        let mut data = self.data.write();
        
        let cf_data = data.get_mut(&cf_name).unwrap();
        let key_bytes = key.as_ref().to_vec();
        let value_bytes = value.as_ref().to_vec();
        
        cf_data.insert(key_bytes, value_bytes);
        
        Ok(())
    }
    
    fn put_object<K, V>(&self, cf: impl AsColumnFamily, key: K, value: &V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: Serialize,
    {
        let serialized = bincode::serialize(value)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.put(cf, key, serialized)
    }
    
    fn delete<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
    {
        let cf_name = self.get_cf_data(cf)?;
        let mut data = self.data.write();
        
        let cf_data = data.get_mut(&cf_name).unwrap();
        let key_bytes = key.as_ref().to_vec();
        
        cf_data.remove(&key_bytes);
        
        Ok(())
    }
    
    fn execute_transaction(&self, transaction: &Transaction) -> StorageResult<()> {
        // For memory database, we just execute each operation in the transaction
        // This is not atomic but sufficient for testing
        
        // Parse operations from the batch
        // Note: This is a simplification and would need to be extended for a real implementation
        for op in transaction.batch.iter() {
            if let Some((cf_name, key, value)) = parse_write_batch_operation(op) {
                if !value.is_empty() {
                    // This is a put operation
                    self.put(cf_name, key, value)?;
                } else {
                    // This is a delete operation
                    self.delete(cf_name, key)?;
                }
            }
        }
        
        Ok(())
    }
    
    fn iterator(&self, cf: impl AsColumnFamily) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>> {
        let cf_name = self.get_cf_data(cf)?;
        let data = self.data.read();
        
        let cf_data = data.get(&cf_name).unwrap();
        
        // Clone the data for iteration
        let items: Vec<(Vec<u8>, Vec<u8>)> = cf_data
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        
        // Create an iterator that returns storage results
        let iter = items.into_iter().map(|item| Ok(item));
        
        Ok(Box::new(iter))
    }
    
    fn prefix_iterator<P>(&self, cf: impl AsColumnFamily, prefix: P) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>>
    where
        P: AsRef<[u8]>,
    {
        let cf_name = self.get_cf_data(cf)?;
        let data = self.data.read();
        
        let cf_data = data.get(&cf_name).unwrap();
        let prefix_bytes = prefix.as_ref().to_vec();
        
        // Filter and clone the data for iteration
        let items: Vec<(Vec<u8>, Vec<u8>)> = cf_data
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix_bytes))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        
        // Create an iterator that returns storage results
        let iter = items.into_iter().map(|item| Ok(item));
        
        Ok(Box::new(iter))
    }
    
    fn flush(&self) -> StorageResult<()> {
        // No-op for memory database
        Ok(())
    }
    
    fn compact(&self) -> StorageResult<()> {
        // No-op for memory database
        Ok(())
    }
    
    fn backup(&self, path: &Path) -> StorageResult<()> {
        // Create a simple JSON backup for memory database
        let data = self.data.read();
        
        // Serialize the entire database to JSON
        let json = serde_json::to_string(&*data)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        
        // Create the directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(path).map_err(StorageError::IO)?;
        }
        
        // Write the JSON to a file
        let backup_file = path.join("memory_db_backup.json");
        std::fs::write(backup_file, json).map_err(StorageError::IO)?;
        
        Ok(())
    }
    
    fn check_integrity(&self) -> StorageResult<bool> {
        // Memory database is always consistent
        Ok(true)
    }
    
    fn cf_handle(&self, cf: impl AsColumnFamily) -> StorageResult<String> {
        self.get_cf_data(cf)
    }
}

// Helper function to parse a write batch operation
// This is a simplified version and would need to be extended for a real implementation
fn parse_write_batch_operation(op: &[u8]) -> Option<(String, Vec<u8>, Vec<u8>)> {
    // This is a placeholder - in a real implementation, we would need to parse the
    // RocksDB write batch format to extract operations
    None
}

/// Creates a database instance based on the specified engine
pub fn create_database(engine: &str, config: &StorageConfig) -> Result<impl Database> {
    match engine {
        "rocksdb" => {
            RocksDatabase::open(config)
                .map_err(|e| AevorError::storage(format!("Failed to open RocksDB: {}", e)))
        }
        "memory" => {
            let db = MemoryDatabase::new(config);
            Ok(db)
        }
        _ => Err(AevorError::storage(format!("Unsupported database engine: {}", engine))),
    }
}

/// Restores a database from a backup
pub fn restore_database_from_backup(backup_path: &Path, db_path: &Path, engine: &str) -> Result<()> {
    match engine {
        "rocksdb" => {
            // RocksDB has a built-in backup and restore mechanism
            let backup_engine = rocksdb::backup::BackupEngine::open(
                &rocksdb::backup::BackupEngineOptions::default(),
                backup_path,
            )
            .map_err(|e| AevorError::storage(format!("Failed to open backup engine: {}", e)))?;
            
            // Restore from the latest backup
            let restore_options = rocksdb::backup::RestoreOptions::default();
            backup_engine
                .restore_from_latest_backup(db_path, db_path, &restore_options)
                .map_err(|e| AevorError::storage(format!("Failed to restore from backup: {}", e)))?;
            
            Ok(())
        }
        "memory" => {
            // For memory database, we just copy the backup file
            let backup_file = backup_path.join("memory_db_backup.json");
            if !backup_file.exists() {
                return Err(AevorError::storage("Backup file not found".to_string()));
            }
            
            // Create the target directory if it doesn't exist
            if !db_path.exists() {
                std::fs::create_dir_all(db_path)
                    .map_err(|e| AevorError::io(e))?;
            }
            
            // Copy the backup file
            let target_file = db_path.join("memory_db_backup.json");
            std::fs::copy(backup_file, target_file)
                .map_err(|e| AevorError::io(e))?;
            
            Ok(())
        }
        _ => Err(AevorError::storage(format!("Unsupported database engine: {}", engine))),
    }
}

impl From<rocksdb::Error> for StorageError {
    fn from(error: rocksdb::Error) -> Self {
        StorageError::RocksDB(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::collections::HashMap;
    use serde::{Deserialize, Serialize};
    
    // Test data type
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u32,
        name: String,
        value: f64,
    }
    
    // Helper function to create a test database
    fn create_test_database(engine: &str) -> (Box<dyn Database>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = StorageConfig::default();
        config.engine = engine.to_string();
        config.db_path = temp_dir.path().to_path_buf();
        
        let db = match engine {
            "rocksdb" => {
                let rocksdb = RocksDatabase::open(&config).unwrap();
                Box::new(rocksdb) as Box<dyn Database>
            }
            "memory" => {
                let memdb = MemoryDatabase::new(&config);
                Box::new(memdb) as Box<dyn Database>
            }
            _ => panic!("Unsupported database engine"),
        };
        
        (db, temp_dir)
    }
    
    #[test]
    fn test_memory_database_basic_operations() {
        let (db, _temp_dir) = create_test_database("memory");
        
        // Test put and get
        let key = b"test_key";
        let value = b"test_value";
        
        assert!(db.put(ColumnFamily::Default, key, value).is_ok());
        
        let result = db.get(ColumnFamily::Default, key).unwrap();
        assert_eq!(result, Some(value.to_vec()));
        
        // Test exists
        assert!(db.exists(ColumnFamily::Default, key).unwrap());
        assert!(!db.exists(ColumnFamily::Default, b"nonexistent").unwrap());
        
        // Test delete
        assert!(db.delete(ColumnFamily::Default, key).is_ok());
        assert!(!db.exists(ColumnFamily::Default, key).unwrap());
    }
    
    #[test]
    fn test_memory_database_object_operations() {
        let (db, _temp_dir) = create_test_database("memory");
        
        // Test object
        let test_obj = TestData {
            id: 1,
            name: "Test".to_string(),
            value: 3.14,
        };
        
        // Test put_object and get_object
        assert!(db.put_object(ColumnFamily::Default, b"test_obj", &test_obj).is_ok());
        
        let result: Option<TestData> = db.get_object(ColumnFamily::Default, b"test_obj").unwrap();
        assert_eq!(result, Some(test_obj));
    }
    
    #[test]
    fn test_memory_database_transaction() {
        let (db, _temp_dir) = create_test_database("memory");
        
        // Create a transaction
        let mut tx = db.transaction();
        
        // Add operations to the transaction
        tx.put(ColumnFamily::Default, b"tx_key1", b"tx_value1");
        tx.put(ColumnFamily::Default, b"tx_key2", b"tx_value2");
        
        // Execute the transaction
        assert!(db.execute_transaction(&tx).is_ok());
        
        // Verify the results
        assert_eq!(
            db.get(ColumnFamily::Default, b"tx_key1").unwrap(),
            Some(b"tx_value1".to_vec())
        );
        assert_eq!(
            db.get(ColumnFamily::Default, b"tx_key2").unwrap(),
            Some(b"tx_value2".to_vec())
        );
    }
    
    #[test]
    fn test_memory_database_iterator() {
        let (db, _temp_dir) = create_test_database("memory");
        
        // Insert some test data
        let test_data = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
            (b"key3".to_vec(), b"value3".to_vec()),
        ];
        
        for (key, value) in &test_data {
            db.put(ColumnFamily::Default, key, value).unwrap();
        }
        
        // Test iterator
        let mut items = Vec::new();
        for result in db.iterator(ColumnFamily::Default).unwrap() {
            items.push(result.unwrap());
        }
        
        // Sort for deterministic comparison
        items.sort_by(|a, b| a.0.cmp(&b.0));
        
        assert_eq!(items.len(), test_data.len());
        for (i, (key, value)) in items.iter().enumerate() {
            assert_eq!(key, &test_data[i].0);
            assert_eq!(value, &test_data[i].1);
        }
    }
    
    #[test]
    fn test_memory_database_prefix_iterator() {
        let (db, _temp_dir) = create_test_database("memory");
        
        // Insert some test data with prefixes
        let test_data = vec![
            (b"prefix1_key1".to_vec(), b"value1".to_vec()),
            (b"prefix1_key2".to_vec(), b"value2".to_vec()),
            (b"prefix2_key1".to_vec(), b"value3".to_vec()),
            (b"prefix2_key2".to_vec(), b"value4".to_vec()),
        ];
        
        for (key, value) in &test_data {
            db.put(ColumnFamily::Default, key, value).unwrap();
        }
        
        // Test prefix iterator for prefix1
        let mut prefix1_items = Vec::new();
        for result in db.prefix_iterator(ColumnFamily::Default, b"prefix1_").unwrap() {
            prefix1_items.push(result.unwrap());
        }
        
        // Sort for deterministic comparison
        prefix1_items.sort_by(|a, b| a.0.cmp(&b.0));
        
        assert_eq!(prefix1_items.len(), 2);
        assert_eq!(prefix1_items[0].0, b"prefix1_key1".to_vec());
        assert_eq!(prefix1_items[0].1, b"value1".to_vec());
        assert_eq!(prefix1_items[1].0, b"prefix1_key2".to_vec());
        assert_eq!(prefix1_items[1].1, b"value2".to_vec());
        
        // Test prefix iterator for prefix2
        let mut prefix2_items = Vec::new();
        for result in db.prefix_iterator(ColumnFamily::Default, b"prefix2_").unwrap() {
            prefix2_items.push(result.unwrap());
        }
        
        // Sort for deterministic comparison
        prefix2_items.sort_by(|a, b| a.0.cmp(&b.0));
        
        assert_eq!(prefix2_items.len(), 2);
        assert_eq!(prefix2_items[0].0, b"prefix2_key1".to_vec());
        assert_eq!(prefix2_items[0].1, b"value3".to_vec());
        assert_eq!(prefix2_items[1].0, b"prefix2_key2".to_vec());
        assert_eq!(prefix2_items[1].1, b"value4".to_vec());
    }
    
    // Only run the RocksDB tests if we're not in CI environment
    // as they may require specific OS dependencies
    #[cfg(not(feature = "ci"))]
    mod rocksdb_tests {
        use super::*;
        
        #[test]
        fn test_rocksdb_basic_operations() {
            let (db, _temp_dir) = create_test_database("rocksdb");
            
            // Test put and get
            let key = b"test_key";
            let value = b"test_value";
            
            assert!(db.put(ColumnFamily::Default, key, value).is_ok());
            
            let result = db.get(ColumnFamily::Default, key).unwrap();
            assert_eq!(result, Some(value.to_vec()));
            
            // Test exists
            assert!(db.exists(ColumnFamily::Default, key).unwrap());
            assert!(!db.exists(ColumnFamily::Default, b"nonexistent").unwrap());
            
            // Test delete
            assert!(db.delete(ColumnFamily::Default, key).is_ok());
            assert!(!db.exists(ColumnFamily::Default, key).unwrap());
        }
        
        #[test]
        fn test_rocksdb_object_operations() {
            let (db, _temp_dir) = create_test_database("rocksdb");
            
            // Test object
            let test_obj = TestData {
                id: 1,
                name: "Test".to_string(),
                value: 3.14,
            };
            
            // Test put_object and get_object
            assert!(db.put_object(ColumnFamily::Default, b"test_obj", &test_obj).is_ok());
            
            let result: Option<TestData> = db.get_object(ColumnFamily::Default, b"test_obj").unwrap();
            assert_eq!(result, Some(test_obj));
        }
        
        #[test]
        fn test_rocksdb_transaction() {
            let (db, _temp_dir) = create_test_database("rocksdb");
            
            // Create a transaction
            let mut tx = db.transaction();
            
            // Add operations to the transaction
            tx.put(ColumnFamily::Default, b"tx_key1", b"tx_value1");
            tx.put(ColumnFamily::Default, b"tx_key2", b"tx_value2");
            
            // Execute the transaction
            assert!(db.execute_transaction(&tx).is_ok());
            
            // Verify the results
            assert_eq!(
                db.get(ColumnFamily::Default, b"tx_key1").unwrap(),
                Some(b"tx_value1".to_vec())
            );
            assert_eq!(
                db.get(ColumnFamily::Default, b"tx_key2").unwrap(),
                Some(b"tx_value2".to_vec())
            );
        }
        
        #[test]
        fn test_rocksdb_flush_and_compact() {
            let (db, _temp_dir) = create_test_database("rocksdb");
            
            // Insert some test data
            for i in 0..100 {
                let key = format!("key{}", i).into_bytes();
                let value = format!("value{}", i).into_bytes();
                db.put(ColumnFamily::Default, key, value).unwrap();
            }
            
            // Test flush and compact operations
            assert!(db.flush().is_ok());
            assert!(db.compact().is_ok());
            
            // Verify data is still accessible
            let key = b"key50";
            let expected_value = b"value50".to_vec();
            assert_eq!(
                db.get(ColumnFamily::Default, key).unwrap(),
                Some(expected_value)
            );
        }
    }
}

    where
        K: AsRef<[u8]>,
        V: Serialize;
    
    /// Deletes a key from the database
    fn delete<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<()>
    where
        K: AsRef<[u8]>;
    
    /// Executes a transaction
    fn execute_transaction(&self, transaction: &Transaction) -> StorageResult<()>;
    
    /// Creates a new transaction
    fn transaction(&self) -> Transaction {
        Transaction::new()
    }
    
    /// Gets an iterator over a column family
    fn iterator(&self, cf: impl AsColumnFamily) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>>;
    
    /// Gets a prefix iterator over a column family
    fn prefix_iterator<P>(&self, cf: impl AsColumnFamily, prefix: P) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>>
    where
        P: AsRef<[u8]>;
    
    /// Flushes the database to disk
    fn flush(&self) -> StorageResult<()>;
    
    /// Compacts the database
    fn compact(&self) -> StorageResult<()>;
    
    /// Backups the database to the specified path
    fn backup(&self, path: &Path) -> StorageResult<()>;
    
    /// Checks the integrity of the database
    fn check_integrity(&self) -> StorageResult<bool>;
    
    /// Gets a column family handle
    fn cf_handle(&self, cf: impl AsColumnFamily) -> StorageResult<String>;
}

/// RocksDB implementation of the Database trait
pub struct RocksDatabase {
    /// RocksDB instance
    db: DB,
    
    /// Column family handles
    column_families: Vec<(ColumnFamily, String)>,
    
    /// Database configuration
    config: StorageConfig,
}

impl RocksDatabase {
    /// Opens a RocksDB database with the given configuration
    pub fn open(config: &StorageConfig) -> StorageResult<Self> {
        // Create the directory if it doesn't exist
        if !config.db_path.exists() && config.create_if_missing {
            std::fs::create_dir_all(&config.db_path)
                .map_err(|e| StorageError::IO(e))?;
        }
        
        // Define the column families we want to use
        let column_families = vec![
            ColumnFamily::Default,
            ColumnFamily::Blocks,
            ColumnFamily::Transactions,
            ColumnFamily::Objects,
            ColumnFamily::ObjectsByOwner,
            ColumnFamily::ObjectsByType,
            ColumnFamily::SuperpositionedObjects,
            ColumnFamily::BlockHeightIndex,
            ColumnFamily::TransactionBlockIndex,
            ColumnFamily::StateSnapshots,
            ColumnFamily::Metadata,
            ColumnFamily::Validators,
            ColumnFamily::ChainData,
            ColumnFamily::UncorruptedChains,
        ];
        
        // Create database options
        let mut options = Options::default();
        options.create_if_missing(config.create_if_missing);
        options.create_missing_column_families(config.create_if_missing);
        options.set_max_open_files(config.max_open_files);
        options.set_write_buffer_size(config.write_buffer_size);
        
        // Set cache size
        options.set_db_write_buffer_size(config.cache_size_mb * 1024 * 1024);
        
        // Enable compression if configured
        if config.compression_enabled {
            options.set_compression_type(rocksdb::DBCompressionType::Lz4);
        } else {
            options.set_compression_type(rocksdb::DBCompressionType::None);
        }
        
        // Prepare column family descriptors
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = column_families
            .iter()
            .map(|cf| {
                let mut cf_options = Options::default();
                cf_options.set_compression_type(if config.compression_enabled {
                    rocksdb::DBCompressionType::Lz4
                } else {
                    rocksdb::DBCompressionType::None
                });
                ColumnFamilyDescriptor::new(cf.to_string(), cf_options)
            })
            .collect();
        
        // Attempt to open the database with the defined column families
        let db = match DB::open_cf_descriptors(&options, &config.db_path, cf_descriptors) {
            Ok(db) => db,
            Err(e) => {
                // If the error is due to missing column families, try opening with default column family
                // and then create the missing ones
                if e.to_string().contains("Invalid argument: Column family not found") && config.create_if_missing {
                    let db = DB::open(&options, &config.db_path)?;
                    
                    // Create missing column families
                    for cf in &column_families {
                        if *cf != ColumnFamily::Default {
                            let _ = db.create_cf(cf.to_string(), &options);
                        }
                    }
                    
                    // Re-open with all column families
                    DB::open_cf_descriptors(&options, &config.db_path, cf_descriptors)?
                } else {
                    return Err(e.into());
                }
            }
        };
        
        // Prepare the column family handles
        let cf_handles = column_families
            .into_iter()
            .map(|cf| (cf, cf.to_string()))
            .collect();
        
        Ok(Self {
            db,
            column_families: cf_handles,
            config: config.clone(),
        })
    }
    
    /// Gets the actual RocksDB column family handle
    fn get_cf_handle(&self, cf: impl AsColumnFamily) -> StorageResult<&rocksdb::ColumnFamily> {
        let cf_name = cf.as_column_family().to_string();
        self.db
            .cf_handle(&cf_name)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(cf_name))
    }
}

impl Database for RocksDatabase {
    fn get<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        let cf_handle = self.get_cf_handle(cf)?;
        self.db
            .get_cf(cf_handle, key)
            .map_err(StorageError::from)
    }
    
    fn get_object<K, V>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<Option<V>>
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned,
    {
        let data = self.get(cf, key)?;
        
        match data {
            Some(bytes) => {
                let obj = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Deserialization(e.to_string()))?;
                Ok(Some(obj))
            }
            None => Ok(None),
        }
    }
    
    fn exists<K>(&self, cf: impl AsColumnFamily, key: K) -> StorageResult<bool>
    where
        K: AsRef<[u8]>,
    {
        let cf_handle = self.get_cf_handle(cf)?;
        
        // RocksDB doesn't have a direct exists method, so we use get with a nullptr value
        match self.db.get_pinned_cf(cf_handle, key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    
    fn put<K, V>(&self, cf: impl AsColumnFamily, key: K, value: V) -> StorageResult<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let cf_handle = self.get_cf_handle(cf)?;
        self.db
            .put_cf(cf_handle, key, value)
            .map_err(StorageError::from)
    }
    
    fn put_object<K, V>(&self, cf: impl AsColumnFamily, key: K, value: &V) -> StorageResult<()>
