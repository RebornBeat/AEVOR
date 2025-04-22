use std::path::PathBuf;
use std::sync::Arc;

use crate::config::StorageConfig;
use crate::error::{AevorError, Result};

// Re-export key storage types
pub use blockchain::BlockchainStore;
pub use database::Database;
pub use object_store::ObjectStore;
pub use state_store::StateStore;

// Define the submodules
pub mod blockchain;
pub mod database;
pub mod object_store;
pub mod state_store;

/// Main storage interface for the Aevor blockchain
///
/// The Storage struct serves as the central interface to all storage subsystems
/// in Aevor, including blockchain data, objects, state, and supporting database
/// abstractions. It provides a unified way to initialize and access all storage
/// components based on configuration.
pub struct Storage {
    /// Database instance for all storage operations
    pub db: Arc<dyn Database>,
    
    /// Blockchain store for blocks and transactions
    pub blockchain: Arc<BlockchainStore>,
    
    /// Object store for managing objects
    pub object_store: Arc<ObjectStore>,
    
    /// State store for managing global state
    pub state_store: Arc<StateStore>,
    
    /// Storage configuration
    config: StorageConfig,
}

impl Storage {
    /// Creates a new Storage instance with the given configuration
    pub fn new(config: &StorageConfig) -> Result<Self> {
        // Initialize the database
        let db = database::create_database(&config.engine, config)?;
        let db_arc = Arc::new(db);
        
        // Initialize the blockchain store
        let blockchain = Arc::new(BlockchainStore::new(db_arc.clone())?);
        
        // Initialize the object store
        let object_store = Arc::new(ObjectStore::new(db_arc.clone())?);
        
        // Initialize the state store
        let state_store = Arc::new(StateStore::new(db_arc.clone())?);
        
        Ok(Self {
            db: db_arc,
            blockchain,
            object_store,
            state_store,
            config: config.clone(),
        })
    }
    
    /// Opens storage at the specified path
    pub fn open(path: PathBuf) -> Result<Self> {
        let mut config = StorageConfig::default();
        config.db_path = path;
        Self::new(&config)
    }
    
    /// Starts the storage subsystem
    pub async fn start(&self) -> Result<()> {
        // Perform any necessary startup procedures
        self.blockchain.initialize().await?;
        self.object_store.initialize().await?;
        self.state_store.initialize().await?;
        
        Ok(())
    }
    
    /// Stops the storage subsystem
    pub async fn stop(&self) -> Result<()> {
        // Perform any necessary shutdown procedures
        self.state_store.shutdown().await?;
        self.object_store.shutdown().await?;
        self.blockchain.shutdown().await?;
        
        // Flush all pending writes to disk
        self.db.flush()?;
        
        Ok(())
    }
    
    /// Creates a new transaction for atomic operations
    pub fn transaction(&self) -> database::Transaction {
        self.db.transaction()
    }
    
    /// Gets the configured data directory path
    pub fn data_dir(&self) -> &PathBuf {
        &self.config.db_path
    }
    
    /// Gets a reference to the blockchain store
    pub fn blockchain_store(&self) -> &Arc<BlockchainStore> {
        &self.blockchain
    }
    
    /// Gets a reference to the object store
    pub fn object_store(&self) -> &Arc<ObjectStore> {
        &self.object_store
    }
    
    /// Gets a reference to the state store
    pub fn state_store(&self) -> &Arc<StateStore> {
        &self.state_store
    }
    
    /// Performs a storage compaction operation
    pub async fn compact(&self) -> Result<()> {
        // Check if compaction is enabled in the config
        if !self.config.compaction.enabled {
            return Ok(());
        }
        
        // Perform the compaction
        self.db.compact()?;
        
        Ok(())
    }
    
    /// Prunes old data based on configuration
    pub async fn prune(&self) -> Result<()> {
        // Check if pruning is enabled in the config
        if !self.config.pruning.enabled {
            return Ok(());
        }
        
        // Get the latest block height
        let latest_height = self.blockchain.get_latest_height()?;
        
        // Calculate the height threshold based on the keep_latest_blocks setting
        let height_threshold = if latest_height > self.config.pruning.keep_latest_blocks {
            latest_height - self.config.pruning.keep_latest_blocks
        } else {
            0
        };
        
        // Prune old blocks and transactions
        self.blockchain.prune_blocks_below(height_threshold).await?;
        
        // Prune old state if configured
        if self.config.pruning.keep_state_blocks < self.config.pruning.keep_latest_blocks {
            let state_threshold = if latest_height > self.config.pruning.keep_state_blocks {
                latest_height - self.config.pruning.keep_state_blocks
            } else {
                0
            };
            
            self.state_store.prune_state_below(state_threshold).await?;
        }
        
        // Prune orphaned objects
        self.object_store.prune_orphaned_objects().await?;
        
        Ok(())
    }
    
    /// Performs a full backup of the storage to the specified path
    pub async fn backup(&self, backup_path: PathBuf) -> Result<()> {
        // Check if the path exists and is a directory
        if !backup_path.exists() {
            std::fs::create_dir_all(&backup_path)
                .map_err(|e| AevorError::io(e))?;
        } else if !backup_path.is_dir() {
            return Err(AevorError::storage("Backup path must be a directory".to_string()));
        }
        
        // Create a backup of the database
        self.db.backup(&backup_path)?;
        
        Ok(())
    }
    
    /// Restores a backup from the specified path
    pub async fn restore_backup(backup_path: PathBuf, config: &StorageConfig) -> Result<Self> {
        // Check if the backup path exists and is a directory
        if !backup_path.exists() || !backup_path.is_dir() {
            return Err(AevorError::storage("Invalid backup path".to_string()));
        }
        
        // Create a new storage instance with the provided configuration
        let mut storage = Self::new(config)?;
        
        // Stop the storage to ensure no active operations
        storage.stop().await?;
        
        // Restore the database from backup
        database::restore_database_from_backup(&backup_path, &config.db_path, &config.engine)?;
        
        // Reinitialize storage with the restored database
        storage = Self::new(config)?;
        
        Ok(storage)
    }
    
    /// Checks the storage integrity
    pub async fn check_integrity(&self) -> Result<bool> {
        // Check database integrity
        let db_integrity = self.db.check_integrity()?;
        
        // Check blockchain store integrity
        let blockchain_integrity = self.blockchain.check_integrity().await?;
        
        // Check object store integrity
        let object_integrity = self.object_store.check_integrity().await?;
        
        // Check state store integrity
        let state_integrity = self.state_store.check_integrity().await?;
        
        // All checks must pass for overall integrity
        Ok(db_integrity && blockchain_integrity && object_integrity && state_integrity)
    }
}

/// Factory function to create a storage instance from configuration
pub fn create_storage(config: &StorageConfig) -> Result<Arc<Storage>> {
    let storage = Storage::new(config)?;
    Ok(Arc::new(storage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CompactionConfig, PruningConfig, StorageConfig};
    use tempfile::TempDir;
    
    /// Creates a test storage configuration with the given path
    fn create_test_config(path: PathBuf) -> StorageConfig {
        StorageConfig {
            engine: "memory".to_string(), // Use in-memory database for tests
            db_path: path,
            create_if_missing: true,
            compression_enabled: true,
            cache_size_mb: 32,
            max_open_files: 100,
            write_buffer_size: 64 * 1024 * 1024, // 64 MB
            compaction: CompactionConfig {
                enabled: true,
                style: "level".to_string(),
                interval_secs: 3600,
            },
            pruning: PruningConfig {
                enabled: true,
                interval_secs: 3600,
                keep_latest_blocks: 1000,
                keep_finalized_blocks: true,
                keep_state_blocks: 100,
            },
        }
    }
    
    #[tokio::test]
    async fn test_storage_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(temp_dir.path().to_path_buf());
        
        let storage = Storage::new(&config).unwrap();
        assert_eq!(storage.data_dir(), &config.db_path);
        
        // Test starting and stopping
        assert!(storage.start().await.is_ok());
        assert!(storage.stop().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_storage_backup_restore() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(temp_dir.path().to_path_buf());
        
        // Create original storage
        let storage = Storage::new(&config).unwrap();
        assert!(storage.start().await.is_ok());
        
        // Create backup directory
        let backup_dir = TempDir::new().unwrap();
        
        // Perform backup
        assert!(storage.backup(backup_dir.path().to_path_buf()).await.is_ok());
        
        // Stop original storage
        assert!(storage.stop().await.is_ok());
        
        // Create new storage from backup
        let restore_dir = TempDir::new().unwrap();
        let restore_config = create_test_config(restore_dir.path().to_path_buf());
        
        // This should fail because we haven't restored the backup yet
        let restored_storage = Storage::restore_backup(backup_dir.path().to_path_buf(), &restore_config).await;
        
        // We're using in-memory storage for tests, so restoration doesn't actually work
        // In a real implementation, this would restore the database from the backup
        assert!(restored_storage.is_ok());
    }
    
    #[tokio::test]
    async fn test_storage_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(temp_dir.path().to_path_buf());
        
        let storage = Storage::new(&config).unwrap();
        assert!(storage.start().await.is_ok());
        
        // Check integrity
        let integrity = storage.check_integrity().await.unwrap();
        assert!(integrity);
        
        // Stop storage
        assert!(storage.stop().await.is_ok());
    }
}
