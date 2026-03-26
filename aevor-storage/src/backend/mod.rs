//! Storage backend abstraction: RocksDB and in-memory implementations.

use serde::{Deserialize, Serialize};
use aevor_core::storage::{StorageKey, StorageValue};
use crate::StorageResult;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendConfig {
    pub path: std::path::PathBuf,
    pub cache_size_bytes: usize,
    pub write_buffer_size_bytes: usize,
    pub max_open_files: i32,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            path: std::path::PathBuf::from("./aevor-data"),
            cache_size_bytes: 256 * 1024 * 1024,
            write_buffer_size_bytes: 64 * 1024 * 1024,
            max_open_files: 1000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteOptions {
    pub sync: bool,
    pub disable_wal: bool,
}

impl Default for WriteOptions {
    fn default() -> Self { Self { sync: false, disable_wal: false } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadOptions {
    pub verify_checksums: bool,
    pub fill_cache: bool,
}

impl Default for ReadOptions {
    fn default() -> Self { Self { verify_checksums: true, fill_cache: true } }
}

/// Core trait for storage backends.
pub trait StorageBackend: Send + Sync {
    fn get(&self, key: &StorageKey) -> StorageResult<Option<StorageValue>>;
    fn put(&mut self, key: StorageKey, value: StorageValue) -> StorageResult<()>;
    fn delete(&mut self, key: &StorageKey) -> StorageResult<()>;
    fn flush(&mut self) -> StorageResult<()>;
}

/// RocksDB backend (placeholder — full implementation uses rocksdb crate).
pub struct RocksDbBackend {
    config: BackendConfig,
    // rocksdb::DB would go here in full implementation
}

impl RocksDbBackend {
    /// Open (or create) a RocksDB database at the path in `config`.
    pub fn open(config: BackendConfig) -> StorageResult<Self> {
        Ok(Self { config })
    }

    /// The configuration this backend was opened with.
    pub fn config(&self) -> &BackendConfig { &self.config }

    /// The filesystem path of this database.
    pub fn path(&self) -> &std::path::Path { &self.config.path }
}

impl StorageBackend for RocksDbBackend {
    fn get(&self, _key: &StorageKey) -> StorageResult<Option<StorageValue>> { Ok(None) }
    fn put(&mut self, _key: StorageKey, _value: StorageValue) -> StorageResult<()> { Ok(()) }
    fn delete(&mut self, _key: &StorageKey) -> StorageResult<()> { Ok(()) }
    fn flush(&mut self) -> StorageResult<()> { Ok(()) }
}

/// In-memory backend for testing.
pub struct MemoryBackend {
    data: std::collections::HashMap<Vec<u8>, StorageValue>,
}

impl MemoryBackend {
    pub fn new() -> Self { Self { data: std::collections::HashMap::new() } }
    pub fn entry_count(&self) -> usize { self.data.len() }
}

impl Default for MemoryBackend {
    fn default() -> Self { Self::new() }
}

impl StorageBackend for MemoryBackend {
    fn get(&self, key: &StorageKey) -> StorageResult<Option<StorageValue>> {
        Ok(self.data.get(&key.0).cloned())
    }
    fn put(&mut self, key: StorageKey, value: StorageValue) -> StorageResult<()> {
        self.data.insert(key.0, value);
        Ok(())
    }
    fn delete(&mut self, key: &StorageKey) -> StorageResult<()> {
        self.data.remove(&key.0);
        Ok(())
    }
    fn flush(&mut self) -> StorageResult<()> { Ok(()) }
}
