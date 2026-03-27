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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WriteOptions {
    pub sync: bool,
    pub disable_wal: bool,
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
    /// Retrieve the value for a key.
    ///
    /// # Errors
    /// Returns an error if the underlying storage read fails.
    fn get(&self, key: &StorageKey) -> StorageResult<Option<StorageValue>>;

    /// Write a key-value pair.
    ///
    /// # Errors
    /// Returns an error if the underlying storage write fails.
    fn put(&mut self, key: StorageKey, value: StorageValue) -> StorageResult<()>;

    /// Delete a key.
    ///
    /// # Errors
    /// Returns an error if the underlying storage delete fails.
    fn delete(&mut self, key: &StorageKey) -> StorageResult<()>;

    /// Flush all pending writes to durable storage.
    ///
    /// # Errors
    /// Returns an error if the flush cannot be completed.
    fn flush(&mut self) -> StorageResult<()>;
}

/// `RocksDB` backend (placeholder — full implementation uses rocksdb crate).
pub struct RocksDbBackend {
    config: BackendConfig,
    // rocksdb::DB would go here in full implementation
}

impl RocksDbBackend {
    /// Open (or create) a `RocksDB` database at the path in `config`.
    ///
    /// # Errors
    /// Returns an error if the database path cannot be created or the
    /// `RocksDB` options are invalid.
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::storage::{StorageKey, StorageValue};

    fn key(n: u8) -> StorageKey { StorageKey(vec![n]) }
    fn val(n: u8) -> StorageValue { StorageValue(vec![n]) }

    // ── BackendConfig ──────────────────────────────────────────

    #[test]
    fn backend_config_default_path_and_sizes() {
        let cfg = BackendConfig::default();
        assert!(cfg.path.to_string_lossy().contains("aevor-data"));
        assert!(cfg.cache_size_bytes > 0);
        assert!(cfg.write_buffer_size_bytes > 0);
        assert!(cfg.max_open_files > 0);
    }

    // ── WriteOptions / ReadOptions ─────────────────────────────

    #[test]
    fn write_options_default_no_sync_no_wal_disable() {
        let opts = WriteOptions::default();
        assert!(!opts.sync);
        assert!(!opts.disable_wal);
    }

    #[test]
    fn read_options_default_verify_checksums_and_fill_cache() {
        let opts = ReadOptions::default();
        assert!(opts.verify_checksums);
        assert!(opts.fill_cache);
    }

    // ── RocksDbBackend stubs ───────────────────────────────────

    #[test]
    fn rocksdb_open_returns_ok() {
        let cfg = BackendConfig::default();
        let path = cfg.path.clone();
        let backend = RocksDbBackend::open(cfg).unwrap();
        assert_eq!(backend.path(), &path);
    }

    #[test]
    fn rocksdb_get_returns_none_stub() {
        let backend = RocksDbBackend::open(BackendConfig::default()).unwrap();
        let result = backend.get(&key(1)).unwrap();
        assert!(result.is_none());
    }

    // ── MemoryBackend (fully functional) ──────────────────────

    #[test]
    fn memory_backend_put_and_get() {
        let mut b = MemoryBackend::new();
        b.put(key(1), val(42)).unwrap();
        assert_eq!(b.get(&key(1)).unwrap(), Some(val(42)));
        assert_eq!(b.entry_count(), 1);
    }

    #[test]
    fn memory_backend_get_missing_returns_none() {
        let b = MemoryBackend::default();
        assert_eq!(b.get(&key(99)).unwrap(), None);
    }

    #[test]
    fn memory_backend_delete_removes_key() {
        let mut b = MemoryBackend::new();
        b.put(key(1), val(1)).unwrap();
        b.delete(&key(1)).unwrap();
        assert_eq!(b.get(&key(1)).unwrap(), None);
        assert_eq!(b.entry_count(), 0);
    }

    #[test]
    fn memory_backend_delete_missing_key_is_noop() {
        let mut b = MemoryBackend::new();
        // delete of missing key must not error
        b.delete(&key(99)).unwrap();
    }

    #[test]
    fn memory_backend_overwrite_existing_key() {
        let mut b = MemoryBackend::new();
        b.put(key(1), val(10)).unwrap();
        b.put(key(1), val(20)).unwrap();
        assert_eq!(b.get(&key(1)).unwrap(), Some(val(20)));
        assert_eq!(b.entry_count(), 1);
    }

    #[test]
    fn memory_backend_flush_is_noop_ok() {
        let mut b = MemoryBackend::new();
        b.put(key(1), val(1)).unwrap();
        b.flush().unwrap();
        // data still accessible after flush
        assert_eq!(b.get(&key(1)).unwrap(), Some(val(1)));
    }
}
