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

    /// Enumerate all live key-value pairs.
    ///
    /// Used for authenticated-state reconstruction on startup and for state
    /// sync when a node joins.
    ///
    /// # Errors
    /// Returns an error if the underlying store cannot be read.
    fn scan(&self) -> StorageResult<Vec<(StorageKey, StorageValue)>>;
}

/// Append-only, log-structured backend — a pure-Rust durable key-value store
/// (no C/C++ dependency), tuned for AEVOR's access pattern: uniformly-hashed
/// keys, point lookups, write-heavy, atomic batch commit.
///
/// Design (Bitcask-family):
/// - **Writes** are sequential appends to a single log file — no write
///   amplification, no tree rebalancing, no compaction on the hot path.
/// - **Reads** are an in-memory index lookup (`key → (offset, len)`) plus one
///   positioned read of the value from disk (lock-free `read_at` on Unix), so
///   the value bytes never sit in RAM.
/// - **Durability & crash recovery:** every write group is followed by a commit
///   marker carrying a CRC over the group. On open, the log is replayed and
///   truncated at the last valid committed marker, so a torn tail from a crash
///   is discarded atomically (all-or-nothing per batch).
/// - **Compaction** ([`compact`](LogBackend::compact)) rewrites the log with
///   only live values, off the write path.
///
/// Record framing (little-endian):
/// - data:   `[1][key_len:u32][key][val_len:u32][value]`
/// - delete: `[2][key_len:u32][key]`
/// - commit: `[3][crc32:u32]` — CRC over all record bytes since the previous commit
pub struct LogBackend {
    path: std::path::PathBuf,
    writer: std::fs::File,
    reader: std::fs::File,
    index: std::collections::HashMap<Vec<u8>, ValueLoc>,
    write_offset: u64,
}

#[derive(Clone, Copy)]
struct ValueLoc {
    offset: u64,
    len: u32,
}

const TAG_DATA: u8 = 1;
const TAG_DELETE: u8 = 2;
const TAG_COMMIT: u8 = 3;

fn backend_err(e: &std::io::Error) -> crate::StorageError {
    crate::StorageError::BackendError(e.to_string())
}

/// CRC-32/IEEE (pure Rust, no dependency) for detecting torn log records.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn take_u32(bytes: &[u8], i: &mut usize) -> Option<u32> {
    let slice = bytes.get(*i..*i + 4)?;
    *i += 4;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Some(u32::from_le_bytes(buf))
}

fn take_slice<'a>(bytes: &'a [u8], i: &mut usize, len: usize) -> Option<&'a [u8]> {
    let slice = bytes.get(*i..*i + len)?;
    *i += len;
    Some(slice)
}

/// Read `len` bytes at `offset` without disturbing any cursor. Lock-free on Unix
/// (`read_at`); portable elsewhere via a cloned handle.
fn read_value_at(reader: &std::fs::File, offset: u64, len: usize) -> StorageResult<Vec<u8>> {
    let mut buf = vec![0u8; len];
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        reader.read_at(&mut buf, offset).map_err(|e| backend_err(&e))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut r = reader.try_clone().map_err(|e| backend_err(&e))?;
        r.seek(SeekFrom::Start(offset)).map_err(|e| backend_err(&e))?;
        r.read_exact(&mut buf).map_err(|e| backend_err(&e))?;
    }
    Ok(buf)
}

impl LogBackend {
    /// Open (or create) a log-backed database at the path in `config`, replaying
    /// and repairing (truncating any torn tail) the existing log.
    ///
    /// # Errors
    /// Returns a backend error if the path cannot be created or the log cannot
    /// be read/opened.
    #[allow(clippy::needless_pass_by_value)] // a constructor taking owned config is idiomatic
    pub fn open(config: BackendConfig) -> StorageResult<Self> {
        let path = config.path.clone();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| backend_err(&e))?;
            }
        }

        let mut index = std::collections::HashMap::new();
        let mut committed_len = 0u64;
        if path.exists() {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(&path)
                .map_err(|e| backend_err(&e))?
                .read_to_end(&mut bytes)
                .map_err(|e| backend_err(&e))?;
            committed_len = Self::replay(&bytes, &mut index);
            // Discard any torn/uncommitted tail so future appends stay clean.
            if committed_len < bytes.len() as u64 {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|e| backend_err(&e))?;
                f.set_len(committed_len).map_err(|e| backend_err(&e))?;
            }
        }

        let writer = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| backend_err(&e))?;
        let reader = std::fs::File::open(&path).map_err(|e| backend_err(&e))?;
        Ok(Self {
            path,
            writer,
            reader,
            index,
            write_offset: committed_len,
        })
    }

    /// Replay the log, applying only fully-committed batches; returns the byte
    /// length of the valid committed prefix.
    fn replay(bytes: &[u8], index: &mut std::collections::HashMap<Vec<u8>, ValueLoc>) -> u64 {
        let mut i = 0usize;
        let mut committed_end = 0usize;
        let mut batch: Vec<(Vec<u8>, Option<ValueLoc>)> = Vec::new();
        let mut batch_start = 0usize;

        loop {
            let rec_start = i;
            let Some(&tag) = bytes.get(i) else { break };
            i += 1;
            match tag {
                TAG_DATA => {
                    let Some(klen) = take_u32(bytes, &mut i) else { break };
                    let Some(key) = take_slice(bytes, &mut i, klen as usize) else { break };
                    let Some(vlen) = take_u32(bytes, &mut i) else { break };
                    let value_offset = i as u64;
                    if take_slice(bytes, &mut i, vlen as usize).is_none() {
                        break;
                    }
                    batch.push((
                        key.to_vec(),
                        Some(ValueLoc { offset: value_offset, len: vlen }),
                    ));
                }
                TAG_DELETE => {
                    let Some(klen) = take_u32(bytes, &mut i) else { break };
                    let Some(key) = take_slice(bytes, &mut i, klen as usize) else { break };
                    batch.push((key.to_vec(), None));
                }
                TAG_COMMIT => {
                    let Some(crc) = take_u32(bytes, &mut i) else { break };
                    let group = &bytes[batch_start..rec_start];
                    if crc32(group) != crc {
                        break; // corrupt group → stop; prefix up to here is valid
                    }
                    for (k, loc) in batch.drain(..) {
                        match loc {
                            Some(l) => {
                                index.insert(k, l);
                            }
                            None => {
                                index.remove(&k);
                            }
                        }
                    }
                    committed_end = i;
                    batch_start = i;
                }
                _ => break,
            }
        }
        committed_end as u64
    }

    /// Append a batch of operations as one atomically-committed group.
    fn append_batch(&mut self, ops: &[(Vec<u8>, Option<Vec<u8>>)]) -> StorageResult<()> {
        use std::io::Write;
        let base = self.write_offset;
        let mut buf: Vec<u8> = Vec::new();
        let mut locs: Vec<(Vec<u8>, Option<ValueLoc>)> = Vec::new();

        for (key, val) in ops {
            let klen = u32::try_from(key.len())
                .map_err(|_| crate::StorageError::BackendError("key too large".into()))?;
            if let Some(v) = val {
                let vlen = u32::try_from(v.len())
                    .map_err(|_| crate::StorageError::BackendError("value too large".into()))?;
                buf.push(TAG_DATA);
                buf.extend_from_slice(&klen.to_le_bytes());
                buf.extend_from_slice(key);
                buf.extend_from_slice(&vlen.to_le_bytes());
                let value_offset = base + buf.len() as u64;
                buf.extend_from_slice(v);
                locs.push((key.clone(), Some(ValueLoc { offset: value_offset, len: vlen })));
            } else {
                buf.push(TAG_DELETE);
                buf.extend_from_slice(&klen.to_le_bytes());
                buf.extend_from_slice(key);
                locs.push((key.clone(), None));
            }
        }

        // Commit marker: CRC over the group's record bytes.
        let crc = crc32(&buf);
        buf.push(TAG_COMMIT);
        buf.extend_from_slice(&crc.to_le_bytes());

        self.writer.write_all(&buf).map_err(|e| backend_err(&e))?;
        self.write_offset += buf.len() as u64;

        for (k, loc) in locs {
            match loc {
                Some(l) => {
                    self.index.insert(k, l);
                }
                None => {
                    self.index.remove(&k);
                }
            }
        }
        Ok(())
    }

    /// Atomically commit a batch of writes/deletes (the block-commit primitive:
    /// all operations persist together or, on crash, none do).
    ///
    /// # Errors
    /// Returns a backend error if the log write fails.
    pub fn commit_batch(
        &mut self,
        ops: Vec<(StorageKey, Option<StorageValue>)>,
    ) -> StorageResult<()> {
        let mapped: Vec<(Vec<u8>, Option<Vec<u8>>)> =
            ops.into_iter().map(|(k, v)| (k.0, v.map(|x| x.0))).collect();
        self.append_batch(&mapped)
    }

    /// Rewrite the log with only live values, reclaiming space from overwrites
    /// and tombstones. Off the write path.
    ///
    /// # Errors
    /// Returns a backend error if the temporary log cannot be written, the
    /// rename fails, or the reopen fails.
    pub fn compact(&mut self) -> StorageResult<()> {
        use std::io::Write;
        // Read all live values (from disk) into a single fresh batch.
        let mut buf: Vec<u8> = Vec::new();
        for (k, loc) in &self.index {
            let v = read_value_at(&self.reader, loc.offset, loc.len as usize)?;
            let klen = u32::try_from(k.len())
                .map_err(|_| crate::StorageError::BackendError("key too large".into()))?;
            buf.push(TAG_DATA);
            buf.extend_from_slice(&klen.to_le_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(&loc.len.to_le_bytes());
            buf.extend_from_slice(&v);
        }
        let crc = crc32(&buf);
        buf.push(TAG_COMMIT);
        buf.extend_from_slice(&crc.to_le_bytes());

        let tmp = self.path.with_extension("compact");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| backend_err(&e))?;
            f.write_all(&buf).map_err(|e| backend_err(&e))?;
            f.sync_all().map_err(|e| backend_err(&e))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| backend_err(&e))?;

        // Reopen to rebuild the offset index against the compacted file.
        let reopened = Self::open(BackendConfig {
            path: self.path.clone(),
            ..BackendConfig::default()
        })?;
        *self = reopened;
        Ok(())
    }

    /// Number of live keys.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.index.len()
    }

    /// The filesystem path of this database's log.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl StorageBackend for LogBackend {
    fn get(&self, key: &StorageKey) -> StorageResult<Option<StorageValue>> {
        match self.index.get(key.as_bytes()) {
            Some(loc) => Ok(Some(StorageValue(read_value_at(
                &self.reader,
                loc.offset,
                loc.len as usize,
            )?))),
            None => Ok(None),
        }
    }

    fn put(&mut self, key: StorageKey, value: StorageValue) -> StorageResult<()> {
        self.append_batch(&[(key.0, Some(value.0))])
    }

    fn delete(&mut self, key: &StorageKey) -> StorageResult<()> {
        self.append_batch(&[(key.as_bytes().to_vec(), None)])
    }

    fn flush(&mut self) -> StorageResult<()> {
        self.writer.sync_all().map_err(|e| backend_err(&e))
    }

    fn scan(&self) -> StorageResult<Vec<(StorageKey, StorageValue)>> {
        let mut out = Vec::with_capacity(self.index.len());
        for (key, loc) in &self.index {
            let value = read_value_at(&self.reader, loc.offset, loc.len as usize)?;
            out.push((StorageKey::from_bytes(key.clone()), StorageValue(value)));
        }
        Ok(out)
    }
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

    fn scan(&self) -> StorageResult<Vec<(StorageKey, StorageValue)>> {
        Ok(self
            .data
            .iter()
            .map(|(k, v)| (StorageKey::from_bytes(k.clone()), v.clone()))
            .collect())
    }
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

    // ── LogBackend (pure-Rust durable, log-structured) ─────────

    fn temp_cfg(name: &str) -> BackendConfig {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "aevor-logbackend-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        BackendConfig { path: dir, ..BackendConfig::default() }
    }

    #[test]
    fn log_backend_put_get_delete() {
        let cfg = temp_cfg("crud");
        let mut b = LogBackend::open(cfg.clone()).unwrap();
        b.put(key(1), StorageValue(b"hello".to_vec())).unwrap();
        assert_eq!(b.get(&key(1)).unwrap().unwrap().as_bytes(), b"hello");
        // Overwrite.
        b.put(key(1), StorageValue(b"world".to_vec())).unwrap();
        assert_eq!(b.get(&key(1)).unwrap().unwrap().as_bytes(), b"world");
        // Delete.
        b.delete(&key(1)).unwrap();
        assert!(b.get(&key(1)).unwrap().is_none());
        let _ = std::fs::remove_file(&cfg.path);
    }

    #[test]
    fn log_backend_persists_across_reopen() {
        // The whole point: data survives a process restart via log replay.
        let cfg = temp_cfg("durable");
        {
            let mut b = LogBackend::open(cfg.clone()).unwrap();
            b.put(key(1), StorageValue(b"alpha".to_vec())).unwrap();
            b.put(key(2), StorageValue(b"beta".to_vec())).unwrap();
            b.delete(&key(1)).unwrap();
            b.flush().unwrap();
        }
        // Reopen — index is rebuilt from the log.
        let b = LogBackend::open(cfg.clone()).unwrap();
        assert!(b.get(&key(1)).unwrap().is_none()); // deleted
        assert_eq!(b.get(&key(2)).unwrap().unwrap().as_bytes(), b"beta");
        assert_eq!(b.entry_count(), 1);
        let _ = std::fs::remove_file(&cfg.path);
    }

    #[test]
    fn log_backend_atomic_batch_commit() {
        let cfg = temp_cfg("batch");
        {
            let mut b = LogBackend::open(cfg.clone()).unwrap();
            b.commit_batch(vec![
                (key(1), Some(StorageValue(b"one".to_vec()))),
                (key(2), Some(StorageValue(b"two".to_vec()))),
                (key(3), Some(StorageValue(b"three".to_vec()))),
            ])
            .unwrap();
            b.flush().unwrap();
        }
        let b = LogBackend::open(cfg.clone()).unwrap();
        assert_eq!(b.get(&key(2)).unwrap().unwrap().as_bytes(), b"two");
        assert_eq!(b.entry_count(), 3);
        let _ = std::fs::remove_file(&cfg.path);
    }

    #[test]
    fn log_backend_recovers_from_torn_tail() {
        // Simulate a crash mid-write: append garbage after a valid commit.
        let cfg = temp_cfg("torn");
        {
            let mut b = LogBackend::open(cfg.clone()).unwrap();
            b.put(key(1), StorageValue(b"good".to_vec())).unwrap();
            b.flush().unwrap();
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&cfg.path).unwrap();
            f.write_all(&[TAG_DATA, 9, 9, 9, 9]).unwrap(); // truncated/garbage record
        }
        // Reopen must discard the torn tail and keep the committed value.
        let b = LogBackend::open(cfg.clone()).unwrap();
        assert_eq!(b.get(&key(1)).unwrap().unwrap().as_bytes(), b"good");
        assert_eq!(b.entry_count(), 1);
        let _ = std::fs::remove_file(&cfg.path);
    }

    #[test]
    fn log_backend_compaction_preserves_live_state() {
        let cfg = temp_cfg("compact");
        let mut b = LogBackend::open(cfg.clone()).unwrap();
        for i in 0..10u8 {
            b.put(key(i), StorageValue(vec![i; 100])).unwrap();
        }
        // Overwrite and delete some to create garbage.
        b.put(key(0), StorageValue(vec![0xEE; 50])).unwrap();
        b.delete(&key(5)).unwrap();
        b.compact().unwrap();
        assert_eq!(b.entry_count(), 9);
        assert_eq!(b.get(&key(0)).unwrap().unwrap().as_bytes(), &vec![0xEE; 50][..]);
        assert!(b.get(&key(5)).unwrap().is_none());
        assert_eq!(b.get(&key(9)).unwrap().unwrap().as_bytes(), &vec![9u8; 100][..]);
        let _ = std::fs::remove_file(&cfg.path);
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
