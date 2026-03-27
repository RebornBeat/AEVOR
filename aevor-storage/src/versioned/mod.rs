//! Versioned state with MVCC (Multi-Version Concurrency Control) for parallel execution.
//!
//! Each transaction operates on a snapshot of state at a specific version.
//! Conflicting writes are detected via optimistic locking before commit.

use serde::{Deserialize, Serialize};
pub use aevor_core::storage::VersionedState;
pub use aevor_core::state::StateVersion;
use aevor_core::storage::{StorageKey, StorageValue, StateRoot};

/// Versioned object store: maintains a history of state roots indexed by version number.
///
/// `StorageValue` is used to represent the raw bytes read/written at a specific version,
/// enabling callers to diff values across versions for conflict detection.
pub struct VersionedObjectStore {
    current_version: u64,
    snapshots: std::collections::BTreeMap<u64, StateRoot>,
    /// Latest value written for each key, keyed by version.
    writes: std::collections::BTreeMap<u64, std::collections::HashMap<Vec<u8>, StorageValue>>,
}

impl VersionedObjectStore {
    /// Create an empty versioned store starting at version 0.
    pub fn new() -> Self {
        Self {
            current_version: 0,
            snapshots: std::collections::BTreeMap::new(),
            writes: std::collections::BTreeMap::new(),
        }
    }

    /// Current version number.
    pub fn current_version(&self) -> u64 { self.current_version }

    /// State root at the given version, if it exists.
    pub fn snapshot_root(&self, version: u64) -> Option<StateRoot> {
        self.snapshots.get(&version).copied()
    }

    /// Commit a new version with the given state root and writes.
    pub fn advance(&mut self, new_root: StateRoot, writes: Vec<(StorageKey, StorageValue)>) -> u64 {
        self.current_version += 1;
        self.snapshots.insert(self.current_version, new_root);
        let write_map: std::collections::HashMap<Vec<u8>, StorageValue> = writes
            .into_iter()
            .map(|(k, v)| (k.0, v))
            .collect();
        self.writes.insert(self.current_version, write_map);
        self.current_version
    }

    /// Retrieve the value written for `key` at `version`, if any.
    pub fn read_at(&self, key: &StorageKey, version: u64) -> Option<&StorageValue> {
        self.writes.get(&version)?.get(key.0.as_slice())
    }

    /// Check whether two versions wrote conflicting values for the same key.
    ///
    /// Returns the conflicting key if found, or `None` if the versions are compatible.
    pub fn detect_conflict(&self, v1: u64, v2: u64) -> Option<StorageKey> {
        let w1 = self.writes.get(&v1)?;
        let w2 = self.writes.get(&v2)?;
        for (key_bytes, val1) in w1 {
            if let Some(val2) = w2.get(key_bytes) {
                if val1.0 != val2.0 {
                    return Some(StorageKey(key_bytes.clone()));
                }
            }
        }
        None
    }
}

impl Default for VersionedObjectStore {
    fn default() -> Self { Self::new() }
}

/// Optimistic lock for a specific object version.
///
/// Before committing, the caller verifies the object is still at `expected_version`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptimisticLock {
    /// Key being locked.
    pub key: StorageKey,
    /// Version the caller read — must still be current at commit time.
    pub expected_version: u64,
}

/// Validates optimistic locks before committing a transaction.
pub struct ConcurrencyControl;

impl ConcurrencyControl {
    /// Returns `true` if `actual_version` matches the lock's expected version.
    ///
    /// If `false`, the transaction must be retried.
    pub fn check_lock(lock: &OptimisticLock, actual_version: u64) -> bool {
        lock.expected_version == actual_version
    }

    /// Check all locks in a batch. Returns the first failing lock, if any.
    pub fn check_all<'a>(
        locks: &'a [OptimisticLock],
        actual_versions: &std::collections::HashMap<Vec<u8>, u64>,
    ) -> Option<&'a OptimisticLock> {
        locks.iter().find(|lock| {
            let actual = actual_versions.get(lock.key.0.as_slice()).copied().unwrap_or(0);
            !Self::check_lock(lock, actual)
        })
    }
}

/// Records the outcome of a conflict between two concurrent transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictResolution {
    /// Version that won (committed first or had higher priority).
    pub winner_version: u64,
    /// Version that lost (must be retried).
    pub loser_version: u64,
}

impl ConflictResolution {
    /// Create a resolution, with the lower version number as winner (first-write-wins).
    pub fn first_write_wins(v1: u64, v2: u64) -> Self {
        let (winner, loser) = if v1 < v2 { (v1, v2) } else { (v2, v1) };
        Self { winner_version: winner, loser_version: loser }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::storage::{StorageKey, StorageValue, StateRoot};

    fn key(n: u8) -> StorageKey { StorageKey(vec![n]) }
    fn val(n: u8) -> StorageValue { StorageValue::from_bytes(vec![n]) }

    #[test]
    fn versioned_store_starts_at_zero() {
        let store = VersionedObjectStore::new();
        assert_eq!(store.current_version(), 0);
        assert!(store.snapshot_root(0).is_none());
    }

    #[test]
    fn advance_increments_version_and_stores_root() {
        let mut store = VersionedObjectStore::new();
        let new_v = store.advance(StateRoot::EMPTY, vec![]);
        assert_eq!(new_v, 1);
        assert_eq!(store.current_version(), 1);
        assert!(store.snapshot_root(1).is_some());
    }

    #[test]
    fn read_at_returns_written_value() {
        let mut store = VersionedObjectStore::new();
        store.advance(StateRoot::EMPTY, vec![(key(1), val(42))]);
        assert_eq!(store.read_at(&key(1), 1).unwrap().0, vec![42]);
        assert!(store.read_at(&key(1), 0).is_none());
        assert!(store.read_at(&key(2), 1).is_none());
    }

    #[test]
    fn detect_conflict_finds_differing_values() {
        let mut store = VersionedObjectStore::new();
        store.advance(StateRoot::EMPTY, vec![(key(1), val(10))]);
        store.advance(StateRoot::EMPTY, vec![(key(1), val(20))]);
        let conflict = store.detect_conflict(1, 2);
        assert!(conflict.is_some());
        assert_eq!(conflict.unwrap().0, vec![1]);
    }

    #[test]
    fn detect_conflict_no_conflict_for_same_value() {
        let mut store = VersionedObjectStore::new();
        store.advance(StateRoot::EMPTY, vec![(key(1), val(5))]);
        store.advance(StateRoot::EMPTY, vec![(key(1), val(5))]);
        assert!(store.detect_conflict(1, 2).is_none());
    }

    #[test]
    fn optimistic_lock_check_passes_when_version_matches() {
        let lock = OptimisticLock { key: key(1), expected_version: 3 };
        assert!(ConcurrencyControl::check_lock(&lock, 3));
        assert!(!ConcurrencyControl::check_lock(&lock, 4));
    }

    #[test]
    fn conflict_resolution_first_write_wins_lower_version() {
        let r = ConflictResolution::first_write_wins(5, 3);
        assert_eq!(r.winner_version, 3);
        assert_eq!(r.loser_version, 5);
    }

    #[test]
    fn conflict_resolution_same_version_both_same() {
        let r = ConflictResolution::first_write_wins(2, 2);
        assert_eq!(r.winner_version, 2);
        assert_eq!(r.loser_version, 2);
    }
}
