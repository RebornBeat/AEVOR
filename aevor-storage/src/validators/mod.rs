//! Validator state, stake, and performance record storage.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Amount, EpochNumber, ValidatorId};
use crate::{StorageError, StorageResult};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub id: ValidatorId,
    pub status: String,
    pub stake: Amount,
    pub epoch_joined: EpochNumber,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeRecord {
    pub staker: aevor_core::primitives::Address,
    pub validator: ValidatorId,
    pub amount: Amount,
    pub locked_until_epoch: Option<EpochNumber>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerformanceRecord {
    pub validator: ValidatorId,
    pub epoch: EpochNumber,
    pub participation_pct: u8,
    pub slash_count: u32,
}

/// In-memory validator state store.
pub struct ValidatorStore {
    records: std::collections::HashMap<[u8; 32], ValidatorRecord>,
}

impl ValidatorStore {
    /// Create an empty validator store.
    pub fn new() -> Self { Self { records: std::collections::HashMap::new() } }

    /// Store a validator record (insert or overwrite).
    pub fn store(&mut self, r: ValidatorRecord) { self.records.insert(r.id.0, r); }

    /// Retrieve a validator record by ID.
    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorRecord> { self.records.get(&id.0) }

    /// Retrieve a validator record or return `NotFound`.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no validator with this ID is stored.
    pub fn get_required(&self, id: &ValidatorId) -> StorageResult<&ValidatorRecord> {
        self.records.get(&id.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(id.0),
        })
    }

    /// Update a validator's stake. Returns `NotFound` if validator doesn't exist.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no validator with this ID is stored.
    pub fn update_stake(&mut self, id: &ValidatorId, new_stake: Amount) -> StorageResult<()> {
        let record = self.records.get_mut(&id.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(id.0),
        })?;
        record.stake = new_stake;
        Ok(())
    }

    /// Remove a validator from the store. Returns `NotFound` if not present.
    ///
    /// # Errors
    /// Returns `StorageError::NotFound` if no validator with this ID is stored.
    pub fn remove(&mut self, id: &ValidatorId) -> StorageResult<ValidatorRecord> {
        self.records.remove(&id.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(id.0),
        })
    }

    /// Number of validators in the store.
    pub fn count(&self) -> usize { self.records.len() }

    /// All active validators (status == "active").
    pub fn active_validators(&self) -> Vec<&ValidatorRecord> {
        self.records.values().filter(|r| r.status == "active").collect()
    }
}

impl Default for ValidatorStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Amount, EpochNumber, Hash256, ValidatorId};

    fn vid(n: u8) -> ValidatorId { Hash256([n; 32]) }
    fn amt(n: u128) -> Amount { Amount::from_nano(n) }

    fn make_record(n: u8, status: &str, stake: u128) -> ValidatorRecord {
        ValidatorRecord {
            id: vid(n),
            status: status.into(),
            stake: amt(stake),
            epoch_joined: EpochNumber(1),
        }
    }

    #[test]
    fn store_and_get_by_id() {
        let mut store = ValidatorStore::new();
        store.store(make_record(1, "active", 1_000_000));
        let rec = store.get(&vid(1)).unwrap();
        assert_eq!(rec.stake.as_nano(), 1_000_000u128);
        assert_eq!(rec.status, "active");
    }

    #[test]
    fn get_missing_returns_none() {
        let store = ValidatorStore::default();
        assert!(store.get(&vid(99)).is_none());
    }

    #[test]
    fn get_required_missing_returns_error() {
        let store = ValidatorStore::new();
        assert!(store.get_required(&vid(5)).is_err());
    }

    #[test]
    fn update_stake_changes_stake() {
        let mut store = ValidatorStore::new();
        store.store(make_record(1, "active", 500));
        store.update_stake(&vid(1), amt(2_000)).unwrap();
        assert_eq!(store.get(&vid(1)).unwrap().stake.as_nano(), 2_000u128);
    }

    #[test]
    fn update_stake_missing_returns_error() {
        let mut store = ValidatorStore::new();
        assert!(store.update_stake(&vid(99), amt(100)).is_err());
    }

    #[test]
    fn remove_existing_validator() {
        let mut store = ValidatorStore::new();
        store.store(make_record(2, "active", 100));
        let removed = store.remove(&vid(2)).unwrap();
        assert_eq!(removed.id, vid(2));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn remove_missing_returns_error() {
        let mut store = ValidatorStore::new();
        assert!(store.remove(&vid(0)).is_err());
    }

    #[test]
    fn active_validators_filters_correctly() {
        let mut store = ValidatorStore::new();
        store.store(make_record(1, "active", 100));
        store.store(make_record(2, "inactive", 200));
        store.store(make_record(3, "active", 300));
        let active = store.active_validators();
        assert_eq!(active.len(), 2);
        assert!(active.iter().all(|r| r.status == "active"));
    }
}
