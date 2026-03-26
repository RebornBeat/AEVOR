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
    pub fn get_required(&self, id: &ValidatorId) -> StorageResult<&ValidatorRecord> {
        self.records.get(&id.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(&id.0),
        })
    }

    /// Update a validator's stake. Returns `NotFound` if validator doesn't exist.
    pub fn update_stake(&mut self, id: &ValidatorId, new_stake: Amount) -> StorageResult<()> {
        let record = self.records.get_mut(&id.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(&id.0),
        })?;
        record.stake = new_stake;
        Ok(())
    }

    /// Remove a validator from the store. Returns `NotFound` if not present.
    pub fn remove(&mut self, id: &ValidatorId) -> StorageResult<ValidatorRecord> {
        self.records.remove(&id.0).ok_or_else(|| StorageError::NotFound {
            key: hex::encode(&id.0),
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
