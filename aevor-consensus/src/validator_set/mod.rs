//! Validator set management: active set, rotation, weighted selection.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{ValidatorSet, ValidatorEntry};
pub use aevor_core::primitives::{EpochNumber, ValidatorId, ValidatorIndex, ValidatorWeight};

/// Tracks when and how a validator's weight changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRotation {
    pub epoch: EpochNumber,
    pub joining: Vec<ValidatorId>,
    pub leaving: Vec<ValidatorId>,
    pub weight_changes: Vec<(ValidatorId, ValidatorWeight)>,
}

/// A proposed update to the active validator set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSetUpdate {
    pub epoch: EpochNumber,
    pub new_set: ValidatorSet,
    pub rotation: ValidatorRotation,
}

/// Weighted random selection from the validator set (for proposer election).
pub struct WeightedValidatorSelection {
    validators: Vec<(ValidatorId, ValidatorWeight)>,
}

impl WeightedValidatorSelection {
    pub fn from_set(set: &ValidatorSet) -> Self {
        let validators = set.validators.iter()
            .map(|(id, entry)| (*id, entry.weight))
            .collect();
        Self { validators }
    }

    /// Pseudorandomly select a validator weighted by stake.
    ///
    /// # Panics
    /// Never panics in practice — the `try_into().unwrap()` on `seed[..8]` always
    /// succeeds because the slice is exactly 8 bytes.
    pub fn select(&self, seed: &[u8; 32]) -> Option<ValidatorId> {
        if self.validators.is_empty() { return None; }
        let total: u64 = self.validators.iter().map(|(_, w)| w.as_u64()).sum();
        if total == 0 { return None; }
        let pick = u64::from_le_bytes(seed[..8].try_into().unwrap()) % total;
        let mut acc = 0u64;
        for (id, weight) in &self.validators {
            acc += weight.as_u64();
            if acc > pick { return Some(*id); }
        }
        self.validators.last().map(|(id, _)| *id)
    }
}
