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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, EpochNumber, Hash256, PublicKey, ValidatorId, ValidatorIndex, ValidatorWeight};
    use aevor_core::consensus::{SecurityThresholds, ValidatorEntry, ValidatorSet};
    use std::collections::HashMap;

    fn vid(n: u8) -> ValidatorId { Hash256([n; 32]) }
    fn weight(n: u64) -> ValidatorWeight { ValidatorWeight::from_u64(n) }

    fn entry(n: u8, w: u64) -> ValidatorEntry {
        ValidatorEntry {
            id: vid(n),
            public_key: PublicKey([n; 32]),
            weight: weight(w),
            index: ValidatorIndex(u32::from(n)),
            stake_address: Address([n; 32]),
            is_active: true,
        }
    }

    fn thresholds() -> SecurityThresholds {
        SecurityThresholds {
            minimal: weight(1),
            basic: weight(2),
            strong: weight(3),
            full: weight(4),
        }
    }

    fn make_set(entries: &[(u8, u64)]) -> ValidatorSet {
        let mut validators = HashMap::new();
        let total: u64 = entries.iter().map(|(_, w)| w).sum();
        for &(n, w) in entries {
            validators.insert(vid(n), entry(n, w));
        }
        ValidatorSet {
            epoch: EpochNumber(1),
            validators,
            total_weight: weight(total),
            security_thresholds: thresholds(),
        }
    }

    #[test]
    fn weighted_selection_empty_set_returns_none() {
        let sel = WeightedValidatorSelection { validators: vec![] };
        assert!(sel.select(&[0u8; 32]).is_none());
    }

    #[test]
    fn weighted_selection_single_validator_always_selected() {
        let set = make_set(&[(1, 100)]);
        let sel = WeightedValidatorSelection::from_set(&set);
        for seed_byte in [0u8, 1, 127, 255] {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;
            assert_eq!(sel.select(&seed), Some(vid(1)));
        }
    }

    #[test]
    fn weighted_selection_returns_a_validator_from_the_set() {
        let set = make_set(&[(1, 50), (2, 50)]);
        let sel = WeightedValidatorSelection::from_set(&set);
        let result = sel.select(&[0u8; 32]);
        assert!(result.is_some());
        let id = result.unwrap();
        assert!(id == vid(1) || id == vid(2));
    }

    #[test]
    fn validator_rotation_stores_epoch_and_lists() {
        let rot = ValidatorRotation {
            epoch: EpochNumber(5),
            joining: vec![vid(10)],
            leaving: vec![vid(20)],
            weight_changes: vec![(vid(1), weight(200))],
        };
        assert_eq!(rot.epoch.0, 5);
        assert_eq!(rot.joining.len(), 1);
        assert_eq!(rot.leaving.len(), 1);
        assert_eq!(rot.weight_changes[0].1.as_u64(), 200);
    }
}
