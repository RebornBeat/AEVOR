//! Byzantine fault detection and isolation.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{ByzantineFaultProof, ByzantineFaultType};
use aevor_core::primitives::ValidatorId;

pub type ByzantineEvidence = ByzantineFaultProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MisbehaviorType {
    DoubleSign,
    InvalidAttestation,
    Equivocation,
    ExtendedDowntime,
    CoordinatedAttack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorruptionProof {
    pub offender: ValidatorId,
    pub misbehavior: MisbehaviorType,
    pub evidence: Vec<u8>,
    pub proof_hash: aevor_core::primitives::Hash256,
}

pub struct ByzantineDetector {
    threshold_fraction: f64,
}

impl ByzantineDetector {
    pub fn new(threshold_fraction: f64) -> Self {
        Self { threshold_fraction }
    }

    pub fn is_byzantine(&self, participation: f64) -> bool {
        participation < (1.0 - self.threshold_fraction)
    }
}

pub struct ByzantineIsolation {
    isolated: Vec<ValidatorId>,
}

impl ByzantineIsolation {
    pub fn new() -> Self { Self { isolated: Vec::new() } }

    pub fn isolate(&mut self, validator: ValidatorId) {
        if !self.isolated.contains(&validator) {
            self.isolated.push(validator);
        }
    }

    pub fn is_isolated(&self, validator: &ValidatorId) -> bool {
        self.isolated.contains(validator)
    }
}

impl Default for ByzantineIsolation {
    fn default() -> Self { Self::new() }
}
