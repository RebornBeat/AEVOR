//! Deterministic finality: proofs, gadgets, immediate confirmation.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{
    FinalityProof, MathematicalCertainty, DeterministicFinality,
};
use aevor_core::consensus::SecurityLevel;
use aevor_core::primitives::Hash256;

/// The finality gadget: determines when a block has achieved finality.
pub struct FinalityGadget {
    required_level: SecurityLevel,
}

impl FinalityGadget {
    pub fn new(required_level: SecurityLevel) -> Self {
        Self { required_level }
    }

    pub fn is_final(&self, proof: &FinalityProof) -> bool {
        proof.security_level >= self.required_level
    }
}

/// Immediate finality confirmation for Minimal security.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImmediateFinalityConfirmation {
    pub item_hash: Hash256,
    pub confirmed_at_ms: u64,
    pub security_level: SecurityLevel,
}
