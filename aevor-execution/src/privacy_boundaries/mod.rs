//! Privacy boundary enforcement during execution.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::{PrivacyBoundary, PrivacyLevel};
use aevor_core::primitives::Hash256;

pub struct PrivacyBoundaryManager { boundaries: Vec<PrivacyBoundary> }
impl PrivacyBoundaryManager {
    pub fn new() -> Self { Self { boundaries: Vec::new() } }
    pub fn add(&mut self, b: PrivacyBoundary) { self.boundaries.push(b); }
    pub fn boundary_count(&self) -> usize { self.boundaries.len() }
}
impl Default for PrivacyBoundaryManager { fn default() -> Self { Self::new() } }

pub struct BoundaryEnforcement { strict: bool }
impl BoundaryEnforcement {
    pub fn new(strict: bool) -> Self { Self { strict } }
    pub fn allows_crossing(&self, from: PrivacyLevel, to: PrivacyLevel) -> bool {
        !self.strict || from <= to
    }
}

pub struct CrossPrivacyMediator;
pub struct PrivacyAwareExecution { pub effective_level: PrivacyLevel }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundaryViolationProof {
    pub violating_operation: Hash256,
    pub from_level: PrivacyLevel,
    pub to_level: PrivacyLevel,
}
