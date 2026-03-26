//! State rollback on execution failure.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Hash256, TransactionHash};
use aevor_core::storage::StateRoot;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackPoint { pub transaction: TransactionHash, pub snapshot_root: StateRoot }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RollbackReason { ExecutionFailed, ConflictDetected, PrivacyViolation, OutOfGas }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackResult { pub rolled_back_to: StateRoot, pub reason: RollbackReason }

pub struct StateRestoration { snapshots: Vec<(Hash256, StateRoot)> }
impl StateRestoration {
    pub fn new() -> Self { Self { snapshots: Vec::new() } }
    pub fn save(&mut self, id: Hash256, root: StateRoot) { self.snapshots.push((id, root)); }
    pub fn restore(&self, id: &Hash256) -> Option<StateRoot> {
        self.snapshots.iter().find(|(k, _)| k == id).map(|(_, r)| *r)
    }
}
impl Default for StateRestoration { fn default() -> Self { Self::new() } }

pub struct RollbackManager { points: Vec<RollbackPoint> }
impl RollbackManager {
    pub fn new() -> Self { Self { points: Vec::new() } }
    pub fn create_point(&mut self, p: RollbackPoint) { self.points.push(p); }
    pub fn rollback_to(&self, tx: &TransactionHash) -> Option<&RollbackPoint> {
        self.points.iter().find(|p| &p.transaction == tx)
    }
}
impl Default for RollbackManager { fn default() -> Self { Self::new() } }
