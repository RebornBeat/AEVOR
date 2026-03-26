//! Speculative execution for throughput optimization.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;
use aevor_core::execution::StateChange;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpeculativeState {
    pub based_on: aevor_core::storage::StateRoot,
    pub speculative_changes: Vec<StateChange>,
    pub is_committed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackPoint {
    pub transaction: TransactionHash,
    pub snapshot_root: aevor_core::storage::StateRoot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitDecision {
    pub transaction: TransactionHash,
    pub commit: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpeculativeResult {
    pub transaction: TransactionHash,
    pub changes: Vec<StateChange>,
    pub conflict_detected: bool,
}

pub struct SpeculativeExecution {
    pending: Vec<SpeculativeResult>,
}

impl SpeculativeExecution {
    pub fn new() -> Self { Self { pending: Vec::new() } }
    pub fn add_result(&mut self, r: SpeculativeResult) { self.pending.push(r); }
    pub fn pending_count(&self) -> usize { self.pending.len() }
    pub fn has_conflicts(&self) -> bool { self.pending.iter().any(|r| r.conflict_detected) }
}

impl Default for SpeculativeExecution {
    fn default() -> Self { Self::new() }
}
