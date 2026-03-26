//! Speculative execution with conflict detection.

use serde::{Deserialize, Serialize};
use aevor_core::execution::{ExecutionResult, StateChange};
use aevor_core::primitives::TransactionHash;

pub struct SpeculativeContext { pub base_root: aevor_core::storage::StateRoot }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictDetectionResult { pub has_conflict: bool, pub conflicting_tx: Option<TransactionHash> }

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SpeculativeMetrics { pub speculative_count: u64, pub conflict_rate: f64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitOrRollback { pub commit: bool, pub reason: String }

pub struct SpeculativeExecutor { pending: Vec<(TransactionHash, Vec<StateChange>)> }
impl SpeculativeExecutor {
    pub fn new() -> Self { Self { pending: Vec::new() } }
    pub fn add(&mut self, tx: TransactionHash, changes: Vec<StateChange>) { self.pending.push((tx, changes)); }
    pub fn pending_count(&self) -> usize { self.pending.len() }
}
impl Default for SpeculativeExecutor { fn default() -> Self { Self::new() } }
