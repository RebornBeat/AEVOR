//! Parallel execution scheduler within the VM.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{ObjectId, TransactionHash};
use aevor_core::execution::ExecutionLane;

pub struct VmParallelScheduler { lane_count: usize }
impl VmParallelScheduler {
    pub fn new(lane_count: usize) -> Self { Self { lane_count } }
    pub fn assign_lane(&self, tx: TransactionHash) -> ExecutionLane {
        ExecutionLane((tx.0[0] as usize % self.lane_count) as u32)
    }
}

pub struct ObjectDagAnalyzer;
impl ObjectDagAnalyzer {
    pub fn conflict_free(a_writes: &[ObjectId], b_reads: &[ObjectId], b_writes: &[ObjectId]) -> bool {
        !a_writes.iter().any(|w| b_reads.contains(w) || b_writes.contains(w))
    }
}

pub struct ExecutionLaneManager { lanes: Vec<Vec<TransactionHash>> }
impl ExecutionLaneManager {
    pub fn new(count: usize) -> Self { Self { lanes: vec![Vec::new(); count] } }
    pub fn assign(&mut self, tx: TransactionHash, lane: ExecutionLane) {
        if let Some(l) = self.lanes.get_mut(lane.id() as usize) { l.push(tx); }
    }
    pub fn lane_count(&self) -> usize { self.lanes.len() }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelContractSet { pub contracts: Vec<aevor_core::primitives::Address>, pub no_conflicts: bool }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictAwareLaneAssignment { pub tx: TransactionHash, pub lane: ExecutionLane, pub conflicts: Vec<TransactionHash> }
