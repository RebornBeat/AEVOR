//! Parallel transaction scheduler.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;
use aevor_core::execution::ExecutionLane;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchedulingDecision {
    pub transaction: TransactionHash,
    pub lane: ExecutionLane,
    pub priority: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaneAllocation {
    pub lane: ExecutionLane,
    pub transactions: Vec<TransactionHash>,
    pub estimated_gas: aevor_core::primitives::GasAmount,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub max_gas: aevor_core::primitives::GasAmount,
    pub max_tee_slots: usize,
    pub max_memory_bytes: usize,
}

pub struct ExecutionQueue { items: std::collections::VecDeque<TransactionHash> }
impl ExecutionQueue {
    pub fn new() -> Self { Self { items: std::collections::VecDeque::new() } }
    pub fn push(&mut self, tx: TransactionHash) { self.items.push_back(tx); }
    pub fn pop(&mut self) -> Option<TransactionHash> { self.items.pop_front() }
    pub fn len(&self) -> usize { self.items.len() }
    pub fn is_empty(&self) -> bool { self.items.is_empty() }
}
impl Default for ExecutionQueue { fn default() -> Self { Self::new() } }

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SchedulerMetrics {
    pub total_scheduled: u64,
    pub avg_lane_utilization: f64,
    pub conflict_rate: f64,
}

pub struct ParallelScheduler { lane_count: usize }
impl ParallelScheduler {
    pub fn new(lane_count: usize) -> Self { Self { lane_count } }
    pub fn schedule(&self, txs: Vec<TransactionHash>) -> Vec<SchedulingDecision> {
        txs.into_iter().enumerate().map(|(i, tx)| SchedulingDecision {
            transaction: tx,
            #[allow(clippy::cast_possible_truncation)] // lane index bounded by lane_count — small value
            lane: ExecutionLane((i % self.lane_count) as u32),
            #[allow(clippy::cast_possible_truncation)] // scheduling priority index — small in practice
            priority: i as u32,
        }).collect()
    }
}
