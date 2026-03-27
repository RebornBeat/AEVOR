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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{GasAmount, Hash256, TransactionHash};
    use aevor_core::execution::ExecutionLane;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }

    // ── ExecutionQueue ──────────────────────────────────────────

    #[test]
    fn execution_queue_push_and_pop_fifo() {
        let mut q = ExecutionQueue::new();
        q.push(tx(1));
        q.push(tx(2));
        assert_eq!(q.pop(), Some(tx(1)));
        assert_eq!(q.pop(), Some(tx(2)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn execution_queue_len_and_is_empty() {
        let mut q = ExecutionQueue::default();
        assert!(q.is_empty());
        q.push(tx(1));
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
    }

    // ── ResourceBudget ──────────────────────────────────────────

    #[test]
    fn resource_budget_stores_limits() {
        let budget = ResourceBudget {
            max_gas: GasAmount::from_u64(1_000_000),
            max_tee_slots: 4,
            max_memory_bytes: 256 * 1024 * 1024,
        };
        assert_eq!(budget.max_gas.as_u64(), 1_000_000);
        assert_eq!(budget.max_tee_slots, 4);
        assert_eq!(budget.max_memory_bytes, 256 * 1024 * 1024);
    }

    // ── SchedulerMetrics ─────────────────────────────────────────

    #[test]
    fn scheduler_metrics_default_is_zero() {
        let m = SchedulerMetrics::default();
        assert_eq!(m.total_scheduled, 0);
        assert_eq!(m.avg_lane_utilization, 0.0);
        assert_eq!(m.conflict_rate, 0.0);
    }

    // ── ParallelScheduler ────────────────────────────────────────

    #[test]
    fn scheduler_assigns_all_transactions() {
        let sched = ParallelScheduler::new(4);
        let txs: Vec<_> = (1..=8).map(tx).collect();
        let decisions = sched.schedule(txs);
        assert_eq!(decisions.len(), 8);
    }

    #[test]
    fn scheduler_round_robins_lanes() {
        let sched = ParallelScheduler::new(3);
        let txs: Vec<_> = (0..6).map(tx).collect();
        let decisions = sched.schedule(txs);
        assert_eq!(decisions[0].lane, ExecutionLane(0));
        assert_eq!(decisions[1].lane, ExecutionLane(1));
        assert_eq!(decisions[2].lane, ExecutionLane(2));
        assert_eq!(decisions[3].lane, ExecutionLane(0)); // wraps
    }

    #[test]
    fn scheduler_priority_increases_with_index() {
        let sched = ParallelScheduler::new(2);
        let txs: Vec<_> = (0..4).map(tx).collect();
        let d = sched.schedule(txs);
        assert_eq!(d[0].priority, 0);
        assert_eq!(d[1].priority, 1);
        assert_eq!(d[2].priority, 2);
    }
}
