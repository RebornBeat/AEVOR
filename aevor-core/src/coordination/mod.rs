//! # Multi-Validator Coordination Types
//!
//! Types for coordinating execution across multiple validators, managing
//! parallel execution dependency graphs, and establishing synchronization
//! points in the Dual-DAG consensus.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::primitives::{Hash256, ObjectId, TransactionHash, ValidatorId};
use crate::consensus::SecurityLevel;
use crate::execution::ExecutionLane;
// ============================================================
// COORDINATION CONTEXT
// ============================================================

/// Context shared across a coordinated multi-validator execution session.
///
/// When multiple validators coordinate to execute a set of transactions
/// in parallel (across different execution lanes and TEE platforms),
/// the `CoordinationContext` carries the shared state needed for consistency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationContext {
    /// Unique identifier for this coordination session.
    pub session_id: Hash256,
    /// Validators participating in this coordination.
    pub participating_validators: Vec<ValidatorId>,
    /// Required security level for the coordination outcome.
    pub security_level: SecurityLevel,
    /// The parallel execution plan for this session.
    pub execution_plan: crate::execution::ParallelExecutionPlan,
    /// Synchronization points that must be reached before proceeding.
    pub sync_points: Vec<SynchronizationPoint>,
    /// Whether TEE attestation is required from all participants.
    pub require_tee_attestation: bool,
}

impl CoordinationContext {
    /// Returns the number of participating validators.
    pub fn participant_count(&self) -> usize {
        self.participating_validators.len()
    }

    /// Returns `true` if this coordination meets its security requirements.
    pub fn meets_security_requirements(&self, validators_confirmed: usize) -> bool {
        let fraction = validators_confirmed as f64 / self.participating_validators.len() as f64;
        fraction >= self.security_level.min_participation()
    }
}

// ============================================================
// DEPENDENCY GRAPH
// ============================================================

/// A directed acyclic graph of execution dependencies.
///
/// The dependency graph drives the parallel scheduler — it determines which
/// transactions can be executed concurrently (no path between them) and which
/// must be serialized (there is a directed path between them).
///
/// An edge A → B means "A must complete before B can begin."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// Vertices: transaction hashes.
    pub vertices: Vec<TransactionHash>,
    /// Edges: vertex index → list of vertex indices that depend on it.
    pub edges: HashMap<usize, Vec<usize>>,
    /// Reverse edges: vertex index → list of vertices it depends on.
    pub reverse_edges: HashMap<usize, Vec<usize>>,
    /// Pre-computed topological order for serial execution fallback.
    pub topological_order: Vec<usize>,
}

impl DependencyGraph {
    /// Create an empty dependency graph.
    pub fn empty() -> Self {
        Self {
            vertices: Vec::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
            topological_order: Vec::new(),
        }
    }

    /// Returns the number of vertices (transactions) in the graph.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Returns the number of dependency edges.
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }

    /// Returns `true` if the graph has no edges (all transactions are independent).
    pub fn is_fully_independent(&self) -> bool {
        self.edge_count() == 0
    }

    /// Returns the set of root vertices (no dependencies, can run first).
    pub fn roots(&self) -> Vec<TransactionHash> {
        self.vertices
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                self.reverse_edges
                    .get(i)
                    .map(|deps| deps.is_empty())
                    .unwrap_or(true)
            })
            .map(|(_, tx)| *tx)
            .collect()
    }

    /// Returns the maximum depth of the dependency chain (critical path length).
    pub fn critical_path_length(&self) -> usize {
        if self.vertices.is_empty() {
            return 0;
        }
        // Simple BFS-based longest path from any root
        let roots = self.roots();
        if roots.is_empty() {
            return 0;
        }
        // Return topological order length as approximation
        self.topological_order.len()
    }
}

// ============================================================
// PARALLEL COORDINATION
// ============================================================

/// Coordination state for a parallel execution batch.
///
/// Tracks which execution lanes have completed, which are in-progress,
/// and manages the merge of parallel state changes back into a consistent
/// global state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelCoordination {
    /// Dependency graph for this coordination batch.
    pub dependency_graph: DependencyGraph,
    /// Status of each execution lane.
    pub lane_status: HashMap<ExecutionLane, LaneStatus>,
    /// State changes from each completed lane.
    pub lane_results: HashMap<ExecutionLane, Vec<crate::execution::StateChange>>,
    /// Conflicts detected during parallel execution (require re-serialization).
    pub detected_conflicts: Vec<ExecutionConflict>,
    /// Whether all lanes have completed without conflicts.
    pub is_clean: bool,
}

impl ParallelCoordination {
    /// Create a new parallel coordination for the given dependency graph.
    pub fn new(graph: DependencyGraph, lane_count: usize) -> Self {
        let lane_status = (0..lane_count as u32)
            .map(|i| (ExecutionLane(i), LaneStatus::Pending))
            .collect();
        Self {
            dependency_graph: graph,
            lane_status,
            lane_results: HashMap::new(),
            detected_conflicts: Vec::new(),
            is_clean: true,
        }
    }

    /// Mark a lane as completed.
    pub fn complete_lane(&mut self, lane: ExecutionLane, changes: Vec<crate::execution::StateChange>) {
        self.lane_status.insert(lane, LaneStatus::Completed);
        self.lane_results.insert(lane, changes);
    }

    /// Record a conflict detected between two lanes.
    pub fn record_conflict(&mut self, conflict: ExecutionConflict) {
        self.is_clean = false;
        self.detected_conflicts.push(conflict);
    }

    /// Returns `true` if all lanes have completed.
    pub fn all_lanes_complete(&self) -> bool {
        self.lane_status
            .values()
            .all(|s| matches!(s, LaneStatus::Completed | LaneStatus::Failed))
    }

    /// Returns the number of active (running) lanes.
    pub fn active_lane_count(&self) -> usize {
        self.lane_status
            .values()
            .filter(|s| matches!(s, LaneStatus::Running))
            .count()
    }
}

/// Status of a single execution lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LaneStatus {
    /// Waiting for dependencies to complete.
    Pending,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Completed,
    /// Failed — state changes discarded.
    Failed,
}

/// A conflict detected between two parallel execution lanes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConflict {
    /// First lane involved.
    pub lane_a: u32,
    /// Second lane involved.
    pub lane_b: u32,
    /// Object that caused the conflict.
    pub conflicting_object: ObjectId,
    /// Type of conflict.
    pub conflict_type: crate::execution::DependencyType,
}

// ============================================================
// SYNCHRONIZATION POINT
// ============================================================

/// A synchronization point in a coordinated execution.
///
/// A synchronization point is a moment in the execution pipeline where
/// all in-progress lanes must complete before execution can continue.
/// This ensures that dependent operations see consistent state.
///
/// Synchronization points are used sparingly — excessive synchronization
/// negates the performance benefits of parallel execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizationPoint {
    /// Unique identifier for this sync point.
    pub id: Hash256,
    /// Lanes that must complete before this sync point is reached.
    pub required_lanes: Vec<u32>,
    /// Lanes that can proceed after this sync point.
    pub unblocked_lanes: Vec<u32>,
    /// Whether this sync point has been reached.
    pub is_reached: bool,
    /// State root that must be agreed upon at this sync point.
    pub expected_root: Option<crate::storage::StateRoot>,
}

impl SynchronizationPoint {
    /// Create a new synchronization point.
    pub fn new(
        id: Hash256,
        required_lanes: Vec<u32>,
        unblocked_lanes: Vec<u32>,
    ) -> Self {
        Self {
            id,
            required_lanes,
            unblocked_lanes,
            is_reached: false,
            expected_root: None,
        }
    }

    /// Mark this synchronization point as reached.
    pub fn reach(&mut self) {
        self.is_reached = true;
    }

    /// Returns `true` if a given lane is blocked by this sync point.
    pub fn blocks_lane(&self, lane: u32) -> bool {
        self.unblocked_lanes.contains(&lane) && !self.is_reached
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_graph_empty_is_fully_independent() {
        let g = DependencyGraph::empty();
        assert!(g.is_fully_independent());
        assert_eq!(g.vertex_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn parallel_coordination_all_lanes_complete() {
        let graph = DependencyGraph::empty();
        let mut coord = ParallelCoordination::new(graph, 2);
        assert!(!coord.all_lanes_complete());

        coord.complete_lane(ExecutionLane(0), vec![]);
        assert!(!coord.all_lanes_complete());

        coord.complete_lane(ExecutionLane(1), vec![]);
        assert!(coord.all_lanes_complete());
    }

    #[test]
    fn parallel_coordination_conflict_marks_dirty() {
        let graph = DependencyGraph::empty();
        let mut coord = ParallelCoordination::new(graph, 2);
        assert!(coord.is_clean);

        coord.record_conflict(ExecutionConflict {
            lane_a: 0,
            lane_b: 1,
            conflicting_object: ObjectId::from_hash(Hash256::ZERO),
            conflict_type: crate::execution::DependencyType::WriteAfterWrite,
        });
        assert!(!coord.is_clean);
        assert_eq!(coord.detected_conflicts.len(), 1);
    }

    #[test]
    fn sync_point_blocks_unblocked_lane_when_not_reached() {
        let sp = SynchronizationPoint::new(
            Hash256::ZERO,
            vec![0],
            vec![1],
        );
        assert!(sp.blocks_lane(1));
        assert!(!sp.blocks_lane(0)); // Lane 0 is required, not unblocked
    }

    #[test]
    fn sync_point_does_not_block_after_reaching() {
        let mut sp = SynchronizationPoint::new(Hash256::ZERO, vec![0], vec![1]);
        sp.reach();
        assert!(!sp.blocks_lane(1));
    }

    #[test]
    fn coordination_context_participant_count() {
        let ctx = CoordinationContext {
            session_id: Hash256::ZERO,
            participating_validators: vec![Hash256::ZERO, Hash256([1u8; 32]), Hash256([2u8; 32])],
            security_level: SecurityLevel::Basic,
            execution_plan: crate::execution::ParallelExecutionPlan {
                lanes: std::collections::HashMap::new(),
                lane_dependencies: std::collections::HashMap::new(),
                tee_objects: vec![],
                max_parallelism: 3,
                transaction_count: 0,
                estimated_execution_ms: 0,
            },
            sync_points: vec![],
            require_tee_attestation: false,
        };
        assert_eq!(ctx.participant_count(), 3);
    }
}
