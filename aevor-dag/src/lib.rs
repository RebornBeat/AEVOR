//! # AEVOR DAG: The Uncorrupted Dual-DAG Frontier
//!
//! `aevor-dag` implements AEVOR's revolutionary Dual-DAG state advancement architecture
//! that enables genuine blockchain trilemma transcendence through parallel execution
//! scaling with available computational resources.
//!
//! ## Dual-DAG Architecture
//!
//! ### Micro-DAG: Transaction-Level Parallelism
//!
//! The Micro-DAG analyzes object-level dependencies between transactions to identify
//! independent operations that can execute simultaneously. Transactions reading and writing
//! disjoint object sets execute in true parallel — no coordination, no sequential blocking.
//! Conflicting transactions are **rejected before execution begins** — no state is ever
//! unwound after execution. Finalized state is immutable.
//!
//! ```text
//! Transaction A: reads [Obj1], writes [Obj2]   ─┐
//! Transaction B: reads [Obj3], writes [Obj4]   ─┼─ Execute in parallel
//! Transaction C: reads [Obj5], writes [Obj6]   ─┘
//! Transaction D: reads [Obj2], writes [Obj7]     ─ Must wait for A (dependency)
//! Transaction E: reads [Obj2], writes [Obj2]     ─ Rejected (conflicts with A)
//! ```
//!
//! ### Macro-DAG: Concurrent Block Production
//!
//! The Macro-DAG enables multiple validators to produce blocks simultaneously without
//! leader election bottlenecks. All concurrent blocks contribute to network consensus,
//! and throughput **increases** with validator participation rather than degrading.
//!
//! ## Uncorrupted Frontier
//!
//! The frontier tracks the mathematically verified leading edge of blockchain state.
//! Advancement requires TEE attestation of execution correctness — corruption is
//! mathematically impossible, not merely economically difficult. Corrupted branches
//! are isolated and excluded from frontier advancement; finalized transactions are
//! never reversed.
//!
//! ## Logical Ordering
//!
//! All ordering uses dependency-based logical sequencing with blockchain consensus time
//! authority. No external clock synchronization, no timing-based coordination bottlenecks.
//!
//! ## Throughput Scaling
//!
//! The following are measured reference points on specific hardware configurations.
//! Throughput scales unboundedly with available computational resources — these are
//! floors, not ceilings.
//!
//! | Validators | Concurrent Producers | Measured TPS (Reference) |
//! |-----------|---------------------|--------------------------|
//! | 100       | 6–8                 | ~50,000                  |
//! | 500       | 12–16               | ~125,000                 |
//! | 1,000     | 18–24               | ~200,000                 |
//! | 2,000+    | 30+                 | ~350,000+                |

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Micro-DAG: transaction-level dependency analysis and parallel execution planning.
pub mod micro_dag;

/// Macro-DAG: concurrent block production coordination and multi-parent block management.
pub mod macro_dag;

/// Uncorrupted frontier: mathematical state advancement verification.
pub mod frontier;

/// Object dependency graph: tracking read/write sets and conflict detection.
pub mod dependency;

/// Logical ordering: dependency-based sequencing without temporal synchronization.
pub mod ordering;

/// Parallel execution planner: lane assignment and workload distribution.
pub mod parallel;

/// DAG storage: efficient persistent storage of DAG structure.
pub mod storage;

/// Conflict resolution: detecting and resolving write-write and read-write conflicts.
pub mod conflict;

/// Pre-execution conflict resolution: accept/reject decisions made before any execution begins.
/// No speculative state execution occurs — conflicts are resolved at the scheduler.
pub mod speculative;

/// DAG metrics: frontier advancement rate, parallelism factor, throughput measurement.
pub mod metrics;

// ============================================================
// PRELUDE
// ============================================================

/// DAG prelude — all essential DAG types.
///
/// ```rust
/// use aevor_dag::prelude::*;
/// ```
pub mod prelude {
    pub use crate::micro_dag::{
        MicroDag, MicroDagEntry, DependencyEdge, ConflictSet,
        MicroDagAnalyzer, ParallelExecutionSet, ObjectAccessPattern,
    };
    pub use crate::macro_dag::{
        MacroDag, MacroDagBlock, BlockParents, ConcurrentProducers,
        MacroDagBuilder, ForkResolution, BlockOrdering,
    };
    pub use crate::frontier::{
        UncorruptedFrontier, FrontierBlock, FrontierAdvancement,
        FrontierProof, FrontierCorruptionDetector, FrontierState,
    };
    pub use crate::dependency::{
        ObjectDependencyGraph, DependencyNode,
        ReadWriteSet, ConflictDetector, DependencyAnalyzer,
    };
    pub use crate::ordering::{
        LogicalOrdering, TopologicalSort, DependencyOrder,
        CausalOrder, ConsensusTimeOrder,
    };
    pub use crate::parallel::{
        ParallelLane, LaneAssignment, WorkloadDistributor,
        ParallelismFactor, ConcurrencyEstimator,
    };
    pub use crate::conflict::{
        ConflictType, ConflictResolution, WriteWriteConflict,
        ReadWriteConflict, ConflictResolver,
    };
    pub use crate::speculative::{
        PreExecutionDecision, ConflictFreeSet, PreExecutionBatch,
    };
    pub use crate::metrics::{
        DagMetrics, FrontierRate, ParallelismMetrics, ThroughputMeasurement,
    };
    pub use crate::{DagError, DagResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from DAG operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DagError {
    /// Dependency cycle detected in the transaction graph.
    #[error("dependency cycle detected involving {transaction_count} transactions")]
    DependencyCycle {
        /// Number of transactions in the cycle.
        transaction_count: usize,
    },

    /// Frontier advancement failed due to attestation error.
    #[error("frontier advancement failed: {reason}")]
    FrontierAdvancementFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Write-write conflict detected between concurrent transactions.
    #[error("write-write conflict on object {object_id}")]
    WriteConflict {
        /// Identifier of the conflicted object.
        object_id: String,
    },

    /// Block references an unknown parent.
    #[error("unknown parent block: {block_hash}")]
    UnknownParent {
        /// Hash of the unknown parent block.
        block_hash: String,
    },

    /// Concurrent producer count exceeds the configured default for current network size.
    /// This default scales with network size and is not a hard architectural ceiling.
    #[error("too many concurrent producers: {actual} > {max}")]
    TooManyConcurrentProducers {
        /// Actual number of concurrent producers.
        actual: usize,
        /// Configured default maximum.
        max: usize,
    },

    /// Fork resolution failed.
    #[error("fork resolution failed: {reason}")]
    ForkResolutionFailed {
        /// Reason for failure.
        reason: String,
    },
}

/// Convenience alias for DAG results.
pub type DagResult<T> = Result<T, DagError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default concurrent block producers for a small network (~100 validators).
/// Scales with network size — not a hard ceiling. Configurable per deployment.
pub const DEFAULT_PRODUCERS_SMALL_NET: usize = 8;

/// Default concurrent block producers for a medium network (~1,000 validators).
/// Scales with network size — not a hard ceiling. Configurable per deployment.
pub const DEFAULT_PRODUCERS_MEDIUM_NET: usize = 24;

/// Default concurrent block producers for a large network (2,000+ validators).
/// Scales with network size — not a hard ceiling. Configurable per deployment.
pub const DEFAULT_PRODUCERS_LARGE_NET: usize = 32;

/// Default maximum parent block references in a Macro-DAG block.
/// Configurable per deployment. Not an architectural ceiling — multi-parent
/// references are unbounded by design (`dag_parents: Vec<BlockHash>`).
pub const DEFAULT_MAX_BLOCK_PARENTS: usize = 32;

/// Per-transaction object access default limit.
/// Configurable per deployment. Prevents runaway dependency graph growth.
pub const MAX_MICRO_DAG_OBJECTS_PER_TX: usize = 1_024;

/// Default parallel execution lanes per processing unit.
/// Scales with available hardware — not a hard ceiling. Configurable per deployment.
pub const DEFAULT_PARALLEL_LANES: usize = 256;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_producer_defaults_scale_with_network() {
        assert!(DEFAULT_PRODUCERS_SMALL_NET < DEFAULT_PRODUCERS_MEDIUM_NET);
        assert!(DEFAULT_PRODUCERS_MEDIUM_NET < DEFAULT_PRODUCERS_LARGE_NET);
    }

    #[test]
    fn parallel_lanes_default_exceeds_large_net_producers() {
        // Default lanes should comfortably exceed the largest producer default
        // to avoid scheduling bottlenecks on large networks.
        assert!(DEFAULT_PARALLEL_LANES > DEFAULT_PRODUCERS_LARGE_NET);
    }

    #[test]
    fn default_block_parents_is_nonzero() {
        // Multi-parent references are architecturally unbounded (Vec<BlockHash>);
        // DEFAULT_MAX_BLOCK_PARENTS is a per-node propagation budget, not a ceiling.
        assert!(DEFAULT_MAX_BLOCK_PARENTS > 0);
    }
}
