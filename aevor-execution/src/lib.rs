//! # AEVOR Execution: Multi-TEE Orchestration and Coordination
//!
//! `aevor-execution` orchestrates the complete transaction execution pipeline,
//! coordinating AevorVM, TEE environments, parallel scheduling, and privacy
//! boundary management into a unified execution framework.
//!
//! ## Responsibilities
//!
//! This crate owns the execution pipeline from transaction receipt to result commitment:
//!
//! 1. **Pre-execution**: dependency analysis, TEE allocation, gas validation
//! 2. **Parallel scheduling**: lane assignment across available execution resources
//! 3. **Deterministic execution**: coordinated AevorVM invocations with TEE attestation
//! 4. **Post-execution**: result collection, state commitment, receipt generation
//!
//! ## Multi-TEE Coordination
//!
//! Applications can span multiple TEE instances for scalability, fault tolerance, or
//! geographic distribution. This crate coordinates state consistency across distributed
//! secure execution environments, ensuring mathematically identical outcomes regardless
//! of which TEE instances process individual transactions.
//!
//! ## Privacy Boundary Management
//!
//! The execution orchestrator enforces privacy boundaries across the complete execution
//! lifecycle. Private objects are never exposed to non-TEE execution contexts, and
//! cross-privacy coordination is mediated through mathematically verified channels.
//!
//! ## Deterministic Parallel Execution
//!
//! This crate implements AEVOR's Transaction-Level Parallel Execution with Mathematical
//! Verification — the corrected architecture that replaces the original "superposition"
//! concept. All parallel execution is deterministic: identical inputs always produce
//! identical outputs, enabling mathematical verification and consensus certainty.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Execution pipeline: end-to-end transaction execution orchestration.
pub mod pipeline;

/// Parallel scheduler: workload distribution across execution lanes and TEE instances.
pub mod scheduler;

/// Multi-TEE coordination: state consistency across distributed secure environments.
pub mod multi_tee;

/// Privacy boundary manager: enforcement across the complete execution lifecycle.
pub mod privacy_boundaries;

/// Application lifecycle: deploy, upgrade, destroy contract lifecycle management.
pub mod lifecycle;

/// Execution context factory: building complete contexts from transactions.
pub mod context_factory;

/// Result aggregation: collecting and verifying results from parallel execution.
pub mod aggregation;

/// Speculative execution: optimistic processing with conflict detection and rollback.
pub mod speculative;

/// Execution metrics: throughput, latency, parallelism factor measurement.
pub mod metrics;

/// Cross-contract execution: coordinating multi-contract atomic operations.
pub mod cross_contract;

/// Rollback manager: clean state restoration on execution failure.
pub mod rollback;

// ============================================================
// PRELUDE
// ============================================================

/// Execution prelude — all essential execution orchestration types.
///
/// ```rust
/// use aevor_execution::prelude::*;
/// ```
pub mod prelude {
    pub use crate::pipeline::{
        ExecutionPipeline, PipelineStage, PipelineConfig, PipelineResult,
        PreExecutionCheck, PostExecutionCommit,
    };
    pub use crate::scheduler::{
        ParallelScheduler, SchedulingDecision, LaneAllocation,
        ResourceBudget, ExecutionQueue, SchedulerMetrics,
    };
    pub use crate::multi_tee::{
        MultiTeeOrchestrator, TeeCoordinationContext, DistributedExecution,
        TeeConsistencyVerifier, MultiTeeResult, TeeInstanceSelector,
    };
    pub use crate::privacy_boundaries::{
        PrivacyBoundaryManager, BoundaryEnforcement, CrossPrivacyMediator,
        PrivacyAwareExecution, BoundaryViolationProof,
    };
    pub use crate::lifecycle::{
        ContractLifecycle, DeploymentRecord, UpgradeRecord, DestroyRecord,
        LifecycleEvent, LifecycleValidator,
    };
    pub use crate::aggregation::{
        ResultAggregator, ParallelResultSet, ConsistencyCheck,
        AggregatedReceipt, ExecutionSummary,
    };
    pub use crate::speculative::{
        SpeculativeExecutor, SpeculativeContext, CommitOrRollback,
        ConflictDetectionResult, SpeculativeMetrics,
    };
    pub use crate::rollback::{
        RollbackManager, RollbackPoint, RollbackReason, RollbackResult,
        StateRestoration,
    };
    pub use crate::{ExecutionError, ExecutionResult as ExecResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from execution orchestration.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ExecutionError {
    /// VM execution failed.
    #[error("VM execution failed: {0}")]
    VmFailed(String),

    /// TEE allocation for execution failed.
    #[error("TEE allocation failed: {reason}")]
    TeeAllocationFailed {
        /// Reason the TEE could not be allocated.
        reason: String,
    },

    /// Parallel scheduling conflict that could not be resolved.
    #[error("scheduling conflict: {description}")]
    SchedulingConflict {
        /// Description of the unresolvable conflict.
        description: String,
    },

    /// Multi-TEE consistency verification failed.
    #[error("multi-TEE consistency failure: {description}")]
    ConsistencyFailure {
        /// Description of the inconsistency.
        description: String,
    },

    /// Privacy boundary was violated during execution.
    #[error("privacy boundary violation: {description}")]
    PrivacyViolation {
        /// Description of the attempted violation.
        description: String,
    },

    /// Transaction exceeded its gas limit.
    #[error("gas limit exceeded: used {used}, limit {limit}")]
    GasLimitExceeded {
        /// Gas consumed.
        used: u64,
        /// Gas limit.
        limit: u64,
    },

    /// Contract rollback was required due to execution failure.
    #[error("execution rolled back: {reason}")]
    RolledBack {
        /// Reason for rollback.
        reason: String,
    },

    /// Speculative execution conflict detected.
    #[error("speculative conflict on object {object_id}")]
    SpeculativeConflict {
        /// Object ID at the center of the conflict.
        object_id: String,
    },
}

/// Convenience alias for execution results.
pub type ExecutionResult<T> = Result<T, ExecutionError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum number of transactions in a single parallel execution batch.
pub const MAX_PARALLEL_BATCH_SIZE: usize = 10_000;

/// Maximum number of concurrent TEE execution contexts.
pub const MAX_CONCURRENT_TEE_CONTEXTS: usize = 256;

/// Timeout for a single transaction execution in milliseconds.
pub const TX_EXECUTION_TIMEOUT_MS: u64 = 5_000;

/// Maximum speculative execution depth before forced commit.
pub const MAX_SPECULATIVE_DEPTH: usize = 8;

/// Minimum parallelism factor before sequential fallback is considered.
pub const MIN_PARALLELISM_FACTOR: f32 = 1.5;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_constants_are_reasonable() {
        assert!(MAX_PARALLEL_BATCH_SIZE > 0);
        assert!(MAX_CONCURRENT_TEE_CONTEXTS > 0);
        assert!(TX_EXECUTION_TIMEOUT_MS > 0);
        assert!(MIN_PARALLELISM_FACTOR > 1.0);
    }
}
