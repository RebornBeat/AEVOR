//! # AEVOR Execution: Multi-TEE Orchestration and Coordination
//!
//! `aevor-execution` orchestrates the complete transaction execution pipeline,
//! coordinating `AevorVM`, TEE environments, parallel scheduling, and privacy
//! boundary management into a unified execution framework.
//!
//! ## Responsibilities
//!
//! This crate owns the execution pipeline from transaction receipt to result commitment:
//!
//! 1. **Pre-execution**: dependency analysis, TEE allocation, gas validation
//! 2. **Parallel scheduling**: lane assignment across available execution resources
//! 3. **Deterministic execution**: coordinated `AevorVM` invocations with TEE attestation
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

/// Pre-execution conflict analysis: tracking which transactions were accepted or rejected
/// before execution begins. No speculative state execution occurs.
pub mod speculative;

/// Execution metrics: throughput, latency, parallelism factor measurement.
pub mod metrics;

/// Cross-contract execution: coordinating multi-contract atomic operations.
pub mod cross_contract;

/// Transaction rejection log: records why transactions were rejected (gas, privacy,
/// pre-execution conflicts) without any state being unwound.
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

    /// Transaction was rejected due to a pre-execution conflict detected by the scheduler.
    ///
    /// This is NOT a rollback of committed state — the transaction never began execution.
    /// The sender may resubmit after the conflicting transaction completes.
    #[error("transaction rejected: pre-execution conflict on object {object_id}")]
    TransactionRejected {
        /// Object ID at the center of the pre-execution conflict.
        object_id: String,
    },
}

/// Convenience alias for execution results.
pub type ExecutionResult<T> = Result<T, ExecutionError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default number of transactions in a single parallel execution batch.
/// Scales with available hardware — not a hard ceiling. Configurable per deployment.
pub const DEFAULT_PARALLEL_BATCH_SIZE: usize = 10_000;

/// Default number of concurrent TEE execution contexts.
/// Scales with available TEE hardware — not a hard ceiling. Configurable per deployment.
pub const DEFAULT_CONCURRENT_TEE_CONTEXTS: usize = 256;

/// Default per-transaction gas execution timeout in milliseconds.
/// Prevents runaway gas consumption. Configurable per deployment.
/// This is not a throughput ceiling — it is a per-transaction resource budget.
pub const DEFAULT_TX_EXECUTION_TIMEOUT_MS: u64 = 5_000;

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
        assert!(DEFAULT_PARALLEL_BATCH_SIZE > 0);
        assert!(DEFAULT_CONCURRENT_TEE_CONTEXTS > 0);
        assert!(DEFAULT_TX_EXECUTION_TIMEOUT_MS > 0);
        assert!(MIN_PARALLELISM_FACTOR > 1.0);
    }

    #[test]
    fn vm_failed_error_formats_correctly() {
        let e = ExecutionError::VmFailed("out of gas".into());
        assert!(e.to_string().contains("out of gas"));
    }

    #[test]
    fn gas_limit_exceeded_contains_values() {
        let e = ExecutionError::GasLimitExceeded { used: 1000, limit: 500 };
        let s = e.to_string();
        assert!(s.contains("1000") && s.contains("500"));
    }

    #[test]
    fn privacy_violation_error_formats() {
        let e = ExecutionError::PrivacyViolation { description: "boundary crossed".into() };
        assert!(e.to_string().contains("boundary crossed"));
    }

    #[test]
    fn tee_allocation_failed_formats() {
        let e = ExecutionError::TeeAllocationFailed { reason: "no enclave".into() };
        assert!(e.to_string().contains("no enclave"));
    }

    #[test]
    fn transaction_rejected_is_pre_execution_not_rollback() {
        // TransactionRejected replaces the removed RolledBack/SpeculativeConflict variants.
        // It represents pre-execution conflict detection — the transaction never began
        // execution, so no state was ever unwound.
        let e = ExecutionError::TransactionRejected { object_id: "obj_0x1234".into() };
        let s = e.to_string();
        assert!(s.contains("obj_0x1234"));
        assert!(s.contains("rejected"));
    }

    #[test]
    fn execution_result_ok_is_ok() {
        let r: ExecutionResult<u32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn execution_result_err_is_err() {
        let r: ExecutionResult<()> = Err(ExecutionError::VmFailed("x".into()));
        assert!(r.is_err());
    }

    #[test]
    fn pipeline_config_default_enables_parallel() {
        let cfg = pipeline::PipelineConfig::default();
        assert!(cfg.parallel_stages);
        assert!(cfg.max_pipeline_depth > 0);
    }

    #[test]
    fn execution_metrics_default_zero() {
        let m = metrics::ExecutionMetrics::default();
        assert_eq!(m.total_executed, 0);
        assert_eq!(m.success_rate, 0.0);
    }

    #[test]
    fn scheduling_decision_lane_assigned() {
        use crate::scheduler::SchedulingDecision;
        use aevor_core::primitives::Hash256;
        use aevor_core::execution::ExecutionLane;
        let d = SchedulingDecision {
            transaction: Hash256([1u8; 32]),
            lane: ExecutionLane(3),
            priority: 10,
        };
        assert_eq!(d.lane, ExecutionLane(3));
        assert_eq!(d.priority, 10);
    }
}
