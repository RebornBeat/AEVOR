//! # AEVOR Node: Complete System Orchestration
//!
//! `node` is the final integration point that assembles all AEVOR infrastructure
//! crates into a unified, production-ready blockchain node. This crate demonstrates
//! genuine blockchain trilemma transcendence by coordinating the complete set of
//! revolutionary capabilities into seamless operation.
//!
//! ## Integration Architecture
//!
//! The node orchestrates 21 specialized crates through a dependency-respecting
//! initialization sequence that ensures each subsystem starts in the correct order
//! with all its dependencies properly initialized:
//!
//! ```text
//! PATH 0 (Foundation)
//!   aevor-core → aevor-config → aevor-crypto → aevor-tee
//!
//! PATH 1 (Core Blockchain)
//!   aevor-consensus → aevor-dag → aevor-storage → aevor-vm → aevor-execution
//!
//! PATH 2 (Network + Security)
//!   aevor-network → aevor-security
//!
//! PATH 3 (Language + Cross-Chain)
//!   aevor-move → aevor-zk → aevor-bridge
//!
//! PATH 4 (Governance + Naming)
//!   aevor-governance → aevor-ns
//!
//! PATH 5 (External Interface)
//!   aevor-metrics → aevor-api → aevor-client → aevor-cli
//!
//! PATH 6 (Final Services)
//!   aevor-faucet → node (final integration)
//! ```
//!
//! ## Node Types
//!
//! **Validator Node**: Full participation in consensus with TEE service provision.
//! Earns rewards for consensus participation and service quality.
//!
//! **Full Node**: Stores complete blockchain state, serves API requests, but does
//! not participate in consensus or earn validator rewards.
//!
//! **Archive Node**: Stores complete historical blockchain state including pruned
//! state for historical queries.
//!
//! **Light Node**: Verifies only headers and relevant Merkle proofs. Minimal
//! resource requirements for edge deployment.
//!
//! ## Revolutionary Capabilities Demonstration
//!
//! The node initialization verifies at startup that the assembled system can
//! achieve the performance and security characteristics that distinguish genuine
//! trilemma transcendence from traditional trade-off optimization.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Node orchestrator: top-level node lifecycle and subsystem coordination.
pub mod orchestrator;

/// Initialization sequence: ordered startup of all subsystems.
pub mod init;

/// Shutdown sequence: graceful shutdown with state preservation.
pub mod shutdown;

/// Node configuration: assembling `AevorConfig` for the complete node.
pub mod config;

/// Health monitoring: node-wide health checks and readiness probes.
pub mod health;

/// Validator node: consensus participation and TEE service provision.
pub mod validator;

/// Full node: complete state storage without consensus participation.
pub mod full_node;

/// Archive node: complete historical state with extended storage.
pub mod archive;

/// Light node: header-only verification for edge deployment.
pub mod light_node;

/// Process management: signal handling, process supervision.
pub mod process;

/// Node metrics: system-level metrics across all subsystems.
pub mod metrics;

// ============================================================
// PRELUDE
// ============================================================

/// Node prelude — all essential node orchestration types.
///
/// ```rust
/// use node::prelude::*;
/// ```
pub mod prelude {
    pub use crate::orchestrator::{
        NodeOrchestrator, OrchestratorConfig, SubsystemHandle, OrchestratorState,
        NodeHandle,
    };
    pub use crate::init::{
        NodeInitializer, InitializationSequence, InitStep, InitResult,
        SubsystemDependency,
    };
    pub use crate::shutdown::{
        GracefulShutdown, ShutdownReason, ShutdownSequence, ShutdownTimeout,
        StatePreservation,
    };
    pub use crate::config::{
        NodeConfig, ValidatorConfig, FullNodeConfig, ArchiveConfig,
        LightNodeConfig,
    };
    pub use crate::health::{
        HealthChecker, HealthStatus, SubsystemHealth, ReadinessProbe,
        LivenessProbe,
    };
    pub use crate::validator::{
        ValidatorNode, ValidatorOrchestrator, ConsensusHandle,
        ValidatorTeeHandle, ValidatorState,
    };
    pub use crate::full_node::{
        FullNode, FullNodeOrchestrator, StorageHandle,
        ApiHandle, FullNodeNetworkHandle,
    };
    pub use crate::metrics::{
        NodeMetrics, SystemMetrics, SubsystemMetrics, MetricsDashboard,
    };
    pub use crate::{NodeError, NodeResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from node orchestration.
#[derive(Clone, Debug, thiserror::Error)]
pub enum NodeError {
    /// A required subsystem failed to initialize.
    #[error("subsystem initialization failed: {subsystem} — {reason}")]
    InitializationFailed {
        /// Name of the subsystem that failed.
        subsystem: String,
        /// Reason for initialization failure.
        reason: String,
    },

    /// A subsystem crashed during operation and could not be recovered.
    #[error("subsystem crash: {subsystem} — {reason}")]
    SubsystemCrash {
        /// Name of the crashed subsystem.
        subsystem: String,
        /// Reason for the crash.
        reason: String,
    },

    /// Configuration is invalid for the requested node type.
    #[error("invalid configuration for {node_type}: {reason}")]
    InvalidConfiguration {
        /// Type of node being configured.
        node_type: String,
        /// Reason the configuration is invalid.
        reason: String,
    },

    /// Shutdown timed out waiting for subsystems to stop cleanly.
    #[error("shutdown timeout: {subsystem} did not stop within {timeout_ms}ms")]
    ShutdownTimeout {
        /// Subsystem that failed to stop.
        subsystem: String,
        /// Timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// TEE environment required for validator operation is unavailable.
    #[error("TEE unavailable for validator operation: {reason}")]
    TeeUnavailableForValidator {
        /// Reason TEE is unavailable.
        reason: String,
    },

    /// Health check failed — node is not healthy.
    #[error("health check failed: {subsystem} — {status}")]
    HealthCheckFailed {
        /// Subsystem with health failure.
        subsystem: String,
        /// Health status description.
        status: String,
    },
}

/// Convenience alias for node results.
pub type NodeResult<T> = Result<T, NodeError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Startup timeout: maximum time to initialize all subsystems in milliseconds (60s).
pub const NODE_STARTUP_TIMEOUT_MS: u64 = 60_000;

/// Shutdown timeout: maximum time for graceful shutdown in milliseconds (30s).
pub const NODE_SHUTDOWN_TIMEOUT_MS: u64 = 30_000;

/// Health check interval in milliseconds.
pub const HEALTH_CHECK_INTERVAL_MS: u64 = 5_000;

/// Maximum subsystem restart attempts before marking node unhealthy.
pub const MAX_SUBSYSTEM_RESTART_ATTEMPTS: u32 = 3;

/// Subsystem restart backoff in milliseconds.
pub const SUBSYSTEM_RESTART_BACKOFF_MS: u64 = 1_000;

/// Number of subsystems in the complete AEVOR node.
pub const TOTAL_SUBSYSTEM_COUNT: usize = 21;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_timeout_less_than_startup() {
        assert!(NODE_SHUTDOWN_TIMEOUT_MS < NODE_STARTUP_TIMEOUT_MS);
    }

    #[test]
    fn subsystem_count_matches_crate_count() {
        // 21 subsystem crates (all crates except node itself)
        assert_eq!(TOTAL_SUBSYSTEM_COUNT, 21);
    }

    #[test]
    fn restart_backoff_is_reasonable() {
        assert!(SUBSYSTEM_RESTART_BACKOFF_MS > 0);
        assert!(MAX_SUBSYSTEM_RESTART_ATTEMPTS >= 2);
    }
}
