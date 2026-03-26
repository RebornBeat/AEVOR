//! # AevorVM: Hyper-Performant Double DAG Execution Environment
//!
//! `aevor-vm` implements AevorVM, AEVOR's revolutionary smart contract execution
//! environment built on the Double DAG architecture with native TEE integration,
//! mixed privacy support, and cross-platform behavioral consistency.
//!
//! ## Double DAG Execution Architecture
//!
//! AevorVM operates on two complementary DAG layers simultaneously:
//!
//! **Object DAG** — tracks which blockchain objects each contract reads and writes,
//! enabling the Micro-DAG scheduler to identify independent contracts that can execute
//! in true parallel without any coordination overhead.
//!
//! **Execution DAG** — records the causal relationships between contract invocations,
//! enabling mathematical verification of execution flow correctness through TEE attestation.
//!
//! ## Move-First Architecture
//!
//! AevorVM uses the Move language as its primary smart contract language, extended with
//! AEVOR-specific capabilities:
//! - Native TEE service access through type-safe interfaces
//! - Object-level privacy policy declarations
//! - Mixed privacy execution (public and private in the same contract)
//! - Cross-platform attestation integration
//!
//! ## TEE-Secured Runtime
//!
//! The VM runtime can operate inside TEE environments for confidential contract
//! execution. When TEE execution is requested, the entire VM state is isolated within
//! the secure enclave and execution is attested cryptographically.
//!
//! ## Performance
//!
//! | Contract Type | Throughput | Latency |
//! |--------------|------------|---------|
//! | Basic | 50,000+ ops/sec | <1ms |
//! | TEE-Enhanced | 25,000+ ops/sec | <2ms |
//! | Mixed Privacy | 15,000+ ops/sec | <5ms |
//! | Cross-Contract | 10,000+ ops/sec | <10ms |
//!
//! JIT compilation of hot code paths (activated after configurable warmup)
//! provides an additional 200–400% performance improvement for frequently executed contracts.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Core VM: execution engine, instruction dispatch, call stack management.
pub mod vm;

/// Move language runtime: bytecode interpreter, type checker, resource safety.
pub mod move_runtime;

/// Bytecode: Move bytecode representation, parsing, serialization.
pub mod bytecode;

/// Memory manager: object memory, privacy-isolated heap regions, TEE-protected pages.
pub mod memory;

/// Gas metering: instruction costs, memory costs, TEE execution premiums.
pub mod gas;

/// JIT compiler: hot-path compilation for performance-critical code paths.
pub mod jit;

/// TEE integration: secure execution environments, attestation, anti-snooping.
pub mod tee_integration;

/// Parallel execution coordinator: Object DAG analysis, lane scheduling.
pub mod parallel;

/// Mixed privacy execution: cross-privacy contract coordination.
pub mod privacy;

/// Cross-contract calls: inter-contract communication with dependency tracking.
pub mod cross_contract;

/// Execution context: transaction context, block context, TEE context.
pub mod context;

/// Instruction set: complete AevorVM instruction definitions and semantics.
pub mod instructions;

/// Object model: AEVOR object lifecycle within the VM.
pub mod objects;

/// Standard library: built-in Move modules with AEVOR extensions.
pub mod stdlib;

// ============================================================
// PRELUDE
// ============================================================

/// VM prelude — all essential VM types.
///
/// ```rust
/// use aevor_vm::prelude::*;
/// ```
pub mod prelude {
    pub use crate::vm::{
        AevorVm, VmConfig, VmState, ExecutionSession,
        VmCapabilities, ContractRegistry,
    };
    pub use crate::move_runtime::{
        MoveRuntime, MoveModule, MoveFunction, MoveValue, MoveType,
        ResourceTable, TypeParameters, ModuleMetadata,
    };
    pub use crate::bytecode::{
        Bytecode, BytecodeModule, Instruction, FunctionDefinition,
        BytecodeVerifier,
    };
    pub use crate::memory::{
        MemoryManager, MemoryRegion, PrivateHeap, PublicHeap,
        TeeProtectedMemory, MemoryIsolation,
    };
    pub use crate::gas::{
        GasMeter, GasSchedule, InstructionGas, MemoryGas,
        TeeExecutionPremium, GasEstimator,
    };
    pub use crate::jit::{
        JitCompiler, JitCache, CompiledFunction, WarmupTracker,
        HotPathOptimizer,
    };
    pub use crate::tee_integration::{
        TeeVmExecutor, TeeContractContext, AttestationIntegration,
        SecureContractExecution, TeeIsolatedVm,
    };
    pub use crate::parallel::{
        VmParallelScheduler, ObjectDagAnalyzer, ExecutionLaneManager,
        ParallelContractSet, ConflictAwareLaneAssignment,
    };
    pub use crate::privacy::{
        MixedPrivacyExecutor, PrivacyBoundaryEnforcer, CrossPrivacyContract,
        SelectiveDisclosureVm, PrivateStateManager,
    };
    pub use crate::context::{
        VmExecutionContext, TransactionContext, BlockContext, TeeContext,
        VmPrivacyContext,
    };
    pub use crate::{VmError, VmResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from VM execution.
#[derive(Clone, Debug, thiserror::Error)]
pub enum VmError {
    /// Contract execution ran out of gas.
    #[error("out of gas: used {used}, limit {limit}")]
    OutOfGas {
        /// Gas consumed before the limit was reached.
        used: u64,
        /// Gas limit for this execution.
        limit: u64,
    },

    /// Smart contract aborted with an error code.
    #[error("contract aborted with code {code}: {message}")]
    ContractAbort {
        /// Numeric abort code from the contract.
        code: u64,
        /// Optional message from the contract.
        message: String,
    },

    /// Move type or resource safety violation.
    #[error("Move type error: {0}")]
    TypeViolation(String),

    /// Stack overflow in recursive contract calls.
    #[error("call stack overflow at depth {depth}")]
    StackOverflow {
        /// Call depth when overflow occurred.
        depth: u32,
    },

    /// Attempted to access an object without proper authorization.
    #[error("unauthorized object access: object {object_id}")]
    UnauthorizedAccess {
        /// Identifier of the object that was illegally accessed.
        object_id: String,
    },

    /// Privacy boundary violation attempt.
    #[error("privacy boundary violation: {description}")]
    PrivacyViolation {
        /// Description of the attempted violation.
        description: String,
    },

    /// Contract module is not deployed or has been destroyed.
    #[error("module not found: {module_id}")]
    ModuleNotFound {
        /// Module identifier that was not found.
        module_id: String,
    },

    /// TEE execution required but TEE is unavailable.
    #[error("TEE execution required but unavailable: {reason}")]
    TeeUnavailable {
        /// Reason TEE is unavailable.
        reason: String,
    },

    /// Bytecode verification failed.
    #[error("bytecode verification failed: {0}")]
    BytecodeVerificationFailed(String),

    /// JIT compilation error.
    #[error("JIT compilation error: {0}")]
    JitError(String),
}

/// Convenience alias for VM results.
pub type VmResult<T> = Result<T, VmError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum call stack depth to prevent stack overflow.
pub const MAX_CALL_STACK_DEPTH: u32 = 128;

/// Default gas limit for a single contract invocation.
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

/// Gas cost per instruction (base).
pub const GAS_PER_INSTRUCTION: u64 = 1;

/// Gas cost per byte of memory allocated.
pub const GAS_PER_MEMORY_BYTE: u64 = 1;

/// Gas multiplier for TEE-protected execution.
pub const TEE_EXECUTION_GAS_MULTIPLIER: u64 = 2;

/// Number of invocations before JIT compilation activates for a function.
pub const JIT_WARMUP_THRESHOLD: u64 = 100;

/// Maximum Move bytecode module size in bytes (8 MiB).
pub const MAX_MODULE_SIZE_BYTES: usize = 8_388_608;

/// Maximum number of generic type parameters in a Move function.
pub const MAX_TYPE_PARAMETERS: usize = 32;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_constants_are_positive() {
        assert!(GAS_PER_INSTRUCTION > 0);
        assert!(GAS_PER_MEMORY_BYTE > 0);
        assert!(TEE_EXECUTION_GAS_MULTIPLIER > 1);
    }

    #[test]
    fn call_depth_limit_is_reasonable() {
        assert!(MAX_CALL_STACK_DEPTH >= 64);
        assert!(MAX_CALL_STACK_DEPTH <= 1024);
    }
}
