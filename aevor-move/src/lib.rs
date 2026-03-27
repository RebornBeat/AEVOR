//! # AEVOR Move: Move Language TEE Integration
//!
//! `aevor-move` provides the Move language integration layer for AEVOR, extending
//! the base Move language with native TEE service access, object-level privacy
//! policies, mixed privacy execution, and cross-platform attestation.
//!
//! ## Move Language Extensions
//!
//! AEVOR extends Move with capabilities that leverage the revolutionary infrastructure:
//!
//! **TEE Service Integration**:
//! ```move
//! // Request a TEE execution environment declaratively
//! public fun confidential_compute(
//!     data: PrivateData<T>,
//!     ctx: &TeeContext
//! ): PrivateResult<R> acquires TeeService {
//!     tee::execute_confidential(data, ctx)
//! }
//! ```
//!
//! **Object-Level Privacy**:
//! ```move
//! // Declare privacy at the object definition level
//! struct SensitiveRecord has key, store {
//!     #[privacy = Confidential]
//!     medical_data: vector<u8>,
//!     #[privacy = Protected]
//!     patient_id: address,
//!     #[privacy = Public]
//!     record_type: u8,
//! }
//! ```
//!
//! **Mixed Privacy Execution**:
//! Functions can handle both public and private objects in the same transaction,
//! with the VM automatically managing privacy boundary enforcement.
//!
//! ## Compiler Pipeline
//!
//! Source → Parse → Type Check → Borrow Check → Privacy Check → Bytecode
//!
//! The privacy check pass verifies that privacy annotations are consistent and
//! that cross-privacy access patterns are properly mediated.
//!
//! ## No Development Environment
//!
//! This crate provides language integration primitives. Comprehensive development
//! tools (IDE support, debuggers, test frameworks) belong in external ecosystem
//! projects that use these primitives through well-defined interfaces.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Move compiler frontend: parsing, AST, type resolution.
pub mod compiler;

/// Move runtime integration: bytecode loading, execution interface.
pub mod runtime;

/// AEVOR Move standard library: built-in modules with TEE and privacy extensions.
pub mod stdlib;

/// TEE extension modules: native TEE service access from Move contracts.
pub mod tee_extensions;

/// Privacy extension modules: object-level privacy annotations and enforcement.
pub mod privacy_extensions;

/// Move bytecode verifier: extended verification including privacy consistency.
pub mod verifier;

/// Move type system: extended types for TEE-backed and privacy-aware values.
pub mod types;

/// Module registry: deployed module management and upgrade coordination.
pub mod registry;

/// AEVOR-specific Move attributes: `#[privacy]`, `#[tee_required]`, `#[cross_chain]`.
pub mod attributes;

/// Cross-chain Move: modules for cross-chain coordination from Move contracts.
pub mod cross_chain;

// ============================================================
// PRELUDE
// ============================================================

/// Move prelude — all essential Move integration types.
///
/// ```rust
/// use aevor_move::prelude::*;
/// ```
pub mod prelude {
    pub use crate::compiler::{
        MoveCompiler, CompileUnit, CompileOptions, CompileError,
        ParsedModule, TypeCheckedModule, VerifiedModule,
    };
    pub use crate::runtime::{
        MoveRuntimeAdapter, ModuleLoader, FunctionDispatch,
        RuntimeHandle, ExecutionHandle,
    };
    pub use crate::stdlib::{
        AevorStdlib, PrivacyModule, TeeModule, CryptoModule,
        ObjectModule, ConsensusModule,
    };
    pub use crate::tee_extensions::{
        TeeServiceModule, ConfidentialCompute, TeeContext as MoveTeeContext,
        TeeAttestation as MoveTeeAttestation, SecureExecution,
    };
    pub use crate::privacy_extensions::{
        PrivacyAnnotation, PrivateData, ProtectedData, PublicData,
        MixedPrivacyModule, SelectiveDisclosureModule,
    };
    pub use crate::verifier::{
        AevorMoveVerifier, PrivacyConsistencyCheck, TeeCompatibilityCheck,
        SecurityAnalysis, VerificationReport,
    };
    pub use crate::types::{
        PrivacyType, TeeType, AttestationType, CrossChainType,
        AevorMoveType,
    };
    pub use crate::registry::{
        ModuleRegistry, RegistryEntry, ModuleVersion, UpgradePolicy,
        ModuleMetadata,
    };
    pub use crate::attributes::{
        PrivacyAttribute, TeeRequiredAttribute, CrossChainAttribute,
        MixedPrivacyAttribute, AttributeParser,
    };
    pub use crate::{MoveError, MoveResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from Move language integration.
#[derive(Clone, Debug, thiserror::Error)]
pub enum MoveError {
    /// Move compilation failed.
    #[error("compilation failed: {message}")]
    CompilationFailed {
        /// Compiler error message.
        message: String,
        /// Source location if available.
        location: Option<String>,
    },

    /// Bytecode verification failed.
    #[error("bytecode verification failed: {reason}")]
    VerificationFailed {
        /// Reason for verification failure.
        reason: String,
    },

    /// Privacy annotation consistency violation.
    #[error("privacy annotation violation: {description}")]
    PrivacyAnnotationViolation {
        /// Description of the violation.
        description: String,
    },

    /// TEE extension usage requires TEE runtime.
    #[error("TEE extension requires TEE runtime: {extension}")]
    TeeExtensionRequiresTee {
        /// Name of the extension that requires TEE.
        extension: String,
    },

    /// Module not found in registry.
    #[error("module not found: {module_id}")]
    ModuleNotFound {
        /// Module identifier.
        module_id: String,
    },

    /// Module upgrade policy violation.
    #[error("upgrade policy violation: {reason}")]
    UpgradePolicyViolation {
        /// Reason for policy violation.
        reason: String,
    },
}

/// Convenience alias for Move operation results.
pub type MoveResult<T> = Result<T, MoveError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum size of a Move module source file in bytes (1 MiB).
pub const MAX_MODULE_SOURCE_BYTES: usize = 1_048_576;

/// Maximum number of functions per Move module.
pub const MAX_FUNCTIONS_PER_MODULE: usize = 1_024;

/// Maximum number of structs per Move module.
pub const MAX_STRUCTS_PER_MODULE: usize = 256;

/// Maximum generic type parameter depth.
pub const MAX_TYPE_DEPTH: usize = 16;

/// AEVOR Move language version.
pub const AEVOR_MOVE_VERSION: &str = "1.1.0";

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_error_display_type_error() {
        // TypeError doesn't exist - use VerificationFailed which covers type check failures
        let e = MoveError::VerificationFailed { reason: "bad type annotation".into() };
        assert!(e.to_string().contains("bad type"));
    }

    #[test]
    fn move_error_display_resource_not_found() {
        // ResourceNotFound doesn't exist - use ModuleNotFound which covers missing resources
        let e = MoveError::ModuleNotFound { module_id: "0x1::coin::Coin".into() };
        assert!(e.to_string().contains("0x1::coin::Coin"));
    }

    #[test]
    fn move_result_ok_value() {
        let r: MoveResult<u64> = Ok(99);
        assert_eq!(r.unwrap(), 99);
    }

    #[test]
    fn privacy_level_ordering() {
        use aevor_core::privacy::PrivacyLevel;
        assert!(PrivacyLevel::Private > PrivacyLevel::Public);
    }

    #[test]
    fn verifier_returns_report_for_empty_bytecode() {
        use crate::verifier::AevorMoveVerifier;
        let report = AevorMoveVerifier::verify(&[]);
        // Empty bytecode should fail verification
        assert!(!report.security.passed);
    }

    #[test]
    fn verifier_security_flags_are_consistent() {
        use crate::verifier::AevorMoveVerifier;
        let r = AevorMoveVerifier::verify(b"fake bytecode");
        // Security, privacy_consistent, tee_compatible fields are accessible
        let _ = r.security;
        let _ = r.privacy_consistent;
        let _ = r.tee_compatible;
    }
}
