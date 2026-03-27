//! # AEVOR TEE: Multi-Platform Trusted Execution Environment Coordination
//!
//! `aevor-tee` provides the unified interface for AEVOR's TEE-as-a-Service infrastructure,
//! coordinating secure execution across Intel SGX, AMD SEV, ARM `TrustZone`, RISC-V Keystone,
//! and AWS Nitro Enclaves with behavioral consistency and anti-snooping protection.
//!
//! ## Design Principles
//!
//! **Behavioral Consistency**: Identical security guarantees and execution results across all
//! five supported platforms. Platform-specific optimizations are permitted and encouraged as
//! long as they don't alter observable behavior.
//!
//! **Service Allocation Without Business Logic**: This crate allocates TEE resources and
//! manages platform coordination. Business logic, service policies, and economic decisions
//! belong in higher-level crates that use these primitives.
//!
//! **Anti-Snooping by Default**: All TEE operations implement hardware-level isolation that
//! prevents infrastructure providers from observing computation inputs, outputs, or
//! intermediate states, even when they control the underlying hardware.
//!
//! **Decentralized Coordination**: TEE service allocation happens through validator
//! infrastructure without centralized registries or external authority dependencies.
//!
//! ## Platform Architecture
//!
//! Each supported platform has a dedicated module implementing the `TeeBackend` trait,
//! which normalizes platform-specific APIs into a unified interface. The `coordinator`
//! module orchestrates cross-platform operation and attestation verification.
//!
//! ## Mathematical Verification
//!
//! TEE attestation provides mathematical proof that execution occurred correctly within
//! a verified secure environment. This eliminates probabilistic assumptions about
//! infrastructure provider behavior.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Platform abstraction: the `TeeBackend` trait and platform selection logic.
pub mod platform;

/// Intel SGX integration: enclave management, sealing, local/remote attestation.
pub mod sgx;

/// AMD SEV integration: encrypted VM management, attestation report generation.
pub mod sev;

/// ARM TrustZone integration: secure world management, TA lifecycle, attestation.
pub mod trustzone;

/// RISC-V Keystone integration: enclave lifecycle, configurable attestation.
pub mod keystone;

/// AWS Nitro Enclaves integration: enclave image management, NSM attestation.
pub mod nitro;

/// Cross-platform attestation: normalization, verification, and composition.
pub mod attestation;

/// Memory isolation and protection: hardware-enforced boundary management.
pub mod isolation;

/// TEE service coordination: allocation, discovery, quality management.
pub mod service;

/// Hardware acceleration integration: cryptographic offload per platform.
pub mod acceleration;

/// Anti-snooping protection: metadata shielding, traffic analysis resistance.
pub mod anti_snooping;

/// Multi-TEE coordination: distributed secure execution across multiple instances.
pub mod multi_tee;

/// TEE runtime environment standardization for cross-platform consistency.
pub mod runtime;

// ============================================================
// PRELUDE
// ============================================================

/// TEE prelude — all essential TEE types and traits.
///
/// ```rust
/// use aevor_tee::prelude::*;
/// ```
pub mod prelude {
    pub use crate::platform::{
        TeeBackend, TeePlatform, PlatformCapabilities, PlatformDetection,
        TeeVersion, SupportedPlatforms,
    };
    pub use crate::attestation::{
        AttestationReport, AttestationVerifier, CrossPlatformAttestation,
        AttestationEvidence, SecurityClaims, AttestationMode,
        LocalAttestation, RemoteAttestation,
    };
    pub use crate::isolation::{
        IsolationBoundary, MemoryProtection, ExecutionIsolation,
        IsolationLevel, SecureChannel,
    };
    pub use crate::service::{
        TeeServiceAllocator, TeeServiceRequest, TeeServiceResponse,
        TeeServiceType, AllocationStrategy, ServiceQuality,
        TeeServiceHandle, ServiceCapability,
    };
    pub use crate::anti_snooping::{
        AntiSnoopingConfig, MetadataShield, TrafficObfuscation,
        SideChannelProtection, AntiSnoopingLevel,
    };
    pub use crate::multi_tee::{
        MultiTeeCoordinator, TeeInstance, DistributedTeeExecution,
        TeeConsistencyVerifier, FaultTolerantTee,
    };
    pub use crate::runtime::{
        TeeRuntime, RuntimeEnvironment, EnvironmentStandards,
        DeterministicExecution, CrossPlatformRuntime,
    };
    pub use crate::{TeeError, TeeResult};
}

// ============================================================
// RE-EXPORTS FROM aevor-core TEE TYPES
// ============================================================

pub use aevor_core::tee::{
    AttestationReport, EnclaveIdentity, PlatformCapabilities,
    TeeIsolationBoundary, TeePlatform, TeeServiceType, TeeVersion,
};

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from TEE operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum TeeError {
    /// Requested TEE platform is not available on this hardware.
    #[error("TEE platform not available: {platform}")]
    PlatformUnavailable {
        /// Name of the unavailable platform.
        platform: String,
    },

    /// TEE attestation generation or verification failed.
    #[error("attestation failed: {reason}")]
    AttestationFailed {
        /// Reason for attestation failure.
        reason: String,
    },

    /// Memory isolation boundary could not be established.
    #[error("isolation setup failed: {reason}")]
    IsolationFailed {
        /// Reason for isolation failure.
        reason: String,
    },

    /// TEE service allocation failed.
    #[error("service allocation failed: {reason}")]
    AllocationFailed {
        /// Reason for allocation failure.
        reason: String,
    },

    /// Cross-platform consistency check failed.
    #[error("cross-platform consistency violation: {description}")]
    ConsistencyViolation {
        /// Description of the inconsistency.
        description: String,
    },

    /// Communication between TEE instances failed.
    #[error("inter-TEE communication failed: {reason}")]
    CommunicationFailed {
        /// Reason for communication failure.
        reason: String,
    },

    /// TEE enclave has been compromised or tampered with.
    #[error("TEE integrity violation detected")]
    IntegrityViolation,

    /// Platform-specific operation failed.
    #[error("platform error on {platform}: {message}")]
    PlatformError {
        /// Platform where the error occurred.
        platform: String,
        /// Error message from the platform.
        message: String,
    },
}

/// Convenience alias for TEE operation results.
pub type TeeResult<T> = Result<T, TeeError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum number of concurrent TEE instances per validator node.
pub const MAX_TEE_INSTANCES_PER_NODE: usize = 64;

/// Maximum memory per TEE instance in bytes (256 MiB default limit).
pub const DEFAULT_TEE_MEMORY_LIMIT_BYTES: usize = 268_435_456;

/// SGX enclave signature size in bytes.
pub const SGX_SIGNATURE_SIZE: usize = 384;

/// SGX measurement (MRENCLAVE) size in bytes.
pub const SGX_MEASUREMENT_SIZE: usize = 32;

/// AMD SEV measurement size in bytes.
pub const SEV_MEASUREMENT_SIZE: usize = 48;

/// ARM `TrustZone` TA UUID size in bytes.
pub const TRUSTZONE_UUID_SIZE: usize = 16;

/// AWS Nitro attestation document maximum size in bytes.
pub const NITRO_ATTESTATION_MAX_SIZE: usize = 16_384;

/// Attestation freshness window in seconds.
pub const ATTESTATION_FRESHNESS_SECONDS: u64 = 3_600; // 1 hour

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_limit_is_reasonable() {
        // 256 MiB — enough for sophisticated workloads, not excessive
        assert_eq!(DEFAULT_TEE_MEMORY_LIMIT_BYTES, 256 * 1024 * 1024);
    }

    #[test]
    fn attestation_constants_are_correct() {
        assert_eq!(SGX_MEASUREMENT_SIZE, 32);
        assert_eq!(SEV_MEASUREMENT_SIZE, 48);
        assert_eq!(TRUSTZONE_UUID_SIZE, 16);
    }
}
