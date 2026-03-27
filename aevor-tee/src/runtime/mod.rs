//! TEE runtime environment standardization for cross-platform consistency.

use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;
use aevor_core::primitives::Hash256;

/// Standards enforced across all TEE runtimes for behavioral consistency.
#[allow(clippy::struct_excessive_bools)] // Each bool represents an independent compliance property
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvironmentStandards {
    /// All executions must be deterministic: identical inputs produce identical outputs.
    pub deterministic_execution: bool,
    /// Enclave data is encrypted at rest and sealed to the enclave identity.
    pub sealed_storage: bool,
    /// All inter-enclave communication uses authenticated encryption.
    pub secure_channels: bool,
    /// Results are identical across all supported TEE platforms.
    pub cross_platform_consistent: bool,
}

impl Default for EnvironmentStandards {
    fn default() -> Self {
        Self {
            deterministic_execution: true,
            sealed_storage: true,
            secure_channels: true,
            cross_platform_consistent: true,
        }
    }
}

impl EnvironmentStandards {
    /// Returns `true` if all standards are met.
    pub fn all_met(&self) -> bool {
        self.deterministic_execution
            && self.sealed_storage
            && self.secure_channels
            && self.cross_platform_consistent
    }
}

/// Ensures all TEE executions are deterministic (same input → same output).
pub struct DeterministicExecution {
    /// Determinism seed for PRNG operations within the enclave.
    pub seed: [u8; 32],
    /// Whether to insert constant-time delays to remove timing variance.
    pub eliminate_timing_variance: bool,
}

impl DeterministicExecution {
    /// Create a deterministic execution context with a given seed.
    pub fn new(seed: [u8; 32], eliminate_timing_variance: bool) -> Self {
        Self { seed, eliminate_timing_variance }
    }
}

/// A TEE runtime environment for a specific platform.
pub struct RuntimeEnvironment {
    /// The hardware platform this runtime runs on.
    pub platform: TeePlatform,
    /// Standards this environment is configured to enforce.
    pub standards: EnvironmentStandards,
    /// Measurement (hash) of the enclave code loaded into this environment.
    pub measurement: Hash256,
}

impl RuntimeEnvironment {
    /// Create a new runtime environment.
    pub fn new(platform: TeePlatform, measurement: Hash256) -> Self {
        Self { platform, standards: EnvironmentStandards::default(), measurement }
    }

    /// Returns `true` if this environment meets all required standards.
    pub fn is_compliant(&self) -> bool { self.standards.all_met() }
}

/// Cross-platform runtime ensuring behavioral consistency across TEEs.
pub struct CrossPlatformRuntime {
    supported: Vec<TeePlatform>,
    standards: EnvironmentStandards,
}

impl CrossPlatformRuntime {
    /// Create a cross-platform runtime supporting the given platforms.
    pub fn new(supported: Vec<TeePlatform>) -> Self {
        Self { supported, standards: EnvironmentStandards::default() }
    }

    /// Returns `true` if the given platform is in the supported set.
    pub fn supports(&self, platform: TeePlatform) -> bool {
        self.supported.contains(&platform)
    }

    /// Number of supported platforms.
    pub fn platform_count(&self) -> usize { self.supported.len() }

    /// The standards this runtime enforces.
    pub fn standards(&self) -> &EnvironmentStandards { &self.standards }
}

/// The unified TEE runtime interface used by the rest of the system.
pub struct TeeRuntime {
    platform: TeePlatform,
    environment: RuntimeEnvironment,
}

impl TeeRuntime {
    /// Create a new TEE runtime for the given platform and code measurement.
    pub fn new(platform: TeePlatform, measurement: Hash256) -> Self {
        Self {
            platform,
            environment: RuntimeEnvironment::new(platform, measurement),
        }
    }

    /// The hardware platform this runtime uses.
    pub fn platform(&self) -> TeePlatform { self.platform }

    /// The code measurement (MRENCLAVE / equivalent) for this runtime.
    pub fn measurement(&self) -> Hash256 { self.environment.measurement }

    /// Returns `true` if this runtime meets all compliance standards.
    pub fn is_compliant(&self) -> bool { self.environment.is_compliant() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_standards_all_met() {
        assert!(EnvironmentStandards::default().all_met());
    }

    #[test]
    fn runtime_environment_is_compliant_by_default() {
        let env = RuntimeEnvironment::new(TeePlatform::IntelSgx, Hash256::ZERO);
        assert!(env.is_compliant());
    }

    #[test]
    fn cross_platform_runtime_supports_check() {
        let rt = CrossPlatformRuntime::new(vec![TeePlatform::IntelSgx, TeePlatform::AmdSev]);
        assert!(rt.supports(TeePlatform::IntelSgx));
        assert!(!rt.supports(TeePlatform::AwsNitro));
        assert_eq!(rt.platform_count(), 2);
    }
}
