//! TEE platform abstraction: `TeeBackend` trait and runtime platform detection.
//!
//! This module provides the unified interface that the rest of the system
//! uses to interact with any of the five supported TEE platforms without
//! platform-specific code paths in callers.

pub use aevor_core::tee::{TeePlatform, PlatformCapabilities, TeeVersion};
use crate::{AttestationReport, TeeResult};

/// The set of TEE platforms detected as available on this hardware.
#[derive(Clone, Debug)]
pub struct SupportedPlatforms {
    /// Platforms detected and ready to use.
    pub available: Vec<TeePlatform>,
    /// The preferred platform to use (first in `available`, if any).
    pub preferred: Option<TeePlatform>,
}

impl SupportedPlatforms {
    /// Detect which TEE platforms are available on this machine at runtime.
    ///
    /// Probes each platform's device file / sysfs entry. Results depend on
    /// the hardware and installed kernel drivers.
    pub fn detect() -> Self {
        let mut available = Vec::new();

        #[cfg(target_arch = "x86_64")]
        if crate::sgx::is_available() { available.push(TeePlatform::IntelSgx); }

        if crate::sev::is_available()       { available.push(TeePlatform::AmdSev); }
        if crate::trustzone::is_available() { available.push(TeePlatform::ArmTrustZone); }
        if crate::keystone::is_available()  { available.push(TeePlatform::RiscvKeystone); }
        if crate::nitro::is_available()     { available.push(TeePlatform::AwsNitro); }

        let preferred = available.first().copied();
        Self { available, preferred }
    }

    /// Returns `true` if at least one TEE platform is available.
    pub fn has_any(&self) -> bool { !self.available.is_empty() }

    /// Returns `true` if the given platform is in the available set.
    pub fn supports(&self, platform: TeePlatform) -> bool {
        self.available.contains(&platform)
    }
}

/// Dispatches platform capability queries to the correct backend.
pub struct PlatformDetection;

impl PlatformDetection {
    /// Query capabilities for the given platform.
    ///
    /// # Errors
    /// Returns an error if the platform is not available on this machine.
    pub fn detect_capabilities(platform: TeePlatform) -> TeeResult<PlatformCapabilities> {
        match platform {
            TeePlatform::IntelSgx     => crate::sgx::detect_capabilities(),
            TeePlatform::AmdSev       => crate::sev::detect_capabilities(),
            TeePlatform::ArmTrustZone => crate::trustzone::detect_capabilities(),
            TeePlatform::RiscvKeystone => crate::keystone::detect_capabilities(),
            TeePlatform::AwsNitro     => crate::nitro::detect_capabilities(),
        }
    }

    /// Generate an attestation report on the given platform.
    ///
    /// # Errors
    /// Returns an error if the platform is unavailable or the hardware fails
    /// to produce an attestation (e.g. quoting service not running for SGX).
    pub fn generate_report(platform: TeePlatform, user_data: &[u8]) -> TeeResult<AttestationReport> {
        match platform {
            TeePlatform::IntelSgx     => crate::sgx::generate_report(user_data),
            TeePlatform::AmdSev       => crate::sev::generate_report(user_data),
            TeePlatform::ArmTrustZone => crate::trustzone::generate_report(user_data),
            TeePlatform::RiscvKeystone => crate::keystone::generate_report(user_data),
            TeePlatform::AwsNitro     => crate::nitro::generate_report(user_data),
        }
    }
}

/// Core trait implemented by each TEE platform backend.
///
/// All five platforms implement this trait — the coordinator uses it to
/// route operations to the correct platform without knowing the specifics.
pub trait TeeBackend: Send + Sync {
    /// The platform this backend implements.
    fn platform(&self) -> TeePlatform;

    /// Generate an attestation report for the given user data.
    ///
    /// # Errors
    /// Returns an error if the TEE is unavailable or attestation generation fails.
    fn generate_attestation(&self, user_data: &[u8]) -> TeeResult<AttestationReport>;

    /// Verify an attestation report from another enclave on this platform.
    ///
    /// # Errors
    /// Returns an error if the platform is unable to parse or verify the report.
    fn verify_attestation(&self, report: &AttestationReport) -> TeeResult<bool>;

    /// Returns `true` if this backend is available on the current hardware.
    fn is_available(&self) -> bool;

    /// Detected capabilities of this platform.
    ///
    /// # Errors
    /// Returns an error if the platform driver is not loaded or not accessible.
    fn capabilities(&self) -> TeeResult<PlatformCapabilities>;

    /// Execute a closure inside an isolated enclave context.
    ///
    /// The closure runs with the platform's full isolation guarantees.
    /// Results are returned after the isolated execution completes.
    ///
    /// # Errors
    /// Returns an error if the enclave cannot be created or the closure fails.
    fn execute_isolated<F, R>(&self, f: F) -> TeeResult<R>
    where
        F: FnOnce() -> TeeResult<R> + Send,
        R: Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_platforms_detect_does_not_panic() {
        let platforms = SupportedPlatforms::detect();
        // In CI without TEE hardware this will be empty — that's valid.
        let _ = platforms.has_any();
    }

    #[test]
    fn platform_detection_fails_gracefully_on_ci() {
        // All platforms should fail gracefully when hardware is absent.
        for platform in [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ] {
            let result = PlatformDetection::detect_capabilities(platform);
            // Either succeeds (hardware present) or returns PlatformUnavailable.
            match result {
                Ok(_) | Err(crate::TeeError::PlatformUnavailable { .. }) => {}
                Err(e) => panic!("unexpected error for {:?}: {:?}", platform, e),
            }
        }
    }

    #[test]
    fn generate_report_works_for_all_platforms() {
        let user_data = b"test user data";
        for platform in [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ] {
            let report = PlatformDetection::generate_report(platform, user_data).unwrap();
            assert_eq!(report.platform, platform);
            assert!(!report.raw_report.is_empty());
        }
    }
}
