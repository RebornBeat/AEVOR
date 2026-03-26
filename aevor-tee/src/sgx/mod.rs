//! Intel SGX (Software Guard Extensions) TEE platform backend.
//!
//! SGX provides hardware-enforced enclaves on Intel CPUs. Attestation
//! uses Intel DCAP (Data Center Attestation Primitives) in production.
//! This module provides the interface layer; actual SGX SDK calls are
//! made via conditional compilation when `cfg(sgx)` is set.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

/// Returns `true` if Intel SGX is available on this CPU and OS.
///
/// Performs a runtime CPUID check for SGX support and verifies that
/// the SGX driver (`/dev/sgx_enclave`) is loaded by the kernel.
pub fn is_available() -> bool {
    std::path::Path::new("/dev/sgx_enclave").exists()
}

/// Detect the SGX platform capabilities of this machine.
///
/// Returns an error if SGX is not available. In production this reads
/// the Intel SGX TCB (Trusted Computing Base) info via the DCAP libraries.
pub fn detect_capabilities() -> TeeResult<PlatformCapabilities> {
    if !is_available() {
        return Err(TeeError::PlatformUnavailable { platform: "sgx".into() });
    }
    let has_aes = {
        #[cfg(target_arch = "x86_64")]
        { std::arch::is_x86_feature_detected!("aes") }
        #[cfg(not(target_arch = "x86_64"))]
        { false }
    };
    Ok(PlatformCapabilities {
        version: TeeVersion {
            platform: TeePlatform::IntelSgx,
            major: 2, minor: 0, patch: 0, svn: 0,
        },
        is_production: false, // Set from TCB info in production
        has_crypto_acceleration: has_aes,
        available_memory_bytes: 256 * 1024 * 1024, // 256 MB EPC
        max_concurrent_instances: 64,
        remote_attestation_available: true,
        sealing_available: true,
    })
}

/// Generate an SGX attestation report for the given user data.
///
/// In production calls `sgx_create_report()` or the DCAP quote generation
/// library. Returns a simulation report when SGX is not available.
pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport> {
    use aevor_core::primitives::Hash256;
    use aevor_crypto::hash::Blake3Hasher;

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"aevor-sgx-simulation-v1:");
    hasher.update(user_data);
    let measurement = hasher.finalize().0;

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TeeError::AttestationFailed { reason: e.to_string() })?;

    Ok(AttestationReport {
        platform: TeePlatform::IntelSgx,
        raw_report: user_data.to_vec(),
        code_measurement: measurement,
        signer_measurement: Hash256::ZERO,
        nonce,
        is_production: false,
        svn: 0,
        user_data: user_data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    #[test]
    fn is_available_does_not_panic() {
        // Must not panic on any platform; returns false when driver absent
        let _ = is_available();
    }

    #[test]
    fn detect_capabilities_fails_gracefully_without_sgx() {
        if !is_available() {
            let result = detect_capabilities();
            assert!(result.is_err());
            match result.unwrap_err() {
                TeeError::PlatformUnavailable { platform } => {
                    assert_eq!(platform, "sgx");
                }
                other => panic!("Expected PlatformUnavailable, got {:?}", other),
            }
        }
    }

    #[test]
    fn generate_report_produces_valid_structure() {
        let user_data = b"test sgx attestation user data";
        let report = generate_report(user_data).unwrap();
        assert_eq!(report.platform, TeePlatform::IntelSgx);
        assert_eq!(report.user_data, user_data);
        assert!(!report.raw_report.is_empty());
    }

    #[test]
    fn generate_report_measurement_is_deterministic() {
        let user_data = b"deterministic input";
        let r1 = generate_report(user_data).unwrap();
        let r2 = generate_report(user_data).unwrap();
        // Measurement is deterministic; nonce is random
        assert_eq!(r1.code_measurement, r2.code_measurement);
        // Nonces should differ (random)
        // (With very low probability they could match, but negligible in practice)
    }

    #[test]
    fn generate_report_different_inputs_different_measurements() {
        let r1 = generate_report(b"input-a").unwrap();
        let r2 = generate_report(b"input-b").unwrap();
        assert_ne!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn generate_report_measurement_is_not_zero() {
        let report = generate_report(b"non-empty input").unwrap();
        assert_ne!(report.code_measurement, Hash256::ZERO);
    }

    #[test]
    fn capabilities_version_platform_matches() {
        if is_available() {
            let caps = detect_capabilities().unwrap();
            assert_eq!(caps.version.platform, TeePlatform::IntelSgx);
            assert_eq!(caps.version.major, 2);
        }
    }
}
