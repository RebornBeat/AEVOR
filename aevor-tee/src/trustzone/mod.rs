//! ARM TrustZone TEE platform backend.
//!
//! TrustZone divides the SoC into a Secure World and Normal World.
//! Attestation uses ARM's Platform Security Architecture (PSA) attestation
//! token API or the OP-TEE GlobalPlatform TEE API via `/dev/tee0`.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

/// Returns `true` if ARM `TrustZone` is available on this platform.
///
/// Checks for the OP-TEE device (`/dev/tee0`) on Linux, which is present
/// when the OP-TEE OS is running as the Secure World OS.
pub fn is_available() -> bool {
    std::path::Path::new("/dev/tee0").exists()
}

/// Detect ARM `TrustZone` platform capabilities.
///
/// Returns an error if `TrustZone` is not available. In production reads
/// the `TrustZone` configuration from the device tree and OP-TEE features.
///
/// # Errors
/// Returns `TeeError::PlatformUnavailable` if the OP-TEE device is not present.
pub fn detect_capabilities() -> TeeResult<PlatformCapabilities> {
    if !is_available() {
        return Err(TeeError::PlatformUnavailable { platform: "trustzone".into() });
    }
    let has_arm_crypto = {
        #[cfg(target_arch = "aarch64")]
        { std::arch::is_aarch64_feature_detected!("aes") }
        #[cfg(not(target_arch = "aarch64"))]
        { false }
    };
    Ok(PlatformCapabilities {
        version: TeeVersion {
            platform: TeePlatform::ArmTrustZone,
            major: 1, minor: 0, patch: 0, svn: 0,
        },
        is_production: false,
        has_crypto_acceleration: has_arm_crypto,
        available_memory_bytes: 32 * 1024 * 1024, // 32 MB secure memory (SoC-dependent)
        max_concurrent_instances: 8,
        remote_attestation_available: true,
        sealing_available: true, // OP-TEE supports secure storage
    })
}

/// Generate an ARM `TrustZone` attestation report via PSA attestation token.
///
/// In production calls the PSA Attestation API (`psa_initial_attest_get_token`)
/// which produces a COSE-signed EAT (Entity Attestation Token).
///
/// # Errors
/// Returns an error if OS entropy generation fails during nonce creation.
pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport> {
    use aevor_core::primitives::Hash256;
    use aevor_crypto::hash::Blake3Hasher;

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"aevor-trustzone-simulation-v1:");
    hasher.update(user_data);
    let measurement = hasher.finalize().0;

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TeeError::AttestationFailed { reason: e.to_string() })?;

    Ok(AttestationReport {
        platform: TeePlatform::ArmTrustZone,
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
        let _ = is_available();
    }

    #[test]
    fn detect_capabilities_fails_gracefully_without_trustzone() {
        if !is_available() {
            let err = detect_capabilities().unwrap_err();
            match err {
                TeeError::PlatformUnavailable { platform } => assert_eq!(platform, "trustzone"),
                other => panic!("Expected PlatformUnavailable, got {:?}", other),
            }
        }
    }

    #[test]
    fn generate_report_valid_structure() {
        let report = generate_report(b"trustzone test").unwrap();
        assert_eq!(report.platform, TeePlatform::ArmTrustZone);
        assert_eq!(report.user_data, b"trustzone test");
        assert_ne!(report.code_measurement, Hash256::ZERO);
    }

    #[test]
    fn generate_report_deterministic_measurement() {
        let r1 = generate_report(b"same-ta-binary").unwrap();
        let r2 = generate_report(b"same-ta-binary").unwrap();
        assert_eq!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn generate_report_different_ta_different_measurement() {
        let r1 = generate_report(b"ta-version-1").unwrap();
        let r2 = generate_report(b"ta-version-2").unwrap();
        assert_ne!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn capabilities_supports_sealing() {
        // OP-TEE supports secure storage (sealing)
        if is_available() {
            let caps = detect_capabilities().unwrap();
            assert!(caps.sealing_available);
            assert_eq!(caps.version.platform, TeePlatform::ArmTrustZone);
        }
    }
}
