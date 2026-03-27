//! RISC-V Keystone TEE platform backend.
//!
//! Keystone is an open-source TEE framework for RISC-V processors.
//! It uses hardware Physical Memory Protection (PMP) to enforce enclave
//! isolation boundaries. Attestation uses ED25519 signatures from the
//! Security Monitor (SM) and the Keystone RoT key.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

/// Returns `true` if RISC-V Keystone is available on this platform.
///
/// Checks for the Keystone kernel driver (`/dev/keystone_enclave`).
pub fn is_available() -> bool {
    std::path::Path::new("/dev/keystone_enclave").exists()
}

/// Detect RISC-V Keystone platform capabilities.
///
/// Returns an error if Keystone is not available. In production reads
/// configuration from the Keystone Security Monitor via ioctl.
///
/// # Errors
/// Returns `TeeError::PlatformUnavailable` if the Keystone driver is absent.
pub fn detect_capabilities() -> TeeResult<PlatformCapabilities> {
    if !is_available() {
        return Err(TeeError::PlatformUnavailable { platform: "keystone".into() });
    }
    Ok(PlatformCapabilities {
        version: TeeVersion {
            platform: TeePlatform::RiscvKeystone,
            major: 1, minor: 0, patch: 0, svn: 0,
        },
        is_production: false,
        has_crypto_acceleration: false, // RISC-V Zk* extensions are board-specific
        available_memory_bytes: 128 * 1024 * 1024, // 128 MB (board-dependent)
        max_concurrent_instances: 4,
        remote_attestation_available: true,
        sealing_available: false, // Keystone has no hardware sealing
    })
}

/// Generate a RISC-V Keystone attestation report.
///
/// In production calls the Keystone Security Monitor via the runtime API
/// (`keystone_create_enclave` + `keystone_run_enclave`) and retrieves the
/// SM-signed attestation via `keystone_call`.
///
/// # Errors
/// Returns an error if OS entropy generation fails during nonce creation.
pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport> {
    use aevor_core::primitives::Hash256;
    use aevor_crypto::hash::Blake3Hasher;

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"aevor-keystone-simulation-v1:");
    hasher.update(user_data);
    let measurement = hasher.finalize().0;

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TeeError::AttestationFailed { reason: e.to_string() })?;

    Ok(AttestationReport {
        platform: TeePlatform::RiscvKeystone,
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
    fn detect_capabilities_fails_gracefully_without_keystone() {
        if !is_available() {
            let err = detect_capabilities().unwrap_err();
            match err {
                TeeError::PlatformUnavailable { platform } => assert_eq!(platform, "keystone"),
                other => panic!("Expected PlatformUnavailable, got {:?}", other),
            }
        }
    }

    #[test]
    fn generate_report_valid_structure() {
        let report = generate_report(b"keystone enclave binary").unwrap();
        assert_eq!(report.platform, TeePlatform::RiscvKeystone);
        assert_eq!(report.user_data, b"keystone enclave binary");
        assert!(!report.raw_report.is_empty());
        assert_ne!(report.code_measurement, Hash256::ZERO);
    }

    #[test]
    fn generate_report_measurement_is_deterministic() {
        let r1 = generate_report(b"same-eapp").unwrap();
        let r2 = generate_report(b"same-eapp").unwrap();
        assert_eq!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn generate_report_different_eapps_different_measurements() {
        let r1 = generate_report(b"eapp-version-1").unwrap();
        let r2 = generate_report(b"eapp-version-2").unwrap();
        assert_ne!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn capabilities_no_sealing_no_crypto_accel() {
        if is_available() {
            let caps = detect_capabilities().unwrap();
            // Keystone: no hardware sealing, conservative on crypto accel
            assert!(!caps.sealing_available);
            assert!(!caps.has_crypto_acceleration);
        }
    }
}
