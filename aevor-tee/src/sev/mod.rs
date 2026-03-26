//! AMD SEV (Secure Encrypted Virtualization) TEE platform backend.
//!
//! SEV-SNP provides hardware memory encryption and integrity for VMs.
//! Attestation uses the AMD Key Distribution Service (KDS) and the
//! VCEK certificate chain rooted in AMD's hardware root of trust.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

/// Returns `true` if AMD SEV-SNP is available on this platform.
///
/// Checks for the SNP guest device (`/sys/kernel/security/sev-guest`).
pub fn is_available() -> bool {
    std::path::Path::new("/sys/kernel/security/sev-guest").exists()
}

/// Detect AMD SEV platform capabilities.
///
/// Returns an error if SEV-SNP is not available. In production reads
/// the CPUID leaf 0x8000001F for SEV/SNP feature flags.
pub fn detect_capabilities() -> TeeResult<PlatformCapabilities> {
    if !is_available() {
        return Err(TeeError::PlatformUnavailable { platform: "sev".into() });
    }
    let has_aes = {
        #[cfg(target_arch = "x86_64")]
        { std::arch::is_x86_feature_detected!("aes") }
        #[cfg(not(target_arch = "x86_64"))]
        { false }
    };
    Ok(PlatformCapabilities {
        version: TeeVersion {
            platform: TeePlatform::AmdSev,
            major: 1, minor: 0, patch: 0, svn: 0,
        },
        is_production: false,
        has_crypto_acceleration: has_aes, // AMD platforms have AES-NI
        available_memory_bytes: 32 * 1024 * 1024 * 1024, // 32 GB (VM memory)
        max_concurrent_instances: 1, // One VM = one SEV context
        remote_attestation_available: true,
        sealing_available: false, // SEV-SNP: no hardware sealing API
    })
}

/// Generate an AMD SEV-SNP attestation report.
///
/// In production issues `SNP_GET_REPORT` ioctl via `/dev/sev-guest`
/// to obtain a signed attestation document with VM measurement (MEASUREMENT).
pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport> {
    use aevor_core::primitives::Hash256;
    use aevor_crypto::hash::Blake3Hasher;

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"aevor-sev-simulation-v1:");
    hasher.update(user_data);
    let measurement = hasher.finalize().0;

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TeeError::AttestationFailed { reason: e.to_string() })?;

    Ok(AttestationReport {
        platform: TeePlatform::AmdSev,
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
    fn detect_capabilities_fails_gracefully_without_sev() {
        if !is_available() {
            let err = detect_capabilities().unwrap_err();
            match err {
                TeeError::PlatformUnavailable { platform } => assert_eq!(platform, "sev"),
                other => panic!("Expected PlatformUnavailable, got {:?}", other),
            }
        }
    }

    #[test]
    fn generate_report_produces_valid_structure() {
        let report = generate_report(b"sev test data").unwrap();
        assert_eq!(report.platform, TeePlatform::AmdSev);
        assert!(!report.raw_report.is_empty());
        assert!(!report.is_production);
    }

    #[test]
    fn generate_report_measurement_non_zero() {
        let report = generate_report(b"non-empty").unwrap();
        assert_ne!(report.code_measurement, Hash256::ZERO);
    }

    #[test]
    fn generate_report_different_inputs_different_measurements() {
        let r1 = generate_report(b"vm-config-a").unwrap();
        let r2 = generate_report(b"vm-config-b").unwrap();
        assert_ne!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn generate_report_measurement_is_deterministic() {
        let r1 = generate_report(b"stable-input").unwrap();
        let r2 = generate_report(b"stable-input").unwrap();
        assert_eq!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn capabilities_sealing_not_available() {
        // SEV-SNP does not expose a sealing API — verify this is reflected
        if is_available() {
            let caps = detect_capabilities().unwrap();
            assert!(!caps.sealing_available);
            assert!(caps.remote_attestation_available);
        }
    }
}
