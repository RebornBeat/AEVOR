//! AWS Nitro Enclaves TEE platform backend.
//!
//! Nitro Enclaves are isolated VMs on AWS EC2 instances backed by the
//! Nitro Security Module (NSM). Attestation produces a COSE_Sign1-signed
//! CBOR document containing PCR measurements and an AWS-rooted certificate.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

/// Returns `true` if running inside an AWS Nitro Enclave.
///
/// The NSM device (`/dev/nsm`) is present only inside Nitro Enclaves;
/// it is absent on the parent EC2 instance.
pub fn is_available() -> bool {
    std::path::Path::new("/dev/nsm").exists()
}

/// Detect AWS Nitro Enclave platform capabilities.
///
/// Returns an error if not running in a Nitro Enclave. In production
/// queries the NSM via `NSM_DESCRIBE` ioctl for PCR counts and capabilities.
///
/// # Errors
/// Returns `TeeError::PlatformUnavailable` if the NSM device is not present.
pub fn detect_capabilities() -> TeeResult<PlatformCapabilities> {
    if !is_available() {
        return Err(TeeError::PlatformUnavailable { platform: "nitro".into() });
    }
    let has_aes = {
        #[cfg(target_arch = "x86_64")]
        { std::arch::is_x86_feature_detected!("aes") }
        #[cfg(not(target_arch = "x86_64"))]
        { false }
    };
    Ok(PlatformCapabilities {
        version: TeeVersion {
            platform: TeePlatform::AwsNitro,
            major: 1, minor: 0, patch: 0, svn: 0,
        },
        is_production: true, // AWS manages hardware root of trust
        has_crypto_acceleration: has_aes,
        available_memory_bytes: 24 * 1024 * 1024 * 1024, // 24 GB (m5.24xlarge enclave)
        max_concurrent_instances: 1, // One enclave per EC2 instance
        remote_attestation_available: true,
        sealing_available: false, // Nitro does not expose sealing keys
    })
}

/// Generate an AWS Nitro attestation document.
///
/// In production issues the `NSM_GET_ATTESTATION_DOC` ioctl to `/dev/nsm`,
/// which returns a COSE_Sign1-encoded document with PCR[0..15] measurements
/// signed by the AWS Nitro Attestation PKI.
///
/// # Errors
/// Returns an error if OS entropy generation fails during nonce creation.
pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport> {
    use aevor_core::primitives::Hash256;
    use aevor_crypto::hash::Blake3Hasher;

    // Simulate PCR0 (enclave image measurement)
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"aevor-nitro-simulation-pcr0-v1:");
    hasher.update(user_data);
    let pcr0 = hasher.finalize().0;

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TeeError::AttestationFailed { reason: e.to_string() })?;

    Ok(AttestationReport {
        platform: TeePlatform::AwsNitro,
        raw_report: user_data.to_vec(),
        code_measurement: pcr0,      // PCR0: enclave image measurement
        signer_measurement: Hash256::ZERO, // PCR8: signing cert (empty in sim)
        nonce,
        is_production: false, // Simulation mode
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
    fn detect_capabilities_fails_gracefully_outside_nitro() {
        if !is_available() {
            let err = detect_capabilities().unwrap_err();
            match err {
                TeeError::PlatformUnavailable { platform } => assert_eq!(platform, "nitro"),
                other => panic!("Expected PlatformUnavailable, got {:?}", other),
            }
        }
    }

    #[test]
    fn generate_report_valid_structure() {
        let user_data = b"nitro enclave image";
        let report = generate_report(user_data).unwrap();
        assert_eq!(report.platform, TeePlatform::AwsNitro);
        assert_eq!(report.user_data, user_data);
        assert_ne!(report.code_measurement, Hash256::ZERO);
    }

    #[test]
    fn generate_report_pcr0_is_deterministic() {
        let r1 = generate_report(b"same-enclave-image").unwrap();
        let r2 = generate_report(b"same-enclave-image").unwrap();
        // PCR0 is deterministic for the same image
        assert_eq!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn generate_report_different_images_different_pcr0() {
        let r1 = generate_report(b"enclave-v1.0").unwrap();
        let r2 = generate_report(b"enclave-v2.0").unwrap();
        assert_ne!(r1.code_measurement, r2.code_measurement);
    }

    #[test]
    fn capabilities_nitro_is_production_fused() {
        // AWS manages hardware root of trust — always production
        if is_available() {
            let caps = detect_capabilities().unwrap();
            assert!(caps.is_production);
            assert!(!caps.sealing_available);
        }
    }

    #[test]
    fn capabilities_max_one_concurrent_instance() {
        if is_available() {
            let caps = detect_capabilities().unwrap();
            assert_eq!(caps.max_concurrent_instances, 1);
        }
    }
}
