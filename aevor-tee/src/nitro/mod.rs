//! AWS Nitro Enclaves TEE platform backend.
//!
//! Nitro Enclaves are isolated VMs on AWS EC2 instances backed by the
//! Nitro Security Module (NSM). Attestation produces a COSE_Sign1-signed
//! CBOR document containing PCR measurements and an AWS-rooted certificate.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

pub mod verify;

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

/// Generate an AWS Nitro attestation document (simulation abstraction).
///
/// The real device path is [`attest`]; this retains the simulated
/// [`AttestationReport`] shape used by the platform abstraction and tests.
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

    Ok(crate::attestation::seal(AttestationReport {
        platform: TeePlatform::AwsNitro,
        raw_report: Vec::new(),
        code_measurement: pcr0,      // PCR0: enclave image measurement
        signer_measurement: Hash256::ZERO, // PCR8: signing cert (empty in sim)
        nonce,
        is_production: false, // Simulation mode
        svn: 0,
        user_data: user_data.to_vec(),
    }))
}

/// Request a **real** AWS Nitro attestation document from the NSM device,
/// binding `user_data` (AEVOR: the `ExecutionAttestation` body) and a fresh
/// nonce. The returned bytes are a `COSE_Sign1` document that
/// [`verify::verify_document`] checks. Only functions inside a Nitro Enclave
/// (needs `/dev/nsm`); returns [`TeeError::PlatformUnavailable`] elsewhere. This
/// is the producer half of real attestation — it compiles everywhere but only
/// executes on Nitro hardware.
///
/// # Errors
/// Returns an error if entropy generation fails, the NSM device is unavailable,
/// or the NSM returns an unexpected response.
pub fn attest(user_data: &[u8]) -> TeeResult<Vec<u8>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TeeError::AttestationFailed { reason: e.to_string() })?;

    let fd = nsm_init();
    if fd < 0 {
        return Err(TeeError::PlatformUnavailable { platform: "nitro".to_string() });
    }
    let request = Request::Attestation {
        user_data: Some(user_data.to_vec().into()),
        nonce: Some(nonce.to_vec().into()),
        public_key: None,
    };
    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => Ok(document),
        other => Err(TeeError::AttestationFailed {
            reason: format!("unexpected NSM response: {other:?}"),
        }),
    }
}

/// One accepted enclave image: the PCR measurements permitted to produce blocks.
/// PCR0/1/2 are the image measurements (from `nitro-cli build-enclave`); PCR8,
/// when `Some`, additionally pins the enclave-image signing certificate.
#[derive(Clone, Debug)]
pub struct AcceptedMeasurement {
    /// PCR0 — enclave image file measurement.
    pub pcr0: Vec<u8>,
    /// PCR1 — Linux kernel + bootstrap measurement.
    pub pcr1: Vec<u8>,
    /// PCR2 — application measurement.
    pub pcr2: Vec<u8>,
    /// PCR8 — signing certificate measurement (enforced when `Some`).
    pub pcr8: Option<Vec<u8>>,
}

/// The network-agreed set of enclave measurements permitted to produce blocks.
///
/// The TEE proves *"this measured code ran in a genuine enclave"*; this registry
/// proves *"that measured code is the one the network agreed to run"*. Together
/// they are corruption detection: a validator's attestation is accepted only if
/// its PCRs match an entry here, so a validator running different code produces
/// an attestation that every verifier rejects — instant, O(1), no re-execution
/// (doc 22). Updating the registry is a governance action (a protocol upgrade).
#[derive(Clone, Debug, Default)]
pub struct MeasurementRegistry {
    accepted: Vec<AcceptedMeasurement>,
}

impl MeasurementRegistry {
    /// An empty registry (accepts nothing until measurements are added).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an accepted enclave image.
    pub fn allow(&mut self, measurement: AcceptedMeasurement) {
        self.accepted.push(measurement);
    }

    /// Number of accepted images.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Accept the document's PCRs if they match any registered measurement.
    ///
    /// # Errors
    /// Returns [`TeeError::AttestationFailed`] if no registered image matches.
    pub fn check(&self, pcrs: &std::collections::BTreeMap<u32, Vec<u8>>) -> TeeResult<()> {
        let get = |i: u32| pcrs.get(&i).map_or(&[][..], std::vec::Vec::as_slice);
        for m in &self.accepted {
            let base = get(0) == m.pcr0.as_slice()
                && get(1) == m.pcr1.as_slice()
                && get(2) == m.pcr2.as_slice();
            let signer = m.pcr8.as_ref().is_none_or(|p8| get(8) == p8.as_slice());
            if base && signer {
                return Ok(());
            }
        }
        Err(TeeError::AttestationFailed {
            reason: "enclave PCR measurements are not in the accepted registry".to_string(),
        })
    }
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
