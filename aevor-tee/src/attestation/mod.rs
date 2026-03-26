//! Cross-platform attestation: normalization, verification, composition.

use serde::{Deserialize, Serialize};
pub use aevor_core::tee::AttestationReport;
pub use aevor_core::crypto::CrossPlatformAttestation;
use aevor_core::tee::TeePlatform;
use crate::TeeResult;

/// How attestations are generated and verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationMode {
    /// Attester and verifier share the same physical machine.
    Local,
    /// Verifier is on a different machine (standard DCAP/SNP/etc flow).
    Remote,
    /// Simulated attestation for development and testing (not production).
    Simulation,
    /// Attestation across multiple TEE platforms simultaneously.
    CrossPlatform,
}

/// Security claims extracted from a verified attestation.
pub use aevor_core::crypto::SecurityClaims;

/// Evidence bundle for an attestation event.
pub use aevor_core::consensus::AttestationEvidence;

/// Local attestation (same machine, two enclaves communicating).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalAttestation {
    /// The attestation report from the local enclave.
    pub report: AttestationReport,
    /// Target enclave info needed to produce the local attestation.
    pub target_info: Vec<u8>,
}

/// Remote attestation (verifier is off-machine, full DCAP/SNP quote).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteAttestation {
    /// The attestation quote from the remote enclave.
    pub report: AttestationReport,
    /// Collateral data (certificate chain, CRL, etc.) for quote verification.
    pub collateral: Vec<u8>,
    /// Random nonce binding this attestation to a specific challenge.
    pub nonce: [u8; 32],
}

impl RemoteAttestation {
    /// Returns `true` if this attestation includes a non-empty nonce.
    pub fn is_fresh(&self) -> bool { self.nonce != [0u8; 32] }
}

/// Verifies attestation reports from all supported platforms.
pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify an attestation report from any supported platform.
    ///
    /// Dispatches to the appropriate platform-specific verifier.
    /// Returns `true` if the report is structurally valid and passes
    /// basic integrity checks. Full cryptographic verification
    /// requires the platform SDK (Intel DCAP, AMD SEV-SNP tools, etc.).
    pub fn verify(report: &AttestationReport) -> TeeResult<bool> {
        match report.platform {
            TeePlatform::IntelSgx     => Self::verify_sgx(report),
            TeePlatform::AmdSev       => Self::verify_sev(report),
            TeePlatform::ArmTrustZone => Self::verify_trustzone(report),
            TeePlatform::RiscvKeystone => Self::verify_keystone(report),
            TeePlatform::AwsNitro     => Self::verify_nitro(report),
        }
    }

    /// Verify and check consistency of a cross-platform attestation.
    ///
    /// All platforms in the bundle must individually verify, and their
    /// code measurements must be consistent with each other.
    pub fn verify_cross_platform(cross: &CrossPlatformAttestation) -> TeeResult<bool> {
        let primary_ok = Self::verify(&cross.primary)?;
        if !primary_ok { return Ok(false); }
        for secondary in &cross.secondary {
            if !Self::verify(secondary)? { return Ok(false); }
        }
        Ok(cross.is_consistent())
    }

    /// SGX-specific verification (structural check; full DCAP in production).
    fn verify_sgx(report: &AttestationReport) -> TeeResult<bool> {
        Ok(!report.raw_report.is_empty())
    }

    /// SEV-SNP-specific verification.
    fn verify_sev(report: &AttestationReport) -> TeeResult<bool> {
        Ok(!report.raw_report.is_empty())
    }

    /// TrustZone-specific verification.
    fn verify_trustzone(report: &AttestationReport) -> TeeResult<bool> {
        Ok(!report.raw_report.is_empty())
    }

    /// Keystone-specific verification.
    fn verify_keystone(report: &AttestationReport) -> TeeResult<bool> {
        Ok(!report.raw_report.is_empty())
    }

    /// AWS Nitro Enclave-specific verification.
    fn verify_nitro(report: &AttestationReport) -> TeeResult<bool> {
        Ok(!report.raw_report.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    #[test]
    fn attestation_verifier_rejects_empty_report() {
        let report = AttestationReport {
            platform: TeePlatform::IntelSgx,
            raw_report: vec![],
            code_measurement: Hash256::ZERO,
            signer_measurement: Hash256::ZERO,
            nonce: [0u8; 32],
            is_production: false,
            svn: 0,
            user_data: vec![],
        };
        assert!(!AttestationVerifier::verify(&report).unwrap());
    }

    #[test]
    fn attestation_verifier_accepts_nonempty_report() {
        let report = AttestationReport {
            platform: TeePlatform::AwsNitro,
            raw_report: vec![1, 2, 3],
            code_measurement: Hash256::ZERO,
            signer_measurement: Hash256::ZERO,
            nonce: [0u8; 32],
            is_production: false,
            svn: 1,
            user_data: vec![],
        };
        assert!(AttestationVerifier::verify(&report).unwrap());
    }

    #[test]
    fn remote_attestation_freshness_check() {
        let fresh = RemoteAttestation {
            report: AttestationReport {
                platform: TeePlatform::AmdSev,
                raw_report: vec![1],
                code_measurement: Hash256::ZERO,
                signer_measurement: Hash256::ZERO,
                nonce: [1u8; 32],
                is_production: false,
                svn: 0,
                user_data: vec![],
            },
            collateral: vec![],
            nonce: [1u8; 32],
        };
        assert!(fresh.is_fresh());
    }
}
