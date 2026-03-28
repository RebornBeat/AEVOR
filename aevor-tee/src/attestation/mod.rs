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
    ///
    /// # Errors
    /// Returns an error if the platform-specific verification step fails
    /// (e.g. malformed quote structure).
    pub fn verify(report: &AttestationReport) -> TeeResult<bool> {
        let ok = match report.platform {
            TeePlatform::IntelSgx     => Self::verify_sgx(report),
            TeePlatform::AmdSev       => Self::verify_sev(report),
            TeePlatform::ArmTrustZone => Self::verify_trustzone(report),
            TeePlatform::RiscvKeystone => Self::verify_keystone(report),
            TeePlatform::AwsNitro     => Self::verify_nitro(report),
        };
        Ok(ok)
    }

    /// Verify and check consistency of a cross-platform attestation.
    ///
    /// All platforms in the bundle must individually verify, and their
    /// code measurements must be consistent with each other.
    ///
    /// # Errors
    /// Returns an error if any individual platform verification step fails.
    pub fn verify_cross_platform(cross: &CrossPlatformAttestation) -> TeeResult<bool> {
        let primary_ok = Self::verify(&cross.primary)?;
        if !primary_ok { return Ok(false); }
        for secondary in &cross.secondary {
            if !Self::verify(secondary)? { return Ok(false); }
        }
        Ok(cross.is_consistent())
    }

    /// SGX-specific verification (structural check; full DCAP in production).
    fn verify_sgx(report: &AttestationReport) -> bool {
        !report.raw_report.is_empty()
    }

    /// SEV-SNP-specific verification.
    fn verify_sev(report: &AttestationReport) -> bool {
        !report.raw_report.is_empty()
    }

    /// TrustZone-specific verification.
    fn verify_trustzone(report: &AttestationReport) -> bool {
        !report.raw_report.is_empty()
    }

    /// Keystone-specific verification.
    fn verify_keystone(report: &AttestationReport) -> bool {
        !report.raw_report.is_empty()
    }

    /// AWS Nitro Enclave-specific verification.
    fn verify_nitro(report: &AttestationReport) -> bool {
        !report.raw_report.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::tee::TeePlatform;
    use aevor_core::crypto::CrossPlatformAttestation;

    fn report(platform: TeePlatform, nonempty: bool) -> AttestationReport {
        AttestationReport {
            platform,
            raw_report: if nonempty { vec![0xAB, 0xCD] } else { vec![] },
            code_measurement: Hash256([0x42; 32]),
            signer_measurement: Hash256::ZERO,
            nonce: [1u8; 32],
            is_production: true,
            svn: 1,
            user_data: vec![],
        }
    }

    // ── All 5 platforms accepted with non-empty report ─────────────────────
    // The whitepaper mandates cross-platform behavioral consistency:
    // IntelSgx, AmdSev, ArmTrustZone, RiscvKeystone, AwsNitro.

    #[test]
    fn all_five_platforms_verify_with_nonempty_report() {
        for platform in [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ] {
            let r = report(platform, true);
            assert!(
                AttestationVerifier::verify(&r).unwrap(),
                "Platform {:?} should verify with non-empty report", platform
            );
        }
    }

    #[test]
    fn all_five_platforms_reject_empty_report() {
        for platform in [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ] {
            let r = report(platform, false);
            assert!(
                !AttestationVerifier::verify(&r).unwrap(),
                "Platform {:?} should reject empty report", platform
            );
        }
    }

    // ── Cross-platform verification ────────────────────────────────────────

    #[test]
    fn cross_platform_verification_consistent_measurements() {
        let primary = report(TeePlatform::IntelSgx, true);
        // Secondary uses a different platform but same code_measurement
        let mut secondary = report(TeePlatform::AmdSev, true);
        secondary.code_measurement = primary.code_measurement;
        let cross = CrossPlatformAttestation {
            primary,
            secondary: vec![secondary],
            consistency_proof: Hash256::ZERO,
            agreed_computation_hash: Hash256([0x42; 32]),
        };
        assert!(AttestationVerifier::verify_cross_platform(&cross).unwrap());
    }

    #[test]
    fn cross_platform_verification_rejects_inconsistent_measurements() {
        let primary = report(TeePlatform::IntelSgx, true);
        let mut secondary = report(TeePlatform::ArmTrustZone, true);
        // Different code measurement — platforms disagree about what ran
        secondary.code_measurement = Hash256([0xFF; 32]);
        let cross = CrossPlatformAttestation {
            primary,
            secondary: vec![secondary],
            consistency_proof: Hash256::ZERO,
            agreed_computation_hash: Hash256([0x42; 32]),
        };
        assert!(!AttestationVerifier::verify_cross_platform(&cross).unwrap());
    }

    #[test]
    fn cross_platform_verification_rejects_empty_secondary_report() {
        let primary = report(TeePlatform::IntelSgx, true);
        let empty_secondary = report(TeePlatform::AwsNitro, false); // empty report
        let cross = CrossPlatformAttestation {
            primary,
            secondary: vec![empty_secondary],
            consistency_proof: Hash256::ZERO,
            agreed_computation_hash: Hash256::ZERO,
        };
        assert!(!AttestationVerifier::verify_cross_platform(&cross).unwrap());
    }

    // ── Simulation mode (non-production) ──────────────────────────────────
    // Per whitepaper: non-production TEEs work for devnet/testnet.
    // The TEE-layer AttestationVerifier is platform-structural only —
    // production vs simulation policy is enforced at consensus layer.

    #[test]
    fn simulation_mode_report_is_structurally_valid() {
        let mut r = report(TeePlatform::RiscvKeystone, true);
        r.is_production = false;
        r.svn = 0;
        // TEE-layer verifier checks structure not policy — must not reject
        assert!(AttestationVerifier::verify(&r).unwrap());
    }

    // ── Remote attestation freshness ──────────────────────────────────────

    #[test]
    fn remote_attestation_fresh_with_nonzero_nonce() {
        let ra = RemoteAttestation {
            report: report(TeePlatform::AmdSev, true),
            collateral: vec![0x01],
            nonce: [0xAB; 32],
        };
        assert!(ra.is_fresh());
    }

    #[test]
    fn remote_attestation_stale_with_zero_nonce() {
        let ra = RemoteAttestation {
            report: report(TeePlatform::AmdSev, true),
            collateral: vec![],
            nonce: [0u8; 32],
        };
        assert!(!ra.is_fresh());
    }

    // ── AttestationMode variants ──────────────────────────────────────────

    #[test]
    fn attestation_mode_variants_are_distinct() {
        assert_ne!(AttestationMode::Local, AttestationMode::Remote);
        assert_ne!(AttestationMode::Simulation, AttestationMode::CrossPlatform);
        assert_ne!(AttestationMode::Local, AttestationMode::Simulation);
    }
}
