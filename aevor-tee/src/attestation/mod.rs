//! Cross-platform attestation: normalization, verification, composition.

use serde::{Deserialize, Serialize};
pub use aevor_core::tee::AttestationReport;
pub use aevor_core::crypto::CrossPlatformAttestation;
use aevor_core::primitives::Hash256;
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

// The simulation attestation trust root lives in `aevor_crypto::attestation`
// so the TEE and consensus layers share one key and one sign/verify
// implementation. This module only builds the report-specific canonical body.

fn platform_tag(p: TeePlatform) -> u8 {
    match p {
        TeePlatform::IntelSgx => 1,
        TeePlatform::AmdSev => 2,
        TeePlatform::ArmTrustZone => 3,
        TeePlatform::RiscvKeystone => 4,
        TeePlatform::AwsNitro => 5,
    }
}

/// Canonical, signature-free serialization of the trust-relevant report fields.
/// Both [`seal`] and [`AttestationVerifier::verify`] derive the signed bytes
/// from this one function, so signing and verification cannot drift.
fn canonical_body(r: &AttestationReport) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 32 + 32 + 32 + 1 + 4 + r.user_data.len());
    m.push(platform_tag(r.platform));
    m.extend_from_slice(&r.code_measurement.0);
    m.extend_from_slice(&r.signer_measurement.0);
    m.extend_from_slice(&r.nonce);
    m.push(u8::from(r.is_production));
    m.extend_from_slice(&r.svn.to_le_bytes());
    m.extend_from_slice(&r.user_data);
    m
}

/// Seal a freshly-generated simulation report by signing its canonical body and
/// storing the signature as the raw quote.
///
/// This gives simulation reports real cryptographic integrity, so
/// [`AttestationVerifier::verify`] exercises the same signature-checking path a
/// production verifier would (only the trust root differs).
#[must_use]
pub fn seal(mut report: AttestationReport) -> AttestationReport {
    report.raw_report = aevor_crypto::attestation::sim_sign(&canonical_body(&report)).to_vec();
    report
}

/// Verifies attestation reports from all supported platforms.
pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify an attestation report from any supported platform.
    ///
    /// The report's quote (`raw_report`) must be a valid signature over its
    /// canonical body under the trusted attestation key, and it must commit to a
    /// non-degenerate code measurement. Platform dispatch is retained so
    /// platform-specific measurement policy can be layered on, but the
    /// cryptographic core is shared via [`verify_sealed`](Self::verify_sealed)
    /// so it cannot drift between platforms.
    ///
    /// In a production build the trust root is a real vendor certificate chain;
    /// here it is the simulation attestation key (see [`SIM_ATTESTATION_SEED`]).
    ///
    /// # Errors
    /// Returns an error only if a future platform-specific step fails; the
    /// simulation path is infallible and reports validity via the `bool`.
    pub fn verify(report: &AttestationReport) -> TeeResult<bool> {
        let platform_supported = matches!(
            report.platform,
            TeePlatform::IntelSgx
                | TeePlatform::AmdSev
                | TeePlatform::ArmTrustZone
                | TeePlatform::RiscvKeystone
                | TeePlatform::AwsNitro
        );
        Ok(platform_supported && Self::verify_sealed(report))
    }

    /// Verify and check consistency of a cross-platform attestation.
    ///
    /// All platforms in the bundle must individually verify, and their
    /// code measurements must be consistent with each other.
    ///
    /// # Errors
    /// Returns an error if any individual platform verification step fails.
    pub fn verify_cross_platform(cross: &CrossPlatformAttestation) -> TeeResult<bool> {
        if !Self::verify(&cross.primary)? {
            return Ok(false);
        }
        for secondary in &cross.secondary {
            if !Self::verify(secondary)? {
                return Ok(false);
            }
        }
        Ok(cross.is_consistent())
    }

    /// The shared, real verification core: a valid signature (the quote) over
    /// the canonical body under the trusted attestation key, plus a
    /// non-degenerate code measurement.
    #[must_use]
    pub fn verify_sealed(report: &AttestationReport) -> bool {
        if report.code_measurement == Hash256::ZERO {
            return false; // a report that measures nothing attests nothing
        }
        let sig: [u8; 64] = match report.raw_report.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return false, // missing or malformed quote
        };
        aevor_crypto::attestation::sim_verify(&canonical_body(report), &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::tee::TeePlatform;
    use aevor_core::crypto::CrossPlatformAttestation;

    /// A validly-sealed report with a chosen code measurement.
    fn sealed_report(platform: TeePlatform, measurement: [u8; 32]) -> AttestationReport {
        seal(AttestationReport {
            platform,
            raw_report: Vec::new(),
            code_measurement: Hash256(measurement),
            signer_measurement: Hash256::ZERO,
            nonce: [1u8; 32],
            is_production: true,
            svn: 1,
            user_data: vec![],
        })
    }

    fn report(platform: TeePlatform, nonempty: bool) -> AttestationReport {
        if nonempty {
            // A validly-sealed (verifiable) report.
            sealed_report(platform, [0x42; 32])
        } else {
            // An unsealed report (empty quote) — must be rejected.
            AttestationReport {
                platform,
                raw_report: vec![],
                code_measurement: Hash256([0x42; 32]),
                signer_measurement: Hash256::ZERO,
                nonce: [1u8; 32],
                is_production: true,
                svn: 1,
                user_data: vec![],
            }
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
        // A validly-sealed secondary that measured DIFFERENT code — it verifies
        // individually, but disagrees with the primary about what ran.
        let secondary = sealed_report(TeePlatform::ArmTrustZone, [0xFF; 32]);
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
        // A simulation report (is_production = false) sealed correctly must still
        // verify at the TEE layer — the production-vs-simulation *policy* is
        // enforced at the consensus layer, not here.
        let r = seal(AttestationReport {
            platform: TeePlatform::RiscvKeystone,
            raw_report: Vec::new(),
            code_measurement: Hash256([0x42; 32]),
            signer_measurement: Hash256::ZERO,
            nonce: [1u8; 32],
            is_production: false,
            svn: 0,
            user_data: vec![],
        });
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

    // ── Real seal verification: tampering is rejected ─────────────────────

    #[test]
    fn tampering_with_measurement_after_sealing_is_rejected() {
        let mut r = sealed_report(TeePlatform::IntelSgx, [0x42; 32]);
        assert!(AttestationVerifier::verify(&r).unwrap(), "sealed report verifies");
        // Swap in a different code measurement — the signature no longer matches.
        r.code_measurement = Hash256([0x99; 32]);
        assert!(
            !AttestationVerifier::verify(&r).unwrap(),
            "measurement tampering must break the seal"
        );
    }

    #[test]
    fn tampering_with_nonce_after_sealing_is_rejected() {
        let mut r = sealed_report(TeePlatform::AwsNitro, [0x42; 32]);
        r.nonce = [0x7Eu8; 32]; // replay a different nonce
        assert!(
            !AttestationVerifier::verify(&r).unwrap(),
            "nonce tampering must break the seal (freshness is bound)"
        );
    }

    #[test]
    fn garbage_quote_is_rejected() {
        let mut r = sealed_report(TeePlatform::AmdSev, [0x42; 32]);
        r.raw_report = vec![0xABu8; 64]; // 64 bytes, but not a valid signature
        assert!(
            !AttestationVerifier::verify(&r).unwrap(),
            "a well-sized but invalid quote must be rejected"
        );
    }

    #[test]
    fn zero_measurement_is_rejected_even_if_sealed() {
        // Sealing a zero-measurement report produces a valid signature, but a
        // report that measures nothing attests nothing.
        let r = seal(AttestationReport {
            platform: TeePlatform::RiscvKeystone,
            raw_report: Vec::new(),
            code_measurement: Hash256::ZERO,
            signer_measurement: Hash256::ZERO,
            nonce: [1u8; 32],
            is_production: false,
            svn: 0,
            user_data: vec![],
        });
        assert!(!AttestationVerifier::verify(&r).unwrap());
    }
}
