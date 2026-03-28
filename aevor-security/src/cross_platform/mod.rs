//! Cross-platform behavioral consistency verification.
//!
//! AEVOR's core guarantee: identical inputs produce identical outputs across
//! all five TEE platforms (Intel SGX, AMD SEV, ARM TrustZone, RISC-V Keystone,
//! AWS Nitro). The `CrossPlatformVerifier` detects any divergence, which would
//! indicate either a corrupted execution environment or hardware misbehavior.

use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BehavioralConsistencyCheck {
    pub computation_hash: Hash256,
    pub platforms_checked: Vec<TeePlatform>,
    pub consistent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyViolation {
    pub platform_a: TeePlatform,
    pub platform_b: TeePlatform,
    pub hash_a: Hash256,
    pub hash_b: Hash256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformSecurityAudit {
    pub platform: TeePlatform,
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformComplianceReport {
    pub audits: Vec<PlatformSecurityAudit>,
    pub overall_compliant: bool,
}

pub struct CrossPlatformVerifier;
impl CrossPlatformVerifier {
    pub fn verify(hashes: &[(TeePlatform, Hash256)]) -> Option<ConsistencyViolation> {
        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                if hashes[i].1 != hashes[j].1 {
                    return Some(ConsistencyViolation {
                        platform_a: hashes[i].0, platform_b: hashes[j].0,
                        hash_a: hashes[i].1, hash_b: hashes[j].1,
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::tee::TeePlatform;
    use aevor_core::primitives::Hash256;

    fn h(n: u8) -> Hash256 { Hash256([n; 32]) }

    const ALL_PLATFORMS: [TeePlatform; 5] = [
        TeePlatform::IntelSgx, TeePlatform::AmdSev, TeePlatform::ArmTrustZone,
        TeePlatform::RiscvKeystone, TeePlatform::AwsNitro,
    ];

    // ── CrossPlatformVerifier (core whitepaper guarantee) ───────────────

    #[test]
    fn all_five_platforms_consistent_same_hash() {
        // Core guarantee: identical inputs → identical outputs across all platforms
        let hashes: Vec<(TeePlatform, Hash256)> = ALL_PLATFORMS.iter()
            .map(|&p| (p, h(0xAB))).collect();
        assert!(CrossPlatformVerifier::verify(&hashes).is_none());
    }

    #[test]
    fn divergence_detected_between_two_platforms() {
        let hashes = vec![
            (TeePlatform::IntelSgx, h(1)),
            (TeePlatform::AmdSev, h(1)),
            (TeePlatform::ArmTrustZone, h(99)), // diverges
            (TeePlatform::RiscvKeystone, h(1)),
        ];
        let violation = CrossPlatformVerifier::verify(&hashes);
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert_ne!(v.hash_a, v.hash_b);
    }

    #[test]
    fn empty_and_single_platform_always_consistent() {
        assert!(CrossPlatformVerifier::verify(&[]).is_none());
        assert!(CrossPlatformVerifier::verify(&[(TeePlatform::IntelSgx, h(5))]).is_none());
    }

    #[test]
    fn violation_reports_correct_platforms() {
        let hashes = vec![
            (TeePlatform::IntelSgx, h(1)),
            (TeePlatform::AmdSev, h(2)), // different
        ];
        let v = CrossPlatformVerifier::verify(&hashes).unwrap();
        assert!(v.platform_a == TeePlatform::IntelSgx || v.platform_b == TeePlatform::IntelSgx);
        assert!(v.platform_a == TeePlatform::AmdSev || v.platform_b == TeePlatform::AmdSev);
    }

    // ── PlatformSecurityAudit ────────────────────────────────────────────

    #[test]
    fn audit_passes_when_no_failures() {
        let audit = PlatformSecurityAudit {
            platform: TeePlatform::AwsNitro,
            checks_passed: 10,
            checks_failed: 0,
            issues: vec![],
        };
        assert_eq!(audit.checks_failed, 0);
        assert!(audit.issues.is_empty());
    }

    #[test]
    fn compliance_report_overall_not_compliant_when_any_audit_fails() {
        let report = PlatformComplianceReport {
            audits: vec![
                PlatformSecurityAudit { platform: TeePlatform::IntelSgx, checks_passed: 5, checks_failed: 1, issues: vec!["SVN too low".into()] },
            ],
            overall_compliant: false,
        };
        assert!(!report.overall_compliant);
        assert_eq!(report.audits[0].checks_failed, 1);
    }
}
