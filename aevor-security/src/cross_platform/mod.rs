//! Cross-platform behavioral consistency verification.

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
