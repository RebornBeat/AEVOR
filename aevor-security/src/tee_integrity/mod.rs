//! TEE integrity monitoring and compromise detection.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnclaveIntegrityProof { pub platform: TeePlatform, pub measurement: Hash256, pub timestamp_round: u64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompromiseIndicator { pub platform: TeePlatform, pub indicator: String, pub confidence: u8 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrityViolationResponse { pub action: String, pub validator_isolated: bool }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeHealthStatus { pub platform: TeePlatform, pub is_healthy: bool, pub last_checked_round: u64 }

pub struct TeeIntegrityMonitor { proofs: Vec<EnclaveIntegrityProof> }
impl TeeIntegrityMonitor {
    pub fn new() -> Self { Self { proofs: Vec::new() } }
    pub fn record(&mut self, proof: EnclaveIntegrityProof) { self.proofs.push(proof); }
    pub fn is_consistent(&self, expected: &Hash256) -> bool {
        self.proofs.iter().all(|p| &p.measurement == expected)
    }
}
impl Default for TeeIntegrityMonitor { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::tee::TeePlatform;

    fn proof(platform: TeePlatform, m: u8) -> EnclaveIntegrityProof {
        EnclaveIntegrityProof { platform, measurement: Hash256([m; 32]), timestamp_round: 100 }
    }

    #[test]
    fn tee_integrity_monitor_consistent_measurements() {
        let expected = Hash256([0xAB; 32]);
        let mut mon = TeeIntegrityMonitor::new();
        mon.record(proof(TeePlatform::IntelSgx, 0xAB));
        mon.record(proof(TeePlatform::AmdSev, 0xAB));
        assert!(mon.is_consistent(&expected));
    }

    #[test]
    fn tee_integrity_monitor_detects_inconsistency() {
        let expected = Hash256([0xAB; 32]);
        let mut mon = TeeIntegrityMonitor::default();
        mon.record(proof(TeePlatform::IntelSgx, 0xAB));
        mon.record(proof(TeePlatform::ArmTrustZone, 0xFF)); // differs
        assert!(!mon.is_consistent(&expected));
    }

    #[test]
    fn tee_health_status_fields() {
        let s = TeeHealthStatus { platform: TeePlatform::AwsNitro, is_healthy: true, last_checked_round: 500 };
        assert!(s.is_healthy);
        assert_eq!(s.last_checked_round, 500);
    }
}
