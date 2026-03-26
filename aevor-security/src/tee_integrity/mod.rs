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
