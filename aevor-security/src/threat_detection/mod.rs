//! Privacy-preserving infrastructure threat detection.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatSignature { pub id: String, pub pattern: Vec<u8>, pub severity: u8 }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnomalyScore(pub u32);

impl AnomalyScore {
    pub const NORMAL: Self = Self(0);
    pub const WARNING: Self = Self(50);
    pub const CRITICAL: Self = Self(90);
    pub fn is_anomalous(&self) -> bool { self.0 >= 50 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: Hash256,
    pub signature: ThreatSignature,
    pub score: AnomalyScore,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum InfrastructureThreat {
    DdosAttack, SybilAttack, EclipseAttack,
    ByzantineValidator, TeeCompromise, FrontierCorruption,
}

pub struct PrivacyPreservingDetector { threshold: AnomalyScore }
impl PrivacyPreservingDetector {
    pub fn new(threshold: AnomalyScore) -> Self { Self { threshold } }
    pub fn check(&self, score: AnomalyScore) -> bool { score >= self.threshold }
}

pub struct ThreatDetector { signatures: Vec<ThreatSignature> }
impl ThreatDetector {
    pub fn new() -> Self { Self { signatures: Vec::new() } }
    pub fn add_signature(&mut self, sig: ThreatSignature) { self.signatures.push(sig); }
    pub fn signature_count(&self) -> usize { self.signatures.len() }
}
impl Default for ThreatDetector { fn default() -> Self { Self::new() } }
