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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn sig(id: &str, severity: u8) -> ThreatSignature {
        ThreatSignature { id: id.into(), pattern: vec![severity], severity }
    }

    #[test]
    fn anomaly_score_constants_ordered() {
        assert!(AnomalyScore::NORMAL < AnomalyScore::WARNING);
        assert!(AnomalyScore::WARNING < AnomalyScore::CRITICAL);
    }

    #[test]
    fn anomaly_score_is_anomalous_at_and_above_warning() {
        assert!(!AnomalyScore(49).is_anomalous());
        assert!(AnomalyScore::WARNING.is_anomalous());
        assert!(AnomalyScore::CRITICAL.is_anomalous());
        assert!(AnomalyScore(100).is_anomalous());
    }

    #[test]
    fn privacy_preserving_detector_threshold() {
        let det = PrivacyPreservingDetector::new(AnomalyScore::WARNING);
        assert!(!det.check(AnomalyScore(49)));
        assert!(det.check(AnomalyScore::WARNING));
        assert!(det.check(AnomalyScore::CRITICAL));
    }

    #[test]
    fn threat_detector_add_and_count() {
        let mut det = ThreatDetector::new();
        det.add_signature(sig("ddos-1", 80));
        det.add_signature(sig("sybil-1", 70));
        assert_eq!(det.signature_count(), 2);
    }

    #[test]
    fn infrastructure_threat_variants() {
        let threats = [
            InfrastructureThreat::DdosAttack,
            InfrastructureThreat::SybilAttack,
            InfrastructureThreat::EclipseAttack,
            InfrastructureThreat::ByzantineValidator,
            InfrastructureThreat::TeeCompromise,
            InfrastructureThreat::FrontierCorruption,
        ];
        assert_eq!(threats.len(), 6); // all threat classes covered
    }

    #[test]
    fn threat_alert_stores_all_fields() {
        let alert = ThreatAlert {
            id: Hash256::ZERO,
            signature: sig("eclipse-1", 90),
            score: AnomalyScore::CRITICAL,
            description: "potential eclipse attack detected".into(),
        };
        assert!(alert.score.is_anomalous());
        assert!(!alert.description.is_empty());
    }
}
