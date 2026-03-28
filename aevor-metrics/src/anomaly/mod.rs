//! Anomaly detection for infrastructure metrics.
use serde::{Deserialize, Serialize};
use aevor_core::consensus::ConsensusTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyEvent { pub metric: String, pub value: f64, pub threshold: f64, pub timestamp: ConsensusTimestamp }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatIndicator { pub indicator: String, pub confidence: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyThreshold { pub metric: String, pub warn: f64, pub critical: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InfrastructureThreatAlert { pub threat: String, pub severity: u8, pub indicators: Vec<ThreatIndicator> }

pub struct AnomalyDetector { thresholds: Vec<AnomalyThreshold> }
impl AnomalyDetector {
    pub fn new() -> Self { Self { thresholds: Vec::new() } }
    pub fn add_threshold(&mut self, t: AnomalyThreshold) { self.thresholds.push(t); }
    pub fn check(&self, metric: &str, value: f64) -> Option<AnomalyEvent> {
        self.thresholds.iter().find(|t| t.metric == metric && value > t.warn).map(|t| AnomalyEvent {
            metric: metric.to_string(), value, threshold: t.warn, timestamp: ConsensusTimestamp::GENESIS,
        })
    }
}
impl Default for AnomalyDetector { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    fn threshold(metric: &str, warn: f64, crit: f64) -> AnomalyThreshold {
        AnomalyThreshold { metric: metric.into(), warn, critical: crit }
    }

    #[test]
    fn anomaly_detector_triggers_above_warn() {
        let mut det = AnomalyDetector::new();
        det.add_threshold(threshold("cpu", 0.8, 0.95));
        let ev = det.check("cpu", 0.85).unwrap();
        assert_eq!(ev.metric, "cpu");
        assert!(ev.value > ev.threshold);
    }

    #[test]
    fn anomaly_detector_no_trigger_below_warn() {
        let mut det = AnomalyDetector::new();
        det.add_threshold(threshold("cpu", 0.8, 0.95));
        assert!(det.check("cpu", 0.70).is_none());
    }

    #[test]
    fn threat_indicator_stores_confidence() {
        let t = ThreatIndicator { indicator: "spike".into(), confidence: 0.92 };
        assert!(t.confidence > 0.9);
    }
}
