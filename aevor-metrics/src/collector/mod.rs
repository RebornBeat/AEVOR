//! Metrics collection infrastructure.

use serde::{Deserialize, Serialize};
use aevor_core::consensus::ConsensusTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricPoint { pub name: String, pub value: f64, pub timestamp: ConsensusTimestamp, pub labels: Vec<(String, String)> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricSeries { pub name: String, pub points: Vec<MetricPoint> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectorConfig { pub sampling_interval_ms: u64, pub retention_hours: u64, pub max_series: usize }
impl Default for CollectorConfig {
    fn default() -> Self { Self { sampling_interval_ms: 1_000, retention_hours: 24, max_series: 10_000 } }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SamplingRate(pub u64); // samples per second
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionPolicy { pub duration_hours: u64, pub downsample_after_hours: u64 }

pub struct MetricsCollector { series: Vec<MetricSeries>, config: CollectorConfig }
impl MetricsCollector {
    pub fn new(config: CollectorConfig) -> Self { Self { series: Vec::new(), config } }
    pub fn config(&self) -> &CollectorConfig { &self.config }
    pub fn sampling_interval_ms(&self) -> u64 { self.config.sampling_interval_ms }
    pub fn record(&mut self, point: MetricPoint) {
        if let Some(s) = self.series.iter_mut().find(|s| s.name == point.name) {
            s.points.push(point);
        } else {
            self.series.push(MetricSeries { name: point.name.clone(), points: vec![point] });
        }
    }
    pub fn series_count(&self) -> usize { self.series.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::consensus::ConsensusTimestamp;

    fn point(name: &str, value: f64) -> MetricPoint {
        MetricPoint { name: name.into(), value, timestamp: ConsensusTimestamp::new(1,0,1), labels: vec![] }
    }

    #[test]
    fn collector_config_default_sensible() {
        let cfg = CollectorConfig::default();
        assert!(cfg.sampling_interval_ms > 0);
        assert!(cfg.max_series > 0);
        assert_eq!(cfg.retention_hours, 24);
    }

    #[test]
    fn metrics_collector_record_new_series() {
        let mut col = MetricsCollector::new(CollectorConfig::default());
        col.record(point("cpu_usage", 0.72));
        assert_eq!(col.series_count(), 1);
    }

    #[test]
    fn metrics_collector_appends_to_existing_series() {
        let mut col = MetricsCollector::new(CollectorConfig::default());
        col.record(point("cpu_usage", 0.70));
        col.record(point("cpu_usage", 0.75));
        assert_eq!(col.series_count(), 1); // same series, not duplicated
    }

    #[test]
    fn metrics_collector_multiple_series() {
        let mut col = MetricsCollector::new(CollectorConfig::default());
        col.record(point("cpu_usage", 0.5));
        col.record(point("mem_usage", 0.6));
        assert_eq!(col.series_count(), 2);
    }
}
