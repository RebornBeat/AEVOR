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
