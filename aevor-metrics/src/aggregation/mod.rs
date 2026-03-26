//! Metric aggregation: histograms, percentiles, counters, gauges.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Histogram { pub buckets: Vec<(f64, u64)>, pub count: u64, pub sum: f64 }
impl Histogram {
    pub fn mean(&self) -> f64 { if self.count == 0 { 0.0 } else { self.sum / self.count as f64 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Percentile { pub p50: f64, pub p95: f64, pub p99: f64, pub p999: f64 }

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Counter(pub u64);
impl Counter {
    pub fn increment(&mut self) { self.0 += 1; }
    pub fn add(&mut self, n: u64) { self.0 += n; }
    pub fn value(&self) -> u64 { self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Gauge(pub f64);
impl Gauge {
    pub fn set(&mut self, v: f64) { self.0 = v; }
    pub fn value(&self) -> f64 { self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateMeter { pub count: u64, pub rate_per_sec: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MovingAverage { pub window: Vec<f64>, pub average: f64 }
impl MovingAverage {
    pub fn new(capacity: usize) -> Self { Self { window: Vec::with_capacity(capacity), average: 0.0 } }
    pub fn add(&mut self, value: f64) {
        self.window.push(value);
        self.average = self.window.iter().sum::<f64>() / self.window.len() as f64;
    }
}

pub struct MetricAggregator;
impl MetricAggregator {
    pub fn compute_percentiles(values: &mut [f64]) -> Percentile {
        if values.is_empty() { return Percentile { p50: 0.0, p95: 0.0, p99: 0.0, p999: 0.0 }; }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |pct: f64| { let idx = ((pct / 100.0) * values.len() as f64) as usize; values[idx.min(values.len()-1)] };
        Percentile { p50: p(50.0), p95: p(95.0), p99: p(99.0), p999: p(99.9) }
    }
}
