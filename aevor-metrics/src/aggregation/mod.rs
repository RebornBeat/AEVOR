//! Metric aggregation: histograms, percentiles, counters, gauges.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Histogram { pub buckets: Vec<(f64, u64)>, pub count: u64, pub sum: f64 }
impl Histogram {
    #[allow(clippy::cast_precision_loss)] // sample count: u64→f64 precision loss acceptable for means
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
    #[allow(clippy::cast_precision_loss)] // window length: usize→f64 precision loss acceptable for averages
    pub fn add(&mut self, value: f64) {
        self.window.push(value);
        self.average = self.window.iter().sum::<f64>() / self.window.len() as f64;
    }
}

pub struct MetricAggregator;
impl MetricAggregator {
    /// Compute p50/p95/p99/p99.9 percentiles from a mutable slice of values.
    ///
    /// # Panics
    /// Panics if `values` contains NaN (via `partial_cmp(...).unwrap()`).
    /// All metric values in AEVOR are finite by construction.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // percentile: pct ∈ [0,100] and len is small so truncation/sign-loss are safe
    pub fn compute_percentiles(values: &mut [f64]) -> Percentile {
        if values.is_empty() { return Percentile { p50: 0.0, p95: 0.0, p99: 0.0, p999: 0.0 }; }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |pct: f64| { let idx = ((pct / 100.0) * values.len() as f64) as usize; values[idx.min(values.len()-1)] };
        Percentile { p50: p(50.0), p95: p(95.0), p99: p(99.0), p999: p(99.9) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_mean_with_values() {
        let h = Histogram { buckets: vec![], count: 4, sum: 20.0 };
        assert!((h.mean() - 5.0).abs() < 1e-9);
    }

    #[test]
    fn histogram_mean_empty_is_zero() {
        let h = Histogram::default();
        assert_eq!(h.mean(), 0.0);
    }

    #[test]
    fn counter_increment_and_add() {
        let mut c = Counter::default();
        c.increment();
        c.increment();
        c.add(8);
        assert_eq!(c.value(), 10);
    }

    #[test]
    fn gauge_set_and_get() {
        let mut g = Gauge::default();
        g.set(3.14);
        assert!((g.value() - 3.14).abs() < 1e-9);
    }

    #[test]
    fn moving_average_tracks_correct_average() {
        let mut ma = MovingAverage::new(4);
        ma.add(10.0);
        ma.add(20.0);
        // average = (10 + 20) / 2 = 15
        assert!((ma.average - 15.0).abs() < 1e-9);
    }

    #[test]
    fn percentiles_empty_are_zero() {
        let pct = MetricAggregator::compute_percentiles(&mut []);
        assert_eq!(pct.p50, 0.0);
        assert_eq!(pct.p99, 0.0);
    }

    #[test]
    fn percentiles_single_value() {
        let pct = MetricAggregator::compute_percentiles(&mut [42.0]);
        assert!((pct.p50 - 42.0).abs() < 1e-9);
        assert!((pct.p99 - 42.0).abs() < 1e-9);
    }

    #[test]
    fn percentiles_ordered_values() {
        let mut values: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let pct = MetricAggregator::compute_percentiles(&mut values);
        // p50 should be around the median (50th value)
        assert!(pct.p50 >= 49.0 && pct.p50 <= 51.0);
        // p99 should be near the top
        assert!(pct.p99 >= 98.0);
    }
}
