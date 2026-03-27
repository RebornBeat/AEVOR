//! # AEVOR Metrics: Privacy-Preserving Network Intelligence
//!
//! `aevor-metrics` provides system monitoring and network intelligence capabilities
//! that enable operational excellence while strictly respecting privacy boundaries.
//!
//! ## Privacy-First Monitoring
//!
//! **What this crate monitors**: Infrastructure health, throughput, latency, validator
//! performance, TEE service utilization, network topology quality, consensus round timing,
//! and anomalous patterns that could indicate infrastructure attacks.
//!
//! **What this crate never monitors**: User transaction patterns, contract invocation
//! frequencies per address, wallet behavior, private object access patterns, or any
//! user-identifying information. Monitoring is for infrastructure health, not surveillance.
//!
//! ## Anomaly Detection vs Surveillance
//!
//! The anomaly detection subsystem identifies:
//! - Infrastructure attacks (`DDoS`, eclipse attacks, Sybil attacks)
//! - Validator misbehavior (liveness failures, performance degradation)
//! - TEE integrity issues (attestation failures, anomalous execution times)
//! - Network partition indicators
//!
//! It does **not** create user behavioral profiles, flag "suspicious" transaction patterns,
//! or implement financial surveillance that would compromise user financial privacy.
//!
//! ## No External Service Integration
//!
//! Metrics are collected, processed, and stored entirely within AEVOR infrastructure.
//! No external monitoring platforms (Datadog, Prometheus remote write to external endpoints,
//! etc.) are integrated directly. External monitoring tools can pull metrics via the
//! well-defined metrics API in `aevor-api`.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Metrics collector: efficient time-series collection with ring buffers.
pub mod collector;

/// Metrics aggregation: percentile computation, histograms, counters, gauges.
pub mod aggregation;

/// Privacy filter: ensures collected metrics never contain user-identifying information.
pub mod privacy;

/// Reporting: structured metric reports for operational dashboards.
pub mod reporting;

/// Network metrics: topology quality, propagation latency, bandwidth utilization.
pub mod network;

/// Performance metrics: TPS, latency distribution, parallelism factor, gas throughput.
pub mod performance;

/// Validator metrics: liveness, performance scores, TEE health, reward rates.
pub mod validators;

/// TEE metrics: attestation latency, execution overhead, platform utilization.
pub mod tee;

/// Consensus metrics: round timing, security level distribution, finality latency.
pub mod consensus;

/// Anomaly detection: privacy-preserving infrastructure threat detection.
pub mod anomaly;

/// Differential privacy: formal privacy guarantees for aggregate statistics.
pub mod differential_privacy;

// ============================================================
// PRELUDE
// ============================================================

/// Metrics prelude — all essential metrics types.
///
/// ```rust
/// use aevor_metrics::prelude::*;
/// ```
pub mod prelude {
    pub use crate::collector::{
        MetricsCollector, MetricPoint, MetricSeries, CollectorConfig,
        SamplingRate, RetentionPolicy,
    };
    pub use crate::aggregation::{
        MetricAggregator, Histogram, Percentile, Counter, Gauge,
        RateMeter, MovingAverage,
    };
    pub use crate::performance::{
        ThroughputMetric, LatencyMetric, ParallelismMetric, GasMetric,
        PerformanceSummary, TpsReading,
    };
    pub use crate::validators::{
        ValidatorMetrics, LivenessScore, PerformanceScore, TeeHealthScore,
        RewardRateMetric, ValidatorSummary,
    };
    pub use crate::tee::{
        TeeMetrics, AttestationLatency, ExecutionOverhead, PlatformUtilization,
        TeeSummary,
    };
    pub use crate::consensus::{
        ConsensusMetrics, RoundDuration, SecurityLevelDistribution,
        FinalityLatency, ConsensusSummary,
    };
    pub use crate::anomaly::{
        AnomalyDetector, AnomalyEvent, ThreatIndicator, AnomalyThreshold,
        InfrastructureThreatAlert,
    };
    pub use crate::reporting::{
        MetricsReport, ReportConfig, OperationalDashboard, MetricSnapshot,
        ReportInterval,
    };
    pub use crate::{MetricsError, MetricsResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from metrics operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum MetricsError {
    /// Metric collection failed.
    #[error("collection failed: {reason}")]
    CollectionFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Privacy filter rejected a metric as potentially user-identifying.
    #[error("metric rejected by privacy filter: {metric_name}")]
    PrivacyFilterRejection {
        /// Name of the rejected metric.
        metric_name: String,
    },

    /// Metrics storage is full.
    #[error("metrics storage full: {used_bytes} / {capacity_bytes} bytes used")]
    StorageFull {
        /// Used storage in bytes.
        used_bytes: u64,
        /// Storage capacity in bytes.
        capacity_bytes: u64,
    },

    /// Metric aggregation computation failed.
    #[error("aggregation error: {0}")]
    AggregationError(String),
}

/// Convenience alias for metrics results.
pub type MetricsResult<T> = Result<T, MetricsError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default metrics collection interval in milliseconds.
pub const DEFAULT_COLLECTION_INTERVAL_MS: u64 = 1_000;

/// Default metrics retention period in seconds (7 days).
pub const DEFAULT_RETENTION_SECONDS: u64 = 604_800;

/// Percentile targets for latency histograms.
pub const LATENCY_PERCENTILES: &[f64] = &[0.50, 0.90, 0.95, 0.99, 0.999];

/// Maximum in-memory metrics series before oldest are evicted.
pub const MAX_IN_MEMORY_SERIES: usize = 10_000;

/// Anomaly detection sensitivity (standard deviations above mean to trigger alert).
pub const ANOMALY_DETECTION_SIGMA: f64 = 3.0;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_percentiles_are_ascending() {
        let p = LATENCY_PERCENTILES;
        for i in 1..p.len() {
            assert!(p[i] > p[i - 1]);
        }
        assert!(*p.last().unwrap() < 1.0);
    }

    #[test]
    fn anomaly_sigma_is_reasonable() {
        // 3σ gives 99.7% specificity — practical without too many false positives
        assert!(ANOMALY_DETECTION_SIGMA >= 2.0);
        assert!(ANOMALY_DETECTION_SIGMA <= 5.0);
    }

    use crate::collector::{CollectorConfig, MetricsCollector, MetricPoint};
    use crate::differential_privacy::{DpConfig, LaplaceMechanism};
    use aevor_core::consensus::ConsensusTimestamp;

    #[test]
    fn metrics_error_display() {
        let e = MetricsError::CollectionFailed { reason: "no data".into() };
        assert!(e.to_string().contains("no data"));
    }

    #[test]
    fn metrics_result_ok() {
        let r: MetricsResult<u64> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn collector_records_and_counts_series() {
        let mut collector = MetricsCollector::new(CollectorConfig::default());
        let point = MetricPoint {
            name: "tps".into(),
            value: 200_000.0,
            timestamp: ConsensusTimestamp::GENESIS,
            labels: vec![],
        };
        collector.record(point);
        assert_eq!(collector.series_count(), 1);
    }

    #[test]
    fn collector_sampling_interval_from_config() {
        let cfg = CollectorConfig { sampling_interval_ms: 500, ..CollectorConfig::default() };
        let collector = MetricsCollector::new(cfg);
        assert_eq!(collector.sampling_interval_ms(), 500);
    }

    #[test]
    fn laplace_mechanism_scale_is_sensitivity_over_epsilon() {
        let dp = DpConfig { epsilon: 2.0, delta: 0.0, sensitivity: 1.0 };
        let mech = LaplaceMechanism::new(dp);
        assert!((mech.scale() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn laplace_mechanism_epsilon_consumed_matches_config() {
        let dp = DpConfig { epsilon: 0.5, delta: 0.0, sensitivity: 1.0 };
        let mech = LaplaceMechanism::new(dp);
        let result = mech.apply(42.0);
        assert_eq!(result.epsilon_consumed, 0.5);
    }

    #[test]
    fn dp_consensus_defaults_are_sane() {
        let cfg = DpConfig::consensus_defaults();
        assert!(cfg.epsilon > 0.0);
        assert!(cfg.sensitivity > 0.0);
    }
}
