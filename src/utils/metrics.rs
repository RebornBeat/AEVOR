// Aevor Metrics Module
//
// This module provides functionality for collecting and reporting metrics
// about the Aevor blockchain performance and health.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use prometheus::{Counter as PromCounter, Gauge as PromGauge, 
                 Histogram as PromHistogram, HistogramOpts, 
                 Opts, Registry};
use lazy_static::lazy_static;

/// Type of metric
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricType {
    /// Counter (monotonically increasing)
    Counter,
    
    /// Gauge (can increase or decrease)
    Gauge,
    
    /// Histogram (distribution of values)
    Histogram,
}

/// A counter metric (monotonically increasing)
#[derive(Clone)]
pub struct Counter {
    /// Metric name
    name: String,
    
    /// Metric description
    description: String,
    
    /// Inner Prometheus counter
    counter: Arc<PromCounter>,
}

impl Counter {
    /// Creates a new counter with the given name and description
    pub fn new(name: String, description: String) -> Self {
        let opts = Opts::new(name.clone(), description.clone());
        let counter = PromCounter::with_opts(opts)
            .expect("Failed to create counter");
        
        Self {
            name,
            description,
            counter: Arc::new(counter),
        }
    }
    
    /// Increments the counter by the given amount
    pub fn inc(&self, amount: u64) {
        self.counter.inc_by(amount as f64);
    }
    
    /// Increments the counter by 1
    pub fn inc_one(&self) {
        self.counter.inc();
    }
    
    /// Gets the current value of the counter
    pub fn value(&self) -> u64 {
        self.counter.get() as u64
    }
    
    /// Gets the name of the counter
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Gets the description of the counter
    pub fn description(&self) -> &str {
        &self.description
    }
    
    /// Gets the underlying Prometheus counter
    pub fn inner(&self) -> &PromCounter {
        &self.counter
    }
}

impl fmt::Debug for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Counter")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("value", &self.value())
            .finish()
    }
}

/// A gauge metric (can increase or decrease)
#[derive(Clone)]
pub struct Gauge {
    /// Metric name
    name: String,
    
    /// Metric description
    description: String,
    
    /// Inner Prometheus gauge
    gauge: Arc<PromGauge>,
}

impl Gauge {
    /// Creates a new gauge with the given name and description
    pub fn new(name: String, description: String) -> Self {
        let opts = Opts::new(name.clone(), description.clone());
        let gauge = PromGauge::with_opts(opts)
            .expect("Failed to create gauge");
        
        Self {
            name,
            description,
            gauge: Arc::new(gauge),
        }
    }
    
    /// Sets the gauge to the given value
    pub fn set(&self, value: f64) {
        self.gauge.set(value);
    }
    
    /// Increments the gauge by the given amount
    pub fn inc(&self, amount: f64) {
        self.gauge.inc_by(amount);
    }
    
    /// Decrements the gauge by the given amount
    pub fn dec(&self, amount: f64) {
        self.gauge.dec_by(amount);
    }
    
    /// Increments the gauge by 1
    pub fn inc_one(&self) {
        self.gauge.inc();
    }
    
    /// Decrements the gauge by 1
    pub fn dec_one(&self) {
        self.gauge.dec();
    }
    
    /// Gets the current value of the gauge
    pub fn value(&self) -> f64 {
        self.gauge.get()
    }
    
    /// Gets the name of the gauge
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Gets the description of the gauge
    pub fn description(&self) -> &str {
        &self.description
    }
    
    /// Gets the underlying Prometheus gauge
    pub fn inner(&self) -> &PromGauge {
        &self.gauge
    }
}

impl fmt::Debug for Gauge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gauge")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("value", &self.value())
            .finish()
    }
}

/// A histogram metric (distribution of values)
#[derive(Clone)]
pub struct Histogram {
    /// Metric name
    name: String,
    
    /// Metric description
    description: String,
    
    /// Inner Prometheus histogram
    histogram: Arc<PromHistogram>,
}

impl Histogram {
    /// Creates a new histogram with the given name, description, and buckets
    pub fn new(name: String, description: String, buckets: Vec<f64>) -> Self {
        let opts = HistogramOpts::new(name.clone(), description.clone())
            .buckets(buckets);
        let histogram = PromHistogram::with_opts(opts)
            .expect("Failed to create histogram");
        
        Self {
            name,
            description,
            histogram: Arc::new(histogram),
        }
    }
    
    /// Creates a new histogram with default buckets
    pub fn with_default_buckets(name: String, description: String) -> Self {
        let opts = HistogramOpts::new(name.clone(), description.clone());
        let histogram = PromHistogram::with_opts(opts)
            .expect("Failed to create histogram");
        
        Self {
            name,
            description,
            histogram: Arc::new(histogram),
        }
    }
    
    /// Creates a new histogram with linear buckets
    pub fn with_linear_buckets(name: String, description: String, 
                              start: f64, width: f64, count: usize) -> Self {
        let opts = HistogramOpts::new(name.clone(), description.clone())
            .buckets(prometheus::linear_buckets(start, width, count)
                .expect("Failed to create linear buckets"));
        let histogram = PromHistogram::with_opts(opts)
            .expect("Failed to create histogram");
        
        Self {
            name,
            description,
            histogram: Arc::new(histogram),
        }
    }
    
    /// Creates a new histogram with exponential buckets
    pub fn with_exponential_buckets(name: String, description: String,
                                  start: f64, factor: f64, count: usize) -> Self {
        let opts = HistogramOpts::new(name.clone(), description.clone())
            .buckets(prometheus::exponential_buckets(start, factor, count)
                .expect("Failed to create exponential buckets"));
        let histogram = PromHistogram::with_opts(opts)
            .expect("Failed to create histogram");
        
        Self {
            name,
            description,
            histogram: Arc::new(histogram),
        }
    }
    
    /// Records a value in the histogram
    pub fn observe(&self, value: f64) {
        self.histogram.observe(value);
    }
    
    /// Gets the name of the histogram
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Gets the description of the histogram
    pub fn description(&self) -> &str {
        &self.description
    }
    
    /// Gets the underlying Prometheus histogram
    pub fn inner(&self) -> &PromHistogram {
        &self.histogram
    }
    
    /// Creates a timer that will record the duration when dropped
    pub fn start_timer(&self) -> HistogramTimerGuard {
        HistogramTimerGuard {
            histogram: self.clone(),
            start: Instant::now(),
        }
    }
    
    /// Records a duration in the histogram
    pub fn observe_duration(&self, duration: Duration) {
        self.observe(duration.as_secs_f64());
    }
}

impl fmt::Debug for Histogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Histogram")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish()
    }
}

/// A timer guard for histograms
pub struct HistogramTimerGuard {
    /// The histogram to record the duration in
    histogram: Histogram,
    
    /// The start time of the timer
    start: Instant,
}

impl Drop for HistogramTimerGuard {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.histogram.observe_duration(duration);
    }
}

/// The main metrics collector for the blockchain
#[derive(Clone)]
pub struct MetricsCollector {
    /// Registry of all metrics
    registry: Arc<Registry>,
    
    /// Metrics by name
    metrics: Arc<RwLock<HashMap<String, MetricType>>>,
    
    /// Counters by name
    counters: Arc<RwLock<HashMap<String, Counter>>>,
    
    /// Gauges by name
    gauges: Arc<RwLock<HashMap<String, Gauge>>>,
    
    /// Histograms by name
    histograms: Arc<RwLock<HashMap<String, Histogram>>>,
}

impl MetricsCollector {
    /// Creates a new metrics collector
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Registry::new()),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Creates a new counter
    pub fn create_counter(&self, name: &str, description: &str) -> Counter {
        // Check if the metric already exists
        if self.metric_exists(name) {
            if let Some(counter) = self.get_counter(name) {
                return counter;
            } else {
                // It exists but with a different type, remove it
                self.remove_metric(name);
            }
        }
        
        // Create the counter
        let counter = Counter::new(name.to_string(), description.to_string());
        
        // Register the counter
        self.registry.register(Box::new(counter.inner().clone()))
            .expect("Failed to register counter");
        
        // Store the counter
        self.metrics.write().insert(name.to_string(), MetricType::Counter);
        self.counters.write().insert(name.to_string(), counter.clone());
        
        counter
    }
    
    /// Gets a counter by name
    pub fn get_counter(&self, name: &str) -> Option<Counter> {
        self.counters.read().get(name).cloned()
    }
    
    /// Creates a new gauge
    pub fn create_gauge(&self, name: &str, description: &str) -> Gauge {
        // Check if the metric already exists
        if self.metric_exists(name) {
            if let Some(gauge) = self.get_gauge(name) {
                return gauge;
            } else {
                // It exists but with a different type, remove it
                self.remove_metric(name);
            }
        }
        
        // Create the gauge
        let gauge = Gauge::new(name.to_string(), description.to_string());
        
        // Register the gauge
        self.registry.register(Box::new(gauge.inner().clone()))
            .expect("Failed to register gauge");
        
        // Store the gauge
        self.metrics.write().insert(name.to_string(), MetricType::Gauge);
        self.gauges.write().insert(name.to_string(), gauge.clone());
        
        gauge
    }
    
    /// Gets a gauge by name
    pub fn get_gauge(&self, name: &str) -> Option<Gauge> {
        self.gauges.read().get(name).cloned()
    }
    
    /// Creates a new histogram
    pub fn create_histogram(&self, name: &str, description: &str, buckets: Option<Vec<f64>>) -> Histogram {
        // Check if the metric already exists
        if self.metric_exists(name) {
            if let Some(histogram) = self.get_histogram(name) {
                return histogram;
            } else {
                // It exists but with a different type, remove it
                self.remove_metric(name);
            }
        }
        
        // Create the histogram
        let histogram = match buckets {
            Some(buckets) => Histogram::new(name.to_string(), description.to_string(), buckets),
            None => Histogram::with_default_buckets(name.to_string(), description.to_string()),
        };
        
        // Register the histogram
        self.registry.register(Box::new(histogram.inner().clone()))
            .expect("Failed to register histogram");
        
        // Store the histogram
        self.metrics.write().insert(name.to_string(), MetricType::Histogram);
        self.histograms.write().insert(name.to_string(), histogram.clone());
        
        histogram
    }
    
    /// Creates a new histogram with linear buckets
    pub fn create_linear_histogram(&self, name: &str, description: &str, 
                                  start: f64, width: f64, count: usize) -> Histogram {
        // Check if the metric already exists
        if self.metric_exists(name) {
            if let Some(histogram) = self.get_histogram(name) {
                return histogram;
            } else {
                // It exists but with a different type, remove it
                self.remove_metric(name);
            }
        }
        
        // Create the histogram
        let histogram = Histogram::with_linear_buckets(
            name.to_string(), description.to_string(), start, width, count);
        
        // Register the histogram
        self.registry.register(Box::new(histogram.inner().clone()))
            .expect("Failed to register histogram");
        
        // Store the histogram
        self.metrics.write().insert(name.to_string(), MetricType::Histogram);
        self.histograms.write().insert(name.to_string(), histogram.clone());
        
        histogram
    }
    
    /// Creates a new histogram with exponential buckets
    pub fn create_exponential_histogram(&self, name: &str, description: &str,
                                      start: f64, factor: f64, count: usize) -> Histogram {
        // Check if the metric already exists
        if self.metric_exists(name) {
            if let Some(histogram) = self.get_histogram(name) {
                return histogram;
            } else {
                // It exists but with a different type, remove it
                self.remove_metric(name);
            }
        }
        
        // Create the histogram
        let histogram = Histogram::with_exponential_buckets(
            name.to_string(), description.to_string(), start, factor, count);
        
        // Register the histogram
        self.registry.register(Box::new(histogram.inner().clone()))
            .expect("Failed to register histogram");
        
        // Store the histogram
        self.metrics.write().insert(name.to_string(), MetricType::Histogram);
        self.histograms.write().insert(name.to_string(), histogram.clone());
        
        histogram
    }
    
    /// Gets a histogram by name
    pub fn get_histogram(&self, name: &str) -> Option<Histogram> {
        self.histograms.read().get(name).cloned()
    }
    
    /// Checks if a metric with the given name exists
    pub fn metric_exists(&self, name: &str) -> bool {
        self.metrics.read().contains_key(name)
    }
    
    /// Gets the type of a metric
    pub fn metric_type(&self, name: &str) -> Option<MetricType> {
        self.metrics.read().get(name).cloned()
    }
    
    /// Removes a metric
    pub fn remove_metric(&self, name: &str) {
        // Remove from the appropriate collection
        if let Some(metric_type) = self.metric_type(name) {
            match metric_type {
                MetricType::Counter => { self.counters.write().remove(name); },
                MetricType::Gauge => { self.gauges.write().remove(name); },
                MetricType::Histogram => { self.histograms.write().remove(name); },
            }
        }
        
        // Remove from the metrics map
        self.metrics.write().remove(name);
        
        // Note: We cannot unregister from the Prometheus registry,
        // as it does not support this operation.
    }
    
    /// Gets all metrics
    pub fn get_all_metrics(&self) -> HashMap<String, MetricType> {
        self.metrics.read().clone()
    }
    
    /// Gets all counter values
    pub fn get_all_counter_values(&self) -> HashMap<String, u64> {
        let counters = self.counters.read();
        let mut values = HashMap::new();
        
        for (name, counter) in counters.iter() {
            values.insert(name.clone(), counter.value());
        }
        
        values
    }
    
    /// Gets all gauge values
    pub fn get_all_gauge_values(&self) -> HashMap<String, f64> {
        let gauges = self.gauges.read();
        let mut values = HashMap::new();
        
        for (name, gauge) in gauges.iter() {
            values.insert(name.clone(), gauge.value());
        }
        
        values
    }
    
    /// Gets the Prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    
    /// Creates standard blockchain metrics
    pub fn create_standard_metrics(&self) {
        // Block metrics
        self.create_counter("blocks_produced", "Total number of blocks produced");
        self.create_counter("blocks_received", "Total number of blocks received");
        self.create_counter("blocks_validated", "Total number of blocks validated");
        self.create_counter("blocks_rejected", "Total number of blocks rejected");
        self.create_counter("blocks_finalized", "Total number of blocks finalized");
        
        // Transaction metrics
        self.create_counter("transactions_processed", "Total number of transactions processed");
        self.create_counter("transactions_validated", "Total number of transactions validated");
        self.create_counter("transactions_rejected", "Total number of transactions rejected");
        self.create_gauge("transactions_pending", "Number of pending transactions");
        self.create_histogram("transaction_execution_time", 
                            "Transaction execution time in seconds",
                            Some(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]));
        
        // Network metrics
        self.create_gauge("peers_connected", "Number of connected peers");
        self.create_counter("messages_sent", "Total number of messages sent");
        self.create_counter("messages_received", "Total number of messages received");
        self.create_counter("bytes_sent", "Total number of bytes sent");
        self.create_counter("bytes_received", "Total number of bytes received");
        
        // Consensus metrics
        self.create_gauge("validators_active", "Number of active validators");
        self.create_counter("validation_confirmations", "Total number of validation confirmations");
        self.create_counter("validation_rejections", "Total number of validation rejections");
        self.create_histogram("validation_time", 
                            "Validation time in seconds",
                            Some(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]));
        
        // Security level metrics
        self.create_counter("minimal_security_achieved", "Total transactions reaching minimal security");
        self.create_counter("basic_security_achieved", "Total transactions reaching basic security");
        self.create_counter("strong_security_achieved", "Total transactions reaching strong security");
        self.create_counter("full_security_achieved", "Total transactions reaching full security");
        self.create_histogram("security_level_latency", 
                            "Time to reach security level in seconds",
                            Some(vec![0.01, 0.05, 0.1, 0.2, 0.5, 0.8, 1.0, 1.5, 2.0, 5.0]));
        
        // TEE metrics
        self.create_counter("tee_attestations", "Total number of TEE attestations");
        self.create_counter("tee_verification_success", "Total number of successful TEE verifications");
        self.create_counter("tee_verification_failure", "Total number of failed TEE verifications");
        
        // DAG metrics
        self.create_gauge("micro_dag_size", "Size of the micro-DAG");
        self.create_gauge("macro_dag_size", "Size of the macro-DAG");
        self.create_counter("parent_references", "Total number of parent references in the macro-DAG");
        self.create_gauge("parallel_chains", "Number of parallel chains");
        
        // System metrics
        self.create_gauge("cpu_usage", "CPU usage percentage");
        self.create_gauge("memory_usage", "Memory usage in bytes");
        self.create_gauge("disk_usage", "Disk usage in bytes");
        self.create_gauge("open_files", "Number of open files");
        self.create_gauge("goroutines", "Number of goroutines");
    }
    
    /// Updates performance metrics from the system
    pub fn update_performance_metrics(&self) {
        // TODO: Implement system metrics collection
        // For now, we'll just add placeholder updates
        
        if let Some(cpu_gauge) = self.get_gauge("cpu_usage") {
            // This is a placeholder - in a real implementation, we would get the actual CPU usage
            let cpu_usage = 10.0; // Example value
            cpu_gauge.set(cpu_usage);
        }
        
        if let Some(memory_gauge) = self.get_gauge("memory_usage") {
            // This is a placeholder - in a real implementation, we would get the actual memory usage
            let memory_usage = 1024.0 * 1024.0 * 100.0; // Example value: 100 MB
            memory_gauge.set(memory_usage);
        }
    }
    
    /// Records a block being produced
    pub fn record_block_produced(&self) {
        if let Some(counter) = self.get_counter("blocks_produced") {
            counter.inc_one();
        }
    }
    
    /// Records a block being received
    pub fn record_block_received(&self) {
        if let Some(counter) = self.get_counter("blocks_received") {
            counter.inc_one();
        }
    }
    
    /// Records a block being validated
    pub fn record_block_validated(&self, duration: Duration) {
        if let Some(counter) = self.get_counter("blocks_validated") {
            counter.inc_one();
        }
        
        if let Some(histogram) = self.get_histogram("validation_time") {
            histogram.observe_duration(duration);
        }
    }
    
    /// Records a block being rejected
    pub fn record_block_rejected(&self) {
        if let Some(counter) = self.get_counter("blocks_rejected") {
            counter.inc_one();
        }
    }
    
    /// Records a block being finalized
    pub fn record_block_finalized(&self) {
        if let Some(counter) = self.get_counter("blocks_finalized") {
            counter.inc_one();
        }
    }
    
    /// Records a transaction being processed
    pub fn record_transaction_processed(&self, duration: Duration) {
        if let Some(counter) = self.get_counter("transactions_processed") {
            counter.inc_one();
        }
        
        if let Some(histogram) = self.get_histogram("transaction_execution_time") {
            histogram.observe_duration(duration);
        }
    }
    
    /// Records a transaction reaching a security level
    pub fn record_security_level_achieved(&self, level: u8, duration: Duration) {
        let counter_name = match level {
            0 => "minimal_security_achieved",
            1 => "basic_security_achieved",
            2 => "strong_security_achieved",
            3 => "full_security_achieved",
            _ => return,
        };
        
        if let Some(counter) = self.get_counter(counter_name) {
            counter.inc_one();
        }
        
        if let Some(histogram) = self.get_histogram("security_level_latency") {
            histogram.observe_duration(duration);
        }
    }
    
    /// Updates the number of pending transactions
    pub fn update_pending_transactions(&self, count: u64) {
        if let Some(gauge) = self.get_gauge("transactions_pending") {
            gauge.set(count as f64);
        }
    }
    
    /// Updates the number of connected peers
    pub fn update_connected_peers(&self, count: u64) {
        if let Some(gauge) = self.get_gauge("peers_connected") {
            gauge.set(count as f64);
        }
    }
    
    /// Updates the DAG sizes
    pub fn update_dag_sizes(&self, micro_dag_size: usize, macro_dag_size: usize, parallel_chains: usize) {
        if let Some(gauge) = self.get_gauge("micro_dag_size") {
            gauge.set(micro_dag_size as f64);
        }
        
        if let Some(gauge) = self.get_gauge("macro_dag_size") {
            gauge.set(macro_dag_size as f64);
        }
        
        if let Some(gauge) = self.get_gauge("parallel_chains") {
            gauge.set(parallel_chains as f64);
        }
    }
    
    /// Records a parent reference being added
    pub fn record_parent_reference(&self) {
        if let Some(counter) = self.get_counter("parent_references") {
            counter.inc_one();
        }
    }
    
    /// Updates the number of active validators
    pub fn update_active_validators(&self, count: u64) {
        if let Some(gauge) = self.get_gauge("validators_active") {
            gauge.set(count as f64);
        }
    }
    
    /// Records a TEE attestation
    pub fn record_tee_attestation(&self) {
        if let Some(counter) = self.get_counter("tee_attestations") {
            counter.inc_one();
        }
    }
    
    /// Records a successful TEE verification
    pub fn record_tee_verification_success(&self) {
        if let Some(counter) = self.get_counter("tee_verification_success") {
            counter.inc_one();
        }
    }
    
    /// Records a failed TEE verification
    pub fn record_tee_verification_failure(&self) {
        if let Some(counter) = self.get_counter("tee_verification_failure") {
            counter.inc_one();
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        let collector = Self::new();
        collector.create_standard_metrics();
        collector
    }
}

impl fmt::Debug for MetricsCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsCollector")
            .field("metrics_count", &self.metrics.read().len())
            .field("counters_count", &self.counters.read().len())
            .field("gauges_count", &self.gauges.read().len())
            .field("histograms_count", &self.histograms.read().len())
            .finish()
    }
}

// Global metrics collector
lazy_static! {
    static ref METRICS_COLLECTOR: MetricsCollector = MetricsCollector::default();
}

/// Gets a default metrics collector instance
pub fn get_metrics_collector() -> &'static MetricsCollector {
    &METRICS_COLLECTOR
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_counter() {
        let counter = Counter::new("test_counter".to_string(), "Test counter".to_string());
        
        assert_eq!(counter.value(), 0);
        
        counter.inc_one();
        assert_eq!(counter.value(), 1);
        
        counter.inc(5);
        assert_eq!(counter.value(), 6);
        
        assert_eq!(counter.name(), "test_counter");
        assert_eq!(counter.description(), "Test counter");
    }
    
    #[test]
    fn test_gauge() {
        let gauge = Gauge::new("test_gauge".to_string(), "Test gauge".to_string());
        
        assert_eq!(gauge.value(), 0.0);
        
        gauge.set(10.5);
        assert_eq!(gauge.value(), 10.5);
        
        gauge.inc(2.5);
        assert_eq!(gauge.value(), 13.0);
        
        gauge.dec(3.0);
        assert_eq!(gauge.value(), 10.0);
        
        gauge.inc_one();
        assert_eq!(gauge.value(), 11.0);
        
        gauge.dec_one();
        assert_eq!(gauge.value(), 10.0);
        
        assert_eq!(gauge.name(), "test_gauge");
        assert_eq!(gauge.description(), "Test gauge");
    }
    
    #[test]
    fn test_histogram() {
        let histogram = Histogram::with_default_buckets(
            "test_histogram".to_string(), "Test histogram".to_string());
        
        // Observe some values
        histogram.observe(0.1);
        histogram.observe(0.5);
        histogram.observe(1.0);
        
        // We can't directly get the values from a Prometheus histogram,
        // but we can check that name and description are correct
        assert_eq!(histogram.name(), "test_histogram");
        assert_eq!(histogram.description(), "Test histogram");
    }
    
}
