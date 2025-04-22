use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::core::{Object, ObjectID, Transaction};
use crate::core::object::AccessType;
use crate::core::transaction::ObjectRef;
use crate::error::{AevorError, Result};
use crate::storage::object_store::ObjectStore;
use crate::utils::metrics::Metrics;

/// Configuration for the Predictive Prefetcher
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    /// Enable predictive prefetching
    pub enabled: bool,
    
    /// Maximum number of objects to prefetch per transaction
    pub max_objects_per_tx: usize,
    
    /// Maximum number of prefetch requests to queue
    pub max_queue_size: usize,
    
    /// Concurrency limit for prefetching
    pub concurrency_limit: usize,
    
    /// Time-to-live for cached objects in milliseconds
    pub cache_ttl_ms: u64,
    
    /// Maximum size of the access pattern cache (number of entries)
    pub max_pattern_cache_size: usize,
    
    /// Prefetch threshold score (0.0 - 1.0)
    pub prefetch_threshold: f64,
    
    /// Weight decay factor for historical patterns (0.0 - 1.0)
    pub weight_decay: f64,
    
    /// Minimum number of observations before prediction
    pub min_observations: usize,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_objects_per_tx: 50,
            max_queue_size: 1000,
            concurrency_limit: 32,
            cache_ttl_ms: 5000,
            max_pattern_cache_size: 10000,
            prefetch_threshold: 0.7,
            weight_decay: 0.95,
            min_observations: 3,
        }
    }
}

/// Record of object access, used for pattern recognition
#[derive(Debug, Clone)]
struct AccessRecord {
    /// Object ID being accessed
    object_id: ObjectID,
    
    /// Access type (read or write)
    access_type: AccessType,
    
    /// Transaction hash
    tx_hash: Vec<u8>,
    
    /// Timestamp of access
    timestamp: Instant,
}

/// Access pattern between objects
#[derive(Debug, Clone)]
struct AccessPattern {
    /// Source object ID
    source: ObjectID,
    
    /// Target object ID
    target: ObjectID,
    
    /// Access type for the target
    access_type: AccessType,
    
    /// Number of observations of this pattern
    observations: usize,
    
    /// Confidence score (0.0 - 1.0)
    confidence: f64,
    
    /// Last updated timestamp
    last_updated: Instant,
}

/// Prefetch request for an object
#[derive(Debug, Clone)]
struct PrefetchRequest {
    /// Object ID to prefetch
    object_id: ObjectID,
    
    /// Expected access type
    access_type: AccessType,
    
    /// Priority (higher = more important)
    priority: u8,
    
    /// Source transaction hash
    source_tx: Option<Vec<u8>>,
    
    /// Timestamp when the request was created
    timestamp: Instant,
}

/// Result of a prefetch operation
#[derive(Debug, Clone)]
pub struct PrefetchResult {
    /// Object ID that was prefetched
    pub object_id: ObjectID,
    
    /// Whether the prefetch was successful
    pub success: bool,
    
    /// Time taken to prefetch
    pub duration: Duration,
    
    /// Priority of the prefetch request
    pub priority: u8,
}

/// Predictive prefetcher for the Aevor micro-DAG
///
/// The prefetcher analyzes transaction access patterns to predict
/// which objects will be needed next and preloads them into cache.
/// This reduces micro-DAG scheduling latency by 10-15% under heavy load.
pub struct PredictivePrefetcher {
    /// Configuration
    config: PrefetchConfig,
    
    /// Object store for accessing objects
    object_store: Arc<ObjectStore>,
    
    /// Recent object accesses for pattern recognition
    recent_accesses: Arc<RwLock<VecDeque<AccessRecord>>>,
    
    /// Access patterns between objects
    access_patterns: Arc<RwLock<HashMap<ObjectID, HashMap<ObjectID, AccessPattern>>>>,
    
    /// Currently prefetched objects with expiration time
    prefetched_objects: Arc<RwLock<HashMap<ObjectID, Instant>>>,
    
    /// Prefetch request queue
    prefetch_queue: Arc<Mutex<VecDeque<PrefetchRequest>>>,
    
    /// Currently active prefetch operations
    active_prefetches: Arc<RwLock<HashSet<ObjectID>>>,
    
    /// Send channel for prefetch requests
    request_sender: mpsc::Sender<PrefetchRequest>,
    
    /// Receive channel for prefetch requests
    request_receiver: Arc<Mutex<mpsc::Receiver<PrefetchRequest>>>,
    
    /// Worker task handles
    worker_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    
    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
    
    /// Metrics
    metrics: Arc<Metrics>,
}

impl PredictivePrefetcher {
    /// Creates a new predictive prefetcher
    pub fn new(
        config: PrefetchConfig,
        object_store: Arc<ObjectStore>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let (request_sender, request_receiver) = mpsc::channel(config.max_queue_size);
        
        Self {
            config,
            object_store,
            recent_accesses: Arc::new(RwLock::new(VecDeque::new())),
            access_patterns: Arc::new(RwLock::new(HashMap::new())),
            prefetched_objects: Arc::new(RwLock::new(HashMap::new())),
            prefetch_queue: Arc::new(Mutex::new(VecDeque::new())),
            active_prefetches: Arc::new(RwLock::new(HashSet::new())),
            request_sender,
            request_receiver: Arc::new(Mutex::new(request_receiver)),
            worker_tasks: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(RwLock::new(false)),
            metrics,
        }
    }
    
    /// Starts the prefetcher worker tasks
    pub fn start(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Predictive prefetching is disabled");
            return Ok(());
        }
        
        // Reset the shutdown signal
        {
            let mut shutdown = self.shutdown.write();
            *shutdown = false;
        }
        
        // Start worker tasks
        let mut workers = self.worker_tasks.lock();
        
        for i in 0..self.config.concurrency_limit {
            let worker = self.start_worker_task(i)?;
            workers.push(worker);
        }
        
        // Start cache cleanup task
        let cleanup_task = self.start_cleanup_task()?;
        workers.push(cleanup_task);
        
        // Start pattern analysis task
        let analysis_task = self.start_analysis_task()?;
        workers.push(analysis_task);
        
        info!(
            "Started predictive prefetcher with {} worker tasks",
            self.config.concurrency_limit + 2 // workers + cleanup + analysis
        );
        
        Ok(())
    }
    
    /// Stops the prefetcher worker tasks
    pub fn stop(&self) -> Result<()> {
        // Signal shutdown
        {
            let mut shutdown = self.shutdown.write();
            *shutdown = true;
        }
        
        // Wait for worker tasks to finish
        let mut workers = self.worker_tasks.lock();
        for worker in workers.drain(..) {
            match worker.abort_handle().is_finished() {
                true => debug!("Worker task already finished"),
                false => {
                    debug!("Aborting worker task");
                    worker.abort();
                }
            }
        }
        
        info!("Stopped predictive prefetcher");
        Ok(())
    }
    
    /// Starts a worker task for processing prefetch requests
    fn start_worker_task(&self, worker_id: usize) -> Result<JoinHandle<()>> {
        let object_store = self.object_store.clone();
        let prefetched_objects = self.prefetched_objects.clone();
        let active_prefetches = self.active_prefetches.clone();
        let request_receiver = self.request_receiver.clone();
        let shutdown = self.shutdown.clone();
        let metrics = self.metrics.clone();
        let cache_ttl = Duration::from_millis(self.config.cache_ttl_ms);
        
        let task = tokio::spawn(async move {
            debug!("Started prefetch worker task {}", worker_id);
            
            loop {
                // Check for shutdown signal
                if *shutdown.read() {
                    debug!("Prefetch worker {} shutting down", worker_id);
                    break;
                }
                
                // Get the next request from the receiver
                let request = {
                    let mut receiver = request_receiver.lock();
                    match receiver.try_recv() {
                        Ok(req) => Some(req),
                        Err(_) => None,
                    }
                };
                
                if let Some(request) = request {
                    let object_id = request.object_id.clone();
                    let priority = request.priority;
                    
                    // Skip if already active
                    if active_prefetches.read().contains(&object_id) {
                        trace!("Skipping prefetch for object already in progress: {:?}", object_id);
                        continue;
                    }
                    
                    // Skip if already prefetched and not expired
                    {
                        let prefetched = prefetched_objects.read();
                        if let Some(expiry) = prefetched.get(&object_id) {
                            if expiry > &Instant::now() {
                                trace!("Skipping prefetch for already cached object: {:?}", object_id);
                                continue;
                            }
                        }
                    }
                    
                    // Mark as active
                    active_prefetches.write().insert(object_id.clone());
                    
                    // Perform the prefetch
                    let start_time = Instant::now();
                    let result = match object_store.get_object(&object_id) {
                        Ok(Some(_object)) => {
                            // Successfully prefetched
                            let duration = start_time.elapsed();
                            
                            // Update prefetched objects with expiry time
                            let expiry = Instant::now() + cache_ttl;
                            prefetched_objects.write().insert(object_id.clone(), expiry);
                            
                            // Update metrics
                            metrics.record_prefetch_hit();
                            
                            PrefetchResult {
                                object_id: object_id.clone(),
                                success: true,
                                duration,
                                priority,
                            }
                        }
                        Ok(None) => {
                            // Object not found
                            let duration = start_time.elapsed();
                            
                            // Update metrics
                            metrics.record_prefetch_miss();
                            
                            PrefetchResult {
                                object_id: object_id.clone(),
                                success: false,
                                duration,
                                priority,
                            }
                        }
                        Err(err) => {
                            // Error during prefetch
                            let duration = start_time.elapsed();
                            warn!("Error prefetching object {:?}: {}", object_id, err);
                            
                            // Update metrics
                            metrics.record_prefetch_error();
                            
                            PrefetchResult {
                                object_id: object_id.clone(),
                                success: false,
                                duration,
                                priority,
                            }
                        }
                    };
                    
                    // Log result
                    if result.success {
                        trace!(
                            "Prefetched object {:?} in {:?} (priority {})",
                            result.object_id,
                            result.duration,
                            result.priority
                        );
                    } else {
                        trace!(
                            "Failed to prefetch object {:?} in {:?} (priority {})",
                            result.object_id,
                            result.duration,
                            result.priority
                        );
                    }
                    
                    // Remove from active prefetches
                    active_prefetches.write().remove(&object_id);
                } else {
                    // No request available, sleep briefly
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        });
        
        Ok(task)
    }
    
    /// Starts a background task to clean up expired prefetched objects
    fn start_cleanup_task(&self) -> Result<JoinHandle<()>> {
        let prefetched_objects = self.prefetched_objects.clone();
        let shutdown = self.shutdown.clone();
        
        let task = tokio::spawn(async move {
            debug!("Started prefetch cache cleanup task");
            
            loop {
                // Check for shutdown signal
                if *shutdown.read() {
                    debug!("Prefetch cleanup task shutting down");
                    break;
                }
                
                // Remove expired prefetched objects
                let now = Instant::now();
                let mut expired_count = 0;
                
                {
                    let mut prefetched = prefetched_objects.write();
                    let before_count = prefetched.len();
                    
                    // Remove expired entries
                    prefetched.retain(|_, expiry| {
                        let valid = expiry > &now;
                        if !valid {
                            expired_count += 1;
                        }
                        valid
                    });
                    
                    if expired_count > 0 {
                        trace!(
                            "Removed {} expired prefetched objects, {} remaining",
                            expired_count,
                            prefetched.len()
                        );
                    }
                }
                
                // Sleep for 100ms before next cleanup
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        
        Ok(task)
    }
    
    /// Starts a background task to analyze access patterns
    fn start_analysis_task(&self) -> Result<JoinHandle<()>> {
        let recent_accesses = self.recent_accesses.clone();
        let access_patterns = self.access_patterns.clone();
        let shutdown = self.shutdown.clone();
        let max_pattern_cache_size = self.config.max_pattern_cache_size;
        let weight_decay = self.config.weight_decay;
        
        let task = tokio::spawn(async move {
            debug!("Started access pattern analysis task");
            
            loop {
                // Check for shutdown signal
                if *shutdown.read() {
                    debug!("Pattern analysis task shutting down");
                    break;
                }
                
                // Analyze recent accesses to find patterns
                {
                    let accesses = recent_accesses.read();
                    let mut patterns = access_patterns.write();
                    
                    // Skip if we don't have enough accesses
                    if accesses.len() < 2 {
                        // Sleep briefly before next analysis
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    
                    // Group accesses by transaction
                    let mut tx_accesses: HashMap<Vec<u8>, Vec<&AccessRecord>> = HashMap::new();
                    for access in accesses.iter() {
                        tx_accesses
                            .entry(access.tx_hash.clone())
                            .or_default()
                            .push(access);
                    }
                    
                    // Analyze patterns within each transaction
                    for (_tx_hash, tx_records) in tx_accesses.iter() {
                        // Skip transactions with too few accesses
                        if tx_records.len() < 2 {
                            continue;
                        }
                        
                        // Sort by timestamp
                        let mut sorted_records = tx_records.clone();
                        sorted_records.sort_by_key(|r| r.timestamp);
                        
                        // Find access patterns
                        for i in 0..(sorted_records.len() - 1) {
                            let source = &sorted_records[i];
                            let target = &sorted_records[i + 1];
                            
                            // Update the pattern
                            let source_patterns = patterns
                                .entry(source.object_id.clone())
                                .or_insert_with(HashMap::new);
                            
                            let pattern = source_patterns
                                .entry(target.object_id.clone())
                                .or_insert_with(|| AccessPattern {
                                    source: source.object_id.clone(),
                                    target: target.object_id.clone(),
                                    access_type: target.access_type,
                                    observations: 0,
                                    confidence: 0.0,
                                    last_updated: Instant::now(),
                                });
                            
                            // Update the pattern
                            pattern.observations += 1;
                            pattern.access_type = target.access_type;
                            pattern.confidence = pattern.confidence * weight_decay + (1.0 - weight_decay);
                            pattern.last_updated = Instant::now();
                        }
                    }
                    
                    // Prune the patterns if we have too many
                    if patterns.len() > max_pattern_cache_size {
                        // Find the least recently updated patterns
                        let mut all_patterns: Vec<(ObjectID, ObjectID, Instant)> = Vec::new();
                        for (source, targets) in patterns.iter() {
                            for (target, pattern) in targets.iter() {
                                all_patterns.push((
                                    source.clone(),
                                    target.clone(),
                                    pattern.last_updated,
                                ));
                            }
                        }
                        
                        // Sort by last updated (oldest first)
                        all_patterns.sort_by_key(|p| p.2);
                        
                        // Calculate how many to remove
                        let to_remove = all_patterns.len().saturating_sub(max_pattern_cache_size);
                        if to_remove > 0 {
                            // Remove the oldest patterns
                            for i in 0..to_remove {
                                if i < all_patterns.len() {
                                    let (source, target, _) = &all_patterns[i];
                                    if let Some(targets) = patterns.get_mut(source) {
                                        targets.remove(target);
                                        if targets.is_empty() {
                                            patterns.remove(source);
                                        }
                                    }
                                }
                            }
                            
                            trace!("Pruned {} access patterns, {} remaining", to_remove, all_patterns.len() - to_remove);
                        }
                    }
                }
                
                // Sleep for 50ms before next analysis
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        
        Ok(task)
    }
    
    /// Records an object access for pattern recognition
    pub fn record_access(&self, object_id: ObjectID, access_type: AccessType, tx_hash: Vec<u8>) {
        if !self.config.enabled {
            return;
        }
        
        // Create an access record
        let record = AccessRecord {
            object_id,
            access_type,
            tx_hash,
            timestamp: Instant::now(),
        };
        
        // Add to recent accesses
        let mut accesses = self.recent_accesses.write();
        accesses.push_back(record);
        
        // Limit the size of the queue
        while accesses.len() > 1000 {
            accesses.pop_front();
        }
    }
    
    /// Records transaction object accesses for pattern recognition
    pub fn record_transaction_accesses(&self, tx: &Transaction) {
        if !self.config.enabled {
            return;
        }
        
        let tx_hash = tx.hash();
        
        // Record all objects accessed by this transaction
        for object_ref in tx.accessed_objects() {
            self.record_access(object_ref.id.clone(), object_ref.access_type, tx_hash.clone());
        }
    }
    
    /// Predicts which objects will be accessed next based on the current access
    pub fn predict_next_accesses(&self, object_id: &ObjectID) -> Vec<(ObjectID, AccessType, f64)> {
        if !self.config.enabled {
            return Vec::new();
        }
        
        let patterns = self.access_patterns.read();
        
        // Find patterns that start with this object
        if let Some(object_patterns) = patterns.get(object_id) {
            // Filter and sort by confidence
            let mut predictions: Vec<(ObjectID, AccessType, f64)> = object_patterns
                .iter()
                .filter(|(_, pattern)| {
                    pattern.observations >= self.config.min_observations &&
                    pattern.confidence >= self.config.prefetch_threshold
                })
                .map(|(target, pattern)| {
                    (target.clone(), pattern.access_type, pattern.confidence)
                })
                .collect();
            
            // Sort by confidence (highest first)
            predictions.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
            
            // Limit the number of predictions
            if predictions.len() > self.config.max_objects_per_tx {
                predictions.truncate(self.config.max_objects_per_tx);
            }
            
            predictions
        } else {
            Vec::new()
        }
    }
    
    /// Prefetches objects that are likely to be accessed after the given object
    pub fn prefetch_for_object(&self, object_id: &ObjectID) -> Result<usize> {
        if !self.config.enabled {
            return Ok(0);
        }
        
        // Predict which objects will be accessed next
        let predictions = self.predict_next_accesses(object_id);
        
        // Prefetch the predicted objects
        let mut prefetch_count = 0;
        for (target, access_type, confidence) in predictions {
            // Calculate priority based on confidence (0-255)
            let priority = (confidence * 255.0).min(255.0) as u8;
            
            // Create a prefetch request
            let request = PrefetchRequest {
                object_id: target,
                access_type,
                priority,
                source_tx: None,
                timestamp: Instant::now(),
            };
            
            // Send the request
            match self.request_sender.try_send(request) {
                Ok(_) => {
                    prefetch_count += 1;
                    trace!(
                        "Queued prefetch for object after {:?} with priority {}",
                        object_id,
                        priority
                    );
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Queue is full, log and continue
                    warn!("Prefetch queue is full, skipping prefetch for object after {:?}", object_id);
                    break;
                }
                Err(e) => {
                    // Other error, log and continue
                    warn!("Error queuing prefetch for object after {:?}: {}", object_id, e);
                }
            }
        }
        
        Ok(prefetch_count)
    }
    
    /// Prefetches objects for a transaction based on its access patterns
    pub fn prefetch_for_transaction(&self, tx: &Transaction) -> Result<usize> {
        if !self.config.enabled {
            return Ok(0);
        }
        
        let tx_hash = tx.hash();
        let mut prefetch_count = 0;
        
        // First, prefetch directly accessed objects
        for object_ref in tx.accessed_objects() {
            // Create a prefetch request
            let request = PrefetchRequest {
                object_id: object_ref.id.clone(),
                access_type: object_ref.access_type,
                priority: 255, // Highest priority for direct accesses
                source_tx: Some(tx_hash.clone()),
                timestamp: Instant::now(),
            };
            
            // Send the request
            match self.request_sender.try_send(request) {
                Ok(_) => {
                    prefetch_count += 1;
                    trace!(
                        "Queued prefetch for object {:?} directly accessed by transaction",
                        object_ref.id
                    );
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Queue is full, log and continue
                    warn!("Prefetch queue is full, skipping direct access prefetch");
                    break;
                }
                Err(e) => {
                    // Other error, log and continue
                    warn!("Error queuing direct access prefetch: {}", e);
                }
            }
            
            // Then, predict and prefetch objects that might be accessed next
            if prefetch_count < self.config.max_objects_per_tx {
                let additional = self.prefetch_for_object(&object_ref.id)?;
                prefetch_count += additional;
                
                // Check if we've reached the limit
                if prefetch_count >= self.config.max_objects_per_tx {
                    break;
                }
            }
        }
        
        // Record transaction accesses for future pattern recognition
        self.record_transaction_accesses(tx);
        
        Ok(prefetch_count)
    }
    
    /// Prefetches objects for multiple transactions
    pub fn prefetch_for_transactions(&self, txs: &[Transaction]) -> Result<usize> {
        if !self.config.enabled || txs.is_empty() {
            return Ok(0);
        }
        
        let mut total_prefetch_count = 0;
        
        // Prefetch for each transaction
        for tx in txs {
            let count = self.prefetch_for_transaction(tx)?;
            total_prefetch_count += count;
            
            // If we've prefetched too many objects already, stop
            if total_prefetch_count >= self.config.max_objects_per_tx * 2 {
                break;
            }
        }
        
        Ok(total_prefetch_count)
    }
    
    /// Checks if an object is already prefetched
    pub fn is_prefetched(&self, object_id: &ObjectID) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        let prefetched = self.prefetched_objects.read();
        if let Some(expiry) = prefetched.get(object_id) {
            expiry > &Instant::now()
        } else {
            false
        }
    }
    
    /// Gets the confidence score for an object access pattern
    pub fn get_pattern_confidence(&self, source: &ObjectID, target: &ObjectID) -> f64 {
        if !self.config.enabled {
            return 0.0;
        }
        
        let patterns = self.access_patterns.read();
        
        // Find the pattern
        if let Some(object_patterns) = patterns.get(source) {
            if let Some(pattern) = object_patterns.get(target) {
                pattern.confidence
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
    
    /// Gets the current cache hit rate
    pub fn get_cache_hit_rate(&self) -> f64 {
        self.metrics.get_prefetch_hit_rate()
    }
    
    /// Gets the number of objects currently prefetched
    pub fn prefetched_count(&self) -> usize {
        self.prefetched_objects.read().len()
    }
    
    /// Gets the number of active prefetch operations
    pub fn active_prefetch_count(&self) -> usize {
        self.active_prefetches.read().len()
    }
    
    /// Gets the number of access patterns currently tracked
    pub fn pattern_count(&self) -> usize {
        let patterns = self.access_patterns.read();
        let mut count = 0;
        
        for (_, targets) in patterns.iter() {
            count += targets.len();
        }
        
        count
    }
    
    /// Clears all access patterns
    pub fn clear_patterns(&self) {
        let mut patterns = self.access_patterns.write();
        patterns.clear();
    }
    
    /// Clears recent accesses
    pub fn clear_recent_accesses(&self) {
        let mut accesses = self.recent_accesses.write();
        accesses.clear();
    }
    
    /// Clears prefetched objects
    pub fn clear_prefetched(&self) {
        let mut prefetched = self.prefetched_objects.write();
        prefetched.clear();
    }
    
    /// Gets the configuration
    pub fn config(&self) -> &PrefetchConfig {
        &self.config
    }
    
    /// Sets a new configuration
    pub fn set_config(&mut self, config: PrefetchConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{Transaction, TransactionType, TransactionData};
    use crate::core::transaction::data::TransferData;
    use crate::storage::StorageConfig;
    
    fn create_test_object_store() -> Arc<ObjectStore> {
        let storage_config = StorageConfig {
            engine: "memory".to_string(),
            db_path: PathBuf::from("./data/test-db"),
            create_if_missing: true,
            compression_enabled: false,
            cache_size_mb: 10,
            max_open_files: 100,
            write_buffer_size: 4 * 1024 * 1024,
            compaction: crate::storage::CompactionConfig {
                enabled: false,
                style: "level".to_string(),
                interval_secs: 3600,
            },
            pruning: crate::storage::PruningConfig {
                enabled: false,
                interval_secs: 3600,
                keep_latest_blocks: 1000,
                keep_finalized_blocks: true,
                keep_state_blocks: 100,
            },
        };
        
        Arc::new(ObjectStore::new(storage_config).unwrap())
    }
    
    fn create_test_metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new())
    }
}
