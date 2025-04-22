use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time;

use crate::config::NetworkConfig;
use crate::error::{AevorError, Result};
use crate::networking::peer::{PeerInfo, PeerManager, PeerState};
use crate::networking::protocol::{Message, MessageType};
use crate::utils::metrics::Metrics;

/// Network topology manager for optimizing validations and network communication
pub struct TopologyManager {
    /// Network configuration
    config: Arc<NetworkConfig>,
    
    /// Node ID (public key)
    node_id: Vec<u8>,
    
    /// Network topology information
    topology: RwLock<NetworkTopology>,
    
    /// Background task handles
    tasks: Mutex<Vec<JoinHandle<()>>>,
    
    /// Last optimization time
    last_optimization: RwLock<Instant>,
    
    /// Whether the manager is running
    running: RwLock<bool>,
    
    /// Optional peer manager reference
    peer_manager: RwLock<Option<Arc<PeerManager>>>,
    
    /// Cached latency measurements to peers
    latency_cache: DashMap<Vec<u8>, LatencyInfo>,
    
    /// Known regions
    known_regions: RwLock<HashMap<String, RegionInfo>>,
    
    /// The region of this node
    local_region: RwLock<Option<String>>,
    
    /// Metrics collection
    metrics: Option<Arc<Metrics>>,
}

impl TopologyManager {
    /// Creates a new topology manager
    pub fn new(config: Arc<NetworkConfig>, node_id: Vec<u8>) -> Result<Self> {
        let now = Instant::now();
        
        Ok(Self {
            config,
            node_id,
            topology: RwLock::new(NetworkTopology::new()),
            tasks: Mutex::new(Vec::new()),
            last_optimization: RwLock::new(now),
            running: RwLock::new(false),
            peer_manager: RwLock::new(None),
            latency_cache: DashMap::new(),
            known_regions: RwLock::new(HashMap::new()),
            local_region: RwLock::new(None),
            metrics: None,
        })
    }
    
    /// Sets the peer manager
    pub async fn set_peer_manager(&self, peer_manager: Arc<PeerManager>) {
        let mut pm = self.peer_manager.write().await;
        *pm = Some(peer_manager);
    }
    
    /// Starts the topology manager
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        // Initialize the topology
        self.initialize_topology().await?;
        
        // Start the optimization task
        let topology_manager = Arc::new(self.clone());
        let optimization_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(
                topology_manager.config.topology_optimization_interval_secs,
            ));
            
            loop {
                interval.tick().await;
                
                if !*topology_manager.running.read().await {
                    break;
                }
                
                if let Err(e) = topology_manager.optimize_topology().await {
                    tracing::error!("Failed to optimize topology: {}", e);
                }
            }
        });
        
        let mut tasks = self.tasks.lock().await;
        tasks.push(optimization_handle);
        
        // Start the latency measurement task
        let topology_manager = Arc::new(self.clone());
        let latency_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60)); // Measure latency every minute
            
            loop {
                interval.tick().await;
                
                if !*topology_manager.running.read().await {
                    break;
                }
                
                if let Err(e) = topology_manager.measure_peer_latencies().await {
                    tracing::error!("Failed to measure peer latencies: {}", e);
                }
            }
        });
        
        tasks.push(latency_handle);
        
        // Start the region discovery task
        let topology_manager = Arc::new(self.clone());
        let region_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(300)); // Update regions every 5 minutes
            
            loop {
                interval.tick().await;
                
                if !*topology_manager.running.read().await {
                    break;
                }
                
                if let Err(e) = topology_manager.discover_regions().await {
                    tracing::error!("Failed to discover regions: {}", e);
                }
            }
        });
        
        tasks.push(region_handle);
        
        *running = true;
        Ok(())
    }
    
    /// Stops the topology manager
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        // Stop all background tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        
        *running = false;
        Ok(())
    }
    
    /// Initializes the topology
    async fn initialize_topology(&self) -> Result<()> {
        // Discover our own region
        let local_region = self.determine_local_region().await?;
        
        // Initialize known regions with our own region
        let mut known_regions = self.known_regions.write().await;
        known_regions.insert(
            local_region.clone(),
            RegionInfo {
                name: local_region.clone(),
                peers: 1,
                validators: 0, // Will be updated later
                average_latency_ms: 0,
                classification: RegionClassification::Local,
            },
        );
        
        // Set our local region
        let mut local = self.local_region.write().await;
        *local = Some(local_region);
        
        // Initialize the topology
        let mut topology = self.topology.write().await;
        topology.node_id = self.node_id.clone();
        
        Ok(())
    }
    
    /// Determines the local region of this node
    async fn determine_local_region(&self) -> Result<String> {
        // Try to get region from IP geolocation service or configuration
        // For now, we'll use a placeholder implementation
        
        // In a real implementation, this would call a geolocation service or
        // use the local configuration to determine the region
        
        // For testing, we'll just return a default region
        Ok("default-region".to_string())
    }
    
    /// Measures the latency to all connected peers
    async fn measure_peer_latencies(&self) -> Result<()> {
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return Ok(()),
        };
        
        let peers = peer_manager.get_peers().await;
        
        // Measure latency to each peer
        let futures: Vec<_> = peers
            .iter()
            .map(|peer| {
                let peer_id = peer.id.clone();
                let peer_manager = peer_manager.clone();
                
                async move {
                    if let Err(e) = Self::measure_peer_latency(peer_manager.clone(), &peer_id).await {
                        tracing::warn!("Failed to measure latency to peer {}: {}", hex::encode(&peer_id), e);
                        return None;
                    }
                    
                    // Wait for the ping response (handled by the peer manager)
                    // In a real implementation, we would track the ping/pong times
                    // For now, simulate a random latency
                    let latency = rand::random::<u64>() % 100 + 10; // 10-110ms
                    
                    Some((peer_id, latency))
                }
            })
            .collect();
        
        // Wait for all measurements to complete
        let results: Vec<_> = stream::iter(futures)
            .buffer_unordered(10) // Measure up to 10 peers concurrently
            .filter_map(|r| async move { r })
            .collect()
            .await;
        
        // Update latency cache
        for (peer_id, latency) in results {
            self.update_peer_latency(peer_id, latency).await;
        }
        
        Ok(())
    }
    
    /// Measures the latency to a specific peer
    async fn measure_peer_latency(peer_manager: Arc<PeerManager>, peer_id: &[u8]) -> Result<()> {
        // Create a ping message
        let ping_message = Message::create_ping();
        
        // Send the ping message
        peer_manager.send_to_peer(peer_id, ping_message).await?;
        
        Ok(())
    }
    
    /// Updates the peer latency in the cache
    async fn update_peer_latency(&self, peer_id: Vec<u8>, latency_ms: u64) {
        let now = Instant::now();
        
        // Get or create the latency info
        let entry = self.latency_cache.entry(peer_id.clone()).or_insert_with(|| {
            LatencyInfo {
                peer_id,
                min_latency_ms: latency_ms,
                max_latency_ms: latency_ms,
                avg_latency_ms: latency_ms,
                measurements: 1,
                last_updated: now,
            }
        });
        
        // Update the latency info
        let mut info = entry.value().clone();
        info.min_latency_ms = info.min_latency_ms.min(latency_ms);
        info.max_latency_ms = info.max_latency_ms.max(latency_ms);
        
        // Update the average latency
        let total = info.avg_latency_ms * info.measurements;
        info.measurements += 1;
        info.avg_latency_ms = (total + latency_ms) / info.measurements;
        info.last_updated = now;
        
        // Store the updated info
        *entry.value_mut() = info;
        
        // Update the peer's region information if available
        self.update_peer_region_latency(&peer_id, latency_ms).await;
    }
    
    /// Updates the latency information for a peer's region
    async fn update_peer_region_latency(&self, peer_id: &[u8], latency_ms: u64) {
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return,
        };
        
        // Get the peer's region
        let region = match peer_manager.get_peer_region(peer_id).await {
            Some(r) => r,
            None => return,
        };
        
        // Update the region's average latency
        let mut known_regions = self.known_regions.write().await;
        
        if let Some(region_info) = known_regions.get_mut(&region) {
            // Update the average latency
            let total = region_info.average_latency_ms * region_info.peers as u64;
            let new_avg = (total + latency_ms) / (region_info.peers as u64);
            region_info.average_latency_ms = new_avg;
        }
    }
    
    /// Discovers the regions of all connected peers
    async fn discover_regions(&self) -> Result<()> {
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return Ok(()),
        };
        
        let peers = peer_manager.get_peers().await;
        let local_region = {
            let local = self.local_region.read().await;
            match local.as_ref() {
                Some(region) => region.clone(),
                None => "unknown".to_string(),
            }
        };
        
        // Group peers by region
        let mut regions: HashMap<String, Vec<PeerInfo>> = HashMap::new();
        
        for peer in peers {
            let region = peer.region.unwrap_or_else(|| "unknown".to_string());
            regions.entry(region).or_default().push(peer);
        }
        
        // Update known regions
        let mut known_regions = self.known_regions.write().await;
        
        // Add our local region if it doesn't exist
        if !known_regions.contains_key(&local_region) {
            known_regions.insert(
                local_region.clone(),
                RegionInfo {
                    name: local_region.clone(),
                    peers: 1,
                    validators: 0, // Will be updated later
                    average_latency_ms: 0,
                    classification: RegionClassification::Local,
                },
            );
        }
        
        // Update region information
        for (region_name, region_peers) in regions {
            let validator_count = region_peers
                .iter()
                .filter(|p| p.is_validator)
                .count();
            
            // Calculate average latency
            let mut total_latency = 0;
            let mut measured_peers = 0;
            
            for peer in &region_peers {
                if let Some(latency) = self.get_peer_latency(&peer.id) {
                    total_latency += latency;
                    measured_peers += 1;
                }
            }
            
            let avg_latency = if measured_peers > 0 {
                total_latency / measured_peers
            } else {
                0
            };
            
            // Determine classification
            let classification = if region_name == local_region {
                RegionClassification::Local
            } else if avg_latency < 50 {
                RegionClassification::Near
            } else if avg_latency < 150 {
                RegionClassification::Medium
            } else {
                RegionClassification::Far
            };
            
            // Update or create the region info
            let region_info = known_regions.entry(region_name.clone()).or_insert_with(|| {
                RegionInfo {
                    name: region_name.clone(),
                    peers: 0,
                    validators: 0,
                    average_latency_ms: 0,
                    classification: RegionClassification::Unknown,
                }
            });
            
            region_info.peers = region_peers.len();
            region_info.validators = validator_count;
            region_info.average_latency_ms = avg_latency;
            region_info.classification = classification;
        }
        
        // Update the topology with the new region information
        let mut topology = self.topology.write().await;
        topology.regions = known_regions.values().cloned().collect();
        topology.last_updated = std::time::SystemTime::now();
        
        Ok(())
    }
    
    /// Gets the cached latency to a peer
    fn get_peer_latency(&self, peer_id: &[u8]) -> Option<u64> {
        self.latency_cache.get(peer_id).map(|l| l.avg_latency_ms)
    }
    
    /// Optimizes the network topology
    async fn optimize_topology(&self) -> Result<()> {
        // Update last optimization time
        let mut last_opt = self.last_optimization.write().await;
        *last_opt = Instant::now();
        
        // Only optimize if we have a peer manager
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return Ok(()),
        };
        
        // Get current peers
        let peers = peer_manager.get_peers().await;
        
        // Count peers by region
        let mut peers_by_region: HashMap<String, Vec<PeerInfo>> = HashMap::new();
        
        for peer in peers {
            let region = peer.region.clone().unwrap_or_else(|| "unknown".to_string());
            peers_by_region.entry(region).or_default().push(peer);
        }
        
        // Determine which regions need more connections
        let known_regions = self.known_regions.read().await;
        let mut connection_targets: HashMap<String, usize> = HashMap::new();
        
        // Calculate ideal connections per region based on classification
        let mut total_connections = 0;
        
        for (region, _) in &peers_by_region {
            if let Some(region_info) = known_regions.get(region) {
                let target_connections = match region_info.classification {
                    RegionClassification::Local => 2, // Local region needs fewer connections
                    RegionClassification::Near => 4,  // Near regions get more connections
                    RegionClassification::Medium => 3, // Medium regions get moderate connections
                    RegionClassification::Far => 1,   // Far regions get fewer connections
                    RegionClassification::Unknown => 1, // Unknown regions get minimal connections
                };
                
                connection_targets.insert(region.clone(), target_connections);
                total_connections += target_connections;
            }
        }
        
        // Adjust targets to fit within max peers limit
        if total_connections > self.config.max_peers {
            let scale_factor = self.config.max_peers as f64 / total_connections as f64;
            
            for (_, target) in connection_targets.iter_mut() {
                *target = (*target as f64 * scale_factor).max(1.0) as usize;
            }
        }
        
        // Perform connection optimization
        for (region, target) in connection_targets {
            let current = peers_by_region.get(&region).map_or(0, |p| p.len());
            
            if current < target {
                // Need more connections to this region
                self.add_connections_to_region(&region, target - current).await?;
            } else if current > target {
                // Need fewer connections to this region
                self.remove_connections_from_region(&region, current - target).await?;
            }
        }
        
        Ok(())
    }
    
    /// Adds connections to a specific region
    async fn add_connections_to_region(&self, region: &str, count: usize) -> Result<()> {
        // Only proceed if we have a peer manager
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return Ok(()),
        };
        
        // Get candidate peers from this region
        let candidates = peer_manager.get_candidate_peers_by_region(region).await;
        
        // Try to connect to the specified number of candidates
        let mut connected = 0;
        
        for candidate in candidates {
            if connected >= count {
                break;
            }
            
            if let Err(e) = peer_manager.connect(candidate.address.clone()).await {
                tracing::warn!("Failed to connect to candidate peer in region {}: {}", region, e);
                continue;
            }
            
            connected += 1;
        }
        
        if connected < count {
            tracing::debug!("Could only add {} out of {} connections to region {}", connected, count, region);
        }
        
        Ok(())
    }
    
    /// Removes connections from a specific region
    async fn remove_connections_from_region(&self, region: &str, count: usize) -> Result<()> {
        // Only proceed if we have a peer manager
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return Ok(()),
        };
        
        // Get current peers from this region
        let peers = peer_manager.get_peers_by_region(region).await;
        
        // Sort peers by priority (keep validators and good latency)
        let mut sorted_peers = peers.clone();
        sorted_peers.sort_by(|a, b| {
            // Prioritize keeping validators
            if a.is_validator && !b.is_validator {
                return Ordering::Greater;
            }
            if !a.is_validator && b.is_validator {
                return Ordering::Less;
            }
            
            // Then prioritize by latency
            let a_latency = self.get_peer_latency(&a.id).unwrap_or(u64::MAX);
            let b_latency = self.get_peer_latency(&b.id).unwrap_or(u64::MAX);
            
            a_latency.cmp(&b_latency)
        });
        
        // Disconnect from the lowest priority peers
        let to_disconnect = sorted_peers.iter().take(count);
        
        for peer in to_disconnect {
            if let Err(e) = peer_manager.disconnect(&peer.id).await {
                tracing::warn!("Failed to disconnect from peer in region {}: {}", region, e);
            }
        }
        
        Ok(())
    }
    
    /// Gets the current network topology
    pub async fn get_topology(&self) -> NetworkTopology {
        self.topology.read().await.clone()
    }
    
    /// Gets the list of connected regions
    pub async fn get_connected_regions(&self) -> Vec<String> {
        let known_regions = self.known_regions.read().await;
        known_regions.keys().cloned().collect()
    }
    
    /// Gets the local region
    pub async fn get_local_region(&self) -> Option<String> {
        let local = self.local_region.read().await;
        local.clone()
    }
    
    /// Finds the optimal validators for a specific security level
    pub async fn find_optimal_validators(
        &self,
        security_level: crate::core::transaction::SecurityLevel,
        validator_count: usize,
    ) -> Vec<Vec<u8>> {
        // Only proceed if we have a peer manager
        let peer_manager_guard = self.peer_manager.read().await;
        let peer_manager = match peer_manager_guard.as_ref() {
            Some(pm) => pm,
            None => return Vec::new(),
        };
        
        // Get all validator peers
        let all_validators = peer_manager.get_validator_peers().await;
        
        // If we don't have enough validators, return all of them
        if all_validators.len() <= validator_count {
            return all_validators.iter().map(|p| p.id.clone()).collect();
        }
        
        // Get known regions
        let known_regions = self.known_regions.read().await;
        
        // Group validators by region
        let mut validators_by_region: HashMap<String, Vec<PeerInfo>> = HashMap::new();
        
        for validator in all_validators {
            let region = validator.region.clone().unwrap_or_else(|| "unknown".to_string());
            validators_by_region.entry(region).or_default().push(validator);
        }
        
        // Create a distribution of validators based on security level
        let mut selected_validators = Vec::new();
        
        match security_level {
            crate::core::transaction::SecurityLevel::Minimal => {
                // For minimal security, just pick the closest validator
                let mut sorted_validators: Vec<_> = all_validators.into_iter().collect();
                sorted_validators.sort_by(|a, b| {
                    let a_latency = self.get_peer_latency(&a.id).unwrap_or(u64::MAX);
                    let b_latency = self.get_peer_latency(&b.id).unwrap_or(u64::MAX);
                    a_latency.cmp(&b_latency)
                });
                
                if let Some(validator) = sorted_validators.first() {
                    selected_validators.push(validator.id.clone());
                }
            },
            crate::core::transaction::SecurityLevel::Basic => {
                // For basic security, pick validators with good latency from different regions
                let distribution = self.create_region_distribution(validators_by_region, validator_count, &known_regions);
                selected_validators = self.select_validators_from_distribution(distribution);
            },
            crate::core::transaction::SecurityLevel::Strong => {
                // For strong security, ensure we have validators from most regions
                let distribution = self.create_region_distribution(validators_by_region, validator_count, &known_regions);
                selected_validators = self.select_validators_from_distribution(distribution);
            },
            crate::core::transaction::SecurityLevel::Full => {
                // For full security, we need a broad distribution of validators
                // Try to include validators from all regions
                let distribution = self.create_region_distribution(validators_by_region, validator_count, &known_regions);
                selected_validators = self.select_validators_from_distribution(distribution);
            },
        }
        
        selected_validators
    }
    
    /// Creates a distribution of validators by region
    fn create_region_distribution(
        &self,
        validators_by_region: HashMap<String, Vec<PeerInfo>>,
        total_count: usize,
        known_regions: &HashMap<String, RegionInfo>,
    ) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        
        // Calculate distribution weights based on region classification
        let mut total_weight = 0.0;
        let mut region_weights = HashMap::new();
        
        for (region, validators) in &validators_by_region {
            let weight = match known_regions.get(region).map(|r| r.classification) {
                Some(RegionClassification::Local) => 1.0,
                Some(RegionClassification::Near) => 2.0,
                Some(RegionClassification::Medium) => 1.5,
                Some(RegionClassification::Far) => 0.5,
                Some(RegionClassification::Unknown) | None => 0.3,
            };
            
            // Adjust weight by number of validators in region
            let adjusted_weight = weight * (validators.len() as f64).sqrt();
            region_weights.insert(region.clone(), adjusted_weight);
            total_weight += adjusted_weight;
        }
        
        // Calculate distribution
        let mut remaining = total_count;
        
        for (region, validators) in &validators_by_region {
            if remaining == 0 {
                break;
            }
            
            let weight = region_weights.get(region).unwrap_or(&0.0);
            let share = ((*weight / total_weight) * total_count as f64).round() as usize;
            let count = share.min(validators.len()).min(remaining);
            
            if count > 0 {
                distribution.insert(region.clone(), count);
                remaining -= count;
            }
        }
        
        // If we still have remaining slots, assign them to regions with more validators
        if remaining > 0 {
            let mut regions: Vec<_> = validators_by_region.iter().collect();
            regions.sort_by(|(_, a), (_, b)| b.len().cmp(&a.len()));
            
            for (region, validators) in regions {
                if remaining == 0 {
                    break;
                }
                
                let current = distribution.get(region).cloned().unwrap_or(0);
                let available = validators.len() - current;
                let to_add = remaining.min(available);
                
                if to_add > 0 {
                    *distribution.entry(region.clone()).or_insert(0) += to_add;
                    remaining -= to_add;
                }
            }
        }
        
        distribution
    }
    
    /// Selects validators from a distribution
    fn select_validators_from_distribution(
        &self,
        distribution: HashMap<String, usize>,
    ) -> Vec<Vec<u8>> {
        let mut selected = Vec::new();
        
        // Only proceed if we have a peer manager
        let peer_manager_guard = self.peer_manager.try_read();
        let peer_manager = match peer_manager_guard {
            Ok(guard) => match guard.as_ref() {
                Some(pm) => pm,
                None => return selected,
            },
            Err(_) => return selected,
        };
        
        // Get validators by region
        for (region, count) in distribution {
            let validators = match peer_manager.get_validators_by_region(&region) {
                Ok(v) => v,
                Err(_) => continue,
            };
            
            // Sort by latency
            let mut sorted: Vec<_> = validators.into_iter().collect();
            sorted.sort_by(|a, b| {
                let a_latency = self.get_peer_latency(&a.id).unwrap_or(u64::MAX);
                let b_latency = self.get_peer_latency(&b.id).unwrap_or(u64::MAX);
                a_latency.cmp(&b_latency)
            });
            
            // Select the best validators
            for validator in sorted.iter().take(count) {
                selected.push(validator.id.clone());
            }
        }
        
        selected
    }
}

impl Clone for TopologyManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            topology: RwLock::new(self.topology.try_read().unwrap_or_default().clone()),
            tasks: Mutex::new(Vec::new()),
            last_optimization: RwLock::new(*self.last_optimization.try_read().unwrap_or(&Instant::now())),
            running: RwLock::new(*self.running.try_read().unwrap_or(&false)),
            peer_manager: RwLock::new(None),
            latency_cache: DashMap::new(),
            known_regions: RwLock::new(self.known_regions.try_read().unwrap_or_default().clone()),
            local_region: RwLock::new(self.local_region.try_read().unwrap_or_default().clone()),
            metrics: self.metrics.clone(),
        }
    }
}

/// Network topology information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkTopology {
    /// Node ID (public key)
    pub node_id: Vec<u8>,
    
    /// Regions in the network
    pub regions: Vec<RegionInfo>,
    
    /// Last time the topology was updated
    pub last_updated: std::time::SystemTime,
}

/// Information about a network region
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegionInfo {
    /// Region name
    pub name: String,
    
    /// Number of peers in this region
    pub peers: usize,
    
    /// Number of validators in this region
    pub validators: usize,
    
    /// Average latency to this region in milliseconds
    pub average_latency_ms: u64,
    
    /// Classification of this region
    pub classification: RegionClassification,
}

/// Region classification for topology optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionClassification {
    /// Local region (where this node is located)
    Local,
    
    /// Near region (low latency)
    Near,
    
    /// Medium region (moderate latency)
    Medium,
    
    /// Far region (high latency)
    Far,
    
    /// Unknown region (not enough information)
    Unknown,
}

/// Latency information for a peer
#[derive(Debug, Clone)]
struct LatencyInfo {
    /// Peer ID
    peer_id: Vec<u8>,
    
    /// Minimum latency in milliseconds
    min_latency_ms: u64,
    
    /// Maximum latency in milliseconds
    max_latency_ms: u64,
    
    /// Average latency in milliseconds
    avg_latency_ms: u64,
    
    /// Number of measurements
    measurements: u64,
    
    /// Last time this information was updated
    last_updated: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkConfig, DiscoveryConfig};
    
    // Helper to create a test network config
    fn create_test_config() -> Arc<NetworkConfig> {
        Arc::new(NetworkConfig {
            listen_addr: "127.0.0.1".to_string(),
            p2p_port: 7777,
            enable_upnp: false,
            bootstrap_nodes: Vec::new(),
            max_peers: 10,
            target_outbound_peers: 3,
            connection_timeout_secs: 5,
            discovery: DiscoveryConfig {
                enabled: true,
                method: "kademlia".to_string(),
                interval_secs: 60,
                max_discovered_peers: 100,
                prefer_validators: true,
            },
            topology_optimization: true,
            topology_optimization_interval_secs: 300,
            enable_rdma_transport: false, // Disable for tests
            rdma_port: Some(7778),
            rdma_buffer_size: 8192,
            enable_erasure_coding: true,
            erasure_coding_shard_count: 10,
            erasure_coding_total_count: 16,
            node_key_path: None,
            is_validator: false,
        })
    }
    
    #[tokio::test]
    async fn test_topology_manager_creation() {
        let config = create_test_config();
        let node_id = vec![1, 2, 3, 4];
        
        let result = TopologyManager::new(config, node_id);
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_region_distribution() {
        let config = create_test_config();
        let node_id = vec![1, 2, 3, 4];
        
        let manager = TopologyManager::new(config, node_id).unwrap();
        
        // Create mock validators by region
        let mut validators_by_region = HashMap::new();
        validators_by_region.insert("region1".to_string(), vec![
            PeerInfo { id: vec![1], address: "127.0.0.1:7001".parse().unwrap(), ..Default::default() },
            PeerInfo { id: vec![2], address: "127.0.0.1:7002".parse().unwrap(), ..Default::default() },
        ]);
        validators_by_region.insert("region2".to_string(), vec![
            PeerInfo { id: vec![3], address: "127.0.0.1:7003".parse().unwrap(), ..Default::default() },
            PeerInfo { id: vec![4], address: "127.0.0.1:7004".parse().unwrap(), ..Default::default() },
            PeerInfo { id: vec![5], address: "127.0.0.1:7005".parse().unwrap(), ..Default::default() },
        ]);
        validators_by_region.insert("region3".to_string(), vec![
            PeerInfo { id: vec![6], address: "127.0.0.1:7006".parse().unwrap(), ..Default::default() },
        ]);
        
        // Create known regions
        let mut known_regions = HashMap::new();
        known_regions.insert("region1".to_string(), RegionInfo {
            name: "region1".to_string(),
            peers: 2,
            validators: 2,
            average_latency_ms: 20,
            classification: RegionClassification::Near,
        });
        known_regions.insert("region2".to_string(), RegionInfo {
            name: "region2".to_string(),
            peers: 3,
            validators: 3,
            average_latency_ms: 100,
            classification: RegionClassification::Medium,
        });
        known_regions.insert("region3".to_string(), RegionInfo {
            name: "region3".to_string(),
            peers: 1,
            validators: 1,
            average_latency_ms: 200,
            classification: RegionClassification::Far,
        });
        
        // Test distribution with different total counts
        let distribution1 = manager.create_region_distribution(validators_by_region.clone(), 3, &known_regions);
        assert_eq!(distribution1.values().sum::<usize>(), 3);
        
        let distribution2 = manager.create_region_distribution(validators_by_region.clone(), 6, &known_regions);
        assert_eq!(distribution2.values().sum::<usize>(), 6);
    }
}
