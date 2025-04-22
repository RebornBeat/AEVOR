use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::config::NetworkConfig;
use crate::core::Blockchain;
use crate::consensus::Manager as ConsensusManager;
use crate::error::{AevorError, Result};

mod discovery;
mod erasure_coding;
mod peer;
mod protocol;
mod rdma;
mod sync;
mod topology;

pub use discovery::{DiscoveryService, NodeAddress, NodeCapability};
pub use erasure_coding::{ErasureCoding, DataFragment, ParityFragment};
pub use peer::{Peer, PeerInfo, PeerState, PeerManager};
pub use protocol::{Message, MessageType, Protocol, ProtocolHandler, ProtocolVersion};
pub use rdma::{RdmaConfig, RdmaConnection, RdmaEndpoint, RdmaTransport};
pub use sync::{SyncManager, SyncState, SyncRequest, SyncResponse};
pub use topology::{NetworkTopology, RegionClassification, RegionInfo, TopologyManager};

/// Network manager responsible for P2P communication
pub struct Manager {
    /// Network configuration
    config: Arc<NetworkConfig>,
    
    /// Reference to the blockchain
    blockchain: Arc<Blockchain>,
    
    /// Reference to the consensus manager
    consensus: Arc<ConsensusManager>,
    
    /// Peer manager for handling connections
    peer_manager: Option<Arc<PeerManager>>,
    
    /// Discovery service for finding peers
    discovery_service: Option<Arc<DiscoveryService>>,
    
    /// Sync manager for blockchain synchronization
    sync_manager: Option<Arc<SyncManager>>,
    
    /// Topology manager for network optimizations
    topology_manager: Option<Arc<TopologyManager>>,
    
    /// RDMA transport for high-performance communication
    rdma_transport: Option<Arc<RdmaTransport>>,
    
    /// Erasure coding for data availability
    erasure_coding: Option<Arc<ErasureCoding>>,
    
    /// Node ID (public key)
    node_id: Vec<u8>,
    
    /// Whether the node is a validator
    is_validator: bool,
    
    /// Protocol version
    protocol_version: ProtocolVersion,
    
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl Manager {
    /// Creates a new network manager
    pub fn new(
        config: Arc<NetworkConfig>,
        blockchain: Arc<Blockchain>,
        consensus: Arc<ConsensusManager>,
    ) -> Result<Self> {
        // Generate or load the node ID
        let node_id = generate_node_id(&config)?;
        
        Ok(Self {
            config,
            blockchain,
            consensus,
            peer_manager: None,
            discovery_service: None,
            sync_manager: None,
            topology_manager: None,
            rdma_transport: None,
            erasure_coding: None,
            node_id,
            is_validator: false, // Will be set during start
            protocol_version: ProtocolVersion::V1,
            running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Starts the network manager and its components
    pub async fn start(&mut self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(()); // Already running
        }
        
        // Set whether this node is a validator
        self.is_validator = self.config.is_validator;
        
        // Initialize the topology manager
        let topology_manager = TopologyManager::new(self.config.clone(), self.node_id.clone())?;
        let topology_manager = Arc::new(topology_manager);
        self.topology_manager = Some(topology_manager.clone());
        
        // Initialize the peer manager
        let peer_manager = PeerManager::new(
            self.config.clone(),
            self.node_id.clone(),
            self.protocol_version,
            self.is_validator,
        )?;
        let peer_manager = Arc::new(peer_manager);
        self.peer_manager = Some(peer_manager.clone());
        
        // Initialize the discovery service
        let discovery_service = DiscoveryService::new(
            self.config.clone(),
            self.node_id.clone(),
            self.is_validator,
            peer_manager.clone(),
        )?;
        let discovery_service = Arc::new(discovery_service);
        self.discovery_service = Some(discovery_service.clone());
        
        // Initialize the RDMA transport if enabled
        if self.config.enable_rdma_transport {
            let rdma_config = RdmaConfig {
                listen_addr: self.config.listen_addr.clone(),
                port: self.config.rdma_port.unwrap_or(self.config.p2p_port + 1),
                max_connections: self.config.max_peers,
                buffer_size: self.config.rdma_buffer_size,
                timeout: Duration::from_secs(self.config.connection_timeout_secs),
            };
            
            let rdma_transport = RdmaTransport::new(rdma_config, topology_manager.clone())?;
            let rdma_transport = Arc::new(rdma_transport);
            self.rdma_transport = Some(rdma_transport.clone());
        }
        
        // Initialize the erasure coding if enabled
        if self.config.enable_erasure_coding {
            let erasure_coding = ErasureCoding::new(
                self.config.erasure_coding_shard_count,
                self.config.erasure_coding_total_count,
            )?;
            let erasure_coding = Arc::new(erasure_coding);
            self.erasure_coding = Some(erasure_coding.clone());
        }
        
        // Initialize the sync manager
        let sync_manager = SyncManager::new(
            self.config.clone(),
            self.blockchain.clone(),
            peer_manager.clone(),
            topology_manager.clone(),
        )?;
        let sync_manager = Arc::new(sync_manager);
        self.sync_manager = Some(sync_manager.clone());
        
        // Start all components
        if let Some(rdma) = &self.rdma_transport {
            rdma.start().await?;
        }
        
        discovery_service.start().await?;
        topology_manager.start().await?;
        peer_manager.start().await?;
        sync_manager.start().await?;
        
        // Connect to bootstrap nodes
        self.connect_to_bootstrap_nodes().await?;
        
        *running = true;
        Ok(())
    }
    
    /// Stops the network manager and its components
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(()); // Not running
        }
        
        // Stop all components in reverse order
        if let Some(sync_manager) = &self.sync_manager {
            sync_manager.stop().await?;
        }
        
        if let Some(peer_manager) = &self.peer_manager {
            peer_manager.stop().await?;
        }
        
        if let Some(topology_manager) = &self.topology_manager {
            topology_manager.stop().await?;
        }
        
        if let Some(discovery_service) = &self.discovery_service {
            discovery_service.stop().await?;
        }
        
        if let Some(rdma) = &self.rdma_transport {
            rdma.stop().await?;
        }
        
        *running = false;
        Ok(())
    }
    
    /// Connects to the bootstrap nodes specified in the configuration
    async fn connect_to_bootstrap_nodes(&self) -> Result<()> {
        if let Some(peer_manager) = &self.peer_manager {
            for addr in &self.config.bootstrap_nodes {
                // Try to connect to each bootstrap node
                if let Err(e) = peer_manager.connect(addr.clone()).await {
                    tracing::warn!("Failed to connect to bootstrap node {}: {}", addr, e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Broadcasts a message to all connected peers
    pub async fn broadcast(&self, message: Message) -> Result<()> {
        if let Some(peer_manager) = &self.peer_manager {
            peer_manager.broadcast(message).await?;
        }
        
        Ok(())
    }
    
    /// Sends a message to a specific peer
    pub async fn send_to_peer(&self, peer_id: &[u8], message: Message) -> Result<()> {
        if let Some(peer_manager) = &self.peer_manager {
            peer_manager.send_to_peer(peer_id, message).await?;
        }
        
        Ok(())
    }
    
    /// Gets the number of connected peers
    pub async fn peer_count(&self) -> usize {
        if let Some(peer_manager) = &self.peer_manager {
            peer_manager.peer_count().await
        } else {
            0
        }
    }
    
    /// Gets information about all connected peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        if let Some(peer_manager) = &self.peer_manager {
            peer_manager.get_peers().await
        } else {
            Vec::new()
        }
    }
    
    /// Gets the network topology information
    pub async fn get_network_topology(&self) -> Option<NetworkTopology> {
        if let Some(topology_manager) = &self.topology_manager {
            Some(topology_manager.get_topology().await)
        } else {
            None
        }
    }
    
    /// Gets the sync manager
    pub fn sync_manager(&self) -> Option<Arc<SyncManager>> {
        self.sync_manager.clone()
    }
    
    /// Gets the peer manager
    pub fn peer_manager(&self) -> Option<Arc<PeerManager>> {
        self.peer_manager.clone()
    }
    
    /// Gets the discovery service
    pub fn discovery_service(&self) -> Option<Arc<DiscoveryService>> {
        self.discovery_service.clone()
    }
    
    /// Gets the topology manager
    pub fn topology_manager(&self) -> Option<Arc<TopologyManager>> {
        self.topology_manager.clone()
    }
    
    /// Gets the RDMA transport
    pub fn rdma_transport(&self) -> Option<Arc<RdmaTransport>> {
        self.rdma_transport.clone()
    }
    
    /// Gets the erasure coding
    pub fn erasure_coding(&self) -> Option<Arc<ErasureCoding>> {
        self.erasure_coding.clone()
    }
    
    /// Gets the node ID
    pub fn node_id(&self) -> &[u8] {
        &self.node_id
    }
    
    /// Checks if this node is a validator
    pub fn is_validator(&self) -> bool {
        self.is_validator
    }
    
    /// Gets the protocol version
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
    
    /// Gets information about the network status
    pub async fn get_network_status(&self) -> NetworkStatus {
        let peer_count = self.peer_count().await;
        let connected_regions = if let Some(topology) = &self.topology_manager {
            topology.get_connected_regions().await.len()
        } else {
            0
        };
        
        let sync_status = if let Some(sync) = &self.sync_manager {
            sync.get_state().await
        } else {
            SyncState::Idle
        };
        
        let inbound_bandwidth = 0; // TODO: Implement bandwidth tracking
        let outbound_bandwidth = 0; // TODO: Implement bandwidth tracking
        
        NetworkStatus {
            peer_count,
            connected_regions,
            sync_status,
            inbound_bandwidth,
            outbound_bandwidth,
            is_validator: self.is_validator,
            protocol_version: self.protocol_version,
        }
    }
}

/// Network status information
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    /// Number of connected peers
    pub peer_count: usize,
    
    /// Number of connected regions
    pub connected_regions: usize,
    
    /// Sync state
    pub sync_status: SyncState,
    
    /// Inbound bandwidth in bytes per second
    pub inbound_bandwidth: u64,
    
    /// Outbound bandwidth in bytes per second
    pub outbound_bandwidth: u64,
    
    /// Whether this node is a validator
    pub is_validator: bool,
    
    /// Protocol version
    pub protocol_version: ProtocolVersion,
}

/// Generates a node ID from the configuration
fn generate_node_id(config: &NetworkConfig) -> Result<Vec<u8>> {
    // If a node key file is specified, load it
    if let Some(ref key_path) = config.node_key_path {
        if std::path::Path::new(key_path).exists() {
            let key_data = std::fs::read(key_path)
                .map_err(|e| AevorError::io(format!("Failed to read node key file: {}", e)))?;
            
            return Ok(key_data);
        }
    }
    
    // Generate a new node ID (public key)
    let key_pair = crate::crypto::signature::KeyPair::generate(
        crate::crypto::signature::SignatureAlgorithm::ED25519,
    )
    .map_err(|e| AevorError::crypto("Key generation failed".into(), e.to_string(), None))?;
    
    // Save the private key if a key path is specified
    if let Some(ref key_path) = config.node_key_path {
        if let Some(parent) = std::path::Path::new(key_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AevorError::io(format!("Failed to create directory for node key: {}", e)))?;
        }
        
        std::fs::write(key_path, &key_pair.private_key)
            .map_err(|e| AevorError::io(format!("Failed to write node key: {}", e)))?;
    }
    
    Ok(key_pair.public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkConfig, DiscoveryConfig};
    use std::net::SocketAddr;
    use std::str::FromStr;
    
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
    async fn test_manager_creation() {
        // This is a simple test for creating a network manager
        // Full networking tests would require mock components
        
        // TODO: Replace these with proper mocks
        let blockchain = Arc::new(Blockchain::default());
        let consensus = Arc::new(ConsensusManager::default());
        
        let config = create_test_config();
        let result = Manager::new(config, blockchain, consensus);
        
        assert!(result.is_ok());
    }
}
