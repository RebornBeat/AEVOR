use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::config::NetworkConfig;
use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::crypto::signature::{Signature, SignatureAlgorithm};
use crate::error::{AevorError, Result};
use crate::networking::peer::PeerManager;

/// Represents the address information of a node in the network
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeAddress {
    /// Node ID derived from public key
    pub id: Vec<u8>,
    
    /// Node's socket address (IP:Port)
    pub address: SocketAddr,
    
    /// Advertised port for P2P communication
    pub p2p_port: u16,
    
    /// RDMA port if available
    pub rdma_port: Option<u16>,
    
    /// Last seen timestamp (milliseconds since epoch)
    pub last_seen: u64,
    
    /// Whether the node is a validator
    pub is_validator: bool,
    
    /// Node's capabilities
    pub capabilities: Vec<NodeCapability>,
    
    /// Node's region if known
    pub region: Option<String>,
    
    /// Node's latency from our perspective (ms)
    pub latency: Option<u32>,
    
    /// User agent string
    pub user_agent: String,
}

impl NodeAddress {
    /// Creates a new node address
    pub fn new(
        id: Vec<u8>,
        address: SocketAddr,
        p2p_port: u16,
        is_validator: bool,
    ) -> Self {
        Self {
            id,
            address,
            p2p_port,
            rdma_port: None,
            last_seen: chrono::Utc::now().timestamp_millis() as u64,
            is_validator,
            capabilities: Vec::new(),
            region: None,
            latency: None,
            user_agent: format!("aevor/v1.0.0"),
        }
    }
    
    /// Creates a new node address with all fields
    pub fn with_details(
        id: Vec<u8>,
        address: SocketAddr,
        p2p_port: u16,
        rdma_port: Option<u16>,
        last_seen: u64,
        is_validator: bool,
        capabilities: Vec<NodeCapability>,
        region: Option<String>,
        latency: Option<u32>,
        user_agent: String,
    ) -> Self {
        Self {
            id,
            address,
            p2p_port,
            rdma_port,
            last_seen,
            is_validator,
            capabilities,
            region,
            latency,
            user_agent,
        }
    }
    
    /// Gets the socket address for P2P communication
    pub fn p2p_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address.ip(), self.p2p_port)
    }
    
    /// Gets the socket address for RDMA communication if available
    pub fn rdma_addr(&self) -> Option<SocketAddr> {
        self.rdma_port.map(|port| SocketAddr::new(self.address.ip(), port))
    }
    
    /// Updates the last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Checks if the node is online based on last seen timestamp
    pub fn is_online(&self, max_age_secs: u64) -> bool {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let age = now.saturating_sub(self.last_seen);
        
        age < (max_age_secs * 1000)
    }
    
    /// Adds a capability if it doesn't already exist
    pub fn add_capability(&mut self, capability: NodeCapability) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
    }
    
    /// Checks if the node has a specific capability
    pub fn has_capability(&self, capability: &NodeCapability) -> bool {
        self.capabilities.contains(capability)
    }
    
    /// Sets the region
    pub fn set_region(&mut self, region: String) {
        self.region = Some(region);
    }
    
    /// Updates the latency
    pub fn update_latency(&mut self, latency: u32) {
        self.latency = Some(latency);
    }
}

impl fmt::Debug for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeAddress")
            .field("id", &hex::encode(&self.id))
            .field("address", &self.address)
            .field("p2p_port", &self.p2p_port)
            .field("rdma_port", &self.rdma_port)
            .field("last_seen", &self.last_seen)
            .field("is_validator", &self.is_validator)
            .field("capabilities", &self.capabilities)
            .field("region", &self.region)
            .field("latency", &self.latency)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Hashable for NodeAddress {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
        let mut hasher = CryptoHash::new_hasher(algorithm);
        hasher.update(&self.id);
        hasher.update(self.address.to_string().as_bytes());
        hasher.update(&self.p2p_port.to_le_bytes());
        if let Some(rdma_port) = self.rdma_port {
            hasher.update(&rdma_port.to_le_bytes());
        }
        CryptoHash::new(algorithm, hasher.finalize())
    }
}

/// Represents a capability of a node in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeCapability {
    /// Full node capability
    FullNode,
    
    /// Validator node capability
    Validator,
    
    /// Light client capability
    LightClient,
    
    /// Bootstrap node capability
    Bootstrap,
    
    /// RPC service capability
    RpcService,
    
    /// WebSocket service capability
    WebSocketService,
    
    /// Explorer service capability
    ExplorerService,
    
    /// RDMA transport capability
    RdmaTransport,
    
    /// Custom capability
    Custom(String),
}

impl fmt::Display for NodeCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeCapability::FullNode => write!(f, "FullNode"),
            NodeCapability::Validator => write!(f, "Validator"),
            NodeCapability::LightClient => write!(f, "LightClient"),
            NodeCapability::Bootstrap => write!(f, "Bootstrap"),
            NodeCapability::RpcService => write!(f, "RpcService"),
            NodeCapability::WebSocketService => write!(f, "WebSocketService"),
            NodeCapability::ExplorerService => write!(f, "ExplorerService"),
            NodeCapability::RdmaTransport => write!(f, "RdmaTransport"),
            NodeCapability::Custom(s) => write!(f, "Custom({})", s),
        }
    }
}

/// Types of messages used in the discovery protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMessageType {
    /// Ping message to check if a node is alive
    Ping,
    
    /// Pong response to a ping message
    Pong,
    
    /// Request to find nodes near a target ID
    FindNodes,
    
    /// Response to a FindNodes request
    Nodes,
    
    /// Announce presence on the network
    Announce,
    
    /// Request for detailed node information
    NodeInfoRequest,
    
    /// Response with detailed node information
    NodeInfoResponse,
}

/// Discovery protocol message
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    /// Message type
    pub message_type: DiscoveryMessageType,
    
    /// Message sequence number
    pub sequence: u64,
    
    /// Sender node ID
    pub sender_id: Vec<u8>,
    
    /// Sender address information
    pub sender_addr: NodeAddress,
    
    /// Target node ID (for FindNodes)
    pub target_id: Option<Vec<u8>>,
    
    /// List of nodes (for Nodes response)
    pub nodes: Option<Vec<NodeAddress>>,
    
    /// Timestamp of the message
    pub timestamp: u64,
    
    /// TTL (time to live) for message forwarding
    pub ttl: u8,
    
    /// Signature of the message
    pub signature: Option<Signature>,
}

impl DiscoveryMessage {
    /// Creates a new discovery message
    pub fn new(
        message_type: DiscoveryMessageType,
        sequence: u64,
        sender_id: Vec<u8>,
        sender_addr: NodeAddress,
    ) -> Self {
        Self {
            message_type,
            sequence,
            sender_id,
            sender_addr,
            target_id: None,
            nodes: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            ttl: 3, // Default TTL
            signature: None,
        }
    }
    
    /// Creates a ping message
    pub fn ping(sequence: u64, sender_id: Vec<u8>, sender_addr: NodeAddress) -> Self {
        Self::new(
            DiscoveryMessageType::Ping,
            sequence,
            sender_id,
            sender_addr,
        )
    }
    
    /// Creates a pong message in response to a ping
    pub fn pong(sequence: u64, sender_id: Vec<u8>, sender_addr: NodeAddress) -> Self {
        Self::new(
            DiscoveryMessageType::Pong,
            sequence,
            sender_id,
            sender_addr,
        )
    }
    
    /// Creates a find nodes message
    pub fn find_nodes(
        sequence: u64,
        sender_id: Vec<u8>,
        sender_addr: NodeAddress,
        target_id: Vec<u8>,
    ) -> Self {
        let mut msg = Self::new(
            DiscoveryMessageType::FindNodes,
            sequence,
            sender_id,
            sender_addr,
        );
        msg.target_id = Some(target_id);
        msg
    }
    
    /// Creates a nodes response message
    pub fn nodes(
        sequence: u64,
        sender_id: Vec<u8>,
        sender_addr: NodeAddress,
        nodes: Vec<NodeAddress>,
    ) -> Self {
        let mut msg = Self::new(
            DiscoveryMessageType::Nodes,
            sequence,
            sender_id,
            sender_addr,
        );
        msg.nodes = Some(nodes);
        msg
    }
    
    /// Creates an announce message
    pub fn announce(sequence: u64, sender_id: Vec<u8>, sender_addr: NodeAddress) -> Self {
        Self::new(
            DiscoveryMessageType::Announce,
            sequence,
            sender_id,
            sender_addr,
        )
    }
    
    /// Signs the message with the provided private key
    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        // Create a signature for the serialized message
        let message_bytes = self.to_bytes_without_signature()?;
        
        let signature = Signature::sign(
            SignatureAlgorithm::ED25519,
            private_key,
            &message_bytes,
        ).map_err(|e| AevorError::crypto(
            "Failed to sign discovery message".into(),
            e.to_string(),
            None,
        ))?;
        
        self.signature = Some(signature);
        Ok(())
    }
    
    /// Verifies the message signature with the provided public key
    pub fn verify(&self, public_key: &[u8]) -> Result<bool> {
        let signature = match &self.signature {
            Some(sig) => sig,
            None => return Ok(false),
        };
        
        let message_bytes = self.to_bytes_without_signature()?;
        
        signature.verify(public_key, &message_bytes)
            .map_err(|e| AevorError::crypto(
                "Failed to verify discovery message signature".into(),
                e.to_string(),
                None,
            ))
    }
    
    /// Serializes the message without the signature for signing
    fn to_bytes_without_signature(&self) -> Result<Vec<u8>> {
        // Create a temporary copy without the signature
        let mut msg = self.clone();
        msg.signature = None;
        
        bincode::serialize(&msg)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize discovery message: {}", e)))
    }
    
    /// Serializes the message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize discovery message: {}", e)))
    }
    
    /// Deserializes a message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize discovery message: {}", e)))
    }
    
    /// Checks if the message is expired
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let age = now.saturating_sub(self.timestamp);
        
        age > (max_age_secs * 1000)
    }
    
    /// Decrements the TTL
    pub fn decrement_ttl(&mut self) {
        if self.ttl > 0 {
            self.ttl -= 1;
        }
    }
    
    /// Checks if the TTL is expired
    pub fn is_ttl_expired(&self) -> bool {
        self.ttl == 0
    }
}

impl fmt::Debug for DiscoveryMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryMessage")
            .field("message_type", &self.message_type)
            .field("sequence", &self.sequence)
            .field("sender_id", &hex::encode(&self.sender_id))
            .field("target_id", &self.target_id.as_ref().map(hex::encode))
            .field("nodes_count", &self.nodes.as_ref().map(|n| n.len()))
            .field("timestamp", &self.timestamp)
            .field("ttl", &self.ttl)
            .field("has_signature", &self.signature.is_some())
            .finish()
    }
}

/// Configuration for the discovery service
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// UDP socket address for discovery
    pub bind_addr: SocketAddr,
    
    /// Maximum number of nodes to store
    pub max_nodes: usize,
    
    /// Discovery interval in seconds
    pub discovery_interval_secs: u64,
    
    /// Ping interval in seconds
    pub ping_interval_secs: u64,
    
    /// Timeout for messages in seconds
    pub message_timeout_secs: u64,
    
    /// Maximum age of nodes before they're considered stale
    pub max_node_age_secs: u64,
    
    /// Whether to only store verified nodes
    pub verified_nodes_only: bool,
    
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    
    /// Buffer size for UDP messages
    pub udp_buffer_size: usize,
    
    /// Whether to prefer validator nodes
    pub prefer_validators: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:7770".parse().unwrap(),
            max_nodes: 1000,
            discovery_interval_secs: 60,
            ping_interval_secs: 30,
            message_timeout_secs: 10,
            max_node_age_secs: 3600, // 1 hour
            verified_nodes_only: true,
            bootstrap_nodes: Vec::new(),
            udp_buffer_size: 65536,
            prefer_validators: true,
        }
    }
}

/// Commands for the discovery service
#[derive(Debug)]
pub enum DiscoveryCommand {
    /// Add a node to the known nodes list
    AddNode(NodeAddress, oneshot::Sender<Result<()>>),
    
    /// Remove a node from the known nodes list
    RemoveNode(Vec<u8>, oneshot::Sender<Result<()>>),
    
    /// Get all nodes matching certain criteria
    GetNodes(NodeQueryCriteria, oneshot::Sender<Result<Vec<NodeAddress>>>),
    
    /// Ping a specific node
    Ping(SocketAddr, oneshot::Sender<Result<bool>>),
    
    /// Find nodes near a target ID
    FindNodes(Vec<u8>, oneshot::Sender<Result<Vec<NodeAddress>>>),
    
    /// Request detailed information about a node
    RequestNodeInfo(Vec<u8>, oneshot::Sender<Result<Option<NodeAddress>>>),
    
    /// Announce this node to the network
    Announce(oneshot::Sender<Result<()>>),
    
    /// Shutdown the discovery service
    Shutdown(oneshot::Sender<Result<()>>),
}

/// Criteria for querying nodes
#[derive(Debug, Clone)]
pub struct NodeQueryCriteria {
    /// Match nodes with these capabilities (empty = any)
    pub capabilities: Option<Vec<NodeCapability>>,
    
    /// Match validator nodes
    pub validators_only: bool,
    
    /// Maximum node age in seconds (0 = any)
    pub max_age_secs: u64,
    
    /// Maximum number of nodes to return (0 = all)
    pub limit: usize,
    
    /// Sort by distance to target ID
    pub target_id: Option<Vec<u8>>,
    
    /// Match nodes in this region (None = any)
    pub region: Option<String>,
    
    /// Match nodes with RDMA capability
    pub has_rdma: bool,
}

impl Default for NodeQueryCriteria {
    fn default() -> Self {
        Self {
            capabilities: None,
            validators_only: false,
            max_age_secs: 0,
            limit: 0,
            target_id: None,
            region: None,
            has_rdma: false,
        }
    }
}

/// Discovery service for finding and tracking network nodes
pub struct DiscoveryService {
    /// Discovery configuration
    config: DiscoveryConfig,
    
    /// UDP socket for discovery protocol
    socket: Arc<UdpSocket>,
    
    /// Known nodes
    known_nodes: Arc<RwLock<HashMap<Vec<u8>, NodeAddress>>>,
    
    /// Recently seen nodes to prevent continuous rediscovery
    recently_seen: Arc<RwLock<HashSet<Vec<u8>>>>,
    
    /// Command sender for the discovery service
    command_sender: mpsc::Sender<DiscoveryCommand>,
    
    /// Command receiver for the discovery service
    command_receiver: Option<mpsc::Receiver<DiscoveryCommand>>,
    
    /// Next sequence number for messages
    next_sequence: Arc<RwLock<u64>>,
    
    /// Background task handles
    tasks: Vec<JoinHandle<()>>,
    
    /// Node ID (public key)
    node_id: Vec<u8>,
    
    /// Private key for signing messages
    private_key: Vec<u8>,
    
    /// Node information
    node_info: NodeAddress,
    
    /// Peer manager for establishing TCP connections
    peer_manager: Option<Arc<PeerManager>>,
    
    /// Last discovery time
    last_discovery: Arc<Mutex<Instant>>,
    
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl DiscoveryService {
    /// Creates a new discovery service
    pub fn new(
        config: Arc<NetworkConfig>,
        node_id: Vec<u8>,
        private_key: Vec<u8>,
        is_validator: bool,
    ) -> Result<Self> {
        // Create UDP socket address
        let udp_port = config.discovery_port.unwrap_or(config.p2p_port - 1);
        let bind_addr = format!("{}:{}", config.listen_addr, udp_port)
            .parse()
            .map_err(|e| AevorError::network(format!("Invalid UDP bind address: {}", e)))?;
        
        // Create discovery configuration
        let discovery_config = DiscoveryConfig {
            bind_addr,
            max_nodes: config.discovery.max_discovered_peers,
            discovery_interval_secs: config.discovery.interval_secs,
            ping_interval_secs: 30,
            message_timeout_secs: 10,
            max_node_age_secs: 3600, // 1 hour
            verified_nodes_only: true,
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            udp_buffer_size: 65536,
            prefer_validators: config.discovery.prefer_validators,
        };
        
        // Set up channels for commands
        let (command_sender, command_receiver) = mpsc::channel(100);
        
        // Create the node info
        let mut capabilities = vec![NodeCapability::FullNode];
        if is_validator {
            capabilities.push(NodeCapability::Validator);
        }
        if config.enable_rdma_transport {
            capabilities.push(NodeCapability::RdmaTransport);
        }
        
        let node_info = NodeAddress::with_details(
            node_id.clone(),
            bind_addr,
            config.p2p_port,
            config.enable_rdma_transport.then(|| config.rdma_port.unwrap_or(config.p2p_port + 1)),
            chrono::Utc::now().timestamp_millis() as u64,
            is_validator,
            capabilities,
            None, // Region will be determined later
            None, // Latency to self is 0, but we leave it as None
            format!("aevor/v1.0.0"),
        );
        
        Ok(Self {
            config: discovery_config,
            socket: Arc::new(tokio::runtime::Handle::current().block_on(async {
                UdpSocket::bind(bind_addr).await
                    .map_err(|e| AevorError::network(format!("Failed to bind UDP socket: {}", e)))
            })?),
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
            recently_seen: Arc::new(RwLock::new(HashSet::new())),
            command_sender,
            command_receiver: Some(command_receiver),
            next_sequence: Arc::new(RwLock::new(0)),
            tasks: Vec::new(),
            node_id,
            private_key,
            node_info,
            peer_manager: None,
            last_discovery: Arc::new(Mutex::new(Instant::now())),
            running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Sets the peer manager
    pub fn set_peer_manager(&mut self, peer_manager: Arc<PeerManager>) {
        self.peer_manager = Some(peer_manager);
    }
    
    /// Sets the node region
    pub fn set_region(&mut self, region: String) {
        self.node_info.region = Some(region);
    }
    
    /// Starts the discovery service
    pub async fn start(&mut self) -> Result<()> {
        let mut running = self.running.write();
        if *running {
            return Ok(());
        }
        
        info!("Starting discovery service on {}", self.config.bind_addr);
        
        // Start the message handler task
        let socket = self.socket.clone();
        let known_nodes = self.known_nodes.clone();
        let recently_seen = self.recently_seen.clone();
        let node_id = self.node_id.clone();
        let private_key = self.private_key.clone();
        let next_sequence = self.next_sequence.clone();
        let node_info = self.node_info.clone();
        let peer_manager = self.peer_manager.clone();
        let config = self.config.clone();
        let cmd_sender = self.command_sender.clone();
        
        let msg_handler = tokio::spawn(async move {
            let mut buf = vec![0u8; config.udp_buffer_size];
            
            loop {
                // Receive a message from the UDP socket
                let (len, src) = match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => (len, src),
                    Err(e) => {
                        error!("Error receiving UDP packet: {}", e);
                        continue;
                    }
                };
                
                // Parse the message
                let message = match DiscoveryMessage::from_bytes(&buf[..len]) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse discovery message: {}", e);
                        continue;
                    }
                };
                
                // Skip our own messages
                if message.sender_id == node_id {
                    continue;
                }
                
                // Check if the message is expired
                if message.is_expired(config.message_timeout_secs) {
                    continue;
                }
                
                // Verify message signature
                if config.verified_nodes_only {
                    match message.verify(&message.sender_id) {
                        Ok(true) => (), // Signature verified
                        Ok(false) => {
                            warn!("Invalid signature for discovery message from {}", hex::encode(&message.sender_id));
                            continue;
                        }
                        Err(e) => {
                            warn!("Error verifying discovery message signature: {}", e);
                            continue;
                        }
                    }
                }
                
                // Update the known nodes list with the sender's address
                let sender_addr = message.sender_addr.clone();
                let sender_id = message.sender_id.clone();
                
                // Add to recently seen set
                {
                    let mut seen = recently_seen.write();
                    seen.insert(sender_id.clone());
                    
                    // Limit the size of the set
                    if seen.len() > config.max_nodes * 2 {
                        // Clear oldest entries
                        *seen = HashSet::new();
                    }
                }
                
                // Update the sender's address with the actual source IP
                let mut updated_addr = sender_addr.clone();
                if updated_addr.address.ip() != src.ip() {
                    updated_addr.address = SocketAddr::new(src.ip(), updated_addr.address.port());
                }
                updated_addr.update_last_seen();
                
                {
                    let mut nodes = known_nodes.write();
                    nodes.insert(sender_id.clone(), updated_addr.clone());
                    
                    // Limit the size of the known nodes
                    if nodes.len() > config.max_nodes {
                        // Remove the oldest nodes
                        let mut nodes_vec: Vec<_> = nodes.iter().collect();
                        nodes_vec.sort_by_key(|(_, node)| node.last_seen);
                        
                        while nodes.len() > config.max_nodes / 2 {
                            if let Some((id, _)) = nodes_vec.first() {
                                nodes.remove(*id);
                                nodes_vec.remove(0);
                            } else {
                                break;
                            }
                        }
                    }
                }
                
                // Process the message based on its type
                match message.message_type {
                    DiscoveryMessageType::Ping => {
                        // Respond with a Pong
                        let mut response = DiscoveryMessage::pong(
                            {
                                let mut seq = next_sequence.write();
                                *seq += 1;
                                *seq
                            },
                            node_id.clone(),
                            node_info.clone(),
                        );
                        
                        if let Err(e) = response.sign(&private_key) {
                            error!("Failed to sign Pong message: {}", e);
                            continue;
                        }
                        
                        if let Err(e) = send_message(&socket, &response, updated_addr.address).await {
                            warn!("Failed to send Pong message: {}", e);
                        }
                    }
                    
                    DiscoveryMessageType::Pong => {
                        // Just update the node info, which we already did
                        trace!("Received Pong from {}", hex::encode(&sender_id));
                    }
                    
                    DiscoveryMessageType::FindNodes => {
                        if let Some(target_id) = &message.target_id {
                            // Find nodes closest to the target ID
                            let closest_nodes = {
                                let nodes = known_nodes.read();
                                let mut nodes_vec: Vec<_> = nodes.values().cloned().collect();
                                
                                // Sort by distance to target ID (XOR distance)
                                nodes_vec.sort_by_key(|node| xor_distance(&node.id, target_id));
                                
                                // Take up to 20 nodes
                                nodes_vec.into_iter().take(20).collect::<Vec<_>>()
                            };
                            
                            // Respond with the closest nodes
                            let mut response = DiscoveryMessage::nodes(
                                {
                                    let mut seq = next_sequence.write();
                                    *seq += 1;
                                    *seq
                                },
                                node_id.clone(),
                                node_info.clone(),
                                closest_nodes,
                            );
                            
                            if let Err(e) = response.sign(&private_key) {
                                error!("Failed to sign Nodes message: {}", e);
                                continue;
                            }
                            
                            if let Err(e) = send_message(&socket, &response, updated_addr.address).await {
                                warn!("Failed to send Nodes message: {}", e);
                            }
                        }
                    }
                    
                    DiscoveryMessageType::Nodes => {
                        // Process the nodes in the message
                        if let Some(nodes) = message.nodes {
                            let mut known = known_nodes.write();
                            for node in nodes {
                                if node.id != node_id {
                                    // Don't add ourselves
                                    known.insert(node.id.clone(), node);
                                }
                            }
                        }
                    }
                    
                    DiscoveryMessageType::Announce => {
                        trace!("Received Announce from {}", hex::encode(&sender_id));
                        // We already updated the known nodes with the sender's address
                        
                        // If peer manager is set, try to connect to this node
                        if let Some(peer_mgr) = &peer_manager {
                            let addr = updated_addr.p2p_addr().to_string();
                            let _ = peer_mgr.connect(addr).await; // Ignore errors here
                        }
                    }
                    
                    DiscoveryMessageType::NodeInfoRequest => {
                        // Respond with our node info
                        let mut response = DiscoveryMessage::new(
                            DiscoveryMessageType::NodeInfoResponse,
                            {
                                let mut seq = next_sequence.write();
                                *seq += 1;
                                *seq
                            },
                            node_id.clone(),
                            node_info.clone(),
                        );
                        
                        if let Err(e) = response.sign(&private_key) {
                            error!("Failed to sign NodeInfoResponse message: {}", e);
                            continue;
                        }
                        
                        if let Err(e) = send_message(&socket, &response, updated_addr.address).await {
                            warn!("Failed to send NodeInfoResponse message: {}", e);
                        }
                    }
                    
                    DiscoveryMessageType::NodeInfoResponse => {
                        trace!("Received NodeInfoResponse from {}", hex::encode(&sender_id));
                        // We already updated the known nodes with the sender's info
                    }
                }
            }
        });
        
        self.tasks.push(msg_handler);
        
        // Start the command processing task
        let command_receiver = self.command_receiver.take().unwrap();
        let socket = self.socket.clone();
        let known_nodes = self.known_nodes.clone();
        let node_id = self.node_id.clone();
        let private_key = self.private_key.clone();
        let next_sequence = self.next_sequence.clone();
        let node_info = self.node_info.clone();
        let config = self.config.clone();
        let running = self.running.clone();
        let last_discovery = self.last_discovery.clone();
        
        let cmd_handler = tokio::spawn(async move {
            let mut discovery_interval = tokio::time::interval(Duration::from_secs(config.discovery_interval_secs));
            let mut ping_interval = tokio::time::interval(Duration::from_secs(config.ping_interval_secs));
            
            loop {
                tokio::select! {
                    _ = discovery_interval.tick() => {
                        // Perform discovery
                        *last_discovery.lock() = Instant::now();
                        
                        // Check if we need to discover more nodes
                        let known_count = known_nodes.read().len();
                        if known_count < config.max_nodes / 2 {
                            if let Err(e) = perform_discovery(&socket, &known_nodes, &node_id, &private_key, &next_sequence, &node_info).await {
                                error!("Discovery failed: {}", e);
                            }
                        }
                    }
                    
                    _ = ping_interval.tick() => {
                        // Ping random nodes to keep connections alive
                        let nodes_to_ping = {
                            let nodes = known_nodes.read();
                            let mut nodes_vec: Vec<_> = nodes.values().cloned().collect();
                            
                            // Shuffle and take up to 5 nodes
                            use rand::seq::SliceRandom;
                            let mut rng = rand::thread_rng();
                            nodes_vec.shuffle(&mut rng);
                            
                            nodes_vec.into_iter().take(5).collect::<Vec<_>>()
                        };
                        
                        for node in nodes_to_ping {
                            // Send ping
                            let mut ping = DiscoveryMessage::ping(
                                {
                                    let mut seq = next_sequence.write();
                                    *seq += 1;
                                    *seq
                                },
                                node_id.clone(),
                                node_info.clone(),
                            );
                            
                            if let Err(e) = ping.sign(&private_key) {
                                error!("Failed to sign Ping message: {}", e);
                                continue;
                            }
                            
                            if let Err(e) = send_message(&socket, &ping, node.address).await {
                                warn!("Failed to send Ping message to {}: {}", node.address, e);
                                
                                // If we can't reach the node, mark it as offline
                                let mut nodes = known_nodes.write();
                                if let Some(node_entry) = nodes.get_mut(&node.id) {
                                    // Only mark as offline if it's been a while since we've seen it
                                    let now = chrono::Utc::now().timestamp_millis() as u64;
                                    let age = now.saturating_sub(node_entry.last_seen);
                                    
                                    if age > (config.ping_interval_secs * 3 * 1000) {
                                        nodes.remove(&node.id);
                                    }
                                }
                            }
                        }
                    }
                    
                    cmd = command_receiver.recv() => {
                        match cmd {
                            Some(DiscoveryCommand::AddNode(node, responder)) => {
                                let mut nodes = known_nodes.write();
                                nodes.insert(node.id.clone(), node);
                                let _ = responder.send(Ok(()));
                            }
                            
                            Some(DiscoveryCommand::RemoveNode(node_id, responder)) => {
                                let mut nodes = known_nodes.write();
                                nodes.remove(&node_id);
                                let _ = responder.send(Ok(()));
                            }
                            
                            Some(DiscoveryCommand::GetNodes(criteria, responder)) => {
                                let nodes = known_nodes.read();
                                let mut result = Vec::new();
                                
                                for node in nodes.values() {
                                    // Apply criteria filters
                                    if criteria.validators_only && !node.is_validator {
                                        continue;
                                    }
                                    
                                    if criteria.max_age_secs > 0 && !node.is_online(criteria.max_age_secs) {
                                        continue;
                                    }
                                    
                                    if criteria.has_rdma && node.rdma_port.is_none() {
                                        continue;
                                    }
                                    
                                    if let Some(ref caps) = criteria.capabilities {
                                        let has_all = caps.iter().all(|cap| node.has_capability(cap));
                                        if !has_all {
                                            continue;
                                        }
                                    }
                                    
                                    if let Some(ref region) = criteria.region {
                                        if node.region.as_ref() != Some(region) {
                                            continue;
                                        }
                                    }
                                    
                                    result.push(node.clone());
                                }
                                
                                // Sort by distance to target_id if provided
                                if let Some(ref target_id) = criteria.target_id {
                                    result.sort_by_key(|node| xor_distance(&node.id, target_id));
                                }
                                
                                // Apply limit if provided
                                if criteria.limit > 0 && result.len() > criteria.limit {
                                    result.truncate(criteria.limit);
                                }
                                
                                let _ = responder.send(Ok(result));
                            }
                            
                            Some(DiscoveryCommand::Ping(addr, responder)) => {
                                // Send ping to the specified address
                                let mut ping = DiscoveryMessage::ping(
                                    {
                                        let mut seq = next_sequence.write();
                                        *seq += 1;
                                        *seq
                                    },
                                    node_id.clone(),
                                    node_info.clone(),
                                );
                                
                                if let Err(e) = ping.sign(&private_key) {
                                    let _ = responder.send(Err(AevorError::crypto(
                                        "Failed to sign Ping message".into(),
                                        e.to_string(),
                                        None,
                                    )));
                                    continue;
                                }
                                
                                match send_message(&socket, &ping, addr).await {
                                    Ok(_) => {
                                        let _ = responder.send(Ok(()));
                                    }
                                    Err(e) => {
                                        let _ = responder.send(Err(e));
                                    }
                                }
                            }
                            
                            Some(DiscoveryCommand::FindNodes(target_id, responder)) => {
                                // Find nodes closest to the target_id from our known nodes
                                let closest_nodes = {
                                    let nodes = known_nodes.read();
                                    let mut nodes_vec: Vec<_> = nodes.values().cloned().collect();
                                    
                                    // Sort by distance to target ID (XOR distance)
                                    nodes_vec.sort_by_key(|node| xor_distance(&node.id, &target_id));
                                    
                                    // Take up to 20 nodes
                                    nodes_vec.into_iter().take(20).collect::<Vec<_>>()
                                };
                                
                                // Send FindNodes requests to the closest nodes
                                let mut results = Vec::new();
                                
                                for node in closest_nodes {
                                    let mut find_nodes = DiscoveryMessage::find_nodes(
                                        {
                                            let mut seq = next_sequence.write();
                                            *seq += 1;
                                            *seq
                                        },
                                        node_id.clone(),
                                        node_info.clone(),
                                        target_id.clone(),
                                    );
                                    
                                    if let Err(e) = find_nodes.sign(&private_key) {
                                        error!("Failed to sign FindNodes message: {}", e);
                                        continue;
                                    }
                                    
                                    if let Err(e) = send_message(&socket, &find_nodes, node.address).await {
                                        warn!("Failed to send FindNodes message to {}: {}", node.address, e);
                                        continue;
                                    }
                                    
                                    // We don't wait for responses here as they'll be handled by the message handler
                                    results.push(node);
                                }
                                
                                let _ = responder.send(Ok(results));
                            }
                            
                            Some(DiscoveryCommand::RequestNodeInfo(node_id, responder)) => {
                                // Find the node in our known nodes
                                let node_addr = {
                                    let nodes = known_nodes.read();
                                    nodes.get(&node_id).cloned()
                                };
                                
                                if let Some(node) = node_addr {
                                    // Send NodeInfoRequest
                                    let mut request = DiscoveryMessage::new(
                                        DiscoveryMessageType::NodeInfoRequest,
                                        {
                                            let mut seq = next_sequence.write();
                                            *seq += 1;
                                            *seq
                                        },
                                        node_id.clone(),
                                        node_info.clone(),
                                    );
                                    
                                    if let Err(e) = request.sign(&private_key) {
                                        let _ = responder.send(Err(AevorError::crypto(
                                            "Failed to sign NodeInfoRequest message".into(),
                                            e.to_string(),
                                            None,
                                        )));
                                        continue;
                                    }
                                    
                                    match send_message(&socket, &request, node.address).await {
                                        Ok(_) => {
                                            let _ = responder.send(Ok(node));
                                        }
                                        Err(e) => {
                                            let _ = responder.send(Err(e));
                                        }
                                    }
                                } else {
                                    let _ = responder.send(Err(AevorError::network(format!("Node not found"))));
                                }
                            }
                            
                            Some(DiscoveryCommand::Announce(responder)) => {
                                // Send announce message to all known nodes
                                let nodes_to_announce = {
                                    let nodes = known_nodes.read();
                                    nodes.values().cloned().collect::<Vec<_>>()
                                };
                                
                                for node in nodes_to_announce {
                                    let mut announce = DiscoveryMessage::announce(
                                        {
                                            let mut seq = next_sequence.write();
                                            *seq += 1;
                                            *seq
                                        },
                                        node_id.clone(),
                                        node_info.clone(),
                                    );
                                    
                                    if let Err(e) = announce.sign(&private_key) {
                                        error!("Failed to sign Announce message: {}", e);
                                        continue;
                                    }
                                    
                                    if let Err(e) = send_message(&socket, &announce, node.address).await {
                                        warn!("Failed to send Announce message to {}: {}", node.address, e);
                                    }
                                }
                                
                                let _ = responder.send(Ok(()));
                            }
                            
                            Some(DiscoveryCommand::Shutdown(responder)) => {
                                // Set running to false
                                *running.write() = false;
                                let _ = responder.send(Ok(()));
                                break;
                            }
                            
                            None => {
                                // Channel closed, exit
                                *running.write() = false;
                                break;
                            }
                        }
                    }
                }
                
                // Exit if running is false
                if !*running.read() {
                    break;
                }
            }
        });
        
        self.tasks.push(cmd_handler);
        
        // Start bootstrap process by connecting to bootstrap nodes
        for addr_str in &self.config.bootstrap_nodes {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    // Send a ping to the bootstrap node
                    let mut ping = DiscoveryMessage::ping(
                        {
                            let mut seq = self.next_sequence.write();
                            *seq += 1;
                            *seq
                        },
                        self.node_id.clone(),
                        self.node_info.clone(),
                    );
                    
                    if let Err(e) = ping.sign(&self.private_key) {
                        error!("Failed to sign Ping message for bootstrap node: {}", e);
                        continue;
                    }
                    
                    if let Err(e) = send_message(&self.socket, &ping, addr).await {
                        warn!("Failed to ping bootstrap node {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    warn!("Invalid bootstrap node address {}: {}", addr_str, e);
                }
            }
        }
        
        // Mark as running
        *running = true;
        
        // Announce our presence
        let (tx, rx) = oneshot::channel();
        let _ = self.command_sender.send(DiscoveryCommand::Announce(tx)).await;
        let _ = rx.await; // Ignore result
        
        Ok(())
    }
    
    /// Stops the discovery service
    pub async fn stop(&self) -> Result<()> {
        // Send shutdown command
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::Shutdown(tx)).await {
            return Err(AevorError::network(format!("Failed to send shutdown command: {}", e)));
        }
        
        // Wait for shutdown to complete
        if let Err(e) = rx.await {
            return Err(AevorError::network(format!("Shutdown failed: {}", e)));
        }
        
        Ok(())
    }
    
    /// Adds a node to the known nodes list
    pub async fn add_node(&self, node: NodeAddress) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::AddNode(node, tx)).await {
            return Err(AevorError::network(format!("Failed to send AddNode command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("AddNode failed: {}", e)))?
    }
    
    /// Removes a node from the known nodes list
    pub async fn remove_node(&self, node_id: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::RemoveNode(node_id, tx)).await {
            return Err(AevorError::network(format!("Failed to send RemoveNode command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("RemoveNode failed: {}", e)))?
    }
    
    /// Gets a list of known nodes matching certain criteria
    pub async fn get_nodes(&self, criteria: NodeQueryCriteria) -> Result<Vec<NodeAddress>> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::GetNodes(criteria, tx)).await {
            return Err(AevorError::network(format!("Failed to send GetNodes command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("GetNodes failed: {}", e)))?
    }
    
    /// Sends a ping message to a node
    pub async fn ping(&self, addr: SocketAddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::Ping(addr, tx)).await {
            return Err(AevorError::network(format!("Failed to send Ping command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("Ping failed: {}", e)))?
    }
    
    /// Finds nodes near a target ID
    pub async fn find_nodes(&self, target_id: Vec<u8>) -> Result<Vec<NodeAddress>> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::FindNodes(target_id, tx)).await {
            return Err(AevorError::network(format!("Failed to send FindNodes command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("FindNodes failed: {}", e)))?
    }
    
    /// Requests detailed information about a node
    pub async fn request_node_info(&self, node_id: Vec<u8>) -> Result<NodeAddress> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::RequestNodeInfo(node_id, tx)).await {
            return Err(AevorError::network(format!("Failed to send RequestNodeInfo command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("RequestNodeInfo failed: {}", e)))?
    }
    
    /// Announces this node to the network
    pub async fn announce(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.command_sender.send(DiscoveryCommand::Announce(tx)).await {
            return Err(AevorError::network(format!("Failed to send Announce command: {}", e)));
        }
        
        rx.await.map_err(|e| AevorError::network(format!("Announce failed: {}", e)))?
    }
    
    /// Gets the number of known nodes
    pub fn node_count(&self) -> usize {
        self.known_nodes.read().len()
    }
    
    /// Gets the time since the last discovery
    pub fn time_since_last_discovery(&self) -> Duration {
        self.last_discovery.lock().elapsed()
    }
    
    /// Gets a clone of the command sender
    pub fn command_sender(&self) -> mpsc::Sender<DiscoveryCommand> {
        self.command_sender.clone()
    }
}

/// Helper function to send a discovery message via UDP
async fn send_message(socket: &UdpSocket, message: &DiscoveryMessage, target: SocketAddr) -> Result<()> {
    let bytes = message.to_bytes()?;
    socket.send_to(&bytes, target).await
        .map_err(|e| AevorError::network(format!("Failed to send discovery message: {}", e)))?;
    Ok(())
}

/// Helper function to perform discovery
async fn perform_discovery(
    socket: &UdpSocket,
    known_nodes: &Arc<RwLock<HashMap<Vec<u8>, NodeAddress>>>,
    node_id: &[u8],
    private_key: &[u8],
    next_sequence: &Arc<RwLock<u64>>,
    node_info: &NodeAddress,
) -> Result<()> {
    // If we don't have any known nodes, we can't do discovery
    if known_nodes.read().is_empty() {
        return Ok(());
    }
    
    // Get a random subset of known nodes
    let target_nodes = {
        let nodes = known_nodes.read();
        let mut nodes_vec: Vec<_> = nodes.values().cloned().collect();
        
        // Shuffle and take up to 10 nodes
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        nodes_vec.shuffle(&mut rng);
        
        nodes_vec.into_iter().take(10).collect::<Vec<_>>()
    };
    
    // Generate a random target ID for discovery
    let mut target_id = [0u8; 32];
    rand::thread_rng().fill(&mut target_id);
    let target_id = target_id.to_vec();
    
    // Send FindNodes requests to the target nodes
    for node in target_nodes {
        let mut find_nodes = DiscoveryMessage::find_nodes(
            {
                let mut seq = next_sequence.write();
                *seq += 1;
                *seq
            },
            node_id.to_vec(),
            node_info.clone(),
            target_id.clone(),
        );
        
        if let Err(e) = find_nodes.sign(private_key) {
            error!("Failed to sign FindNodes message: {}", e);
            continue;
        }
        
        if let Err(e) = send_message(socket, &find_nodes, node.address).await {
            warn!("Failed to send FindNodes message to {}: {}", node.address, e);
        }
    }
    
    Ok(())
}

/// Calculates the XOR distance between two IDs
fn xor_distance(id1: &[u8], id2: &[u8]) -> Vec<u8> {
    id1.iter()
        .zip(id2.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_node_address() {
        let id = vec![1, 2, 3, 4];
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7777);
        let p2p_port = 8888;
        let is_validator = true;
        
        let node = NodeAddress::new(id.clone(), socket_addr, p2p_port, is_validator);
        
        assert_eq!(node.id, id);
        assert_eq!(node.address, socket_addr);
        assert_eq!(node.p2p_port, p2p_port);
        assert_eq!(node.is_validator, is_validator);
        
        // Test p2p_addr
        let p2p_addr = node.p2p_addr();
        assert_eq!(p2p_addr.ip(), socket_addr.ip());
        assert_eq!(p2p_addr.port(), p2p_port);
        
        // Test RDMA port
        assert_eq!(node.rdma_addr(), None);
        
        let mut node_with_rdma = node.clone();
        node_with_rdma.rdma_port = Some(9999);
        let rdma_addr = node_with_rdma.rdma_addr().unwrap();
        assert_eq!(rdma_addr.ip(), socket_addr.ip());
        assert_eq!(rdma_addr.port(), 9999);
        
        // Test online status
        assert!(node.is_online(3600));
        
        // Test capabilities
        assert!(node.capabilities.is_empty());
        let mut node_with_cap = node.clone();
        node_with_cap.add_capability(NodeCapability::FullNode);
        assert!(node_with_cap.has_capability(&NodeCapability::FullNode));
        assert!(!node_with_cap.has_capability(&NodeCapability::Validator));
    }
    
    #[test]
    fn test_discovery_message() {
        let id = vec![1, 2, 3, 4];
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7777);
        let p2p_port = 8888;
        let is_validator = true;
        
        let sender_addr = NodeAddress::new(id.clone(), socket_addr, p2p_port, is_validator);
        
        // Test ping message
        let ping = DiscoveryMessage::ping(1, id.clone(), sender_addr.clone());
        assert_eq!(ping.message_type, DiscoveryMessageType::Ping);
        assert_eq!(ping.sequence, 1);
        assert_eq!(ping.sender_id, id);
        assert_eq!(ping.sender_addr, sender_addr);
        
        // Test pong message
        let pong = DiscoveryMessage::pong(2, id.clone(), sender_addr.clone());
        assert_eq!(pong.message_type, DiscoveryMessageType::Pong);
        assert_eq!(pong.sequence, 2);
        
        // Test find_nodes message
        let target_id = vec![5, 6, 7, 8];
        let find_nodes = DiscoveryMessage::find_nodes(3, id.clone(), sender_addr.clone(), target_id.clone());
        assert_eq!(find_nodes.message_type, DiscoveryMessageType::FindNodes);
        assert_eq!(find_nodes.sequence, 3);
        assert_eq!(find_nodes.target_id, Some(target_id));
        
        // Test nodes message
        let nodes = vec![sender_addr.clone()];
        let nodes_msg = DiscoveryMessage::nodes(4, id.clone(), sender_addr.clone(), nodes.clone());
        assert_eq!(nodes_msg.message_type, DiscoveryMessageType::Nodes);
        assert_eq!(nodes_msg.sequence, 4);
        assert_eq!(nodes_msg.nodes, Some(nodes));
        
        // Test announce message
        let announce = DiscoveryMessage::announce(5, id.clone(), sender_addr.clone());
        assert_eq!(announce.message_type, DiscoveryMessageType::Announce);
        assert_eq!(announce.sequence, 5);
        
        // Test TTL handling
        let mut msg = DiscoveryMessage::ping(6, id.clone(), sender_addr.clone());
        assert_eq!(msg.ttl, 3); // Default TTL
        assert!(!msg.is_ttl_expired());
        
        msg.decrement_ttl();
        assert_eq!(msg.ttl, 2);
        
        msg.decrement_ttl();
        assert_eq!(msg.ttl, 1);
        
        msg.decrement_ttl();
        assert_eq!(msg.ttl, 0);
        assert!(msg.is_ttl_expired());
        
        // Test one more decrement should not go below 0
        msg.decrement_ttl();
        assert_eq!(msg.ttl, 0);
    }
    
    #[test]
    fn test_xor_distance() {
        let id1 = vec![1, 2, 3, 4];
        let id2 = vec![5, 6, 7, 8];
        
        let distance = xor_distance(&id1, &id2);
        
        // XOR of each byte: 1^5=4, 2^6=4, 3^7=4, 4^8=12
        assert_eq!(distance, vec![4, 4, 4, 12]);
        
        // Distance to self should be all zeros
        let self_distance = xor_distance(&id1, &id1);
        assert_eq!(self_distance, vec![0, 0, 0, 0]);
    }
}
