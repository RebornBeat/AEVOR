use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock, Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{self, sleep, timeout};

use crate::config::NetworkConfig;
use crate::crypto::signature::{Signature, SignatureAlgorithm, verify_signature};
use crate::error::{AevorError, Result};
use crate::utils::metrics::{Counter, Gauge};

use super::protocol::{Message, MessageType, Protocol, ProtocolHandler, ProtocolVersion};
use super::topology::TopologyManager;

/// Represents the connection state of a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerState {
    /// Initiating a connection
    Connecting,
    
    /// Performing handshake
    Handshaking,
    
    /// Active connection
    Active,
    
    /// In process of disconnecting
    Disconnecting,
    
    /// Disconnected
    Disconnected,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::Connecting => write!(f, "Connecting"),
            PeerState::Handshaking => write!(f, "Handshaking"),
            PeerState::Active => write!(f, "Active"),
            PeerState::Disconnecting => write!(f, "Disconnecting"),
            PeerState::Disconnected => write!(f, "Disconnected"),
        }
    }
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID (public key)
    pub id: Vec<u8>,
    
    /// Peer's socket address
    pub address: SocketAddr,
    
    /// Current connection state
    pub state: PeerState,
    
    /// Negotiated protocol version
    pub protocol_version: ProtocolVersion,
    
    /// Time when the connection was established
    pub connected_since: Instant,
    
    /// Last message received time
    pub last_seen: Instant,
    
    /// Whether this peer is a validator
    pub is_validator: bool,
    
    /// Capabilities advertised by this peer
    pub capabilities: Vec<String>,
    
    /// Peer's user agent string
    pub user_agent: String,
    
    /// Network region this peer belongs to (if known)
    pub region: Option<String>,
    
    /// Connection quality metrics (0-100)
    pub connection_quality: u8,
    
    /// Ping latency in milliseconds
    pub ping_ms: Option<u64>,
    
    /// Whether we have an outbound connection to this peer
    pub is_outbound: bool,
    
    /// Total bytes sent to this peer
    pub bytes_sent: u64,
    
    /// Total bytes received from this peer
    pub bytes_received: u64,
}

/// Commands that can be sent to the peer manager
#[derive(Debug)]
pub enum PeerCommand {
    /// Connect to a peer
    Connect(SocketAddr, oneshot::Sender<Result<()>>),
    
    /// Disconnect from a peer
    Disconnect(Vec<u8>, oneshot::Sender<Result<()>>),
    
    /// Send a message to a specific peer
    SendMessage(Vec<u8>, Message, oneshot::Sender<Result<()>>),
    
    /// Broadcast a message to all peers
    Broadcast(Message, oneshot::Sender<Result<()>>),
    
    /// Ban a peer
    Ban(Vec<u8>, Duration, oneshot::Sender<Result<()>>),
    
    /// Unban a peer
    Unban(Vec<u8>, oneshot::Sender<Result<()>>),
    
    /// Get peer information
    GetPeer(Vec<u8>, oneshot::Sender<Result<Option<PeerInfo>>>),
    
    /// Get information about all peers
    GetPeers(oneshot::Sender<Vec<PeerInfo>>),
    
    /// Get banned peers
    GetBannedPeers(oneshot::Sender<Vec<Vec<u8>>>),
    
    /// Send ping to peer
    Ping(Vec<u8>, oneshot::Sender<Result<u64>>),
}

/// Messages sent internally by peers
#[derive(Debug)]
pub enum PeerMessage {
    /// A message was received from a peer
    MessageReceived(Vec<u8>, Message),
    
    /// Peer connected
    Connected(Vec<u8>, PeerInfo),
    
    /// Peer disconnected
    Disconnected(Vec<u8>, String),
    
    /// Peer handshake completed
    HandshakeCompleted(Vec<u8>, PeerInfo),
    
    /// Peer error
    Error(Vec<u8>, AevorError),
}

/// Handler for peer messages
pub type MessageHandler = Arc<dyn Fn(Vec<u8>, Message) -> Result<()> + Send + Sync>;

/// Handler for peer events
pub type PeerEventHandler = Arc<dyn Fn(PeerEvent) -> Result<()> + Send + Sync>;

/// Peer events for external handlers
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Peer connected
    Connected(PeerInfo),
    
    /// Peer disconnected
    Disconnected(Vec<u8>, String),
    
    /// Peer handshake completed
    HandshakeCompleted(PeerInfo),
    
    /// Peer error
    Error(Vec<u8>, String),
}

/// Represents a connected peer
pub struct Peer {
    /// Peer information
    info: PeerInfo,
    
    /// TCP stream for communication
    stream: TcpStream,
    
    /// Message sender to the main peer manager
    peer_message_sender: mpsc::Sender<PeerMessage>,
    
    /// Message handler for incoming messages
    message_handler: MessageHandler,
    
    /// Sender for outgoing messages
    message_sender: mpsc::Sender<(Message, oneshot::Sender<Result<()>>)>,
    
    /// Receiver for outgoing messages
    message_receiver: Option<mpsc::Receiver<(Message, oneshot::Sender<Result<()>>)>>,
    
    /// Protocol handler
    protocol: Arc<Protocol>,
    
    /// Node ID (our ID)
    node_id: Vec<u8>,
    
    /// Background tasks
    tasks: Vec<JoinHandle<()>>,
    
    /// Whether this peer is starting up
    starting: bool,
    
    /// Whether this peer is shutting down
    shutdown: Arc<RwLock<bool>>,
}

impl Peer {
    /// Creates a new peer from a TCP stream
    pub fn new(
        stream: TcpStream,
        address: SocketAddr,
        peer_message_sender: mpsc::Sender<PeerMessage>,
        message_handler: MessageHandler,
        protocol: Arc<Protocol>,
        node_id: Vec<u8>,
        is_outbound: bool,
    ) -> Self {
        let (message_sender, message_receiver) = mpsc::channel(100);
        
        let now = Instant::now();
        let info = PeerInfo {
            id: Vec::new(), // Will be filled during handshake
            address,
            state: PeerState::Connecting,
            protocol_version: ProtocolVersion::V1, // Default, negotiated during handshake
            connected_since: now,
            last_seen: now,
            is_validator: false, // Will be determined during handshake
            capabilities: Vec::new(), // Will be filled during handshake
            user_agent: String::new(), // Will be filled during handshake
            region: None, // Will be determined later
            connection_quality: 100, // Start with max quality
            ping_ms: None, // Will be measured later
            is_outbound,
            bytes_sent: 0,
            bytes_received: 0,
        };
        
        Self {
            info,
            stream,
            peer_message_sender,
            message_handler,
            message_sender,
            message_receiver: Some(message_receiver),
            protocol,
            node_id,
            tasks: Vec::new(),
            starting: true,
            shutdown: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Starts the peer tasks
    pub async fn start(&mut self) -> Result<()> {
        if !self.starting {
            return Err(AevorError::network("Peer already started"));
        }
        
        // Split the stream for concurrent reading and writing
        let (mut reader, mut writer) = self.stream.split();
        
        // Take the message receiver
        let mut message_receiver = self.message_receiver.take()
            .ok_or_else(|| AevorError::network("Message receiver already taken"))?;
        
        // Clone necessary data for tasks
        let peer_message_sender = self.peer_message_sender.clone();
        let info = self.info.clone();
        let peer_id = info.id.clone();
        let address = info.address;
        let message_sender = self.message_sender.clone();
        let message_handler = self.message_handler.clone();
        let protocol = self.protocol.clone();
        let node_id = self.node_id.clone();
        let shutdown = self.shutdown.clone();
        
        // Perform handshake for outbound connections or wait for handshake for inbound
        if info.is_outbound {
            // Create and send handshake message
            let handshake_msg = protocol.create_handshake(
                node_id.clone(),
                ProtocolVersion::V1,
                Vec::new(), // Capabilities will be filled by Protocol
                String::from("Aevor/1.0"), // User agent
            )?;
            
            // Serialize the message
            let handshake_data = protocol.serialize(&handshake_msg)?;
            
            // Send the handshake
            writer.write_all(&handshake_data).await
                .map_err(|e| AevorError::network(format!("Failed to send handshake: {}", e)))?;
            
            // Update state
            self.info.state = PeerState::Handshaking;
        }
        
        // 1. Read task - reads messages from the peer
        let read_task = {
            let peer_message_sender = peer_message_sender.clone();
            let mut info = info.clone();
            let protocol = protocol.clone();
            let shutdown = shutdown.clone();
            
            tokio::spawn(async move {
                let mut buffer = [0u8; 65536]; // 64KB buffer
                
                while !*shutdown.read().await {
                    // Read the length prefix (4 bytes)
                    let length_result = match timeout(Duration::from_secs(30), reader.read_u32()).await {
                        Ok(result) => result,
                        Err(_) => {
                            // Timeout, check if we should ping the peer
                            if info.state == PeerState::Active && info.last_seen.elapsed() > Duration::from_secs(60) {
                                // Send ping
                                let ping_msg = protocol.create_ping(node_id.clone());
                                if let Ok(ping_msg) = ping_msg {
                                    let (tx, _) = oneshot::channel();
                                    let _ = message_sender.send((ping_msg, tx)).await;
                                }
                            }
                            continue;
                        }
                    };
                    
                    let length = match length_result {
                        Ok(len) => len as usize,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                // Connection closed
                                let _ = peer_message_sender.send(PeerMessage::Disconnected(
                                    info.id.clone(),
                                    "Connection closed by peer".to_string(),
                                )).await;
                                break;
                            }
                            
                            // Other errors
                            let _ = peer_message_sender.send(PeerMessage::Error(
                                info.id.clone(),
                                AevorError::network(format!("Failed to read message length: {}", e)),
                            )).await;
                            break;
                        }
                    };
                    
                    // Sanity check on length
                    if length == 0 || length > buffer.len() {
                        let _ = peer_message_sender.send(PeerMessage::Error(
                            info.id.clone(),
                            AevorError::network(format!("Invalid message length: {}", length)),
                        )).await;
                        break;
                    }
                    
                    // Read the message body
                    let read_result = reader.read_exact(&mut buffer[..length]).await;
                    if let Err(e) = read_result {
                        let _ = peer_message_sender.send(PeerMessage::Error(
                            info.id.clone(),
                            AevorError::network(format!("Failed to read message body: {}", e)),
                        )).await;
                        break;
                    }
                    
                    // Update bytes received and last seen time
                    info.bytes_received += length as u64 + 4; // 4 bytes for length prefix
                    info.last_seen = Instant::now();
                    
                    // Deserialize message
                    let message_result = protocol.deserialize(&buffer[..length]);
                    let message = match message_result {
                        Ok(msg) => msg,
                        Err(e) => {
                            let _ = peer_message_sender.send(PeerMessage::Error(
                                info.id.clone(),
                                AevorError::network(format!("Failed to deserialize message: {}", e)),
                            )).await;
                            continue; // Don't disconnect on deserialization errors
                        }
                    };
                    
                    // Handle handshake message for inbound connections
                    if info.state == PeerState::Connecting && message.message_type == MessageType::Handshake {
                        // Extract peer information from handshake
                        if let Ok(handshake_data) = protocol.extract_handshake(&message) {
                            info.id = handshake_data.sender.clone();
                            info.protocol_version = handshake_data.version;
                            info.capabilities = handshake_data.capabilities;
                            info.user_agent = handshake_data.user_agent;
                            info.is_validator = handshake_data.is_validator;
                            
                            // Update state
                            info.state = PeerState::Handshaking;
                            
                            // Send our handshake response
                            let handshake_resp = protocol.create_handshake(
                                node_id.clone(),
                                ProtocolVersion::V1,
                                Vec::new(), // Capabilities will be filled by Protocol
                                String::from("Aevor/1.0"), // User agent
                            );
                            
                            if let Ok(handshake_resp) = handshake_resp {
                                let (tx, _) = oneshot::channel();
                                let _ = message_sender.send((handshake_resp, tx)).await;
                            }
                            
                            // Notify about successful handshake
                            let _ = peer_message_sender.send(PeerMessage::HandshakeCompleted(
                                info.id.clone(), 
                                info.clone(),
                            )).await;
                            
                            // Update state to active
                            info.state = PeerState::Active;
                        }
                    }
                    // Handle handshake response for outbound connections
                    else if info.state == PeerState::Handshaking && message.message_type == MessageType::Handshake {
                        // Extract peer information from handshake
                        if let Ok(handshake_data) = protocol.extract_handshake(&message) {
                            info.id = handshake_data.sender.clone();
                            info.protocol_version = handshake_data.version;
                            info.capabilities = handshake_data.capabilities;
                            info.user_agent = handshake_data.user_agent;
                            info.is_validator = handshake_data.is_validator;
                            
                            // Notify about successful handshake
                            let _ = peer_message_sender.send(PeerMessage::HandshakeCompleted(
                                info.id.clone(), 
                                info.clone(),
                            )).await;
                            
                            // Update state to active
                            info.state = PeerState::Active;
                        }
                    }
                    // Handle pong messages (response to ping)
                    else if info.state == PeerState::Active && message.message_type == MessageType::Pong {
                        // Calculate ping time based on original ping timestamp
                        if let Ok(ping_data) = protocol.extract_ping(&message) {
                            let ping_time = Instant::now().duration_since(
                                Instant::now() - Duration::from_millis(ping_data.timestamp)
                            ).as_millis() as u64;
                            
                            info.ping_ms = Some(ping_time);
                            
                            // Update connection quality based on ping time
                            info.connection_quality = if ping_time < 50 {
                                100
                            } else if ping_time < 100 {
                                90
                            } else if ping_time < 200 {
                                80
                            } else if ping_time < 500 {
                                60
                            } else {
                                40
                            };
                        }
                    }
                    // Handle ping messages
                    else if info.state == PeerState::Active && message.message_type == MessageType::Ping {
                        // Create pong response
                        if let Ok(pong_msg) = protocol.create_pong(
                            node_id.clone(),
                            message.id, // Use the same ID as the ping
                        ) {
                            let (tx, _) = oneshot::channel();
                            let _ = message_sender.send((pong_msg, tx)).await;
                        }
                    }
                    
                    // For regular messages, forward to handler
                    if info.state == PeerState::Active {
                        // Notify peer manager about received message
                        let _ = peer_message_sender.send(PeerMessage::MessageReceived(
                            info.id.clone(),
                            message.clone(),
                        )).await;
                        
                        // Forward to message handler
                        let peer_id = info.id.clone();
                        let _ = message_handler(peer_id, message);
                    }
                }
                
                // Notify about disconnection
                if !info.id.is_empty() {
                    let _ = peer_message_sender.send(PeerMessage::Disconnected(
                        info.id.clone(),
                        "Read task completed".to_string(),
                    )).await;
                }
            })
        };
        
        // 2. Write task - writes messages to the peer
        let write_task = {
            let peer_message_sender = peer_message_sender.clone();
            let mut info = info.clone();
            let protocol = protocol.clone();
            let shutdown = shutdown.clone();
            
            tokio::spawn(async move {
                while !*shutdown.read().await {
                    match timeout(Duration::from_secs(1), message_receiver.recv()).await {
                        Ok(Some((message, response_sender))) => {
                            // Serialize the message
                            let result = protocol.serialize(&message);
                            let data = match result {
                                Ok(data) => data,
                                Err(e) => {
                                    let _ = response_sender.send(Err(AevorError::network(format!("Failed to serialize message: {}", e))));
                                    continue;
                                }
                            };
                            
                            // Write length prefix (4 bytes) + message data
                            let len = data.len() as u32;
                            let write_result = writer.write_u32(len).await;
                            if let Err(e) = write_result {
                                let _ = response_sender.send(Err(AevorError::network(format!("Failed to write message length: {}", e))));
                                let _ = peer_message_sender.send(PeerMessage::Error(
                                    info.id.clone(),
                                    AevorError::network(format!("Failed to write message length: {}", e)),
                                )).await;
                                break;
                            }
                            
                            let write_result = writer.write_all(&data).await;
                            if let Err(e) = write_result {
                                let _ = response_sender.send(Err(AevorError::network(format!("Failed to write message data: {}", e))));
                                let _ = peer_message_sender.send(PeerMessage::Error(
                                    info.id.clone(),
                                    AevorError::network(format!("Failed to write message data: {}", e)),
                                )).await;
                                break;
                            }
                            
                            // Flush to ensure the message is sent
                            let flush_result = writer.flush().await;
                            if let Err(e) = flush_result {
                                let _ = response_sender.send(Err(AevorError::network(format!("Failed to flush writer: {}", e))));
                                let _ = peer_message_sender.send(PeerMessage::Error(
                                    info.id.clone(),
                                    AevorError::network(format!("Failed to flush writer: {}", e)),
                                )).await;
                                break;
                            }
                            
                            // Update bytes sent
                            info.bytes_sent += data.len() as u64 + 4; // 4 bytes for length prefix
                            
                            // Send success response
                            let _ = response_sender.send(Ok(()));
                        },
                        Ok(None) => {
                            // Channel closed
                            break;
                        },
                        Err(_) => {
                            // Timeout - check shutdown
                            if *shutdown.read().await {
                                break;
                            }
                        }
                    }
                }
                
                // Notify about disconnection
                if !info.id.is_empty() {
                    let _ = peer_message_sender.send(PeerMessage::Disconnected(
                        info.id.clone(),
                        "Write task completed".to_string(),
                    )).await;
                }
            })
        };
        
        // Store tasks
        self.tasks.push(read_task);
        self.tasks.push(write_task);
        self.starting = false;
        
        // Send connected message
        let _ = self.peer_message_sender.send(PeerMessage::Connected(
            self.info.id.clone(),
            self.info.clone(),
        )).await;
        
        Ok(())
    }
    
    /// Stops the peer tasks
    pub async fn stop(&self) -> Result<()> {
        // Set shutdown flag
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
        
        // Close the stream to unblock the read task
        let _ = self.stream.shutdown().await;
        
        Ok(())
    }
    
    /// Sends a message to the peer
    pub async fn send(&self, message: Message) -> Result<()> {
        // Create response channel
        let (tx, rx) = oneshot::channel();
        
        // Send message to the write task
        self.message_sender.send((message, tx)).await
            .map_err(|_| AevorError::network("Failed to send message to write task"))?;
        
        // Wait for response with timeout
        match timeout(Duration::from_secs(5), rx).await {
            Ok(result) => result.map_err(|_| AevorError::network("Write task response channel closed"))?,
            Err(_) => Err(AevorError::timeout("Send message timed out")),
        }
    }
    
    /// Gets the peer information
    pub fn info(&self) -> &PeerInfo {
        &self.info
    }
    
    /// Gets the peer ID
    pub fn id(&self) -> &[u8] {
        &self.info.id
    }
    
    /// Gets the peer address
    pub fn address(&self) -> SocketAddr {
        self.info.address
    }
    
    /// Gets the peer state
    pub fn state(&self) -> PeerState {
        self.info.state
    }
    
    /// Sets the peer ID
    pub fn set_id(&mut self, id: Vec<u8>) {
        self.info.id = id;
    }
    
    /// Sets the peer state
    pub fn set_state(&mut self, state: PeerState) {
        self.info.state = state;
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // Clean up tasks
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

/// Manager for handling peer connections
pub struct PeerManager {
    /// Network configuration
    config: Arc<NetworkConfig>,
    
    /// Node ID (public key)
    node_id: Vec<u8>,
    
    /// Protocol version
    protocol_version: ProtocolVersion,
    
    /// Whether this node is a validator
    is_validator: bool,
    
    /// TCP listener for incoming connections
    listener: Option<TcpListener>,
    
    /// Connected peers
    peers: Arc<RwLock<HashMap<Vec<u8>, Arc<Mutex<Peer>>>>>,
    
    /// Peer connection attempts in progress
    connecting_peers: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
    
    /// Banned peers (ID -> expiry time)
    banned_peers: Arc<RwLock<HashMap<Vec<u8>, Instant>>>,
    
    /// Banned addresses (addr -> expiry time)
    banned_addresses: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
    
    /// Command channel
    command_sender: mpsc::Sender<PeerCommand>,
    
    /// Command receiver
    command_receiver: Option<mpsc::Receiver<PeerCommand>>,
    
    /// Peer message channel
    peer_message_sender: mpsc::Sender<PeerMessage>,
    
    /// Peer message receiver
    peer_message_receiver: Option<mpsc::Receiver<PeerMessage>>,
    
    /// Protocol handler
    protocol: Arc<Protocol>,
    
    /// Message handler
    message_handler: MessageHandler,
    
    /// Peer event handler
    event_handler: Option<PeerEventHandler>,
    
    /// Topology manager
    topology_manager: Option<Arc<TopologyManager>>,
    
    /// Background tasks
    tasks: Vec<JoinHandle<()>>,
    
    /// Running state
    running: Arc<RwLock<bool>>,
    
    /// Stats
    stats: PeerManagerStats,
}

/// Statistics for the peer manager
#[derive(Debug, Default)]
pub struct PeerManagerStats {
    /// Number of incoming connections
    pub incoming_connections: usize,
    
    /// Number of outgoing connections
    pub outgoing_connections: usize,
    
    /// Number of failed connection attempts
    pub failed_connections: usize,
    
    /// Number of handshake failures
    pub handshake_failures: usize,
    
    /// Number of messages sent
    pub messages_sent: usize,
    
    /// Number of messages received
    pub messages_received: usize,
    
    /// Number of peers banned
    pub peers_banned: usize,
    
    /// Number of peers disconnected
    pub peers_disconnected: usize,
}

impl PeerManager {
    /// Creates a new peer manager
    pub fn new(
        config: Arc<NetworkConfig>,
        node_id: Vec<u8>,
        protocol_version: ProtocolVersion,
        is_validator: bool,
    ) -> Result<Self> {
        let (command_sender, command_receiver) = mpsc::channel(100);
        let (peer_message_sender, peer_message_receiver) = mpsc::channel(1000);
        
        let protocol = Arc::new(Protocol::new(protocol_version));
        
        // Create default message handler
        let message_handler: MessageHandler = Arc::new(|_peer_id, _message| {
            // Default handler does nothing
            Ok(())
        });
        
        Ok(Self {
            config,
            node_id,
            protocol_version,
            is_validator,
            listener: None,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connecting_peers: Arc::new(RwLock::new(HashMap::new())),
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
            banned_addresses: Arc::new(RwLock::new(HashMap::new())),
            command_sender,
            command_receiver: Some(command_receiver),
            peer_message_sender,
            peer_message_receiver: Some(peer_message_receiver),
            protocol,
            message_handler,
            event_handler: None,
            topology_manager: None,
            tasks: Vec::new(),
            running: Arc::new(RwLock::new(false)),
            stats: PeerManagerStats::default(),
        })
    }
    
    /// Sets the message handler
    pub fn set_message_handler(&mut self, handler: MessageHandler) {
        self.message_handler = handler;
    }
    
    /// Sets the event handler
    pub fn set_event_handler(&mut self, handler: PeerEventHandler) {
        self.event_handler = Some(handler);
    }
    
    /// Sets the topology manager
    pub fn set_topology_manager(&mut self, topology_manager: Arc<TopologyManager>) {
        self.topology_manager = Some(topology_manager);
    }
    
    /// Starts the peer manager
    pub async fn start(&mut self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        // Start listening for incoming connections
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.p2p_port);
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| AevorError::network(format!("Failed to bind to {}: {}", listen_addr, e)))?;
        
        self.listener = Some(listener);
        
        // Take the receivers
        let command_receiver = self.command_receiver.take()
            .ok_or_else(|| AevorError::network("Command receiver already taken"))?;
        
        let peer_message_receiver = self.peer_message_receiver.take()
            .ok_or_else(|| AevorError::network("Peer message receiver already taken"))?;
        
        // Clone necessary data for tasks
        let peers = self.peers.clone();
        let connecting_peers = self.connecting_peers.clone();
        let banned_peers = self.banned_peers.clone();
        let banned_addresses = self.banned_addresses.clone();
        let command_sender = self.command_sender.clone();
        let peer_message_sender = self.peer_message_sender.clone();
        let protocol = self.protocol.clone();
        let node_id = self.node_id.clone();
        let message_handler = self.message_handler.clone();
        let event_handler = self.event_handler.clone();
        let topology_manager = self.topology_manager.clone();
        let running = self.running.clone();
        let config = self.config.clone();
        let is_validator = self.is_validator;
        
        // Start the listener task
        let listener_task = {
            let listener = self.listener.as_ref().unwrap().try_clone().unwrap();
            let peer_message_sender = peer_message_sender.clone();
            let protocol = protocol.clone();
            let node_id = node_id.clone();
            let message_handler = message_handler.clone();
            let peers = peers.clone();
            let banned_addresses = banned_addresses.clone();
            let running = running.clone();
            
            tokio::spawn(async move {
                while *running.read().await {
                    // Accept a connection with timeout
                    let accept_result = timeout(Duration::from_secs(1), listener.accept()).await;
                    
                    match accept_result {
                        Ok(Ok((stream, address))) => {
                            // Check if the address is banned
                            let is_banned = {
                                let banned = banned_addresses.read().await;
                                banned.contains_key(&address) && banned.get(&address).unwrap() > Instant::now()
                            };
                            
                            if is_banned {
                                // Drop the connection
                                continue;
                            }
                            
                            // Create a new peer
                            let mut peer = Peer::new(
                                stream,
                                address,
                                peer_message_sender.clone(),
                                message_handler.clone(),
                                protocol.clone(),
                                node_id.clone(),
                                false, // inbound connection
                            );
                            
                            // Start the peer tasks
                            if let Err(e) = peer.start().await {
                                tracing::warn!("Failed to start peer {}: {}", address, e);
                                continue;
                            }
                            
                            // Save the peer temporarily (will be moved once the handshake completes)
                            let peer = Arc::new(Mutex::new(peer));
                            {
                                let mut peers_map = peers.write().await;
                                peers_map.insert(Vec::new(), peer); // Empty ID until handshake completes
                            }
                        },
                        Ok(Err(e)) => {
                            tracing::warn!("Failed to accept connection: {}", e);
                        },
                        Err(_) => {
                            // Timeout, check if we should continue running
                            if !*running.read().await {
                                break;
                            }
                        }
                    }
                }
            })
        };
        
        // Start the command processor task
        let command_task = {
            let peers = peers.clone();
            let connecting_peers = connecting_peers.clone();
            let banned_peers = banned_peers.clone();
            let banned_addresses = banned_addresses.clone();
            let peer_message_sender = peer_message_sender.clone();
            let protocol = protocol.clone();
            let node_id = node_id.clone();
            let message_handler = message_handler.clone();
            let running = running.clone();
            
            tokio::spawn(async move {
                let mut command_receiver = command_receiver;
                
                while *running.read().await {
                    match timeout(Duration::from_secs(1), command_receiver.recv()).await {
                        Ok(Some(command)) => {
                            match command {
                                PeerCommand::Connect(address, response) => {
                                    // Check if we're already connected to this address
                                    let already_connected = {
                                        let peers_map = peers.read().await;
                                        peers_map.values().any(|peer| {
                                            let peer_info = peer.try_lock().map(|p| p.info().address);
                                            peer_info.map_or(false, |addr| addr == address)
                                        })
                                    };
                                    
                                    if already_connected {
                                        let _ = response.send(Err(AevorError::network(format!("Already connected to {}", address))));
                                        continue;
                                    }
                                    
                                    // Check if the address is banned
                                    let is_banned = {
                                        let banned = banned_addresses.read().await;
                                        banned.contains_key(&address) && banned.get(&address).unwrap() > Instant::now()
                                    };
                                    
                                    if is_banned {
                                        let _ = response.send(Err(AevorError::network(format!("Address {} is banned", address))));
                                        continue;
                                    }
                                    
                                    // Check if we're already trying to connect
                                    let already_connecting = {
                                        let connecting = connecting_peers.read().await;
                                        connecting.contains_key(&address)
                                    };
                                    
                                    if already_connecting {
                                        let _ = response.send(Err(AevorError::network(format!("Already connecting to {}", address))));
                                        continue;
                                    }
                                    
                                    // Add to connecting peers
                                    {
                                        let mut connecting = connecting_peers.write().await;
                                        connecting.insert(address, Instant::now());
                                    }
                                    
                                    // Connect to the address
                                    let connect_result = timeout(
                                        Duration::from_secs(config.connection_timeout_secs),
                                        TcpStream::connect(address)
                                    ).await;
                                    
                                    // Remove from connecting peers
                                    {
                                        let mut connecting = connecting_peers.write().await;
                                        connecting.remove(&address);
                                    }
                                    
                                    match connect_result {
                                        Ok(Ok(stream)) => {
                                            // Create a new peer
                                            let mut peer = Peer::new(
                                                stream,
                                                address,
                                                peer_message_sender.clone(),
                                                message_handler.clone(),
                                                protocol.clone(),
                                                node_id.clone(),
                                                true, // outbound connection
                                            );
                                            
                                            // Start the peer tasks
                                            match peer.start().await {
                                                Ok(()) => {
                                                    // Save the peer temporarily (will be moved once the handshake completes)
                                                    let peer = Arc::new(Mutex::new(peer));
                                                    {
                                                        let mut peers_map = peers.write().await;
                                                        peers_map.insert(Vec::new(), peer); // Empty ID until handshake completes
                                                    }
                                                    
                                                    let _ = response.send(Ok(()));
                                                },
                                                Err(e) => {
                                                    let _ = response.send(Err(e));
                                                }
                                            }
                                        },
                                        Ok(Err(e)) => {
                                            let _ = response.send(Err(AevorError::network(format!("Failed to connect to {}: {}", address, e))));
                                        },
                                        Err(_) => {
                                            let _ = response.send(Err(AevorError::timeout(format!("Connection to {} timed out", address))));
                                        }
                                    }
                                },
                                PeerCommand::Disconnect(peer_id, response) => {
                                    let peer_opt = {
                                        let mut peers_map = peers.write().await;
                                        peers_map.remove(&peer_id)
                                    };
                                    
                                    match peer_opt {
                                        Some(peer) => {
                                            // Stop the peer tasks
                                            let mut peer_guard = peer.lock().await;
                                            match peer_guard.stop().await {
                                                Ok(()) => {
                                                    let _ = response.send(Ok(()));
                                                },
                                                Err(e) => {
                                                    let _ = response.send(Err(e));
                                                }
                                            }
                                        },
                                        None => {
                                            let _ = response.send(Err(AevorError::network(format!("Peer not found: {}", hex::encode(&peer_id)))));
                                        }
                                    }
                                },
                                PeerCommand::SendMessage(peer_id, message, response) => {
                                    let peer_opt = {
                                        let peers_map = peers.read().await;
                                        peers_map.get(&peer_id).cloned()
                                    };
                                    
                                    match peer_opt {
                                        Some(peer) => {
                                            let peer_guard = peer.lock().await;
                                            match peer_guard.send(message).await {
                                                Ok(()) => {
                                                    let _ = response.send(Ok(()));
                                                },
                                                Err(e) => {
                                                    let _ = response.send(Err(e));
                                                }
                                            }
                                        },
                                        None => {
                                            let _ = response.send(Err(AevorError::network(format!("Peer not found: {}", hex::encode(&peer_id)))));
                                        }
                                    }
                                },
                                PeerCommand::Broadcast(message, response) => {
                                    let peer_ids = {
                                        let peers_map = peers.read().await;
                                        peers_map.keys().cloned().collect::<Vec<_>>()
                                    };
                                    
                                    let mut errors = Vec::new();
                                    
                                    for peer_id in peer_ids {
                                        if peer_id.is_empty() {
                                            continue; // Skip peers without ID (handshake not completed)
                                        }
                                        
                                        let peer_opt = {
                                            let peers_map = peers.read().await;
                                            peers_map.get(&peer_id).cloned()
                                        };
                                        
                                        if let Some(peer) = peer_opt {
                                            let peer_guard = peer.lock().await;
                                            if let Err(e) = peer_guard.send(message.clone()).await {
                                                errors.push(format!("Failed to send to {}: {}", hex::encode(&peer_id), e));
                                            }
                                        }
                                    }
                                    
                                    if errors.is_empty() {
                                        let _ = response.send(Ok(()));
                                    } else {
                                        let _ = response.send(Err(AevorError::network(format!("Broadcast errors: {}", errors.join(", ")))));
                                    }
                                },
                                PeerCommand::Ban(peer_id, duration, response) => {
                                    // Add to banned peers
                                    {
                                        let mut banned = banned_peers.write().await;
                                        banned.insert(peer_id.clone(), Instant::now() + duration);
                                    }
                                    
                                    // Get peer address
                                    let peer_opt = {
                                        let peers_map = peers.read().await;
                                        peers_map.get(&peer_id).cloned()
                                    };
                                    
                                    // Ban the address too
                                    if let Some(peer) = peer_opt {
                                        let address = {
                                            let peer_guard = peer.lock().await;
                                            peer_guard.address()
                                        };
                                        
                                        {
                                            let mut banned = banned_addresses.write().await;
                                            banned.insert(address, Instant::now() + duration);
                                        }
                                    }
                                    
                                    // Disconnect the peer
                                    let disconnect_cmd = PeerCommand::Disconnect(peer_id, response);
                                    command_sender.send(disconnect_cmd).await.unwrap();
                                },
                                PeerCommand::Unban(peer_id, response) => {
                                    // Remove from banned peers
                                    {
                                        let mut banned = banned_peers.write().await;
                                        banned.remove(&peer_id);
                                    }
                                    
                                    let _ = response.send(Ok(()));
                                },
                                PeerCommand::GetPeer(peer_id, response) => {
                                    let peer_info = {
                                        let peers_map = peers.read().await;
                                        peers_map.get(&peer_id).and_then(|peer| {
                                            peer.try_lock().ok().map(|p| p.info().clone())
                                        })
                                    };
                                    
                                    let _ = response.send(Ok(peer_info));
                                },
                                PeerCommand::GetPeers(response) => {
                                    let peer_infos = {
                                        let peers_map = peers.read().await;
                                        peers_map.values().filter_map(|peer| {
                                            peer.try_lock().ok().map(|p| p.info().clone())
                                        }).collect::<Vec<_>>()
                                    };
                                    
                                    let _ = response.send(peer_infos);
                                },
                                PeerCommand::GetBannedPeers(response) => {
                                    let banned_list = {
                                        let banned = banned_peers.read().await;
                                        banned.keys().cloned().collect::<Vec<_>>()
                                    };
                                    
                                    let _ = response.send(banned_list);
                                },
                                PeerCommand::Ping(peer_id, response) => {
                                    let peer_opt = {
                                        let peers_map = peers.read().await;
                                        peers_map.get(&peer_id).cloned()
                                    };
                                    
                                    match peer_opt {
                                        Some(peer) => {
                                            let peer_guard = peer.lock().await;
                                            
                                            // Create ping message
                                            let ping_msg = match protocol.create_ping(node_id.clone()) {
                                                Ok(msg) => msg,
                                                Err(e) => {
                                                    let _ = response.send(Err(e));
                                                    continue;
                                                }
                                            };
                                            
                                            // Send ping and measure time
                                            let start = Instant::now();
                                            match peer_guard.send(ping_msg).await {
                                                Ok(()) => {
                                                    // We don't actually wait for the pong here, just measure send time
                                                    // The actual pong will be handled in the read task
                                                    let elapsed = start.elapsed().as_millis() as u64;
                                                    let _ = response.send(Ok(elapsed));
                                                },
                                                Err(e) => {
                                                    let _ = response.send(Err(e));
                                                }
                                            }
                                        },
                                        None => {
                                            let _ = response.send(Err(AevorError::network(format!("Peer not found: {}", hex::encode(&peer_id)))));
                                        }
                                    }
                                },
                            }
                        },
                        Ok(None) => {
                            // Channel closed
                            break;
                        },
                        Err(_) => {
                            // Timeout - check if we should continue running
                            if !*running.read().await {
                                break;
                            }
                        }
                    }
                }
            })
        };
        
        // Start the peer message processor task
        let message_task = {
            let peers = peers.clone();
            let event_handler = event_handler.clone();
            let topology_manager = topology_manager.clone();
            let running = running.clone();
            
            tokio::spawn(async move {
                let mut peer_message_receiver = peer_message_receiver;
                
                while *running.read().await {
                    match timeout(Duration::from_secs(1), peer_message_receiver.recv()).await {
                        Ok(Some(message)) => {
                            match message {
                                PeerMessage::Connected(peer_id, info) => {
                                    // Notify event handler
                                    if let Some(handler) = &event_handler {
                                        let _ = handler(PeerEvent::Connected(info.clone()));
                                    }
                                    
                                    // If topology manager exists, update peer region
                                    if let Some(topo) = &topology_manager {
                                        if let Some(region) = topo.get_region_for_address(&info.address).await {
                                            // Update peer info with region
                                            let peer_opt = {
                                                let peers_map = peers.read().await;
                                                peers_map.get(&peer_id).cloned()
                                            };
                                            
                                            if let Some(peer) = peer_opt {
                                                let mut peer_guard = peer.lock().await;
                                                peer_guard.info.region = Some(region);
                                            }
                                        }
                                    }
                                },
                                PeerMessage::Disconnected(peer_id, reason) => {
                                    // Get peer info before removing
                                    let peer_info = {
                                        let peers_map = peers.read().await;
                                        peers_map.get(&peer_id).and_then(|peer| {
                                            peer.try_lock().ok().map(|p| p.info().clone())
                                        })
                                    };
                                    
                                    // Remove the peer
                                    let peer_opt = {
                                        let mut peers_map = peers.write().await;
                                        if peer_id.is_empty() {
                                            // For peers without ID, find by matching empty ID
                                            let empty_key = peers_map.keys()
                                                .find(|k| k.is_empty())
                                                .cloned();
                                            
                                            if let Some(key) = empty_key {
                                                peers_map.remove(&key)
                                            } else {
                                                None
                                            }
                                        } else {
                                            peers_map.remove(&peer_id)
                                        }
                                    };
                                    
                                    // Stop the peer tasks
                                    if let Some(peer) = peer_opt {
                                        let mut peer_guard = peer.lock().await;
                                        let _ = peer_guard.stop().await;
                                    }
                                    
                                    // Notify event handler
                                    if let Some(handler) = &event_handler {
                                        if let Some(info) = peer_info {
                                            let _ = handler(PeerEvent::Disconnected(info.id, reason));
                                        } else if !peer_id.is_empty() {
                                            let _ = handler(PeerEvent::Disconnected(peer_id, reason));
                                        }
                                    }
                                },
                                PeerMessage::HandshakeCompleted(peer_id, info) => {
                                    // Check if the peer ID is already connected
                                    let peer_exists = {
                                        let peers_map = peers.read().await;
                                        peers_map.contains_key(&peer_id)
                                    };
                                    
                                    if peer_exists && !peer_id.is_empty() {
                                        // This peer ID is already connected, disconnect the new one
                                        let peer_opt = {
                                            let mut peers_map = peers.write().await;
                                            // Find the peer with empty ID
                                            let empty_key = peers_map.keys()
                                                .find(|k| k.is_empty())
                                                .cloned();
                                            
                                            if let Some(key) = empty_key {
                                                peers_map.remove(&key)
                                            } else {
                                                None
                                            }
                                        };
                                        
                                        // Stop the peer tasks
                                        if let Some(peer) = peer_opt {
                                            let mut peer_guard = peer.lock().await;
                                            let _ = peer_guard.stop().await;
                                        }
                                        
                                        continue;
                                    }
                                    
                                    // Check if the peer is banned
                                    let is_banned = {
                                        let banned = banned_peers.read().await;
                                        banned.contains_key(&peer_id) && banned.get(&peer_id).unwrap() > Instant::now()
                                    };
                                    
                                    if is_banned && !peer_id.is_empty() {
                                        // This peer is banned, disconnect it
                                        let peer_opt = {
                                            let mut peers_map = peers.write().await;
                                            // Find the peer with empty ID
                                            let empty_key = peers_map.keys()
                                                .find(|k| k.is_empty())
                                                .cloned();
                                            
                                            if let Some(key) = empty_key {
                                                peers_map.remove(&key)
                                            } else {
                                                None
                                            }
                                        };
                                        
                                        // Stop the peer tasks
                                        if let Some(peer) = peer_opt {
                                            let mut peer_guard = peer.lock().await;
                                            let _ = peer_guard.stop().await;
                                        }
                                        
                                        continue;
                                    }
                                    
                                    // Move the peer from empty ID to actual ID
                                    if !peer_id.is_empty() {
                                        let peer_opt = {
                                            let mut peers_map = peers.write().await;
                                            // Find the peer with empty ID
                                            let empty_key = peers_map.keys()
                                                .find(|k| k.is_empty())
                                                .cloned();
                                            
                                            if let Some(key) = empty_key {
                                                peers_map.remove(&key)
                                            } else {
                                                None
                                            }
                                        };
                                        
                                        // Insert with actual ID
                                        if let Some(peer) = peer_opt {
                                            let mut peer_guard = peer.lock().await;
                                            peer_guard.set_id(peer_id.clone());
                                            peer_guard.set_state(PeerState::Active);
                                            
                                            let mut peers_map = peers.write().await;
                                            peers_map.insert(peer_id.clone(), peer);
                                        }
                                    }
                                    
                                    // Notify event handler
                                    if let Some(handler) = &event_handler {
                                        let _ = handler(PeerEvent::HandshakeCompleted(info));
                                    }
                                },
                                PeerMessage::MessageReceived(peer_id, message) => {
                                    // We don't need to do anything here since the message handler is called directly
                                },
                                PeerMessage::Error(peer_id, error) => {
                                    // Notify event handler
                                    if let Some(handler) = &event_handler {
                                        let _ = handler(PeerEvent::Error(peer_id.clone(), error.to_string()));
                                    }
                                    
                                    // Disconnect the peer on error
                                    let (tx, _) = oneshot::channel();
                                    let _ = command_sender.send(PeerCommand::Disconnect(peer_id, tx)).await;
                                },
                            }
                        },
                        Ok(None) => {
                            // Channel closed
                            break;
                        },
                        Err(_) => {
                            // Timeout - check if we should continue running
                            if !*running.read().await {
                                break;
                            }
                        }
                    }
                }
            })
        };
        
        // Start the cleanup task (remove expired bans, check peer timeouts)
        let cleanup_task = {
            let banned_peers = banned_peers.clone();
            let banned_addresses = banned_addresses.clone();
            let peers = peers.clone();
            let command_sender = command_sender.clone();
            let running = running.clone();
            
            tokio::spawn(async move {
                while *running.read().await {
                    // Sleep for a while
                    sleep(Duration::from_secs(60)).await;
                    
                    // Remove expired bans
                    {
                        let mut banned = banned_peers.write().await;
                        banned.retain(|_, expiry| *expiry > Instant::now());
                    }
                    
                    {
                        let mut banned = banned_addresses.write().await;
                        banned.retain(|_, expiry| *expiry > Instant::now());
                    }
                    
                    // Check for peer timeouts (no messages received for a long time)
                    let timeout_peers = {
                        let peers_map = peers.read().await;
                        peers_map.iter()
                            .filter_map(|(id, peer)| {
                                if let Ok(guard) = peer.try_lock() {
                                    let info = guard.info();
                                    // Timeout after 5 minutes of inactivity
                                    if info.last_seen.elapsed() > Duration::from_secs(5 * 60) {
                                        return Some(id.clone());
                                    }
                                }
                                None
                            })
                            .collect::<Vec<_>>()
                    };
                    
                    // Disconnect timeout peers
                    for peer_id in timeout_peers {
                        let (tx, _) = oneshot::channel();
                        let _ = command_sender.send(PeerCommand::Disconnect(peer_id, tx)).await;
                    }
                }
            })
        };
        
        // Store tasks
        self.tasks.push(listener_task);
        self.tasks.push(command_task);
        self.tasks.push(message_task);
        self.tasks.push(cleanup_task);
        
        *running = true;
        Ok(())
    }
    
    /// Stops the peer manager
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        *running = false;
        
        // Disconnect all peers
        let peer_ids = {
            let peers_map = self.peers.read().await;
            peers_map.keys().cloned().collect::<Vec<_>>()
        };
        
        for peer_id in peer_ids {
            let (tx, _) = oneshot::channel();
            let _ = self.command_sender.send(PeerCommand::Disconnect(peer_id, tx)).await;
        }
        
        // Wait for tasks to complete (with timeout)
        for task in &self.tasks {
            let _ = timeout(Duration::from_secs(5), task).await;
        }
        
        Ok(())
    }
    
    /// Connects to a peer
    pub async fn connect(&self, address: SocketAddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::Connect(address, tx)).await
            .map_err(|_| AevorError::network("Failed to send connect command"))?;
        
        rx.await.map_err(|_| AevorError::network("Connect response channel closed"))?
    }
    
    /// Disconnects from a peer
    pub async fn disconnect(&self, peer_id: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::Disconnect(peer_id, tx)).await
            .map_err(|_| AevorError::network("Failed to send disconnect command"))?;
        
        rx.await.map_err(|_| AevorError::network("Disconnect response channel closed"))?
    }
    
    /// Sends a message to a specific peer
    pub async fn send_to_peer(&self, peer_id: Vec<u8>, message: Message) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::SendMessage(peer_id, message, tx)).await
            .map_err(|_| AevorError::network("Failed to send message command"))?;
        
        rx.await.map_err(|_| AevorError::network("Send message response channel closed"))?
    }
    
    /// Broadcasts a message to all peers
    pub async fn broadcast(&self, message: Message) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::Broadcast(message, tx)).await
            .map_err(|_| AevorError::network("Failed to send broadcast command"))?;
        
        rx.await.map_err(|_| AevorError::network("Broadcast response channel closed"))?
    }
    
    /// Bans a peer for a specified duration
    pub async fn ban_peer(&self, peer_id: Vec<u8>, duration: Duration) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::Ban(peer_id, duration, tx)).await
            .map_err(|_| AevorError::network("Failed to send ban command"))?;
        
        rx.await.map_err(|_| AevorError::network("Ban response channel closed"))?
    }
    
    /// Unbans a peer
    pub async fn unban_peer(&self, peer_id: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::Unban(peer_id, tx)).await
            .map_err(|_| AevorError::network("Failed to send unban command"))?;
        
        rx.await.map_err(|_| AevorError::network("Unban response channel closed"))?
    }
    
    /// Gets information about a specific peer
    pub async fn get_peer(&self, peer_id: Vec<u8>) -> Result<Option<PeerInfo>> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::GetPeer(peer_id, tx)).await
            .map_err(|_| AevorError::network("Failed to send get peer command"))?;
        
        rx.await.map_err(|_| AevorError::network("Get peer response channel closed"))?
    }
    
    /// Gets information about all peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = oneshot::channel();
        if let Err(_) = self.command_sender.send(PeerCommand::GetPeers(tx)).await {
            return Vec::new();
        }
        
        rx.await.unwrap_or_default()
    }
    
    /// Gets the number of connected peers
    pub async fn peer_count(&self) -> usize {
        let peers_map = self.peers.read().await;
        peers_map.len()
    }
    
    /// Gets a list of banned peers
    pub async fn get_banned_peers(&self) -> Vec<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        if let Err(_) = self.command_sender.send(PeerCommand::GetBannedPeers(tx)).await {
            return Vec::new();
        }
        
        rx.await.unwrap_or_default()
    }
    
    /// Sends a ping to a peer and returns the round-trip time
    pub async fn ping(&self, peer_id: Vec<u8>) -> Result<u64> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(PeerCommand::Ping(peer_id, tx)).await
            .map_err(|_| AevorError::network("Failed to send ping command"))?;
        
        rx.await.map_err(|_| AevorError::network("Ping response channel closed"))?
    }
    
    /// Gets the command sender
    pub fn command_sender(&self) -> mpsc::Sender<PeerCommand> {
        self.command_sender.clone()
    }
    
    /// Gets the peer message sender
    pub fn peer_message_sender(&self) -> mpsc::Sender<PeerMessage> {
        self.peer_message_sender.clone()
    }
    
    /// Gets the protocol handler
    pub fn protocol(&self) -> Arc<Protocol> {
        self.protocol.clone()
    }
    
    /// Gets the node ID
    pub fn node_id(&self) -> &[u8] {
        &self.node_id
    }
    
    /// Checks if this node is a validator
    pub fn is_validator(&self) -> bool {
        self.is_validator
    }
    
    /// Gets the peer manager stats
    pub fn stats(&self) -> &PeerManagerStats {
        &self.stats
    }
    
    /// Updates peer manager stats
    fn update_stats(&mut self, incoming_connections: Option<usize>, outgoing_connections: Option<usize>,
                    failed_connections: Option<usize>, handshake_failures: Option<usize>,
                    messages_sent: Option<usize>, messages_received: Option<usize>,
                    peers_banned: Option<usize>, peers_disconnected: Option<usize>) {
        if let Some(val) = incoming_connections {
            self.stats.incoming_connections = val;
        }
        
        if let Some(val) = outgoing_connections {
            self.stats.outgoing_connections = val;
        }
        
        if let Some(val) = failed_connections {
            self.stats.failed_connections = val;
        }
        
        if let Some(val) = handshake_failures {
            self.stats.handshake_failures = val;
        }
        
        if let Some(val) = messages_sent {
            self.stats.messages_sent = val;
        }
        
        if let Some(val) = messages_received {
            self.stats.messages_received = val;
        }
        
        if let Some(val) = peers_banned {
            self.stats.peers_banned = val;
        }
        
        if let Some(val) = peers_disconnected {
            self.stats.peers_disconnected = val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    
    // Test helpers
    fn create_test_config() -> Arc<NetworkConfig> {
        Arc::new(NetworkConfig {
            listen_addr: "127.0.0.1".to_string(),
            p2p_port: 0, // Use 0 to get a random available port
            enable_upnp: false,
            bootstrap_nodes: Vec::new(),
            max_peers: 10,
            target_outbound_peers: 3,
            connection_timeout_secs: 5,
            discovery: crate::config::DiscoveryConfig {
                enabled: true,
                method: "kademlia".to_string(),
                interval_secs: 60,
                max_discovered_peers: 100,
                prefer_validators: true,
            },
            topology_optimization: true,
            topology_optimization_interval_secs: 300,
            enable_rdma_transport: false,
            rdma_port: None,
            rdma_buffer_size: 8192,
            enable_erasure_coding: false,
            erasure_coding_shard_count: 10,
            erasure_coding_total_count: 16,
            node_key_path: None,
            is_validator: false,
        })
    }
    
    // Implement our own message handler for testing
    struct TestProtocolHandler;
    
    impl ProtocolHandler for TestProtocolHandler {
        fn handle_message(&self, _sender: Vec<u8>, _message: Message) -> Result<()> {
            Ok(())
        }
        
        fn protocol_version(&self) -> ProtocolVersion {
            ProtocolVersion::V1
        }
    }
    
    #[tokio::test]
    async fn test_peer_manager_creation() {
        let config = create_test_config();
        let node_id = vec![1, 2, 3, 4];
        let protocol_version = ProtocolVersion::V1;
        
        let manager = PeerManager::new(
            config,
            node_id,
            protocol_version,
            false, // not a validator
        );
        
        assert!(manager.is_ok());
    }
    
    // Note: More comprehensive tests would require mock network connections
    // and are beyond the scope of this implementation
}
