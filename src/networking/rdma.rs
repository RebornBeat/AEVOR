use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio::time;

use crate::error::{AevorError, Result};
use crate::networking::topology::TopologyManager;
use crate::utils::metrics::Metrics;

/// Configuration for RDMA-style transport
#[derive(Debug, Clone)]
pub struct RdmaConfig {
    /// Listen IP address
    pub listen_addr: String,
    
    /// Port for RDMA communication
    pub port: u16,
    
    /// Maximum number of connections
    pub max_connections: usize,
    
    /// Buffer size for each connection
    pub buffer_size: usize,
    
    /// Connection timeout
    pub timeout: Duration,
}

/// RDMA-style transport for high-performance network communication
pub struct RdmaTransport {
    /// Transport configuration
    config: RdmaConfig,
    
    /// Connected endpoints
    endpoints: DashMap<Vec<u8>, Arc<RdmaEndpoint>>,
    
    /// Background task handles
    tasks: Mutex<Vec<JoinHandle<()>>>,
    
    /// Whether the transport is running
    running: RwLock<bool>,
    
    /// Topology manager for optimizing connections
    topology_manager: Arc<TopologyManager>,
    
    /// Metrics collection
    metrics: Option<Arc<Metrics>>,
    
    /// Connection semaphore to limit concurrent connections
    connection_semaphore: Arc<Semaphore>,
    
    /// Channel for sending connection events
    connection_sender: mpsc::Sender<ConnectionEvent>,
    
    /// Channel for receiving connection events
    connection_receiver: Mutex<mpsc::Receiver<ConnectionEvent>>,
    
    /// Message handlers
    message_handlers: RwLock<HashMap<u8, Arc<dyn MessageHandler + Send + Sync>>>,
}

impl RdmaTransport {
    /// Creates a new RDMA-style transport
    pub fn new(config: RdmaConfig, topology_manager: Arc<TopologyManager>) -> Result<Self> {
        let (connection_sender, connection_receiver) = mpsc::channel(100);
        
        Ok(Self {
            config: config.clone(),
            endpoints: DashMap::new(),
            tasks: Mutex::new(Vec::new()),
            running: RwLock::new(false),
            topology_manager,
            metrics: None,
            connection_semaphore: Arc::new(Semaphore::new(config.max_connections)),
            connection_sender,
            connection_receiver: Mutex::new(connection_receiver),
            message_handlers: RwLock::new(HashMap::new()),
        })
    }
    
    /// Starts the RDMA transport
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        // Start the listener task
        self.start_listener().await?;
        
        // Start the connection event processor
        self.start_connection_processor().await?;
        
        *running = true;
        Ok(())
    }
    
    /// Stops the RDMA transport
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
        
        // Close all connections
        self.close_all_connections().await?;
        
        *running = false;
        Ok(())
    }
    
    /// Starts the connection listener
    async fn start_listener(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| AevorError::network(format!("Failed to bind RDMA listener: {}", e)))?;
        
        let connection_sender = self.connection_sender.clone();
        let connection_semaphore = self.connection_semaphore.clone();
        let buffer_size = self.config.buffer_size;
        
        // Spawn the listener task
        let listener_task = tokio::spawn(async move {
            loop {
                // Wait for a connection
                let (socket, remote_addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::error!("Failed to accept RDMA connection: {}", e);
                        continue;
                    }
                };
                
                // Acquire a connection slot
                let permit = match connection_semaphore.clone().try_acquire() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!("Connection limit reached, rejecting connection from {}", remote_addr);
                        continue;
                    }
                };
                
                // Initialize the connection
                let connection_sender = connection_sender.clone();
                
                tokio::spawn(async move {
                    // The permit is dropped when this task completes
                    let _permit = permit;
                    
                    // Set socket options
                    if let Err(e) = socket.set_nodelay(true) {
                        tracing::warn!("Failed to set TCP_NODELAY: {}", e);
                    }
                    
                    // Handle the incoming connection
                    if let Err(e) = handle_incoming_connection(socket, remote_addr, buffer_size, connection_sender).await {
                        tracing::error!("Failed to handle incoming RDMA connection: {}", e);
                    }
                });
            }
        });
        
        let mut tasks = self.tasks.lock().await;
        tasks.push(listener_task);
        
        Ok(())
    }
    
    /// Starts the connection event processor
    async fn start_connection_processor(&self) -> Result<()> {
        let mut receiver = self.connection_receiver.lock().await;
        let rdma_transport = Arc::new(self.clone());
        
        let processor_task = tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    ConnectionEvent::Connected(endpoint) => {
                        rdma_transport.handle_connected_endpoint(endpoint).await;
                    }
                    ConnectionEvent::Disconnected(node_id) => {
                        rdma_transport.handle_disconnected_endpoint(node_id).await;
                    }
                    ConnectionEvent::Message(node_id, message_type, data) => {
                        rdma_transport.handle_message(node_id, message_type, data).await;
                    }
                }
            }
        });
        
        let mut tasks = self.tasks.lock().await;
        tasks.push(processor_task);
        
        Ok(())
    }
    
    /// Handles a connected endpoint
    async fn handle_connected_endpoint(&self, endpoint: Arc<RdmaEndpoint>) {
        let node_id = endpoint.node_id().to_vec();
        
        // Update the topology manager with the new connection
        if let Err(e) = self.topology_manager.add_connection(&node_id, endpoint.addr()).await {
            tracing::warn!("Failed to update topology with new connection: {}", e);
        }
        
        // Store the endpoint
        self.endpoints.insert(node_id.clone(), endpoint.clone());
        
        tracing::info!("RDMA connection established with node {}", hex::encode(&node_id));
    }
    
    /// Handles a disconnected endpoint
    async fn handle_disconnected_endpoint(&self, node_id: Vec<u8>) {
        // Remove the endpoint
        if self.endpoints.remove(&node_id).is_some() {
            // Update the topology manager
            if let Err(e) = self.topology_manager.remove_connection(&node_id).await {
                tracing::warn!("Failed to update topology after connection removal: {}", e);
            }
            
            tracing::info!("RDMA connection closed with node {}", hex::encode(&node_id));
        }
    }
    
    /// Handles a received message
    async fn handle_message(&self, node_id: Vec<u8>, message_type: u8, data: Vec<u8>) {
        // Find a handler for this message type
        let handlers = self.message_handlers.read().await;
        if let Some(handler) = handlers.get(&message_type) {
            // Handle the message
            if let Err(e) = handler.handle_message(&node_id, &data).await {
                tracing::warn!("Error handling RDMA message type {}: {}", message_type, e);
            }
        } else {
            tracing::warn!("No handler for RDMA message type {}", message_type);
        }
    }
    
    /// Connects to a remote endpoint
    pub async fn connect(&self, addr: SocketAddr, node_id: Vec<u8>) -> Result<Arc<RdmaEndpoint>> {
        if !self.is_running().await {
            return Err(AevorError::network("RDMA transport is not running"));
        }
        
        // Check if we're already connected
        if let Some(endpoint) = self.endpoints.get(&node_id) {
            return Ok(endpoint.clone());
        }
        
        // Acquire a connection slot
        let _permit = self.connection_semaphore.clone().acquire().await
            .map_err(|_| AevorError::network("Failed to acquire connection semaphore"))?;
        
        // Connect to the remote endpoint
        let socket = TcpStream::connect(addr).await
            .map_err(|e| AevorError::network(format!("Failed to connect to {}: {}", addr, e)))?;
        
        // Set socket options
        socket.set_nodelay(true)
            .map_err(|e| AevorError::network(format!("Failed to set TCP_NODELAY: {}", e)))?;
        
        // Create the endpoint
        let endpoint = Arc::new(RdmaEndpoint::new(
            socket,
            addr,
            node_id.clone(),
            self.config.buffer_size,
            self.connection_sender.clone(),
        ));
        
        // Start the endpoint
        endpoint.start().await?;
        
        // Store the endpoint
        self.endpoints.insert(node_id.clone(), endpoint.clone());
        
        // Update the topology manager
        self.topology_manager.add_connection(&node_id, addr).await?;
        
        tracing::info!("RDMA connection established with node {} at {}", hex::encode(&node_id), addr);
        
        Ok(endpoint)
    }
    
    /// Sends a message to a remote endpoint
    pub async fn send(&self, node_id: &[u8], message_type: u8, data: Vec<u8>) -> Result<()> {
        if !self.is_running().await {
            return Err(AevorError::network("RDMA transport is not running"));
        }
        
        // Find the endpoint
        let endpoint = self.endpoints.get(node_id)
            .ok_or_else(|| AevorError::network(format!("No RDMA connection to node {}", hex::encode(node_id))))?;
        
        // Send the message
        endpoint.send(message_type, data).await?;
        
        Ok(())
    }
    
    /// Broadcasts a message to all connected endpoints
    pub async fn broadcast(&self, message_type: u8, data: Vec<u8>) -> Result<()> {
        if !self.is_running().await {
            return Err(AevorError::network("RDMA transport is not running"));
        }
        
        // Collect all endpoints
        let endpoints: Vec<Arc<RdmaEndpoint>> = self.endpoints.iter()
            .map(|e| e.value().clone())
            .collect();
        
        // Send the message to all endpoints in parallel
        let results = stream::iter(endpoints)
            .map(|endpoint| {
                let data = data.clone();
                async move {
                    endpoint.send(message_type, data).await
                }
            })
            .buffer_unordered(10) // Process up to 10 sends concurrently
            .collect::<Vec<Result<()>>>()
            .await;
        
        // Check for errors
        let errors: Vec<String> = results.into_iter()
            .filter_map(|r| r.err().map(|e| e.to_string()))
            .collect();
        
        if !errors.is_empty() {
            return Err(AevorError::network(format!("Failed to broadcast to some nodes: {}", errors.join(", "))));
        }
        
        Ok(())
    }
    
    /// Closes a connection to a specific node
    pub async fn close_connection(&self, node_id: &[u8]) -> Result<()> {
        if let Some((_, endpoint)) = self.endpoints.remove(node_id) {
            endpoint.close().await?;
            
            // Update the topology manager
            self.topology_manager.remove_connection(node_id).await?;
            
            tracing::info!("RDMA connection closed with node {}", hex::encode(node_id));
        }
        
        Ok(())
    }
    
    /// Closes all connections
    pub async fn close_all_connections(&self) -> Result<()> {
        // Collect all node IDs
        let node_ids: Vec<Vec<u8>> = self.endpoints.iter()
            .map(|e| e.key().clone())
            .collect();
        
        // Close each connection
        for node_id in node_ids {
            if let Err(e) = self.close_connection(&node_id).await {
                tracing::warn!("Error closing connection to {}: {}", hex::encode(&node_id), e);
            }
        }
        
        Ok(())
    }
    
    /// Registers a message handler
    pub async fn register_handler(&self, message_type: u8, handler: Arc<dyn MessageHandler + Send + Sync>) {
        let mut handlers = self.message_handlers.write().await;
        handlers.insert(message_type, handler);
    }
    
    /// Checks if the transport is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
    
    /// Gets the number of active connections
    pub async fn connection_count(&self) -> usize {
        self.endpoints.len()
    }
    
    /// Gets information about all connections
    pub async fn get_connections(&self) -> Vec<RdmaConnectionInfo> {
        self.endpoints.iter()
            .map(|e| {
                let endpoint = e.value();
                RdmaConnectionInfo {
                    node_id: e.key().clone(),
                    addr: endpoint.addr(),
                    established_at: endpoint.established_at(),
                    bytes_sent: endpoint.bytes_sent(),
                    bytes_received: endpoint.bytes_received(),
                    latency_ms: endpoint.latency_ms(),
                }
            })
            .collect()
    }
    
    /// Sets metrics collection
    pub fn set_metrics(&mut self, metrics: Arc<Metrics>) {
        self.metrics = Some(metrics);
    }
}

impl Clone for RdmaTransport {
    fn clone(&self) -> Self {
        // Create a new channel for the clone
        let (connection_sender, connection_receiver) = mpsc::channel(100);
        
        Self {
            config: self.config.clone(),
            endpoints: DashMap::new(),
            tasks: Mutex::new(Vec::new()),
            running: RwLock::new(false),
            topology_manager: self.topology_manager.clone(),
            metrics: self.metrics.clone(),
            connection_semaphore: self.connection_semaphore.clone(),
            connection_sender,
            connection_receiver: Mutex::new(connection_receiver),
            message_handlers: RwLock::new(HashMap::new()),
        }
    }
}

/// RDMA endpoint for a single connection
pub struct RdmaEndpoint {
    /// TCP stream for the connection
    socket: Mutex<TcpStream>,
    
    /// Remote address
    addr: SocketAddr,
    
    /// Remote node ID
    node_id: Vec<u8>,
    
    /// Buffer size for messages
    buffer_size: usize,
    
    /// Whether the endpoint is running
    running: RwLock<bool>,
    
    /// Connection event sender
    connection_sender: mpsc::Sender<ConnectionEvent>,
    
    /// Message queue
    message_queue: Mutex<VecDeque<(u8, Vec<u8>)>>,
    
    /// Background task handles
    tasks: Mutex<Vec<JoinHandle<()>>>,
    
    /// Time when the connection was established
    established_at: Instant,
    
    /// Number of bytes sent
    bytes_sent: RwLock<u64>,
    
    /// Number of bytes received
    bytes_received: RwLock<u64>,
    
    /// Latest measured latency in milliseconds
    latency_ms: RwLock<u64>,
    
    /// Latest ping timestamp
    last_ping: RwLock<Option<Instant>>,
}

impl RdmaEndpoint {
    /// Creates a new RDMA endpoint
    pub fn new(
        socket: TcpStream,
        addr: SocketAddr,
        node_id: Vec<u8>,
        buffer_size: usize,
        connection_sender: mpsc::Sender<ConnectionEvent>,
    ) -> Self {
        Self {
            socket: Mutex::new(socket),
            addr,
            node_id,
            buffer_size,
            running: RwLock::new(false),
            connection_sender,
            message_queue: Mutex::new(VecDeque::new()),
            tasks: Mutex::new(Vec::new()),
            established_at: Instant::now(),
            bytes_sent: RwLock::new(0),
            bytes_received: RwLock::new(0),
            latency_ms: RwLock::new(0),
            last_ping: RwLock::new(None),
        }
    }
    
    /// Starts the endpoint
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        // Start the reader task
        self.start_reader().await?;
        
        // Start the writer task
        self.start_writer().await?;
        
        // Start the ping task
        self.start_ping().await?;
        
        *running = true;
        
        // Notify about the connection
        self.connection_sender.send(ConnectionEvent::Connected(Arc::new(self.clone()))).await
            .map_err(|_| AevorError::network("Failed to send connection event"))?;
        
        Ok(())
    }
    
    /// Starts the reader task
    async fn start_reader(&self) -> Result<()> {
        let node_id = self.node_id.clone();
        let buffer_size = self.buffer_size;
        let connection_sender = self.connection_sender.clone();
        let bytes_received = self.bytes_received.clone();
        
        let mut socket = self.socket.lock().await;
        let (read_half, _) = socket.split();
        let read_half = Arc::new(tokio::sync::Mutex::new(read_half));
        
        let reader_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; buffer_size];
            let mut read_half = read_half.lock().await;
            
            loop {
                // Read the message header (type and length)
                let mut header = [0u8; 5]; // 1 byte for type, 4 bytes for length
                match read_half.read_exact(&mut header).await {
                    Ok(_) => {},
                    Err(e) => {
                        tracing::error!("Failed to read message header: {}", e);
                        break;
                    }
                }
                
                // Parse the header
                let message_type = header[0];
                let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
                
                // Check if the message is too large
                if length > buffer_size {
                    tracing::error!("Message too large: {} bytes", length);
                    break;
                }
                
                // Read the message body
                let mut message_buffer = if length <= buffer.len() {
                    &mut buffer[..length]
                } else {
                    // Allocate a larger buffer if needed
                    buffer = vec![0u8; length];
                    &mut buffer
                };
                
                match read_half.read_exact(&mut message_buffer).await {
                    Ok(_) => {},
                    Err(e) => {
                        tracing::error!("Failed to read message body: {}", e);
                        break;
                    }
                }
                
                // Update bytes received counter
                let mut bytes_received = bytes_received.write().await;
                *bytes_received += (5 + length) as u64;
                
                // Handle the message
                if message_type == MessageType::Ping as u8 {
                    // Respond to ping with a pong
                    if let Err(e) = connection_sender.send(ConnectionEvent::Message(
                        node_id.clone(),
                        MessageType::Pong as u8,
                        message_buffer.to_vec(),
                    )).await {
                        tracing::error!("Failed to send ping response: {}", e);
                        break;
                    }
                } else if message_type == MessageType::Pong as u8 {
                    // Process pong response
                    if message_buffer.len() >= 8 {
                        let timestamp_bytes = [
                            message_buffer[0], message_buffer[1], message_buffer[2], message_buffer[3],
                            message_buffer[4], message_buffer[5], message_buffer[6], message_buffer[7],
                        ];
                        let timestamp = u64::from_be_bytes(timestamp_bytes);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let latency = now.saturating_sub(timestamp);
                        
                        // Update latency
                        let mut latency_ms = connection_sender.latency_ms.write().await;
                        *latency_ms = latency;
                    }
                } else {
                    // Regular message, forward to handler
                    if let Err(e) = connection_sender.send(ConnectionEvent::Message(
                        node_id.clone(),
                        message_type,
                        message_buffer[..length].to_vec(),
                    )).await {
                        tracing::error!("Failed to forward message: {}", e);
                        break;
                    }
                }
            }
            
            // Connection closed
            if let Err(e) = connection_sender.send(ConnectionEvent::Disconnected(node_id)).await {
                tracing::error!("Failed to send disconnection event: {}", e);
            }
        });
        
        let mut tasks = self.tasks.lock().await;
        tasks.push(reader_task);
        
        Ok(())
    }
    
    /// Starts the writer task
    async fn start_writer(&self) -> Result<()> {
        let message_queue = self.message_queue.clone();
        let bytes_sent = self.bytes_sent.clone();
        
        let mut socket = self.socket.lock().await;
        let (_, write_half) = socket.split();
        let write_half = Arc::new(tokio::sync::Mutex::new(write_half));
        
        let writer_task = tokio::spawn(async move {
            loop {
                // Wait for a message to send
                let mut queue = message_queue.lock().await;
                if queue.is_empty() {
                    // No messages, wait for a bit
                    drop(queue);
                    time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                
                let (message_type, data) = queue.pop_front().unwrap();
                drop(queue);
                
                let mut write_half = write_half.lock().await;
                
                // Write the message header (type and length)
                let length = data.len() as u32;
                let length_bytes = length.to_be_bytes();
                let header = [message_type, length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3]];
                
                if let Err(e) = write_half.write_all(&header).await {
                    tracing::error!("Failed to write message header: {}", e);
                    break;
                }
                
                // Write the message body
                if let Err(e) = write_half.write_all(&data).await {
                    tracing::error!("Failed to write message body: {}", e);
                    break;
                }
                
                // Update bytes sent counter
                let mut bytes_sent = bytes_sent.write().await;
                *bytes_sent += (5 + data.len()) as u64;
            }
        });
        
        let mut tasks = self.tasks.lock().await;
        tasks.push(writer_task);
        
        Ok(())
    }
    
    /// Starts the ping task
    async fn start_ping(&self) -> Result<()> {
        let node_id = self.node_id.clone();
        let message_queue = self.message_queue.clone();
        let last_ping = self.last_ping.clone();
        
        let ping_task = tokio::spawn(async move {
            let ping_interval = Duration::from_secs(10);
            
            loop {
                // Sleep for the ping interval
                time::sleep(ping_interval).await;
                
                // Send a ping message
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let timestamp_bytes = now.to_be_bytes();
                
                // Queue the ping message
                let mut queue = message_queue.lock().await;
                queue.push_back((MessageType::Ping as u8, timestamp_bytes.to_vec()));
                
                // Update last ping timestamp
                let mut last_ping = last_ping.write().await;
                *last_ping = Some(Instant::now());
            }
        });
        
        let mut tasks = self.tasks.lock().await;
        tasks.push(ping_task);
        
        Ok(())
    }
    
    /// Sends a message through this endpoint
    pub async fn send(&self, message_type: u8, data: Vec<u8>) -> Result<()> {
        let mut queue = self.message_queue.lock().await;
        queue.push_back((message_type, data));
        Ok(())
    }
    
    /// Closes the endpoint
    pub async fn close(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        // Abort all tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        
        // Close the socket
        let mut socket = self.socket.lock().await;
        let _ = socket.shutdown().await;
        
        *running = false;
        Ok(())
    }
    
    /// Gets the remote node ID
    pub fn node_id(&self) -> &[u8] {
        &self.node_id
    }
    
    /// Gets the remote address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    
    /// Gets the time when the connection was established
    pub fn established_at(&self) -> Instant {
        self.established_at
    }
    
    /// Gets the number of bytes sent
    pub fn bytes_sent(&self) -> u64 {
        *self.bytes_sent.blocking_read()
    }
    
    /// Gets the number of bytes received
    pub fn bytes_received(&self) -> u64 {
        *self.bytes_received.blocking_read()
    }
    
    /// Gets the latest measured latency in milliseconds
    pub fn latency_ms(&self) -> u64 {
        *self.latency_ms.blocking_read()
    }
}

impl Clone for RdmaEndpoint {
    fn clone(&self) -> Self {
        // This is a shallow clone that doesn't include the TCP stream
        // It's used for creating references to the endpoint
        Self {
            socket: Mutex::new(TcpStream::from_std(std::net::TcpStream::connect(self.addr).unwrap()).unwrap()),
            addr: self.addr,
            node_id: self.node_id.clone(),
            buffer_size: self.buffer_size,
            running: RwLock::new(false),
            connection_sender: self.connection_sender.clone(),
            message_queue: Mutex::new(VecDeque::new()),
            tasks: Mutex::new(Vec::new()),
            established_at: self.established_at,
            bytes_sent: RwLock::new(0),
            bytes_received: RwLock::new(0),
            latency_ms: RwLock::new(0),
            last_ping: RwLock::new(None),
        }
    }
}

/// Handle incoming connection
async fn handle_incoming_connection(
    mut socket: TcpStream,
    remote_addr: SocketAddr,
    buffer_size: usize,
    connection_sender: mpsc::Sender<ConnectionEvent>,
) -> Result<()> {
    // Read the handshake
    let mut handshake = [0u8; 4];
    socket.read_exact(&mut handshake).await
        .map_err(|e| AevorError::network(format!("Failed to read handshake: {}", e)))?;
    
    // Verify the handshake
    if handshake != *b"RDMA" {
        return Err(AevorError::network("Invalid handshake"));
    }
    
    // Read the node ID length
    let mut node_id_len = [0u8; 4];
    socket.read_exact(&mut node_id_len).await
        .map_err(|e| AevorError::network(format!("Failed to read node ID length: {}", e)))?;
    
    let node_id_len = u32::from_be_bytes(node_id_len) as usize;
    if node_id_len == 0 || node_id_len > 1024 {
        return Err(AevorError::network(format!("Invalid node ID length: {}", node_id_len)));
    }
    
    // Read the node ID
    let mut node_id = vec![0u8; node_id_len];
    socket.read_exact(&mut node_id).await
        .map_err(|e| AevorError::network(format!("Failed to read node ID: {}", e)))?;
    
    // Create and start the endpoint
    let endpoint = Arc::new(RdmaEndpoint::new(
        socket,
        remote_addr,
        node_id.clone(),
        buffer_size,
        connection_sender.clone(),
    ));
    
    endpoint.start().await?;
    
    Ok(())
}

/// RDMA connection information
#[derive(Debug, Clone)]
pub struct RdmaConnectionInfo {
    /// Remote node ID
    pub node_id: Vec<u8>,
    
    /// Remote address
    pub addr: SocketAddr,
    
    /// Time when the connection was established
    pub established_at: Instant,
    
    /// Number of bytes sent
    pub bytes_sent: u64,
    
    /// Number of bytes received
    pub bytes_received: u64,
    
    /// Latest measured latency in milliseconds
    pub latency_ms: u64,
}

/// RDMA connection
pub struct RdmaConnection {
    /// Local endpoint
    endpoint: Arc<RdmaEndpoint>,
    
    /// Connection info
    info: RdmaConnectionInfo,
}

impl RdmaConnection {
    /// Creates a new RDMA connection
    pub fn new(endpoint: Arc<RdmaEndpoint>) -> Self {
        let info = RdmaConnectionInfo {
            node_id: endpoint.node_id().to_vec(),
            addr: endpoint.addr(),
            established_at: endpoint.established_at(),
            bytes_sent: endpoint.bytes_sent(),
            bytes_received: endpoint.bytes_received(),
            latency_ms: endpoint.latency_ms(),
        };
        
        Self {
            endpoint,
            info,
        }
    }
    
    /// Sends a message through this connection
    pub async fn send(&self, message_type: u8, data: Vec<u8>) -> Result<()> {
        self.endpoint.send(message_type, data).await
    }
    
    /// Gets the connection info
    pub fn info(&self) -> &RdmaConnectionInfo {
        &self.info
    }
    
    /// Updates the connection info
    pub fn update_info(&mut self) {
        self.info = RdmaConnectionInfo {
            node_id: self.endpoint.node_id().to_vec(),
            addr: self.endpoint.addr(),
            established_at: self.endpoint.established_at(),
            bytes_sent: self.endpoint.bytes_sent(),
            bytes_received: self.endpoint.bytes_received(),
            latency_ms: self.endpoint.latency_ms(),
        };
    }
    
    /// Gets the remote node ID
    pub fn node_id(&self) -> &[u8] {
        self.endpoint.node_id()
    }
    
    /// Gets the remote address
    pub fn addr(&self) -> SocketAddr {
        self.endpoint.addr()
    }
}

/// Connection event
#[derive(Debug)]
enum ConnectionEvent {
    /// New connection established
    Connected(Arc<RdmaEndpoint>),
    
    /// Connection closed
    Disconnected(Vec<u8>),
    
    /// Message received
    Message(Vec<u8>, u8, Vec<u8>),
}

/// Message type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Ping message for latency measurement
    Ping = 0,
    
    /// Pong response to ping
    Pong = 1,
    
    /// Data message
    Data = 2,
    
    /// Control message
    Control = 3,
    
    /// Custom message type
    Custom = 255,
}

/// Message handler trait
#[async_trait::async_trait]
pub trait MessageHandler {
    /// Handles a message
    async fn handle_message(&self, sender: &[u8], data: &[u8]) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    
    // Helper to create a test topology manager
    fn create_test_topology_manager() -> Arc<TopologyManager> {
        let config = Arc::new(crate::config::NetworkConfig {
            topology_optimization: true,
            topology_optimization_interval_secs: 60,
            ..Default::default()
        });
        
        Arc::new(TopologyManager::new(config, vec![1, 2, 3, 4]).unwrap())
    }
    
    #[tokio::test]
    async fn test_rdma_config() {
        let config = RdmaConfig {
            listen_addr: "127.0.0.1".to_string(),
            port: 7778,
            max_connections: 10,
            buffer_size: 8192,
            timeout: Duration::from_secs(5),
        };
        
        assert_eq!(config.listen_addr, "127.0.0.1");
        assert_eq!(config.port, 7778);
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.buffer_size, 8192);
        assert_eq!(config.timeout, Duration::from_secs(5));
    }
    
    // Note: Full RDMA transport tests would require network mocks
    // The following test just verifies that the transport can be created
    #[tokio::test]
    async fn test_create_rdma_transport() {
        let config = RdmaConfig {
            listen_addr: "127.0.0.1".to_string(),
            port: 7778,
            max_connections: 10,
            buffer_size: 8192,
            timeout: Duration::from_secs(5),
        };
        
        let topology_manager = create_test_topology_manager();
        let result = RdmaTransport::new(config, topology_manager);
        
        assert!(result.is_ok());
    }
}
