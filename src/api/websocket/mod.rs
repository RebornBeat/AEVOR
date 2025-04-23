use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{WebSocketUpgrade, Extension};
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::api::ApiContext;
use crate::core::block::Block;
use crate::core::object::ObjectID;
use crate::core::transaction::Transaction;

/// Type of WebSocket subscription
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum SubscriptionType {
    /// Subscribe to new blocks
    NewBlocks,
    
    /// Subscribe to new transactions
    NewTransactions,
    
    /// Subscribe to validator updates
    ValidatorUpdates,
    
    /// Subscribe to chain status updates
    ChainStatus,
    
    /// Subscribe to a specific block by hash
    Block(String),
    
    /// Subscribe to a specific transaction by hash
    Transaction(String),
    
    /// Subscribe to a specific object by ID
    Object(String),
}

/// WebSocket subscription request
#[derive(Debug, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    /// The subscription action (subscribe/unsubscribe)
    pub action: String,
    
    /// The subscription type
    pub subscription: SubscriptionType,
}

/// WebSocket event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketEvent {
    /// The event type
    pub event_type: String,
    
    /// The subscription type that triggered this event
    pub subscription: SubscriptionType,
    
    /// The event data
    pub data: serde_json::Value,
    
    /// The event timestamp
    pub timestamp: u64,
}

/// WebSocket client
#[derive(Debug)]
struct Client {
    /// The client ID
    id: String,
    
    /// The client's subscriptions
    subscriptions: Vec<SubscriptionType>,
    
    /// The last activity timestamp
    last_activity: Instant,
}

/// WebSocket server for the Aevor blockchain
#[derive(Clone)]
pub struct WebSocketServer {
    /// The server context
    context: ApiContext,
    
    /// Connected clients
    clients: Arc<RwLock<HashMap<String, Client>>>,
    
    /// Event broadcaster
    event_tx: broadcast::Sender<WebSocketEvent>,
    
    /// Client connection counter
    connection_count: Arc<RwLock<usize>>,
    
    /// Background tasks handles
    #[allow(dead_code)]
    tasks: Arc<RwLock<Vec<JoinHandle<()>>>>,
}

impl WebSocketServer {
    /// Create a new WebSocket server
    pub fn new(context: ApiContext) -> Self {
        // Create the event broadcast channel
        let (event_tx, _) = broadcast::channel(1000);
        
        let server = Self {
            context,
            clients: Arc::new(RwLock::new(HashMap::new())),
            event_tx: event_tx.clone(),
            connection_count: Arc::new(RwLock::new(0)),
            tasks: Arc::new(RwLock::new(Vec::new())),
        };
        
        // Start the cleanup task
        server.start_cleanup_task();
        
        server
    }
    
    /// Handle a new WebSocket connection
    pub async fn handle_connection(&self, socket: WebSocket) {
        // Generate a unique client ID
        let client_id = Uuid::new_v4().to_string();
        
        // Split the socket
        let (mut sender, mut receiver) = socket.split();
        
        // Create a new client
        let client = Client {
            id: client_id.clone(),
            subscriptions: Vec::new(),
            last_activity: Instant::now(),
        };
        
        // Add the client to the clients map
        {
            let mut clients = self.clients.write();
            clients.insert(client_id.clone(), client);
            
            // Update connection count
            let mut count = self.connection_count.write();
            *count += 1;
            
            info!("New WebSocket client connected: {} (total: {})", client_id, *count);
        }
        
        // Subscribe to events
        let mut event_rx = self.event_tx.subscribe();
        
        // Clone values for the receiver task
        let clients = self.clients.clone();
        let client_id_clone = client_id.clone();
        
        // Spawn task to handle incoming messages
        let receiver_task = tokio::spawn(async move {
            while let Some(result) = receiver.next().await {
                match result {
                    Ok(Message::Text(text)) => {
                        // Try to parse the message as a subscription request
                        match serde_json::from_str::<SubscriptionRequest>(&text) {
                            Ok(request) => {
                                // Handle the subscription request
                                match request.action.as_str() {
                                    "subscribe" => {
                                        // Add the subscription
                                        let mut clients = clients.write();
                                        if let Some(client) = clients.get_mut(&client_id_clone) {
                                            // Update last activity
                                            client.last_activity = Instant::now();
                                            
                                            // Add the subscription if it doesn't already exist
                                            if !client.subscriptions.contains(&request.subscription) {
                                                client.subscriptions.push(request.subscription.clone());
                                                debug!("Client {} subscribed to: {:?}", client_id_clone, request.subscription);
                                            }
                                        }
                                    },
                                    "unsubscribe" => {
                                        // Remove the subscription
                                        let mut clients = clients.write();
                                        if let Some(client) = clients.get_mut(&client_id_clone) {
                                            // Update last activity
                                            client.last_activity = Instant::now();
                                            
                                            // Remove the subscription
                                            client.subscriptions.retain(|s| s != &request.subscription);
                                            debug!("Client {} unsubscribed from: {:?}", client_id_clone, request.subscription);
                                        }
                                    },
                                    _ => {
                                        warn!("Unknown subscription action: {}", request.action);
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("Failed to parse subscription request: {}", e);
                            }
                        }
                    },
                    Ok(Message::Ping(ping)) => {
                        // Respond to ping with pong
                        if let Err(e) = sender.send(Message::Pong(ping)).await {
                            error!("Failed to send pong: {}", e);
                            break;
                        }
                        
                        // Update last activity
                        let mut clients = clients.write();
                        if let Some(client) = clients.get_mut(&client_id_clone) {
                            client.last_activity = Instant::now();
                        }
                    },
                    Ok(Message::Pong(_)) => {
                        // Update last activity
                        let mut clients = clients.write();
                        if let Some(client) = clients.get_mut(&client_id_clone) {
                            client.last_activity = Instant::now();
                        }
                    },
                    Ok(Message::Close(_)) => {
                        debug!("WebSocket client closed connection: {}", client_id_clone);
                        break;
                    },
                    Ok(Message::Binary(_)) => {
                        // We don't handle binary messages
                        warn!("Received unexpected binary message from client: {}", client_id_clone);
                    },
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                }
            }
            
            // Remove the client
            let mut clients = clients.write();
            clients.remove(&client_id_clone);
            
            // Update connection count
            let mut count = self.connection_count.write();
            *count = count.saturating_sub(1);
            
            info!("WebSocket client disconnected: {} (total: {})", client_id_clone, *count);
        });
        
        // Clone values for the sender task
        let clients = self.clients.clone();
        let client_id_clone = client_id.clone();
        
        // Spawn task to handle outgoing messages
        let sender_task = tokio::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                // Check if the client is subscribed to this event
                let subscribed = {
                    let clients = clients.read();
                    if let Some(client) = clients.get(&client_id_clone) {
                        // Check if the client is subscribed to this event
                        match &event.subscription {
                            SubscriptionType::NewBlocks => {
                                client.subscriptions.contains(&SubscriptionType::NewBlocks)
                            },
                            SubscriptionType::NewTransactions => {
                                client.subscriptions.contains(&SubscriptionType::NewTransactions)
                            },
                            SubscriptionType::ValidatorUpdates => {
                                client.subscriptions.contains(&SubscriptionType::ValidatorUpdates)
                            },
                            SubscriptionType::ChainStatus => {
                                client.subscriptions.contains(&SubscriptionType::ChainStatus)
                            },
                            SubscriptionType::Block(hash) => {
                                client.subscriptions.contains(&SubscriptionType::Block(hash.clone()))
                            },
                            SubscriptionType::Transaction(hash) => {
                                client.subscriptions.contains(&SubscriptionType::Transaction(hash.clone()))
                            },
                            SubscriptionType::Object(id) => {
                                client.subscriptions.contains(&SubscriptionType::Object(id.clone()))
                            },
                        }
                    } else {
                        false
                    }
                };
                
                if subscribed {
                    // Serialize the event
                    match serde_json::to_string(&event) {
                        Ok(json) => {
                            // Send the event
                            if let Err(e) = sender.send(Message::Text(json)).await {
                                error!("Failed to send event to client {}: {}", client_id_clone, e);
                                break;
                            }
                        },
                        Err(e) => {
                            error!("Failed to serialize event: {}", e);
                        }
                    }
                }
            }
        });
        
        // Spawn a task to join both tasks
        tokio::spawn(async move {
            // Wait for either task to complete
            tokio::select! {
                _ = receiver_task => {},
                _ = sender_task => {},
            }
        });
    }
    
    /// Broadcast an event to all subscribed clients
    pub fn broadcast_event(&self, event: WebSocketEvent) {
        // Send the event to all subscribers
        let _ = self.event_tx.send(event);
    }
    
    /// Broadcast a new block event
    pub fn broadcast_new_block(&self, block: &Block) {
        // Create the event data
        let data = serde_json::json!({
            "hash": hex::encode(block.hash()),
            "height": block.height(),
            "timestamp": block.timestamp(),
            "status": block.status(),
            "transaction_count": block.transaction_count(),
            "validator": hex::encode(block.validator()),
        });
        
        // Create the event
        let event = WebSocketEvent {
            event_type: "new_block".to_string(),
            subscription: SubscriptionType::NewBlocks,
            data,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Broadcast the event
        self.broadcast_event(event);
        
        // Also broadcast as a specific block event
        let block_hash = hex::encode(block.hash());
        let block_event = WebSocketEvent {
            event_type: "block_update".to_string(),
            subscription: SubscriptionType::Block(block_hash),
            data,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        self.broadcast_event(block_event);
    }
    
    /// Broadcast a new transaction event
    pub fn broadcast_new_transaction(&self, transaction: &Transaction) {
        // Create the event data
        let data = serde_json::json!({
            "hash": hex::encode(transaction.hash()),
            "sender": hex::encode(transaction.sender()),
            "nonce": transaction.nonce(),
            "status": transaction.status(),
            "transaction_type": transaction.transaction_type(),
            "security_level": transaction.security_level(),
        });
        
        // Create the event
        let event = WebSocketEvent {
            event_type: "new_transaction".to_string(),
            subscription: SubscriptionType::NewTransactions,
            data: data.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Broadcast the event
        self.broadcast_event(event);
        
        // Also broadcast as a specific transaction event
        let tx_hash = hex::encode(transaction.hash());
        let tx_event = WebSocketEvent {
            event_type: "transaction_update".to_string(),
            subscription: SubscriptionType::Transaction(tx_hash),
            data,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        self.broadcast_event(tx_event);
    }
    
    /// Broadcast a chain status update
    pub fn broadcast_chain_status(&self, status: &crate::api::handlers::ChainStatus) {
        // Create the event data
        let data = serde_json::json!(status);
        
        // Create the event
        let event = WebSocketEvent {
            event_type: "chain_status".to_string(),
            subscription: SubscriptionType::ChainStatus,
            data,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Broadcast the event
        self.broadcast_event(event);
    }
    
    /// Broadcast validator updates
    pub fn broadcast_validator_updates(&self, validators: &[crate::api::handlers::validator::ValidatorInfo]) {
        // Create the event data
        let data = serde_json::json!({
            "validators": validators,
        });
        
        // Create the event
        let event = WebSocketEvent {
            event_type: "validator_updates".to_string(),
            subscription: SubscriptionType::ValidatorUpdates,
            data,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Broadcast the event
        self.broadcast_event(event);
    }
    
    /// Broadcast an object update
    pub fn broadcast_object_update(&self, object_id: &ObjectID, data: serde_json::Value) {
        // Convert object ID to hex string
        let id_hex = hex::encode(&object_id.0);
        
        // Create the event
        let event = WebSocketEvent {
            event_type: "object_update".to_string(),
            subscription: SubscriptionType::Object(id_hex),
            data,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Broadcast the event
        self.broadcast_event(event);
    }
    
    /// Start a task to clean up inactive clients
    fn start_cleanup_task(&self) {
        let clients = self.clients.clone();
        let connection_count = self.connection_count.clone();
        
        // Spawn a task to clean up inactive clients
        let cleanup_task = tokio::spawn(async move {
            // Create an interval for cleanup
            let mut interval = interval(Duration::from_secs(60));
            
            loop {
                // Wait for the next interval
                interval.tick().await;
                
                // Get the current time
                let now = Instant::now();
                
                // Remove inactive clients
                let mut clients_to_remove = Vec::new();
                
                {
                    let clients_read = clients.read();
                    
                    // Find inactive clients
                    for (id, client) in clients_read.iter() {
                        // If the client has been inactive for more than 5 minutes, remove it
                        if now.duration_since(client.last_activity) > Duration::from_secs(300) {
                            clients_to_remove.push(id.clone());
                        }
                    }
                }
                
                // Remove the inactive clients
                if !clients_to_remove.is_empty() {
                    let mut clients_write = clients.write();
                    
                    for id in &clients_to_remove {
                        clients_write.remove(id);
                    }
                    
                    // Update connection count
                    let mut count = connection_count.write();
                    *count = count.saturating_sub(clients_to_remove.len());
                    
                    info!("Cleaned up {} inactive WebSocket clients (total: {})", clients_to_remove.len(), *count);
                }
            }
        });
        
        // Store the task handle
        let mut tasks = self.tasks.write();
        tasks.push(cleanup_task);
    }
    
    /// Get the number of connected clients
    pub fn get_connection_count(&self) -> usize {
        *self.connection_count.read()
    }
}

/// Handler for WebSocket upgrade requests
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(server): Extension<WebSocketServer>,
) -> impl IntoResponse {
    // Upgrade the connection to a WebSocket
    ws.on_upgrade(move |socket| async move {
        // Handle the WebSocket connection
        server.handle_connection(socket).await;
    })
}

/// Start the WebSocket server
pub async fn start_websocket_server(context: ApiContext, port: u16) -> Result<WebSocketServer, crate::error::AevorError> {
    // Create the WebSocket server
    let server = WebSocketServer::new(context);
    
    // Return the server
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    
    // Mock implementation for testing
    struct MockWebSocket {
        tx: mpsc::Sender<Message>,
        rx: mpsc::Receiver<Message>,
    }
    
    impl MockWebSocket {
        fn new() -> (Self, mpsc::Receiver<Message>, mpsc::Sender<Message>) {
            let (client_tx, server_rx) = mpsc::channel(100);
            let (server_tx, client_rx) = mpsc::channel(100);
            
            (
                Self {
                    tx: server_tx,
                    rx: server_rx,
                },
                client_rx,
                client_tx,
            )
        }
    }
    
    // More comprehensive tests would be included in a real implementation
}
