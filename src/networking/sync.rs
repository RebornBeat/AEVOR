use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex as TokioMutex, RwLock};
use tokio::time;

use crate::config::NetworkConfig;
use crate::core::{Block, Blockchain, Transaction, Object, ObjectID};
use crate::error::{AevorError, Result};
use crate::networking::peer::{PeerManager, PeerInfo};
use crate::networking::protocol::{Message, MessageType};
use crate::networking::topology::TopologyManager;

/// Sync state of the blockchain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Blockchain synchronization has not started
    Idle,
    
    /// Blockchain is currently syncing
    Syncing,
    
    /// Blockchain is synchronized
    Synchronized,
    
    /// Blockchain synchronization has failed
    Failed,
}

/// Request types for blockchain synchronization
#[derive(Debug, Clone)]
pub enum SyncRequest {
    /// Request for a specific block by hash
    GetBlock(Vec<u8>),
    
    /// Request for a specific block by height
    GetBlockByHeight(u64),
    
    /// Request for a range of blocks by height
    GetBlocks(u64, u64),
    
    /// Request for a specific transaction by hash
    GetTransaction(Vec<u8>),
    
    /// Request for a specific object by ID
    GetObject(ObjectID),
    
    /// Request for chain information
    GetChainInfo,
    
    /// Request for the latest blocks (useful for DAG synchronization)
    GetLatestBlocks(usize),
    
    /// Request for the latest transactions in a block
    GetBlockTransactions(Vec<u8>),
    
    /// Request for the uncorrupted chain (important for PoU consensus)
    GetUncorruptedChain,
    
    /// Request for superpositioned states of an object
    GetSuperpositionedStates(ObjectID),
}

/// Response types for blockchain synchronization
#[derive(Debug, Clone)]
pub enum SyncResponse {
    /// Response with a block
    Block(Block),
    
    /// Response with multiple blocks
    Blocks(Vec<Block>),
    
    /// Response with a transaction
    Transaction(Transaction),
    
    /// Response with multiple transactions
    Transactions(Vec<Transaction>),
    
    /// Response with an object
    Object(Object),
    
    /// Response with chain information
    ChainInfo {
        /// Latest block height
        height: u64,
        /// Latest block hash
        hash: Vec<u8>,
        /// Genesis block hash
        genesis_hash: Vec<u8>,
        /// Latest uncorrupted block hash
        uncorrupted_hash: Option<Vec<u8>>,
    },
    
    /// Response with the uncorrupted chain information
    UncorruptedChain {
        /// Chain identifier
        id: String,
        /// Block hashes in the uncorrupted chain
        block_hashes: Vec<Vec<u8>>,
        /// Latest block hash in the uncorrupted chain
        latest_hash: Vec<u8>,
        /// Latest block height in the uncorrupted chain
        latest_height: u64,
    },
    
    /// Response with the superpositioned states of an object
    SuperpositionedStates {
        /// Object ID
        id: ObjectID,
        /// Potential states and their hashes
        states: Vec<(Object, Vec<u8>)>,
        /// Validator confirmations for each state
        confirmations: Vec<HashMap<Vec<u8>, Vec<u8>>>,
    },
    
    /// No data found
    NotFound,
    
    /// Error response
    Error(String),
}

/// Represents a pending sync request
struct PendingSyncRequest {
    /// The request that was sent
    request: SyncRequest,
    
    /// The peer the request was sent to
    peer_id: Vec<u8>,
    
    /// When the request was sent
    sent_at: Instant,
    
    /// Whether a response was received
    response_received: bool,
    
    /// Number of retries
    retries: usize,
}

/// Configuration for the sync manager
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum number of blocks to request at once
    pub max_blocks_per_request: u32,
    
    /// Timeout for sync requests
    pub request_timeout: Duration,
    
    /// Interval for checking sync progress
    pub sync_check_interval: Duration,
    
    /// Maximum number of pending requests
    pub max_pending_requests: usize,
    
    /// Prioritize uncorrupted chains
    pub prioritize_uncorrupted_chains: bool,
    
    /// Maximum block queue size
    pub max_block_queue_size: usize,
    
    /// Maximum retries for a request
    pub max_request_retries: usize,
    
    /// Batch size for transaction processing
    pub transaction_batch_size: usize,
    
    /// Whether to verify blocks during sync
    pub verify_blocks_during_sync: bool,
    
    /// Whether to download objects during sync
    pub download_objects_during_sync: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_blocks_per_request: 50,
            request_timeout: Duration::from_secs(30),
            sync_check_interval: Duration::from_secs(5),
            max_pending_requests: 100,
            prioritize_uncorrupted_chains: true,
            max_block_queue_size: 1000,
            max_request_retries: 3,
            transaction_batch_size: 100,
            verify_blocks_during_sync: true,
            download_objects_during_sync: false,
        }
    }
}

/// Manager for blockchain synchronization
pub struct SyncManager {
    /// Network configuration
    config: Arc<NetworkConfig>,
    
    /// Sync-specific configuration
    sync_config: SyncConfig,
    
    /// Current sync state
    state: Arc<RwLock<SyncState>>,
    
    /// Reference to the blockchain
    blockchain: Arc<Blockchain>,
    
    /// Reference to the peer manager
    peer_manager: Option<Arc<PeerManager>>,
    
    /// Reference to the topology manager
    topology_manager: Option<Arc<TopologyManager>>,
    
    /// Pending sync requests
    pending_requests: Arc<TokioMutex<HashMap<String, PendingSyncRequest>>>,
    
    /// Queue of blocks to process
    block_queue: Arc<TokioMutex<VecDeque<Block>>>,
    
    /// Set of requested block hashes to avoid duplicates
    requested_blocks: Arc<RwLock<HashSet<Vec<u8>>>>,
    
    /// Set of requested transaction hashes to avoid duplicates
    requested_txs: Arc<RwLock<HashSet<Vec<u8>>>>,
    
    /// Set of requested object IDs to avoid duplicates
    requested_objects: Arc<RwLock<HashSet<ObjectID>>>,
    
    /// Latest known block height from peers
    latest_known_height: Arc<RwLock<u64>>,
    
    /// Local blockchain height
    local_height: Arc<RwLock<u64>>,
    
    /// Message channel for sending and receiving sync messages
    message_sender: mpsc::Sender<(String, Message)>,
    message_receiver: Arc<TokioMutex<mpsc::Receiver<(String, Message)>>>,
    
    /// Signal for shutdown
    shutdown: Arc<RwLock<bool>>,
    
    /// Background task handles
    _task_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl SyncManager {
    /// Creates a new sync manager
    pub fn new(
        config: Arc<NetworkConfig>,
        blockchain: Arc<Blockchain>,
        peer_manager: Arc<PeerManager>,
        topology_manager: Arc<TopologyManager>,
    ) -> Result<Self> {
        let sync_config = SyncConfig::default();
        let (message_sender, message_receiver) = mpsc::channel(1000);
        
        Ok(Self {
            config,
            sync_config,
            state: Arc::new(RwLock::new(SyncState::Idle)),
            blockchain,
            peer_manager: Some(peer_manager),
            topology_manager: Some(topology_manager),
            pending_requests: Arc::new(TokioMutex::new(HashMap::new())),
            block_queue: Arc::new(TokioMutex::new(VecDeque::new())),
            requested_blocks: Arc::new(RwLock::new(HashSet::new())),
            requested_txs: Arc::new(RwLock::new(HashSet::new())),
            requested_objects: Arc::new(RwLock::new(HashSet::new())),
            latest_known_height: Arc::new(RwLock::new(0)),
            local_height: Arc::new(RwLock::new(0)),
            message_sender,
            message_receiver: Arc::new(TokioMutex::new(message_receiver)),
            shutdown: Arc::new(RwLock::new(false)),
            _task_handles: Vec::new(),
        })
    }
    
    /// Creates a new sync manager with custom configuration
    pub fn with_config(
        config: Arc<NetworkConfig>,
        blockchain: Arc<Blockchain>,
        peer_manager: Arc<PeerManager>,
        topology_manager: Arc<TopologyManager>,
        sync_config: SyncConfig,
    ) -> Result<Self> {
        let (message_sender, message_receiver) = mpsc::channel(1000);
        
        Ok(Self {
            config,
            sync_config,
            state: Arc::new(RwLock::new(SyncState::Idle)),
            blockchain,
            peer_manager: Some(peer_manager),
            topology_manager: Some(topology_manager),
            pending_requests: Arc::new(TokioMutex::new(HashMap::new())),
            block_queue: Arc::new(TokioMutex::new(VecDeque::new())),
            requested_blocks: Arc::new(RwLock::new(HashSet::new())),
            requested_txs: Arc::new(RwLock::new(HashSet::new())),
            requested_objects: Arc::new(RwLock::new(HashSet::new())),
            latest_known_height: Arc::new(RwLock::new(0)),
            local_height: Arc::new(RwLock::new(0)),
            message_sender,
            message_receiver: Arc::new(TokioMutex::new(message_receiver)),
            shutdown: Arc::new(RwLock::new(false)),
            _task_handles: Vec::new(),
        })
    }
    
    /// Sets the peer manager
    pub fn set_peer_manager(&mut self, peer_manager: Arc<PeerManager>) {
        self.peer_manager = Some(peer_manager);
    }
    
    /// Sets the topology manager
    pub fn set_topology_manager(&mut self, topology_manager: Arc<TopologyManager>) {
        self.topology_manager = Some(topology_manager);
    }
    
    /// Sets the local blockchain height
    pub async fn set_local_height(&self, height: u64) {
        let mut local_height = self.local_height.write().await;
        *local_height = height;
    }
    
    /// Sets the sync configuration
    pub fn set_sync_config(&mut self, sync_config: SyncConfig) {
        self.sync_config = sync_config;
    }
    
    /// Starts the sync manager
    pub async fn start(&mut self) -> Result<()> {
        // Set the initial local height
        let height = self.blockchain.get_height().await?;
        self.set_local_height(height).await;
        
        // Create task handles for async tasks
        let mut task_handles = Vec::new();
        
        // Start the message processing task
        task_handles.push(self.spawn_message_processor());
        
        // Start the request timeout checker task
        task_handles.push(self.spawn_timeout_checker());
        
        // Start the block processor task
        task_handles.push(self.spawn_block_processor());
        
        // Start the sync progress checker task
        task_handles.push(self.spawn_sync_checker());
        
        // Store task handles
        self._task_handles = task_handles;
        
        Ok(())
    }
    
    /// Stops the sync manager
    pub async fn stop(&self) -> Result<()> {
        // Signal shutdown
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
        
        // Task handles will be dropped and joined automatically when Self is dropped
        
        Ok(())
    }
    
    /// Gets the current state of the sync manager
    pub async fn get_state(&self) -> SyncState {
        *self.state.read().await
    }
    
    /// Gets the latest known block height from peers
    pub async fn get_latest_known_height(&self) -> u64 {
        *self.latest_known_height.read().await
    }
    
    /// Gets the local blockchain height
    pub async fn get_local_height(&self) -> u64 {
        *self.local_height.read().await
    }
    
    /// Gets the next block from the queue
    pub async fn get_next_block(&self) -> Option<Block> {
        let mut block_queue = self.block_queue.lock().await;
        block_queue.pop_front()
    }
    
    /// Gets all blocks from the queue
    pub async fn get_all_blocks(&self) -> Vec<Block> {
        let mut block_queue = self.block_queue.lock().await;
        let blocks: Vec<Block> = block_queue.drain(..).collect();
        blocks
    }
    
    /// Handles an incoming message related to sync
    pub async fn handle_message(&self, peer_id: Vec<u8>, message: Message) -> Result<()> {
        // Create a unique ID for this request-response pair
        let peer_id_str = hex::encode(&peer_id);
        
        // Send the message to the message processor task
        self.message_sender.send((peer_id_str, message)).await
            .map_err(|e| AevorError::network(format!("Failed to send message to processor: {}", e)))?;
            
        Ok(())
    }
    
    /// Spawn the message processor task
    fn spawn_message_processor(&self) -> tokio::task::JoinHandle<()> {
        let message_receiver = self.message_receiver.clone();
        let pending_requests = self.pending_requests.clone();
        let block_queue = self.block_queue.clone();
        let blockchain = self.blockchain.clone();
        let requested_blocks = self.requested_blocks.clone();
        let requested_txs = self.requested_txs.clone();
        let requested_objects = self.requested_objects.clone();
        let latest_known_height = self.latest_known_height.clone();
        let local_height = self.local_height.clone();
        let state = self.state.clone();
        let shutdown = self.shutdown.clone();
        let sync_config = self.sync_config.clone();
        
        tokio::spawn(async move {
            tracing::debug!("Starting sync message processor task");
            
            loop {
                // Check shutdown signal
                if *shutdown.read().await {
                    break;
                }
                
                // Wait for messages
                let message_receiver_lock = message_receiver.lock().await;
                let message_result = tokio::time::timeout(
                    Duration::from_millis(100),
                    message_receiver_lock.recv(),
                ).await;
                
                drop(message_receiver_lock); // Release the lock
                
                // Process message if received
                if let Ok(Some((peer_id_str, message))) = message_result {
                    let mut pending_requests_lock = pending_requests.lock().await;
                    
                    // Process the message based on type
                    match message.message_type() {
                        MessageType::BlockResponse => {
                            if let Some(block) = message.get_block() {
                                tracing::trace!("Received block response: {}", hex::encode(block.hash()));
                                
                                // Check if we requested this block
                                let block_hash = block.hash();
                                let mut requested_blocks_lock = requested_blocks.write().await;
                                
                                if requested_blocks_lock.remove(&block_hash) {
                                    // Add the block to the queue
                                    let mut block_queue_lock = block_queue.lock().await;
                                    
                                    // Check if we've hit the block queue limit
                                    if block_queue_lock.len() < sync_config.max_block_queue_size {
                                        block_queue_lock.push_back(block.clone());
                                    } else {
                                        tracing::warn!("Block queue full, dropping block {}", hex::encode(&block_hash));
                                        // Re-add to requested blocks so we'll request it again
                                        requested_blocks_lock.insert(block_hash);
                                    }
                                    
                                    // Update latest known height if this block is newer
                                    let height = block.height();
                                    let mut latest_height = latest_known_height.write().await;
                                    if height > *latest_height {
                                        *latest_height = height;
                                    }
                                    
                                    // Mark any pending request for this block as completed
                                    for (request_id, request) in pending_requests_lock.iter_mut() {
                                        match &request.request {
                                            SyncRequest::GetBlock(hash) if hash == &block_hash => {
                                                request.response_received = true;
                                                tracing::trace!("Marked request {} as completed", request_id);
                                                break;
                                            }
                                            SyncRequest::GetBlockByHeight(h) if *h == height => {
                                                request.response_received = true;
                                                tracing::trace!("Marked request {} as completed", request_id);
                                                break;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        MessageType::BlocksResponse => {
                            if let Some(blocks) = message.get_blocks() {
                                tracing::trace!("Received blocks response with {} blocks", blocks.len());
                                
                                // Process each block
                                let mut requested_blocks_lock = requested_blocks.write().await;
                                let mut block_queue_lock = block_queue.lock().await;
                                let mut highest_height = 0;
                                
                                for block in blocks {
                                    let block_hash = block.hash();
                                    
                                    // Check if we requested this block or if it's new
                                    if requested_blocks_lock.remove(&block_hash) || !blockchain.has_block(&block_hash).await.unwrap_or(false) {
                                        // Update highest height
                                        let height = block.height();
                                        if height > highest_height {
                                            highest_height = height;
                                        }
                                        
                                        // Add to block queue if not full
                                        if block_queue_lock.len() < sync_config.max_block_queue_size {
                                            block_queue_lock.push_back(block.clone());
                                        } else {
                                            tracing::warn!("Block queue full, dropping block {}", hex::encode(&block_hash));
                                            // Re-add to requested blocks so we'll request it again
                                            requested_blocks_lock.insert(block_hash);
                                        }
                                    }
                                }
                                
                                // Update latest known height if we found a newer block
                                if highest_height > 0 {
                                    let mut latest_height = latest_known_height.write().await;
                                    if highest_height > *latest_height {
                                        *latest_height = highest_height;
                                    }
                                }
                                
                                // Mark any pending request for blocks as completed
                                for (request_id, request) in pending_requests_lock.iter_mut() {
                                    match &request.request {
                                        SyncRequest::GetBlocks(start_height, end_height) => {
                                            // Mark as completed if we received blocks that include this range
                                            if highest_height >= *end_height {
                                                request.response_received = true;
                                                tracing::trace!("Marked request {} as completed", request_id);
                                            }
                                        }
                                        SyncRequest::GetLatestBlocks(_) => {
                                            // Always mark as completed for GetLatestBlocks
                                            request.response_received = true;
                                            tracing::trace!("Marked request {} as completed", request_id);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        MessageType::TransactionResponse => {
                            if let Some(tx) = message.get_transaction() {
                                tracing::trace!("Received transaction response: {}", hex::encode(tx.hash()));
                                
                                // Check if we requested this transaction
                                let tx_hash = tx.hash();
                                let mut requested_txs_lock = requested_txs.write().await;
                                
                                if requested_txs_lock.remove(&tx_hash) {
                                    // Process the transaction
                                    // TODO: Handle transaction processing
                                    
                                    // Mark any pending request for this transaction as completed
                                    for (request_id, request) in pending_requests_lock.iter_mut() {
                                        match &request.request {
                                            SyncRequest::GetTransaction(hash) if hash == &tx_hash => {
                                                request.response_received = true;
                                                tracing::trace!("Marked request {} as completed", request_id);
                                                break;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        MessageType::TransactionsResponse => {
                            if let Some(txs) = message.get_transactions() {
                                tracing::trace!("Received transactions response with {} transactions", txs.len());
                                
                                // Process each transaction
                                let mut requested_txs_lock = requested_txs.write().await;
                                
                                for tx in txs {
                                    let tx_hash = tx.hash();
                                    
                                    if requested_txs_lock.remove(&tx_hash) {
                                        // Process the transaction
                                        // TODO: Handle transaction processing
                                    }
                                }
                                
                                // Mark any pending request for transactions as completed
                                for (request_id, request) in pending_requests_lock.iter_mut() {
                                    match &request.request {
                                        SyncRequest::GetBlockTransactions(block_hash) => {
                                            // Mark as completed if we specifically requested transactions for this block
                                            request.response_received = true;
                                            tracing::trace!("Marked request {} as completed", request_id);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        MessageType::ObjectResponse => {
                            if let Some(object) = message.get_object() {
                                let object_id = object.id().clone();
                                tracing::trace!("Received object response: {}", object_id);
                                
                                // Check if we requested this object
                                let mut requested_objects_lock = requested_objects.write().await;
                                
                                if requested_objects_lock.remove(&object_id) {
                                    // Process the object
                                    // TODO: Handle object processing
                                    
                                    // Mark any pending request for this object as completed
                                    for (request_id, request) in pending_requests_lock.iter_mut() {
                                        match &request.request {
                                            SyncRequest::GetObject(id) if id == &object_id => {
                                                request.response_received = true;
                                                tracing::trace!("Marked request {} as completed", request_id);
                                                break;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        MessageType::ChainInfoResponse => {
                            if let Some(info) = message.get_chain_info() {
                                tracing::trace!("Received chain info response: height={}", info.height);
                                
                                // Update latest known height if this info is newer
                                let mut latest_height = latest_known_height.write().await;
                                if info.height > *latest_height {
                                    *latest_height = info.height;
                                    
                                    // If we're significantly behind, change state to Syncing
                                    let current_height = *local_height.read().await;
                                    if info.height > current_height + 10 {
                                        let mut state_lock = state.write().await;
                                        if *state_lock != SyncState::Syncing {
                                            *state_lock = SyncState::Syncing;
                                            tracing::info!("Starting sync: local={}, remote={}", current_height, info.height);
                                        }
                                    }
                                }
                                
                                // Mark any pending request for chain info as completed
                                for (request_id, request) in pending_requests_lock.iter_mut() {
                                    if let SyncRequest::GetChainInfo = &request.request {
                                        request.response_received = true;
                                        tracing::trace!("Marked request {} as completed", request_id);
                                    }
                                }
                            }
                        }
                        MessageType::UncorruptedChainResponse => {
                            if let Some(chain) = message.get_uncorrupted_chain() {
                                tracing::trace!("Received uncorrupted chain response: id={}, blocks={}", 
                                    chain.id, chain.block_hashes.len());
                                
                                // Process the uncorrupted chain
                                // TODO: Handle uncorrupted chain processing
                                
                                // Mark any pending request for uncorrupted chain as completed
                                for (request_id, request) in pending_requests_lock.iter_mut() {
                                    if let SyncRequest::GetUncorruptedChain = &request.request {
                                        request.response_received = true;
                                        tracing::trace!("Marked request {} as completed", request_id);
                                    }
                                }
                            }
                        }
                        MessageType::SuperpositionedStatesResponse => {
                            if let Some(states) = message.get_superpositioned_states() {
                                tracing::trace!("Received superpositioned states response: {}", states.id);
                                
                                // Process the superpositioned states
                                // TODO: Handle superpositioned states processing
                                
                                // Mark any pending request for superpositioned states as completed
                                for (request_id, request) in pending_requests_lock.iter_mut() {
                                    if let SyncRequest::GetSuperpositionedStates(id) = &request.request {
                                        if id == &states.id {
                                            request.response_received = true;
                                            tracing::trace!("Marked request {} as completed", request_id);
                                        }
                                    }
                                }
                            }
                        }
                        MessageType::Error => {
                            if let Some(error) = message.get_error() {
                                tracing::warn!("Received error response from peer {}: {}", peer_id_str, error);
                            }
                        }
                        _ => {
                            // Ignore other message types
                        }
                    }
                }
                
                // Yield to other tasks
                tokio::task::yield_now().await;
            }
            
            tracing::debug!("Sync message processor task stopped");
        })
    }
    
    /// Spawn the request timeout checker task
    fn spawn_timeout_checker(&self) -> tokio::task::JoinHandle<()> {
        let pending_requests = self.pending_requests.clone();
        let peer_manager = self.peer_manager.clone();
        let topology_manager = self.topology_manager.clone();
        let shutdown = self.shutdown.clone();
        let request_timeout = self.sync_config.request_timeout;
        let max_request_retries = self.sync_config.max_request_retries;
        
        tokio::spawn(async move {
            tracing::debug!("Starting sync request timeout checker task");
            
            loop {
                // Check shutdown signal
                if *shutdown.read().await {
                    break;
                }
                
                // Check for timed-out requests every second
                tokio::time::sleep(Duration::from_secs(1)).await;
                
                // Get current time
                let now = Instant::now();
                
                // Get pending requests
                let mut pending_requests_lock = pending_requests.lock().await;
                let peer_manager = match &peer_manager {
                    Some(pm) => pm,
                    None => continue,
                };
                
                // Check each pending request for timeout
                let mut timed_out_requests = Vec::new();
                
                for (request_id, request) in pending_requests_lock.iter() {
                    // Skip requests that have received a response
                    if request.response_received {
                        timed_out_requests.push(request_id.clone());
                        continue;
                    }
                    
                    // Check if the request has timed out
                    if now.duration_since(request.sent_at) > request_timeout {
                        // If we've reached the maximum retries, remove the request
                        if request.retries >= max_request_retries {
                            tracing::warn!("Request {} to peer {} timed out after {} retries",
                                request_id, hex::encode(&request.peer_id), request.retries);
                            
                            timed_out_requests.push(request_id.clone());
                            
                            // Penalize the peer
                            if let Err(e) = peer_manager.report_peer_misbehavior(&request.peer_id, "sync_request_timeout").await {
                                tracing::warn!("Failed to report peer misbehavior: {}", e);
                            }
                        }
                        // Otherwise, we'll retry the request with a different peer
                        else {
                            timed_out_requests.push(request_id.clone());
                            
                            // Get original request to retry
                            let original_request = request.request.clone();
                            
                            // Retry with a different peer
                            if let Some(topology) = &topology_manager {
                                // Use topology to find a good peer
                                if let Ok(peers) = topology.get_best_peers_for_sync(5).await {
                                    // Filter out the peer that timed out
                                    let peer_id_to_avoid = request.peer_id.clone();
                                    let peers: Vec<PeerInfo> = peers.into_iter().filter(|p| p.id != peer_id_to_avoid).collect();
                                    
                                    if !peers.is_empty() {
                                        // Choose a random peer from the filtered list
                                        use rand::seq::SliceRandom;
                                        let mut rng = rand::thread_rng();
                                        
                                        if let Some(peer) = peers.choose(&mut rng) {
                                            // Send the retry request
                                            if let Err(e) = Self::send_sync_request_to_peer(
                                                peer_manager.clone(),
                                                pending_requests.clone(),
                                                peer.id.clone(),
                                                original_request,
                                                request.retries + 1,
                                            ).await {
                                                tracing::warn!("Failed to retry timed out request: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Remove all timed out requests
                for request_id in timed_out_requests {
                    pending_requests_lock.remove(&request_id);
                }
            }
            
            tracing::debug!("Sync request timeout checker task stopped");
        })
    }
    
    /// Spawn the block processor task
    fn spawn_block_processor(&self) -> tokio::task::JoinHandle<()> {
        let block_queue = self.block_queue.clone();
        let blockchain = self.blockchain.clone();
        let state = self.state.clone();
        let local_height = self.local_height.clone();
        let latest_known_height = self.latest_known_height.clone();
        let shutdown = self.shutdown.clone();
        let verify_blocks = self.sync_config.verify_blocks_during_sync;
        
        tokio::spawn(async move {
            tracing::debug!("Starting sync block processor task");
            
            loop {
                // Check shutdown signal
                if *shutdown.read().await {
                    break;
                }
                
                // Sleep to prevent CPU hogging
                tokio::time::sleep(Duration::from_millis(50)).await;
                
                // Process blocks in the queue
                let mut block_queue_lock = block_queue.lock().await;
                
                if let Some(block) = block_queue_lock.pop_front() {
                    // Release the lock while processing
                    drop(block_queue_lock);
                    
                    // Get the block hash and height
                    let block_hash = block.hash();
                    let block_height = block.height();
                    
                    // Check if we already have this block
                    if blockchain.has_block(&block_hash).await.unwrap_or(false) {
                        tracing::trace!("Block {} already exists, skipping", hex::encode(&block_hash));
                        continue;
                    }
                    
                    // Process the block
                    let result = if verify_blocks {
                        blockchain.process_block(block.clone()).await
                    } else {
                        blockchain.add_block_without_verification(block.clone()).await
                    };
                    
                    match result {
                        Ok(_) => {
                            tracing::debug!("Successfully processed block {} at height {}",
                                hex::encode(&block_hash), block_height);
                            
                            // Update local height
                            let mut local_height_lock = local_height.write().await;
                            if block_height > *local_height_lock {
                                *local_height_lock = block_height;
                                
                                // Check if we're caught up
                                let latest_height = *latest_known_height.read().await;
                                if *local_height_lock >= latest_height.saturating_sub(5) {
                                    let mut state_lock = state.write().await;
                                    if *state_lock == SyncState::Syncing {
                                        *state_lock = SyncState::Synchronized;
                                        tracing::info!("Sync complete: height={}", *local_height_lock);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to process block {}: {}", hex::encode(&block_hash), e);
                        }
                    }
                } else {
                    // No blocks to process, release the lock
                    drop(block_queue_lock);
                }
            }
            
            tracing::debug!("Sync block processor task stopped");
        })
    }
    
    /// Spawn the sync progress checker task
    fn spawn_sync_checker(&self) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        let local_height = self.local_height.clone();
        let latest_known_height = self.latest_known_height.clone();
        let blockchain = self.blockchain.clone();
        let peer_manager = self.peer_manager.clone();
        let sync_check_interval = self.sync_config.sync_check_interval;
        let shutdown = self.shutdown.clone();
        
        tokio::spawn(async move {
            tracing::debug!("Starting sync progress checker task");
            
            loop {
                // Check shutdown signal
                if *shutdown.read().await {
                    break;
                }
                
                // Sleep for the check interval
                tokio::time::sleep(sync_check_interval).await;
                
                // Check sync progress
                let current_state = *state.read().await;
                let current_height = *local_height.read().await;
                let latest_height = *latest_known_height.read().await;
                
                match current_state {
                    SyncState::Idle => {
                        // Check if we need to start syncing
                        if latest_height > current_height + 10 {
                            // Start syncing
                            let mut state_lock = state.write().await;
                            *state_lock = SyncState::Syncing;
                            tracing::info!("Starting sync: local={}, remote={}", current_height, latest_height);
                        }
                    }
                    SyncState::Syncing => {
                        // Check if we've caught up
                        if current_height >= latest_height.saturating_sub(5) {
                            let mut state_lock = state.write().await;
                            *state_lock = SyncState::Synchronized;
                            tracing::info!("Sync complete: height={}", current_height);
                        }
                        // Otherwise, check if we need to request more blocks
                        else {
                            // Update local height (it might have changed)
                            let height = blockchain.get_height().await.unwrap_or(current_height);
                            if height != current_height {
                                let mut local_height_lock = local_height.write().await;
                                *local_height_lock = height;
                            }
                            
                            // Request more blocks if needed
                            if let Some(peer_manager) = &peer_manager {
                                Self::sync_with_peers(
                                    peer_manager.clone(),
                                    blockchain.clone(),
                                    state.clone(),
                                    local_height.clone(),
                                    latest_known_height.clone(),
                                ).await;
                            }
                        }
                    }
                    SyncState::Synchronized => {
                        // Check if we've fallen behind
                        if latest_height > current_height + 10 {
                            let mut state_lock = state.write().await;
                            *state_lock = SyncState::Syncing;
                            tracing::info!("Restarting sync: local={}, remote={}", current_height, latest_height);
                        }
                    }
                    SyncState::Failed => {
                        // Try to recover from failure
                        let mut state_lock = state.write().await;
                        *state_lock = SyncState::Syncing;
                        tracing::info!("Attempting to recover from sync failure");
                    }
                }
            }
            
            tracing::debug!("Sync progress checker task stopped");
        })
    }
    
    /// Static helper method to sync with peers
    async fn sync_with_peers(
        peer_manager: Arc<PeerManager>,
        blockchain: Arc<Blockchain>,
        state: Arc<RwLock<SyncState>>,
        local_height: Arc<RwLock<u64>>,
        latest_known_height: Arc<RwLock<u64>>,
    ) {
        // Get peers
        let peers = match peer_manager.get_peers().await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::warn!("Failed to get peers for sync: {}", e);
                return;
            }
        };
        
        if peers.is_empty() {
            tracing::debug!("No peers available for sync");
            return;
        }
        
        // Get current heights
        let current_height = *local_height.read().await;
        let latest_height = *latest_known_height.read().await;
        
        // Choose a random peer
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        
        if let Some(peer) = peers.choose(&mut rng) {
            // Request chain info to update latest known height
            let chain_info_request = Message::create_get_chain_info(
                peer_manager.node_id().to_vec(),
            );
            
            if let Err(e) = peer_manager.send_to_peer(&peer.id, chain_info_request).await {
                tracing::warn!("Failed to send chain info request to peer {}: {}", 
                    hex::encode(&peer.id), e);
            }
            
            // If we're significantly behind, request blocks in batches
            if latest_height > current_height + 5 {
                let start_height = current_height + 1;
                let end_height = std::cmp::min(
                    start_height + 50, // Request up to 50 blocks at a time
                    latest_height,
                );
                
                let blocks_request = Message::create_get_blocks(
                    peer_manager.node_id().to_vec(),
                    start_height,
                    end_height,
                );
                
                if let Err(e) = peer_manager.send_to_peer(&peer.id, blocks_request).await {
                    tracing::warn!("Failed to send blocks request to peer {}: {}", 
                        hex::encode(&peer.id), e);
                } else {
                    tracing::debug!("Requested blocks {} to {} from peer {}", 
                        start_height, end_height, hex::encode(&peer.id));
                }
            }
        }
    }
    
    /// Send a sync request to a specific peer
    async fn send_sync_request_to_peer(
        peer_manager: Arc<PeerManager>,
        pending_requests: Arc<TokioMutex<HashMap<String, PendingSyncRequest>>>,
        peer_id: Vec<u8>,
        request: SyncRequest,
        retries: usize,
    ) -> Result<()> {
        // Create the appropriate message for the request
        let message = match &request {
            SyncRequest::GetBlock(hash) => {
                Message::create_get_block(peer_manager.node_id().to_vec(), hash.clone())
            }
            SyncRequest::GetBlockByHeight(height) => {
                Message::create_get_block_by_height(peer_manager.node_id().to_vec(), *height)
            }
            SyncRequest::GetBlocks(start_height, end_height) => {
                Message::create_get_blocks(peer_manager.node_id().to_vec(), *start_height, *end_height)
            }
            SyncRequest::GetTransaction(hash) => {
                Message::create_get_transaction(peer_manager.node_id().to_vec(), hash.clone())
            }
            SyncRequest::GetObject(id) => {
                Message::create_get_object(peer_manager.node_id().to_vec(), id.clone())
            }
            SyncRequest::GetChainInfo => {
                Message::create_get_chain_info(peer_manager.node_id().to_vec())
            }
            SyncRequest::GetLatestBlocks(count) => {
                Message::create_get_latest_blocks(peer_manager.node_id().to_vec(), *count)
            }
            SyncRequest::GetBlockTransactions(block_hash) => {
                Message::create_get_block_transactions(peer_manager.node_id().to_vec(), block_hash.clone())
            }
            SyncRequest::GetUncorruptedChain => {
                Message::create_get_uncorrupted_chain(peer_manager.node_id().to_vec())
            }
            SyncRequest::GetSuperpositionedStates(object_id) => {
                Message::create_get_superpositioned_states(peer_manager.node_id().to_vec(), object_id.clone())
            }
        };
        
        // Send the message to the peer
        peer_manager.send_to_peer(&peer_id, message).await?;
        
        // Create a unique request ID
        let request_id = format!("{}-{}-{}", 
            hex::encode(&peer_id),
            request.request_type_string(),
            uuid::Uuid::new_v4(),
        );
        
        // Add to pending requests
        let mut pending_requests_lock = pending_requests.lock().await;
        pending_requests_lock.insert(request_id.clone(), PendingSyncRequest {
            request,
            peer_id,
            sent_at: Instant::now(),
            response_received: false,
            retries,
        });
        
        tracing::trace!("Sent sync request {} (retry {}): {}", request_id, retries, request_id);
        
        Ok(())
    }
}

// Extension trait for SyncRequest to get a string representation of the request type
trait SyncRequestExt {
    fn request_type_string(&self) -> &'static str;
}

impl SyncRequestExt for SyncRequest {
    fn request_type_string(&self) -> &'static str {
        match self {
            SyncRequest::GetBlock(_) => "GetBlock",
            SyncRequest::GetBlockByHeight(_) => "GetBlockByHeight",
            SyncRequest::GetBlocks(_, _) => "GetBlocks",
            SyncRequest::GetTransaction(_) => "GetTransaction",
            SyncRequest::GetObject(_) => "GetObject",
            SyncRequest::GetChainInfo => "GetChainInfo",
            SyncRequest::GetLatestBlocks(_) => "GetLatestBlocks",
            SyncRequest::GetBlockTransactions(_) => "GetBlockTransactions",
            SyncRequest::GetUncorruptedChain => "GetUncorruptedChain",
            SyncRequest::GetSuperpositionedStates(_) => "GetSuperpositionedStates",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use crate::core::block::BlockBuilder;
    use crate::networking::peer::PeerManager;
    use crate::networking::topology::TopologyManager;
    
    // Helper to create a test sync manager
    async fn create_test_sync_manager() -> SyncManager {
        // Create a test blockchain
        let blockchain = Arc::new(Blockchain::default());
        
        // Create a network config
        let config = Arc::new(NetworkConfig::default());
        
        // Create a peer manager
        let peer_manager = Arc::new(PeerManager::new(
            config.clone(),
            vec![1, 2, 3, 4], // node_id
            crate::networking::protocol::ProtocolVersion::V1,
            false, // is_validator
        ).unwrap());
        
        // Create a topology manager
        let topology_manager = Arc::new(TopologyManager::new(
            config.clone(),
            vec![1, 2, 3, 4], // node_id
        ).unwrap());
        
        // Create a sync manager
        let sync_manager = SyncManager::new(
            config,
            blockchain,
            peer_manager,
            topology_manager,
        ).unwrap();
        
        // Set initial local height
        sync_manager.set_local_height(0).await;
        
        sync_manager
    }
    
    #[tokio::test]
    async fn test_sync_manager_creation() {
        let sync_manager = create_test_sync_manager().await;
        assert_eq!(sync_manager.get_state().await, SyncState::Idle);
    }
    
    #[tokio::test]
    async fn test_set_local_height() {
        let sync_manager = create_test_sync_manager().await;
        
        // Set local height
        sync_manager.set_local_height(100).await;
        
        // Verify it was set
        assert_eq!(sync_manager.get_local_height().await, 100);
    }
    
    // Add more tests as needed
}
