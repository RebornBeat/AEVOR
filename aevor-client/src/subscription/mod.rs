//! Real-time event subscriptions via WebSocket.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use crate::ClientResult;

/// Filter for event subscriptions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Subscribe only to these event type names (empty = all events).
    pub event_types: Vec<String>,
    /// Subscribe only to events involving these addresses.
    pub addresses: Vec<String>,
}

impl EventFilter {
    /// Create a filter that matches all events.
    pub fn all() -> Self { Self::default() }
    /// Create a filter for specific event types.
    pub fn for_types(types: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { event_types: types.into_iter().map(Into::into).collect(), addresses: vec![] }
    }
    /// Add an address filter.
    pub fn with_address(mut self, addr: impl Into<String>) -> Self {
        self.addresses.push(addr.into()); self
    }
    /// Returns `true` if this filter has no restrictions (matches everything).
    pub fn is_open(&self) -> bool { self.event_types.is_empty() && self.addresses.is_empty() }
}

/// A live event delivered over a subscription.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveEvent {
    /// Event type identifier.
    pub event_type: String,
    /// Serialized event payload.
    pub data: Vec<u8>,
    /// Block height at which this event was emitted.
    pub block_height: u64,
}

/// A subscription to filtered blockchain events.
pub struct EventSubscription {
    /// Unique subscription ID (assigned by the server).
    pub id: String,
    /// Filter applied to this subscription.
    pub filter: EventFilter,
}

impl EventSubscription {
    /// Create a new event subscription handle.
    pub fn new(id: impl Into<String>, filter: EventFilter) -> Self {
        Self { id: id.into(), filter }
    }
}

/// A subscription to all new block headers.
pub struct BlockSubscription {
    /// Unique subscription ID (assigned by the server).
    pub id: String,
}

impl BlockSubscription {
    /// Create a new block subscription handle.
    pub fn new(id: impl Into<String>) -> Self { Self { id: id.into() } }
}

/// A subscription that tracks a single transaction to finality.
pub struct TransactionSubscription {
    /// Unique subscription ID.
    pub id: String,
    /// Hash of the transaction being tracked.
    pub tx_hash: Hash256,
}

impl TransactionSubscription {
    /// Create a new transaction subscription.
    pub fn new(id: impl Into<String>, tx_hash: Hash256) -> Self {
        Self { id: id.into(), tx_hash }
    }
}

/// Client for managing WebSocket event subscriptions.
pub struct SubscriptionClient {
    endpoint: String,
}

impl SubscriptionClient {
    /// Create a subscription client pointing at the given WebSocket endpoint.
    pub fn new(endpoint: String) -> Self { Self { endpoint } }

    /// The endpoint this client connects to.
    pub fn endpoint(&self) -> &str { &self.endpoint }

    /// Subscribe to filtered events.
    ///
    /// Returns a subscription handle. Call `unsubscribe()` when done.
    pub async fn subscribe_events(&self, filter: EventFilter) -> ClientResult<EventSubscription> {
        let _ = filter;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "WebSocket transport not yet wired".into(),
        })
    }

    /// Subscribe to new block headers.
    pub async fn subscribe_blocks(&self) -> ClientResult<BlockSubscription> {
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "WebSocket transport not yet wired".into(),
        })
    }

    /// Subscribe to a specific transaction, delivering status updates until finality.
    pub async fn subscribe_transaction(&self, tx_hash: Hash256) -> ClientResult<TransactionSubscription> {
        let _ = tx_hash;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "WebSocket transport not yet wired".into(),
        })
    }
}
