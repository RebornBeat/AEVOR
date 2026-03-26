//! Multi-network client: connect to mainnet, testnet, and subnets simultaneously.

use serde::{Deserialize, Serialize};
use crate::ClientResult;

/// Identifies an AEVOR network (mainnet, testnet, or subnet).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub u64);

/// Type alias exported in the prelude.
pub type ClientNetworkId = NetworkId;

impl NetworkId {
    /// AEVOR mainnet network ID.
    pub const MAINNET: Self = Self(1);
    /// AEVOR public testnet network ID.
    pub const TESTNET: Self = Self(2);
    /// Returns `true` if this is the mainnet.
    pub fn is_mainnet(&self) -> bool { self.0 == 1 }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            1 => write!(f, "mainnet"),
            2 => write!(f, "testnet"),
            n => write!(f, "subnet-{}", n),
        }
    }
}

/// A handle to a connected AEVOR network.
pub struct NetworkHandle {
    /// The network this handle connects to.
    pub id: NetworkId,
    /// gRPC/HTTP endpoint for this network.
    pub endpoint: String,
}

impl NetworkHandle {
    /// Create a new network handle.
    pub fn new(id: NetworkId, endpoint: impl Into<String>) -> Self {
        Self { id, endpoint: endpoint.into() }
    }
    /// Returns `true` if this handle points to mainnet.
    pub fn is_mainnet(&self) -> bool { self.id.is_mainnet() }
}

/// Selects which network to route a request to based on context.
pub struct NetworkSelector;

impl NetworkSelector {
    /// Select the appropriate network for a given network ID.
    pub fn select<'a>(
        handles: &'a [NetworkHandle],
        id: NetworkId,
    ) -> Option<&'a NetworkHandle> {
        handles.iter().find(|h| h.id == id)
    }
}

/// A client that maintains connections to multiple AEVOR networks simultaneously.
///
/// Useful for cross-chain bridge operations or applications that need to
/// read from both mainnet and subnets.
pub struct MultiNetworkClient {
    handles: Vec<NetworkHandle>,
}

impl MultiNetworkClient {
    /// Create a new multi-network client with no connections.
    pub fn new() -> Self { Self { handles: Vec::new() } }

    /// Add a network connection.
    pub fn add(&mut self, handle: NetworkHandle) {
        // Replace existing handle for this network ID if present.
        if let Some(existing) = self.handles.iter_mut().find(|h| h.id == handle.id) {
            *existing = handle;
        } else {
            self.handles.push(handle);
        }
    }

    /// Remove the connection for a given network ID.
    pub fn remove(&mut self, id: NetworkId) {
        self.handles.retain(|h| h.id != id);
    }

    /// Get a handle for the given network ID.
    pub fn get(&self, id: NetworkId) -> Option<&NetworkHandle> {
        self.handles.iter().find(|h| h.id == id)
    }

    /// Number of connected networks.
    pub fn network_count(&self) -> usize { self.handles.len() }

    /// Returns `true` if connected to the given network.
    pub fn is_connected_to(&self, id: NetworkId) -> bool {
        self.handles.iter().any(|h| h.id == id)
    }
}

impl Default for MultiNetworkClient {
    fn default() -> Self { Self::new() }
}
