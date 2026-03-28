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
            n => write!(f, "subnet-{n}"),
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
    pub fn select(
        handles: &[NetworkHandle],
        id: NetworkId,
    ) -> Option<&NetworkHandle> {
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

    /// Connect to a network, returning an error if the endpoint is invalid.
    ///
    /// An endpoint is considered invalid if it is empty or does not start
    /// with a supported scheme (`http://`, `https://`, or `grpc://`).
    ///
    /// # Errors
    /// Returns an error if the endpoint is empty or uses an unsupported scheme.
    pub fn connect(&mut self, id: NetworkId, endpoint: impl Into<String>) -> ClientResult<()> {
        let endpoint = endpoint.into();
        if endpoint.is_empty() {
            return Err(crate::ClientError::ConnectionFailed {
                endpoint: endpoint.clone(),
                reason: "endpoint cannot be empty".into(),
            });
        }
        let valid_scheme = endpoint.starts_with("http://") || endpoint.starts_with("https://") || endpoint.starts_with("grpc://");
        if !valid_scheme {
            return Err(crate::ClientError::ConnectionFailed {
                endpoint: endpoint.clone(),
                reason: "endpoint must start with http://, https://, or grpc://".into(),
            });
        }
        self.add(NetworkHandle::new(id, endpoint));
        Ok(())
    }

    /// Disconnect from a network.
    ///
    /// # Errors
    /// Returns an error if not currently connected to the given network.
    pub fn disconnect(&mut self, id: NetworkId) -> ClientResult<()> {
        if !self.is_connected_to(id) {
            return Err(crate::ClientError::ConnectionFailed {
                endpoint: id.to_string(),
                reason: "not connected to this network".into(),
            });
        }
        self.remove(id);
        Ok(())
    }
}

impl Default for MultiNetworkClient {
    fn default() -> Self { Self::new() }
}

/// Routes a request to the appropriate network based on subnet ID or network type.
///
/// This is infrastructure capability — which subnet receives which requests is
/// application policy implemented by the caller, not embedded in this type.
pub struct SubnetRouter {
    networks: Vec<NetworkHandle>,
}

impl SubnetRouter {
    /// Create a new subnet router.
    pub fn new(networks: Vec<NetworkHandle>) -> Self { Self { networks } }

    /// Find the network handle for a given network ID.
    pub fn route(&self, id: NetworkId) -> Option<&NetworkHandle> {
        self.networks.iter().find(|h| h.id == id)
    }

    /// All connected network IDs.
    pub fn connected_networks(&self) -> Vec<NetworkId> {
        self.networks.iter().map(|h| h.id).collect()
    }

    /// Returns `true` if any enterprise subnet is connected.
    /// Enterprise subnets use network IDs >= 1000 by convention.
    pub fn has_enterprise_subnet(&self) -> bool {
        self.networks.iter().any(|h| h.id.0 >= 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_constants() {
        assert!(NetworkId::MAINNET.is_mainnet());
        assert!(!NetworkId::TESTNET.is_mainnet());
    }

    #[test]
    fn network_id_display() {
        assert_eq!(NetworkId::MAINNET.to_string(), "mainnet");
        assert_eq!(NetworkId::TESTNET.to_string(), "testnet");
        assert_eq!(NetworkId(99).to_string(), "subnet-99");
    }

    #[test]
    fn network_handle_is_mainnet() {
        let h = NetworkHandle::new(NetworkId::MAINNET, "http://localhost:8731");
        assert!(h.is_mainnet());
        assert_eq!(h.endpoint, "http://localhost:8731");
    }

    #[test]
    fn network_selector_finds_correct_handle() {
        let handles = vec![
            NetworkHandle::new(NetworkId::MAINNET, "http://mainnet"),
            NetworkHandle::new(NetworkId::TESTNET, "http://testnet"),
        ];
        let h = NetworkSelector::select(&handles, NetworkId::TESTNET).unwrap();
        assert_eq!(h.endpoint, "http://testnet");
    }

    #[test]
    fn network_selector_returns_none_for_missing() {
        let handles: Vec<NetworkHandle> = vec![];
        assert!(NetworkSelector::select(&handles, NetworkId::MAINNET).is_none());
    }

    #[test]
    fn multi_client_connect_and_get() {
        let mut client = MultiNetworkClient::new();
        client.connect(NetworkId::MAINNET, "http://localhost:8731").unwrap();
        assert!(client.is_connected_to(NetworkId::MAINNET));
        assert_eq!(client.network_count(), 1);
        assert_eq!(client.get(NetworkId::MAINNET).unwrap().endpoint, "http://localhost:8731");
    }

    #[test]
    fn multi_client_connect_replaces_existing() {
        let mut client = MultiNetworkClient::new();
        client.connect(NetworkId::MAINNET, "http://old:8731").unwrap();
        client.connect(NetworkId::MAINNET, "http://new:8731").unwrap();
        assert_eq!(client.network_count(), 1);
        assert_eq!(client.get(NetworkId::MAINNET).unwrap().endpoint, "http://new:8731");
    }

    #[test]
    fn multi_client_empty_endpoint_fails() {
        let mut client = MultiNetworkClient::new();
        assert!(client.connect(NetworkId::MAINNET, "").is_err());
    }

    #[test]
    fn multi_client_bad_scheme_fails() {
        let mut client = MultiNetworkClient::new();
        assert!(client.connect(NetworkId::MAINNET, "ftp://node").is_err());
    }

    #[test]
    fn multi_client_disconnect_removes_network() {
        let mut client = MultiNetworkClient::new();
        client.connect(NetworkId::TESTNET, "http://testnet:8731").unwrap();
        client.disconnect(NetworkId::TESTNET).unwrap();
        assert!(!client.is_connected_to(NetworkId::TESTNET));
    }

    #[test]
    fn multi_client_disconnect_not_connected_returns_error() {
        let mut client = MultiNetworkClient::new();
        assert!(client.disconnect(NetworkId::MAINNET).is_err());
    }

    // ── SubnetRouter ───────────────────────────────────────────────────────
    // Whitepaper §17.5: "Multi-Network Coordination and Cross-Subnet
    // Communication Through Decentralized Management"

    #[test]
    fn subnet_router_routes_to_correct_network() {
        let router = SubnetRouter::new(vec![
            NetworkHandle::new(NetworkId::MAINNET, "http://mainnet"),
            NetworkHandle::new(NetworkId(1001), "http://enterprise-subnet"),
        ]);
        assert!(router.route(NetworkId::MAINNET).is_some());
        assert!(router.route(NetworkId(1001)).is_some());
        assert!(router.route(NetworkId(999)).is_none());
    }

    #[test]
    fn subnet_router_connected_networks() {
        let router = SubnetRouter::new(vec![
            NetworkHandle::new(NetworkId::MAINNET, "http://mainnet"),
            NetworkHandle::new(NetworkId::TESTNET, "http://testnet"),
        ]);
        let networks = router.connected_networks();
        assert_eq!(networks.len(), 2);
        assert!(networks.contains(&NetworkId::MAINNET));
        assert!(networks.contains(&NetworkId::TESTNET));
    }

    #[test]
    fn subnet_router_detects_enterprise_subnet() {
        // Whitepaper §17.4: enterprise subnets are deployment configurations,
        // not special infrastructure — distinguished by network ID convention.
        let router = SubnetRouter::new(vec![
            NetworkHandle::new(NetworkId(1000), "http://enterprise"),
        ]);
        assert!(router.has_enterprise_subnet());

        let public_only = SubnetRouter::new(vec![
            NetworkHandle::new(NetworkId::MAINNET, "http://mainnet"),
        ]);
        assert!(!public_only.has_enterprise_subnet());
    }

    #[test]
    fn network_id_subnet_display() {
        // Any numeric subnet ID is a valid network identifier
        let subnet = NetworkId(42_000);
        assert_eq!(subnet.to_string(), "subnet-42000");
        assert!(!subnet.is_mainnet());
    }
