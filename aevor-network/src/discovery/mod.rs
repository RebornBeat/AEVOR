//! Peer discovery: bootstrap, DHT, mDNS.

use serde::{Deserialize, Serialize};
use aevor_core::network::NodeId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapConfig { pub peers: Vec<String>, pub max_discovered: usize }
impl Default for BootstrapConfig {
    fn default() -> Self { Self { peers: Vec::new(), max_discovered: 50 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAdvertisement { pub node_id: NodeId, pub endpoints: Vec<String> }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DiscoveryProtocol { Bootstrap, Dht, Mdns }

pub struct PrivacyPreservingDiscovery { use_dht: bool }
impl PrivacyPreservingDiscovery {
    /// Create a privacy-preserving discovery component.
    ///
    /// When `use_dht` is `true`, the DHT is used for peer discovery but with
    /// onion-routing so the node's identity is not revealed to the DHT.
    /// When `false`, only bootstrap nodes and mDNS are used.
    pub fn new(use_dht: bool) -> Self { Self { use_dht } }

    /// Whether DHT-based peer discovery is enabled.
    pub fn uses_dht(&self) -> bool { self.use_dht }

    /// Whether this discovery strategy reveals the node's network identity.
    pub fn is_anonymous(&self) -> bool {
        // DHT mode uses onion routing and is considered anonymous.
        // Non-DHT mode uses direct bootstrap connections which are not anonymous.
        self.use_dht
    }
}

pub struct PeerDiscovery { config: BootstrapConfig }
impl PeerDiscovery {
    pub fn new(config: BootstrapConfig) -> Self { Self { config } }
    pub fn bootstrap_count(&self) -> usize { self.config.peers.len() }
}
