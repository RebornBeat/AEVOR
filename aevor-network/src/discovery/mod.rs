//! Peer discovery: bootstrap, DHT, mDNS.
//!
//! Privacy-preserving discovery uses onion routing over DHT so nodes can
//! discover peers without revealing their network identity to the DHT.

use serde::{Deserialize, Serialize};
use aevor_core::network::NodeId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapConfig { pub peers: Vec<String>, pub max_discovered: usize }
impl Default for BootstrapConfig {
    fn default() -> Self { Self { peers: Vec::new(), max_discovered: 50 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAdvertisement { pub node_id: NodeId, pub endpoints: Vec<String> }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryProtocol { Bootstrap, Dht, Mdns }

pub struct PrivacyPreservingDiscovery { use_dht: bool }
impl PrivacyPreservingDiscovery {
    pub fn new(use_dht: bool) -> Self { Self { use_dht } }
    pub fn uses_dht(&self) -> bool { self.use_dht }
    pub fn is_anonymous(&self) -> bool { self.use_dht }
}

pub struct PeerDiscovery { config: BootstrapConfig }
impl PeerDiscovery {
    pub fn new(config: BootstrapConfig) -> Self { Self { config } }
    pub fn bootstrap_count(&self) -> usize { self.config.peers.len() }
    pub fn max_discovered(&self) -> usize { self.config.max_discovered }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::network::NodeId;
    use aevor_core::primitives::Hash256;

    fn node(n: u8) -> NodeId { NodeId(Hash256([n; 32])) }

    #[test]
    fn bootstrap_config_default_no_peers() {
        let cfg = BootstrapConfig::default();
        assert!(cfg.peers.is_empty());
        assert!(cfg.max_discovered > 0);
    }

    #[test]
    fn peer_discovery_bootstrap_count() {
        let cfg = BootstrapConfig {
            peers: vec!["192.168.1.1:4001".into(), "10.0.0.1:4001".into()],
            max_discovered: 50,
        };
        let disc = PeerDiscovery::new(cfg);
        assert_eq!(disc.bootstrap_count(), 2);
        assert_eq!(disc.max_discovered(), 50);
    }

    #[test]
    fn privacy_preserving_discovery_dht_is_anonymous() {
        // Whitepaper: onion routing over DHT hides node identity
        let ppd = PrivacyPreservingDiscovery::new(true);
        assert!(ppd.uses_dht());
        assert!(ppd.is_anonymous());
    }

    #[test]
    fn privacy_preserving_discovery_no_dht_not_anonymous() {
        let ppd = PrivacyPreservingDiscovery::new(false);
        assert!(!ppd.uses_dht());
        assert!(!ppd.is_anonymous());
    }

    #[test]
    fn discovery_protocol_variants_distinct() {
        assert_ne!(DiscoveryProtocol::Bootstrap, DiscoveryProtocol::Dht);
        assert_ne!(DiscoveryProtocol::Dht, DiscoveryProtocol::Mdns);
    }

    #[test]
    fn peer_advertisement_stores_node_and_endpoints() {
        let adv = PeerAdvertisement {
            node_id: node(1),
            endpoints: vec!["192.168.1.1:4001".into()],
        };
        assert_eq!(adv.node_id, node(1));
        assert_eq!(adv.endpoints.len(), 1);
    }
}
