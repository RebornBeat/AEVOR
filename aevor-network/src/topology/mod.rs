//! Network topology management and peer scoring.

use serde::{Deserialize, Serialize};
pub use aevor_core::network::NetworkTopology;
use aevor_core::network::{NodeId, NetworkAddress};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: NodeId,
    pub address: NetworkAddress,
    pub score: PeerScore,
    pub connected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerScore { pub latency_ms: u32, pub uptime_pct: u8, pub reliability: u8 }

impl PeerScore {
    pub fn total(&self) -> u32 {
        (self.uptime_pct as u32 * 100 + self.reliability as u32 * 100)
            .saturating_sub(self.latency_ms)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologyUpdate { pub added: Vec<PeerInfo>, pub removed: Vec<NodeId> }

pub struct PrivacyPreservingTopology { topology: NetworkTopology }
impl PrivacyPreservingTopology {
    pub fn new(t: NetworkTopology) -> Self { Self { topology: t } }
    pub fn node_count(&self) -> usize { self.topology.node_count() }
}

pub struct TopologyManager { peers: Vec<PeerInfo> }
impl TopologyManager {
    pub fn new() -> Self { Self { peers: Vec::new() } }
    pub fn add_peer(&mut self, p: PeerInfo) { self.peers.push(p); }
    pub fn peer_count(&self) -> usize { self.peers.len() }
    pub fn connected_peers(&self) -> usize { self.peers.iter().filter(|p| p.connected).count() }
}
impl Default for TopologyManager { fn default() -> Self { Self::new() } }
