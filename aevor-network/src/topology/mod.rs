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
        (u32::from(self.uptime_pct) * 100 + u32::from(self.reliability) * 100)
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::network::{NodeId, NetworkAddress, NetworkProtocol, GeographicRegion};
    use aevor_core::primitives::Hash256;

    fn make_peer(connected: bool, latency_ms: u32) -> PeerInfo {
        PeerInfo {
            id: NodeId(Hash256([1u8; 32])),
            address: NetworkAddress::new(
                NodeId(Hash256([1u8; 32])),
                "127.0.0.1:8731",
                vec![NetworkProtocol::Quic],
                GeographicRegion::NorthAmerica,
            ),
            score: PeerScore { latency_ms, uptime_pct: 99, reliability: 90 },
            connected,
        }
    }

    #[test]
    fn peer_score_total_subtracts_latency() {
        let s = PeerScore { latency_ms: 10, uptime_pct: 100, reliability: 100 };
        // (100*100 + 100*100) - 10 = 19 990
        assert_eq!(s.total(), 19_990);
    }

    #[test]
    fn peer_score_saturates_at_zero() {
        let s = PeerScore { latency_ms: u32::MAX, uptime_pct: 1, reliability: 1 };
        assert_eq!(s.total(), 0);
    }

    #[test]
    fn topology_manager_counts_connected_peers() {
        let mut tm = TopologyManager::new();
        tm.add_peer(make_peer(true, 5));
        tm.add_peer(make_peer(false, 50));
        tm.add_peer(make_peer(true, 10));
        assert_eq!(tm.peer_count(), 3);
        assert_eq!(tm.connected_peers(), 2);
    }

    #[test]
    fn topology_manager_default_is_empty() {
        let tm = TopologyManager::default();
        assert_eq!(tm.peer_count(), 0);
        assert_eq!(tm.connected_peers(), 0);
    }
}
