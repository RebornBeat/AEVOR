//! # Network Topology Types
//!
//! Network addressing, topology, routing, and geographic distribution types
//! for AEVOR's topology-aware P2P infrastructure.
//!
//! Geographic distribution is fundamental to AEVOR's security model — the
//! network topology is designed to maximize validator geographic distribution,
//! ensuring no single region can compromise the majority of validators.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::primitives::Hash256;

// ============================================================
// GEOGRAPHIC REGION
// ============================================================

/// A geographic region classification for network topology optimization.
///
/// AEVOR uses geographic distribution as a security property — validators
/// spread across multiple regions makes geographic-correlation attacks
/// (controlling all validators in one physical location) much harder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeographicRegion {
    /// North America (USA, Canada, Mexico).
    NorthAmerica,
    /// South America.
    SouthAmerica,
    /// Western Europe.
    WesternEurope,
    /// Eastern Europe.
    EasternEurope,
    /// East Asia (Japan, Korea, China, Taiwan).
    EastAsia,
    /// Southeast Asia.
    SoutheastAsia,
    /// South Asia (India, Pakistan, Bangladesh).
    SouthAsia,
    /// Middle East.
    MiddleEast,
    /// Africa.
    Africa,
    /// Oceania (Australia, New Zealand, Pacific).
    Oceania,
    /// Central Asia.
    CentralAsia,
    /// Unknown / unclassified.
    Unknown,
}

impl GeographicRegion {
    /// Returns the canonical name of this region.
    pub fn name(&self) -> &'static str {
        match self {
            Self::NorthAmerica => "North America",
            Self::SouthAmerica => "South America",
            Self::WesternEurope => "Western Europe",
            Self::EasternEurope => "Eastern Europe",
            Self::EastAsia => "East Asia",
            Self::SoutheastAsia => "Southeast Asia",
            Self::SouthAsia => "South Asia",
            Self::MiddleEast => "Middle East",
            Self::Africa => "Africa",
            Self::Oceania => "Oceania",
            Self::CentralAsia => "Central Asia",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns a short code for this region.
    pub fn short_code(&self) -> &'static str {
        match self {
            Self::NorthAmerica => "NA",
            Self::SouthAmerica => "SA",
            Self::WesternEurope => "WE",
            Self::EasternEurope => "EE",
            Self::EastAsia => "EA",
            Self::SoutheastAsia => "SEA",
            Self::SouthAsia => "SA2",
            Self::MiddleEast => "ME",
            Self::Africa => "AF",
            Self::Oceania => "OC",
            Self::CentralAsia => "CA",
            Self::Unknown => "XX",
        }
    }

    /// Whether this region is classified (not Unknown).
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// All well-defined geographic regions (excluding Unknown).
    pub fn all_known() -> &'static [Self] {
        &[
            Self::NorthAmerica, Self::SouthAmerica, Self::WesternEurope,
            Self::EasternEurope, Self::EastAsia, Self::SoutheastAsia,
            Self::SouthAsia, Self::MiddleEast, Self::Africa,
            Self::Oceania, Self::CentralAsia,
        ]
    }
}

impl std::fmt::Display for GeographicRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================
// NODE ID / PEER ID
// ============================================================

/// Unique identifier for a network node, derived from its public key.
///
/// `NodeId` is derived as `BLAKE3(ed25519_public_key)` — stable across
/// node restarts as long as the same keypair is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub Hash256);

impl NodeId {
    /// Create from a hash value.
    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }

    /// Create from a public key by hashing it.
    pub fn from_public_key(key: &crate::primitives::PublicKey) -> Self {
        Self(Hash256(*blake3::hash(key.as_bytes()).as_bytes()))
    }

    /// View the inner hash.
    pub fn as_hash(&self) -> &Hash256 {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node:{}", hex::encode(&self.0.0[..8]))
    }
}

/// A peer identifier — alias for `NodeId` in peer-to-peer contexts.
pub type PeerId = NodeId;

// ============================================================
// SUBNET ID
// ============================================================

/// Identifier for a network subnet or permissioned subnetwork.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubnetId(pub Hash256);

impl SubnetId {
    /// The mainnet subnet identifier.
    pub const MAINNET: Self = Self(Hash256::ZERO);

    /// Create from a hash value.
    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }

    /// Returns `true` if this is the mainnet subnet.
    pub fn is_mainnet(&self) -> bool {
        self.0.is_zero()
    }
}

impl std::fmt::Display for SubnetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "subnet:{}", hex::encode(&self.0.0[..8]))
    }
}

// ============================================================
// NETWORK ADDRESS
// ============================================================

/// A network address for connecting to a node.
///
/// AEVOR supports multiple transport protocols — the `NetworkAddress`
/// abstracts over all of them to allow protocol-agnostic addressing.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkAddress {
    /// Node identifier for routing.
    pub node_id: NodeId,
    /// Transport-specific endpoint (IP:port, hostname:port, multiaddr).
    pub endpoint: String,
    /// Transport protocols supported by this address.
    pub protocols: Vec<NetworkProtocol>,
    /// Geographic region of this address.
    pub region: GeographicRegion,
}

impl NetworkAddress {
    /// Create a new network address.
    pub fn new(
        node_id: NodeId,
        endpoint: impl Into<String>,
        protocols: Vec<NetworkProtocol>,
        region: GeographicRegion,
    ) -> Self {
        Self {
            node_id,
            endpoint: endpoint.into(),
            protocols,
            region,
        }
    }

    /// Returns `true` if this address supports gRPC transport.
    pub fn supports_grpc(&self) -> bool {
        self.protocols.contains(&NetworkProtocol::Grpc)
    }

    /// Returns `true` if this address supports QUIC transport.
    pub fn supports_quic(&self) -> bool {
        self.protocols.contains(&NetworkProtocol::Quic)
    }
}

impl std::fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} @ {}", self.node_id, self.endpoint)
    }
}

// ============================================================
// NETWORK PROTOCOL
// ============================================================

/// Transport protocols supported by AEVOR's network layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    /// QUIC — primary transport for low-latency validator communication.
    Quic,
    /// TCP — fallback for environments where QUIC is blocked.
    Tcp,
    /// WebSocket — for browser and web client connectivity.
    WebSocket,
    /// gRPC — for API server communication.
    Grpc,
    /// WebRTC — for peer-to-peer browser connectivity.
    WebRtc,
}

impl NetworkProtocol {
    /// Returns the default port for this protocol.
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Quic => 4001,
            Self::Tcp => 4002,
            Self::WebSocket => 4003,
            Self::Grpc => 8730,
            Self::WebRtc => 4004,
        }
    }

    /// Returns the URI scheme for this protocol.
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Tcp => "tcp",
            Self::WebSocket => "ws",
            Self::Grpc => "grpc",
            Self::WebRtc => "webrtc",
        }
    }
}

// ============================================================
// CONNECTION METADATA
// ============================================================

/// Metadata about an active peer connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionMetadata {
    /// Remote peer identifier.
    pub peer_id: PeerId,
    /// Remote network address.
    pub address: NetworkAddress,
    /// Transport protocol in use.
    pub protocol: NetworkProtocol,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// Whether this connection is TLS-encrypted.
    pub is_encrypted: bool,
    /// Number of active subscriptions on this connection.
    pub subscription_count: u32,
}

// ============================================================
// NETWORK TOPOLOGY
// ============================================================

/// The network topology: how nodes are connected and organized.
///
/// AEVOR uses topology-aware routing to optimize for:
/// 1. Low latency between geographically proximate validators
/// 2. Geographic distribution across all regions
/// 3. Fault tolerance through multiple routing paths
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTopology {
    /// All known nodes indexed by their ID.
    pub nodes: HashMap<NodeId, NetworkAddress>,
    /// Peer connections: node → set of directly connected peers.
    pub connections: HashMap<NodeId, Vec<NodeId>>,
    /// Validator nodes specifically.
    pub validators: Vec<NodeId>,
    /// Distribution of nodes by geographic region.
    pub region_distribution: HashMap<String, usize>,
}

impl NetworkTopology {
    /// Returns the number of nodes in the topology.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of validators in the topology.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if the topology is geographically diverse (multiple regions).
    pub fn is_geographically_diverse(&self) -> bool {
        self.region_distribution
            .values()
            .filter(|&&count| count > 0)
            .count()
            >= 3
    }

    /// Returns the connectivity (average connections per node).
    #[allow(clippy::cast_precision_loss)] // usize->f64 precision loss acceptable for metrics
    pub fn average_connectivity(&self) -> f64 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        let total_connections: usize = self.connections.values().map(Vec::len).sum();
        total_connections as f64 / self.nodes.len() as f64
    }
}

// ============================================================
// TOPOLOGY METRICS
// ============================================================

/// Metrics about the current network topology health.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyMetrics {
    /// Total number of known peers.
    pub peer_count: usize,
    /// Number of active (connected) peers.
    pub active_peer_count: usize,
    /// Number of geographic regions represented.
    pub region_count: usize,
    /// Average peer latency in milliseconds.
    pub avg_latency_ms: u32,
    /// Maximum peer latency in milliseconds.
    pub max_latency_ms: u32,
    /// Whether the topology is well-connected (no isolated clusters).
    pub is_well_connected: bool,
    /// Geographic diversity score (0–100).
    pub diversity_score: u8,
}

impl TopologyMetrics {
    /// Returns `true` if the topology meets minimum health requirements.
    pub fn is_healthy(&self) -> bool {
        self.active_peer_count >= 3
            && self.region_count >= 2
            && self.is_well_connected
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geographic_region_all_known_excludes_unknown() {
        let known = GeographicRegion::all_known();
        assert!(!known.contains(&GeographicRegion::Unknown));
        assert!(known.len() >= 10);
    }

    #[test]
    fn geographic_region_known_flag() {
        assert!(GeographicRegion::NorthAmerica.is_known());
        assert!(!GeographicRegion::Unknown.is_known());
    }

    #[test]
    fn network_protocol_default_ports_nonzero() {
        for proto in &[
            NetworkProtocol::Quic,
            NetworkProtocol::Tcp,
            NetworkProtocol::WebSocket,
            NetworkProtocol::Grpc,
        ] {
            assert!(proto.default_port() > 0);
        }
    }

    #[test]
    fn grpc_default_port_matches_api_constant() {
        // gRPC API server uses port 8730 — must align.
        assert_eq!(NetworkProtocol::Grpc.default_port(), 8730);
    }

    #[test]
    fn node_id_from_public_key_is_deterministic() {
        let key = crate::primitives::PublicKey([1u8; 32]);
        let id1 = NodeId::from_public_key(&key);
        let id2 = NodeId::from_public_key(&key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn subnet_mainnet_is_zero() {
        assert!(SubnetId::MAINNET.is_mainnet());
    }

    #[test]
    fn topology_empty_is_not_geographically_diverse() {
        let topo = NetworkTopology {
            nodes: HashMap::new(),
            connections: HashMap::new(),
            validators: vec![],
            region_distribution: HashMap::new(),
        };
        assert!(!topo.is_geographically_diverse());
    }

    #[test]
    fn topology_metrics_needs_three_active_peers() {
        let m = TopologyMetrics {
            peer_count: 10,
            active_peer_count: 2, // Below threshold
            region_count: 5,
            avg_latency_ms: 50,
            max_latency_ms: 200,
            is_well_connected: true,
            diversity_score: 80,
        };
        assert!(!m.is_healthy());
    }
}
