//! Network configuration types.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::ChainId;
use aevor_core::network::GeographicRegion;

/// Network identity and topology configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Network type.
    pub network_type: NetworkType,
    /// Genesis configuration.
    pub genesis: GenesisConfig,
    /// Peer discovery configuration.
    pub discovery: PeerDiscoveryConfig,
    /// Topology optimization configuration.
    pub topology: TopologyConfig,
    /// Subnets this node participates in.
    pub subnets: Vec<SubnetConfig>,
    /// Bridge configurations.
    pub bridges: Vec<BridgeConfig>,
    /// Maximum number of peers.
    pub max_peers: usize,
    /// Listen addresses (IP:port).
    pub listen_addresses: Vec<String>,
    /// External/public address for advertisement.
    pub external_address: Option<String>,
    /// QUIC listen port.
    pub quic_port: u16,
    /// TCP listen port.
    pub tcp_port: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId::MAINNET,
            network_type: NetworkType::Mainnet,
            genesis: GenesisConfig::default(),
            discovery: PeerDiscoveryConfig::default(),
            topology: TopologyConfig::default(),
            subnets: Vec::new(),
            bridges: Vec::new(),
            max_peers: 50,
            listen_addresses: vec!["0.0.0.0:4001".into()],
            external_address: None,
            quic_port: 4001,
            tcp_port: 4002,
        }
    }
}

/// The type of AEVOR network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum NetworkType {
    /// Public mainnet — real economic value, full security.
    #[default]
    Mainnet,
    /// Public testnet — test tokens, no real value.
    Testnet,
    /// Public devnet — developer testing environment.
    Devnet,
    /// Permissioned enterprise subnet.
    EnterpriseSubnet,
    /// Research or experimental subnet.
    ResearchSubnet,
}

impl NetworkType {
    /// Returns `true` if this network type is a production environment.
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Mainnet)
    }
}

/// Genesis block configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Genesis block hash (None = generate from config).
    pub genesis_hash: Option<String>,
    /// Initial token distribution.
    pub initial_supply_nano: u128,
    /// Genesis validator public keys.
    pub genesis_validators: Vec<String>,
    /// Protocol version at genesis.
    pub protocol_version: String,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            genesis_hash: None,
            initial_supply_nano: 1_000_000_000 * 1_000_000_000u128, // 1B AEVOR
            genesis_validators: Vec::new(),
            protocol_version: "1.0.0".into(),
        }
    }
}

/// Peer discovery configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerDiscoveryConfig {
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<String>,
    /// Whether mDNS local discovery is enabled.
    pub enable_mdns: bool,
    /// Whether DHT-based discovery is enabled.
    pub enable_dht: bool,
    /// Peer discovery interval in seconds.
    pub discovery_interval_s: u64,
    /// Maximum peers to discover per round.
    pub max_discovered_per_round: usize,
}

impl Default for PeerDiscoveryConfig {
    fn default() -> Self {
        Self {
            bootstrap_peers: Vec::new(),
            enable_mdns: false,
            enable_dht: true,
            discovery_interval_s: 30,
            max_discovered_per_round: 10,
        }
    }
}

/// Network topology optimization configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologyConfig {
    /// Whether topology-aware routing is enabled.
    pub enable_topology_aware_routing: bool,
    /// Target geographic region distribution for peers.
    pub target_regions: Vec<GeographicRegion>,
    /// Minimum peers per region.
    pub min_peers_per_region: usize,
    /// Maximum latency for direct peer connections in milliseconds.
    pub max_direct_peer_latency_ms: u32,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            enable_topology_aware_routing: true,
            target_regions: GeographicRegion::all_known().to_vec(),
            min_peers_per_region: 1,
            max_direct_peer_latency_ms: 500,
        }
    }
}

/// Configuration for a specific subnet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubnetConfig {
    /// Subnet identifier (hex hash).
    pub subnet_id: String,
    /// Human-readable subnet name.
    pub name: String,
    /// Whether this subnet is permissioned.
    pub permissioned: bool,
    /// Permitted validator addresses (empty = open).
    pub permitted_validators: Vec<String>,
}

/// Cross-chain bridge configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Bridge identifier.
    pub bridge_id: String,
    /// Target chain identifier.
    pub target_chain: String,
    /// Bridge relayer endpoints.
    pub relayer_endpoints: Vec<String>,
    /// Whether this bridge uses TEE-secured verification.
    pub tee_secured: bool,
}
