//! # AEVOR Network: Privacy-Preserving Global Coordination
//!
//! `aevor-network` provides the networking infrastructure for AEVOR's global validator
//! coordination, enabling 200,000+ TPS operation while preserving network topology
//! privacy and resisting surveillance and traffic analysis.
//!
//! ## Networking Architecture
//!
//! The network layer is designed for the Dual-DAG's throughput requirements:
//! - **90–95% bandwidth utilization** through topology-aware routing
//! - **RDMA-style zero-copy transport** for high-throughput block propagation
//! - **Predictive DAG prefetching** reducing latency for anticipated block dependencies
//! - **Erasure-coded data availability** with confidentiality preservation
//!
//! ## Privacy Preservation
//!
//! Unlike traditional blockchain networks that leak extensive metadata about
//! participant behavior, AEVOR's network layer implements:
//! - **Topology privacy**: network structure is not observable to passive adversaries
//! - **Traffic analysis resistance**: communication patterns are obfuscated
//! - **Metadata shielding**: message origins, sizes, and timing are protected
//! - **Geographic privacy**: validator location information is not disclosed
//!
//! ## Multi-Protocol Transport
//!
//! The transport layer supports TCP, QUIC (primary for low latency), WebSocket
//! (browser/light client), and WebRTC (peer-to-peer without server infrastructure),
//! with automatic protocol selection based on connection quality.
//!
//! ## Geographic Optimization
//!
//! Topology-aware routing reduces cross-continental latency by 15–30% through
//! intelligent relay selection while maintaining privacy of geographic information
//! from potential surveillance actors.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Transport layer: TCP, QUIC, WebSocket, WebRTC with encrypted channels.
pub mod transport;

/// Network topology: peer discovery, topology maintenance, privacy-preserving structure.
pub mod topology;

/// Message routing: topology-aware routing with geographic optimization.
pub mod routing;

/// Privacy layer: traffic obfuscation, metadata protection, topology privacy.
pub mod privacy;

/// Block and transaction propagation: efficient DAG-aware dissemination.
pub mod propagation;

/// Peer discovery: privacy-preserving peer finding and bootstrapping.
pub mod discovery;

/// RDMA-style transport: zero-copy high-throughput message passing.
pub mod rdma;

/// Data availability: erasure coding with confidentiality preservation.
pub mod availability;

/// Bandwidth management: fair allocation, congestion control, rate limiting.
pub mod bandwidth;

/// Geographic distribution: region-aware optimization and latency reduction.
pub mod geographic;

/// Protocol negotiation: version compatibility, capability exchange.
pub mod protocol;

/// Network metrics: latency, throughput, utilization, topology statistics.
pub mod metrics;

// ============================================================
// PRELUDE
// ============================================================

/// Network prelude — all essential networking types.
///
/// ```rust
/// use aevor_network::prelude::*;
/// ```
pub mod prelude {
    pub use crate::transport::{
        Connection, ConnectionPool, Transport, TransportConfig,
        SecureChannel, TlsConfig, QuicConfig,
    };
    pub use crate::topology::{
        NetworkTopology, TopologyManager, PeerInfo, PeerScore,
        TopologyUpdate, PrivacyPreservingTopology,
    };
    pub use crate::routing::{
        Router, RoutingTable, RoutePath, GeographicRoute,
        TopologyAwareRouter, PrivacyPreservingRouter,
    };
    pub use crate::privacy::{
        NetworkPrivacy, TrafficObfuscation, MetadataShield,
        TopologyPrivacy, TimingObfuscation,
    };
    pub use crate::propagation::{
        BlockPropagator, TransactionPropagator, DagAwarePropagation,
        PropagationPolicy, BroadcastResult,
    };
    pub use crate::discovery::{
        PeerDiscovery, BootstrapConfig, PrivacyPreservingDiscovery,
        PeerAdvertisement, DiscoveryProtocol,
    };
    pub use crate::availability::{
        DataAvailability, ErasureCode, ErasureConfig, AvailabilitySample,
        DataReconstruction,
    };
    pub use crate::geographic::{
        GeographicRegion, RegionConfig, LatencyMatrix, GeoRouter,
        GeographicDistribution,
    };
    pub use crate::{NetworkError, NetworkResult};
}

// ============================================================
// RE-EXPORTS FROM aevor-core
// ============================================================

pub use aevor_core::network::{
    ConnectionMetadata, GeographicRegion, NetworkAddress, NetworkProtocol,
    NetworkTopology, NodeId, PeerId, SubnetId, TopologyMetrics,
};

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from network operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum NetworkError {
    /// Connection to a peer failed or was lost.
    #[error("connection failed to {peer}: {reason}")]
    ConnectionFailed {
        /// Peer address or identifier.
        peer: String,
        /// Reason for connection failure.
        reason: String,
    },

    /// Message routing failed — no path to destination.
    #[error("routing failed to {destination}: {reason}")]
    RoutingFailed {
        /// Destination address.
        destination: String,
        /// Reason routing failed.
        reason: String,
    },

    /// Block propagation timed out.
    #[error("propagation timeout for block {block_hash}")]
    PropagationTimeout {
        /// Hash of the block that failed to propagate.
        block_hash: String,
    },

    /// Data availability sampling failed.
    #[error("data availability failure: {reason}")]
    AvailabilityFailure {
        /// Reason for availability failure.
        reason: String,
    },

    /// Network bandwidth limit exceeded.
    #[error("bandwidth limit exceeded: {used_bps} bps > {limit_bps} bps")]
    BandwidthExceeded {
        /// Actual bandwidth usage.
        used_bps: u64,
        /// Configured limit.
        limit_bps: u64,
    },

    /// Protocol version incompatibility with a peer.
    #[error("protocol incompatibility with {peer}: local {local_version}, peer {peer_version}")]
    ProtocolIncompatible {
        /// Peer address or identifier.
        peer: String,
        /// Local protocol version.
        local_version: String,
        /// Peer's protocol version.
        peer_version: String,
    },

    /// Peer discovery failed.
    #[error("peer discovery failed: {reason}")]
    DiscoveryFailed {
        /// Reason for discovery failure.
        reason: String,
    },
}

/// Convenience alias for network results.
pub type NetworkResult<T> = Result<T, NetworkError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default QUIC port for AEVOR validator communication.
pub const DEFAULT_VALIDATOR_PORT: u16 = 8732;

/// Default TCP port for AEVOR RPC.
pub const DEFAULT_RPC_PORT: u16 = 8731;

/// Default WebSocket port for light client connections.
pub const DEFAULT_WS_PORT: u16 = 8733;

/// Target network bandwidth utilization (90%).
pub const TARGET_BANDWIDTH_UTILIZATION: f64 = 0.90;

/// Maximum message size for gossiped transactions in bytes (256 KiB).
pub const MAX_GOSSIP_MESSAGE_SIZE: usize = 262_144;

/// Maximum block message size for propagation (64 MiB).
pub const MAX_BLOCK_MESSAGE_SIZE: usize = 67_108_864;

/// Default peer connection timeout in milliseconds.
pub const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 5_000;

/// Minimum number of peers for healthy network participation.
pub const MIN_PEER_COUNT: usize = 8;

/// Maximum number of simultaneous peer connections.
pub const MAX_PEER_CONNECTIONS: usize = 1_000;

/// Erasure coding data shards (k in RS(k,n)).
pub const ERASURE_DATA_SHARDS: usize = 32;

/// Erasure coding parity shards (n-k in RS(k,n)).
pub const ERASURE_PARITY_SHARDS: usize = 8;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_distinct() {
        assert_ne!(DEFAULT_VALIDATOR_PORT, DEFAULT_RPC_PORT);
        assert_ne!(DEFAULT_RPC_PORT, DEFAULT_WS_PORT);
    }

    #[test]
    fn erasure_coding_parameters_are_valid() {
        assert!(ERASURE_DATA_SHARDS > 0);
        assert!(ERASURE_PARITY_SHARDS > 0);
        let total = ERASURE_DATA_SHARDS + ERASURE_PARITY_SHARDS;
        assert!(total <= 256); // Reed-Solomon constraint
    }

    #[test]
    fn bandwidth_target_is_reasonable() {
        assert!(TARGET_BANDWIDTH_UTILIZATION > 0.5);
        assert!(TARGET_BANDWIDTH_UTILIZATION < 1.0);
    }
}
