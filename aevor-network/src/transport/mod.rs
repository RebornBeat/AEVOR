//! Network transport: QUIC, TCP, WebSocket, gRPC connections.

use serde::{Deserialize, Serialize};
use aevor_core::network::NetworkProtocol;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig { pub cert_path: Option<std::path::PathBuf>, pub key_path: Option<std::path::PathBuf> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicConfig { pub max_streams: u32, pub keep_alive_ms: u64, pub timeout_ms: u64 }
impl Default for QuicConfig {
    fn default() -> Self { Self { max_streams: 256, keep_alive_ms: 5_000, timeout_ms: 30_000 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig { pub protocol: NetworkProtocol, pub tls: Option<TlsConfig>, pub quic: Option<QuicConfig> }

pub struct SecureChannel { established: bool }
impl SecureChannel {
    /// Create a new unestablished secure channel.
    pub fn new() -> Self { Self { established: false } }
    /// Mark the channel as established.
    pub fn establish(&mut self) { self.established = true; }
    /// Returns `true` if the channel has been established.
    pub fn is_established(&self) -> bool { self.established }
}

impl Default for SecureChannel {
    fn default() -> Self { Self::new() }
}

pub struct Connection { pub remote: aevor_core::network::NodeId, pub protocol: NetworkProtocol }

pub struct ConnectionPool { connections: Vec<Connection>, max_size: usize }
impl ConnectionPool {
    /// Create a new empty pool with the given maximum size.
    pub fn new(max_size: usize) -> Self { Self { connections: Vec::new(), max_size } }
    /// Add a connection to the pool. Returns `true` if successful, `false` if full.
    pub fn add(&mut self, c: Connection) -> bool {
        if self.connections.len() < self.max_size { self.connections.push(c); true } else { false }
    }
    /// Number of connections in the pool.
    pub fn len(&self) -> usize { self.connections.len() }
    /// Returns `true` if the pool has no connections.
    pub fn is_empty(&self) -> bool { self.connections.is_empty() }
}

pub struct Transport { config: TransportConfig }
impl Transport {
    pub fn new(config: TransportConfig) -> Self { Self { config } }
    pub fn protocol(&self) -> NetworkProtocol { self.config.protocol }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::network::{NetworkProtocol, NodeId};
    use aevor_core::primitives::Hash256;

    fn make_connection() -> Connection {
        Connection {
            remote: NodeId(Hash256([1u8; 32])),
            protocol: NetworkProtocol::Quic,
        }
    }

    #[test]
    fn secure_channel_starts_unestablished() {
        let ch = SecureChannel::new();
        assert!(!ch.is_established());
    }

    #[test]
    fn secure_channel_establish_marks_it_live() {
        let mut ch = SecureChannel::new();
        ch.establish();
        assert!(ch.is_established());
    }

    #[test]
    fn secure_channel_default_is_unestablished() {
        let ch = SecureChannel::default();
        assert!(!ch.is_established());
    }

    #[test]
    fn connection_pool_starts_empty() {
        let pool = ConnectionPool::new(4);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn connection_pool_add_respects_max_size() {
        let mut pool = ConnectionPool::new(1);
        assert!(pool.add(make_connection()));
        assert!(!pool.add(make_connection())); // pool is full
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn transport_reports_protocol() {
        let config = TransportConfig {
            protocol: NetworkProtocol::Tcp,
            tls: None,
            quic: None,
        };
        let t = Transport::new(config);
        assert_eq!(t.protocol(), NetworkProtocol::Tcp);
    }
}
