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
    pub fn new() -> Self { Self { established: false } }
    pub fn establish(&mut self) { self.established = true; }
    pub fn is_established(&self) -> bool { self.established }
}

pub struct Connection { pub remote: aevor_core::network::NodeId, pub protocol: NetworkProtocol }

pub struct ConnectionPool { connections: Vec<Connection>, max_size: usize }
impl ConnectionPool {
    pub fn new(max_size: usize) -> Self { Self { connections: Vec::new(), max_size } }
    pub fn add(&mut self, c: Connection) -> bool {
        if self.connections.len() < self.max_size { self.connections.push(c); true } else { false }
    }
    pub fn len(&self) -> usize { self.connections.len() }
}

pub struct Transport { config: TransportConfig }
impl Transport {
    pub fn new(config: TransportConfig) -> Self { Self { config } }
    pub fn protocol(&self) -> NetworkProtocol { self.config.protocol }
}
