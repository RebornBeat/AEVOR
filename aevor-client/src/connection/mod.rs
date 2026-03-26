//! Client connection management: pooling, status tracking, builder pattern.

use serde::{Deserialize, Serialize};
use crate::{ClientResult, DEFAULT_CONNECTION_TIMEOUT_MS};

/// Configuration for an `AevorConnection`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// gRPC/HTTP endpoint URL (e.g. `http://localhost:8731`).
    pub endpoint: String,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of connections to keep in the pool.
    pub pool_size: usize,
    /// Whether to use TLS for the connection.
    pub tls: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:8731".into(),
            timeout_ms: DEFAULT_CONNECTION_TIMEOUT_MS,
            pool_size: 10,
            tls: false,
        }
    }
}

/// Live status of an `AevorConnection`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// Handshake in progress.
    Connecting,
    /// Connection is live and healthy.
    Connected,
    /// Connection was lost; reconnect is in progress.
    Reconnecting,
    /// Connection is closed (not yet opened or cleanly shut down).
    Disconnected,
}

/// A connection to a validator node, used for sending transactions.
pub struct ValidatorConnection {
    /// gRPC endpoint for this validator.
    pub endpoint: String,
}

/// A connection to an archive node, used for historical queries.
pub struct ArchiveConnection {
    /// HTTP/gRPC endpoint for the archive node.
    pub endpoint: String,
}

/// Builder for `AevorConnection`.
pub struct ConnectionBuilder {
    config: ConnectionConfig,
}

impl ConnectionBuilder {
    /// Create a builder with default configuration (localhost, no TLS).
    pub fn new() -> Self { Self { config: ConnectionConfig::default() } }

    /// Set the endpoint URL.
    pub fn endpoint(mut self, e: &str) -> Self { self.config.endpoint = e.to_string(); self }

    /// Set the request timeout in milliseconds.
    pub fn timeout_ms(mut self, ms: u64) -> Self { self.config.timeout_ms = ms; self }

    /// Enable or disable TLS.
    pub fn tls(mut self, enabled: bool) -> Self { self.config.tls = enabled; self }

    /// Set the connection pool size.
    pub fn pool_size(mut self, size: usize) -> Self { self.config.pool_size = size; self }

    /// Build the connection. Returns an error if the endpoint URL is empty.
    pub fn build(self) -> ClientResult<AevorConnection> {
        if self.config.endpoint.is_empty() {
            return Err(crate::ClientError::ConnectionFailed {
                endpoint: String::new(),
                reason: "endpoint URL is empty".into(),
            });
        }
        Ok(AevorConnection { config: self.config, status: ConnectionStatus::Disconnected })
    }
}

impl Default for ConnectionBuilder { fn default() -> Self { Self::new() } }

/// Pool of reusable `AevorConnection`s to a single endpoint.
pub struct ConnectionPool {
    connections: Vec<AevorConnection>,
    max_size: usize,
}

impl ConnectionPool {
    /// Create a new empty pool with the given maximum size.
    pub fn new(max_size: usize) -> Self { Self { connections: Vec::new(), max_size } }
    /// Number of connections currently in the pool.
    pub fn len(&self) -> usize { self.connections.len() }
    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool { self.connections.is_empty() }
    /// Returns `true` if the pool is at capacity.
    pub fn is_full(&self) -> bool { self.connections.len() >= self.max_size }
}

/// A live (or pending) connection to an AEVOR node.
pub struct AevorConnection {
    config: ConnectionConfig,
    status: ConnectionStatus,
}

impl AevorConnection {
    /// Create a new connection with the given configuration.
    pub fn new(config: ConnectionConfig) -> Self {
        Self { config, status: ConnectionStatus::Disconnected }
    }
    /// Current connection status.
    pub fn status(&self) -> ConnectionStatus { self.status }
    /// The endpoint this connection targets.
    pub fn endpoint(&self) -> &str { &self.config.endpoint }
    /// The connection configuration.
    pub fn config(&self) -> &ConnectionConfig { &self.config }
    /// Mark the connection as live.
    pub fn mark_connected(&mut self) { self.status = ConnectionStatus::Connected; }
    /// Mark the connection as disconnected.
    pub fn mark_disconnected(&mut self) { self.status = ConnectionStatus::Disconnected; }
    /// Returns `true` if the connection is currently live.
    pub fn is_connected(&self) -> bool { self.status == ConnectionStatus::Connected }
}
