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
    #[must_use]
    pub fn endpoint(mut self, e: &str) -> Self { self.config.endpoint = e.to_string(); self }

    /// Set the request timeout in milliseconds.
    #[must_use]
    pub fn timeout_ms(mut self, ms: u64) -> Self { self.config.timeout_ms = ms; self }

    /// Enable or disable TLS.
    #[must_use]
    pub fn tls(mut self, enabled: bool) -> Self { self.config.tls = enabled; self }

    /// Set the connection pool size.
    #[must_use]
    pub fn pool_size(mut self, size: usize) -> Self { self.config.pool_size = size; self }

    /// Build the connection. Returns an error if the endpoint URL is empty.
    ///
    /// # Errors
    /// Returns an error if the endpoint URL is empty.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_default_is_localhost() {
        let cfg = ConnectionConfig::default();
        assert!(cfg.endpoint.contains("localhost"));
        assert!(!cfg.tls);
        assert_eq!(cfg.pool_size, 10);
    }

    #[test]
    fn builder_sets_endpoint() {
        let conn = ConnectionBuilder::new()
            .endpoint("http://node.aevor.io:8731")
            .build()
            .unwrap();
        assert_eq!(conn.endpoint(), "http://node.aevor.io:8731");
    }

    #[test]
    fn builder_empty_endpoint_returns_error() {
        let result = ConnectionBuilder::new().endpoint("").build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_sets_tls() {
        let conn = ConnectionBuilder::new().tls(true).build().unwrap();
        assert!(conn.config().tls);
    }

    #[test]
    fn builder_sets_timeout() {
        let conn = ConnectionBuilder::new().timeout_ms(5000).build().unwrap();
        assert_eq!(conn.config().timeout_ms, 5000);
    }

    #[test]
    fn builder_sets_pool_size() {
        let conn = ConnectionBuilder::new().pool_size(25).build().unwrap();
        assert_eq!(conn.config().pool_size, 25);
    }

    #[test]
    fn new_connection_starts_disconnected() {
        let conn = AevorConnection::new(ConnectionConfig::default());
        assert_eq!(conn.status(), ConnectionStatus::Disconnected);
        assert!(!conn.is_connected());
    }

    #[test]
    fn mark_connected_and_disconnected() {
        let mut conn = AevorConnection::new(ConnectionConfig::default());
        conn.mark_connected();
        assert!(conn.is_connected());
        assert_eq!(conn.status(), ConnectionStatus::Connected);
        conn.mark_disconnected();
        assert!(!conn.is_connected());
    }

    #[test]
    fn connection_pool_starts_empty() {
        let pool = ConnectionPool::new(5);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert!(!pool.is_full());
    }

    #[test]
    fn connection_pool_full_when_at_max() {
        let pool = ConnectionPool { connections: vec![], max_size: 0 };
        assert!(pool.is_full());
    }
}
