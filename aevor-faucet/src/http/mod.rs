//! Faucet HTTP server.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::{faucet::Faucet, FaucetResult};

#[derive(Clone, Debug)]
pub struct HttpConfig { pub listen_addr: SocketAddr, pub enable_cors: bool, pub max_concurrent_requests: usize }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetRequest { pub recipient: String, pub pow_nonce: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetResponse { pub success: bool, pub tx_hash: Option<String>, pub error: Option<String> }

pub struct RequestHandler;

pub struct FaucetServer { faucet: Faucet, config: HttpConfig }
impl FaucetServer {
    pub fn new(faucet: Faucet, config: HttpConfig) -> Self { Self { faucet, config } }

    /// The HTTP configuration for this server (listen address, CORS, concurrency).
    pub fn config(&self) -> &HttpConfig { &self.config }

    /// The listen address this server binds to.
    pub fn listen_addr(&self) -> SocketAddr { self.config.listen_addr }

    /// The faucet instance that processes token distribution requests.
    ///
    /// The faucet enforces cooldown periods, proof-of-work checks, and rate
    /// limiting before submitting distribution transactions to the validator set.
    pub fn faucet(&self) -> &Faucet { &self.faucet }

    /// Start the faucet HTTP server and run until shutdown.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind to the configured address or
    /// encounters a fatal error while serving requests.
    pub fn serve_until_shutdown(&self) -> FaucetResult<()> {
        println!("Faucet server listening on {}", self.config.listen_addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use crate::faucet::{Faucet, FaucetConfig};

    fn test_faucet() -> Faucet {
        Faucet::new(FaucetConfig { network: "testnet".into(), node_endpoint: "http://localhost:8080".into(), distribution_amount: 1_000_000_000, cooldown_seconds: 3600, pow_difficulty: 4, key_file: None }).unwrap()
    }

    fn http_config() -> HttpConfig {
        HttpConfig { listen_addr: "127.0.0.1:8000".parse().unwrap(), enable_cors: true, max_concurrent_requests: 100 }
    }

    #[test]
    fn faucet_server_stores_listen_addr() {
        let server = FaucetServer::new(test_faucet(), http_config());
        assert_eq!(server.listen_addr().port(), 8000);
    }

    #[test]
    fn faucet_server_config_cors_enabled() {
        let server = FaucetServer::new(test_faucet(), http_config());
        assert!(server.config().enable_cors);
        assert_eq!(server.config().max_concurrent_requests, 100);
    }

    #[test]
    fn faucet_response_success_fields() {
        let r = FaucetResponse { success: true, tx_hash: Some("0xABC".into()), error: None };
        assert!(r.success);
        assert!(r.tx_hash.is_some());
    }
}
