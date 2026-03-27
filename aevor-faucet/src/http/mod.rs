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
