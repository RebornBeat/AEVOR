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
    pub async fn serve_until_shutdown(&self) -> FaucetResult<()> {
        println!("Faucet server listening on {}", self.config.listen_addr);
        Ok(())
    }
}
