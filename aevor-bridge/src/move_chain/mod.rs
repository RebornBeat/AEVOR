//! Move-chain (Aptos/Sui) bridge.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveChainConfig { pub chain_id: String, pub rpc_url: String }
pub struct MoveChainBridge { config: MoveChainConfig }
impl MoveChainBridge {
    pub fn new(config: MoveChainConfig) -> Self { Self { config } }
    pub fn config(&self) -> &MoveChainConfig { &self.config }
    pub fn chain_id(&self) -> &str { &self.config.chain_id }
    pub fn rpc_url(&self) -> &str { &self.config.rpc_url }
}
