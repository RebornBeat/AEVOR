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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_chain_bridge_stores_config() {
        let bridge = MoveChainBridge::new(MoveChainConfig { chain_id: "aptos-1".into(), rpc_url: "https://fullnode.aptos.io".into() });
        assert_eq!(bridge.chain_id(), "aptos-1");
        assert!(!bridge.rpc_url().is_empty());
    }
}
