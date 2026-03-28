//! EVM bridge: Ethereum, Polygon, BNB Chain compatibility.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmChainConfig { pub chain_id: u64, pub rpc_url: String, pub finality_blocks: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumStateProof { pub block_hash: Hash256, pub storage_proof: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmEvent { pub address: Vec<u8>, pub topics: Vec<Hash256>, pub data: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmTransaction { pub hash: Hash256, pub from: Vec<u8>, pub to: Vec<u8>, pub data: Vec<u8> }
pub struct SolidityInterop;
pub struct EvmBridge { config: EvmChainConfig }
impl EvmBridge {
    pub fn new(config: EvmChainConfig) -> Self { Self { config } }
    pub fn chain_id(&self) -> u64 { self.config.chain_id }
    pub fn finality_blocks(&self) -> u32 { self.config.finality_blocks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    #[test]
    fn evm_bridge_stores_config() {
        let cfg = EvmChainConfig { chain_id: 1, rpc_url: "https://eth.example.com".into(), finality_blocks: 12 };
        let bridge = EvmBridge::new(cfg);
        assert_eq!(bridge.chain_id(), 1);
        assert_eq!(bridge.finality_blocks(), 12);
    }

    #[test]
    fn evm_event_has_topics() {
        let ev = EvmEvent { address: vec![0xABu8; 20], topics: vec![Hash256::ZERO], data: vec![1, 2] };
        assert_eq!(ev.topics.len(), 1);
        assert_eq!(ev.address.len(), 20);
    }

    #[test]
    fn ethereum_state_proof_has_storage_proof() {
        let p = EthereumStateProof { block_hash: Hash256([1u8; 32]), storage_proof: vec![0xFF; 32] };
        assert!(!p.storage_proof.is_empty());
    }
}
