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
}
