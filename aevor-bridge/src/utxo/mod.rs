//! UTXO bridge: Bitcoin SPV.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinChainConfig { pub network: String, pub confirmations: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoStateProof { pub tx_hash: Hash256, pub merkle_path: Vec<Hash256> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinSpv { pub block_header: Vec<u8>, pub proof: UtxoStateProof }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoTransaction { pub hash: Hash256, pub inputs: Vec<Vec<u8>>, pub outputs: Vec<Vec<u8>> }
pub struct UtxoBridge { config: BitcoinChainConfig }
impl UtxoBridge {
    pub fn new(c: BitcoinChainConfig) -> Self { Self { config: c } }
    pub fn config(&self) -> &BitcoinChainConfig { &self.config }
    pub fn network(&self) -> &str { &self.config.network }
    pub fn required_confirmations(&self) -> u32 { self.config.confirmations }
}
