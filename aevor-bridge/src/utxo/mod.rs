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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    #[test]
    fn utxo_bridge_stores_network_and_confirmations() {
        let bridge = UtxoBridge::new(BitcoinChainConfig { network: "mainnet".into(), confirmations: 6 });
        assert_eq!(bridge.network(), "mainnet");
        assert_eq!(bridge.required_confirmations(), 6);
    }

    #[test]
    fn utxo_state_proof_has_merkle_path() {
        let proof = UtxoStateProof { tx_hash: Hash256::ZERO, merkle_path: vec![Hash256([1u8;32])] };
        assert_eq!(proof.merkle_path.len(), 1);
    }

    #[test]
    fn bitcoin_spv_has_header_and_proof() {
        let spv = BitcoinSpv {
            block_header: vec![0u8; 80],
            proof: UtxoStateProof { tx_hash: Hash256::ZERO, merkle_path: vec![] },
        };
        assert_eq!(spv.block_header.len(), 80);
    }
}
