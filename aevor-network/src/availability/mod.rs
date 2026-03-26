//! Data availability via erasure coding.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErasureConfig { pub data_shards: usize, pub parity_shards: usize }
impl Default for ErasureConfig {
    fn default() -> Self { Self { data_shards: 8, parity_shards: 4 } }
}

pub struct ErasureCode { config: ErasureConfig }
impl ErasureCode {
    pub fn new(config: ErasureConfig) -> Self { Self { config } }
    pub fn encode(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let chunk = (data.len() / self.config.data_shards).max(1);
        data.chunks(chunk).map(|c| c.to_vec()).collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilitySample { pub shard_index: usize, pub data_hash: aevor_core::primitives::Hash256 }

pub struct DataReconstruction;
impl DataReconstruction {
    pub fn reconstruct(shards: &[Vec<u8>]) -> Option<Vec<u8>> {
        if shards.is_empty() { None } else { Some(shards.concat()) }
    }
}

pub struct DataAvailability { code: ErasureCode }
impl DataAvailability {
    pub fn new(config: ErasureConfig) -> Self { Self { code: ErasureCode::new(config) } }
}
